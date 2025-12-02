package gohislip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// mergeDeadline 计算操作截止时间，取 context deadline 和配置超时的较早者。
func mergeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

// TLSConfig 提供创建 TLS 配置的辅助函数。

// NewTLSConfig 创建带有给定服务器名称的基本 TLS 配置。
// 如果 serverName 为空，则跳过主机名验证。
func NewTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: serverName == "",
		MinVersion:         tls.VersionTLS12,
	}
}

// NewTLSConfigWithCA 创建带自定义 CA 证书的 TLS 配置。
func NewTLSConfigWithCA(serverName string, caCertPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		ServerName: serverName,
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// NewTLSConfigWithCert 创建带客户端证书认证的 TLS 配置。
func NewTLSConfigWithCert(serverName, certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewTLSConfigFull 创建带 CA 和客户端证书的 TLS 配置。
func NewTLSConfigFull(serverName, caCertPath, certPath, keyPath string) (*tls.Config, error) {
	// 加载 CA 证书
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// 加载客户端证书
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		ServerName:   serverName,
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// StartTLS 将现有的非加密连接升级为 TLS。
// 遵循 HiSLIP 2.0 StartTLS 序列。
func (c *Client) StartTLS(ctx context.Context) error {
	if c.session.Mode() == ModeOverlapped {
		return fmt.Errorf("StartTLS cannot be called in overlapped mode; use TLS config during Connect")
	}

	if c.session.IsEncrypted() {
		return fmt.Errorf("already encrypted")
	}

	if c.config.TLSConfig == nil {
		return fmt.Errorf("TLS config not provided")
	}

	return c.establishSecureConnection(ctx)
}

// EndTLS 从 TLS 降级为非加密连接。
// 很少使用但在 HiSLIP 2.0 中有规定。
func (c *Client) EndTLS(ctx context.Context) error {
	if c.session.Mode() == ModeOverlapped {
		return fmt.Errorf("EndTLS cannot be called in overlapped mode")
	}

	if !c.session.IsEncrypted() {
		return fmt.Errorf("not encrypted")
	}

	c.log("ending TLS session")

	// 设置截止时间
	deadline := mergeDeadline(ctx, c.config.Timeout)
	if err := c.asyncConn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := c.syncConn.SetDeadline(deadline); err != nil {
		return err
	}
	defer func() {
		c.asyncConn.SetDeadline(time.Time{})
		c.syncConn.SetDeadline(time.Time{})
	}()

	// 步骤 1：发送 AsyncEndTLS
	if err := c.asyncConn.SendMessage(MsgAsyncEndTLS, 0, 0, nil); err != nil {
		return fmt.Errorf("send AsyncEndTLS: %w", err)
	}

	// 步骤 2：等待 AsyncEndTLSResponse
	msg, err := c.asyncConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("wait AsyncEndTLSResponse: %w", err)
	}
	if msg.Header.MsgType != MsgAsyncEndTLSResponse {
		return fmt.Errorf("expected AsyncEndTLSResponse, got %s", MsgTypeName(msg.Header.MsgType))
	}

	if msg.Header.Control != CtrlTLSSuccess {
		return fmt.Errorf("server rejected EndTLS: ctrl=%d", msg.Header.Control)
	}

	// 步骤 3：降级异步连接
	if err := c.asyncConn.DowngradeFromTLS(); err != nil {
		return fmt.Errorf("async TLS downgrade: %w", err)
	}

	// 步骤 4：在同步通道上发送 EndTLS
	if err := c.syncConn.SendMessage(MsgEndTLS, 0, 0, nil); err != nil {
		return fmt.Errorf("send EndTLS: %w", err)
	}

	// 步骤 5：降级同步连接
	if err := c.syncConn.DowngradeFromTLS(); err != nil {
		return fmt.Errorf("sync TLS downgrade: %w", err)
	}

	c.session.SetEncrypted(false)
	c.log("TLS session ended")
	return nil
}

// GetDescriptors 获取服务器能力描述符（HiSLIP 2.0）。
// 返回描述符数据为原始字节。
func (c *Client) GetDescriptors(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClosed
	}
	c.mu.RUnlock()

	if c.session.Mode() == ModeOverlapped {
		return nil, fmt.Errorf("GetDescriptors cannot be called in overlapped mode")
	}

	// 设置截止时间
	deadline := mergeDeadline(ctx, c.config.Timeout)
	if err := c.syncConn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer c.syncConn.SetDeadline(time.Time{})

	// 在同步通道上发送 GetDescriptors
	if err := c.syncConn.SendMessage(MsgGetDescriptors, 0, 0, nil); err != nil {
		return nil, fmt.Errorf("send GetDescriptors: %w", err)
	}

	// 等待响应
	msg, err := c.syncConn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("wait GetDescriptorsResponse: %w", err)
	}
	if msg.Header.MsgType != MsgGetDescriptorsResponse {
		return nil, fmt.Errorf("expected GetDescriptorsResponse, got %s", MsgTypeName(msg.Header.MsgType))
	}

	return msg.Payload, nil
}

// TLSConnectionState 返回加密时的 TLS 连接状态。
// 如果未使用 TLS 则返回 nil。
func (c *Client) TLSConnectionState() *tls.ConnectionState {
	if !c.session.IsEncrypted() {
		return nil
	}

	if c.syncConn != nil && c.syncConn.tlsConn != nil {
		state := c.syncConn.tlsConn.ConnectionState()
		return &state
	}
	return nil
}

// ================ SASL 认证框架 (HiSLIP 2.0) ================

// GetSASLMechanisms 获取服务器支持的 SASL 认证机制列表。
// 仅在 HiSLIP 2.0 或更高版本中可用。
// 注意：此操作只能在同步模式下调用。在 overlapped 模式下会与 readLoopSync 竞争。
func (c *Client) GetSASLMechanisms(ctx context.Context) ([]string, error) {
	if !c.session.IsVersion2OrHigher() {
		return nil, fmt.Errorf("SASL authentication requires HiSLIP 2.0 or higher")
	}

	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClosed
	}
	c.mu.RUnlock()

	if c.session.Mode() == ModeOverlapped {
		return nil, fmt.Errorf("GetSASLMechanisms cannot be called in overlapped mode")
	}

	// 设置截止时间
	deadline := mergeDeadline(ctx, c.config.Timeout)
	if err := c.syncConn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer c.syncConn.SetDeadline(time.Time{})

	// 发送 GetSaslMechanismList
	if err := c.syncConn.SendMessage(MsgGetSaslMechanismList, 0, 0, nil); err != nil {
		return nil, fmt.Errorf("send GetSaslMechanismList: %w", err)
	}

	// 等待响应
	msg, err := c.syncConn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("wait GetSaslMechanismListResponse: %w", err)
	}
	if msg.Header.MsgType != MsgGetSaslMechanismListResponse {
		return nil, fmt.Errorf("expected GetSaslMechanismListResponse, got %s", MsgTypeName(msg.Header.MsgType))
	}

	// 解析机制列表（以空格分隔的字符串）
	if len(msg.Payload) == 0 {
		return nil, nil
	}

	mechanisms := splitSASLMechanisms(string(msg.Payload))
	return mechanisms, nil
}

// splitSASLMechanisms 解析 SASL 机制列表字符串
func splitSASLMechanisms(s string) []string {
	if s == "" {
		return nil
	}
	var mechanisms []string
	for _, m := range splitBySpace(s) {
		if m != "" {
			mechanisms = append(mechanisms, m)
		}
	}
	return mechanisms
}

// splitBySpace 按空格分割字符串
func splitBySpace(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if start < i {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// Authenticate 使用指定的 SASL 机制进行认证。
// 仅在 HiSLIP 2.0 或更高版本中可用。
// 注意：这是一个基础框架，当前仅支持单步认证（如 PLAIN），
// 不支持需要根据服务器 Challenge 动态计算响应的多步机制。
func (c *Client) Authenticate(ctx context.Context, mechanism string, credentials []byte) error {
	if !c.session.IsVersion2OrHigher() {
		return fmt.Errorf("SASL authentication requires HiSLIP 2.0 or higher")
	}

	if !c.session.IsEncrypted() {
		return fmt.Errorf("SASL authentication requires encrypted connection")
	}

	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	if c.session.Mode() == ModeOverlapped {
		return fmt.Errorf("Authenticate cannot be called in overlapped mode")
	}

	// 设置截止时间
	deadline := mergeDeadline(ctx, c.config.Timeout)
	if err := c.syncConn.SetDeadline(deadline); err != nil {
		return err
	}
	defer c.syncConn.SetDeadline(time.Time{})

	// 发送 AuthenticationStart
	if err := c.syncConn.SendMessage(MsgAuthenticationStart, 0, 0, []byte(mechanism)); err != nil {
		return fmt.Errorf("send AuthenticationStart: %w", err)
	}

	credentialsSent := false

	// 认证交换循环
	for {
		// 检查 Context 是否取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := c.syncConn.ReadMessage()
		if err != nil {
			return fmt.Errorf("authentication exchange: %w", err)
		}

		switch msg.Header.MsgType {
		case MsgAuthenticationExchange:
			// 如果服务器请求更多数据
			if credentialsSent {
				// 我们已经发送过凭据了。由于 API 限制，无法生成新的响应。
				// 对于 PLAIN 机制，这通常意味着错误。
				return fmt.Errorf("multi-step authentication not supported by this client API")
			}

			// 发送凭据
			if err := c.syncConn.SendMessage(MsgAuthenticationExchange, 0, 0, credentials); err != nil {
				return fmt.Errorf("send AuthenticationExchange: %w", err)
			}
			credentialsSent = true

		case MsgAuthenticationResult:
			switch msg.Header.Control {
			case CtrlAuthSuccess:
				return nil
			case CtrlAuthFail:
				return ErrAuthFailed
			case CtrlAuthContinue:
				// 服务器可能在成功前发送最后一步数据
				// 继续循环以等待最终结果或更多交换
				continue
			default:
				return fmt.Errorf("unexpected authentication result: ctrl=%d", msg.Header.Control)
			}

		case MsgFatalError:
			return NewFatalError(msg.Header.Control, msg.Payload)

		case MsgError:
			return NewNonFatalError(msg.Header.Control, msg.Payload)

		default:
			return fmt.Errorf("unexpected message during authentication: %s", MsgTypeName(msg.Header.MsgType))
		}
	}
}
