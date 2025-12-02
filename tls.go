package gohislip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

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
	if !c.session.IsEncrypted() {
		return fmt.Errorf("not encrypted")
	}

	c.log("ending TLS session")

	// 步骤 1：发送 AsyncEndTLS
	if err := c.asyncConn.SendMessage(MsgAsyncEndTLS, 0, 0, nil); err != nil {
		return fmt.Errorf("send AsyncEndTLS: %w", err)
	}

	// 步骤 2：等待 AsyncEndTLSResponse
	msg, err := c.asyncConn.ExpectMessage(MsgAsyncEndTLSResponse, c.config.Timeout)
	if err != nil {
		return fmt.Errorf("wait AsyncEndTLSResponse: %w", err)
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

	// 在同步通道上发送 GetDescriptors
	if err := c.syncConn.SendMessage(MsgGetDescriptors, 0, 0, nil); err != nil {
		return nil, fmt.Errorf("send GetDescriptors: %w", err)
	}

	// 等待响应
	msg, err := c.syncConn.ExpectMessage(MsgGetDescriptorsResponse, c.config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("wait GetDescriptorsResponse: %w", err)
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
