package gohislip

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ClientConfig 保存创建 Client 的配置。
type ClientConfig struct {
	// SubAddress 是 HiSLIP 子地址（例如 "hislip0"）
	SubAddress string

	// VendorID 是客户端的供应商 ID（通用客户端通常为 0）
	VendorID uint16

	// Timeout 操作超时时间（默认 30s）
	Timeout time.Duration

	// TLSConfig TLS 配置（nil 表示不使用 TLS）
	TLSConfig *tls.Config

	// UseOverlappedMode 如果服务器支持，尝试使用 overlap 模式
	UseOverlappedMode bool

	// Logger 用于调试输出（nil 禁用日志）
	Logger *log.Logger
}

// DefaultConfig 返回带默认值的 ClientConfig。
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		SubAddress: "hislip0",
		VendorID:   0,
		Timeout:    30 * time.Second,
	}
}

// Client 表示 HiSLIP 客户端连接。
type Client struct {
	syncConn  *Conn // 同步通道
	asyncConn *Conn // 异步通道

	session *Session
	tracker *QueryTracker

	config *ClientConfig

	// 读取循环
	syncDone  chan struct{}
	asyncDone chan struct{}

	// 响应通道
	syncResp  chan *Message
	asyncResp chan *Message

	// SRQ（服务请求）回调
	srqCallback func(stb byte)
	srqMu       sync.Mutex

	// 状态
	mu     sync.RWMutex
	closed bool

	// 用于同步模式查询处理
	queryMu   sync.Mutex
	queryResp chan queryResult
}

type queryResult struct {
	data []byte
	err  error
}

// NewClient 创建新的 HiSLIP 客户端，但尚未连接。
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	return &Client{
		session:   NewSession(),
		tracker:   NewQueryTracker(),
		config:    config,
		syncDone:  make(chan struct{}),
		asyncDone: make(chan struct{}),
		syncResp:  make(chan *Message, 16),
		asyncResp: make(chan *Message, 16),
		queryResp: make(chan queryResult, 1),
	}
}

// Connect 建立与服务器的 HiSLIP 连接。
func (c *Client) Connect(ctx context.Context, address string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.syncConn != nil {
		return fmt.Errorf("already connected")
	}

	// 解析地址
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = fmt.Sprintf("%d", DefaultPort)
	}
	address = net.JoinHostPort(host, port)

	c.log("connecting to %s", address)

	// 步骤 1：建立同步 TCP 连接
	syncConn, err := DialContext(ctx, address)
	if err != nil {
		return fmt.Errorf("dial sync: %w", err)
	}
	c.syncConn = syncConn

	// 步骤 2：发送 Initialize
	if err := c.sendInitialize(); err != nil {
		syncConn.Close()
		c.syncConn = nil
		return fmt.Errorf("initialize: %w", err)
	}

	// 步骤 3：接收 InitializeResponse
	if err := c.recvInitializeResponse(); err != nil {
		syncConn.Close()
		c.syncConn = nil
		return fmt.Errorf("initialize response: %w", err)
	}

	// 步骤 4：建立异步 TCP 连接
	asyncConn, err := DialContext(ctx, address)
	if err != nil {
		syncConn.Close()
		c.syncConn = nil
		return fmt.Errorf("dial async: %w", err)
	}
	c.asyncConn = asyncConn

	// 步骤 5：发送 AsyncInitialize
	if err := c.sendAsyncInitialize(); err != nil {
		syncConn.Close()
		asyncConn.Close()
		c.syncConn = nil
		c.asyncConn = nil
		return fmt.Errorf("async initialize: %w", err)
	}

	// 步骤 6：接收 AsyncInitializeResponse
	if err := c.recvAsyncInitializeResponse(); err != nil {
		syncConn.Close()
		asyncConn.Close()
		c.syncConn = nil
		c.asyncConn = nil
		return fmt.Errorf("async initialize response: %w", err)
	}

	// 步骤 7：协商最大消息大小（可选但建议）
	if err := c.negotiateMaxMessageSize(); err != nil {
		c.log("max message size negotiation failed: %v", err)
		// 非致命，继续
	}

	// 步骤 8：检查是否需要加密
	if c.session.RequiresEncryption() {
		if c.config.TLSConfig == nil {
			syncConn.Close()
			asyncConn.Close()
			c.syncConn = nil
			c.asyncConn = nil
			return ErrTLSRequired
		}
		if err := c.establishSecureConnection(ctx); err != nil {
			syncConn.Close()
			asyncConn.Close()
			c.syncConn = nil
			c.asyncConn = nil
			return fmt.Errorf("secure connection: %w", err)
		}
	}

	// 启动读取循环
	go c.readLoopSync()
	go c.readLoopAsync()

	c.log("connected, session ID: %d, version: %d.%d",
		c.session.SessionID(),
		c.session.serverVersionMajor,
		c.session.serverVersionMinor)

	return nil
}

// Dial 创建客户端并连接到服务器。
func Dial(ctx context.Context, address string, config *ClientConfig) (*Client, error) {
	client := NewClient(config)
	if err := client.Connect(ctx, address); err != nil {
		return nil, err
	}
	return client, nil
}

// Close 关闭客户端连接。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// 关闭连接
	var errs []error
	if c.syncConn != nil {
		if err := c.syncConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.asyncConn != nil {
		if err := c.asyncConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// 等待读取循环退出
	close(c.syncDone)
	close(c.asyncDone)

	// 清除待处理查询
	c.tracker.Clear(ErrClosed)

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// sendInitialize 发送 Initialize 消息。
func (c *Client) sendInitialize() error {
	param := MakeInitializeParam(ProtocolVersion, c.config.VendorID)
	payload := []byte(c.config.SubAddress)

	c.log("sending Initialize: version=%d.%d vendorID=%d subAddr=%s",
		ProtocolVersionMajor, ProtocolVersionMinor, c.config.VendorID, c.config.SubAddress)

	return c.syncConn.SendMessage(MsgInitialize, 0, param, payload)
}

// recvInitializeResponse 接收并处理 InitializeResponse。
func (c *Client) recvInitializeResponse() error {
	msg, err := c.syncConn.ExpectMessage(MsgInitializeResponse, c.config.Timeout)
	if err != nil {
		return err
	}

	// 从负载解析版本
	if len(msg.Payload) < 2 {
		return fmt.Errorf("InitializeResponse payload too short")
	}
	version := uint16(msg.Payload[0])<<8 | uint16(msg.Payload[1])
	major, minor := ParseVersion(version)
	c.session.SetServerVersion(major, minor)

	// 解析参数: overlap | encryption_mode | session_id
	overlap, encMode, sessionID := ParseInitializeResponseParam(msg.Header.Param)
	c.session.SetSessionID(sessionID)
	c.session.SetSupportsOverlap(overlap)
	c.session.SetEncryptionMode(encMode)

	// 根据协商设置模式
	if overlap && c.config.UseOverlappedMode {
		c.session.SetMode(ModeOverlapped)
	}

	c.log("InitializeResponse: version=%d.%d session=%d overlap=%v enc=%d",
		major, minor, sessionID, overlap, encMode)

	return nil
}

// sendAsyncInitialize 发送 AsyncInitialize 消息。
func (c *Client) sendAsyncInitialize() error {
	// 参数是会话 ID
	return c.asyncConn.SendMessage(MsgAsyncInitialize, 0, uint32(c.session.SessionID()), nil)
}

// recvAsyncInitializeResponse 接收 AsyncInitializeResponse。
func (c *Client) recvAsyncInitializeResponse() error {
	msg, err := c.asyncConn.ExpectMessage(MsgAsyncInitializeResponse, c.config.Timeout)
	if err != nil {
		return err
	}

	// 从参数提取服务器供应商 ID
	vendorID := ParseAsyncInitializeResponseParam(msg.Header.Param)
	c.session.SetServerVendorID(vendorID)

	c.log("AsyncInitializeResponse: server vendorID=%d", vendorID)
	return nil
}

// negotiateMaxMessageSize 协商最大消息大小。
func (c *Client) negotiateMaxMessageSize() error {
	// 发送我们首选的最大大小
	maxSize := DefaultMaxMessageSize
	param := uint32(maxSize >> 32)

	msg := NewMessage(MsgAsyncMaximumMessageSize, 0, param, nil)
	// 以特殊方式放置低 32 位或使用负载
	// 实际上根据规范，64 位大小分布在参数和负载中
	payload := make([]byte, 8)
	payload[0] = byte(maxSize >> 56)
	payload[1] = byte(maxSize >> 48)
	payload[2] = byte(maxSize >> 40)
	payload[3] = byte(maxSize >> 32)
	payload[4] = byte(maxSize >> 24)
	payload[5] = byte(maxSize >> 16)
	payload[6] = byte(maxSize >> 8)
	payload[7] = byte(maxSize)
	msg.Header.Length = 8
	msg.Payload = payload

	if err := c.asyncConn.WriteMessage(msg); err != nil {
		return err
	}

	// 接收响应
	resp, err := c.asyncConn.ExpectMessage(MsgAsyncMaximumMessageSizeResp, c.config.Timeout)
	if err != nil {
		return err
	}

	// 解析服务器的最大大小
	if len(resp.Payload) >= 8 {
		serverMax := uint64(resp.Payload[0])<<56 |
			uint64(resp.Payload[1])<<48 |
			uint64(resp.Payload[2])<<40 |
			uint64(resp.Payload[3])<<32 |
			uint64(resp.Payload[4])<<24 |
			uint64(resp.Payload[5])<<16 |
			uint64(resp.Payload[6])<<8 |
			uint64(resp.Payload[7])

		c.session.SetMaxMessageSizeFromServer(serverMax)
		c.log("negotiated max message size: %d bytes", serverMax)
	}

	return nil
}

// Write 向仪器发送 SCPI 命令。
func (c *Client) Write(cmd string) error {
	return c.WriteBytes([]byte(cmd))
}

// WriteBytes 向仪器发送原始字节。
func (c *Client) WriteBytes(data []byte) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	if c.session.IsClearInProgress() {
		return ErrDeviceClear
	}

	// 获取下一个消息 ID
	msgID := c.session.NextMessageID()

	// 控制: RMT-delivered 位
	ctrl := uint8(CtrlRMTDelivered)

	c.log("Write: msgID=0x%08x len=%d", msgID, len(data))

	// 发送 DataEnd（完整消息）
	return c.syncConn.SendMessage(MsgDataEnd, ctrl, msgID, data)
}

// Read 从仪器读取响应数据。
func (c *Client) Read() ([]byte, error) {
	return c.ReadWithTimeout(c.config.Timeout)
}

// ReadWithTimeout 使用自定义超时读取响应。
func (c *Client) ReadWithTimeout(timeout time.Duration) ([]byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClosed
	}
	c.mu.RUnlock()

	var result bytes.Buffer
	deadline := time.Now().Add(timeout)

	for {
		// 设置读取截止时间
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrTimeout
		}

		msg, err := c.syncConn.ReadWithTimeout(remaining)
		if err != nil {
			return nil, err
		}

		// 处理不同的消息类型
		switch msg.Header.MsgType {
		case MsgData:
			// 部分数据，还有更多
			result.Write(msg.Payload)
			c.session.SetLastRecvID(msg.Header.Param)

		case MsgDataEnd:
			// 最终数据段
			result.Write(msg.Payload)
			c.session.SetLastRecvID(msg.Header.Param)
			c.log("Read complete: msgID=0x%08x len=%d", msg.Header.Param, result.Len())
			return result.Bytes(), nil

		case MsgFatalError:
			return nil, NewFatalError(msg.Header.Control, msg.Payload)

		case MsgError:
			return nil, NewNonFatalError(msg.Header.Control, msg.Payload)

		case MsgInterrupted:
			// 清除缓冲区并返回错误
			c.log("Interrupted received")
			return nil, ErrInterrupted

		default:
			c.log("unexpected message type during read: %s", MsgTypeName(msg.Header.MsgType))
		}
	}
}

// Query 发送命令并读取响应。
func (c *Client) Query(cmd string) (string, error) {
	data, err := c.QueryBytes([]byte(cmd))
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}

// QueryBytes 发送命令并以字节形式读取响应。
func (c *Client) QueryBytes(cmd []byte) ([]byte, error) {
	if c.session.Mode() == ModeSynchronized {
		return c.querySynchronized(cmd)
	}
	return c.queryOverlapped(cmd)
}

// querySynchronized 在同步模式下处理查询。
func (c *Client) querySynchronized(cmd []byte) ([]byte, error) {
	c.queryMu.Lock()
	defer c.queryMu.Unlock()

	// Send command
	if err := c.WriteBytes(cmd); err != nil {
		return nil, err
	}

	// 读取响应
	return c.Read()
}

// queryOverlapped 在 overlapped 模式下处理查询。
func (c *Client) queryOverlapped(cmd []byte) ([]byte, error) {
	// 在 overlapped 模式下，可以有多个待处理查询
	msgID := c.session.NextMessageID()

	// 注册待处理查询
	pq := c.tracker.Add(msgID)

	// Send command
	ctrl := uint8(CtrlRMTDelivered)
	if err := c.syncConn.SendMessage(MsgDataEnd, ctrl, msgID, cmd); err != nil {
		c.tracker.Complete(msgID, nil, err)
		return nil, err
	}

	// Wait for response
	select {
	case <-pq.done:
		return pq.response, pq.err
	case <-time.After(c.config.Timeout):
		c.tracker.Complete(msgID, nil, ErrTimeout)
		return nil, ErrTimeout
	}
}

// Lock 获取仪器的独占锁。
func (c *Client) Lock(ctx context.Context, timeout time.Duration) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	// 发送 AsyncLock 请求
	timeoutMs := uint32(timeout / time.Millisecond)
	if err := c.asyncConn.SendMessage(MsgAsyncLock, CtrlLockRequest, timeoutMs, nil); err != nil {
		return err
	}

	c.log("Lock requested: timeout=%v", timeout)

	// Wait for response
	msg, err := c.asyncConn.ExpectMessage(MsgAsyncLockResponse, timeout+time.Second)
	if err != nil {
		return err
	}

	switch msg.Header.Control {
	case CtrlLockSuccess:
		c.session.SetLockState(LockExclusive)
		c.log("Lock acquired")
		return nil
	case CtrlLockFail:
		return ErrLockTimeout
	case CtrlLockError:
		return ErrLockFailed
	default:
		return fmt.Errorf("unexpected lock response: ctrl=%d", msg.Header.Control)
	}
}

// Unlock 释放仪器上的锁。
func (c *Client) Unlock(ctx context.Context) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	if c.session.LockState() == LockNone {
		return ErrNotLocked
	}

	// 根据规范 6.5.1：参数是需要在释放锁之前完成的最后一个消息 ID，
	// 如果没有则为 0xfffffefe
	lastID := c.session.LastSentID()
	if lastID == 0 {
		lastID = MessageIDClear
	}

	if err := c.asyncConn.SendMessage(MsgAsyncLock, CtrlLockRelease, lastID, nil); err != nil {
		return err
	}

	c.log("Unlock requested: lastID=0x%08x", lastID)

	// Wait for response
	msg, err := c.asyncConn.ExpectMessage(MsgAsyncLockResponse, c.config.Timeout)
	if err != nil {
		return err
	}

	if msg.Header.Control == CtrlLockSuccess || msg.Header.Control == CtrlLockFail {
		c.session.SetLockState(LockNone)
		c.log("Lock released")
		return nil
	}

	return fmt.Errorf("unexpected unlock response: ctrl=%d", msg.Header.Control)
}

// Status 从仪器查询状态字节。
func (c *Client) Status(ctx context.Context) (byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, ErrClosed
	}
	c.mu.RUnlock()

	// 参数是最近的消息 ID（用于 MAV 计算）
	lastID := c.session.LastSentID()
	if lastID == 0 {
		lastID = MessageIDClear
	}

	// 控制位 0: RMT-delivered
	ctrl := uint8(CtrlRMTDelivered)

	if err := c.asyncConn.SendMessage(MsgAsyncStatusQuery, ctrl, lastID, nil); err != nil {
		return 0, err
	}

	msg, err := c.asyncConn.ExpectMessage(MsgAsyncStatusResponse, c.config.Timeout)
	if err != nil {
		return 0, err
	}

	stb := msg.Header.Control
	c.log("Status: STB=0x%02x", stb)
	return stb, nil
}

// DeviceClear 执行设备清除操作。
// 清除输入/输出缓冲区并将设备重置为已知状态。
func (c *Client) DeviceClear(ctx context.Context) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	c.session.SetClearInProgress(true)
	defer c.session.SetClearInProgress(false)

	c.log("DeviceClear starting")

	// 步骤 1：在异步通道上发送 AsyncDeviceClear
	if err := c.asyncConn.SendMessage(MsgAsyncDeviceClear, 0, 0, nil); err != nil {
		return fmt.Errorf("send AsyncDeviceClear: %w", err)
	}

	// 步骤 2：等待 AsyncDeviceClearAcknowledge
	// 注意：需要处理清除期间可能到达的消息
	deadline := time.Now().Add(c.config.Timeout)
	for {
		if time.Now().After(deadline) {
			return ErrTimeout
		}

		msg, err := c.asyncConn.ReadWithTimeout(time.Until(deadline))
		if err != nil {
			return fmt.Errorf("wait AsyncDeviceClearAcknowledge: %w", err)
		}

		if msg.Header.MsgType == MsgAsyncDeviceClear {
			// 这是确认（相同的消息类型，只是响应）
			c.log("AsyncDeviceClearAcknowledge received")
			break
		}
		if msg.Header.MsgType == MsgFatalError {
			return NewFatalError(msg.Header.Control, msg.Payload)
		}
		// 清除期间丢弃其他消息
		c.log("discarding message during clear: %s", MsgTypeName(msg.Header.MsgType))
	}

	// 步骤 3：清除本地缓冲区 - 丢弃待处理响应
	c.tracker.Clear(ErrDeviceClear)

	// 步骤 4：在同步通道上发送 DeviceClearComplete
	if err := c.syncConn.SendMessage(MsgDeviceClearComplete, 0, 0, nil); err != nil {
		return fmt.Errorf("send DeviceClearComplete: %w", err)
	}

	// 步骤 5：等待 DeviceClearAcknowledge
	for {
		if time.Now().After(deadline) {
			return ErrTimeout
		}

		msg, err := c.syncConn.ReadWithTimeout(time.Until(deadline))
		if err != nil {
			return fmt.Errorf("wait DeviceClearAcknowledge: %w", err)
		}

		if msg.Header.MsgType == MsgDeviceClearAcknowledge {
			c.log("DeviceClearAcknowledge received")
			break
		}
		if msg.Header.MsgType == MsgFatalError {
			return NewFatalError(msg.Header.Control, msg.Payload)
		}
		// Discard other messages
		c.log("discarding message during clear: %s", MsgTypeName(msg.Header.MsgType))
	}

	// 步骤 6：重置会话状态
	c.session.Reset()

	c.log("DeviceClear complete")
	return nil
}

// Trigger 向仪器发送触发消息。
func (c *Client) Trigger() error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	msgID := c.session.NextMessageID()
	ctrl := uint8(CtrlRMTDelivered)

	c.log("Trigger: msgID=0x%08x", msgID)
	return c.syncConn.SendMessage(MsgTrigger, ctrl, msgID, nil)
}

// RemoteLocal 发送远程/本地控制命令。
func (c *Client) RemoteLocal(mode uint8) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	if err := c.asyncConn.SendMessage(MsgAsyncRemoteLocalControl, mode, 0, nil); err != nil {
		return err
	}

	_, err := c.asyncConn.ExpectMessage(MsgAsyncRemoteLocalResponse, c.config.Timeout)
	return err
}

// SetSRQCallback 设置服务请求通知的回调。
func (c *Client) SetSRQCallback(cb func(stb byte)) {
	c.srqMu.Lock()
	defer c.srqMu.Unlock()
	c.srqCallback = cb
}

// readLoopSync 处理同步通道上的传入消息。
func (c *Client) readLoopSync() {
	defer func() {
		c.log("sync read loop exited")
	}()

	for {
		select {
		case <-c.syncDone:
			return
		default:
		}

		msg, err := c.syncConn.ReadMessage()
		if err != nil {
			if err == io.EOF {
				c.log("sync connection closed by server")
			} else {
				c.log("sync read error: %v", err)
			}
			return
		}

		c.dispatchSync(msg)
	}
}

// readLoopAsync 处理异步通道上的传入消息。
func (c *Client) readLoopAsync() {
	defer func() {
		c.log("async read loop exited")
	}()

	for {
		select {
		case <-c.asyncDone:
			return
		default:
		}

		msg, err := c.asyncConn.ReadMessage()
		if err != nil {
			if err == io.EOF {
				c.log("async connection closed by server")
			} else {
				c.log("async read error: %v", err)
			}
			return
		}

		c.dispatchAsync(msg)
	}
}

// dispatchSync 处理在同步通道上接收的消息。
func (c *Client) dispatchSync(msg *Message) {
	c.log("sync recv: %s", msg.Header)

	switch msg.Header.MsgType {
	case MsgData, MsgDataEnd:
		// 在 overlapped 模式下路由到待处理查询
		if c.session.IsOverlapped() {
			msgID := msg.Header.Param
			if pq, ok := c.tracker.Get(msgID); ok {
				// 累积数据
				pq.response = append(pq.response, msg.Payload...)
				if msg.Header.MsgType == MsgDataEnd {
					c.tracker.Complete(msgID, pq.response, nil)
				}
			}
		} else {
			// 在同步模式下，转发到读取通道
			select {
			case c.syncResp <- msg:
			default:
				c.log("sync response channel full")
			}
		}

	case MsgInterrupted:
		c.log("Interrupted received, clearing buffers")
		c.tracker.Clear(ErrInterrupted)
		c.session.SetPendingResponse(false)

	case MsgFatalError:
		err := NewFatalError(msg.Header.Control, msg.Payload)
		c.log("FatalError: %v", err)
		c.tracker.Clear(err)
		c.Close()

	case MsgError:
		err := NewNonFatalError(msg.Header.Control, msg.Payload)
		c.log("Error: %v", err)

	case MsgDeviceClearAcknowledge:
		// 在 DeviceClear 方法中处理

	default:
		c.log("unhandled sync message: %s", MsgTypeName(msg.Header.MsgType))
	}
}

// dispatchAsync 处理在异步通道上接收的消息。
func (c *Client) dispatchAsync(msg *Message) {
	c.log("async recv: %s", msg.Header)

	switch msg.Header.MsgType {
	case MsgAsyncServiceRequest:
		// SRQ 通知
		stb := msg.Header.Control
		c.log("SRQ: STB=0x%02x", stb)
		c.srqMu.Lock()
		cb := c.srqCallback
		c.srqMu.Unlock()
		if cb != nil {
			go cb(stb)
		}

	case MsgAsyncInterrupted:
		c.log("AsyncInterrupted received")
		c.tracker.Clear(ErrInterrupted)

	case MsgFatalError:
		err := NewFatalError(msg.Header.Control, msg.Payload)
		c.log("FatalError: %v", err)
		c.tracker.Clear(err)
		c.Close()

	case MsgError:
		err := NewNonFatalError(msg.Header.Control, msg.Payload)
		c.log("Error: %v", err)

	default:
		// 路由到异步响应通道以进行特定操作
		select {
		case c.asyncResp <- msg:
		default:
			c.log("async response channel full, discarding: %s", MsgTypeName(msg.Header.MsgType))
		}
	}
}

// establishSecureConnection 根据 HiSLIP 2.0 规范执行 TLS 升级。
func (c *Client) establishSecureConnection(ctx context.Context) error {
	c.log("establishing secure connection")

	// 步骤 1：发送 AsyncStartTLS
	if err := c.asyncConn.SendMessage(MsgAsyncStartTLS, 0, 0, nil); err != nil {
		return fmt.Errorf("send AsyncStartTLS: %w", err)
	}

	// 步骤 2：等待 AsyncStartTLSResponse
	msg, err := c.asyncConn.ExpectMessage(MsgAsyncStartTLSResponse, c.config.Timeout)
	if err != nil {
		return fmt.Errorf("wait AsyncStartTLSResponse: %w", err)
	}

	if msg.Header.Control != CtrlTLSSuccess {
		return fmt.Errorf("server rejected TLS: ctrl=%d", msg.Header.Control)
	}

	// 步骤 3：将异步连接升级为 TLS
	if err := c.asyncConn.UpgradeToTLS(c.config.TLSConfig); err != nil {
		return fmt.Errorf("async TLS upgrade: %w", err)
	}

	// 步骤 4：在同步通道上发送 StartTLS
	if err := c.syncConn.SendMessage(MsgStartTLS, 0, 0, nil); err != nil {
		return fmt.Errorf("send StartTLS: %w", err)
	}

	// 步骤 5：将同步连接升级为 TLS
	if err := c.syncConn.UpgradeToTLS(c.config.TLSConfig); err != nil {
		return fmt.Errorf("sync TLS upgrade: %w", err)
	}

	c.session.SetEncrypted(true)
	c.log("secure connection established")
	return nil
}

// log 在配置了日志记录器时输出调试消息。
func (c *Client) log(format string, args ...interface{}) {
	if c.config.Logger != nil {
		c.config.Logger.Printf("[hislip] "+format, args...)
	}
}

// Session 返回客户端的会话状态。
func (c *Client) Session() *Session {
	return c.session
}

// IsConnected 返回客户端是否已连接。
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.syncConn != nil && !c.closed
}
