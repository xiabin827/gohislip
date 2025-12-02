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

	session  *Session
	tracker  *QueryTracker // 同步通道（overlapped 查询）
	atracker *AsyncTracker // 异步通道请求/响应

	config *ClientConfig

	// 读取循环
	syncDone  chan struct{}
	asyncDone chan struct{}

	// 同步通道响应（overlapped 模式）
	syncResp chan *Message

	// 专用操作通道
	deviceClearAck chan struct{} // DeviceClear 异步确认

	// SRQ（服务请求）回调
	srqCallback func(stb byte)
	srqMu       sync.Mutex

	// 状态
	mu     sync.RWMutex
	closed bool

	// 用于同步模式查询处理
	queryMu          sync.Mutex
	readLoopsStarted bool // 读取循环是否已启动（用于 StartTLS 路径区分）
}

// NewClient 创建新的 HiSLIP 客户端，但尚未连接。
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	return &Client{
		session:        NewSession(),
		tracker:        NewQueryTracker(),
		atracker:       NewAsyncTracker(),
		config:         config,
		syncDone:       make(chan struct{}),
		asyncDone:      make(chan struct{}),
		syncResp:       make(chan *Message, 16),
		deviceClearAck: make(chan struct{}, 1),
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
	// 同步模式下不启动 syncReadLoop，避免与 Read/Query 竞争
	// overlapped 模式下需要 readLoopSync 来分发响应
	if c.session.Mode() == ModeOverlapped {
		go c.readLoopSync()
	}
	go c.readLoopAsync()
	c.readLoopsStarted = true

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

	// 协议版本兼容性检查
	// HiSLIP 2.0 向后兼容 1.x，但某些功能仅在 2.0 可用
	if major < 1 {
		return fmt.Errorf("unsupported protocol version %d.%d (minimum 1.0)", major, minor)
	}

	// 解析参数: overlap | encryption_mode | session_id
	overlap, encMode, sessionID := ParseInitializeResponseParam(msg.Header.Param)
	c.session.SetSessionID(sessionID)
	c.session.SetSupportsOverlap(overlap)
	c.session.SetEncryptionMode(encMode)

	// 根据协商设置模式
	if overlap && c.config.UseOverlappedMode {
		c.session.SetMode(ModeOverlapped)
	}

	// 加密模式仅在 HiSLIP 2.0+ 中有效
	if major < 2 && encMode != EncryptionModeNone {
		c.log("warning: encryption mode in pre-2.0 server response, ignoring")
		c.session.SetEncryptionMode(EncryptionModeNone)
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
// 根据 HiSLIP 2.0 规范（IVI-6.1）第 4.6 节：
// - AsyncMaximumMessageSize (消息类型 15): control=0, param=0, payload=8字节(64位大小，大端序)
// - AsyncMaximumMessageSizeResponse (消息类型 16): control=0, param=0, payload=8字节(协商后的大小)
// 注意：HiSLIP 1.x 也支持此消息，但返回的大小可能不同
func (c *Client) negotiateMaxMessageSize() error {
	// 构造 8 字节的负载（64 位最大消息大小，大端序）
	maxSize := DefaultMaxMessageSize
	payload := encodeUint64(maxSize)

	// 根据规范: control=0, param=0, payload 包含完整的 64 位值。
	// 由于此时尚未启动异步读取循环，仍可直接在 asyncConn 上发送并等待响应。
	if err := c.asyncConn.SendMessage(MsgAsyncMaximumMessageSize, 0, 0, payload); err != nil {
		return err
	}

	resp, err := c.asyncConn.ExpectMessage(MsgAsyncMaximumMessageSizeResp, c.config.Timeout)
	if err != nil {
		return err
	}

	// 解析服务器返回的协商大小
	if len(resp.Payload) < 8 {
		return fmt.Errorf("AsyncMaximumMessageSizeResponse payload too short: %d bytes", len(resp.Payload))
	}

	serverMax := decodeUint64(resp.Payload)

	// 更新会话中的最大消息大小
	// 实际使用时应取客户端和服务器的较小值
	negotiatedSize := serverMax
	if maxSize < serverMax {
		negotiatedSize = maxSize
	}

	c.session.SetMaxMessageSizeFromServer(serverMax)
	c.session.SetMaxMessageSizeToServer(negotiatedSize)
	c.log("negotiated max message size: client=%d, server=%d, using=%d",
		maxSize, serverMax, negotiatedSize)

	return nil
}

// encodeUint64 将 uint64 编码为 8 字节大端序切片
func encodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}

// decodeUint64 从 8 字节大端序切片解码 uint64
func decodeUint64(b []byte) uint64 {
	return uint64(b[0])<<56 |
		uint64(b[1])<<48 |
		uint64(b[2])<<40 |
		uint64(b[3])<<32 |
		uint64(b[4])<<24 |
		uint64(b[5])<<16 |
		uint64(b[6])<<8 |
		uint64(b[7])
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

	// 检查消息大小是否超过协商的最大值
	maxSize := c.session.MaxMessageSizeToServer()
	if uint64(len(data)) > maxSize {
		return fmt.Errorf("%w: payload %d bytes exceeds max %d", ErrMessageTooLarge, len(data), maxSize)
	}

	// 获取下一个消息 ID
	msgID := c.session.NextMessageID()

	// 控制: RMT-delivered 位
	ctrl := uint8(CtrlRMTDelivered)

	c.log("Write: msgID=0x%08x len=%d", msgID, len(data))

	// 发送 DataEnd（完整消息）
	if err := c.syncConn.SendMessage(MsgDataEnd, ctrl, msgID, data); err != nil {
		return err
	}

	// 记录最后发送的消息 ID，用于 Interrupted 逻辑和状态查询
	c.session.SetLastSentID(msgID)
	c.session.SetPendingResponse(true)
	return nil
}

// Read 从仪器读取响应数据。
func (c *Client) Read() ([]byte, error) {
	return c.ReadWithTimeout(c.config.Timeout)
}

// ReadWithTimeout 使用自定义超时读取响应。
// 同步模式下直接从连接读取，overlapped 模式下从 syncResp 通道读取。
func (c *Client) ReadWithTimeout(timeout time.Duration) ([]byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClosed
	}
	c.mu.RUnlock()

	if c.session.Mode() == ModeOverlapped {
		return c.readOverlapped(timeout)
	}
	return c.readSynchronized(timeout)
}

// readSynchronized 在同步模式下直接从连接读取响应。
func (c *Client) readSynchronized(timeout time.Duration) ([]byte, error) {
	var result bytes.Buffer
	deadline := time.Now().Add(timeout)
	maxSize := c.session.MaxMessageSizeFromServer()

	for {
		// 设置读取截止时间
		remaining := time.Until(deadline)
		if remaining <= 0 {
			c.session.SetPendingResponse(false)
			return nil, ErrTimeout
		}

		msg, err := c.syncConn.ReadWithTimeout(remaining)
		if err != nil {
			c.session.SetPendingResponse(false)
			return nil, err
		}

		// 检查接收消息大小是否超过协商的最大值
		if msg.Header.Length > maxSize {
			c.session.SetPendingResponse(false)
			c.log("received message exceeds max size: %d > %d", msg.Header.Length, maxSize)
			return nil, fmt.Errorf("%w: received %d bytes, max %d", ErrMessageTooLarge, msg.Header.Length, maxSize)
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
			c.session.SetPendingResponse(false)
			c.log("Read complete: msgID=0x%08x len=%d", msg.Header.Param, result.Len())
			return result.Bytes(), nil

		case MsgFatalError:
			c.session.SetPendingResponse(false)
			return nil, NewFatalError(msg.Header.Control, msg.Payload)

		case MsgError:
			c.session.SetPendingResponse(false)
			return nil, NewNonFatalError(msg.Header.Control, msg.Payload)

		case MsgInterrupted:
			// 清除缓冲区并返回错误
			c.log("Interrupted received")
			c.session.SetPendingResponse(false)
			return nil, ErrInterrupted

		default:
			c.log("unexpected message type during read: %s", MsgTypeName(msg.Header.MsgType))
		}
	}
}

// readOverlapped 在 overlapped 模式下从 syncResp 通道读取响应。
func (c *Client) readOverlapped(timeout time.Duration) ([]byte, error) {
	var result bytes.Buffer
	deadline := time.Now().Add(timeout)
	maxSize := c.session.MaxMessageSizeFromServer()

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			c.session.SetPendingResponse(false)
			return nil, ErrTimeout
		}

		select {
		case msg := <-c.syncResp:
			// 检查接收消息大小是否超过协商的最大值
			if msg.Header.Length > maxSize {
				c.session.SetPendingResponse(false)
				c.log("received message exceeds max size: %d > %d", msg.Header.Length, maxSize)
				return nil, fmt.Errorf("%w: received %d bytes, max %d", ErrMessageTooLarge, msg.Header.Length, maxSize)
			}

			switch msg.Header.MsgType {
			case MsgData:
				result.Write(msg.Payload)
				c.session.SetLastRecvID(msg.Header.Param)

			case MsgDataEnd:
				result.Write(msg.Payload)
				c.session.SetLastRecvID(msg.Header.Param)
				c.session.SetPendingResponse(false)
				c.log("Read complete: msgID=0x%08x len=%d", msg.Header.Param, result.Len())
				return result.Bytes(), nil

			case MsgFatalError:
				c.session.SetPendingResponse(false)
				return nil, NewFatalError(msg.Header.Control, msg.Payload)

			case MsgError:
				c.session.SetPendingResponse(false)
				return nil, NewNonFatalError(msg.Header.Control, msg.Payload)

			case MsgInterrupted:
				c.log("Interrupted received")
				c.session.SetPendingResponse(false)
				return nil, ErrInterrupted

			default:
				c.log("unexpected message type during read: %s", MsgTypeName(msg.Header.MsgType))
			}

		case <-time.After(remaining):
			c.session.SetPendingResponse(false)
			return nil, ErrTimeout
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
	if c.session.IsClearInProgress() {
		return nil, ErrDeviceClear
	}

	// 检查消息大小是否超过协商的最大值
	maxSize := c.session.MaxMessageSizeToServer()
	if uint64(len(cmd)) > maxSize {
		return nil, fmt.Errorf("%w: payload %d bytes exceeds max %d", ErrMessageTooLarge, len(cmd), maxSize)
	}

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

	// 记录最后发送的消息 ID
	c.session.SetLastSentID(msgID)
	c.session.SetPendingResponse(true)

	// Wait for response
	select {
	case <-pq.done:
		c.session.SetPendingResponse(false)
		return pq.response, pq.err
	case <-time.After(c.config.Timeout):
		c.tracker.Complete(msgID, nil, ErrTimeout)
		c.session.SetPendingResponse(false)
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
	ch, err := c.atracker.Register(MsgAsyncLockResponse)
	if err != nil {
		return fmt.Errorf("lock already in progress: %w", err)
	}

	if err := c.asyncConn.SendMessage(MsgAsyncLock, CtrlLockRequest, timeoutMs, nil); err != nil {
		c.atracker.Cancel(MsgAsyncLockResponse, err)
		return err
	}

	c.log("Lock requested: timeout=%v", timeout)

	waitTimeout := timeout + time.Second
	select {
	case res := <-ch:
		if res.err != nil {
			return res.err
		}
		msg := res.msg
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
	case <-time.After(waitTimeout):
		c.atracker.Cancel(MsgAsyncLockResponse, ErrTimeout)
		return ErrTimeout
	case <-ctx.Done():
		c.atracker.Cancel(MsgAsyncLockResponse, ctx.Err())
		return ctx.Err()
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

	ch, err := c.atracker.Register(MsgAsyncLockResponse)
	if err != nil {
		return fmt.Errorf("unlock already in progress: %w", err)
	}

	if err := c.asyncConn.SendMessage(MsgAsyncLock, CtrlLockRelease, lastID, nil); err != nil {
		c.atracker.Cancel(MsgAsyncLockResponse, err)
		return err
	}

	c.log("Unlock requested: lastID=0x%08x", lastID)

	select {
	case res := <-ch:
		if res.err != nil {
			return res.err
		}
		msg := res.msg
		if msg.Header.Control == CtrlLockSuccess || msg.Header.Control == CtrlLockFail {
			c.session.SetLockState(LockNone)
			c.log("Lock released")
			return nil
		}
		return fmt.Errorf("unexpected unlock response: ctrl=%d", msg.Header.Control)
	case <-time.After(c.config.Timeout):
		c.atracker.Cancel(MsgAsyncLockResponse, ErrTimeout)
		return ErrTimeout
	case <-ctx.Done():
		c.atracker.Cancel(MsgAsyncLockResponse, ctx.Err())
		return ctx.Err()
	}
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

	ch, err := c.atracker.Register(MsgAsyncStatusResponse)
	if err != nil {
		return 0, fmt.Errorf("status query already in progress: %w", err)
	}

	if err := c.asyncConn.SendMessage(MsgAsyncStatusQuery, ctrl, lastID, nil); err != nil {
		c.atracker.Cancel(MsgAsyncStatusResponse, err)
		return 0, err
	}

	select {
	case res := <-ch:
		if res.err != nil {
			return 0, res.err
		}
		stb := res.msg.Header.Control
		c.log("Status: STB=0x%02x", stb)
		return stb, nil
	case <-time.After(c.config.Timeout):
		c.atracker.Cancel(MsgAsyncStatusResponse, ErrTimeout)
		return 0, ErrTimeout
	case <-ctx.Done():
		c.atracker.Cancel(MsgAsyncStatusResponse, ctx.Err())
		return 0, ctx.Err()
	}
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

	// 清空可能残留的确认信号
	select {
	case <-c.deviceClearAck:
	default:
	}

	// 步骤 1：在异步通道上发送 AsyncDeviceClear
	if err := c.asyncConn.SendMessage(MsgAsyncDeviceClear, 0, 0, nil); err != nil {
		return fmt.Errorf("send AsyncDeviceClear: %w", err)
	}

	// 步骤 2：等待 AsyncDeviceClearAcknowledge
	// 确认消息由 readLoopAsync -> dispatchAsync 接收并发送到 deviceClearAck
	select {
	case <-c.deviceClearAck:
		c.log("AsyncDeviceClearAcknowledge received")
	case <-time.After(c.config.Timeout):
		return ErrTimeout
	case <-ctx.Done():
		return ctx.Err()
	}

	// 步骤 3：清除本地缓冲区 - 丢弃待处理响应
	c.tracker.Clear(ErrDeviceClear)

	// 步骤 4 & 5：同步通道上的 DeviceClearComplete/Acknowledge
	// 在 overlapped 模式下，syncConn 由 readLoopSync 读取，需要通过 syncResp 等待
	if c.session.Mode() == ModeOverlapped {
		if err := c.deviceClearSyncOverlapped(ctx); err != nil {
			return err
		}
	} else {
		if err := c.deviceClearSyncDirect(ctx); err != nil {
			return err
		}
	}

	// 步骤 6：重置会话状态
	c.session.Reset()

	c.log("DeviceClear complete")
	return nil
}

// deviceClearSyncDirect 在同步模式下直接处理同步通道清除
func (c *Client) deviceClearSyncDirect(ctx context.Context) error {
	deadline := time.Now().Add(c.config.Timeout)

	// 发送 DeviceClearComplete
	if err := c.syncConn.SendMessage(MsgDeviceClearComplete, 0, 0, nil); err != nil {
		return fmt.Errorf("send DeviceClearComplete: %w", err)
	}

	// 等待 DeviceClearAcknowledge
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
			return nil
		}
		if msg.Header.MsgType == MsgFatalError {
			return NewFatalError(msg.Header.Control, msg.Payload)
		}
		// 清除期间丢弃其他消息
		c.log("discarding message during clear: %s", MsgTypeName(msg.Header.MsgType))
	}
}

// deviceClearSyncOverlapped 在 overlapped 模式下通过 syncResp 等待同步通道清除确认
func (c *Client) deviceClearSyncOverlapped(ctx context.Context) error {
	// 发送 DeviceClearComplete
	if err := c.syncConn.SendMessage(MsgDeviceClearComplete, 0, 0, nil); err != nil {
		return fmt.Errorf("send DeviceClearComplete: %w", err)
	}

	// 等待 DeviceClearAcknowledge 通过 syncResp（由 dispatchSync 处理）
	deadline := time.Now().Add(c.config.Timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrTimeout
		}

		select {
		case msg := <-c.syncResp:
			if msg.Header.MsgType == MsgDeviceClearAcknowledge {
				c.log("DeviceClearAcknowledge received")
				return nil
			}
			if msg.Header.MsgType == MsgFatalError {
				return NewFatalError(msg.Header.Control, msg.Payload)
			}
			// 清除期间丢弃其他消息
			c.log("discarding message during clear: %s", MsgTypeName(msg.Header.MsgType))
		case <-time.After(remaining):
			return ErrTimeout
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Trigger 向仪器发送触发消息。
func (c *Client) Trigger() error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	if c.session.IsClearInProgress() {
		return ErrDeviceClear
	}

	msgID := c.session.NextMessageID()
	ctrl := uint8(CtrlRMTDelivered)

	c.log("Trigger: msgID=0x%08x", msgID)

	if err := c.syncConn.SendMessage(MsgTrigger, ctrl, msgID, nil); err != nil {
		return err
	}

	// 记录最后发送的消息 ID
	c.session.SetLastSentID(msgID)
	// Trigger 不期望响应，不设置 PendingResponse
	return nil
}

// RemoteLocal 发送远程/本地控制命令。
func (c *Client) RemoteLocal(mode uint8) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClosed
	}
	c.mu.RUnlock()

	ch, err := c.atracker.Register(MsgAsyncRemoteLocalResponse)
	if err != nil {
		return fmt.Errorf("remote/local operation already in progress: %w", err)
	}

	if err := c.asyncConn.SendMessage(MsgAsyncRemoteLocalControl, mode, 0, nil); err != nil {
		c.atracker.Cancel(MsgAsyncRemoteLocalResponse, err)
		return err
	}

	select {
	case res := <-ch:
		return res.err
	case <-time.After(c.config.Timeout):
		c.atracker.Cancel(MsgAsyncRemoteLocalResponse, ErrTimeout)
		return ErrTimeout
	}
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
			// 通知所有等待异步结果的操作
			c.atracker.Fail(err)
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
		// 在 overlapped 模式下，先尝试路由到待处理查询
		if c.session.IsOverlapped() {
			msgID := msg.Header.Param
			if pq, ok := c.tracker.Get(msgID); ok {
				// 累积数据到查询跟踪器
				pq.response = append(pq.response, msg.Payload...)
				if msg.Header.MsgType == MsgDataEnd {
					c.tracker.Complete(msgID, pq.response, nil)
				}
				return
			}
		}

		select {
		case c.syncResp <- msg:
		default:
			c.log("sync response channel full")
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
		// 在 overlapped 模式下转发到 syncResp 供 DeviceClear 等待
		select {
		case c.syncResp <- msg:
		default:
			c.log("sync response channel full for DeviceClearAcknowledge")
		}

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
		c.atracker.Fail(ErrInterrupted)

	case MsgAsyncDeviceClear:
		// 服务器用 AsyncDeviceClear 消息响应客户端的 AsyncDeviceClear 请求（规范 5.2）
		c.log("AsyncDeviceClear response received")
		select {
		case c.deviceClearAck <- struct{}{}:
		default:
			// 没有等待者，忽略
		}

	case MsgFatalError:
		err := NewFatalError(msg.Header.Control, msg.Payload)
		c.log("FatalError: %v", err)
		c.tracker.Clear(err)
		c.atracker.Fail(err)
		c.Close()

	case MsgError:
		err := NewNonFatalError(msg.Header.Control, msg.Payload)
		c.log("Error: %v", err)
		// 无法精确关联到具体操作，只能让所有等待的异步操作失败
		c.atracker.Fail(err)

	default:
		// 尝试投递给等待该类型响应的异步操作
		if !c.atracker.Complete(msg) {
			c.log("unhandled async message: %s", MsgTypeName(msg.Header.MsgType))
		}
	}
}

// establishSecureConnection 根据 HiSLIP 2.0 规范执行 TLS 升级。
func (c *Client) establishSecureConnection(ctx context.Context) error {
	c.log("establishing secure connection")

	// 在 Connect 期间尚未启动异步读取循环，可以直接在 asyncConn 上等待响应。
	if !c.readLoopsStarted {
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
	} else {
		// 连接建立后，异步读取循环已启动，必须通过 AsyncTracker 协调响应。
		ch, err := c.atracker.Register(MsgAsyncStartTLSResponse)
		if err != nil {
			return fmt.Errorf("register AsyncStartTLSResponse waiter: %w", err)
		}

		if err := c.asyncConn.SendMessage(MsgAsyncStartTLS, 0, 0, nil); err != nil {
			c.atracker.Cancel(MsgAsyncStartTLSResponse, err)
			return fmt.Errorf("send AsyncStartTLS: %w", err)
		}

		deadline := mergeDeadline(ctx, c.config.Timeout)
		timeout := time.Until(deadline)
		if timeout <= 0 {
			c.atracker.Cancel(MsgAsyncStartTLSResponse, ErrTimeout)
			return ErrTimeout
		}

		select {
		case res := <-ch:
			if res.err != nil {
				return fmt.Errorf("wait AsyncStartTLSResponse: %w", res.err)
			}
			if res.msg.Header.Control != CtrlTLSSuccess {
				return fmt.Errorf("server rejected TLS: ctrl=%d", res.msg.Header.Control)
			}
		case <-time.After(timeout):
			c.atracker.Cancel(MsgAsyncStartTLSResponse, ErrTimeout)
			return ErrTimeout
		case <-ctx.Done():
			c.atracker.Cancel(MsgAsyncStartTLSResponse, ctx.Err())
			return ctx.Err()
		}
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
