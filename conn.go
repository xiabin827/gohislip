package gohislip

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Conn 封装 TCP 连接，提供带缓冲的 I/O 和同步机制。
type Conn struct {
	raw    net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	mu     sync.Mutex // 保护写操作

	// 用于 TLS 升级
	tlsConn *tls.Conn
	isTLS   bool
}

// NewConn 创建一个新的 Conn，封装给定的 net.Conn。
func NewConn(c net.Conn) *Conn {
	return &Conn{
		raw:    c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
	}
}

// Read 从连接读取数据到 p。
func (c *Conn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

// Write 向连接写入数据。
func (c *Conn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err = c.writer.Write(p)
	if err != nil {
		return n, err
	}
	return n, c.writer.Flush()
}

// Close 关闭底层连接。
func (c *Conn) Close() error {
	return c.raw.Close()
}

// SetDeadline 设置读写超时时间。
func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

// SetReadDeadline 设置读取超时时间。
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入超时时间。
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

// LocalAddr 返回本地网络地址。
func (c *Conn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

// RemoteAddr 返回远程网络地址。
func (c *Conn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

// IsTLS 返回连接是否已升级为 TLS。
func (c *Conn) IsTLS() bool {
	return c.isTLS
}

// UpgradeToTLS 将连接升级为 TLS。
// 应在收到 StartTLS/AsyncStartTLS 后调用。
func (c *Conn) UpgradeToTLS(config *tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 先刷新缓冲区中的数据
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("flush before TLS: %w", err)
	}

	// 执行 TLS 握手
	tlsConn := tls.Client(c.raw, config)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	// 用 TLS 连接替换 reader/writer
	c.tlsConn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = bufio.NewWriter(tlsConn)
	c.isTLS = true

	return nil
}

// DowngradeFromTLS 从 TLS 降级为普通 TCP。
// 协议支持但很少使用。
func (c *Conn) DowngradeFromTLS() error {
	if !c.isTLS {
		return nil
	}

	// Go 标准库不支持从 tls.Conn 中“降级”回原始 TCP 连接；
	// 一旦关闭 TLS，底层连接也会被关闭。因此这里明确返回不支持，
	// 调用方应主动关闭连接并重新建立非 TLS 会话。
	return fmt.Errorf("DowngradeFromTLS is not supported; close and reconnect without TLS instead")
}

// ReadMessage 从连接读取一条完整的 HiSLIP 消息。
func (c *Conn) ReadMessage() (*Message, error) {
	return ReadMessage(c.reader)
}

// WriteMessage 向连接写入一条完整的 HiSLIP 消息。
func (c *Conn) WriteMessage(m *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := WriteMessage(c.writer, m); err != nil {
		return err
	}
	return c.writer.Flush()
}

// SendMessage 是创建并发送消息的便捷方法。
func (c *Conn) SendMessage(msgType, ctrl uint8, param uint32, payload []byte) error {
	return c.WriteMessage(NewMessage(msgType, ctrl, param, payload))
}

// DialConn 连接到指定地址的 HiSLIP 服务器。
func DialConn(address string) (*Conn, error) {
	return DialContext(context.Background(), address)
}

// DialContext 使用 context 连接到 HiSLIP 服务器。
func DialContext(ctx context.Context, address string) (*Conn, error) {
	// 如果未指定端口，添加默认端口
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// 假设未指定端口
		host = address
		port = fmt.Sprintf("%d", DefaultPort)
	}
	address = net.JoinHostPort(host, port)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}

	return NewConn(conn), nil
}

// DialConnTLS 通过 TLS 连接到 HiSLIP 服务器。
// 注意：标准 HiSLIP 以非加密方式启动，然后通过 StartTLS 升级。
// 此函数用于从一开始就要求 TLS 的服务器。
func DialConnTLS(address string, config *tls.Config) (*Conn, error) {
	return DialTLSContext(context.Background(), address, config)
}

// DialTLSContext 使用 context 通过 TLS 连接到 HiSLIP 服务器。
func DialTLSContext(ctx context.Context, address string, config *tls.Config) (*Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = fmt.Sprintf("%d", DefaultPort)
	}
	address = net.JoinHostPort(host, port)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	c := &Conn{
		raw:     conn,
		tlsConn: tlsConn,
		reader:  bufio.NewReader(tlsConn),
		writer:  bufio.NewWriter(tlsConn),
		isTLS:   true,
	}
	return c, nil
}

// messageReader 提供带可选超时的消息读取便捷方式。
type messageReader struct {
	conn    *Conn
	timeout time.Duration
}

// ReadWithTimeout 在指定超时时间内读取消息。
func (c *Conn) ReadWithTimeout(timeout time.Duration) (*Message, error) {
	if timeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer c.SetReadDeadline(time.Time{})
	}
	return c.ReadMessage()
}

// ExpectMessage 读取消息并验证其类型是否符合预期。
func (c *Conn) ExpectMessage(expectedType uint8, timeout time.Duration) (*Message, error) {
	msg, err := c.ReadWithTimeout(timeout)
	if err != nil {
		return nil, err
	}

	// 检查错误消息
	if msg.Header.MsgType == MsgFatalError {
		return nil, NewFatalError(msg.Header.Control, msg.Payload)
	}
	if msg.Header.MsgType == MsgError {
		return nil, NewNonFatalError(msg.Header.Control, msg.Payload)
	}

	if msg.Header.MsgType != expectedType {
		return nil, NewProtocolError("expect message",
			MsgTypeName(expectedType),
			MsgTypeName(msg.Header.MsgType))
	}

	return msg, nil
}

// Discard 读取并丢弃数据直到 EOF 或出错。
// 用于 Device Clear 时清空缓冲区。
func (c *Conn) Discard() error {
	_, err := io.Copy(io.Discard, c.reader)
	return err
}
