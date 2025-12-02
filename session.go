package gohislip

import (
	"sync"
	"sync/atomic"
)

// Mode 表示 HiSLIP 操作模式。
type Mode uint8

const (
	ModeSynchronized Mode = iota // 默认：每次一个查询
	ModeOverlapped               // 流水线：多个并发查询
)

// LockState 表示当前锁状态。
type LockState uint8

const (
	LockNone      LockState = iota // 未持有锁
	LockExclusive                  // 持有独占锁
	LockShared                     // 持有共享锁（HiSLIP 2.0）
)

// Session 维护 HiSLIP 会话的状态。
// 包括消息 ID 跟踪、锁状态、模式和协商参数。
type Session struct {
	// 连接标识
	sessionID uint16 // 初始化时由服务器分配

	// 协商的协议版本
	serverVersionMajor uint8
	serverVersionMinor uint8

	// 消息 ID 管理（原子操作以保证线程安全）
	messageID uint32

	// 操作模式
	mode Mode

	// 锁状态
	lockState LockState
	lockMu    sync.RWMutex

	// 协商的能力
	maxMessageSizeToServer   uint64 // 客户端可发送的最大消息大小
	maxMessageSizeFromServer uint64 // 服务器可发送的最大消息大小

	// 服务器能力（来自 AsyncInitializeResponse）
	serverVendorID uint16
	overlapped     bool // 服务器支持 overlap 模式
	secureConn     bool // 服务器支持安全连接

	// 加密状态
	encryptionMode uint8 // 来自 InitializeResponse
	encrypted      bool  // 当前是否加密

	// 设备清除进行中
	clearInProgress atomic.Bool

	// RMT（响应消息终止）跟踪
	// 在同步模式下，跟踪是否正在等待响应
	pendingResponse atomic.Bool
	lastSentID      uint32 // 我们发送的最后一个期望响应的 MessageID
	lastRecvID      uint32 // 我们收到的最后一个 MessageID

	mu sync.RWMutex // 通用状态保护
}

// NewSession 创建带默认值的新 Session。
func NewSession() *Session {
	return &Session{
		messageID:                InitialMessageID,
		mode:                     ModeSynchronized,
		lockState:                LockNone,
		maxMessageSizeToServer:   DefaultMaxMessageSize,
		maxMessageSizeFromServer: DefaultMaxMessageSize,
	}
}

// SessionID 返回服务器分配的会话 ID。
func (s *Session) SessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// SetSessionID 设置会话 ID（初始化后调用）。
func (s *Session) SetSessionID(id uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = id
}

// ServerVersion 返回协商的服务器协议版本。
func (s *Session) ServerVersion() (major, minor uint8) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverVersionMajor, s.serverVersionMinor
}

// SetServerVersion 设置协商的协议版本。
func (s *Session) SetServerVersion(major, minor uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverVersionMajor = major
	s.serverVersionMinor = minor
}

// IsVersion2OrHigher 返回服务器是否支持 HiSLIP 2.0 或更高版本。
// HiSLIP 2.0 增加了 TLS 加密、SASL 认证等功能。
func (s *Session) IsVersion2OrHigher() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverVersionMajor >= 2
}

// VersionAtLeast 检查服务器版本是否至少为指定版本。
func (s *Session) VersionAtLeast(major, minor uint8) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.serverVersionMajor > major {
		return true
	}
	if s.serverVersionMajor == major && s.serverVersionMinor >= minor {
		return true
	}
	return false
}

// NextMessageID 返回下一个消息 ID 并递增计数器。
// 根据规范 3.1.2：从 0xffffff00 开始，每次加 2。
func (s *Session) NextMessageID() uint32 {
	return atomic.AddUint32(&s.messageID, 2) - 2
}

// CurrentMessageID 返回当前消息 ID，不递增。
func (s *Session) CurrentMessageID() uint32 {
	return atomic.LoadUint32(&s.messageID)
}

// ResetMessageID 将消息 ID 重置为初始值。
// 在 DeviceClear 或初始化后调用。
func (s *Session) ResetMessageID() {
	atomic.StoreUint32(&s.messageID, InitialMessageID)
}

// SetMessageID 直接设置消息 ID。
func (s *Session) SetMessageID(id uint32) {
	atomic.StoreUint32(&s.messageID, id)
}

// Mode 返回当前操作模式。
func (s *Session) Mode() Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// SetMode 设置操作模式。
func (s *Session) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// IsOverlapped 返回是否处于 overlapped 模式。
func (s *Session) IsOverlapped() bool {
	return s.Mode() == ModeOverlapped
}

// LockState 返回当前锁状态。
func (s *Session) LockState() LockState {
	s.lockMu.RLock()
	defer s.lockMu.RUnlock()
	return s.lockState
}

// SetLockState 设置锁状态。
func (s *Session) SetLockState(state LockState) {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	s.lockState = state
}

// IsLocked 返回是否持有任何锁。
func (s *Session) IsLocked() bool {
	return s.LockState() != LockNone
}

// MaxMessageSizeToServer 返回发送的最大消息大小。
func (s *Session) MaxMessageSizeToServer() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxMessageSizeToServer
}

// SetMaxMessageSizeToServer 设置发送的最大消息大小。
func (s *Session) SetMaxMessageSizeToServer(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxMessageSizeToServer = size
}

// MaxMessageSizeFromServer 返回接收的最大消息大小。
func (s *Session) MaxMessageSizeFromServer() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxMessageSizeFromServer
}

// SetMaxMessageSizeFromServer 设置接收的最大消息大小。
func (s *Session) SetMaxMessageSizeFromServer(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxMessageSizeFromServer = size
}

// ServerVendorID 返回服务器的供应商 ID。
func (s *Session) ServerVendorID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverVendorID
}

// SetServerVendorID 设置服务器的供应商 ID。
func (s *Session) SetServerVendorID(id uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverVendorID = id
}

// SupportsOverlap 返回服务器是否支持 overlap 模式。
func (s *Session) SupportsOverlap() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.overlapped
}

// SetSupportsOverlap 设置服务器是否支持 overlap 模式。
func (s *Session) SetSupportsOverlap(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overlapped = v
}

// SupportsSecureConn 返回服务器是否支持安全连接。
func (s *Session) SupportsSecureConn() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secureConn
}

// SetSupportsSecureConn 设置服务器是否支持安全连接。
func (s *Session) SetSupportsSecureConn(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secureConn = v
}

// EncryptionMode 返回服务器的加密模式要求。
func (s *Session) EncryptionMode() uint8 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encryptionMode
}

// SetEncryptionMode 设置加密模式。
func (s *Session) SetEncryptionMode(mode uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptionMode = mode
}

// IsEncrypted 返回连接是否已加密。
func (s *Session) IsEncrypted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encrypted
}

// SetEncrypted 设置加密状态。
func (s *Session) SetEncrypted(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encrypted = v
}

// RequiresEncryption 返回服务器是否要求加密。
func (s *Session) RequiresEncryption() bool {
	return s.EncryptionMode() == EncryptionModeMandatory
}

// IsClearInProgress 返回设备清除是否进行中。
func (s *Session) IsClearInProgress() bool {
	return s.clearInProgress.Load()
}

// SetClearInProgress 设置设备清除状态。
func (s *Session) SetClearInProgress(v bool) {
	s.clearInProgress.Store(v)
}

// SetPendingResponse 设置是否正在等待响应。
func (s *Session) SetPendingResponse(v bool) {
	s.pendingResponse.Store(v)
}

// IsPendingResponse 返回是否正在等待响应。
func (s *Session) IsPendingResponse() bool {
	return s.pendingResponse.Load()
}

// SetLastSentID 记录我们发送的最后一个消息 ID。
func (s *Session) SetLastSentID(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSentID = id
}

// LastSentID 返回我们发送的最后一个消息 ID。
func (s *Session) LastSentID() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSentID
}

// SetLastRecvID 记录我们收到的最后一个消息 ID。
func (s *Session) SetLastRecvID(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRecvID = id
}

// LastRecvID 返回我们收到的最后一个消息 ID。
func (s *Session) LastRecvID() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRecvID
}

// Reset 重置会话状态（在 DeviceClear 时调用）。
func (s *Session) Reset() {
	s.ResetMessageID()
	s.SetPendingResponse(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSentID = 0
	s.lastRecvID = 0
}

// pendingQuery 跟踪等待响应的查询。
type pendingQuery struct {
	messageID uint32
	done      chan struct{}
	response  []byte
	err       error
}

// QueryTracker 管理 overlapped 模式下的待处理查询。
type QueryTracker struct {
	mu      sync.Mutex
	pending map[uint32]*pendingQuery
}

// NewQueryTracker 创建新的 QueryTracker。
func NewQueryTracker() *QueryTracker {
	return &QueryTracker{
		pending: make(map[uint32]*pendingQuery),
	}
}

// Add 注册待处理查询。
func (qt *QueryTracker) Add(messageID uint32) *pendingQuery {
	qt.mu.Lock()
	defer qt.mu.Unlock()

	pq := &pendingQuery{
		messageID: messageID,
		done:      make(chan struct{}),
	}
	qt.pending[messageID] = pq
	return pq
}

// Get 根据消息 ID 返回待处理查询。
func (qt *QueryTracker) Get(messageID uint32) (*pendingQuery, bool) {
	qt.mu.Lock()
	defer qt.mu.Unlock()
	pq, ok := qt.pending[messageID]
	return pq, ok
}

// Complete 将查询标记为已完成，并设置响应或错误。
func (qt *QueryTracker) Complete(messageID uint32, response []byte, err error) {
	qt.mu.Lock()
	pq, ok := qt.pending[messageID]
	if ok {
		delete(qt.pending, messageID)
	}
	qt.mu.Unlock()

	if ok {
		pq.response = response
		pq.err = err
		close(pq.done)
	}
}

// Clear 移除所有待处理查询并设置错误。
func (qt *QueryTracker) Clear(err error) {
	qt.mu.Lock()
	pending := qt.pending
	qt.pending = make(map[uint32]*pendingQuery)
	qt.mu.Unlock()

	for _, pq := range pending {
		pq.err = err
		close(pq.done)
	}
}

// Count 返回待处理查询的数量。
func (qt *QueryTracker) Count() int {
	qt.mu.Lock()
	defer qt.mu.Unlock()
	return len(qt.pending)
}
