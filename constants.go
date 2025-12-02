// Package gohislip 实现 HiSLIP 2.0 协议 (IVI-6.1)，
// 用于通过 TCP/IP 控制测试测量仪器。
package gohislip

// 协议常量
const (
	// 序言字节 "HS"
	PrologueHi byte = 'H'
	PrologueLo byte = 'S'

	// HiSLIP 默认端口
	DefaultPort = 4880

	// 消息头大小（字节）
	HeaderSize = 16

	// 初始 MessageID（规范 3.1.2）
	InitialMessageID uint32 = 0xffffff00

	// 无消息时用于"最近消息 ID"的 MessageID
	MessageIDClear uint32 = 0xfffffefe

	// 协议版本（major.minor 编码为 uint16: major<<8 | minor）
	ProtocolVersionMajor uint8  = 2
	ProtocolVersionMinor uint8  = 0
	ProtocolVersion      uint16 = uint16(ProtocolVersionMajor)<<8 | uint16(ProtocolVersionMinor)

	// 默认最大负载大小（可协商）
	DefaultMaxMessageSize uint64 = 256 * 1024 * 1024 // 256 MB
)

// 消息类型（规范表 4）
const (
	MsgInitialize                   uint8 = 0
	MsgInitializeResponse           uint8 = 1
	MsgFatalError                   uint8 = 2
	MsgError                        uint8 = 3
	MsgAsyncLock                    uint8 = 4
	MsgAsyncLockResponse            uint8 = 5
	MsgData                         uint8 = 6
	MsgDataEnd                      uint8 = 7
	MsgDeviceClearComplete          uint8 = 8
	MsgDeviceClearAcknowledge       uint8 = 9
	MsgAsyncRemoteLocalControl      uint8 = 10
	MsgAsyncRemoteLocalResponse     uint8 = 11
	MsgTrigger                      uint8 = 12
	MsgInterrupted                  uint8 = 13
	MsgAsyncInterrupted             uint8 = 14
	MsgAsyncMaximumMessageSize      uint8 = 15
	MsgAsyncMaximumMessageSizeResp  uint8 = 16
	MsgAsyncInitialize              uint8 = 17
	MsgAsyncInitializeResponse      uint8 = 18
	MsgAsyncDeviceClear             uint8 = 19
	MsgAsyncServiceRequest          uint8 = 20
	MsgAsyncStatusQuery             uint8 = 21
	MsgAsyncStatusResponse          uint8 = 22
	MsgAsyncLockInfo                uint8 = 24
	MsgAsyncLockInfoResponse        uint8 = 25
	MsgGetDescriptors               uint8 = 26
	MsgGetDescriptorsResponse       uint8 = 27
	MsgStartTLS                     uint8 = 28
	MsgAsyncStartTLS                uint8 = 29
	MsgAsyncStartTLSResponse        uint8 = 30
	MsgEndTLS                       uint8 = 31
	MsgAsyncEndTLS                  uint8 = 32
	MsgAsyncEndTLSResponse          uint8 = 33
	MsgGetSaslMechanismList         uint8 = 34
	MsgGetSaslMechanismListResponse uint8 = 35
	MsgAuthenticationStart          uint8 = 36
	MsgAuthenticationExchange       uint8 = 37
	MsgAuthenticationResult         uint8 = 38
	MsgVendorSpecificMin            uint8 = 128
)

// 各种消息的控制码位
const (
	// Data/DataEnd 控制位
	CtrlRMTDelivered uint8 = 0x01 // bit 0: RMT-delivered 位

	// AsyncLock 控制码
	CtrlLockRelease         uint8 = 0 // 释放锁
	CtrlLockRequest         uint8 = 1 // 请求独占锁
	CtrlLockRequestResponse uint8 = 2 // 请求共享锁（仅 v2.0，保留）

	// AsyncLockResponse 控制码
	CtrlLockSuccess    uint8 = 1 // 锁已获取
	CtrlLockFail       uint8 = 0 // 锁失败（超时）
	CtrlLockSharedFail uint8 = 2 // 共享锁失败
	CtrlLockError      uint8 = 3 // 锁错误

	// AsyncRemoteLocalControl 控制码
	CtrlDisableRemote  uint8 = 0
	CtrlEnableRemote   uint8 = 1
	CtrlDisableAndGTL  uint8 = 2
	CtrlEnableAndGTL   uint8 = 3
	CtrlEnableAndLLO   uint8 = 4
	CtrlEnableAndGTLLO uint8 = 5
	CtrlEnableLockout  uint8 = 6

	// AsyncStartTLS / AsyncStartTLSResponse 控制码
	CtrlTLSSuccess    uint8 = 0
	CtrlTLSFail       uint8 = 1
	CtrlTLSInProgress uint8 = 2

	// AuthenticationResult 控制码
	CtrlAuthSuccess  uint8 = 0
	CtrlAuthFail     uint8 = 1
	CtrlAuthContinue uint8 = 2
)

// 加密模式标志（来自 InitializeResponse）
const (
	EncryptionModeNone      uint8 = 0 // 不支持加密
	EncryptionModeOptional  uint8 = 1 // 加密可选
	EncryptionModeMandatory uint8 = 2 // 加密必须
)

// InitializeResponse 中的功能标志
const (
	FeatureOverlapMode      uint8 = 0x01 // bit 0: 支持 overlap 模式
	FeatureSecureConnection uint8 = 0x02 // bit 1: 支持安全连接
)
