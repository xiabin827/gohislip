// Package gohislip 实现 HiSLIP 2.0 协议 (IVI-6.1)，
// 用于通过 TCP/IP 控制测试测量仪器。
package gohislip

import (
	"encoding/binary"
	"fmt"
	"io"
)

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

	// 无消息时用于“最近消息 ID”的 MessageID
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

// 消息类型名称（用于调试）
var msgTypeNames = map[uint8]string{
	MsgInitialize:                   "Initialize",
	MsgInitializeResponse:           "InitializeResponse",
	MsgFatalError:                   "FatalError",
	MsgError:                        "Error",
	MsgAsyncLock:                    "AsyncLock",
	MsgAsyncLockResponse:            "AsyncLockResponse",
	MsgData:                         "Data",
	MsgDataEnd:                      "DataEnd",
	MsgDeviceClearComplete:          "DeviceClearComplete",
	MsgDeviceClearAcknowledge:       "DeviceClearAcknowledge",
	MsgAsyncRemoteLocalControl:      "AsyncRemoteLocalControl",
	MsgAsyncRemoteLocalResponse:     "AsyncRemoteLocalResponse",
	MsgTrigger:                      "Trigger",
	MsgInterrupted:                  "Interrupted",
	MsgAsyncInterrupted:             "AsyncInterrupted",
	MsgAsyncMaximumMessageSize:      "AsyncMaximumMessageSize",
	MsgAsyncMaximumMessageSizeResp:  "AsyncMaximumMessageSizeResponse",
	MsgAsyncInitialize:              "AsyncInitialize",
	MsgAsyncInitializeResponse:      "AsyncInitializeResponse",
	MsgAsyncDeviceClear:             "AsyncDeviceClear",
	MsgAsyncServiceRequest:          "AsyncServiceRequest",
	MsgAsyncStatusQuery:             "AsyncStatusQuery",
	MsgAsyncStatusResponse:          "AsyncStatusResponse",
	MsgAsyncLockInfo:                "AsyncLockInfo",
	MsgAsyncLockInfoResponse:        "AsyncLockInfoResponse",
	MsgGetDescriptors:               "GetDescriptors",
	MsgGetDescriptorsResponse:       "GetDescriptorsResponse",
	MsgStartTLS:                     "StartTLS",
	MsgAsyncStartTLS:                "AsyncStartTLS",
	MsgAsyncStartTLSResponse:        "AsyncStartTLSResponse",
	MsgEndTLS:                       "EndTLS",
	MsgAsyncEndTLS:                  "AsyncEndTLS",
	MsgAsyncEndTLSResponse:          "AsyncEndTLSResponse",
	MsgGetSaslMechanismList:         "GetSaslMechanismList",
	MsgGetSaslMechanismListResponse: "GetSaslMechanismListResponse",
	MsgAuthenticationStart:          "AuthenticationStart",
	MsgAuthenticationExchange:       "AuthenticationExchange",
	MsgAuthenticationResult:         "AuthenticationResult",
}

// MsgTypeName 返回消息类型的可读名称。
func MsgTypeName(t uint8) string {
	if name, ok := msgTypeNames[t]; ok {
		return name
	}
	if t >= MsgVendorSpecificMin {
		return fmt.Sprintf("VendorSpecific(%d)", t)
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

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

// Header 表示 HiSLIP 消息头（16 字节）。
// 所有字段在网络上为大端序。
type Header struct {
	MsgType uint8  // 消息类型
	Control uint8  // 控制码
	Param   uint32 // 消息参数
	Length  uint64 // 负载长度
}

// String 返回消息头的可读表示。
func (h *Header) String() string {
	return fmt.Sprintf("Header{Type:%s Ctrl:0x%02x Param:0x%08x Len:%d}",
		MsgTypeName(h.MsgType), h.Control, h.Param, h.Length)
}

// ReadHeader 从 r 读取 16 字节的 HiSLIP 消息头。
func ReadHeader(r io.Reader) (*Header, error) {
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if buf[0] != PrologueHi || buf[1] != PrologueLo {
		return nil, fmt.Errorf("invalid prologue: expected 'HS', got %q%q", buf[0], buf[1])
	}
	h := &Header{
		MsgType: buf[2],
		Control: buf[3],
		Param:   binary.BigEndian.Uint32(buf[4:8]),
		Length:  binary.BigEndian.Uint64(buf[8:16]),
	}
	return h, nil
}

// WriteHeader 向 w 写入 16 字节的 HiSLIP 消息头。
func WriteHeader(w io.Writer, h *Header) error {
	buf := make([]byte, HeaderSize)
	buf[0] = PrologueHi
	buf[1] = PrologueLo
	buf[2] = h.MsgType
	buf[3] = h.Control
	binary.BigEndian.PutUint32(buf[4:8], h.Param)
	binary.BigEndian.PutUint64(buf[8:16], h.Length)
	_, err := w.Write(buf)
	if err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	return nil
}

// Message 表示完整的 HiSLIP 消息（消息头 + 负载）。
type Message struct {
	Header  *Header
	Payload []byte
}

// ReadMessage 从 r 读取完整的 HiSLIP 消息。
func ReadMessage(r io.Reader) (*Message, error) {
	h, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}

	var payload []byte
	if h.Length > 0 {
		payload = make([]byte, h.Length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Message{Header: h, Payload: payload}, nil
}

// WriteMessage 向 w 写入完整的 HiSLIP 消息。
func WriteMessage(w io.Writer, m *Message) error {
	if err := WriteHeader(w, m.Header); err != nil {
		return err
	}
	if len(m.Payload) > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

// NewMessage 使用给定参数创建新的 Message。
func NewMessage(msgType, ctrl uint8, param uint32, payload []byte) *Message {
	return &Message{
		Header: &Header{
			MsgType: msgType,
			Control: ctrl,
			Param:   param,
			Length:  uint64(len(payload)),
		},
		Payload: payload,
	}
}

// ParseInitializeParam 从 Initialize 消息参数中提取客户端版本和供应商 ID。
// 参数格式: [client_protocol_version(16) | vendor_id(16)]
func ParseInitializeParam(param uint32) (version, vendorID uint16) {
	version = uint16(param >> 16)
	vendorID = uint16(param & 0xFFFF)
	return
}

// MakeInitializeParam 从版本和供应商 ID 创建 Initialize 消息参数。
func MakeInitializeParam(version, vendorID uint16) uint32 {
	return uint32(version)<<16 | uint32(vendorID)
}

// ParseInitializeResponseParam 从 InitializeResponse 中提取 overlap 模式和加密模式。
// 参数格式: [overlap(1) | reserved(7) | encryption_mode(8) | session_id(16)]
func ParseInitializeResponseParam(param uint32) (overlap bool, encryptionMode uint8, sessionID uint16) {
	overlap = (param >> 24 & 0x01) != 0
	encryptionMode = uint8((param >> 16) & 0xFF)
	sessionID = uint16(param & 0xFFFF)
	return
}

// MakeInitializeResponseParam 创建 InitializeResponse 消息参数。
func MakeInitializeResponseParam(overlap bool, encryptionMode uint8, sessionID uint16) uint32 {
	var o uint32
	if overlap {
		o = 1
	}
	return o<<24 | uint32(encryptionMode)<<16 | uint32(sessionID)
}

// ParseAsyncInitializeResponseParam 从 AsyncInitializeResponse 中提取服务器供应商 ID。
func ParseAsyncInitializeResponseParam(param uint32) uint16 {
	return uint16(param & 0xFFFF)
}

// ParseVersion 从协议版本 uint16 中提取主版本号和次版本号。
func ParseVersion(v uint16) (major, minor uint8) {
	major = uint8(v >> 8)
	minor = uint8(v & 0xFF)
	return
}

// MakeVersion 从主版本号和次版本号创建协议版本 uint16。
func MakeVersion(major, minor uint8) uint16 {
	return uint16(major)<<8 | uint16(minor)
}
