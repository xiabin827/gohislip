package gohislip

import (
	"encoding/binary"
	"fmt"
	"io"
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
