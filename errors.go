package gohislip

import (
	"errors"
	"fmt"
)

// 标准错误
var (
	ErrClosed           = errors.New("hislip: connection closed")
	ErrNotConnected     = errors.New("hislip: not connected")
	ErrTimeout          = errors.New("hislip: operation timeout")
	ErrInterrupted      = errors.New("hislip: operation interrupted")
	ErrLockTimeout      = errors.New("hislip: lock acquisition timeout")
	ErrLockFailed       = errors.New("hislip: lock acquisition failed")
	ErrNotLocked        = errors.New("hislip: not locked")
	ErrDeviceClear      = errors.New("hislip: device clear in progress")
	ErrInvalidPrologue  = errors.New("hislip: invalid message prologue")
	ErrInvalidMessage   = errors.New("hislip: invalid message")
	ErrProtocolMismatch = errors.New("hislip: protocol version mismatch")
	ErrTLSRequired      = errors.New("hislip: TLS required but not established")
	ErrAuthRequired     = errors.New("hislip: authentication required")
	ErrAuthFailed       = errors.New("hislip: authentication failed")
)

// 致命错误码（规范表 5）
const (
	FatalErrUnidentified          uint8 = 0
	FatalErrPoorlyFormedHeader    uint8 = 1
	FatalErrAttemptUseWithoutInit uint8 = 2
	FatalErrMaxClientsExceeded    uint8 = 3
	FatalErrSecureConnFailed      uint8 = 4
	FatalErrSecureNotEstablished  uint8 = 5 // 安全连接未建立
	FatalErrInvalidInitSequence   uint8 = 6
	FatalErrServerShuttingDown    uint8 = 7
)

// fatalErrorNames 将致命错误码映射到描述
var fatalErrorNames = map[uint8]string{
	FatalErrUnidentified:          "unidentified error",
	FatalErrPoorlyFormedHeader:    "poorly formed message header",
	FatalErrAttemptUseWithoutInit: "attempt to use connection without initialization",
	FatalErrMaxClientsExceeded:    "maximum number of clients exceeded",
	FatalErrSecureConnFailed:      "secure connection failed",
	FatalErrSecureNotEstablished:  "secure connection required but not established",
	FatalErrInvalidInitSequence:   "invalid initialization sequence",
	FatalErrServerShuttingDown:    "server is shutting down",
}

// 非致命错误码（规范表 6）
const (
	NonFatalErrUnidentified          uint8 = 0
	NonFatalErrUnrecognizedMsgType   uint8 = 1
	NonFatalErrUnrecognizedCtrlCode  uint8 = 2
	NonFatalErrUnrecognizedVendorMsg uint8 = 3
	NonFatalErrMsgTooLarge           uint8 = 4
	NonFatalErrAuthFailed            uint8 = 5
)

// nonFatalErrorNames 将非致命错误码映射到描述
var nonFatalErrorNames = map[uint8]string{
	NonFatalErrUnidentified:          "unidentified error",
	NonFatalErrUnrecognizedMsgType:   "unrecognized message type",
	NonFatalErrUnrecognizedCtrlCode:  "unrecognized control code",
	NonFatalErrUnrecognizedVendorMsg: "unrecognized vendor-defined message",
	NonFatalErrMsgTooLarge:           "message too large",
	NonFatalErrAuthFailed:            "authentication mechanism failed",
}

// FatalError 表示 HiSLIP 致命错误（MsgFatalError）。
// 发生致命错误时，必须关闭两个连接。
type FatalError struct {
	Code    uint8
	Message string
}

func (e *FatalError) Error() string {
	desc := fatalErrorNames[e.Code]
	if desc == "" {
		desc = fmt.Sprintf("unknown fatal error code %d", e.Code)
	}
	if e.Message != "" {
		return fmt.Sprintf("hislip fatal error %d: %s (%s)", e.Code, desc, e.Message)
	}
	return fmt.Sprintf("hislip fatal error %d: %s", e.Code, desc)
}

// NewFatalError 从收到的消息创建新的 FatalError。
func NewFatalError(code uint8, payload []byte) *FatalError {
	return &FatalError{
		Code:    code,
		Message: string(payload),
	}
}

// IsFatalError 检查 err 是否为 FatalError。
func IsFatalError(err error) bool {
	var fe *FatalError
	return errors.As(err, &fe)
}

// NonFatalError 表示 HiSLIP 非致命错误（MsgError）。
// 非致命错误后连接可以继续。
type NonFatalError struct {
	Code    uint8
	Message string
}

func (e *NonFatalError) Error() string {
	desc := nonFatalErrorNames[e.Code]
	if desc == "" {
		desc = fmt.Sprintf("unknown error code %d", e.Code)
	}
	if e.Message != "" {
		return fmt.Sprintf("hislip error %d: %s (%s)", e.Code, desc, e.Message)
	}
	return fmt.Sprintf("hislip error %d: %s", e.Code, desc)
}

// NewNonFatalError 从收到的消息创建新的 NonFatalError。
func NewNonFatalError(code uint8, payload []byte) *NonFatalError {
	return &NonFatalError{
		Code:    code,
		Message: string(payload),
	}
}

// IsNonFatalError 检查 err 是否为 NonFatalError。
func IsNonFatalError(err error) bool {
	var nfe *NonFatalError
	return errors.As(err, &nfe)
}

// ProtocolError 表示协议级错误。
type ProtocolError struct {
	Operation string
	Expected  string
	Got       string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("hislip protocol error during %s: expected %s, got %s",
		e.Operation, e.Expected, e.Got)
}

// NewProtocolError 创建新的 ProtocolError。
func NewProtocolError(op, expected, got string) *ProtocolError {
	return &ProtocolError{
		Operation: op,
		Expected:  expected,
		Got:       got,
	}
}
