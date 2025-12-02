package gohislip

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
