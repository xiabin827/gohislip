package gohislip

import (
	"bytes"
	"testing"
)

func TestHeader_ReadWrite(t *testing.T) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "Initialize",
			header: &Header{
				MsgType: MsgInitialize,
				Control: 0,
				Param:   MakeInitializeParam(ProtocolVersion, 0x1234),
				Length:  7,
			},
		},
		{
			name: "DataEnd",
			header: &Header{
				MsgType: MsgDataEnd,
				Control: CtrlRMTDelivered,
				Param:   0xffffff00,
				Length:  100,
			},
		},
		{
			name: "AsyncLock",
			header: &Header{
				MsgType: MsgAsyncLock,
				Control: CtrlLockRequest,
				Param:   5000, // timeout ms
				Length:  0,
			},
		},
		{
			name: "FatalError",
			header: &Header{
				MsgType: MsgFatalError,
				Control: FatalErrPoorlyFormedHeader,
				Param:   0,
				Length:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write header
			var buf bytes.Buffer
			if err := WriteHeader(&buf, tt.header); err != nil {
				t.Fatalf("WriteHeader failed: %v", err)
			}

			// Check size
			if buf.Len() != HeaderSize {
				t.Errorf("header size = %d, want %d", buf.Len(), HeaderSize)
			}

			// Check prologue
			data := buf.Bytes()
			if data[0] != PrologueHi || data[1] != PrologueLo {
				t.Errorf("prologue = %q%q, want 'HS'", data[0], data[1])
			}

			// Read header back
			readHeader, err := ReadHeader(&buf)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			// Compare
			if readHeader.MsgType != tt.header.MsgType {
				t.Errorf("MsgType = %d, want %d", readHeader.MsgType, tt.header.MsgType)
			}
			if readHeader.Control != tt.header.Control {
				t.Errorf("Control = %d, want %d", readHeader.Control, tt.header.Control)
			}
			if readHeader.Param != tt.header.Param {
				t.Errorf("Param = 0x%08x, want 0x%08x", readHeader.Param, tt.header.Param)
			}
			if readHeader.Length != tt.header.Length {
				t.Errorf("Length = %d, want %d", readHeader.Length, tt.header.Length)
			}
		})
	}
}

func TestMessage_ReadWrite(t *testing.T) {
	msg := NewMessage(MsgDataEnd, CtrlRMTDelivered, 0xffffff00, []byte("*IDN?\n"))

	var buf bytes.Buffer
	if err := WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	readMsg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if readMsg.Header.MsgType != msg.Header.MsgType {
		t.Errorf("MsgType mismatch")
	}
	if !bytes.Equal(readMsg.Payload, msg.Payload) {
		t.Errorf("Payload = %q, want %q", readMsg.Payload, msg.Payload)
	}
}

func TestInitializeParam(t *testing.T) {
	version := uint16(0x0200) // v2.0
	vendorID := uint16(0x1234)

	param := MakeInitializeParam(version, vendorID)

	gotVersion, gotVendor := ParseInitializeParam(param)
	if gotVersion != version {
		t.Errorf("version = 0x%04x, want 0x%04x", gotVersion, version)
	}
	if gotVendor != vendorID {
		t.Errorf("vendorID = 0x%04x, want 0x%04x", gotVendor, vendorID)
	}
}

func TestInitializeResponseParam(t *testing.T) {
	overlap := true
	encMode := EncryptionModeOptional
	sessionID := uint16(0x5678)

	param := MakeInitializeResponseParam(overlap, encMode, sessionID)

	gotOverlap, gotEnc, gotSession := ParseInitializeResponseParam(param)
	if gotOverlap != overlap {
		t.Errorf("overlap = %v, want %v", gotOverlap, overlap)
	}
	if gotEnc != encMode {
		t.Errorf("encMode = %d, want %d", gotEnc, encMode)
	}
	if gotSession != sessionID {
		t.Errorf("sessionID = 0x%04x, want 0x%04x", gotSession, sessionID)
	}
}

func TestMsgTypeName(t *testing.T) {
	if name := MsgTypeName(MsgInitialize); name != "Initialize" {
		t.Errorf("MsgTypeName(0) = %q, want 'Initialize'", name)
	}
	if name := MsgTypeName(MsgDataEnd); name != "DataEnd" {
		t.Errorf("MsgTypeName(7) = %q, want 'DataEnd'", name)
	}
	if name := MsgTypeName(200); name != "VendorSpecific(200)" {
		t.Errorf("MsgTypeName(200) = %q, want 'VendorSpecific(200)'", name)
	}
}

func TestVersion(t *testing.T) {
	major, minor := ParseVersion(ProtocolVersion)
	if major != ProtocolVersionMajor || minor != ProtocolVersionMinor {
		t.Errorf("ParseVersion = (%d, %d), want (%d, %d)",
			major, minor, ProtocolVersionMajor, ProtocolVersionMinor)
	}

	v := MakeVersion(2, 1)
	m, n := ParseVersion(v)
	if m != 2 || n != 1 {
		t.Errorf("MakeVersion/ParseVersion roundtrip failed")
	}
}

func TestReadHeader_InvalidPrologue(t *testing.T) {
	buf := bytes.NewReader([]byte("XX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	_, err := ReadHeader(buf)
	if err == nil {
		t.Error("expected error for invalid prologue")
	}
}
