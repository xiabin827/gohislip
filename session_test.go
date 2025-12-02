package gohislip

import (
	"testing"
)

func TestSession_MessageID(t *testing.T) {
	s := NewSession()

	// Initial value
	if id := s.CurrentMessageID(); id != InitialMessageID {
		t.Errorf("initial MessageID = 0x%08x, want 0x%08x", id, InitialMessageID)
	}

	// First NextMessageID
	id1 := s.NextMessageID()
	if id1 != InitialMessageID {
		t.Errorf("first NextMessageID = 0x%08x, want 0x%08x", id1, InitialMessageID)
	}

	// Second NextMessageID (should be +2)
	id2 := s.NextMessageID()
	if id2 != InitialMessageID+2 {
		t.Errorf("second NextMessageID = 0x%08x, want 0x%08x", id2, InitialMessageID+2)
	}

	// Reset
	s.ResetMessageID()
	if id := s.CurrentMessageID(); id != InitialMessageID {
		t.Errorf("after reset MessageID = 0x%08x, want 0x%08x", id, InitialMessageID)
	}
}

func TestSession_Mode(t *testing.T) {
	s := NewSession()

	// Default mode
	if s.Mode() != ModeSynchronized {
		t.Errorf("default mode = %d, want ModeSynchronized", s.Mode())
	}
	if s.IsOverlapped() {
		t.Error("IsOverlapped should be false by default")
	}

	// Change mode
	s.SetMode(ModeOverlapped)
	if s.Mode() != ModeOverlapped {
		t.Errorf("mode = %d, want ModeOverlapped", s.Mode())
	}
	if !s.IsOverlapped() {
		t.Error("IsOverlapped should be true")
	}
}

func TestSession_Lock(t *testing.T) {
	s := NewSession()

	// Default lock state
	if s.LockState() != LockNone {
		t.Errorf("default lock = %d, want LockNone", s.LockState())
	}
	if s.IsLocked() {
		t.Error("IsLocked should be false by default")
	}

	// Set lock
	s.SetLockState(LockExclusive)
	if s.LockState() != LockExclusive {
		t.Errorf("lock = %d, want LockExclusive", s.LockState())
	}
	if !s.IsLocked() {
		t.Error("IsLocked should be true")
	}

	// Clear lock
	s.SetLockState(LockNone)
	if s.IsLocked() {
		t.Error("IsLocked should be false after clearing")
	}
}

func TestSession_DeviceClear(t *testing.T) {
	s := NewSession()

	if s.IsClearInProgress() {
		t.Error("IsClearInProgress should be false by default")
	}

	s.SetClearInProgress(true)
	if !s.IsClearInProgress() {
		t.Error("IsClearInProgress should be true")
	}

	s.SetClearInProgress(false)
	if s.IsClearInProgress() {
		t.Error("IsClearInProgress should be false")
	}
}

func TestSession_Encryption(t *testing.T) {
	s := NewSession()

	// Default
	if s.IsEncrypted() {
		t.Error("IsEncrypted should be false by default")
	}
	if s.RequiresEncryption() {
		t.Error("RequiresEncryption should be false by default")
	}

	// Set encryption mode
	s.SetEncryptionMode(EncryptionModeMandatory)
	if !s.RequiresEncryption() {
		t.Error("RequiresEncryption should be true for mandatory")
	}

	// Set encrypted
	s.SetEncrypted(true)
	if !s.IsEncrypted() {
		t.Error("IsEncrypted should be true")
	}
}

func TestSession_Reset(t *testing.T) {
	s := NewSession()

	// Modify state
	s.NextMessageID()
	s.NextMessageID()
	s.SetPendingResponse(true)
	s.SetLastSentID(0x12345678)
	s.SetLastRecvID(0x87654321)

	// Reset
	s.Reset()

	if id := s.CurrentMessageID(); id != InitialMessageID {
		t.Errorf("MessageID = 0x%08x, want 0x%08x", id, InitialMessageID)
	}
	if s.IsPendingResponse() {
		t.Error("IsPendingResponse should be false after reset")
	}
	if s.LastSentID() != 0 {
		t.Errorf("LastSentID = 0x%08x, want 0", s.LastSentID())
	}
	if s.LastRecvID() != 0 {
		t.Errorf("LastRecvID = 0x%08x, want 0", s.LastRecvID())
	}
}

func TestQueryTracker(t *testing.T) {
	qt := NewQueryTracker()

	// Add queries
	pq1 := qt.Add(0xffffff00)
	pq2 := qt.Add(0xffffff02)

	if qt.Count() != 2 {
		t.Errorf("Count = %d, want 2", qt.Count())
	}

	// Get query
	got, ok := qt.Get(0xffffff00)
	if !ok || got != pq1 {
		t.Error("Get failed for existing query")
	}

	_, ok = qt.Get(0x99999999)
	if ok {
		t.Error("Get should fail for non-existing query")
	}

	// Complete query
	qt.Complete(0xffffff00, []byte("response"), nil)
	if qt.Count() != 1 {
		t.Errorf("Count after complete = %d, want 1", qt.Count())
	}

	select {
	case <-pq1.done:
		if string(pq1.response) != "response" {
			t.Errorf("response = %q, want 'response'", pq1.response)
		}
	default:
		t.Error("pq1.done channel should be closed")
	}

	// Clear remaining
	qt.Clear(ErrClosed)
	if qt.Count() != 0 {
		t.Errorf("Count after clear = %d, want 0", qt.Count())
	}

	select {
	case <-pq2.done:
		if pq2.err != ErrClosed {
			t.Errorf("err = %v, want ErrClosed", pq2.err)
		}
	default:
		t.Error("pq2.done channel should be closed")
	}
}
