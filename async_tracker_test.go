package gohislip

import (
	"errors"
	"testing"
	"time"
)

func TestAsyncTracker_RegisterAndComplete(t *testing.T) {
	tr := NewAsyncTracker()

	ch, err := tr.Register(MsgAsyncStatusResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// 同一类型再次注册应失败
	if _, err := tr.Register(MsgAsyncStatusResponse); err == nil {
		t.Fatalf("expected error when registering duplicate waiter")
	}

	msg := &Message{
		Header: &Header{
			MsgType: MsgAsyncStatusResponse,
			Control: 0x42,
		},
	}

	if ok := tr.Complete(msg); !ok {
		t.Fatalf("Complete returned false, want true")
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("unexpected error: %v", res.err)
		}
		if res.msg != msg {
			t.Fatalf("msg mismatch")
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for async result")
	}
}

func TestAsyncTracker_Cancel(t *testing.T) {
	tr := NewAsyncTracker()

	ch, err := tr.Register(MsgAsyncLockResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	cancelErr := errors.New("cancelled")
	tr.Cancel(MsgAsyncLockResponse, cancelErr)

	select {
	case res := <-ch:
		if !errors.Is(res.err, cancelErr) {
			t.Fatalf("err = %v, want %v", res.err, cancelErr)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for cancel result")
	}
}

func TestAsyncTracker_Fail(t *testing.T) {
	tr := NewAsyncTracker()

	ch1, err := tr.Register(MsgAsyncStatusResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	ch2, err := tr.Register(MsgAsyncLockResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	failErr := errors.New("fail all")
	tr.Fail(failErr)

	for _, ch := range []chan asyncResult{ch1, ch2} {
		select {
		case res := <-ch:
			if !errors.Is(res.err, failErr) {
				t.Fatalf("err = %v, want %v", res.err, failErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for fail result")
		}
	}
}
