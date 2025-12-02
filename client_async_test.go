package gohislip

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDispatchAsync_SRQCallback(t *testing.T) {
	client := NewClient(nil)

	var (
		wg     sync.WaitGroup
		got    byte
		called bool
	)
	wg.Add(1)
	client.SetSRQCallback(func(stb byte) {
		defer wg.Done()
		got = stb
		called = true
	})

	msg := &Message{
		Header: &Header{
			MsgType: MsgAsyncServiceRequest,
			Control: 0x5A,
		},
	}

	client.dispatchAsync(msg)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("SRQ callback not called in time")
	}

	if !called || got != 0x5A {
		t.Fatalf("callback stb = 0x%02X, called=%v, want 0x5A,true", got, called)
	}
}

func TestDispatchAsync_RoutesToAsyncTracker(t *testing.T) {
	client := NewClient(nil)

	ch, err := client.atracker.Register(MsgAsyncStatusResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	msg := &Message{
		Header: &Header{
			MsgType: MsgAsyncStatusResponse,
			Control: 0x33,
		},
	}

	client.dispatchAsync(msg)

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

func TestDispatchAsync_AsyncInterruptedClearsTrackers(t *testing.T) {
	client := NewClient(nil)

	// 为同步 QueryTracker 添加待处理项
	pq := client.tracker.Add(0xffffff00)

	// 为异步 AsyncTracker 注册等待者
	ch, err := client.atracker.Register(MsgAsyncLockResponse)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	msg := &Message{
		Header: &Header{
			MsgType: MsgAsyncInterrupted,
		},
	}

	client.dispatchAsync(msg)

	// QueryTracker 应该被清空，done 被关闭且带 ErrInterrupted
	select {
	case <-pq.done:
		if !errors.Is(pq.err, ErrInterrupted) {
			t.Fatalf("pq.err = %v, want ErrInterrupted", pq.err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for QueryTracker to be cleared")
	}

	// AsyncTracker 所有等待者应收到 ErrInterrupted
	select {
	case res := <-ch:
		if !errors.Is(res.err, ErrInterrupted) {
			t.Fatalf("res.err = %v, want ErrInterrupted", res.err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for AsyncTracker to be cleared")
	}

	if client.tracker.Count() != 0 {
		t.Fatalf("tracker.Count() = %d, want 0", client.tracker.Count())
	}
}
