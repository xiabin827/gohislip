package gohislip

import (
	"fmt"
	"sync"
)

// asyncResult 表示一次异步操作的结果。
// msg 为收到的消息（如果有），err 为操作错误（如果有）。
type asyncResult struct {
	msg *Message
	err error
}

// AsyncTracker 管理异步通道上的请求/响应匹配。
// 以消息类型 (MsgAsyncLockResponse 等) 为键，保证同一类型同时最多只有一个等待者。
type AsyncTracker struct {
	mu      sync.Mutex
	pending map[uint8]chan asyncResult
}

// NewAsyncTracker 创建新的 AsyncTracker。
func NewAsyncTracker() *AsyncTracker {
	return &AsyncTracker{
		pending: make(map[uint8]chan asyncResult),
	}
}

// Register 为给定消息类型注册一个等待通道。
// 如果该类型已存在等待者，则返回错误。
func (t *AsyncTracker) Register(msgType uint8) (chan asyncResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending[msgType] != nil {
		return nil, fmt.Errorf("async operation already pending for message type %d", msgType)
	}

	ch := make(chan asyncResult, 1)
	t.pending[msgType] = ch
	return ch, nil
}

// Complete 将一条消息投递给相应类型的等待者（如果存在）。
// 如果找到等待者则返回 true，否则返回 false。
func (t *AsyncTracker) Complete(msg *Message) bool {
	t.mu.Lock()
	ch := t.pending[msg.Header.MsgType]
	if ch != nil {
		delete(t.pending, msg.Header.MsgType)
	}
	t.mu.Unlock()

	if ch != nil {
		ch <- asyncResult{msg: msg}
		close(ch)
		return true
	}
	return false
}

// Cancel 取消指定消息类型的等待者并返回错误给它（如果存在）。
func (t *AsyncTracker) Cancel(msgType uint8, err error) {
	t.mu.Lock()
	ch := t.pending[msgType]
	if ch != nil {
		delete(t.pending, msgType)
	}
	t.mu.Unlock()

	if ch != nil {
		ch <- asyncResult{err: err}
		close(ch)
	}
}

// Fail 将所有等待者标记为失败并返回相同错误。
func (t *AsyncTracker) Fail(err error) {
	t.mu.Lock()
	pending := t.pending
	t.pending = make(map[uint8]chan asyncResult)
	t.mu.Unlock()

	for _, ch := range pending {
		select {
		case ch <- asyncResult{err: err}:
		default:
			// channel 已满或已关闭，跳过
		}
		close(ch)
	}
}
