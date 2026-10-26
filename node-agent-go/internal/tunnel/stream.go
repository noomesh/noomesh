// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// openMsg is the payload of an OPEN frame.
type openMsg struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Headers [][2]string `json:"headers"`
	// Principal is what the gateway says it is calling as. Only "controller"
	// exists. The node's authority does not rest on this field: it rests on
	// the session the stream arrived on (the handshake) and is carried to
	// the handlers in the request context, not in a header. The field exists
	// so a future second principal is a protocol change, not a guess.
	Principal string `json:"principal"`
}

type headMsg struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
}

// hopHeaders are never carried onto a stream's request: the connection they
// describe is not the one the handler sees. Authorization is dropped too: the
// session already says who is calling, and a bearer on a tunnel stream would
// only be one more thing for a handler to forward.
var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true, "host": true, "authorization": true,
	"content-length": true,
}

func dropRequestHeader(name string) bool {
	n := strings.ToLower(name)
	return hopHeaders[n] || strings.HasPrefix(n, "x-noo-tunnel")
}

// stream is one request being served on the session.
type stream struct {
	id     uint32
	s      *session
	ctx    context.Context
	cancel context.CancelCauseFunc
	req    *reqBody
	send   *window // the gateway's credit for our response DATA
}

// reqBody is the request body a handler reads: DATA frames queued by the
// session's reader, credited back to the gateway as the handler consumes them.
type reqBody struct {
	mu     sync.Mutex
	cond   *sync.Cond
	chunks []chunk
	cur    []byte
	curCst int
	queued int // cost of everything not yet fully consumed
	ended  bool
	err    error
	grant  func(int)
}

type chunk struct {
	b    []byte
	cost int
}

func newReqBody(grant func(int)) *reqBody {
	b := &reqBody{grant: grant}
	b.cond = sync.NewCond(&b.mu)
	return b
}

var errEmptyData = errors.New("the gateway sent an empty DATA frame")

var errWindowExceeded = errors.New("the gateway sent more request body than the stream window allows")

// push queues a DATA payload. window is the per-stream limit.
func (b *reqBody) push(p []byte, window int) error {
	cost := Cost(len(p))
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ended || b.err != nil {
		return nil // late frame for a finished body: ignored
	}
	if b.queued+cost > window {
		return errWindowExceeded
	}
	b.queued += cost
	if len(p) == 0 {
		// The gateway never sends an empty DATA frame. Taking one would owe
		// credit for nothing, and granting it from here could pile up
		// goroutines behind a stalled writer; it is a protocol error.
		return errEmptyData
	}
	b.chunks = append(b.chunks, chunk{b: p, cost: cost})
	b.cond.Broadcast()
	return nil
}

func (b *reqBody) end() {
	b.mu.Lock()
	b.ended = true
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *reqBody) abort(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

// Read implements io.Reader.
func (b *reqBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	for b.err == nil && b.cur == nil && len(b.chunks) == 0 && !b.ended {
		b.cond.Wait()
	}
	if b.err != nil {
		err := b.err
		b.mu.Unlock()
		return 0, err
	}
	if b.cur == nil && len(b.chunks) > 0 {
		c := b.chunks[0]
		b.chunks = b.chunks[1:]
		b.cur, b.curCst = c.b, c.cost
	}
	if b.cur == nil {
		b.mu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, b.cur)
	b.cur = b.cur[n:]
	grant := 0
	if len(b.cur) == 0 {
		grant, b.cur = b.curCst, nil
		b.queued -= grant
	}
	b.mu.Unlock()
	if grant > 0 {
		b.grant(grant)
	}
	return n, nil
}

func (b *reqBody) Close() error { return nil }

// respWriter is the http.ResponseWriter a handler writes the response to:
// every Write becomes DATA frames, spent against the gateway's credit, so a
// slow reader at the gateway slows the handler instead of growing a buffer
// here. Nothing is buffered: a Write is on the wire (or waiting for credit)
// when it returns, which is what keeps SSE frames prompt.
type respWriter struct {
	st       *stream
	h        http.Header
	status   int
	headSent bool
	err      error
}

func (w *respWriter) Header() http.Header { return w.h }

func (w *respWriter) WriteHeader(code int) {
	if w.headSent {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return // interim responses are not carried
	}
	w.status = code
	w.sendHead()
}

func (w *respWriter) sendHead() {
	w.headSent = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	hm := headMsg{Status: w.status}
	for k, vs := range w.h {
		for _, v := range vs {
			hm.Headers = append(hm.Headers, [2]string{k, v})
		}
	}
	b, _ := json.Marshal(hm)
	if err := w.st.s.send(w.st.ctx, encode(FrameHead, w.st.id, b)); err != nil {
		w.err = err
	}
}

func (w *respWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if !w.headSent {
		if w.h.Get("Content-Type") == "" && len(p) > 0 {
			n := len(p)
			if n > 512 {
				n = 512
			}
			w.h.Set("Content-Type", http.DetectContentType(p[:n]))
		}
		w.WriteHeader(http.StatusOK)
		if w.err != nil {
			return 0, w.err
		}
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxData {
			n = MaxData
		}
		if err := w.st.send.take(w.st.ctx, Cost(n)); err != nil {
			w.err = err
			return written, err
		}
		if err := w.st.s.send(w.st.ctx, encode(FrameData, w.st.id, p[:n])); err != nil {
			w.err = err
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Flush sends the response head if it has not gone yet. Data is never held
// back, so there is nothing else to flush.
func (w *respWriter) Flush() { _ = w.FlushError() }

func (w *respWriter) FlushError() error {
	if !w.headSent {
		w.WriteHeader(http.StatusOK)
	}
	return w.err
}

// Deadlines and full duplex are properties of a TCP connection; a tunnel
// stream has none to move. Accepting the calls (rather than answering "not
// supported") keeps a handler that extends its deadline for a long stream
// from treating the tunnel as an error.
func (w *respWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *respWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *respWriter) EnableFullDuplex() error          { return nil }

func (w *respWriter) finish() {
	if w.err != nil {
		return
	}
	if !w.headSent {
		w.sendHead()
	}
	_ = w.st.s.send(w.st.ctx, encode(FrameEnd, w.st.id, nil))
}
