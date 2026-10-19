// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// session is one live connection and the streams on it.
type session struct {
	c      *Client
	conn   *websocket.Conn
	window int
	max    int

	ctx    context.Context
	cancel context.CancelCauseFunc
	out    chan []byte

	mu      sync.Mutex
	streams map[uint32]*stream
	bg      sync.WaitGroup
}

func newSession(c *Client, conn *websocket.Conn, r readyMsg) *session {
	return &session{c: c, conn: conn, window: r.Window, max: r.MaxStreams,
		out: make(chan []byte, 256), streams: map[uint32]*stream{}}
}

var errSessionClosed = errors.New("the tunnel session closed")

// send queues a frame for the writer. It blocks while the writer is behind
// (the backpressure that reaches a handler) and gives up when the stream or
// the session ends.
func (s *session) send(ctx context.Context, b []byte) error {
	select {
	case s.out <- b:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return errSessionClosed
	}
}

func (s *session) serve(parent context.Context) error {
	s.ctx, s.cancel = context.WithCancelCause(parent)
	defer s.cancel(nil)

	deadline := func() { _ = s.conn.SetReadDeadline(time.Now().Add(DeadAfter)) }
	s.conn.SetReadLimit(MaxMessage)
	s.conn.SetPongHandler(func(string) error { deadline(); return nil })
	s.conn.SetPingHandler(func(m string) error {
		deadline()
		err := s.conn.WriteControl(websocket.PongMessage, []byte(m), time.Now().Add(5*time.Second))
		if err != nil && !errors.Is(err, websocket.ErrCloseSent) {
			var ne interface{ Timeout() bool }
			if !errors.As(err, &ne) {
				return err
			}
		}
		return nil
	})

	// Writer: the only goroutine that writes data messages.
	s.bg.Add(2)
	go func() {
		defer s.bg.Done()
		for {
			select {
			case b := <-s.out:
				_ = s.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
				if err := s.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
					s.cancel(fmt.Errorf("write: %w", err))
					return
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
	// Pinger: a peer that stops answering is found inside DeadAfter.
	go func() {
		defer s.bg.Done()
		t := time.NewTicker(PingEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					s.cancel(fmt.Errorf("ping: %w", err))
					return
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-s.ctx.Done()
		_ = s.conn.Close() // unblocks the reader
	}()

	err := s.readLoop(deadline)
	s.cancel(err)
	_ = s.conn.Close()
	s.abortAll(err)
	s.bg.Wait()
	return err
}

func (s *session) readLoop(deadline func()) error {
	for {
		deadline()
		typ, data, err := s.conn.ReadMessage()
		if err != nil {
			if cause := context.Cause(s.ctx); cause != nil && !errors.Is(cause, context.Canceled) {
				return cause
			}
			return err
		}
		if typ != websocket.BinaryMessage {
			continue
		}
		kind, id, payload, err := decode(data)
		if err != nil {
			return err
		}
		s.dispatch(kind, id, payload)
	}
}

func (s *session) get(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *session) remove(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *session) abortAll(cause error) {
	s.mu.Lock()
	all := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		all = append(all, st)
	}
	s.streams = map[uint32]*stream{}
	s.mu.Unlock()
	for _, st := range all {
		st.abort(fmt.Errorf("tunnel dropped: %v", cause))
	}
}

func (st *stream) abort(err error) {
	st.req.abort(err)
	st.send.close()
	st.cancel(err)
}

// resetPeer tells the gateway to drop a stream. Best effort: if the session
// is going away the gateway learns that from the connection.
func (s *session) resetPeer(id uint32, reason string) {
	select {
	case s.out <- encode(FrameReset, id, []byte(reason)):
	default:
		go func() {
			select {
			case s.out <- encode(FrameReset, id, []byte(reason)):
			case <-s.ctx.Done():
			}
		}()
	}
}

func (s *session) dispatch(kind byte, id uint32, payload []byte) {
	switch kind {
	case FrameOpen:
		s.open(id, payload)
	case FrameData:
		st := s.get(id)
		if st == nil {
			return // late frame for a stream that already ended
		}
		if err := st.req.push(payload, s.window); err != nil {
			s.resetPeer(id, err.Error())
			s.remove(id)
			st.abort(err)
		}
	case FrameEnd:
		if st := s.get(id); st != nil {
			st.req.end()
		}
	case FrameCredit:
		if len(payload) != 4 {
			return
		}
		if st := s.get(id); st != nil {
			n := binary.BigEndian.Uint32(payload)
			if uint64(n) > MaxWindow { // also keeps the conversion below inside a 32-bit int
				n = MaxWindow
			}
			st.send.add(int(n))
		}
	case FrameReset:
		if st := s.get(id); st != nil {
			s.remove(id)
			st.abort(fmt.Errorf("the gateway reset the stream: %s", string(payload)))
		}
	}
}

func validMethod(m string) bool {
	if m == "" || len(m) > 16 {
		return false
	}
	for _, r := range m {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func (s *session) open(id uint32, payload []byte) {
	var om openMsg
	if id == 0 || json.Unmarshal(payload, &om) != nil {
		s.resetPeer(id, "malformed OPEN")
		return
	}
	// The only principal there is. Anything else is a gateway newer than this
	// node asking for something it cannot grant.
	if om.Principal != "controller" {
		s.resetPeer(id, fmt.Sprintf("this node does not serve the principal %q over the tunnel", om.Principal))
		return
	}
	if !validMethod(om.Method) || !strings.HasPrefix(om.Path, "/") || strings.HasPrefix(om.Path, "//") {
		s.resetPeer(id, "bad method or path")
		return
	}
	u, err := url.ParseRequestURI(om.Path)
	if err != nil {
		s.resetPeer(id, "bad path")
		return
	}
	s.mu.Lock()
	if _, dup := s.streams[id]; dup {
		s.mu.Unlock()
		s.resetPeer(id, "stream id already in use")
		return
	}
	if len(s.streams) >= s.max {
		s.mu.Unlock()
		s.resetPeer(id, "stream cap reached on the node")
		return
	}
	ctx, cancel := context.WithCancelCause(auth.WithTunnelController(s.ctx))
	st := &stream{id: id, s: s, ctx: ctx, cancel: cancel, send: newWindow(s.window)}
	st.req = newReqBody(func(n int) {
		_ = s.send(ctx, encode(FrameCredit, id, creditPayload(n)))
	})
	s.streams[id] = st
	s.mu.Unlock()
	s.c.Streams.Add(1)

	h := http.Header{}
	var clen int64 = -1
	for _, kv := range om.Headers {
		if strings.EqualFold(kv[0], "content-length") {
			if n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64); err == nil && n >= 0 {
				clen = n
			}
			continue
		}
		if dropRequestHeader(kv[0]) {
			continue
		}
		h.Add(kv[0], kv[1])
	}
	var body io.ReadCloser = st.req
	if clen < 0 && (om.Method == http.MethodGet || om.Method == http.MethodHead || om.Method == http.MethodDelete) {
		body, clen = http.NoBody, 0
	}
	req, err := http.NewRequestWithContext(ctx, om.Method, "http://node-agent"+u.RequestURI(), body)
	if err != nil {
		s.remove(id)
		cancel(err)
		s.resetPeer(id, "bad request")
		return
	}
	req.Header = h
	req.ContentLength = clen
	req.RequestURI = u.RequestURI()
	req.RemoteAddr = "tunnel"

	go func() {
		rw := &respWriter{st: st, h: http.Header{}}
		defer func() {
			if p := recover(); p != nil {
				if p != http.ErrAbortHandler {
					slog.Error("tunnel stream handler panicked", "path", u.Path, "panic", p)
				}
				s.resetPeer(id, "handler failed on the node")
			}
			s.remove(id)
			cancel(nil)
		}()
		s.c.opt.Handler.ServeHTTP(rw, req)
		rw.finish()
	}()
}
