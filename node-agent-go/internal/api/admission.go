// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

// Admission: the proxy counts each inference request against the backend's
// slots (internal/occupancy) and, when the backend is full, says so instead
// of letting the request sit silently in the engine's own queue.
//
//   - a backend whose admission a GPU hold is draining (gpuyield, mode
//     drain) answers `503 backend_draining` with `X-Noo-Busy: draining` at
//     once: nothing new starts there, what runs finishes.
//   - `X-Noo-Busy: reject` on the request: a full backend answers 503 at
//     once, with `Retry-After` and `X-Noo-Queue` (how many wait ahead), so a
//     caller with another candidate can go there.
//   - otherwise the request waits its turn here, up to the first-byte
//     bound. A STREAMING request gets its SSE headers at once and a
//     `: queued` comment every keepAliveInterval while it waits, so the
//     caller sees a live connection, not a stall.
//   - an admitted streaming request whose backend stays silent (a long
//     prefill) gets its headers after earlyHeadersAfter and a `: keep-alive`
//     comment every keepAliveInterval until the engine's first bytes.
//
// Every response names the backend's occupancy: `X-Noo-In-Flight`,
// `X-Noo-Slots`. SSE comment lines are ignored by every consumer on the
// path (the gateway's aggregate reader counts bytes, its pass-through
// forwards them, the harness and the vendor-CLI translator skip lines that
// are not `data:`). noomesh-internal i159, parts A and B.

const (
	// keepAliveInterval is how often a waiting or silent stream gets a
	// comment line. The gateway's first-token and idle windows are 30 s.
	keepAliveInterval = 5 * time.Second
	// earlyHeadersAfter is how long an admitted streaming request waits for
	// the engine's own headers before the proxy sends SSE headers itself.
	// Short enough to beat the gateway's 30 s header window, long enough
	// that an engine's quick refusal (an unknown model, a bad body) still
	// arrives with its own status code.
	earlyHeadersAfter = 10 * time.Second
	// busyRetryAfter is the Retry-After a rejected request is given.
	busyRetryAfter = 5
)

// admission is one request's slot plus the writer the proxy must answer
// through (it keeps the stream alive).
type admission struct {
	w       *liveWriter
	release func()
}

// done releases the slot and ends the writer's keep-alive, emitting the
// buffered error when an early-headed stream failed.
func (a *admission) done() {
	a.w.close()
	a.release()
}

// wantsStream reports whether the request body asks for a stream.
func wantsStream(body []byte) bool {
	var b struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &b)
	return b.Stream
}

// admit takes a slot on the backend for this request, or answers the caller
// and returns nil when it cannot (rejected, or the wait outlasted the
// bound). The occupancy headers are set either way.
func (s *Server) admit(w http.ResponseWriter, r *http.Request, backend string, body []byte, bound time.Duration) *admission {
	return admitWith(w, r, backend, wantsStream(body), bound, keepAliveInterval, earlyHeadersAfter)
}

func admitWith(w http.ResponseWriter, r *http.Request, backend string, stream bool, bound, keepAlive, earlyAfter time.Duration) *admission {
	busy, ahead := occupancy.Busy(backend)
	setOccupancyHeaders(w, backend)
	if occupancy.Draining(backend) {
		w.Header().Set("Retry-After", strconv.Itoa(busyRetryAfter))
		w.Header().Set("X-Noo-Busy", "draining")
		jsonError(w, http.StatusServiceUnavailable, "backend_draining",
			fmt.Sprintf("%s is draining for a GPU hold (%d still in flight); try another node",
				backend, occupancy.InFlight(backend)))
		return nil
	}
	if busy && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Noo-Busy")), "reject") {
		w.Header().Set("Retry-After", strconv.Itoa(busyRetryAfter))
		w.Header().Set("X-Noo-Queue", strconv.Itoa(ahead))
		jsonError(w, http.StatusServiceUnavailable, "backend_busy",
			fmt.Sprintf("every slot on %s is taken (%d in flight of %d, %d queued); retry or try another node",
				backend, occupancy.Report()[backend].InFlight, occupancy.Slots(backend), ahead))
		return nil
	}
	lw := newLiveWriter(w, stream, keepAlive, earlyAfter)
	if busy && stream {
		// The caller sees a live stream while it waits, not silence.
		lw.sendHeadersNow(fmt.Sprintf(": queued ahead=%d", ahead))
	}
	ctx, cancel := context.WithTimeout(r.Context(), bound)
	defer cancel()
	release, err := occupancy.Admit(ctx, backend)
	if err != nil {
		lw.stopKeepAlive()
		_, ahead = occupancy.Busy(backend)
		msg := fmt.Sprintf("every slot on %s stayed taken for %ds (%d queued)", backend, int(bound.Seconds()), ahead)
		if r.Context().Err() != nil {
			msg = "the caller went away while waiting for a slot on " + backend
		}
		w.Header().Set("Retry-After", strconv.Itoa(busyRetryAfter))
		w.Header().Set("X-Noo-Queue", strconv.Itoa(ahead))
		jsonError(lw, http.StatusServiceUnavailable, "backend_busy", msg)
		lw.close()
		return nil
	}
	setOccupancyHeaders(w, backend)
	lw.armEarlyHeaders()
	return &admission{w: lw, release: release}
}

func setOccupancyHeaders(w http.ResponseWriter, backend string) {
	e := occupancy.Report()[backend]
	w.Header().Set("X-Noo-In-Flight", strconv.Itoa(e.InFlight))
	w.Header().Set("X-Noo-Slots", strconv.Itoa(e.Slots))
}

// liveWriter wraps the response for one proxied request. For a streaming
// request it can send the SSE headers before the engine answers and keeps
// the stream alive with comment lines while nothing else flows; once the
// headers are out, an engine's non-2xx reply is carried as an SSE error
// event (the status cannot change any more). A non-streaming request
// passes through untouched.
type liveWriter struct {
	http.ResponseWriter
	stream     bool
	keepAlive  time.Duration
	earlyAfter time.Duration

	mu          sync.Mutex
	headersSent bool // the 200 + text/event-stream went out
	live        bool // keep-alive comments are on
	failStatus  int  // a non-2xx status seen after headersSent
	failBody    bytes.Buffer
	last        time.Time
	closed      bool
	stop        chan struct{}
	stopOnce    sync.Once
	early       *time.Timer
}

func newLiveWriter(w http.ResponseWriter, stream bool, keepAlive, earlyAfter time.Duration) *liveWriter {
	return &liveWriter{ResponseWriter: w, stream: stream, keepAlive: keepAlive, earlyAfter: earlyAfter, last: time.Now(), stop: make(chan struct{})}
}

// Unwrap lets http.ResponseController reach the underlying writer
// (httputil.ReverseProxy flushes through it).
func (l *liveWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }

func (l *liveWriter) Flush() {
	if f, ok := l.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// sendHeadersNow writes the SSE headers (and an optional first comment)
// before any engine reply, then starts the keep-alive.
func (l *liveWriter) sendHeadersNow(comment string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sendHeadersLocked()
	if comment != "" {
		_, _ = l.ResponseWriter.Write([]byte(comment + "\n\n"))
		l.Flush()
		l.last = time.Now()
	}
}

func (l *liveWriter) sendHeadersLocked() {
	if l.headersSent || l.closed {
		return
	}
	h := l.ResponseWriter.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	l.ResponseWriter.WriteHeader(http.StatusOK)
	l.Flush()
	l.headersSent = true
	l.last = time.Now()
	l.startKeepAliveLocked()
}

// armEarlyHeaders starts the clock on an admitted streaming request: if
// the engine has not answered by earlyAfter, the headers go out and the
// keep-alive starts.
func (l *liveWriter) armEarlyHeaders() {
	if !l.stream || l.earlyAfter <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.headersSent || l.closed {
		return
	}
	l.early = time.AfterFunc(l.earlyAfter, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.sendHeadersLocked()
	})
}

func (l *liveWriter) startKeepAliveLocked() {
	if l.live || !l.stream || l.keepAlive <= 0 {
		return
	}
	l.live = true
	go func() {
		t := time.NewTicker(l.keepAlive / 2)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				l.mu.Lock()
				if !l.closed && l.failStatus == 0 && time.Since(l.last) >= l.keepAlive {
					_, _ = l.ResponseWriter.Write([]byte(": keep-alive\n\n"))
					l.Flush()
					l.last = time.Now()
				}
				l.mu.Unlock()
			}
		}
	}()
}

func (l *liveWriter) stopKeepAlive() {
	l.stopOnce.Do(func() { close(l.stop) })
	l.mu.Lock()
	if l.early != nil {
		l.early.Stop()
	}
	l.mu.Unlock()
}

func (l *liveWriter) WriteHeader(code int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.early != nil {
		l.early.Stop()
	}
	if l.headersSent {
		if code/100 != 2 {
			// Too late for a status: carry the engine's refusal in-band.
			l.failStatus = code
		}
		return
	}
	l.ResponseWriter.WriteHeader(code)
	l.headersSent = true
	l.last = time.Now()
	if strings.HasPrefix(l.ResponseWriter.Header().Get("Content-Type"), "text/event-stream") {
		l.startKeepAliveLocked()
	}
}

func (l *liveWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.early != nil {
		l.early.Stop()
	}
	if l.failStatus != 0 {
		if l.failBody.Len() < 64<<10 {
			l.failBody.Write(p)
		}
		return len(p), nil
	}
	if !l.headersSent {
		// net/http would send 200 implicitly; keep our bookkeeping true.
		l.ResponseWriter.WriteHeader(http.StatusOK)
		l.headersSent = true
		if strings.HasPrefix(l.ResponseWriter.Header().Get("Content-Type"), "text/event-stream") {
			l.startKeepAliveLocked()
		}
	}
	n, err := l.ResponseWriter.Write(p)
	l.last = time.Now()
	return n, err
}

// close ends the keep-alive and, when an engine refusal arrived after the
// headers were out, writes it as the stream's error event.
func (l *liveWriter) close() {
	l.stopKeepAlive()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.failStatus == 0 {
		return
	}
	msg := strings.TrimSpace(l.failBody.String())
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(l.failBody.Bytes(), &e) == nil && e.Error.Message != "" {
		msg = e.Error.Message
	}
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	b, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": msg, "type": "node_agent_proxy_error", "code": "backend_error", "status": l.failStatus}})
	_, _ = fmt.Fprintf(l.ResponseWriter, "data: %s\n\ndata: [DONE]\n\n", b)
	l.Flush()
}
