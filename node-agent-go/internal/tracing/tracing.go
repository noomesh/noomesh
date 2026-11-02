// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package tracing continues the gateway's request traces on a node (i359 C2).
//
// The gateway sends a W3C traceparent with every call to a node's inference
// proxy. The agent makes one span for the work it did on that call (picking
// the backend, waiting for a slot, relaying the answer to its end), parented
// on the gateway's span, and passes its own span on to the local backend.
// A node never STARTS a trace: a call without a valid traceparent makes no
// span.
//
// Spans go to the gateway's node route POST /api/cluster/nodes/{id}/traces
// (Tempo is on the controller's Docker network only), as OTLP/HTTP JSON, in
// batches, with the agent's own client and cluster credential, over https
// only. Best effort by design: a bounded queue that drops (and counts) when
// full, and a batch the gateway does not take is dropped, never spilled.
// Metadata only: span names, ids, timings, the backend, the status.
package tracing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	queueCap   = 4096
	batchMax   = 256
	flushEvery = 5 * time.Second
	pushTimout = 10 * time.Second
	// ServiceName is what the gateway stamps on every node span anyway.
	ServiceName = "noo-node-agent"
)

var traceparentRE = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

// ParseTraceparent returns the trace id and the caller's span id of a
// well-formed traceparent. All-zero ids are invalid.
func ParseTraceparent(v string) (traceID, parentID string, ok bool) {
	m := traceparentRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil || strings.Trim(m[1], "0") == "" || strings.Trim(m[2], "0") == "" {
		return "", "", false
	}
	return m[1], m[2], true
}

func newSpanID() string {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err == nil && b != [8]byte{} {
			return hex.EncodeToString(b[:])
		}
	}
}

// Span is one unit of work on this node. Every method is safe on a nil
// *Span, so a call site never checks whether the call was traced.
type Span struct {
	TraceID, SpanID, ParentID, Name string
	Kind                            int
	StartTime, EndTime              time.Time
	mu                              sync.Mutex
	strs                            map[string]string
	ints                            map[string]int64
	Error                           bool
	ended                           atomic.Bool
}

// Start continues traceparent with a SERVER span named name, or returns nil
// when traceparent is not a valid W3C traceparent.
func Start(name, traceparent string) *Span {
	tid, pid, ok := ParseTraceparent(traceparent)
	if !ok {
		return nil
	}
	return &Span{TraceID: tid, SpanID: newSpanID(), ParentID: pid, Name: name, Kind: 2, StartTime: time.Now(),
		strs: map[string]string{}, ints: map[string]int64{}}
}

// Traceparent is the header the next hop continues from.
func (s *Span) Traceparent() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("00-%s-%s-01", s.TraceID, s.SpanID)
}

// SetStr records a text attribute (a name or an id, never content).
func (s *Span) SetStr(k, v string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.strs[k] = v
	s.mu.Unlock()
}

// SetInt records an integer attribute.
func (s *Span) SetInt(k string, v int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.ints[k] = v
	s.mu.Unlock()
}

// End closes the span once, with the HTTP status the call answered (0 when
// none), and hands it to the default exporter.
func (s *Span) End(status int) {
	if s == nil || !s.ended.CompareAndSwap(false, true) {
		return
	}
	s.EndTime = time.Now()
	if status > 0 {
		s.SetInt("http.response.status_code", int64(status))
		s.Error = status >= 500
	}
	if e := defaultExporter.Load(); e != nil {
		e.Record(s)
	}
}

// otlp is the span in the OTLP/HTTP JSON shape.
func (s *Span) otlp() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	attrs := make([]map[string]any, 0, len(s.strs)+len(s.ints))
	for k, v := range s.strs {
		attrs = append(attrs, map[string]any{"key": k, "value": map[string]any{"stringValue": v}})
	}
	for k, v := range s.ints {
		attrs = append(attrs, map[string]any{"key": k, "value": map[string]any{"intValue": strconv.FormatInt(v, 10)}})
	}
	code := 1
	if s.Error {
		code = 2
	}
	return map[string]any{
		"traceId":           s.TraceID,
		"spanId":            s.SpanID,
		"parentSpanId":      s.ParentID,
		"name":              s.Name,
		"kind":              s.Kind,
		"startTimeUnixNano": strconv.FormatInt(s.StartTime.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(s.EndTime.UnixNano(), 10),
		"attributes":        attrs,
		"status":            map[string]any{"code": code},
	}
}

// Body is the OTLP/HTTP JSON request body for a batch.
func Body(spans []*Span) ([]byte, error) {
	out := make([]map[string]any, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.otlp())
	}
	return json.Marshal(map[string]any{
		"resourceSpans": []any{map[string]any{
			"resource":   map[string]any{"attributes": []any{map[string]any{"key": "service.name", "value": map[string]any{"stringValue": ServiceName}}}},
			"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": ServiceName}, "spans": out}},
		}},
	})
}

// Exporter batches spans to the gateway's node span route.
type Exporter struct {
	url     string
	client  *http.Client
	auth    func(*http.Request) error
	ch      chan *Span
	dropped atomic.Int64
	sent    atomic.Int64
}

// NewExporter refuses a plaintext controller URL: spans and the cluster
// credential travel over TLS only.
func NewExporter(controllerURL, nodeID string, client *http.Client, auth func(*http.Request) error) (*Exporter, error) {
	u := strings.TrimRight(strings.TrimSpace(controllerURL), "/")
	if !strings.HasPrefix(strings.ToLower(u), "https://") {
		return nil, fmt.Errorf("span export refuses a plaintext controller URL %q — spans and the cluster token travel over TLS only", controllerURL)
	}
	if nodeID == "" {
		return nil, errors.New("span export needs a node id")
	}
	if client == nil {
		return nil, errors.New("span export needs the agent's HTTP client")
	}
	return &Exporter{url: u + "/api/cluster/nodes/" + nodeID + "/traces", client: client, auth: auth, ch: make(chan *Span, queueCap)}, nil
}

// Record queues a finished span; a full queue drops it and counts.
func (e *Exporter) Record(s *Span) {
	select {
	case e.ch <- s:
	default:
		e.dropped.Add(1)
	}
}

// State is what the heartbeat reports: spans sent and dropped so far.
func (e *Exporter) State() map[string]any {
	return map[string]any{"sent": e.sent.Load(), "dropped": e.dropped.Load()}
}

// Push sends one batch and reports how long to wait before the next (a
// 429's Retry-After), or 0.
func (e *Exporter) Push(ctx context.Context, batch []*Span) time.Duration {
	body, err := Body(batch)
	if err != nil {
		e.dropped.Add(int64(len(batch)))
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, pushTimout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		e.dropped.Add(int64(len(batch)))
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	if e.auth != nil {
		if err := e.auth(req); err != nil {
			e.dropped.Add(int64(len(batch)))
			return 0
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.dropped.Add(int64(len(batch)))
		slog.Debug("span export failed", "error", err)
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 == 2 {
		e.sent.Add(int64(len(batch)))
		return 0
	}
	e.dropped.Add(int64(len(batch)))
	if resp.StatusCode == http.StatusTooManyRequests {
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 && n <= 120 {
			return time.Duration(n) * time.Second
		}
		return time.Minute
	}
	slog.Debug("span export refused", "status", resp.StatusCode)
	return 0
}

// Run flushes batches until ctx ends.
func (e *Exporter) Run(ctx context.Context) {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	var batch []*Span
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wait := e.Push(ctx, batch)
		batch = nil
		if wait > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-e.ch:
			batch = append(batch, s)
			if len(batch) >= batchMax {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

var defaultExporter atomic.Pointer[Exporter]

// SetDefault makes e the exporter every Span.End hands its span to.
func SetDefault(e *Exporter) { defaultExporter.Store(e) }
