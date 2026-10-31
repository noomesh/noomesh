// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEngine is a vLLM-shaped server: /health answers 503 until healthyAfter
// probes, then 200; /v1/chat/completions runs chat.
type fakeEngine struct {
	healthyAfter int32
	probes       atomic.Int32
	healthyAt    atomic.Int64 // unix nanos of the first 200, 0 before
	chats        atomic.Int32
	chatAt       atomic.Int64
	chat         func(w http.ResponseWriter, r *http.Request)

	mu     sync.Mutex
	bodies []map[string]any
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		if f.probes.Add(1) <= f.healthyAfter {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.healthyAt.CompareAndSwap(0, time.Now().UnixNano())
		w.WriteHeader(http.StatusOK)
	case "/v1/chat/completions":
		f.chats.Add(1)
		f.chatAt.Store(time.Now().UnixNano())
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		if f.chat != nil {
			f.chat(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	default:
		http.NotFound(w, r)
	}
}

func testWarmer(t *testing.T, f *fakeEngine) *backendWarmer {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	w := newBackendWarmer(func(context.Context, string) (warmTarget, error) {
		return warmTarget{base: srv.URL, client: srv.Client(), model: "served-model"}, nil
	})
	w.healthEvery = 5 * time.Millisecond
	w.healthBudget = 5 * time.Second
	w.requestTimeout = 5 * time.Second
	return w
}

// report is one heartbeat's backend_containers with Docker calling the
// engine healthy.
func report(started int64) map[string]any {
	return map[string]any{
		"vllm":     map[string]any{"running": true, "started_at": started, "health": "healthy"},
		"llamacpp": map[string]any{"running": true, "started_at": started, "health": "healthy"},
	}
}

func vllmLife(m map[string]any) map[string]any { return m["vllm"].(map[string]any) }

// gateUntilDone runs the gate like successive heartbeats until the warmup
// ends, and returns the last report.
func gateUntilDone(t *testing.T, w *backendWarmer, started int64) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m := report(started)
		w.gate(context.Background(), m)
		if vllmLife(m)["warmup"] != "running" {
			return m
		}
		if h := vllmLife(m)["health"]; h != "starting" {
			t.Fatalf("health %v while the warmup runs; want starting", h)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("warmup never finished")
	return nil
}

// captureWarn sends slog to a buffer for the test.
func captureWarn(t *testing.T) *lockedBuf {
	t.Helper()
	buf := &lockedBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Exactly one warm request, sent only after /health answered 200; the
// backend reads `starting` until it returns, then Docker's own health; later
// heartbeats send nothing more, and a new container start warms again.
func TestWarmupOneRequestAfterHealthThenReady(t *testing.T) {
	release := make(chan struct{})
	f := &fakeEngine{healthyAfter: 3}
	f.chat = func(w http.ResponseWriter, r *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}
	w := testWarmer(t, f)

	// While the warm request is held open, every heartbeat says starting.
	deadline := time.Now().Add(5 * time.Second)
	for f.chats.Load() == 0 && time.Now().Before(deadline) {
		m := report(1000)
		w.gate(context.Background(), m)
		if vllmLife(m)["health"] != "starting" || vllmLife(m)["warmup"] != "running" {
			t.Fatalf("before the warm request returned: %v", vllmLife(m))
		}
		if m["llamacpp"].(map[string]any)["health"] != "healthy" {
			t.Fatal("a backend that is not warmed was held")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f.chats.Load() != 1 {
		t.Fatalf("warm requests = %d, want 1", f.chats.Load())
	}
	if f.healthyAt.Load() == 0 || f.chatAt.Load() < f.healthyAt.Load() {
		t.Fatalf("warm request before /health answered 200 (probes %d)", f.probes.Load())
	}
	for i := 0; i < 5; i++ {
		m := report(1000)
		w.gate(context.Background(), m)
		if vllmLife(m)["health"] != "starting" {
			t.Fatalf("ready before the warm request returned: %v", vllmLife(m))
		}
	}
	close(release)

	m := gateUntilDone(t, w, 1000)
	if got := vllmLife(m); got["health"] != "healthy" || got["warmup"] != "ok" {
		t.Fatalf("after the warmup: %v", got)
	}
	for i := 0; i < 10; i++ { // later heartbeats / reconcile ticks
		w.gate(context.Background(), report(1000))
	}
	time.Sleep(20 * time.Millisecond)
	if n := f.chats.Load(); n != 1 {
		t.Fatalf("warm requests after more heartbeats = %d, want 1", n)
	}
	f.mu.Lock()
	b := f.bodies[0]
	f.mu.Unlock()
	if b["model"] != "served-model" || b["max_tokens"] != float64(1) || b["temperature"] != float64(0) {
		t.Fatalf("warm request body = %v", b)
	}
	if msgs, _ := b["messages"].([]any); len(msgs) != 1 {
		t.Fatalf("warm request messages = %v", b["messages"])
	}

	// A recreate (new start time) warms once more.
	gateUntilDone(t, w, 2000)
	if n := f.chats.Load(); n != 2 {
		t.Fatalf("warm requests after a recreate = %d, want 2", n)
	}
}

// A warm request that fails still ends ready, with a WARN.
func TestWarmupFailureStillReadyWithWarn(t *testing.T) {
	logs := captureWarn(t)
	f := &fakeEngine{chat: func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}}
	w := testWarmer(t, f)
	m := gateUntilDone(t, w, 1000)
	if got := vllmLife(m); got["health"] != "healthy" || got["warmup"] != "failed" {
		t.Fatalf("after a failed warmup: %v", got)
	}
	if s := logs.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "backend warmup failed") {
		t.Fatalf("no WARN for the failed warmup:\n%s", s)
	}
	if f.chats.Load() != 1 {
		t.Fatalf("warm requests = %d, want 1 (no retry)", f.chats.Load())
	}
}

// A warm request that outlives its bound ends ready, with a WARN.
func TestWarmupTimeoutStillReadyWithWarn(t *testing.T) {
	logs := captureWarn(t)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	f := &fakeEngine{chat: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}}
	w := testWarmer(t, f)
	w.requestTimeout = 100 * time.Millisecond
	m := gateUntilDone(t, w, 1000)
	if got := vllmLife(m); got["health"] != "healthy" || got["warmup"] != "timeout" {
		t.Fatalf("after a timed-out warmup: %v", got)
	}
	if s := logs.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "backend warmup timed out") {
		t.Fatalf("no WARN for the timed-out warmup:\n%s", s)
	}
}

// An engine whose /health never answers 200 is not held: once the wait
// is spent it reads as Docker says, with a WARN and no warm request.
func TestWarmupNoHealthDoesNotWedge(t *testing.T) {
	logs := captureWarn(t)
	f := &fakeEngine{healthyAfter: 1 << 30}
	w := testWarmer(t, f)
	w.healthBudget = 50 * time.Millisecond
	m := gateUntilDone(t, w, 1000)
	if got := vllmLife(m); got["health"] != "healthy" || got["warmup"] != "no_health" {
		t.Fatalf("after /health never answered: %v", got)
	}
	if f.chats.Load() != 0 {
		t.Fatal("a warm request went to an engine that never answered /health")
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Fatal("no WARN")
	}
}

// Docker's unhealthy, and a stopped or orphan container, pass through.
func TestWarmupLeavesOtherStatesAlone(t *testing.T) {
	f := &fakeEngine{}
	w := testWarmer(t, f)
	m := map[string]any{"vllm": map[string]any{"running": false, "started_at": int64(1), "health": "healthy"}}
	w.gate(context.Background(), m)
	if vllmLife(m)["health"] != "healthy" || vllmLife(m)["warmup"] != nil {
		t.Fatalf("stopped container touched: %v", vllmLife(m))
	}
	m = map[string]any{"vllm": map[string]any{"running": true, "started_at": int64(1), "health": "healthy", "orphan": true}}
	w.gate(context.Background(), m)
	if vllmLife(m)["health"] != "healthy" {
		t.Fatalf("orphan container held: %v", vllmLife(m))
	}
	m = map[string]any{"vllm": map[string]any{"running": true, "started_at": int64(5), "health": "unhealthy"}}
	w.gate(context.Background(), m)
	if vllmLife(m)["health"] != "unhealthy" {
		t.Fatalf("unhealthy rewritten: %v", vllmLife(m))
	}
}
