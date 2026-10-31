// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

// One warm request before a vLLM engine reads as ready (followup i305).
//
// vLLM compiles Triton kernels for the shapes of its first requests
// (`jit_monitor.py`: "Triton kernel JIT compilation during inference:
// kernel_unified_attention ... consider extending warmup to cover this
// shape/config"), so the first chat after every start paid the compile:
// ~25 s on awolf. Its own load-time warmup does not cover a short chat at
// max_tokens 1, and its GET /health answers 200 before any of it.
//
// The agent now sends that request itself, once per container start: after
// the engine's /health answers 200, ONE minimal chat completion (max_tokens
// 1, temperature 0, the model it serves), dialled exactly as the inference
// proxy dials the engine (inferenceTarget + inferenceTransport: the door, the
// node leaf). Until it returns, the heartbeat's `backend_containers.vllm`
// says `health: starting` even when Docker says healthy, and carries
// `warmup: running`; after, Docker's own health and `warmup: ok|failed|
// timeout|no_health`. A failed or slow warmup logs a WARN and the backend
// reads ready anyway: a warmup never wedges a backend.
//
// Keyed by the container's start time, so a recreate or a restart warms
// again and a reconcile tick or a heartbeat does not.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// warmedBackends are the backends that get a warm request. vLLM only: it is
// the one that compiles at request time.
var warmedBackends = map[string]bool{"vllm": true}

const (
	// warmHealthEvery is how often the engine's /health is asked before the
	// warm request.
	warmHealthEvery = 2 * time.Second
	// warmHealthBudget bounds the wait for /health: the container's own
	// healthcheck allows a 900 s cold model load (backends.go).
	warmHealthBudget = 20 * time.Minute
	// warmRequestTimeout bounds the warm request itself.
	warmRequestTimeout = 120 * time.Second
)

// warmTarget is how to reach one backend: its base URL (no path), the
// client that dials it, and the model it serves.
type warmTarget struct {
	base   string
	client *http.Client
	model  string
}

// backendWarmer runs one warm request per backend container start.
type backendWarmer struct {
	dial           func(ctx context.Context, backend string) (warmTarget, error)
	healthEvery    time.Duration
	healthBudget   time.Duration
	requestTimeout time.Duration

	mu   sync.Mutex
	runs map[string]*warmRun // backend -> the run for its current start
}

type warmRun struct {
	startedAt int64
	done      bool
	result    string // ok | failed | timeout | no_health
	cancel    context.CancelFunc
}

func newBackendWarmer(dial func(ctx context.Context, backend string) (warmTarget, error)) *backendWarmer {
	return &backendWarmer{
		dial:           dial,
		healthEvery:    warmHealthEvery,
		healthBudget:   warmHealthBudget,
		requestTimeout: warmRequestTimeout,
		runs:           map[string]*warmRun{},
	}
}

// gate edits a `backend_containers` report in place: it starts the warmup of
// every warmed backend whose container start it has not seen, and holds a
// Docker `healthy` at `starting` until that warmup is done. ctx bounds the
// warmup goroutines (the agent's life, not a heartbeat's).
func (w *backendWarmer) gate(ctx context.Context, m map[string]any) {
	for key, v := range m {
		if !warmedBackends[key] {
			continue
		}
		life, ok := v.(map[string]any)
		if !ok {
			continue
		}
		running, _ := life["running"].(bool)
		started, ok := life["started_at"].(int64)
		if !running || !ok {
			continue
		}
		if orphan, _ := life["orphan"].(bool); orphan {
			continue // nobody's container: the adopted lane serves this key
		}
		done, result := w.ensure(ctx, key, started)
		if done {
			life["warmup"] = result
			continue
		}
		life["warmup"] = "running"
		if h, _ := life["health"].(string); h == "healthy" {
			life["health"] = "starting"
		}
	}
}

// ensure starts the warmup for (backend, startedAt) unless it has one, and
// says whether it is done and how it ended.
func (w *backendWarmer) ensure(ctx context.Context, backend string, startedAt int64) (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r := w.runs[backend]; r != nil && r.startedAt == startedAt {
		return r.done, r.result
	}
	if old := w.runs[backend]; old != nil && old.cancel != nil {
		old.cancel() // a newer start: the old container is gone
	}
	rctx, cancel := context.WithCancel(ctx)
	r := &warmRun{startedAt: startedAt, cancel: cancel}
	w.runs[backend] = r
	go func() {
		result := w.warm(rctx, backend)
		w.mu.Lock()
		r.done, r.result = true, result
		w.mu.Unlock()
	}()
	return false, ""
}

// warm waits for the engine's /health, then sends the one warm request.
// Every outcome but "ok" is logged at WARN; none of them blocks readiness.
func (w *backendWarmer) warm(ctx context.Context, backend string) string {
	t, ok := w.awaitHealth(ctx, backend)
	if !ok {
		if ctx.Err() != nil {
			return "failed"
		}
		slog.Warn("backend warmup skipped: /health never answered 200; reporting ready without a warm request",
			"backend", backend, "waited", w.healthBudget)
		return "no_health"
	}
	start := time.Now()
	err := w.request(ctx, t)
	took := time.Since(start).Round(time.Millisecond)
	switch {
	case err == nil:
		slog.Info("backend warmed", "backend", backend, "model", t.model, "took", took)
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		slog.Warn("backend warmup timed out; reporting ready anyway",
			"backend", backend, "model", t.model, "timeout", w.requestTimeout)
		return "timeout"
	default:
		slog.Warn("backend warmup failed; reporting ready anyway",
			"backend", backend, "model", t.model, "took", took, "error", err)
		return "failed"
	}
}

// awaitHealth asks the engine's /health every healthEvery until it answers
// 200, within healthBudget. The target is re-dialled until it resolves: the
// container may not be listed as running yet.
func (w *backendWarmer) awaitHealth(ctx context.Context, backend string) (warmTarget, bool) {
	deadline := time.Now().Add(w.healthBudget)
	for {
		if t, err := w.dial(ctx, backend); err == nil && healthOK(ctx, t) {
			return t, true
		}
		if time.Now().After(deadline) {
			return warmTarget{}, false
		}
		select {
		case <-ctx.Done():
			return warmTarget{}, false
		case <-time.After(w.healthEvery):
		}
	}
}

func healthOK(ctx context.Context, t warmTarget) bool {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, t.base+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// request sends the one warm chat: the shape the gateway's short requests
// have (a few prompt tokens, max_tokens 1), which is what the engine's
// request-time compile was for.
func (w *backendWarmer) request(ctx context.Context, t warmTarget) error {
	rctx, cancel := context.WithTimeout(ctx, w.requestTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{
		"model":       t.model,
		"messages":    []map[string]string{{"role": "user", "content": "Reply with one word: ok"}},
		"max_tokens":  1,
		"temperature": 0,
		"stream":      false,
	})
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, t.base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		if rctx.Err() != nil {
			return context.DeadlineExceeded
		}
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil && rctx.Err() != nil {
		return context.DeadlineExceeded
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// warmDial reaches a running backend exactly as the inference proxy does:
// inferenceTarget (the door the running containers declare) and
// inferenceTransport (the node leaf for https, the bridge dialer otherwise).
func (s *Server) warmDial(ctx context.Context, backend string) (warmTarget, error) {
	running, native := s.runningAndNative(ctx)
	model, up := running[backend]
	if !up {
		return warmTarget{}, fmt.Errorf("backend %s is not running", backend)
	}
	base, scheme := s.inferenceTarget(ctx, backend, dockerpkg.BackendPorts[backend], native)
	return warmTarget{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Transport: s.inferenceTransport(scheme, warmRequestTimeout)},
		model:  model,
	}, nil
}

// GateBackendWarmup applies the warmup to a `backend_containers` report (see
// the file comment). ctx is the agent's life: it bounds the warmups.
func (s *Server) GateBackendWarmup(ctx context.Context, m map[string]any) {
	if s == nil || m == nil {
		return
	}
	s.warmOnce.Do(func() {
		if s.warmer == nil {
			s.warmer = newBackendWarmer(s.warmDial)
		}
	})
	s.warmer.gate(ctx, m)
}
