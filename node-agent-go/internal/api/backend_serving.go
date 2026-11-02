// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

// Is the model server answering? (followup 185b, case 2.)
//
// The heartbeat comes from this agent, not from the engine, so a hung vLLM
// (the V2-runner wedge: container healthy, /health 200, every request times
// out) kept its node a first-class chat candidate for as long as the agent
// beat. The gateway only learned by sending a user's request into it and
// waiting out the stall.
//
// The agent now says, per engine, `backend_containers.<b>.serving`:
//
//   - every request the inference proxy relays is evidence: the first body
//     byte from the engine is a success, an upstream failure (first-byte
//     timeout, refused connection, a 5xx) is a failure. A caller that went
//     away is neither.
//   - an engine with no evidence for probeIdleEvery, and nothing in flight,
//     gets one probe: the warm request's shape (backend_warm.go: max_tokens
//     1, dialled as the proxy dials), bounded by probeTimeout.
//   - `serving: false` after failedToMark failures in a row with no success
//     between, or one failed probe. While false, the probe runs every
//     probeRecoverEvery, and the first success puts it back.
//
// Nothing is reported until there is evidence, and an engine still warming
// (`warmup: running`) is not probed: absence means serving to the gateway,
// as it does for an agent that predates the field. A recreated container
// starts over.
//
// Engines only (servedBackends). An ollama loads a model on the request
// that names it, so a probe would load, or keep resident, a model nobody
// asked for.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

// servedBackends are the engines whose serving is reported.
var servedBackends = map[string]bool{"vllm": true, "vllm-secondary": true, "llamacpp": true}

const (
	// probeIdleEvery: an engine that answered nothing for this long, with
	// nothing in flight, is probed.
	probeIdleEvery = 5 * time.Minute
	// probeRecoverEvery: how often an engine reported not serving is probed.
	probeRecoverEvery = 60 * time.Second
	// probeTimeout bounds one probe. One token from an idle engine; the
	// gateway gives a first token 30 s.
	probeTimeout = 60 * time.Second
	// failedToMark relayed failures in a row, no success between, mark an
	// engine not serving: one timeout can be one bad request.
	failedToMark = 2
)

type servingState struct {
	startedAt int64
	lastOK    time.Time
	lastFail  time.Time
	lastProbe time.Time
	fails     int
	marked    bool // not serving
	reason    string
	probing   bool
}

// backendServing holds the evidence per engine.
type backendServing struct {
	dial         func(ctx context.Context, backend string) (warmTarget, error)
	inFlight     func(backend string) int
	idleEvery    time.Duration
	recoverEvery time.Duration
	timeout      time.Duration
	now          func() time.Time
	mu           sync.Mutex
	state        map[string]*servingState
}

func newBackendServing(dial func(ctx context.Context, backend string) (warmTarget, error)) *backendServing {
	return &backendServing{
		dial:         dial,
		inFlight:     occupancy.InFlight,
		idleEvery:    probeIdleEvery,
		recoverEvery: probeRecoverEvery,
		timeout:      probeTimeout,
		now:          time.Now,
		state:        map[string]*servingState{},
	}
}

func (b *backendServing) entry(backend string) *servingState {
	st := b.state[backend]
	if st == nil {
		st = &servingState{}
		b.state[backend] = st
	}
	return st
}

// ok records an answer from the engine.
func (b *backendServing) ok(backend string) {
	if b == nil || !servedBackends[backend] {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.entry(backend)
	st.lastOK, st.fails, st.marked, st.reason = b.now(), 0, false, ""
}

// fail records a failure; decisive (a probe) marks at once.
func (b *backendServing) fail(backend, reason string, decisive bool) {
	if b == nil || !servedBackends[backend] {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.entry(backend)
	st.lastFail = b.now()
	st.fails++
	if decisive || st.fails >= failedToMark {
		if !st.marked {
			slog.Warn("backend not serving: its model server is not answering; the controller routes around it",
				"backend", backend, "reason", reason, "failures", st.fails)
		}
		st.marked, st.reason = true, reason
	}
}

// gate edits a `backend_containers` report in place: `serving` on every
// engine with evidence, and a probe started for any that is due. ctx bounds
// the probes (the agent's life).
func (b *backendServing) gate(ctx context.Context, m map[string]any) {
	for key, v := range m {
		if !servedBackends[key] {
			continue
		}
		life, ok := v.(map[string]any)
		if !ok {
			continue
		}
		running, _ := life["running"].(bool)
		started, _ := life["started_at"].(int64)
		if orphan, _ := life["orphan"].(bool); !running || orphan {
			continue
		}
		if w, _ := life["warmup"].(string); w == "running" {
			continue // not ready yet; the warmup says so
		}
		if serving, reason, known := b.verdict(ctx, key, started); known {
			life["serving"] = serving
			if !serving {
				life["serving_reason"] = reason
			}
		}
	}
}

// verdict resets the evidence on a new container start, starts a probe when
// one is due, and says what is known.
func (b *backendServing) verdict(ctx context.Context, backend string, startedAt int64) (bool, string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.entry(backend)
	if st.startedAt != startedAt {
		// A recreated container starts over. The first start seen keeps
		// what the proxy noted before the first report.
		if st.startedAt != 0 {
			*st = servingState{probing: st.probing}
		}
		st.startedAt = startedAt
	}
	now := b.now()
	last := st.lastOK
	for _, t := range []time.Time{st.lastFail, st.lastProbe} {
		if t.After(last) {
			last = t
		}
	}
	due := now.Sub(last) >= b.idleEvery
	if st.marked {
		due = now.Sub(st.lastProbe) >= b.recoverEvery
	}
	if due && !st.probing && b.inFlight(backend) == 0 {
		st.probing, st.lastProbe = true, now
		go b.probe(ctx, backend)
	}
	known := !st.lastOK.IsZero() || !st.lastFail.IsZero()
	return !st.marked, st.reason, known
}

func (b *backendServing) probe(ctx context.Context, backend string) {
	defer func() {
		b.mu.Lock()
		b.entry(backend).probing = false
		b.mu.Unlock()
	}()
	t, err := b.dial(ctx, backend)
	if err != nil {
		return // not running as far as the proxy can tell: nothing to say
	}
	err = (&backendWarmer{requestTimeout: b.timeout}).request(ctx, t)
	switch {
	case ctx.Err() != nil:
	case err == nil:
		b.ok(backend)
	case errors.Is(err, context.DeadlineExceeded):
		b.fail(backend, fmt.Sprintf("probe got no answer in %s", b.timeout), true)
	default:
		b.fail(backend, "probe failed: "+err.Error(), true)
	}
}

// firstByteBody notes the engine's first body byte as a success.
type firstByteBody struct {
	io.ReadCloser
	once sync.Once
	seen func()
}

func (f *firstByteBody) Read(p []byte) (int, error) {
	n, err := f.ReadCloser.Read(p)
	if n > 0 {
		f.once.Do(f.seen)
	}
	return n, err
}

// observe is the proxy's evidence: a 5xx is a failure, anything else is a
// success at its first body byte.
func (b *backendServing) observe(backend string, resp *http.Response) {
	if b == nil || !servedBackends[backend] || resp == nil {
		return
	}
	if resp.StatusCode >= 500 {
		b.fail(backend, fmt.Sprintf("answered %d", resp.StatusCode), false)
		return
	}
	if resp.Body != nil {
		resp.Body = &firstByteBody{ReadCloser: resp.Body, seen: func() { b.ok(backend) }}
	}
}

// servingTracker is the Server's tracker, built on first use.
func (s *Server) servingTracker() *backendServing {
	s.servingOnce.Do(func() {
		if s.serving == nil {
			s.serving = newBackendServing(s.warmDial)
		}
	})
	return s.serving
}

// GateBackendServing applies the serving report to a `backend_containers`
// report (see the file comment). Run after GateBackendWarmup, which it
// reads. ctx is the agent's life: it bounds the probes.
func (s *Server) GateBackendServing(ctx context.Context, m map[string]any) {
	if s == nil || m == nil {
		return
	}
	s.servingTracker().gate(ctx, m)
}
