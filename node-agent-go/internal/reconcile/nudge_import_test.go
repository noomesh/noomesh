// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// 0.6.28-rc.2, a hosted node: `noo cluster place <node> ollama qwen2.5:0.5b`
// read verified ~11 min later for ~3 s of import — start tick, import tick,
// verify tick, one full interval apart. The steps that finish off the tick
// now nudge the next pass (the rule above startReadyWithin).

// pendingNudges is how many passes the nudges taken so far will cause.
func pendingNudges(r *Reconciler) int { return len(r.nudgeCh()) }

// A successful import nudges reconcile exactly once.
func TestImportDone_NudgesOnce(t *testing.T) {
	imp := newImportRecorder(nil)
	r := importFixture(t, storeAnswers(true, nil), imp)
	r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)

	if n := r.nudges.Load(); n != 1 {
		t.Fatalf("nudges = %d after one successful import, want exactly 1", n)
	}
	if p := pendingNudges(r); p != 1 {
		t.Fatalf("pending passes = %d, want 1", p)
	}
}

// A failed import never nudges, so it cannot re-import in a loop: two
// failures, each followed by ticks, make one attempt per backoff window.
func TestImportFailed_NoNudgeNoLoop(t *testing.T) {
	imp := newImportRecorder(errors.New("fetch harrier-q8.gguf: sha256 mismatch"))
	r := importFixture(t, storeAnswers(true, nil), imp)
	tickNow := func() {
		r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	}

	for window := 1; window <= 2; window++ {
		tickNow()
		imp.wait(t)
		// Ticks inside the backoff (what a nudge would have brought).
		for i := 0; i < 3; i++ {
			tickNow()
		}
		time.Sleep(50 * time.Millisecond)
		if got := imp.count(); got != window {
			t.Fatalf("window %d: import attempts = %d, want %d (one per backoff window)", window, got, window)
		}
		if n := r.nudges.Load(); n != 0 {
			t.Fatalf("window %d: a failed import nudged %d time(s); its backoff decides the retry", window, n)
		}
		if p := pendingNudges(r); p != 0 {
			t.Fatalf("window %d: pending passes = %d after a failed import, want 0", window, p)
		}
		// Let the backoff run out.
		r.pullMu.Lock()
		r.ollamaPulls["harrier"].lastFailed = time.Now().Add(-ollamaPullRetryAfter - time.Second)
		r.pullMu.Unlock()
	}
}

// An ollama container this agent just started nudges once when it answers,
// then stops asking; one that never answers in time does not nudge.
func TestStartedBackend_ReadyNudgesOnce(t *testing.T) {
	var mu sync.Mutex
	probes := 0
	r := &Reconciler{backendReady: func(_ context.Context, backend, model string) bool {
		mu.Lock()
		defer mu.Unlock()
		probes++
		return backend == "ollama" && model == "qwen2.5:0.5b" && probes >= 3
	}}
	r.nudgeWhenReady(context.Background(), "ollama", "qwen2.5:0.5b", time.Second, 5*time.Millisecond)
	if n := r.nudges.Load(); n != 1 {
		t.Fatalf("nudges = %d once the started backend answered, want exactly 1", n)
	}
	if probes != 3 {
		t.Fatalf("probes = %d, want 3: polling stops at the first ready answer", probes)
	}

	never := &Reconciler{backendReady: func(context.Context, string, string) bool { return false }}
	start := time.Now()
	never.nudgeWhenReady(context.Background(), "ollama", "qwen2.5:0.5b", 50*time.Millisecond, 5*time.Millisecond)
	if n := never.nudges.Load(); n != 0 {
		t.Fatalf("nudges = %d for a backend that never answered, want 0", n)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the poll ran %s, want it bounded by its window", d)
	}

	// The start's success path schedules it: StartBackend's error branch
	// returns, then backendStarted, which polls for ollama.
	src, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start1 := strings.Index(s, "r.docker.StartBackend(ctx, p.Backend")
	call := strings.Index(s, "r.backendStarted(ctx, p.Backend, p.Model)")
	if start1 < 0 || call < start1 {
		t.Fatal("a successful StartBackend in convergeContainer must call backendStarted")
	}
	body := s[strings.Index(s, "func (r *Reconciler) backendStarted("):]
	body = body[:strings.Index(body, "\n}\n")]
	if !strings.Contains(body, "go r.nudgeWhenReady(ctx, backend, model, startReadyWithin, startReadyEvery)") {
		t.Fatal("backendStarted must start the readiness nudge for ollama")
	}
}

// Nudges coalesce: several nudges while no pass has taken one (three
// imports finishing together, a ready backend, the controller's POST
// /reconcile) leave ONE pending pass, not one each.
func TestNudges_Coalesce(t *testing.T) {
	r := &Reconciler{}
	for i := 0; i < 3; i++ {
		r.Nudge()
	}
	if n := r.nudges.Load(); n != 3 {
		t.Fatalf("nudges = %d, want 3", n)
	}
	if p := pendingNudges(r); p != 1 {
		t.Fatalf("pending passes = %d after 3 nudges, want 1: nudges coalesce", p)
	}
	<-r.nudgeCh()
	if p := pendingNudges(r); p != 0 {
		t.Fatalf("pending passes = %d after the one pass took it, want 0", p)
	}
}
