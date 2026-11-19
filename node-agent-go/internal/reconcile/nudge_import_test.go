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

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
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

// gatedVerify is a verify loop whose passes block until released, and that
// counts the nudges it asks for.
type gatedVerify struct {
	l       *ollamaVerifyLoop
	release chan struct{}
	mu      sync.Mutex
	nudges  int
	checked []string
}

func newGatedVerify() *gatedVerify {
	g := &gatedVerify{release: make(chan struct{})}
	g.l = newOllamaVerifyLoop(func(_ context.Context, model, _ string) dockerpkg.OllamaVerifyResult {
		<-g.release
		g.mu.Lock()
		g.checked = append(g.checked, model)
		g.mu.Unlock()
		return dockerpkg.OllamaVerifyResult{Model: model, State: dockerpkg.OllamaVerified}
	}, func() {
		g.mu.Lock()
		g.nudges++
		g.mu.Unlock()
	})
	return g
}

func (g *gatedVerify) nudgeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.nudges
}

// waitIdle waits for the running pass to end (busy cleared, nudge sent).
func (g *gatedVerify) waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		g.l.mu.Lock()
		busy := g.l.busy
		g.l.mu.Unlock()
		if !busy {
			time.Sleep(20 * time.Millisecond) // the deferred nudge follows busy=false
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the verify pass never ended")
}

// A model that became due while a pass was busy (an import finished during
// another model's first hash) is checked after that pass, not at the next
// interval: the pass ends with ONE nudge.
func TestVerifySkippedWhileBusy_NudgesAfterPass(t *testing.T) {
	g := newGatedVerify()
	ctx := context.Background()
	g.l.schedule(ctx, []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	// The next ticks, while that pass runs: a new model is due.
	g.l.schedule(ctx, []string{"llama3.2:1b", "qwen2.5:0.5b"}, dockerpkg.OllamaLaneContainer)
	g.l.schedule(ctx, []string{"llama3.2:1b", "qwen2.5:0.5b"}, dockerpkg.OllamaLaneContainer)
	close(g.release)
	g.waitIdle(t)
	if n := g.nudgeCount(); n != 1 {
		t.Fatalf("nudges = %d after a pass that skipped a due model, want exactly 1", n)
	}
	// The nudged tick starts the waiting model's pass.
	g.l.schedule(ctx, []string{"llama3.2:1b", "qwen2.5:0.5b"}, dockerpkg.OllamaLaneContainer)
	g.waitIdle(t)
	g.mu.Lock()
	checked := append([]string(nil), g.checked...)
	g.mu.Unlock()
	if len(checked) != 2 || checked[1] != "qwen2.5:0.5b" {
		t.Fatalf("checked = %v, want the waiting model on the nudged tick", checked)
	}
	if n := g.nudgeCount(); n != 1 {
		t.Fatalf("nudges = %d, want still 1: the second pass skipped nothing", n)
	}

	// Wired in production: the loop New builds nudges the reconciler.
	r := tickFixture(t, &listDaemon{})
	if r.ollamaVerify.nudge == nil {
		t.Fatal("New must give the verify loop the reconciler's Nudge")
	}
	r.ollamaVerify.nudge()
	if n := r.nudges.Load(); n != 1 {
		t.Fatalf("the verify loop's nudge reached Reconciler.Nudge %d time(s), want 1", n)
	}
}

// A pass that skipped nothing does not nudge, so a quiet node gets no extra
// ticks: not alone, and not when the ticks during it found nothing due.
func TestVerifyPassSkippedNothing_NoNudge(t *testing.T) {
	g := newGatedVerify()
	ctx := context.Background()
	g.l.schedule(ctx, []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	g.l.schedule(ctx, nil, dockerpkg.OllamaLaneContainer) // a tick with nothing held
	close(g.release)
	g.waitIdle(t)
	// Re-checked just now: not due, so a tick schedules nothing.
	g.l.schedule(ctx, []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	g.waitIdle(t)
	if n := g.nudgeCount(); n != 0 {
		t.Fatalf("nudges = %d after passes that skipped nothing, want 0", n)
	}
}
