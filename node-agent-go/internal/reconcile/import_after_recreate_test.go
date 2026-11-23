// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// A pass that recreates ollama must not start an import (or pull): it would
// push through the door being replaced. A converged or stuck pass still
// ensures the models.

var ollamaPlacement = placement{Backend: "ollama", Model: "qwen2.5:0.5b", DesiredState: "running"}

func ollamaPassFixture(t *testing.T, label string, ensures, starts *int) (*Reconciler, *tick) {
	t.Helper()
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	r := &Reconciler{
		cfg:            &config.Config{NodeID: "node-a"},
		driftRecreated: map[string]string{},
		ollamaEnsureFn: func(context.Context, *tick) { *ensures++ },
		startBackendFn: func(context.Context, string, string, int, dockerpkg.StartOverrides) error {
			*starts++
			return nil
		},
	}
	tk := &tick{
		desired:    &desiredConfig{},
		running:    map[string]string{"ollama": ollamaPlacement.Model},
		native:     map[string]string{},
		specLabels: map[string]string{},
		floating:   map[string]string{},
	}
	switch label {
	case "converged":
		h, ok := specHashWith(ollamaPlacement, func(ref string) (string, bool) { return dockerpkg.ContentKey(context.Background(), ref) })
		if !ok {
			h = specHash(ollamaPlacement)
		}
		tk.specLabels["ollama"] = h
	case "drifted":
		tk.specLabels["ollama"] = "an-older-spec-hash"
	}
	return r, tk
}

func TestOllamaDriftRecreate_DoesNotEnsureModelsInThePass(t *testing.T) {
	ensures, starts := 0, 0
	r, tk := ollamaPassFixture(t, "drifted", &ensures, &starts)
	r.convergeContainer(context.Background(), tk, ollamaPlacement)
	if starts != 1 {
		t.Fatalf("starts = %d, want the drifted ollama recreated once", starts)
	}
	if ensures != 0 {
		t.Fatalf("ensures = %d: a pass that recreates ollama started an import through the door it replaces", ensures)
	}
	r.pullMu.Lock()
	at := r.ollamaStartedAt
	r.pullMu.Unlock()
	if at.IsZero() {
		t.Fatal("the recreate did not record when ollama was started")
	}
}

func TestOllamaConverged_StillEnsuresModels(t *testing.T) {
	ensures, starts := 0, 0
	r, tk := ollamaPassFixture(t, "converged", &ensures, &starts)
	r.convergeContainer(context.Background(), tk, ollamaPlacement)
	if starts != 0 || ensures != 1 {
		t.Fatalf("starts=%d ensures=%d, want no start and the models ensured once", starts, ensures)
	}
}

func TestOllamaDriftStuck_StillEnsuresModels(t *testing.T) {
	ensures, starts := 0, 0
	r, tk := ollamaPassFixture(t, "drifted", &ensures, &starts)
	r.driftRecreated["ollama"], _ = specHashWith(ollamaPlacement, func(ref string) (string, bool) { return dockerpkg.ContentKey(context.Background(), ref) })
	if r.driftRecreated["ollama"] == "" {
		r.driftRecreated["ollama"] = specHash(ollamaPlacement)
	}
	r.convergeContainer(context.Background(), tk, ollamaPlacement)
	if starts != 0 || ensures != 1 {
		t.Fatalf("starts=%d ensures=%d, want a stuck spec left alone with the models ensured once", starts, ensures)
	}
}

func resetPush(inner error) error {
	op := &net.OpError{Op: "write", Net: "tcp", Err: inner}
	return &url.Error{Op: "Post", URL: "https://noo-stunnel-ollama:11434/api/blobs/sha256:005f", Err: op}
}

func TestDoorReplaced_TypedAndWindowed(t *testing.T) {
	now := time.Now()
	recent := now.Add(-10 * time.Second)
	old := now.Add(-importRecentStartWindow - time.Second)
	cases := []struct {
		name  string
		err   error
		start time.Time
		want  bool
	}{
		{"reset in the window", resetPush(syscall.ECONNRESET), recent, true},
		{"reset via os error in the window", resetPush(fmt.Errorf("write: %w", syscall.ECONNRESET)), recent, true},
		{"broken pipe in the window", resetPush(syscall.EPIPE), recent, true},
		{"EOF in the window", &url.Error{Op: "Post", URL: "u", Err: io.EOF}, recent, true},
		{"unexpected EOF in the window", fmt.Errorf("x: %w", &url.Error{Op: "Post", URL: "u", Err: io.ErrUnexpectedEOF}), recent, true},
		{"reset outside the window", resetPush(syscall.ECONNRESET), old, false},
		{"EOF outside the window", &url.Error{Op: "Post", URL: "u", Err: io.EOF}, old, false},
		{"never started by this agent", resetPush(syscall.ECONNRESET), time.Time{}, false},
		{"start in the future", resetPush(syscall.ECONNRESET), now.Add(time.Minute), false},
		{"an HTTP answer whose text says reset", errors.New("ollama answered HTTP 500: connection reset by peer"), recent, false},
		{"a verification failure", errors.New("sha256 mismatch"), recent, false},
		{"nil", nil, recent, false},
	}
	for _, c := range cases {
		if got := doorReplaced(c.err, c.start, now); got != c.want {
			t.Errorf("doorReplaced(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// d: a push reset inside the window of a start schedules a quick retry and
// takes no backoff; the same reset outside the window takes the backoff.
func TestImportResetAfterRecentStart_RetriesQuickly(t *testing.T) {
	imp := newImportRecorder(resetPush(syscall.ECONNRESET))
	r := importFixture(t, storeAnswers(true, nil), imp)
	rec := &afterRecorder{}
	r.afterFunc = rec.after
	r.noteOllamaStart(time.Now())
	r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)
	st := importState(r, "harrier")
	if !st.lastFailed.IsZero() || st.failures != 0 || st.doorRetries != 1 {
		t.Fatalf("lastFailed=%v failures=%d doorRetries=%d, want a quick retry and no backoff", st.lastFailed, st.failures, st.doorRetries)
	}
	if n := r.nudges.Load(); n != 1 || len(rec.got()) != 1 {
		t.Fatalf("nudges=%d scheduled=%v, want one quick-retry nudge", n, rec.got())
	}
}

func TestImportResetLongAfterStart_TakesTheBackoff(t *testing.T) {
	imp := newImportRecorder(resetPush(syscall.ECONNRESET))
	r := importFixture(t, storeAnswers(true, nil), imp)
	rec := &afterRecorder{}
	r.afterFunc = rec.after
	r.noteOllamaStart(time.Now().Add(-time.Hour))
	r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)
	st := importState(r, "harrier")
	if st.lastFailed.IsZero() || st.failures != 1 || st.doorRetries != 0 {
		t.Fatalf("lastFailed=%v failures=%d doorRetries=%d, want the backoff at once", st.lastFailed, st.failures, st.doorRetries)
	}
	if n := r.nudges.Load(); n != 0 {
		t.Fatalf("nudges = %d, want none", n)
	}
}
