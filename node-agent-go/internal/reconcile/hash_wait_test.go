// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

func hashing(after time.Duration) error {
	return fmt.Errorf("backend ollama image: %w", &dockerpkg.ImageHashingError{
		Ref: "ghcr.io/noomesh/ollama:v0.6.30", Tar: "ollama.tar.gz", RetryAfter: after, Err: errors.New("hashing")})
}

func hashWaitReconciler(t *testing.T) (*Reconciler, *afterRecorder) {
	t.Helper()
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	rec := &afterRecorder{}
	return &Reconciler{hashWaits: map[string]int{}, afterFunc: rec.after}, rec
}

// Inside the window a hashing controller is a wait: a nudge after the
// (clamped) Retry-After and NO refusal, hence no operator alert.
func TestStartWaitingOnHashSchedulesANudgeAndRecordsNoRefusal(t *testing.T) {
	r, rec := hashWaitReconciler(t)
	r.recordBackendStartFailure("ollama", hashing(8*time.Second))
	if hasRefusal("backend_start", "ollama") {
		t.Fatal("a hashing wait inside its window recorded a refusal")
	}
	if got := rec.got(); len(got) != 1 || got[0] != 8*time.Second {
		t.Fatalf("nudges scheduled = %v, want one after 8s", got)
	}
	if n := r.nudges.Load(); n != 1 {
		t.Fatalf("nudges = %d, want 1", n)
	}
}

func TestHashWaitIsClampedToTheQuickRetrySpacing(t *testing.T) {
	if hashWait(time.Second) != hashWaitMin || hashWait(10*time.Minute) != hashWaitMax || hashWait(9*time.Second) != 9*time.Second {
		t.Fatalf("clamp: %v %v %v", hashWait(time.Second), hashWait(10*time.Minute), hashWait(9*time.Second))
	}
}

// After the quick retries are spent the failure is recorded, with its text.
func TestStartWaitingOnHashRecordsOnceTheWindowIsSpent(t *testing.T) {
	r, rec := hashWaitReconciler(t)
	for i := 0; i < hashWaitRetries; i++ {
		r.recordBackendStartFailure("ollama", hashing(5*time.Second))
		if hasRefusal("backend_start", "ollama") {
			t.Fatalf("refusal recorded on quick retry %d", i+1)
		}
	}
	if len(rec.got()) != hashWaitRetries {
		t.Fatalf("scheduled %d nudges, want %d", len(rec.got()), hashWaitRetries)
	}
	r.recordBackendStartFailure("ollama", hashing(5*time.Second))
	if !hasRefusal("backend_start", "ollama") {
		t.Fatal("the failure after the window must be recorded")
	}
	if len(rec.got()) != hashWaitRetries {
		t.Fatalf("a spent window must not nudge again: %d", len(rec.got()))
	}
}

// Any other start failure refuses at once, as before, and resets the count.
func TestANonHashingStartFailureRefusesAtOnce(t *testing.T) {
	r, rec := hashWaitReconciler(t)
	r.recordBackendStartFailure("ollama", hashing(5*time.Second))
	r.recordBackendStartFailure("ollama", errors.New("refusing to start an unverified image"))
	if !hasRefusal("backend_start", "ollama") {
		t.Fatal("a plain failure must record the refusal")
	}
	if len(rec.got()) != 1 {
		t.Fatalf("a plain failure must not nudge: %v", rec.got())
	}
	if r.hashWaits["ollama"] != 0 {
		t.Fatalf("count not reset: %d", r.hashWaits["ollama"])
	}
}

// The start path routes its failure through recordBackendStartFailure rather
// than recording the refusal itself.
func TestTheStartPathRoutesItsFailureThroughTheHashWait(t *testing.T) {
	raw, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	at := strings.Index(s, `slog.Error("reconcile.start_failed"`)
	if at < 0 {
		t.Fatal("start_failed not found")
	}
	tail := s[at:]
	end := strings.Index(tail, "r.backendStarted(ctx, p.Backend, p.Model)")
	if end < 0 || !strings.Contains(tail[:end], "r.recordBackendStartFailure(p.Backend, err)") ||
		strings.Contains(tail[:end], `refusals.Record("backend_start"`) {
		t.Fatal("a failed start must go through recordBackendStartFailure, not record the refusal itself")
	}
}
