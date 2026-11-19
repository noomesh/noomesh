// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// 0.6.28-rc.3, a hosted host-mode agent (the journal):
//
//	11:01:47.48 reconcile.starting_backend (noo-ollama)
//	11:01:49.14 reconcile.backend_ready_nudge
//	11:01:49.22 reconcile.ollama_import_failed: asking ollama for blob 005f95c74751:
//	   Head "https://noo-stunnel-ollama:11434/...": dial tcp: lookup noo-stunnel-ollama ...
//
// The shape the transport returned: a *url.Error around the dialer's
// *net.OpError around a *net.DNSError, wrapped by installMirror.
func doorLookupFailed() error {
	dns := &net.DNSError{Err: "no such host", Name: "noo-stunnel-ollama", Server: "127.0.0.53:53", IsNotFound: true}
	op := &net.OpError{Op: "dial", Net: "tcp", Err: dns}
	return fmt.Errorf("asking ollama for blob 005f95c74751: %w",
		fmt.Errorf("Head \"https://noo-stunnel-ollama:11434/api/blobs/sha256:005f\": %w", op))
}

// The dial-level class is read from the error's type, never its text.
func TestImportDoorNotUp_TypedErrorsOnly(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the rc.3 lookup failure", doorLookupFailed(), true},
		{"a bare DNSError", &net.DNSError{Err: "server misbehaving", Name: "noo-stunnel-ollama"}, true},
		{"an OpError dial (no route)", fmt.Errorf("x: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}), true},
		{"connection refused", fmt.Errorf("x: %w", refused), true},
		{"a bare ECONNREFUSED", fmt.Errorf("x: %w", syscall.ECONNREFUSED), true},
		{"an OpError read (the door answered, then broke)", fmt.Errorf("x: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), false},
		{"an HTTP 500", errors.New("HEAD /api/blobs answered HTTP 500"), false},
		{"a verification failure", errors.New("fetch harrier-q8.gguf: sha256 mismatch"), false},
		{"a message that merely says lookup", errors.New("ollama answered HTTP 502: dial tcp: lookup noo-stunnel-ollama: no such host"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := doorNotUp(c.err); got != c.want {
			t.Errorf("doorNotUp(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// A started ollama nudges once the DOOR the import dials answers, not when
// the container alone does: the door fails to resolve for two probes, then
// answers; exactly one nudge, after the third probe.
func TestReadyNudge_WaitsForTheImportDoor(t *testing.T) {
	var mu sync.Mutex
	probes, nudgedAt := 0, 0
	door := func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		probes++
		if probes < 3 {
			return doorLookupFailed()
		}
		return nil
	}
	r := &Reconciler{backendReady: importDoorReady(door)}
	go func() {
		<-r.nudgeCh()
		mu.Lock()
		nudgedAt = probes
		mu.Unlock()
	}()
	r.nudgeWhenReady(context.Background(), "ollama", "qwen2.5:0.5b", time.Second, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n := r.nudges.Load(); n != 1 {
		t.Fatalf("nudges = %d, want exactly 1 once the door answered", n)
	}
	if probes != 3 || nudgedAt != 3 {
		t.Fatalf("probes = %d, nudged after probe %d; want the one nudge after the 3rd probe (the first the door answered)", probes, nudgedAt)
	}

	// Production asks the import's own path, not `ollama list` in noo-ollama.
	src, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	body := s[strings.Index(s, "func dockerBackendReady("):]
	body = body[:strings.Index(body, "\n}\n")]
	if !strings.Contains(body, "importDoorReady(c.OllamaImportDoorAnswers)") || strings.Contains(body, "OllamaHasModel") {
		t.Fatalf("dockerBackendReady must be importDoorReady over OllamaImportDoorAnswers:\n%s", body)
	}
}

// afterRecorder stands in for time.AfterFunc: it records the delay and runs
// the nudge at once.
type afterRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (a *afterRecorder) after(d time.Duration, f func()) {
	a.mu.Lock()
	a.delays = append(a.delays, d)
	a.mu.Unlock()
	f()
}

func (a *afterRecorder) got() []time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]time.Duration(nil), a.delays...)
}

func importState(r *Reconciler, model string) ollamaPullState {
	r.pullMu.Lock()
	defer r.pullMu.Unlock()
	return *r.ollamaPulls[model]
}

// A door that cannot be dialled gets 5 quick retries, one spaced nudge each,
// inside a minute and without the 10-minute backoff; the 6th dial failure
// takes the backoff with its refusal, and nudges no more.
func TestImportDoorNotUp_BoundedQuickRetries(t *testing.T) {
	imp := newImportRecorder(doorLookupFailed())
	r := importFixture(t, storeAnswers(true, nil), imp)
	rec := &afterRecorder{}
	r.afterFunc = rec.after
	tick := func() {
		r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	}

	for i := 1; i <= len(importDoorRetryAfter); i++ {
		tick()
		imp.wait(t)
		if st := importState(r, "harrier"); !st.lastFailed.IsZero() {
			t.Fatalf("dial failure %d set the %s backoff; want a quick retry", i, ollamaPullRetryAfter)
		}
		if n := r.nudges.Load(); int(n) != i {
			t.Fatalf("after dial failure %d: nudges = %d, want %d (one per quick retry)", i, n, i)
		}
		<-r.nudgeCh() // the nudged pass
	}
	if got := rec.got(); len(got) != 5 {
		t.Fatalf("quick retries scheduled = %v, want 5", got)
	}
	var total time.Duration
	for _, d := range rec.got() {
		if d <= 0 {
			t.Fatalf("a quick retry was not spaced: %v", rec.got())
		}
		total += d
	}
	if total > time.Minute {
		t.Fatalf("quick retries span %s, want at most a minute", total)
	}

	// The 6th: the normal backoff, the refusal, no more quick nudges.
	tick()
	imp.wait(t)
	if st := importState(r, "harrier"); st.lastFailed.IsZero() {
		t.Fatal("the dial failure after the last quick retry did not take the backoff")
	}
	if n := r.nudges.Load(); n != 5 {
		t.Fatalf("nudges = %d after the quick retries ran out, want still 5", n)
	}
	if !hasRefusal("placement_model", "ollama#embed") {
		t.Fatal("the backoff after the quick retries must record the placement_model refusal")
	}
	tick()
	time.Sleep(30 * time.Millisecond)
	if got := imp.count(); got != 6 {
		t.Fatalf("import attempts = %d, want 6: inside the backoff a tick does not import", got)
	}
}

// A failure the door answered (an HTTP status, a verification) backs off at
// once, even when its text says "lookup": no quick retry, no nudge.
func TestImportAnsweredFailure_BacksOffAtOnce(t *testing.T) {
	imp := newImportRecorder(errors.New("asking ollama for blob 005f95c74751: ollama answered HTTP 502: lookup of the blob store failed"))
	r := importFixture(t, storeAnswers(true, nil), imp)
	rec := &afterRecorder{}
	r.afterFunc = rec.after
	r.ensureOllamaModel(context.Background(), "node_a", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)
	if st := importState(r, "harrier"); st.lastFailed.IsZero() || st.doorRetries != 0 {
		t.Fatalf("an answered failure: lastFailed=%v doorRetries=%d; want the backoff at once, no quick retry", st.lastFailed, st.doorRetries)
	}
	if n := r.nudges.Load(); n != 0 || len(rec.got()) != 0 {
		t.Fatalf("an answered failure nudged %d time(s), scheduled %v; want none", n, rec.got())
	}
}

func hasRefusal(scope, target string) bool {
	for _, f := range refusals.List() {
		if f.Scope == scope && f.Target == target {
			return true
		}
	}
	return false
}
