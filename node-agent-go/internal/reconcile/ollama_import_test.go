// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// importRecorder is a fake import-model path: it records each call and
// answers with err.
type importRecorder struct {
	mu    sync.Mutex
	calls []string
	err   error
	done  chan struct{}
}

func newImportRecorder(err error) *importRecorder {
	return &importRecorder{err: err, done: make(chan struct{}, 8)}
}

func (f *importRecorder) importModel(_ context.Context, m string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, m)
	f.mu.Unlock()
	defer func() { f.done <- struct{}{} }()
	if f.err != nil {
		return "", f.err
	}
	return m + " created from harrier-q8.gguf via container", nil
}

func (f *importRecorder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *importRecorder) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the import never ran")
	}
	// The goroutine updates bookkeeping after the import returns.
	time.Sleep(20 * time.Millisecond)
}

func importFixture(t *testing.T, storeHas func(context.Context, string) (bool, error), imp *importRecorder) *Reconciler {
	t.Helper()
	modelpresence.Reset()
	refusals.Reset()
	t.Cleanup(modelpresence.Reset)
	t.Cleanup(refusals.Reset)
	return &Reconciler{
		ollamaPulls: map[string]*ollamaPullState{},
		storeHas:    storeHas,
		importModel: imp.importModel,
	}
}

func storeAnswers(in bool, err error) func(context.Context, string) (bool, error) {
	return func(context.Context, string) (bool, error) { return in, err }
}

func noPull(t *testing.T) func(context.Context, string) (string, error) {
	return func(_ context.Context, m string) (string, error) {
		t.Errorf("import-only model %q was pulled from the public registry", m)
		return "", nil
	}
}

func absent(context.Context, string) (bool, error) { return false, nil }

// host8-ma, 2026-10-10: `noo cluster place host8-ma ollama harrier --role
// embed` succeeded and reconcile logged the import-model remedy every five
// minutes forever. A placed import-only model the store publishes is now
// imported from the store — never pulled from the registry.
func TestImportOnlyModel_InStore_IsImportedNotPulled(t *testing.T) {
	imp := newImportRecorder(nil)
	r := importFixture(t, storeAnswers(true, nil), imp)
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)

	if imp.count() != 1 || imp.calls[0] != "harrier" {
		t.Fatalf("imports = %v, want exactly [harrier]", imp.calls)
	}
	got := modelpresence.Report()["ollama#embed"]
	if got.Present || !got.ImportOnly {
		t.Fatalf("presence = %+v, want absent + import_only until the next tick sees it", got)
	}
	if rs := refusals.List(); len(rs) != 0 {
		t.Fatalf("a successful import leaves no refusal: %+v", rs)
	}
	r.pullMu.Lock()
	st := r.ollamaPulls["harrier"]
	r.pullMu.Unlock()
	if st == nil || st.inFlight || st.failures != 0 {
		t.Fatalf("bookkeeping = %+v, want settled with no failures", st)
	}
}

// A failed import keeps the error and the manual remedy on the placement,
// and is not retried on the very next tick.
func TestImportOnlyModel_ImportFails_RefusalWithReasonAndBackoff(t *testing.T) {
	imp := newImportRecorder(errors.New("fetch harrier-q8.gguf: sha256 mismatch"))
	r := importFixture(t, storeAnswers(true, nil), imp)
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)

	rs := refusals.List()
	if len(rs) != 1 || rs[0].Scope != "placement_model" || rs[0].Target != "ollama#embed" {
		t.Fatalf("refusals = %+v, want one placement_model refusal", rs)
	}
	for _, want := range []string{"sha256 mismatch", "noo cluster import-model host8-ma harrier --place --role embed"} {
		if !strings.Contains(rs[0].Reason, want) {
			t.Errorf("refusal %q does not carry %q", rs[0].Reason, want)
		}
	}

	// Next tick, inside the backoff: no second import.
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	time.Sleep(50 * time.Millisecond)
	if imp.count() != 1 {
		t.Fatalf("imports = %d, want 1 — a failed import must back off", imp.count())
	}

	// After the backoff it is tried again.
	r.pullMu.Lock()
	r.ollamaPulls["harrier"].lastFailed = time.Now().Add(-ollamaPullRetryAfter - time.Second)
	r.pullMu.Unlock()
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)
	if imp.count() != 2 {
		t.Fatalf("imports = %d, want 2 after the backoff", imp.count())
	}
}

// One import in flight at a time: a slow import is not started again by the
// next tick.
func TestImportOnlyModel_InFlightNotRestarted(t *testing.T) {
	release := make(chan struct{})
	var calls int
	var mu sync.Mutex
	modelpresence.Reset()
	refusals.Reset()
	t.Cleanup(modelpresence.Reset)
	t.Cleanup(refusals.Reset)
	r := &Reconciler{
		ollamaPulls: map[string]*ollamaPullState{},
		storeHas:    storeAnswers(true, nil),
		importModel: func(context.Context, string) (string, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			<-release
			return "ok", nil
		},
	}
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	time.Sleep(50 * time.Millisecond)
	close(release)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("imports started = %d, want 1 while one is in flight", calls)
	}
}

// The store answered that it does not publish the model: it is a registry
// tag, pulled as before, and nothing is imported.
func TestNotInStore_PullsFromRegistryNeverImports(t *testing.T) {
	imp := newImportRecorder(nil)
	r := importFixture(t, storeAnswers(false, nil), imp)
	pulled := make(chan string, 1)
	r.ensureOllamaModel("host9", "ollama", placement{Backend: "ollama", Model: "gemma3:1b", DesiredState: "running"},
		absent, func(_ context.Context, m string) (string, error) { pulled <- m; return "success", nil })
	select {
	case <-pulled:
	case <-time.After(2 * time.Second):
		t.Fatal("a registry tag must still be pulled")
	}
	if imp.count() != 0 {
		t.Fatalf("imported a model the store does not publish: %v", imp.calls)
	}
}

// A store check that TIMES OUT is not "not in the store": a model the store
// already answered for stays import-only (no registry pull), and the import
// path is still the one taken.
func TestStoreCheckTimeout_RemembersImportOnly(t *testing.T) {
	imp := newImportRecorder(errors.New("store down"))
	answer := true
	var answerErr error
	r := importFixture(t, func(context.Context, string) (bool, error) { return answer, answerErr }, imp)

	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)

	answer, answerErr = false, errors.New("manifest request timed out after 15s")
	r.pullMu.Lock()
	r.ollamaPulls["harrier"].lastFailed = time.Time{}
	r.pullMu.Unlock()
	r.ensureOllamaModel("host8-ma", "ollama#embed", harrierPlacement(), absent, noPull(t))
	imp.wait(t)
	if got := modelpresence.Report()["ollama#embed"]; !got.ImportOnly {
		t.Fatalf("presence = %+v, want import_only remembered across a timed-out check", got)
	}
	if imp.count() != 2 {
		t.Fatalf("imports = %d, want 2", imp.count())
	}
}

// A registry tag the controller staged (`noo models fetch ollama:gemma4:12b`)
// reaches a placed node through the same import path, never `ollama pull`.
func TestStagedRegistryTag_IsImportedNotPulled(t *testing.T) {
	imp := newImportRecorder(nil)
	r := importFixture(t, storeAnswers(true, nil), imp)
	p := harrierPlacement()
	p.Model = "gemma4:12b"
	r.ensureOllamaModel("host8-ma", "ollama#chat", p, absent, noPull(t))
	imp.wait(t)
	if imp.count() != 1 || imp.calls[0] != "gemma4:12b" {
		t.Fatalf("imports = %v, want exactly [gemma4:12b]", imp.calls)
	}
}
