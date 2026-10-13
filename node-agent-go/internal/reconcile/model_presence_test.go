// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

func presenceFixture(t *testing.T, importOnly bool) *Reconciler {
	t.Helper()
	modelpresence.Reset()
	refusals.Reset()
	t.Cleanup(modelpresence.Reset)
	t.Cleanup(refusals.Reset)
	return &Reconciler{
		ollamaPulls: map[string]*ollamaPullState{},
		storeHas:    func(context.Context, string) (bool, error) { return importOnly, nil },
	}
}

func harrierPlacement() placement {
	return placement{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"}
}

// host9, 2026-10-03: the ollama container is up and holds only llama3.2:1b.
// harrier is import-only, so the agent must report it missing, must NOT run
// `ollama pull harrier` against the public registry, and — with no import
// path wired — must leave a refusal naming the import command.
func TestImportOnlyModelMissing_ReportedNeverPulled(t *testing.T) {
	r := presenceFixture(t, true)
	pulled := make(chan string, 1)
	r.ensureOllamaModel("host9", "ollama", harrierPlacement(),
		func(context.Context, string) (bool, error) { return false, nil },
		func(_ context.Context, m string) (string, error) { pulled <- m; return "", nil })

	select {
	case m := <-pulled:
		t.Fatalf("import-only model %q was pulled from the public registry", m)
	case <-time.After(150 * time.Millisecond):
	}
	got, ok := modelpresence.Report()["ollama"]
	if !ok || got.Present || !got.ImportOnly || got.Model != "harrier" || got.Role != "embed" {
		t.Fatalf("presence = %+v (ok=%v), want harrier/embed absent + import_only", got, ok)
	}
	rs := refusals.List()
	if len(rs) != 1 || rs[0].Scope != "placement_model" || rs[0].Target != "ollama" ||
		!strings.Contains(rs[0].Reason, "noo cluster import-model host9 harrier --place --role embed") {
		t.Fatalf("refusals = %+v, want the import-model remedy", rs)
	}
}

// A registry tag that is missing still pulls (today's behaviour), and is
// reported absent in the meantime.
func TestRegistryModelMissing_StillPulledAndReportedAbsent(t *testing.T) {
	r := presenceFixture(t, false)
	pulled := make(chan string, 1)
	p := placement{Backend: "ollama", Model: "gemma3:1b", DesiredState: "running"}
	r.ensureOllamaModel("host9", "ollama", p,
		func(context.Context, string) (bool, error) { return false, nil },
		func(_ context.Context, m string) (string, error) { pulled <- m; return "success", nil })
	select {
	case <-pulled:
	case <-time.After(2 * time.Second):
		t.Fatal("a registry tag must still be pulled")
	}
	got := modelpresence.Report()["ollama"]
	if got.Present || got.ImportOnly || got.Role != "chat" {
		t.Fatalf("presence = %+v, want absent, not import-only, role chat", got)
	}
	if len(refusals.List()) != 0 {
		t.Fatalf("a pullable model is not a refusal: %+v", refusals.List())
	}
}

func TestModelPresent_ReportedAndClearsRefusal(t *testing.T) {
	r := presenceFixture(t, true)
	refusals.Record("placement_model", "ollama", "stale")
	r.ensureOllamaModel("host9", "ollama", harrierPlacement(),
		func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, string) (string, error) { t.Fatal("pulled a present model"); return "", nil })
	got := modelpresence.Report()["ollama"]
	if !got.Present || got.Model != "harrier" {
		t.Fatalf("presence = %+v, want present", got)
	}
	if len(refusals.List()) != 0 {
		t.Fatalf("a held model must clear its refusal: %+v", refusals.List())
	}
}

// A check that could not run is UNKNOWN, never absent: the entry goes away.
func TestModelCheckFailure_IsUnknownNotAbsent(t *testing.T) {
	r := presenceFixture(t, true)
	modelpresence.Set("ollama", modelpresence.Entry{Model: "harrier", Present: false})
	r.ensureOllamaModel("host9", "ollama", harrierPlacement(),
		func(context.Context, string) (bool, error) { return false, errors.New("noo-ollama is not running") },
		func(context.Context, string) (string, error) { return "", nil })
	if _, ok := modelpresence.Report()["ollama"]; ok {
		t.Fatal("a failed check must clear the entry, not leave or invent a verdict")
	}
}
