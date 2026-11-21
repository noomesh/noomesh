// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Followup i1156: on a Mac the native lane is the ONLY lane for Ollama. With
// nothing answering on its port, the reconciler records a typed refusal with
// the remedy and never reaches Docker (no start, no stop, no image).

// nativeDownFixture is a reconciler over a recording fake daemon whose native
// lane (when exclusive) points at a port nothing listens on. starts counts
// the container starts that reach the start seam.
func nativeDownFixture(t *testing.T, exclusive bool) (*Reconciler, *listDaemon, *int) {
	t.Helper()
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	d := &listDaemon{}
	r := tickFixture(t, d)
	d.mu.Lock()
	d.calls = nil // only what convergeContainer asks counts
	d.mu.Unlock()
	r.native = nil
	if exclusive {
		r.native = backendrt.NewNativeAt("http://127.0.0.1:1") // nothing serves here
	}
	starts := 0
	r.startBackendFn = func(context.Context, string, string, int, dockerpkg.StartOverrides) error {
		starts++
		return nil
	}
	return r, d, &starts
}

func backendStartRefusal(backend string) string {
	for _, f := range refusals.List() {
		if f.Scope == "backend_start" && f.Target == backend {
			return f.Reason
		}
	}
	return ""
}

func TestNativeDownOllamaIsRefusedWithoutDocker(t *testing.T) {
	prev := backendrt.OllamaBinaryPresent
	backendrt.OllamaBinaryPresent = func() bool { return true }
	t.Cleanup(func() { backendrt.OllamaBinaryPresent = prev })

	r, d, starts := nativeDownFixture(t, true)
	tk := &tick{running: map[string]string{}, native: map[string]string{}, specLabels: map[string]string{}, floating: map[string]string{}}
	r.convergeContainer(t.Context(), tk, placement{Backend: "ollama", Model: "qwen3:4b", DesiredState: "running"})

	if *starts != 0 {
		t.Fatalf("a Mac with its native Ollama down must not start an ollama container; starts = %d", *starts)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Fatalf("a Mac with its native Ollama down must make no Docker call; daemon saw %v", seen)
	}
	why := backendStartRefusal("ollama")
	if !strings.Contains(why, "the native Ollama isn't running on this Mac") ||
		!strings.Contains(why, "brew services start --sudo-service-user") ||
		!strings.Contains(why, "re-run `noo enroll`") {
		t.Fatalf("backend_start refusal = %q, want the native-down text with its remedy", why)
	}
	if strings.Contains(why, "docker") {
		t.Fatalf("the refusal must not name Docker: %q", why)
	}
}

// A placement asked to stop: there is no container to stop on a Mac, and
// Docker is not asked even when a stale list says one runs.
func TestNativeDownOllamaStopMakesNoDockerCall(t *testing.T) {
	r, d, _ := nativeDownFixture(t, true)
	tk := &tick{running: map[string]string{"ollama": "qwen3:4b"}, native: map[string]string{}}
	r.convergeContainer(t.Context(), tk, placement{Backend: "ollama", Model: "qwen3:4b", DesiredState: "stopped"})
	if w := d.writes(); len(w) != 0 {
		t.Fatalf("a Mac must not stop an ollama container; daemon saw %v", w)
	}
}

// The control: on Linux (no native lane) the same placement starts the
// container, so the test above is not passing because nothing ever starts.
func TestLinuxOllamaStillStartsAsAContainer(t *testing.T) {
	r, _, starts := nativeDownFixture(t, false)
	tk := &tick{running: map[string]string{}, native: map[string]string{}, specLabels: map[string]string{}, floating: map[string]string{}}
	r.convergeContainer(t.Context(), tk, placement{Backend: "ollama", Model: "qwen3:4b", DesiredState: "running"})
	if *starts != 1 {
		t.Fatalf("linux: starts = %d, want 1 (unchanged container lane)", *starts)
	}
	if why := backendStartRefusal("ollama"); strings.Contains(why, "native Ollama") {
		t.Fatalf("linux must never get the native-down refusal: %q", why)
	}
}
