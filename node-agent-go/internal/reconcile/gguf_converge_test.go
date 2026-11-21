// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// ggufConvergeFixture: a Reconciler whose file check and start are stubs.
// *present is the file on the node; *startErr what the start answers;
// *starts counts the starts that were attempted.
func ggufConvergeFixture(t *testing.T, present *bool, startErr *error, starts *int) *Reconciler {
	t.Helper()
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	t.Setenv("MODELS_DIR", t.TempDir())
	return &Reconciler{
		cfg:         &config.Config{NodeID: "node-a"},
		ggufMissing: map[string]string{},
		ggufExists:  func(context.Context, string, string) (bool, error) { return *present, nil },
		startBackendFn: func(context.Context, string, string, int, dockerpkg.StartOverrides) error {
			*starts++
			if *startErr == nil {
				*present = true // the preseed wrote it
			}
			return *startErr
		},
		driftRecreated: map[string]string{},
	}
}

// stampLabel gives the running container the spec label the tick computes, so
// only the file (not drift) decides whether it is converged.
func stampLabel(tk *tick) {
	h, ok := specHashWith(ggufPlacement, func(ref string) (string, bool) { return dockerpkg.ContentKey(context.Background(), ref) })
	if !ok {
		h = specHash(ggufPlacement)
	}
	tk.specLabels["llamacpp"] = h
}

func ggufTick(running bool) *tick {
	tk := &tick{
		desired:    &desiredConfig{},
		running:    map[string]string{},
		native:     map[string]string{},
		specLabels: map[string]string{},
		floating:   map[string]string{},
	}
	if running {
		tk.running["llamacpp"] = ggufModel
	}
	return tk
}

var unavailable = &dockerpkg.GGUFUnavailableError{Model: ggufModel, Reason: "the controller is still hashing m.gguf ; retrying on the next reconcile pass"}

// A placed .gguf with no file whose preseed errors: the start's error is the
// recorded backend_start refusal, naming the model and the reason; and when
// the file is there on a later tick, it starts and the refusal clears.
func TestAGGUFPlacementWithNoFileIsRefusedThenStartsWhenTheFileArrives(t *testing.T) {
	present, startErr, starts := false, error(unavailable), 0
	r := ggufConvergeFixture(t, &present, &startErr, &starts)
	tk := ggufTick(false)
	r.convergeContainer(context.Background(), tk, ggufPlacement)
	if starts != 1 {
		t.Fatalf("starts = %d, want the start attempted once", starts)
	}
	got := ggufStartRefusals()["llamacpp"]
	for _, want := range []string{"gguf_unavailable", "m.gguf", "still hashing", "no container was started", "retries on the next reconcile tick"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal %q lacks %q", got, want)
		}
	}
	// The controller finished hashing: the next tick's preseed succeeds.
	startErr = nil
	r.convergeContainer(context.Background(), tk, ggufPlacement)
	if starts != 2 || !present {
		t.Fatalf("starts=%d present=%v, want the second tick to start with the file", starts, present)
	}
	if got := ggufStartRefusals()["llamacpp"]; got != "" {
		t.Fatalf("the refusal stands after a successful start: %q", got)
	}
}

// A running, "converged" .gguf placement whose file vanished is not
// converged: the start path re-asks the store and records the refusal; the
// running container is not stopped (the fixture has no docker to stop with).
func TestARunningGGUFWhoseFileVanishedIsRefusedNotConverged(t *testing.T) {
	present, startErr, starts := false, error(unavailable), 0
	r := ggufConvergeFixture(t, &present, &startErr, &starts)
	tk := ggufTick(true)
	stampLabel(tk)
	r.convergeContainer(context.Background(), tk, ggufPlacement)
	if starts != 1 {
		t.Fatalf("starts = %d: a running backend with no file was treated as converged", starts)
	}
	if got := ggufStartRefusals()["llamacpp"]; !strings.Contains(got, "gguf_unavailable") {
		t.Fatalf("refusal = %q, want the gguf_unavailable refusal", got)
	}
}

// With the file there, a running placement stays converged: no start.
func TestARunningGGUFWithItsFileIsConverged(t *testing.T) {
	present, startErr, starts := true, error(nil), 0
	r := ggufConvergeFixture(t, &present, &startErr, &starts)
	tk := ggufTick(true)
	stampLabel(tk)
	r.convergeContainer(context.Background(), tk, ggufPlacement)
	if starts != 0 {
		t.Fatalf("starts = %d, want none for a converged placement", starts)
	}
	if got := ggufStartRefusals()["llamacpp"]; got != "" {
		t.Fatalf("unexpected refusal %q", got)
	}
}
