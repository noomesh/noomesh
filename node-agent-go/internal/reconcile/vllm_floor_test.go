// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"errors"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// The agent refuses to start vLLM on a GPU below the vLLM image's compute
// floor, naming the GPU's compute capability and the floor.
func TestVllmStartIsRefusedBelowTheComputeFloor(t *testing.T) {
	capOf := func(v string) func() (string, error) { return func() (string, error) { return v, nil } }
	why := vllmComputeRefusal("vllm", capOf("6.1"))
	for _, want := range []string{"vllm_compute_low", "compute 6.1", "7.5+", "CUDA 13.0", "ollama"} {
		if !strings.Contains(why, want) {
			t.Fatalf("refusal %q lacks %q", why, want)
		}
	}
	if vllmComputeRefusal("vllm-secondary", capOf("7.0")) == "" {
		t.Fatal("vllm-secondary runs the same image: refused below the floor")
	}
	for _, c := range []struct {
		backend string
		cap     func() (string, error)
		what    string
	}{
		{"vllm", capOf("7.5"), "the floor itself"},
		{"vllm", capOf("8.6"), "above the floor"},
		{"vllm", capOf("10.0"), "compared as numbers"},
		{"ollama", capOf("6.1"), "ollama runs this GPU"},
		{"vllm", func() (string, error) { return "", errors.New("no nvidia-smi") }, "the agent's own unknown (the gateway refuses it)"},
		{"vllm", nil, "no facts"},
	} {
		if why := vllmComputeRefusal(c.backend, c.cap); why != "" {
			t.Errorf("%s: refused: %s", c.what, why)
		}
	}
}

// The floor refusal's remedy is the unplace: once no placement wants the vLLM
// backend running, its start refusal is gone.
func TestAnUnplacedVllmKeepsNoStartRefusal(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	refusals.Record("backend_start", "vllm", "vllm_compute_low: test")
	refusals.Record("backend_start", "ollama", "model_missing: test")
	clearUnplacedVllmRefusals([]placement{{Backend: "vllm", DesiredState: "running"}})
	if len(refusals.List()) != 2 {
		t.Fatalf("still placed: kept, got %v", refusals.List())
	}
	clearUnplacedVllmRefusals([]placement{{Backend: "ollama", DesiredState: "running"}})
	got := refusals.List()
	if len(got) != 1 || got[0].Target != "ollama" {
		t.Fatalf("the unplaced vllm's refusal is dropped, ollama's kept: %v", got)
	}
}
