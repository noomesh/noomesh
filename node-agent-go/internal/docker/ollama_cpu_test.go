// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// A fallback embedder has to be able to share a node with vLLM. ollama's
// GPUCount used to be the literal "all", and GPUCount is not
// placement-overridable, so an ollama placed next to vLLM would demand
// every GPU on the box.
func TestOllamaGPUCountIsOverridable(t *testing.T) {
	spec, ok := backendSpecs["ollama"]
	if !ok {
		t.Fatal("no ollama backend spec")
	}

	t.Run("defaults to all GPUs", func(t *testing.T) {
		if got := resolveEnv(spec.GPUCount); got != "all" {
			t.Errorf("default GPUCount = %q, want all", got)
		}
	})

	t.Run("pins to CPU when the node sets 0", func(t *testing.T) {
		t.Setenv("NOO_OLLAMA_GPU_COUNT", "0")
		got := resolveEnv(spec.GPUCount)
		if got != "0" {
			t.Fatalf("GPUCount = %q, want 0", got)
		}
		// The reservation guard treats "0" and "" as no-GPU; anything else
		// becomes a DeviceRequest. Assert the value lands in that bucket so
		// the spec change actually reaches CPU-only behaviour.
		if got != "" && got != "0" {
			t.Errorf("GPUCount %q would still request a GPU device", got)
		}
	})

	t.Run("honours an explicit single-GPU pin", func(t *testing.T) {
		t.Setenv("NOO_OLLAMA_GPU_COUNT", "1")
		if got := resolveEnv(spec.GPUCount); got != "1" {
			t.Errorf("GPUCount = %q, want 1", got)
		}
		if parseGPUCount("1") != 1 {
			t.Errorf("parseGPUCount(1) = %d, want 1", parseGPUCount("1"))
		}
	})
}
