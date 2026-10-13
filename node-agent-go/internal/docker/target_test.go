// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

func TestCPUTargetHidesTheGPUAndOffloadsNoLayers(t *testing.T) {
	ll := cpuTargetEnv("llamacpp")
	if v, ok := ll["CUDA_VISIBLE_DEVICES"]; !ok || v != "" {
		t.Fatalf("CUDA_VISIBLE_DEVICES must be set empty, got %q (set %v)", v, ok)
	}
	if ll["N_GPU_LAYERS"] != "0" || ll["LLAMA_ARG_N_GPU_LAYERS"] != "0" {
		t.Fatalf("llamacpp on cpu offloads nothing: %v", ll)
	}
	ol := cpuTargetEnv("ollama")
	if _, ok := ol["N_GPU_LAYERS"]; ok {
		t.Fatalf("ollama has no N_GPU_LAYERS: %v", ol)
	}
	if _, ok := ol["CUDA_VISIBLE_DEVICES"]; !ok {
		t.Fatal("ollama on cpu must hide CUDA devices")
	}
}

func TestLlamaArgsMirrorTheNooTuningKeysWithoutOverridingExplicitOnes(t *testing.T) {
	env := map[string]string{"N_THREADS": "6", "N_CTX": "8192", "N_BATCH": "512", "N_PARALLEL": "2",
		"N_GPU_LAYERS": "auto", "LLAMA_ARG_CTX_SIZE": "4096"}
	mirrorLlamaArgs(env)
	want := map[string]string{"LLAMA_ARG_THREADS": "6", "LLAMA_ARG_CTX_SIZE": "4096", "LLAMA_ARG_BATCH": "512", "LLAMA_ARG_N_PARALLEL": "2"}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s = %q, want %q (%v)", k, env[k], v, env)
		}
	}
	if _, ok := env["LLAMA_ARG_N_GPU_LAYERS"]; ok {
		t.Fatal("the auto sentinel is not a llama-server value")
	}
}

func TestLlamacppCPUQuotaFollowsTunedThreadsUpToTheCores(t *testing.T) {
	cases := []struct {
		threads string
		cores   int
		want    float64
	}{
		{"", 16, 4},     // not tuned: the spec's quota
		{"2", 16, 4},    // fewer threads never lowers it
		{"14", 16, 14},  // tuned up: the quota follows
		{"64", 16, 16},  // never above the node's cores
		{"bogus", 8, 4}, // unparsable: the spec's quota
	}
	for _, c := range cases {
		if got := llamacppCPULimit(4, c.threads, c.cores); got != c.want {
			t.Fatalf("threads %q cores %d: got %v want %v", c.threads, c.cores, got, c.want)
		}
	}
}

func TestLlamacppMemoryLimitIsThePlacementsWhenSent(t *testing.T) {
	spec := int64(8 << 30)
	if got := llamacppMemoryLimit(spec, 0); got != spec {
		t.Fatalf("no derived limit: keep the spec's, got %d", got)
	}
	if got := llamacppMemoryLimit(spec, 17_500_000_000); got != 17_500_000_000 {
		t.Fatalf("derived limit must replace the spec's, got %d", got)
	}
}
