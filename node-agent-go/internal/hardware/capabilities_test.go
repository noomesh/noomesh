// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// fakeGPU makes detection an input rather than a property of whatever
// machine runs the test. These cases are ABOUT what Detect does with given
// probe results, so probing real hardware tested the host, not the code.
type fakeGPU struct {
	vram  float64
	count int
	model string
}

func (f fakeGPU) DetectVRAM() float64 { return f.vram }
func (f fakeGPU) DetectCount() int    { return f.count }
func (f fakeGPU) DetectModel() string { return f.model }

// A stale GPU_MODEL env on a GPU-less host (e.g. a Pi provisioned from a
// laptop's config) must not be advertised as a real GPU. With no nvidia-smi
// present, DetectVRAM/DetectCount return 0, so the env model is cleared.
func TestDetect_ClearsStaleGPUEnvWhenNoHardware(t *testing.T) {
	// No GPU detected, whatever this machine actually has.
	caps := Detect(&config.Config{GPUModel: "NVIDIA GeForce RTX 3080 Laptop GPU"}, fakeGPU{})
	if caps.GPUModel != "" {
		t.Errorf("expected GPUModel cleared when no VRAM/GPU detected, got %q", caps.GPUModel)
	}
	if caps.VRAMGB != 0 {
		t.Errorf("expected 0 VRAM, got %v", caps.VRAMGB)
	}
}

// An explicit VRAM_GB override means the operator is asserting real GPU
// hardware (e.g. nvidia-smi unreachable inside the container) — keep the
// declared model.
func TestDetect_KeepsGPUEnvWhenVRAMDeclared(t *testing.T) {
	caps := Detect(&config.Config{GPUModel: "RTX 3060", VRAMGB: 12.0}, fakeGPU{})
	if caps.GPUModel != "RTX 3060" {
		t.Errorf("expected declared GPUModel kept when VRAM declared, got %q", caps.GPUModel)
	}
}

func TestContainsAny(t *testing.T) {
	cases := []struct {
		haystack string
		needles  []string
		want     bool
	}{
		{"noo-tei-gpu", []string{"tei"}, true},
		{"noo-ollama", []string{"tei", "embed"}, false},
		{"noo-ollama-embed", []string{"tei", "embed"}, true},
		{"whisper-service", []string{"whisper", "stt"}, true},
		{"random-container", []string{"whisper", "stt", "tei"}, false},
		{"", []string{"anything"}, false},
		{"something", []string{}, false},
	}

	for _, tc := range cases {
		got := containsAny(tc.haystack, tc.needles...)
		if got != tc.want {
			t.Errorf("containsAny(%q, %v) = %v, want %v", tc.haystack, tc.needles, got, tc.want)
		}
	}
}

func TestDedupe(t *testing.T) {
	input := []string{"inference", "embedding", "inference", "whisper", "embedding"}
	got := dedupe(input)

	if len(got) != 3 {
		t.Errorf("expected 3 unique items, got %d: %v", len(got), got)
	}

	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] {
			t.Errorf("duplicate found: %q", s)
		}
		seen[s] = true
	}
}

func TestRuntimeCapabilityDetector(t *testing.T) {
	d := &RuntimeCapabilityDetector{
		GetRunningBackends: func() map[string]string {
			return map[string]string{
				"ollama": "qwen3:8b",
				"vllm":   "Qwen/Qwen3-8B-AWQ",
			}
		},
		ListContainers: func() []string {
			return []string{"noo-ollama", "noo-vllm", "noo-tei"}
		},
	}

	caps := d.Detect()

	// Should always have "inference"
	hasInference := false
	hasEmbedding := false
	for _, c := range caps {
		if c == "inference" {
			hasInference = true
		}
		if c == "embedding" {
			hasEmbedding = true
		}
	}
	if !hasInference {
		t.Error("expected 'inference' capability")
	}
	if !hasEmbedding {
		t.Error("expected 'embedding' capability (tei container running)")
	}
}

func TestRuntimeCapabilityDetector_OllamaEmbed(t *testing.T) {
	d := &RuntimeCapabilityDetector{
		GetRunningBackends: func() map[string]string {
			return map[string]string{"ollama": "nomic-embed-text"}
		},
		ListContainers: func() []string {
			return []string{"noo-ollama"}
		},
	}

	caps := d.Detect()

	hasEmbedding := false
	for _, c := range caps {
		if c == "embedding" {
			hasEmbedding = true
		}
	}
	if !hasEmbedding {
		t.Error("expected 'embedding' when ollama runs nomic model")
	}
}

// A node must advertise what it can SERVE, not what its silicon could run.
//
// llama.cpp runs excellently on Apple Silicon — Metal support is first-class.
// But this agent starts `llamacpp` only as a Docker container, and Docker on
// macOS is a Linux VM with no path to Metal. host6 advertised
// `ollama,llamacpp` while able to serve neither, and the scheduler read that
// as a placement target.
//
// The platform is a parameter so this runs on CI rather than skipping there.
func TestDarwinAdvertisesOnlyNativelyServableBackends(t *testing.T) {
	got := servableBackendsFor("darwin", []string{"ollama", "llamacpp"})
	if len(got) != 1 || got[0] != "ollama" {
		t.Errorf("darwin advertisement = %v, want [ollama] — llamacpp has no native runtime yet", got)
	}
}

// There is no Metal vLLM, and a unified CUDA box (DGX Spark) must not have its
// list narrowed by a rule written for Macs.
func TestDarwinNeverAdvertisesCudaOnlyBackends(t *testing.T) {
	got := servableBackendsFor("darwin", []string{"ollama", "vllm", "airllm", "llamacpp"})
	for _, b := range got {
		if b == "vllm" || b == "airllm" {
			t.Errorf("darwin advertised %q — there is no Metal vLLM", b)
		}
	}
}

// Off darwin the container lane serves everything, so the list is untouched.
// The guard that keeps a Mac-motivated change from quietly narrowing Linux.
func TestNonDarwinAdvertisementIsUnchanged(t *testing.T) {
	in := []string{"ollama", "vllm", "airllm", "llamacpp"}
	for _, goos := range []string{"linux", "windows"} {
		got := servableBackendsFor(goos, in)
		if len(got) != len(in) {
			t.Errorf("%s advertisement = %v, want unchanged", goos, got)
		}
	}
}

// The filter is driven by the native-runtime table, so adding a runtime
// restores its backend automatically. A native llama-server still filtered out
// would be invisible for exactly the reason this test exists to prevent.
func TestAdvertisementFollowsTheNativeRuntimeTable(t *testing.T) {
	for b, native := range nativeServable {
		if !native {
			continue
		}
		if got := servableBackendsFor("darwin", []string{b}); len(got) != 1 {
			t.Errorf("%q has a native runtime but is filtered out of the darwin advertisement", b)
		}
	}
}
