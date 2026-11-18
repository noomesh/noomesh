// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"testing"
)

// poseGPUFacts makes this node's GPU facts f for the test (and the device
// probe agree with f.NvidiaGPU), restoring both after.
func poseGPUFacts(t *testing.T, f GPUFacts) {
	t.Helper()
	gpuFactsMu.Lock()
	prevKnown, prev := gpuFactsKnown, gpuFactsNow
	gpuFactsMu.Unlock()
	prevDetected := nvidiaGPUDetected
	nvidiaGPUDetected = f.NvidiaGPU
	setNodeGPUFacts(f)
	t.Cleanup(func() {
		nvidiaGPUDetected = prevDetected
		gpuFactsMu.Lock()
		gpuFactsKnown, gpuFactsNow = prevKnown, prev
		gpuFactsMu.Unlock()
	})
}

var usablePascal = GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "6.1"}

func llamacppStart(t *testing.T, target string) (backendImageChoice, string, []string) {
	t.Helper()
	f := NodeGPUFacts()
	ch, err := chooseBackendImageFor("llamacpp", backendSpecs["llamacpp"], "", target, f)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	reserve := applyTarget("llamacpp", target, f, env, "all")
	return ch, reserve, buildEnvList(map[string]string{"N_GPU_LAYERS": "${N_GPU_LAYERS:-auto}"}, env)
}

func hasKV(list []string, kv string) bool {
	for _, x := range list {
		if x == kv {
			return true
		}
	}
	return false
}

// The rule: NVIDIA GPU + nvidia runtime + compute >= LlamacppMinComputeCap +
// a gpu (or undeclared) target is the CUDA image, the GPU device and every
// layer offloaded.
func TestLlamacppOnAUsableGPUNodeRunsTheCUDAImageWithTheDeviceAndEveryLayer(t *testing.T) {
	pinRelease(t)
	poseGPUFacts(t, usablePascal)
	for _, target := range []string{"gpu", ""} {
		ch, reserve, env := llamacppStart(t, target)
		if ch.Ref != "ghcr.io/noomesh/llamacpp-cuda:v0.6.15" || !ch.RailOnly {
			t.Fatalf("target %q: image %+v, want our CUDA build from the rail", target, ch)
		}
		if reserve != "all" {
			t.Fatalf("target %q: gpu reserve %q, want all", target, reserve)
		}
		reqs := gpuDeviceRequests(reserve)
		if len(reqs) != 1 || reqs[0].Driver != "nvidia" || reqs[0].Count != -1 {
			t.Fatalf("target %q: device request %+v", target, reqs)
		}
		if !hasKV(env, "N_GPU_LAYERS=999") {
			t.Fatalf("target %q: auto must offload every layer on a GPU start: %v", target, env)
		}
		if got := BackendImageRef("llamacpp", "", target); got != ch.Ref {
			t.Fatalf("target %q: the prefetch names %q, the start %q", target, got, ch.Ref)
		}
		if got := ReleaseBackendImage("llamacpp", target); got != ch.Ref {
			t.Fatalf("target %q: the spec hash folds %q, the start runs %q", target, got, ch.Ref)
		}
	}
}

// Compute capability below the image's lowest arch (5.2, Maxwell): the CPU
// image, as cpu. Unknown is the same.
func TestLlamacppBelowTheMinComputeCapRunsTheCPUImageAsCPU(t *testing.T) {
	pinRelease(t)
	for _, cc := range []string{"5.2", "6.0", ""} {
		poseGPUFacts(t, GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: cc})
		ch, reserve, env := llamacppStart(t, "gpu")
		if ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" {
			t.Fatalf("compute %q: image %q, want the CPU build", cc, ch.Ref)
		}
		if reserve != "0" || !hasKV(env, "N_GPU_LAYERS=0") {
			t.Fatalf("compute %q: reserve %q env %v, want cpu", cc, reserve, env)
		}
		if got := BackendImageRef("llamacpp", "", "gpu"); got != ch.Ref {
			t.Fatalf("compute %q: the prefetch names %q (a CPU node must never fetch the CUDA image)", cc, got)
		}
	}
}

// An NVIDIA GPU without the nvidia runtime cannot be handed to a container:
// the CPU image, as cpu.
func TestLlamacppWithoutTheNvidiaRuntimeRunsTheCPUImageAsCPU(t *testing.T) {
	pinRelease(t)
	poseGPUFacts(t, GPUFacts{NvidiaGPU: true, NvidiaRuntime: false, MinComputeCap: "8.6"})
	ch, reserve, env := llamacppStart(t, "gpu")
	if ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" || reserve != "0" || !hasKV(env, "N_GPU_LAYERS=0") {
		t.Fatalf("no runtime: image %q reserve %q env %v, want the CPU build as cpu", ch.Ref, reserve, env)
	}
	poseGPUFacts(t, GPUFacts{})
	if ch, reserve, _ := llamacppStart(t, "gpu"); ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" || reserve != "0" {
		t.Fatalf("no NVIDIA GPU: image %q reserve %q", ch.Ref, reserve)
	}
}

// A cpu target on a node that could use the GPU: the CPU image, no device.
func TestLlamacppPlacedOnCPURunsTheCPUImageEvenOnAUsableGPUNode(t *testing.T) {
	pinRelease(t)
	poseGPUFacts(t, usablePascal)
	ch, reserve, env := llamacppStart(t, "cpu")
	if ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" || reserve != "0" || !hasKV(env, "N_GPU_LAYERS=0") {
		t.Fatalf("target cpu: image %q reserve %q env %v", ch.Ref, reserve, env)
	}
	if got := ReleaseBackendImage("llamacpp", "cpu"); got != ch.Ref {
		t.Fatalf("spec hash folds %q for a cpu start of %q", got, ch.Ref)
	}
}

// The explicit overrides: LLAMACPP_CUDA_IMAGE names the GPU image and turns
// off our default for it only; LLAMACPP_IMAGE does the same for the CPU one.
func TestLlamacppImageOverridesAreOnePerBuild(t *testing.T) {
	pinRelease(t)
	t.Setenv("LLAMACPP_CUDA_IMAGE", "registry.example/mine/llama-cuda:1")
	if ours := hardenedDefault("llamacpp", false); ours != "" {
		t.Fatalf("LLAMACPP_CUDA_IMAGE must disable our CUDA default, got %q", ours)
	}
	if ours := hardenedDefault("llamacpp", true); ours != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Fatalf("LLAMACPP_CUDA_IMAGE must not touch the CPU default, got %q", ours)
	}
}

// One rule (LlamacppGPUUsable) and its edges, numerically compared.
func TestLlamacppGPUUsableNeedsEveryFact(t *testing.T) {
	for _, c := range []struct {
		f    GPUFacts
		want bool
	}{
		{usablePascal, true},
		{GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "12.0"}, true},
		{GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "6.0"}, false},
		{GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "5.2"}, false},
		{GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "[N/A]"}, false},
		{GPUFacts{NvidiaGPU: true, NvidiaRuntime: false, MinComputeCap: "8.6"}, false},
		{GPUFacts{NvidiaGPU: false, NvidiaRuntime: true, MinComputeCap: "8.6"}, false},
	} {
		if got := LlamacppGPUUsable(c.f); got != c.want {
			t.Errorf("%+v: usable %v, want %v", c.f, got, c.want)
		}
	}
	if got := minComputeCap([]string{"8.6", "6.1", "10.0"}); got != "6.1" {
		t.Errorf("min of the GPUs = %q", got)
	}
}

// A llamacpp row with no target and N_GPU_LAYERS=0 (cpu before `target`
// existed) starts as cpu, as the gateway's fit reads it: on a usable GPU node
// it must not fetch the CUDA image to offload nothing.
func TestALegacyNGPULayers0LlamacppRowStartsAsCPU(t *testing.T) {
	pinRelease(t)
	poseGPUFacts(t, usablePascal)
	target := StartTarget("llamacpp", "", map[string]string{"N_GPU_LAYERS": "0"})
	if target != "cpu" {
		t.Fatalf("target %q, want cpu", target)
	}
	if got := BackendImageRef("llamacpp", "", target); got != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Fatalf("a legacy cpu row prefetches %q", got)
	}
	if StartTarget("llamacpp", "", map[string]string{"N_GPU_LAYERS": "999"}) != "" || StartTarget("ollama", "", map[string]string{"N_GPU_LAYERS": "0"}) != "" {
		t.Fatal("only llamacpp's N_GPU_LAYERS=0 with no target is read as cpu")
	}
}
