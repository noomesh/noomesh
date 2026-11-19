// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Whether THIS node can run llama.cpp on its GPU, and so whether a llamacpp
// start takes the CUDA image (docker/Dockerfile.llamacpp-cuda) or the CPU one
// (docker/Dockerfile.llamacpp). One rule, LlamacppGPUUsable, read by the start
// (image, GPU device, N_GPU_LAYERS: chooseBackendImage, applyTarget), by the
// reconciler's prefetch, keep list and spec hash (BackendImageRef,
// ReleaseBackendImage) and by gpuyield (LlamacppGPUUsableHere). The gateway's
// fit (placement_fit::llamacpp_gpu_usable) and noo-cli's `place`
// (cluster_tune::llamacpp_gpu_usable) apply the same rule to the facts this
// node's heartbeat reports (gpu_compute_cap, nvidia_runtime), so the fit, the
// CLI and the agent agree on where a llamacpp placement runs.

// LlamacppMinComputeCap is the lowest CUDA compute capability the CUDA image
// carries code for: its lowest cubin (61-real) and its PTX fallback
// (61-virtual) are both compute_61, and PTX only JIT-compiles FORWARD, so a
// compute 6.0 GPU (Tesla P100) would have no kernel to run. The floor is the
// image's arch list, not a round number: docker/Dockerfile.llamacpp-cuda's
// CUDA_ARCHITECTURES (tests/test_llamacpp_gpu_build_claim.py holds this, the
// gateway's and the CLI's copies to its lowest arch).
const LlamacppMinComputeCap = "6.1"

// GPUFacts is what decides LlamacppGPUUsable on this node.
type GPUFacts struct {
	// NvidiaGPU: an NVIDIA GPU is visible to the agent (hasNvidiaGPU).
	NvidiaGPU bool
	// NvidiaRuntime: the daemon lists the nvidia runtime, so a device request
	// can be honoured (NvidiaRuntimeKnown). Unknown counts as absent.
	NvidiaRuntime bool
	// MinComputeCap: the lowest compute capability of the node's GPUs
	// ("6.1"), "" when it could not be read. Unknown counts as too low.
	MinComputeCap string
}

// LlamacppGPUUsable reports whether a node with these facts runs the CUDA
// llama.cpp image: a GPU build exists (LlamacppHasGPUBuild), an NVIDIA GPU is
// present, the nvidia runtime is registered and every GPU is at least
// LlamacppMinComputeCap. Anything unknown is "no": the CPU image always runs.
func LlamacppGPUUsable(f GPUFacts) bool {
	if !LlamacppHasGPUBuild || !f.NvidiaGPU || !f.NvidiaRuntime {
		return false
	}
	ok, err := nodewl.ComputeCapAtLeast(f.MinComputeCap, LlamacppMinComputeCap)
	return err == nil && ok
}

// StartTarget is the target a placement starts with: its declared one, except
// a llamacpp placement that declares none and pins N_GPU_LAYERS=0 in its env
// (the spelling of cpu from before `target` existed), which is cpu, as the
// gateway's fit (placement_fit::resolve_target) and noo-cli read it. So such
// a row never fetches the CUDA image to offload nothing.
func StartTarget(backend, target string, env map[string]string) string {
	if backend == "llamacpp" && target == "" && strings.TrimSpace(env["N_GPU_LAYERS"]) == "0" {
		return "cpu"
	}
	return target
}

// llamacppOnGPU: a llamacpp start with this placement target runs on the GPU
// (the CUDA image, the device, every layer offloaded). `cpu` never does; `gpu`
// and an undeclared target do on a node that can use the GPU build.
func llamacppOnGPU(target string, f GPUFacts) bool {
	return target != "cpu" && LlamacppGPUUsable(f)
}

var (
	gpuFactsMu    sync.Mutex
	gpuFactsKnown bool
	gpuFactsNow   GPUFacts
	// computeCapsFn is the compute capability probe (nvidia-smi).
	computeCapsFn = (&hardware.GPUDetector{}).DetectComputeCaps
)

// NodeGPUFacts is the last refreshed answer (RefreshGPUFacts); before the
// first refresh only the cheap device probe is known, and the runtime and the
// compute capability count as unknown (so: the CPU image).
func NodeGPUFacts() GPUFacts {
	gpuFactsMu.Lock()
	defer gpuFactsMu.Unlock()
	if !gpuFactsKnown {
		return GPUFacts{NvidiaGPU: hasNvidiaGPU()}
	}
	return gpuFactsNow
}

// LlamacppGPUUsableHere is LlamacppGPUUsable on this node's current facts.
func LlamacppGPUUsableHere() bool { return LlamacppGPUUsable(NodeGPUFacts()) }

// setNodeGPUFacts records the facts (tests use it to pose as a node).
func setNodeGPUFacts(f GPUFacts) {
	gpuFactsMu.Lock()
	gpuFactsNow, gpuFactsKnown = f, true
	gpuFactsMu.Unlock()
}

// minComputeCap is the lowest of caps, "" when any does not parse or none.
func minComputeCap(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	min := caps[0]
	for _, c := range caps {
		atLeast, err := nodewl.ComputeCapAtLeast(c, min)
		if err != nil {
			return ""
		}
		if !atLeast {
			min = c
		}
	}
	return min
}

// RefreshGPUFacts re-reads this node's GPU facts (the reconciler, once a
// tick, before it plans; a start that finds none read yet). The nvidia
// runtime is asked every time (the toolkit can be installed under a running
// agent); a failed ask keeps the previous answer. A compute capability does
// not change under a running agent, so a good reading is kept.
func (c *Client) RefreshGPUFacts(ctx context.Context) GPUFacts {
	prev := NodeGPUFacts()
	f := GPUFacts{NvidiaGPU: hasNvidiaGPU()}
	if f.NvidiaGPU {
		f.NvidiaRuntime = prev.NvidiaRuntime
		if c != nil && c.docker != nil {
			if ok, err := c.NvidiaRuntimeKnown(ctx); err == nil {
				f.NvidiaRuntime = ok
			}
		}
		f.MinComputeCap = prev.MinComputeCap
		if f.MinComputeCap == "" {
			if caps, err := computeCapsFn(); err == nil {
				f.MinComputeCap = minComputeCap(caps)
			} else {
				slog.Debug("llamacpp gpu facts: compute capability unknown", "error", err)
			}
		}
	}
	setNodeGPUFacts(f)
	return f
}

// gpuFactsForStart is the facts a start decides on: the refreshed ones, read
// now if no tick has read them yet.
func (c *Client) gpuFactsForStart(ctx context.Context) GPUFacts {
	gpuFactsMu.Lock()
	known := gpuFactsKnown
	gpuFactsMu.Unlock()
	if !known {
		return c.RefreshGPUFacts(ctx)
	}
	return NodeGPUFacts()
}
