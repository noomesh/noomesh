// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A backend spec with both a GPU and a CPU image takes the image the
// placement's target says (the rc.2 rehearsal: `--on cpu` ran the GPU image
// and died on libcuda.so.1). llamacpp has its own rule; no other shipped
// backend carries a CPUImage today (the TEI embedding/reranker ones were
// removed), so the generic rule is exercised with a registered test spec.

const (
	dualGPURef  = "ghcr.io/example/dual:1.6"
	dualCPURef  = "ghcr.io/example/dual:cpu-1.9.4"
	dualBackend = "dualimg"
)

// withDualImageSpec registers a backend with a GPU image and a CPU image for
// the test.
func withDualImageSpec(t *testing.T) {
	t.Helper()
	backendSpecs[dualBackend] = BackendSpec{Image: dualGPURef, CPUImage: dualCPURef, ContainerName: "noo-dual", Network: "noo-cluster"}
	t.Cleanup(func() { delete(backendSpecs, dualBackend) })
}

var (
	gpuUsable  = GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, NvidiaRuntimeRead: true, MinComputeCap: "8.6"}
	gpuDxgOnly = GPUFacts{NvidiaGPU: true, NvidiaRuntimeRead: true}                // /dev/dxg seen, docker says no nvidia runtime
	gpuUnknown = GPUFacts{NvidiaGPU: true, NvidiaRuntimeErr: "connection refused"} // runtime never read
	gpuNone    = GPUFacts{}
)

func dualEnv(t *testing.T) {
	t.Helper()
	withDualImageSpec(t)
}

func chooseFor(backend, target string, f GPUFacts) (backendImageChoice, error) {
	return chooseBackendImageFor(backend, backendSpecs[backend], "", target, f)
}

func TestDualImageCPUTargetIsTheCPUImageOnAUsableGPUNode(t *testing.T) {
	dualEnv(t)
	ch, err := chooseBackendImageFor(dualBackend, backendSpecs[dualBackend], "", "cpu", gpuUsable)
	if err != nil || ch.Ref != dualCPURef {
		t.Fatalf("got %+v, %v; want the CPU image", ch, err)
	}
}

func TestDualImageCPUTargetOnADxgOnlyNodeIsTheCPUImage(t *testing.T) {
	dualEnv(t)
	ch, err := chooseFor(dualBackend, "cpu", gpuDxgOnly)
	if err != nil || ch.Ref != dualCPURef {
		t.Fatalf("got %+v, %v; want the CPU image", ch, err)
	}
}

func TestDualImageGPUTargetWithoutAUsableRuntimeIsRefusedWithTheRemedy(t *testing.T) {
	dualEnv(t)
	for name, f := range map[string]GPUFacts{"dxg-only": gpuDxgOnly, "no gpu": gpuNone, "runtime without gpu": {NvidiaRuntime: true, NvidiaRuntimeRead: true}} {
		ch, err := chooseFor(dualBackend, "gpu", f)
		if err == nil || ch.Ref != "" {
			t.Fatalf("%s: got %+v, %v; want a refusal and no image", name, ch, err)
		}
		var nu *NoUsableGPUError
		if !asNoUsableGPU(err, &nu) {
			t.Fatalf("%s: %T is not a NoUsableGPUError", name, err)
		}
		for _, want := range []string{"NVIDIA container toolkit", "--on cpu", "will not start on the CPU"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: refusal %q lacks %q", name, err, want)
			}
		}
		// The prefetch agrees: nothing to prefetch for a refused start.
		poseGPUFacts(t, f)
		if got := BackendImageRef(dualBackend, "", "gpu"); got != "" {
			t.Fatalf("%s: prefetch names %q for a refused start", name, got)
		}
	}
}

func TestDualImageGPUTargetWithAUsableRuntimeIsTheGPUImage(t *testing.T) {
	dualEnv(t)
	ch, err := chooseFor(dualBackend, "gpu", gpuUsable)
	if err != nil || ch.Ref != dualGPURef || ch.Why != "" {
		t.Fatalf("got %+v, %v; want the GPU image", ch, err)
	}
	poseGPUFacts(t, gpuUsable)
	if got := BackendImageRef(dualBackend, "", "gpu"); got != dualGPURef {
		t.Fatalf("prefetch %q, start %q", got, dualGPURef)
	}
}

func TestDualImageAutoTargetTakesTheGPUOnlyWhenARuntimeIsUsable(t *testing.T) {
	dualEnv(t)
	for _, target := range []string{"", "auto"} {
		ch, err := chooseFor(dualBackend, target, gpuUsable)
		if err != nil || ch.Ref != dualGPURef || ch.Why != "" {
			t.Fatalf("target %q usable: got %+v, %v; want the GPU image", target, ch, err)
		}
		poseGPUFacts(t, gpuUsable)
		if got := BackendImageRef(dualBackend, "", target); got != dualGPURef {
			t.Fatalf("target %q: prefetch %q != start %q", target, got, dualGPURef)
		}
		for name, f := range map[string]GPUFacts{"dxg-only": gpuDxgOnly, "no gpu": gpuNone} {
			ch, err := chooseFor(dualBackend, target, f)
			if err != nil || ch.Ref != dualCPURef {
				t.Fatalf("target %q %s: got %+v, %v; want the CPU image", target, name, ch, err)
			}
			if !strings.Contains(ch.Why, "dualimg on CPU: no usable NVIDIA runtime on this node") {
				t.Fatalf("target %q %s: reason %q not recorded", target, name, ch.Why)
			}
			poseGPUFacts(t, f)
			if got := BackendImageRef(dualBackend, "", target); got != dualCPURef {
				t.Fatalf("target %q %s: prefetch %q != start %q", target, name, got, dualCPURef)
			}
		}
	}
}

func TestDualImageCPUTargetPrefetchAgreesWithTheStart(t *testing.T) {
	dualEnv(t)
	poseGPUFacts(t, gpuUsable)
	if got := BackendImageRef(dualBackend, "", "cpu"); got != dualCPURef {
		t.Fatalf("prefetch %q, want %q", got, dualCPURef)
	}
}

func TestLlamacppUnknownRuntimeIsARetryNotTheCPUBuild(t *testing.T) {
	pinRelease(t)
	f := GPUFacts{NvidiaGPU: true, MinComputeCap: "8.6", NvidiaRuntimeErr: "connection refused"}
	poseGPUFacts(t, f)
	for _, target := range []string{"gpu", ""} {
		ch, err := chooseFor("llamacpp", target, f)
		var ue *GPURuntimeUnknownError
		if ch.Ref != "" || !errors.As(err, &ue) {
			t.Fatalf("target %q: got %+v, %v; want the retry error", target, ch, err)
		}
		if got := BackendImageRef("llamacpp", "", target); got != "" {
			t.Fatalf("target %q: prefetch names %q", target, got)
		}
	}
	if ch, err := chooseFor("llamacpp", "cpu", f); err != nil || ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Fatalf("cpu target: %+v, %v", ch, err)
	}
}

func TestLlamacppKnownAbsentRuntimeIsStillCPUNotRefused(t *testing.T) {
	pinRelease(t)
	f := GPUFacts{NvidiaGPU: true, NvidiaRuntimeRead: true, MinComputeCap: "8.6"}
	poseGPUFacts(t, f)
	for _, target := range []string{"gpu", ""} {
		ch, err := chooseFor("llamacpp", target, f)
		if err != nil || ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" {
			t.Fatalf("target %q: %+v, %v; want the CPU build", target, ch, err)
		}
	}
}

func TestLlamacppKeepsItsOwnRuleAGPUTargetOnAnUnusableNodeIsNotRefused(t *testing.T) {
	pinRelease(t)
	if _, err := chooseFor("llamacpp", "gpu", gpuDxgOnly); err != nil {
		t.Fatalf("llamacpp gpu target on an unusable node must still start as cpu: %v", err)
	}
}

func asNoUsableGPU(err error, target **NoUsableGPUError) bool {
	e, ok := err.(*NoUsableGPUError)
	if ok {
		*target = e
	}
	return ok
}

func TestDualImageUnknownRuntimeWithAutoIsARetryNotAnImage(t *testing.T) {
	dualEnv(t)
	for _, target := range []string{"", "auto"} {
		ch, err := chooseFor(dualBackend, target, gpuUnknown)
		var ue *GPURuntimeUnknownError
		if ch.Ref != "" || !errors.As(err, &ue) {
			t.Fatalf("target %q: got %+v, %v; want the retry error and no image", target, ch, err)
		}
		for _, want := range []string{"cannot tell yet whether the NVIDIA runtime is registered", "docker info failed: connection refused", "retrying on the next pass"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%q lacks %q", err, want)
			}
		}
		poseGPUFacts(t, gpuUnknown)
		if got := BackendImageRef(dualBackend, "", target); got != "" {
			t.Fatalf("target %q: prefetch names %q on an unknown runtime", target, got)
		}
	}
}

func TestDualImageUnknownRuntimeWithGPUTargetIsTheSameRetryNotARefusal(t *testing.T) {
	dualEnv(t)
	_, err := chooseFor(dualBackend, "gpu", gpuUnknown)
	var ue *GPURuntimeUnknownError
	var nu *NoUsableGPUError
	if !errors.As(err, &ue) || errors.As(err, &nu) {
		t.Fatalf("got %T %v; want GPURuntimeUnknownError, not NoUsableGPUError", err, err)
	}
}

func TestDualImageUnknownRuntimeWithCPUTargetIsTheCPUImage(t *testing.T) {
	dualEnv(t)
	ch, err := chooseFor(dualBackend, "cpu", gpuUnknown)
	if err != nil || ch.Ref != dualCPURef {
		t.Fatalf("got %+v, %v", ch, err)
	}
}

func TestDualImageNoGPUAtAllIsCPUWhateverTheRuntimeRead(t *testing.T) {
	dualEnv(t)
	ch, err := chooseFor(dualBackend, "", GPUFacts{})
	if err != nil || ch.Ref != dualCPURef || ch.Why == "" {
		t.Fatalf("got %+v, %v", ch, err)
	}
}

// A fresh process whose first runtime ask fails has NvidiaRuntimeRead=false;
// after one success and then a failure it stays read with the old value.
func TestGPUFactsRuntimeReadSurvivesALaterFailedAsk(t *testing.T) {
	poseGPUFacts(t, GPUFacts{NvidiaGPU: true})
	gpuFactsMu.Lock()
	gpuFactsKnown, gpuFactsNow = false, GPUFacts{}
	gpuFactsMu.Unlock()
	prevAsk, prevCaps := nvidiaRuntimeAskFn, computeCapsFn
	t.Cleanup(func() { nvidiaRuntimeAskFn, computeCapsFn = prevAsk, prevCaps })
	computeCapsFn = func() ([]string, error) { return []string{"8.6"}, nil }
	var ans bool
	var askErr error
	nvidiaRuntimeAskFn = func(context.Context, *Client) (bool, error) { return ans, askErr }

	askErr = errors.New("boom")
	f := (*Client)(nil).RefreshGPUFacts(context.Background())
	if f.NvidiaRuntimeRead || f.NvidiaRuntime || f.NvidiaRuntimeErr != "boom" {
		t.Fatalf("first ask failed: %+v, want unread with the error text", f)
	}
	ans, askErr = true, nil
	f = (*Client)(nil).RefreshGPUFacts(context.Background())
	if !f.NvidiaRuntimeRead || !f.NvidiaRuntime || f.NvidiaRuntimeErr != "" {
		t.Fatalf("good ask: %+v", f)
	}
	askErr = errors.New("slow")
	f = (*Client)(nil).RefreshGPUFacts(context.Background())
	if !f.NvidiaRuntimeRead || !f.NvidiaRuntime {
		t.Fatalf("a failed ask after a good one must keep the old answer: %+v", f)
	}
}
