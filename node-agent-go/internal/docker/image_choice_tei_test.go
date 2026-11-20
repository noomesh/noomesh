// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TEI's image follows the placement's target (the rc.2 rehearsal: `--on cpu`
// ran the GPU image and died on libcuda.so.1).

const (
	teiGPURef = "ghcr.io/huggingface/text-embeddings-inference:1.6"
	teiCPURef = "ghcr.io/huggingface/text-embeddings-inference:cpu-1.9.4"
)

var (
	teiUsable  = GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, NvidiaRuntimeRead: true, MinComputeCap: "8.6"}
	teiDxgOnly = GPUFacts{NvidiaGPU: true, NvidiaRuntimeRead: true}                // /dev/dxg seen, docker says no nvidia runtime
	teiUnknown = GPUFacts{NvidiaGPU: true, NvidiaRuntimeErr: "connection refused"} // runtime never read
	teiNoGPU   = GPUFacts{}
)

func teiEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TEI_GPU_IMAGE", "")
	t.Setenv("TEI_CPU_IMAGE", "")
}

func teiChoose(backend, target string, f GPUFacts) (backendImageChoice, error) {
	return chooseBackendImageFor(backend, backendSpecs[backend], "", target, f)
}

func TestTEICPUTargetIsTheCPUImageOnAUsableGPUNode(t *testing.T) {
	teiEnv(t)
	for _, b := range []string{"embedding", "reranker"} {
		if b == "reranker" {
			t.Setenv("RERANK_ENGINE", "tei")
		}
		spec := backendSpecs[b]
		if b == "reranker" {
			spec = rerankerSpecTEI()
		}
		ch, err := chooseBackendImageFor(b, spec, "", "cpu", teiUsable)
		if err != nil || ch.Ref != teiCPURef {
			t.Fatalf("%s: got %+v, %v; want the CPU image", b, ch, err)
		}
	}
}

func TestTEICPUTargetOnADxgOnlyNodeIsTheCPUImage(t *testing.T) {
	teiEnv(t)
	ch, err := teiChoose("embedding", "cpu", teiDxgOnly)
	if err != nil || ch.Ref != teiCPURef {
		t.Fatalf("got %+v, %v; want the CPU image", ch, err)
	}
}

func TestTEIGPUTargetWithoutAUsableRuntimeIsRefusedWithTheRemedy(t *testing.T) {
	teiEnv(t)
	for name, f := range map[string]GPUFacts{"dxg-only": teiDxgOnly, "no gpu": teiNoGPU, "runtime without gpu": {NvidiaRuntime: true, NvidiaRuntimeRead: true}} {
		ch, err := teiChoose("embedding", "gpu", f)
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
		if got := BackendImageRef("embedding", "", "gpu"); got != "" {
			t.Fatalf("%s: prefetch names %q for a refused start", name, got)
		}
	}
}

func TestTEIGPUTargetWithAUsableRuntimeIsTheGPUImage(t *testing.T) {
	teiEnv(t)
	ch, err := teiChoose("embedding", "gpu", teiUsable)
	if err != nil || ch.Ref != teiGPURef || ch.Why != "" {
		t.Fatalf("got %+v, %v; want the GPU image", ch, err)
	}
	poseGPUFacts(t, teiUsable)
	if got := BackendImageRef("embedding", "", "gpu"); got != teiGPURef {
		t.Fatalf("prefetch %q, start %q", got, teiGPURef)
	}
}

func TestTEIAutoTargetTakesTheGPUOnlyWhenARuntimeIsUsable(t *testing.T) {
	teiEnv(t)
	for _, target := range []string{"", "auto"} {
		ch, err := teiChoose("embedding", target, teiUsable)
		if err != nil || ch.Ref != teiGPURef || ch.Why != "" {
			t.Fatalf("target %q usable: got %+v, %v; want the GPU image", target, ch, err)
		}
		poseGPUFacts(t, teiUsable)
		if got := BackendImageRef("embedding", "", target); got != teiGPURef {
			t.Fatalf("target %q: prefetch %q != start %q", target, got, teiGPURef)
		}
		for name, f := range map[string]GPUFacts{"dxg-only": teiDxgOnly, "no gpu": teiNoGPU} {
			ch, err := teiChoose("embedding", target, f)
			if err != nil || ch.Ref != teiCPURef {
				t.Fatalf("target %q %s: got %+v, %v; want the CPU image", target, name, ch, err)
			}
			if !strings.Contains(ch.Why, "TEI embedding on CPU: no usable NVIDIA runtime on this node") {
				t.Fatalf("target %q %s: reason %q not recorded", target, name, ch.Why)
			}
			poseGPUFacts(t, f)
			if got := BackendImageRef("embedding", "", target); got != teiCPURef {
				t.Fatalf("target %q %s: prefetch %q != start %q", target, name, got, teiCPURef)
			}
		}
	}
}

func TestTEICPUTargetPrefetchAgreesWithTheStart(t *testing.T) {
	teiEnv(t)
	poseGPUFacts(t, teiUsable)
	if got := BackendImageRef("embedding", "", "cpu"); got != teiCPURef {
		t.Fatalf("prefetch %q, want %q", got, teiCPURef)
	}
}

func TestLlamacppUnknownRuntimeIsARetryNotTheCPUBuild(t *testing.T) {
	pinRelease(t)
	f := GPUFacts{NvidiaGPU: true, MinComputeCap: "8.6", NvidiaRuntimeErr: "connection refused"}
	poseGPUFacts(t, f)
	for _, target := range []string{"gpu", ""} {
		ch, err := teiChoose("llamacpp", target, f)
		var ue *TEIRuntimeUnknownError
		if ch.Ref != "" || !errors.As(err, &ue) {
			t.Fatalf("target %q: got %+v, %v; want the retry error", target, ch, err)
		}
		if got := BackendImageRef("llamacpp", "", target); got != "" {
			t.Fatalf("target %q: prefetch names %q", target, got)
		}
	}
	if ch, err := teiChoose("llamacpp", "cpu", f); err != nil || ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Fatalf("cpu target: %+v, %v", ch, err)
	}
}

func TestLlamacppKnownAbsentRuntimeIsStillCPUNotRefused(t *testing.T) {
	pinRelease(t)
	f := GPUFacts{NvidiaGPU: true, NvidiaRuntimeRead: true, MinComputeCap: "8.6"}
	poseGPUFacts(t, f)
	for _, target := range []string{"gpu", ""} {
		ch, err := teiChoose("llamacpp", target, f)
		if err != nil || ch.Ref != "ghcr.io/noomesh/llamacpp:v0.6.15" {
			t.Fatalf("target %q: %+v, %v; want the CPU build", target, ch, err)
		}
	}
}

func TestLlamacppKeepsItsOwnRuleAGPUTargetOnAnUnusableNodeIsNotRefused(t *testing.T) {
	pinRelease(t)
	if _, err := teiChoose("llamacpp", "gpu", teiDxgOnly); err != nil {
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

func TestTEIUnknownRuntimeWithAutoIsARetryNotAnImage(t *testing.T) {
	teiEnv(t)
	for _, target := range []string{"", "auto"} {
		ch, err := teiChoose("embedding", target, teiUnknown)
		var ue *TEIRuntimeUnknownError
		if ch.Ref != "" || !errors.As(err, &ue) {
			t.Fatalf("target %q: got %+v, %v; want the retry error and no image", target, ch, err)
		}
		for _, want := range []string{"cannot tell yet whether the NVIDIA runtime is registered", "docker info failed: connection refused", "retrying on the next pass"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%q lacks %q", err, want)
			}
		}
		poseGPUFacts(t, teiUnknown)
		if got := BackendImageRef("embedding", "", target); got != "" {
			t.Fatalf("target %q: prefetch names %q on an unknown runtime", target, got)
		}
	}
}

func TestTEIUnknownRuntimeWithGPUTargetIsTheSameRetryNotARefusal(t *testing.T) {
	teiEnv(t)
	_, err := teiChoose("embedding", "gpu", teiUnknown)
	var ue *TEIRuntimeUnknownError
	var nu *NoUsableGPUError
	if !errors.As(err, &ue) || errors.As(err, &nu) {
		t.Fatalf("got %T %v; want TEIRuntimeUnknownError, not NoUsableGPUError", err, err)
	}
}

func TestTEIUnknownRuntimeWithCPUTargetIsTheCPUImage(t *testing.T) {
	teiEnv(t)
	ch, err := teiChoose("embedding", "cpu", teiUnknown)
	if err != nil || ch.Ref != teiCPURef {
		t.Fatalf("got %+v, %v", ch, err)
	}
}

func TestTEINoGPUAtAllIsCPUWhateverTheRuntimeRead(t *testing.T) {
	teiEnv(t)
	ch, err := teiChoose("embedding", "", GPUFacts{})
	if err != nil || ch.Ref != teiCPURef || ch.Why == "" {
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
