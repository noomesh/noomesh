// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
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
	teiUsable  = GPUFacts{NvidiaGPU: true, NvidiaRuntime: true, MinComputeCap: "8.6"}
	teiDxgOnly = GPUFacts{NvidiaGPU: true} // /dev/dxg seen, no nvidia runtime in docker
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
	for name, f := range map[string]GPUFacts{"dxg-only": teiDxgOnly, "no gpu": teiNoGPU, "runtime without gpu": {NvidiaRuntime: true}} {
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
