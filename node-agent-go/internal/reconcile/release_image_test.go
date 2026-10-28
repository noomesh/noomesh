// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import "testing"

// rollTo sets the node's release pin the way the bundle's agent.env does.
func rollTo(t *testing.T, tag string) {
	t.Helper()
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", tag)
}

// awolf 2026-10-28: the agent rolled to 0.6.13 and recreated vLLM, but
// noo-llamacpp and its stunnel door stayed on v0.6.12 for good. The
// controller sends no image for llama.cpp (the node derives its release
// ref), so the placement is unchanged by a roll; the spec hash must still
// move, or the running container is "converged" forever.
func TestSpecHash_ARollRecreatesABackendOnTheNodesReleaseImage(t *testing.T) {
	t.Setenv("LLAMACPP_IMAGE", "")
	t.Setenv("STUNNEL_IMAGE", "")
	p := placement{Backend: "llamacpp", Model: "gemma-4-E4B-it-Q4_K_M.gguf", Port: 8085, DesiredState: "running"}

	rollTo(t, "v0.6.12")
	stamped := specHash(p) // the label on the container the 0.6.12 agent created
	rollTo(t, "v0.6.13")
	if got := decideBackendDrift(true, stamped, specHash(p), "", ""); got != driftRecreate {
		t.Fatalf("after a roll the llama.cpp backend must be recreated on the new release image, got %v", got)
	}
	// And once recreated under the new release it is converged (no loop).
	if got := decideBackendDrift(true, specHash(p), specHash(p), "", ""); got != driftConverged {
		t.Fatalf("an unchanged release must converge, got %v", got)
	}
}

// The door sidecar moves with the release even when the placement pins
// the backend's own image (an operator's LLAMACPP_IMAGE in the placement).
func TestSpecHash_TheDoorSidecarFollowsTheRelease(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	p := placement{Backend: "llamacpp", Model: "m.gguf", Image: "reg.example/acme/llamacpp:v9@sha256:00", Port: 8085}
	rollTo(t, "v0.6.12")
	before := specHash(p)
	rollTo(t, "v0.6.13")
	if specHash(p) == before {
		t.Fatal("the stunnel sidecar's image moved with the release but the hash did not")
	}
}

// What must NOT churn: a backend with no sidecar on an image the controller
// pins (vLLM), and any backend on a node with no release pin.
func TestSpecHash_NoChurnWhereNothingFollowsTheRelease(t *testing.T) {
	vllm := basePlacement()
	vllm.Image = ""
	rollTo(t, "v0.6.12")
	before := specHash(vllm)
	rollTo(t, "v0.6.13")
	if specHash(vllm) != before {
		t.Fatal("vLLM's image comes from the placement; a node roll alone must not recreate it")
	}

	t.Setenv("NOO_IMAGE_PREFIX", "")
	t.Setenv("NOO_IMAGE_TAG", "")
	t.Setenv("STUNNEL_IMAGE", "")
	t.Setenv("LLAMACPP_IMAGE", "")
	llama := placement{Backend: "llamacpp", Model: "m.gguf", Port: 8085}
	h := specHash(llama)
	for i := 0; i < 10; i++ {
		if specHash(llama) != h {
			t.Fatal("unstable hash with no release pin")
		}
	}
}

// An operator override that is not this release's image is the operator's
// choice: the release does not fold in for the backend (the sidecar still does).
func TestSpecHash_AnOverrideOffTheReleaseIsNotFolded(t *testing.T) {
	t.Setenv("LLAMACPP_IMAGE", "reg.example/acme/llamacpp:v9")
	t.Setenv("STUNNEL_IMAGE", "reg.example/acme/stunnel:v9")
	p := placement{Backend: "llamacpp", Model: "m.gguf", Port: 8085}
	rollTo(t, "v0.6.12")
	before := specHash(p)
	rollTo(t, "v0.6.13")
	if specHash(p) != before {
		t.Fatal("both images are pinned off the release; a roll must not recreate the backend")
	}
}
