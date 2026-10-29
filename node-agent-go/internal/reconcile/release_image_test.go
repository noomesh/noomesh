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

// What must NOT churn: a backend with no door on an image the placement
// pins (airllm), and any backend on a node with no release pin.
func TestSpecHash_NoChurnWhereNothingFollowsTheRelease(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	airllm := placement{Backend: "airllm", Model: "m", Image: "reg.example/acme/airllm:v1", Port: 8000}
	rollTo(t, "v0.6.12")
	before := specHash(airllm)
	rollTo(t, "v0.6.13")
	if specHash(airllm) != before {
		t.Fatal("airllm's image comes from the placement and it has no door; a node roll alone must not recreate it")
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

// vLLM's door is PINNED (docker door_images.json, operator 2026-10-28): a
// release roll alone leaves its spec hash, so vLLM is not reloaded per roll.
// The stunnel image is rebuilt every release, so following the release would
// recreate vLLM on every roll for a door that did not change.
func TestSpecHash_AReleaseRollAloneLeavesVLLM(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	vllm := basePlacement()
	rollTo(t, "v0.6.13")
	before := specHash(vllm)
	rollTo(t, "v0.6.14")
	if specHash(vllm) != before {
		t.Fatal("a release-tag change alone recreated vLLM; its door is pinned and did not change")
	}
}

// A change to vLLM's door image does move the hash: here the registry the
// pin resolves against (a different image), and an operator's STUNNEL_IMAGE.
// The pin's own tag and digest are covered in the docker package
// (TestThePinnedDoorFollowsItsPinNotTheRelease).
func TestSpecHash_ADoorImageChangeRecreatesVLLM(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	vllm := basePlacement()
	rollTo(t, "v0.6.13")
	before := specHash(vllm)
	t.Setenv("NOO_IMAGE_PREFIX", "reg.example/mirror")
	if specHash(vllm) == before {
		t.Fatal("vLLM's door image changed (another registry) but the hash did not")
	}
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("STUNNEL_IMAGE", "reg.example/acme/stunnel:v9")
	if specHash(vllm) == before {
		t.Fatal("an operator's STUNNEL_IMAGE changed vLLM's door but the hash did not")
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
