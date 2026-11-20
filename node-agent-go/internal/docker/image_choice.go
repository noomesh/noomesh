// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/distribution/reference"
)

// ONE image choice for a backend, used by StartBackendSDK (to start it) and
// BackendImageRef (to prefetch it), so the two cannot drift: the prefetch
// used to mirror the choice by hand.
//
// # The policy
//
// The model server handles every prompt on the node, so a ref that can move
// under it is a hole. The controller sends the digest-pinned ref from the
// signed stack lock in the start overrides (gateway routes/cluster.rs); the
// node enforces:
//
//   - a floating ref (`:latest`, or no tag at all) is refused, wherever it
//     came from (placement, controller override, the node's own env). Our own
//     images (the registry roots and the local build names) are exempt: they
//     are rail-only. When the controller forwards one pinned from the signed
//     lock (`repo:tag@sha256:<index>`), the digest is cut off the ref (the
//     rail's tar is keyed by the tag ref) and kept as the choice's Pin: the
//     start is refused unless the rail staged that tar by exactly this digest
//     and the image loaded is the one staged (resolvePinnedImage).
//   - every image comes from the rail (the only image source). A third-party
//     ref with a digest has the digest stripped before the container is made
//     and the registry is forbidden: the rail's tar is keyed by the tag ref,
//     and the image is the one the manifest names. A ref without a digest is
//     accepted because the rail vouches for it (the tar the controller staged
//     is verified against the gateway's manifest before `docker load`, which
//     is as strong as a digest); if it is not staged the start is refused with
//     the staging command.

// digestRe is the `@sha256:<64 hex>` suffix of a pinned ref.
var digestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// splitDigest splits `repo:tag@sha256:...` into (`repo:tag`, `sha256:...`).
func splitDigest(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if loc := digestRe.FindStringIndex(ref); loc != nil {
		return ref[:loc[0]], ref[loc[0]+1:]
	}
	return ref, ""
}

// isFloatingRef reports a ref with no tag, or the tag `latest`, and no digest.
func isFloatingRef(ref string) bool {
	tagRef, digest := splitDigest(ref)
	if digest != "" {
		return false
	}
	n, err := reference.ParseNormalizedNamed(tagRef)
	if err != nil {
		return false // an unparsable ref is refused elsewhere (resolveImage)
	}
	t, ok := n.(reference.Tagged)
	return !ok || t.Tag() == "latest"
}

// backendImageChoice is the ref to use and how it may be fetched.
type backendImageChoice struct {
	Ref      string // the image to ensure and run (no digest for our own images)
	RailOnly bool   // never from a registry (a rail node)
	// Pin is the digest the controller pinned for one of OUR images
	// (`sha256:…`, from the signed stack lock), "" when none.
	Pin string
	// Why is the reason an automatic CPU image was taken ("TEI embedding on
	// CPU: no usable NVIDIA runtime on this node"), "" otherwise.
	Why string
}

// pickBackendImage is the pure part of the choice: CPU/GPU image, then the
// controller's override or ${VAR} substitution. No policy.
func pickBackendImage(spec BackendSpec, override string, cpuImage bool) string {
	if spec.CPUImage != "" && cpuImage {
		spec.Image = spec.CPUImage
	}
	if override != "" {
		return override
	}
	return resolveEnv(spec.Image)
}

// NoUsableGPUError: a start asked for the GPU (`--on gpu`) on a node with no
// usable NVIDIA runtime. It is a refusal, never a silent CPU image: an
// operator who asked for a GPU must not get a CPU server that looks placed.
// It reaches the placement as a `backend_start` refusal (the reconciler
// records err.Error()), the way ImageNotStagedError does.
type NoUsableGPUError struct{ Backend string }

func (e *NoUsableGPUError) Error() string {
	return fmt.Sprintf("backend %s: placed --on gpu, but this node has no usable NVIDIA runtime "+
		"(an NVIDIA GPU the agent sees AND the nvidia runtime registered with docker), so it will not start on the CPU instead. "+
		"Install the NVIDIA container toolkit (nvidia-ctk runtime configure, then restart docker), or place it `--on cpu`", e.Backend)
}

// TEIRuntimeUnknownError (TEI and llamacpp): the node has an NVIDIA GPU but the agent has never
// had an answer to "does docker list the nvidia runtime" (docker info failed
// or was slow at boot). Unknown is not absent, so the start neither takes the
// GPU image nor silently downgrades to the CPU one: it is refused for now and
// the reconciler records it as a backend_start refusal, then asks again on its
// next pass (RefreshGPUFacts runs first each tick).
type TEIRuntimeUnknownError struct{ Backend, Detail string }

func (e *TEIRuntimeUnknownError) Error() string {
	return fmt.Sprintf("backend %s: cannot tell yet whether the NVIDIA runtime is registered: docker info failed: %s; retrying on the next pass",
		e.Backend, e.Detail)
}

// teiGPUUsable is what "a usable NVIDIA runtime" means for the TEI GPU image:
// an NVIDIA GPU is visible to the agent (GPUFacts.NvidiaGPU) AND the docker
// daemon lists the nvidia runtime (GPUFacts.NvidiaRuntime, NvidiaRuntimeKnown;
// unknown counts as absent). A device node alone is never proof: /dev/dxg
// (WSL2's paravirtual device, which the GPU probe counts) or /dev/nvgpu exist
// on boxes where docker cannot hand a GPU out. Unlike LlamacppGPUUsable there
// is no compute-capability floor: TEI's CUDA image has none the agent knows.
func teiGPUUsable(f GPUFacts) bool { return f.NvidiaGPU && f.NvidiaRuntime }

// wantsCPUImage says which of a spec's two images a start takes, and why
// when the answer is an automatic CPU. llamacpp: the CPU build unless the
// start runs on this node's GPU (llamacppOnGPU). Every other backend with a
// CPUImage (TEI embedding/reranker), by the placement's target:
//
//   - cpu: the CPU image, always;
//   - a GPU present but the runtime never read: a retryable *TEIRuntimeUnknownError
//     for gpu and auto (cpu is unaffected);
//   - gpu: the GPU image on a usable NVIDIA runtime (teiGPUUsable), else a
//     *NoUsableGPUError: never a silent CPU image;
//   - unset/auto: the GPU image on a usable runtime, else the CPU image, with
//     the reason ("TEI embedding on CPU: no usable NVIDIA runtime on this node").
//
// llamacpp keeps its own rule once the runtime is read (a compute-capability
// floor; a `gpu` target on an unusable node is cpu, logged, not a refusal);
// only the never-read case waits, as for TEI (llamacppWaitsOnRuntime).
func wantsCPUImage(backend string, spec BackendSpec, target string, f GPUFacts) (cpu bool, why string, err error) {
	if backend == "llamacpp" {
		if llamacppWaitsOnRuntime(target, f) {
			return false, "", &TEIRuntimeUnknownError{Backend: backend, Detail: f.NvidiaRuntimeErr}
		}
		return !llamacppOnGPU(target, f), "", nil
	}
	if spec.CPUImage == "" {
		return false, "", nil
	}
	if target == "cpu" {
		return true, "", nil
	}
	// A GPU is there but the runtime was never read: not "absent" (see
	// TEIRuntimeUnknownError). No GPU at all: the runtime is irrelevant.
	if f.NvidiaGPU && !f.NvidiaRuntimeRead {
		return false, "", &TEIRuntimeUnknownError{Backend: backend, Detail: f.NvidiaRuntimeErr}
	}
	switch target {
	case "gpu":
		if !teiGPUUsable(f) {
			return false, "", &NoUsableGPUError{Backend: backend}
		}
		return false, "", nil
	}
	if teiGPUUsable(f) {
		return false, "", nil
	}
	return true, fmt.Sprintf("TEI %s on CPU: no usable NVIDIA runtime on this node", backend), nil
}

// chooseBackendImage is chooseBackendImageFor on this node's current GPU facts.
func chooseBackendImage(backend string, spec BackendSpec, override, target string) (backendImageChoice, error) {
	return chooseBackendImageFor(backend, spec, override, target, NodeGPUFacts())
}

// chooseBackendImageFor picks the backend's image and applies the policy
// above. override is StartOverrides.Image (the controller's / the
// placement's); target is the placement's hardware target. A refused `gpu`
// target is an error here, so a start does not run and BackendImageRef (which
// calls this) names no image, so nothing is prefetched.
func chooseBackendImageFor(backend string, spec BackendSpec, override, target string, f GPUFacts) (backendImageChoice, error) {
	cpuImage, why, err := wantsCPUImage(backend, spec, target, f)
	if err != nil {
		return backendImageChoice{}, err
	}
	ch, err := chooseBackendImagePolicy(backend, spec, override, cpuImage)
	ch.Why = why
	return ch, err
}

func chooseBackendImagePolicy(backend string, spec BackendSpec, override string, cpuImage bool) (backendImageChoice, error) {
	ref := pickBackendImage(spec, override, cpuImage)
	// Nothing named an image: the default is OUR hardened build from this
	// node's release (an image of ours, rail-only). There is NO upstream
	// fallback: if ours is not staged for this arch the start is refused,
	// loudly, with the restage command (ImageNotStagedError).
	if override == "" {
		if ours := hardenedDefault(backend, cpuImage); ours != "" {
			return backendImageChoice{Ref: ours, RailOnly: true}, nil
		}
	}
	if ref == "" || isOwnImage(ref) {
		// Until this cut an own ref kept its digest, so the node asked the
		// rail for a tar named after it, which never exists, and refused a
		// staged image (node-b, node-pi: ollama, 0.6.17 and 0.6.18).
		tagRef, digest := splitDigest(ref)
		return backendImageChoice{Ref: tagRef, Pin: digest, RailOnly: ref != ""}, nil
	}
	if isFloatingRef(ref) {
		return backendImageChoice{}, fmt.Errorf(
			"backend %s: refusing the floating image %q (no tag or :latest): it can change under the node with no check. "+
				"The controller sends a digest-pinned ref from the signed stack lock - run `noo upgrade --stack` on the controller; "+
				"a hand-set VLLM_IMAGE / placement image must name a version and a digest", backend, ref)
	}
	tagRef, digest := splitDigest(ref)
	if digest != "" {
		return backendImageChoice{Ref: tagRef, RailOnly: true}, nil
	}
	// No digest: the rail's manifest vouches for the staged tar, or the
	// start is refused ("not staged on the controller") with the command.
	return backendImageChoice{Ref: ref, RailOnly: true}, nil
}

// railOnlyKey marks a context whose image fetch must not reach a registry.
type railOnlyKey struct{}

func withRailOnly(ctx context.Context, on bool) context.Context {
	if !on {
		return ctx
	}
	return context.WithValue(ctx, railOnlyKey{}, true)
}

func isRailOnly(ctx context.Context) bool {
	v, _ := ctx.Value(railOnlyKey{}).(bool)
	return v
}
