// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/distribution/reference"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
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
//     images (the registry roots and the local build names, which exist in no
//     registry and cannot carry a digest) are exempt: they are rail-only.
//   - on a DIST node (NOO_IMAGE_SOURCE=rail, or NOO_IMAGE_PREFIX set) a
//     third-party ref must carry `@sha256:`. A ref without one is accepted
//     only when the rail vouches for it (NOO_IMAGE_SOURCE=rail: the tar the
//     controller staged is verified against the gateway's manifest before
//     `docker load`, which is as strong as a digest); otherwise it is refused
//     with the fix. That is the OLD-controller answer: a controller that
//     sends no ref leaves the node on its own versioned default, which a
//     rail node may run (if the controller staged it) and a registry node
//     refuses, naming the controller roll that fixes it.
//   - on a rail node the digest is stripped before the container is made and
//     the registry is forbidden: the rail's tar is keyed by the tag ref, and
//     the image is the one the manifest names. A registry node pulls the
//     digest ref itself.

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

// isDistNode: this node takes images from the controller (the rail) or from
// a release prefix, as opposed to a hand-run dev node.
func isDistNode() bool {
	return imageSourceMode() == imagesource.ModeRail || strings.TrimSpace(os.Getenv("NOO_IMAGE_PREFIX")) != ""
}

// backendImageChoice is the ref to use and how it may be fetched.
type backendImageChoice struct {
	Ref      string // the image to ensure and run
	RailOnly bool   // never from a registry (a rail node)
}

// pickBackendImage is the pure part of the choice: CPU/GPU image, then the
// controller's override or ${VAR} substitution. No policy.
func pickBackendImage(spec BackendSpec, override string) string {
	if spec.CPUImage != "" && !hasNvidiaGPU() {
		spec.Image = spec.CPUImage
	}
	if override != "" {
		return override
	}
	return resolveEnv(spec.Image)
}

// chooseBackendImage picks the backend's image and applies the policy above.
// override is StartOverrides.Image (the controller's / the placement's).
func chooseBackendImage(backend string, spec BackendSpec, override string) (backendImageChoice, error) {
	ref := pickBackendImage(spec, override)
	if ref == "" || isOwnImage(ref) {
		return backendImageChoice{Ref: ref, RailOnly: ref != "" && imageSourceMode() == imagesource.ModeRail}, nil
	}
	if isFloatingRef(ref) {
		return backendImageChoice{}, fmt.Errorf(
			"backend %s: refusing the floating image %q (no tag or :latest): it can change under the node with no check. "+
				"The controller sends a digest-pinned ref from the signed stack lock - run `noo upgrade --stack` on the controller; "+
				"a hand-set VLLM_IMAGE / placement image must name a version and a digest", backend, ref)
	}
	tagRef, digest := splitDigest(ref)
	rail := imageSourceMode() == imagesource.ModeRail
	switch {
	case digest != "" && rail:
		return backendImageChoice{Ref: tagRef, RailOnly: true}, nil
	case digest != "":
		return backendImageChoice{Ref: ref}, nil
	case rail:
		// No digest: the rail's manifest vouches for the staged tar, or the
		// start is refused ("not staged on the controller") with the command.
		return backendImageChoice{Ref: ref, RailOnly: true}, nil
	case isDistNode() || override != "":
		return backendImageChoice{}, fmt.Errorf(
			"backend %s: refusing image %q: it has no @sha256 digest, and this node runs only digest-pinned images. "+
				"The controller sends the digest from the signed stack lock - the controller is too old or its lock predates it: "+
				"run `noo upgrade --stack` on the controller. To let this node take the controller's staged image instead, "+
				"set NOO_IMAGE_SOURCE=rail (the rail verifies the tar against the controller's manifest)", backend, ref)
	}
	return backendImageChoice{Ref: ref}, nil
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
