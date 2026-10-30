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
//     images (the registry roots and the local build names, which exist in no
//     registry and cannot carry a digest) are exempt: they are rail-only.
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
	Ref      string // the image to ensure and run
	RailOnly bool   // never from a registry (a rail node)
	// Fallback is the upstream image to use INSTEAD only when Ref (our
	// hardened default) is neither local nor staged (ensureImageWithFallback).
	// "" for an explicit image: a named image never silently becomes another.
	Fallback string
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
	// Nothing named an image: the default is OUR hardened build from this
	// node's release (an image of ours, rail-only), with the upstream image
	// as the not-staged fallback (ensureImageWithFallback).
	if override == "" {
		if ours, up := hardenedDefault(backend); ours != "" {
			return backendImageChoice{Ref: ours, RailOnly: true, Fallback: up}, nil
		}
	}
	if ref == "" || isOwnImage(ref) {
		return backendImageChoice{Ref: ref, RailOnly: ref != ""}, nil
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
