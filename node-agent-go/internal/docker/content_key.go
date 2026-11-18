// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
)

// ContentKey is an image ref's CONTENT identity, for the backend spec hash
// (reconcile specHash): what the container runs, not what the release
// called it. Releases re-tag the daily-staged images; the 0.6.24, 0.6.25 and
// 0.6.26 locks pin the same ollama, llamacpp, stunnel and vllm digests, yet
// every roll recreated every backend on one of our tagged images twice
// (noomesh-internal proposal i935): once for the gateway's new tag, once for
// the agent's own sidecar tag.
//
//   - A digest-pinned ref (`repo:tag@sha256:D`): `repo@sha256:D`. Pure.
//   - A tag-only ref (the agent-derived door sidecar, a release-derived
//     backend image): `repo@<lock digest>` from the CONTROLLER's manifest for
//     that tag (the route resolvePinnedImage trusts), cached per ref for the
//     process. Never from the local image's own metadata: a node's local
//     store is not a source of truth for what the release pinned.
//   - The controller has no manifest for it, or an older gateway states no
//     lock digest: the ref itself (the tag), today's behaviour.
//   - The manifest route could not be asked (transport, auth): known=false.
//     The caller makes no drift decision on an unknown key.
//
// It never weakens the pin path: a container is still created only through
// EnsureImage / resolvePinnedImage, which hold the image to the pin.
func ContentKey(ctx context.Context, ref string) (key string, known bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", true
	}
	if i := strings.Index(ref, "@sha256:"); i >= 0 {
		return imageRepo(ref[:i]) + ref[i:], true
	}
	if v, ok := contentKeys.Load(ref); ok {
		return v.(string), true
	}
	m, _, err := contentManifestFetch(ctx, ref, runtime.GOARCH)
	switch {
	case err == nil && m != nil && pinDigestRe.MatchString(m.LockDigest):
		key = imageRepo(ref) + "@" + m.LockDigest
	case err == nil || errors.Is(err, ErrArtifactAbsent):
		// No manifest, or one that states no (or no well-formed) lock
		// digest: the tag, as before. Not cached, so a later staging is
		// seen on the next tick.
		return ref, true
	default:
		return "", false
	}
	contentKeys.Store(ref, key)
	return key, true
}

// contentKeys caches a tag ref's content key once the controller vouched it.
var contentKeys sync.Map // ref -> "repo@sha256:..."

// contentManifestFetch is the controller manifest lookup ContentKey uses: a
// seam for tests, the same lookup the pin path trusts.
var contentManifestFetch = fetchImageManifest

// imageRepo is a ref without its tag or digest: `ghcr.io/noomesh/ollama` for
// `ghcr.io/noomesh/ollama:v0.6.26@sha256:...`. A colon before the last `/`
// is a registry port, not a tag.
func imageRepo(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if c := strings.LastIndex(ref, ":"); c > slash {
		ref = ref[:c]
	}
	return ref
}

// resetContentKeys forgets the cache. Tests only.
func resetContentKeys() { contentKeys = sync.Map{} }
