// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// The 0.6.20 tester's node: a pinned ollama failed to start because its
// stunnel door was resolved under OLLAMA's pin (#837). Each image is held to
// its own digest; the backend's never reaches the door.

const (
	releaseStunnel = "ghcr.io/noomesh/stunnel:v0.6.20"
	stunnelDigest  = "sha256:68ac017b00000000000000000000000000000000000000000000000000000000"
	doorDigest     = "sha256:d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
)

func releaseStunnelEnv(t *testing.T) {
	t.Helper()
	clearImageEnv(t)
	t.Setenv(StunnelImageEnv, "")
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v0.6.20")
}

func pinOllamaDoor(t *testing.T) string {
	t.Helper()
	prev := doorPins
	t.Cleanup(func() { doorPins = prev })
	doorPins = map[string]doorImagePin{"ollama": {Image: "stunnel", Tag: "v0.6.13", Digest: doorDigest}}
	return pinnedDoorFetchRef("ollama")
}

// The backend's pin never reaches the sidecar resolve: a release-following
// door is resolved with no pin at all.
func TestTheBackendPinNeverReachesTheSidecarResolve(t *testing.T) {
	releaseStunnelEnv(t)
	seen := map[string]string{}
	prev := ensureImageFn
	ensureImageFn = func(ctx context.Context, _ *Client, ref string) error {
		seen[ref] = imagePin(ctx)
		return nil
	}
	t.Cleanup(func() { ensureImageFn = prev })
	img, err := (&Client{}).ensureSidecarImage(withImagePin(context.Background(), thePin), "ollama")
	if err != nil || img != releaseStunnel {
		t.Fatalf("sidecar = %q, %v; want %s", img, err, releaseStunnel)
	}
	pin, asked := seen[releaseStunnel]
	if !asked {
		t.Fatalf("the door was never resolved: %v", seen)
	}
	if pin != "" {
		t.Fatalf("the door was resolved under pin %q; the backend's pin must never reach it", pin)
	}
}

// A pinned door is resolved under ITS OWN digest, even when the backend has
// a different pin.
func TestAPinnedDoorIsResolvedUnderItsOwnDigest(t *testing.T) {
	releaseStunnelEnv(t)
	doorRef := pinOllamaDoor(t)
	seen := map[string]string{}
	prev := ensureImageFn
	ensureImageFn = func(ctx context.Context, _ *Client, ref string) error {
		seen[ref] = imagePin(ctx)
		return nil
	}
	t.Cleanup(func() { ensureImageFn = prev })
	img, err := (&Client{}).ensureSidecarImage(withImagePin(context.Background(), thePin), "ollama")
	if err != nil || img != doorRef {
		t.Fatalf("sidecar = %q, %v; want %s", img, err, doorRef)
	}
	if got := seen[doorRef]; got != doorDigest {
		t.Fatalf("the pinned door was resolved under %q, want its own digest %s", got, doorDigest)
	}
}

func stagedPair(stunnelRef, stunnelLock string) map[string]*artifactManifest {
	return map[string]*artifactManifest{
		ImageTarName(pinnedOllama, runtime.GOARCH): {SHA256: strings.Repeat("b", 64), ImageID: "sha256:ollama-staged", LockDigest: thePin},
		ImageTarName(stunnelRef, runtime.GOARCH):   {SHA256: strings.Repeat("c", 64), ImageID: "sha256:stunnel-staged", LockDigest: stunnelLock},
	}
}

// The tester's case: a pinned backend and a release stunnel staged by its own
// (different) digest both start, each checked against its own digest.
func TestAPinnedBackendAndItsDoorStartEachUnderItsOwnDigest(t *testing.T) {
	t.Run("release door", func(t *testing.T) {
		releaseStunnelEnv(t)
		f := &fakeImageRail{local: map[string]string{}, staged: stagedPair(releaseStunnel, stunnelDigest)}
		f.install(t)
		ctx := pinnedCtx()
		if err := (&Client{}).EnsureImage(ctx, pinnedOllama); err != nil {
			t.Fatalf("backend: %v", err)
		}
		img, err := (&Client{}).ensureSidecarImage(ctx, "ollama")
		if err != nil || img != releaseStunnel {
			t.Fatalf("door = %q, %v", img, err)
		}
	})
	t.Run("pinned door", func(t *testing.T) {
		releaseStunnelEnv(t)
		doorRef := pinOllamaDoor(t)
		f := &fakeImageRail{local: map[string]string{}, staged: stagedPair(doorRef, doorDigest)}
		f.install(t)
		ctx := pinnedCtx()
		if err := (&Client{}).EnsureImage(ctx, pinnedOllama); err != nil {
			t.Fatalf("backend: %v", err)
		}
		img, err := (&Client{}).ensureSidecarImage(ctx, "ollama")
		if err != nil || img != doorRef {
			t.Fatalf("door = %q, %v", img, err)
		}
	})
}

// A pinned door whose tar the controller staged by another digest is still
// refused, and the refusal says what is actually wrong (finding 109): not
// "restage", which cannot fix it.
func TestAPinnedDoorStagedByTheWrongDigestIsRefused(t *testing.T) {
	releaseStunnelEnv(t)
	doorRef := pinOllamaDoor(t)
	f := &fakeImageRail{local: map[string]string{doorRef: "sha256:stunnel-staged"}, staged: stagedPair(doorRef, otherPin)}
	f.install(t)
	_, err := (&Client{}).ensureSidecarImage(pinnedCtx(), "ollama")
	if err == nil {
		t.Fatal("a door staged under another digest started")
	}
	for _, w := range []string{"ollama", doorDigest, otherPin, "different releases", "noo upgrade --all"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q: %v", w, err)
		}
	}
	if strings.Contains(err.Error(), "sync-images --stage-only") {
		t.Errorf("refusal points at a restage that cannot fix it: %v", err)
	}
	if len(f.railPulls) != 0 {
		t.Errorf("nothing is pulled for a refused door: %v", f.railPulls)
	}
}

// The door's pin belongs to the door's own ref: an operator's STUNNEL_IMAGE,
// tried first, is resolved unpinned, not under the door's digest.
func TestTheDoorPinAppliesOnlyToTheDoorRef(t *testing.T) {
	releaseStunnelEnv(t)
	doorRef := pinOllamaDoor(t)
	const own = "registry.local/stunnel:mine"
	t.Setenv(StunnelImageEnv, own)
	seen := map[string]string{}
	prev := ensureImageFn
	ensureImageFn = func(ctx context.Context, _ *Client, ref string) error {
		seen[ref] = imagePin(ctx)
		return nil
	}
	t.Cleanup(func() { ensureImageFn = prev })
	img, err := (&Client{}).ensureSidecarImage(withImagePin(context.Background(), thePin), "ollama")
	if err != nil || img != own {
		t.Fatalf("sidecar = %q, %v; want %s", img, err, own)
	}
	if got := seen[own]; got != "" {
		t.Fatalf("STUNNEL_IMAGE was resolved under pin %q; only %s carries the door's pin", got, doorRef)
	}
}

// The tester's case end to end: a pinned backend and the release stunnel,
// staged by its own (different) digest, both start. The backend is still
// held to its pin.
func TestAPinnedBackendAndTheReleaseStunnelBothStart(t *testing.T) {
	releaseStunnelEnv(t)
	f := &fakeImageRail{local: map[string]string{}, staged: map[string]*artifactManifest{
		ImageTarName(pinnedOllama, runtime.GOARCH):   {SHA256: strings.Repeat("b", 64), ImageID: "sha256:ollama-staged", LockDigest: thePin},
		ImageTarName(releaseStunnel, runtime.GOARCH): {SHA256: strings.Repeat("c", 64), ImageID: "sha256:stunnel-staged", LockDigest: stunnelDigest},
	}}
	f.install(t)
	ctx := pinnedCtx()
	if err := (&Client{}).EnsureImage(ctx, pinnedOllama); err != nil {
		t.Fatalf("backend: %v", err)
	}
	img, err := (&Client{}).ensureSidecarImage(ctx, "ollama")
	if err != nil || img != releaseStunnel {
		t.Fatalf("door = %q, %v", img, err)
	}
	if got := sourceOf(t, releaseStunnel); got == "" {
		t.Errorf("the door was not recorded as resolved")
	}
	// The backend is still pin-checked: the same context refuses an ollama
	// staged by another digest.
	f.staged[ImageTarName(pinnedOllama, runtime.GOARCH)].LockDigest = otherPin
	delete(f.local, pinnedOllama)
	if err := (&Client{}).EnsureImage(ctx, pinnedOllama); !IsImagePin(err) {
		t.Fatalf("the backend lost its pin check: %v", err)
	}
}
