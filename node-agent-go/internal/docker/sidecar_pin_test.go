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
// stunnel door was resolved under OLLAMA's pin (#837). The backend's pin
// never reaches the door; the door resolves as it did before #837.

const (
	releaseStunnel = "ghcr.io/noomesh/stunnel:v0.6.20"
	stunnelDigest  = "sha256:68ac017b00000000000000000000000000000000000000000000000000000000"
)

func releaseStunnelEnv(t *testing.T) {
	t.Helper()
	clearImageEnv(t)
	t.Setenv(StunnelImageEnv, "")
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v0.6.20")
}

// The backend's pin never reaches the sidecar resolve.
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
