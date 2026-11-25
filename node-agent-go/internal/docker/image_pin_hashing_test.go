// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// i1167a: a roll hands out the pin before the new gateway has hashed the
// staged tar. The pinned start is a typed, retryable wait: not "not staged",
// not a plain refusal, and it names the tar and the wait.
func TestAPinnedImageWhileTheControllerIsHashingIsATypedRetryableWait(t *testing.T) {
	f := &fakeImageRail{
		local:       map[string]string{pinnedOllama: "sha256:running"},
		manifestErr: &hashingError{retryAfter: 7 * time.Second},
	}
	f.install(t)
	err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama)
	h, ok := AsImageHashing(err)
	if !ok {
		t.Fatalf("want an ImageHashingError, got %T %v", err, err)
	}
	if IsImageNotStaged(err) {
		t.Fatalf("hashing is not a missing tar: %v", err)
	}
	if h.RetryAfter != 7*time.Second || h.Tar == "" || h.Ref != pinnedOllama {
		t.Fatalf("got %+v", h)
	}
	want := "the controller is still hashing " + h.Tar + "; keeping the running image; retrying in 7s"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("text = %q, want it to contain %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "refusing to start") || strings.Contains(err.Error(), "sync-images") {
		t.Fatalf("a wait must not read as a refusal: %v", err)
	}
	if len(f.railPulls) != 0 || len(f.registryPull) != 0 {
		t.Fatalf("nothing is pulled while hashing: rail %v registry %v", f.railPulls, f.registryPull)
	}
}

// The wait running out inside the probe is the same wait.
func TestAPinnedImageWhoseManifestWaitTimedOutIsStillAHashingWait(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, manifestErr: ErrArtifactManifestTimeout}
	f.install(t)
	_, ok := AsImageHashing((&Client{}).EnsureImage(pinnedCtx(), pinnedOllama))
	if !ok {
		t.Fatal("a manifest timeout is the controller still hashing")
	}
}

// Anything else the manifest route says is still the fail-closed refusal.
func TestAPinnedImageWithAnotherManifestFailureIsNotAHashingWait(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, manifestErr: errors.New("connection refused")}
	f.install(t)
	err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama)
	if _, ok := AsImageHashing(err); ok {
		t.Fatalf("a refused connection is not a hashing wait: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "refusing to start an unverified image") {
		t.Fatalf("want the refusal as before, got %v", err)
	}
}

// The wait is raised by ensureImageFn, which runs before the old container
// is stopped or removed: the running image keeps serving.
func TestTheImageIsResolvedBeforeTheRunningContainerIsTouched(t *testing.T) {
	raw, err := os.ReadFile("backends.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	ensure := strings.Index(s, "ensureImageFn(ctx, c, img)")
	stop := strings.Index(s, "c.docker.ContainerStop(ctx, spec.ContainerName")
	remove := strings.Index(s, "c.docker.ContainerRemove(ctx, spec.ContainerName, client.ContainerRemoveOptions{Force: true})")
	if ensure < 0 || stop < 0 || remove < 0 || ensure > stop || ensure > remove {
		t.Fatalf("ensureImageFn must precede stop/remove (ensure=%d stop=%d remove=%d)", ensure, stop, remove)
	}
}
