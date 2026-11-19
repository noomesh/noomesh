// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

const (
	heldCUDA   = "reg.example/acme/llamacpp-cuda:v1"
	heldCPU    = "reg.example/acme/llamacpp:v1"
	heldOllama = "reg.example/acme/ollama:v1"
)

// stubInspect pins the release and answers each ref's inspect from a table
// (a ref not in it panics: the list must be the fixed one), counting calls.
func stubInspect(t *testing.T, answers map[string]error) *int {
	t.Helper()
	t.Setenv("NOO_IMAGE_PREFIX", "reg.example/acme")
	t.Setenv("NOO_IMAGE_TAG", "v1")
	for _, e := range []string{"LLAMACPP_CUDA_IMAGE", "LLAMACPP_IMAGE", "OLLAMA_IMAGE"} {
		t.Setenv(e, "")
	}
	prev := imageInspectErrFn
	calls := 0
	imageInspectErrFn = func(_ context.Context, _ *Client, ref string) error {
		calls++
		err, ok := answers[ref]
		if !ok {
			t.Fatalf("inspected %s, not one of the fixed refs", ref)
		}
		return err
	}
	invalidateHeldImages()
	heldImagesCache.mu.Lock()
	heldImagesCache.val = nil
	heldImagesCache.mu.Unlock()
	t.Cleanup(func() { imageInspectErrFn = prev; invalidateHeldImages() })
	return &calls
}

// A client with a docker handle that is never dialled (inspect is stubbed).
func heldClient(t *testing.T) *Client {
	t.Helper()
	dc, err := client.NewClientWithOpts(client.WithHost("unix:///nonexistent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	return &Client{docker: dc}
}

// i1036: present is true, the daemon's typed not-found is false, any other
// error leaves the ref out — including an error that merely SAYS "no such
// image" without the type.
func TestHeldImagesPresentNotFoundAndUnknown(t *testing.T) {
	stubInspect(t, map[string]error{
		heldCUDA:   cerrdefs.ErrNotFound.WithMessage("No such image: " + heldCUDA),
		heldCPU:    nil,
		heldOllama: errors.New("Error response from daemon: No such image: " + heldOllama),
	})
	got := heldClient(t).HeldImages(context.Background())
	if len(got) != 2 || got[heldCUDA] != false || got[heldCPU] != true {
		t.Fatalf("held_images = %v", got)
	}
	if _, ok := got[heldOllama]; ok {
		t.Fatalf("an untyped error was judged: %v", got)
	}
	// Wrapped, the type still reads.
	if held, known := heldFromInspect(fmt.Errorf("inspect: %w", cerrdefs.ErrNotFound)); held || !known {
		t.Fatalf("wrapped not-found: held=%v known=%v", held, known)
	}
}

// Docker unavailable (no client, or every inspect failing) omits the key;
// so does a node with no release pin (nothing of ours to judge).
func TestHeldImagesOmittedWhenDockerIsUnavailable(t *testing.T) {
	down := errors.New("Cannot connect to the Docker daemon")
	stubInspect(t, map[string]error{heldCUDA: down, heldCPU: down, heldOllama: down})
	if got := heldClient(t).HeldImages(context.Background()); got != nil {
		t.Fatalf("every inspect failed, sent %v", got)
	}
	// No docker client: omitted, even where an inspect would have answered.
	stubInspect(t, map[string]error{heldCUDA: nil, heldCPU: nil, heldOllama: nil})
	if got := (&Client{}).HeldImages(context.Background()); got != nil {
		t.Fatalf("no docker client, sent %v", got)
	}
	t.Setenv("NOO_IMAGE_TAG", "")
	if refs := heldImageRefs(); len(refs) != 0 {
		t.Fatalf("no release pin, refs %v", refs)
	}
}

// The list is fixed and the release's own: an override naming another
// image is not ours to report.
func TestHeldImageRefsAreTheReleasesOwn(t *testing.T) {
	stubInspect(t, map[string]error{})
	if refs := heldImageRefs(); fmt.Sprint(refs) != fmt.Sprint([]string{heldCUDA, heldCPU, heldOllama}) {
		t.Fatalf("refs = %v", refs)
	}
	t.Setenv("LLAMACPP_CUDA_IMAGE", "ghcr.io/ggml-org/llama.cpp:server-cuda")
	if refs := heldImageRefs(); fmt.Sprint(refs) != fmt.Sprint([]string{heldCPU, heldOllama}) {
		t.Fatalf("an upstream override was reported: %v", refs)
	}
}

// A known answer is reused for heldImagesTTL; a load drops it.
func TestHeldImagesAreCachedUntilALoad(t *testing.T) {
	calls := stubInspect(t, map[string]error{heldCUDA: cerrdefs.ErrNotFound, heldCPU: nil, heldOllama: nil})
	c := heldClient(t)
	c.HeldImages(context.Background())
	c.HeldImages(context.Background())
	if *calls != 3 {
		t.Fatalf("second beat re-inspected: %d inspects, want 3", *calls)
	}
	invalidateHeldImages()
	c.HeldImages(context.Background())
	if *calls != 6 {
		t.Fatalf("after a load: %d inspects, want 6", *calls)
	}
}
