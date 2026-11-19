// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
)

// The heartbeat's `held_images` (i1036): for each of this release's OWN
// hardened backend images the agent may have to pull over the rail, whether
// Docker holds it right now — so the controller's GPU llama.cpp place check
// can tell "will pull ~2.6 GB" from "already here". A fixed list of at most
// heldImageBackends' length, one inspect each; never a full image list.

// heldImageBackends: the release images a placement makes this agent pull,
// each with the env that overrides it — the same pairs ReleaseBackendImage
// and hardenedDefault (backends.go) resolve.
var heldImageBackends = []struct{ env, name string }{
	{"LLAMACPP_CUDA_IMAGE", "llamacpp-cuda"},
	{"LLAMACPP_IMAGE", "llamacpp"},
	{"OLLAMA_IMAGE", "ollama"},
}

// heldImageRefs are the refs `held_images` reports: each backend's image as
// this agent resolves it, kept only when it is this release's own
// (NOO_IMAGE_PREFIX/…:NOO_IMAGE_TAG, ReleaseBackendImage's rule). None on a
// node with no release pin.
func heldImageRefs() []string {
	prefix, tag := os.Getenv("NOO_IMAGE_PREFIX"), os.Getenv("NOO_IMAGE_TAG")
	if prefix == "" || tag == "" {
		return nil
	}
	var out []string
	for _, b := range heldImageBackends {
		img := envOr(b.env, releaseImage(b.name))
		if strings.HasPrefix(img, prefix+"/") && strings.HasSuffix(img, ":"+tag) {
			out = append(out, img)
		}
	}
	return out
}

// heldFromInspect reads one `docker image inspect`: present (held), the
// daemon's typed not-found (not held), or anything else (unknown, so the
// ref is left out). Never the error's wording.
func heldFromInspect(err error) (held, known bool) {
	switch {
	case err == nil:
		return true, true
	case cerrdefs.IsNotFound(err):
		return false, true
	default:
		return false, false
	}
}

// imageInspectErrFn inspects ref; a seam so held_images is testable without
// a daemon.
var imageInspectErrFn = func(ctx context.Context, c *Client, ref string) error {
	_, err := c.docker.ImageInspect(ctx, ref)
	return err
}

// heldImagesTTL: how long a `held_images` answer is reused. An image arrives
// through PullImageArtifact, which drops the cache; one removed by the
// reclaim shows up within this.
const heldImagesTTL = 10 * time.Minute

var heldImagesCache struct {
	mu  sync.Mutex
	at  time.Time
	val map[string]bool
}

// invalidateHeldImages makes the next beat re-inspect (after a load).
func invalidateHeldImages() {
	heldImagesCache.mu.Lock()
	heldImagesCache.at = time.Time{}
	heldImagesCache.mu.Unlock()
}

// HeldImages is the provider of the heartbeat's `held_images`: {ref: held}
// over heldImageRefs. nil (the key omitted) when Docker is unavailable or
// no ref could be judged; a known answer is reused for heldImagesTTL.
func (c *Client) HeldImages(ctx context.Context) map[string]bool {
	if c == nil || c.docker == nil {
		return nil
	}
	heldImagesCache.mu.Lock()
	defer heldImagesCache.mu.Unlock()
	if heldImagesCache.val != nil && time.Since(heldImagesCache.at) < heldImagesTTL {
		return heldImagesCache.val
	}
	out := map[string]bool{}
	for _, ref := range heldImageRefs() {
		ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
		held, known := heldFromInspect(imageInspectErrFn(ictx, c, ref))
		cancel()
		if known {
			out[ref] = held
		}
	}
	if len(out) == 0 {
		heldImagesCache.val = nil
		return nil
	}
	heldImagesCache.val, heldImagesCache.at = out, time.Now()
	return out
}
