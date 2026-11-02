// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The hardened Ollama image (docker/Dockerfile.ollama) runs as uid/gid 65532
// with HOME=/home/nonroot, so its store is /home/nonroot/.ollama. The store on
// the host is the SAME directory the upstream image used at /root/.ollama
// (OLLAMA_DATA_DIR), mounted at the new path: no model moves, and the default
// OLLAMA_MODELS (<store>/models) finds them. The upstream image (the
// not-staged fallback, or an operator's own) keeps /root/.ollama and root.
const (
	ollamaUpstreamStore = "/root/.ollama"
	ollamaOursStore     = "/home/nonroot/.ollama"
	ollamaStoreUID      = 65532
)

// ollamaStoreFor points the ollama store mount at the path the chosen image
// expects, and reports whether that image is ours (non-root). The spec's
// volumes are copied, never mutated in place.
func ollamaStoreFor(spec BackendSpec, image string) (BackendSpec, bool) {
	ours := isOwnImage(image)
	if !ours {
		return spec, false
	}
	vols := make([]VolumeMount, len(spec.Volumes))
	copy(vols, spec.Volumes)
	for i := range vols {
		if vols[i].Target == ollamaUpstreamStore {
			vols[i].Target = ollamaOursStore
		}
	}
	spec.Volumes = vols
	return spec, true
}

// Seams for tests: the ownership probe and the root helper that re-owns.
var (
	ollamaOwnerUID = func(path string) (uid int, exists bool) {
		st, err := os.Stat(path)
		if err != nil {
			return 0, false
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, false
		}
		return int(sys.Uid), true
	}
	ollamaReownRun = func(ctx context.Context, c *Client, dir string) (int, string, error) {
		// A throwaway root container (runHelperScript: no User, the node-agent
		// image's alpine shell) with the store bind-mounted. chown only:
		// nothing is deleted or moved.
		script := fmt.Sprintf(`chown -R %d:%d /own`, ollamaStoreUID, ollamaStoreUID)
		return c.runHelperScript(ctx, []string{dir + ":/own"}, script, nil, 30*time.Minute)
	}
)

// ollamaListDir lists a directory's direct children (full paths); a seam.
var ollamaListDir = func(path string) []string {
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, filepath.Join(path, e.Name()))
	}
	return out
}

// ollamaStoreNeedsReown: anything the probe sees in the store is not owned by
// the non-root uid. It checks the store, models, models/blobs and
// models/manifests, AND the direct children of blobs (flat) and manifests
// (first level of the tree): the upstream fallback runs as root over this same
// store and leaves root-owned files under parents that stay 65532, which the
// non-root image could not delete or replace (`ollama rm`, a layer re-pull).
// A fresh or empty store is left alone.
func ollamaStoreNeedsReown(dir string) bool {
	models := filepath.Join(dir, "models")
	blobs, manifests := filepath.Join(models, "blobs"), filepath.Join(models, "manifests")
	paths := []string{dir, models, blobs, manifests}
	paths = append(paths, ollamaListDir(blobs)...)
	paths = append(paths, ollamaListDir(manifests)...)
	for _, p := range paths {
		if uid, ok := ollamaOwnerUID(p); ok && uid != ollamaStoreUID {
			return true
		}
	}
	return false
}

// ensureOllamaStoreOwned hands an existing root-owned Ollama store to the
// non-root uid ONCE, before the hardened image first starts on it. Idempotent
// (an owned store costs two stats), logged, and it only ever chowns: models
// are never deleted or moved. A failure refuses the start, naming the command:
// the non-root container could not write its own store.
func (c *Client) ensureOllamaStoreOwned(ctx context.Context, dir string) error {
	if dir == "" || !ollamaStoreNeedsReown(dir) {
		return nil
	}
	slog.Info("ollama store is not owned by the hardened image's uid; re-owning it once (chown only, no models touched)",
		"dir", dir, "uid", ollamaStoreUID)
	code, out, err := ollamaReownRun(ctx, c, dir)
	if err != nil {
		return fmt.Errorf("re-own the ollama store %s for the non-root image: %w (or run: sudo chown -R %d:%d %s)",
			dir, err, ollamaStoreUID, ollamaStoreUID, dir)
	}
	if code != 0 {
		return fmt.Errorf("re-own the ollama store %s for the non-root image: exit %d: %s (or run: sudo chown -R %d:%d %s)",
			dir, code, out, ollamaStoreUID, ollamaStoreUID, dir)
	}
	return nil
}
