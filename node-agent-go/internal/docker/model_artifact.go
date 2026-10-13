// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// ModelsDir is where this node keeps flat GGUF weights — the same path the
// backend specs bind-mount at /models (backends.go:204), resolved the same
// way so a fetched file lands where the runtime will look for it.
func ModelsDir() string {
	if d := os.Getenv("MODELS_DIR"); d != "" {
		return d
	}
	root := os.Getenv("NOO_DATA_ROOT")
	if root == "" {
		root = dataroots.DefaultDataRoot
	}
	return filepath.Join(root, "models")
}

// PullModelArtifactResult reports what a fetch did. `up_to_date` is a real
// outcome, not a failure: the file was already present with the right digest.
type PullModelArtifactResult struct {
	Status string `json:"status"`
	Model  string `json:"model"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
}

// PullModelArtifact fetches one flat GGUF from the controller's model store
// and verifies it against the artifact manifest.
//
// This is what replaced `noo cluster sync-model-files`, which scp'd weights
// from the controller over SSH. Nothing new was built for it: the control
// plane (`GET /api/artifacts/manifest/gguf/{name}`, size + sha256) and the
// data plane (the model cache, mTLS on :8443) both already existed for images and
// binaries, and `preseed.FetchOneVerified` was already generic. Only a
// caller for kind=gguf was missing.
//
// Why weights do not ride the bundle rail: a CMS-encrypted spool blob is the
// right shape for a small signed payload, not for 15 GB. So the bundle rail
// carries config and certs, and this carries bytes — with the manifest, not
// the transport, stating what the bytes should be.
//
// Idempotent by construction. FetchOneVerified hashes an existing file first
// and returns without downloading when it already matches, so re-running
// this across a fleet costs one hash per node rather than one transfer.
func (c *Client) PullModelArtifact(ctx context.Context, name string) (*PullModelArtifactResult, error) {
	// A model name is a bare filename in a flat store. Reject anything that
	// could climb out of it — this string arrives from a dispatched job and
	// is about to become a path.
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid model name %q — expected a bare filename in the flat store", name)
	}

	cacheURL := preseed.CacheURL()
	if cacheURL == "" {
		return nil, fmt.Errorf("NOO_MODEL_CACHE_URL is not set — no data plane to pull from")
	}

	// No manifest, no fetch. An unverified multi-GB download is worse than
	// none: it looks like success and the runtime loads whatever arrived.
	//
	// The reason matters: "the store does not have it" sends the operator to
	// copy a file that is already there. On 2026-10-10 a 3.3 GB GGUF on an
	// NFS store took the controller 13.5 s to hash, the old 15 s request
	// budget ran out, and the job said exactly that.
	m, err := awaitArtifactManifest(ctx, "gguf", name)
	if err != nil {
		return nil, modelManifestError(name, err)
	}
	sha := m.SHA256

	dir := ModelsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("models dir %s: %w", dir, err)
	}
	dest := filepath.Join(dir, name)
	src := cacheURL + "/gguf/" + url.PathEscape(name) // nginx serves MODELS_DIR at /gguf/, there is no /models/

	slog.Info("pulling model artifact", "model", name, "sha256", sha[:12]+"…", "dest", dest)
	// Generous: a 15 GB GGUF over a home LAN is not fast, and a timeout that
	// kills a nearly-complete transfer wastes the whole thing.
	fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	fetched, err := preseed.New().FetchOneVerified(fetchCtx, src, dest, sha)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	status := "up_to_date"
	if fetched {
		status = "downloaded"
	}
	return &PullModelArtifactResult{Status: status, Model: name, SHA256: sha, Path: dest}, nil
}

// modelManifestError words a manifest failure by its cause. Only the
// store's own answer (ErrArtifactAbsent) is "the store does not have it".
func modelManifestError(name string, err error) error {
	switch {
	case errors.Is(err, ErrArtifactAbsent):
		return fmt.Errorf(
			"no artifact manifest for %s — the controller's GGUF store does not have it; "+
				"put it there with `noo models fetch` or check `ls` on the controller's model dir", name)
	case errors.Is(err, ErrArtifactManifestTimeout):
		return fmt.Errorf(
			"timed out asking the controller for the manifest of %s (%v) — the store may still be "+
				"hashing a large file; the job retries", name, err)
	default:
		return fmt.Errorf("could not get the artifact manifest for %s: %w", name, err)
	}
}
