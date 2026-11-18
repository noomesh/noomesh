// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// effectiveModelsDir is the directory StartBackend mounts at /models: the
// controller's models_dir when this node agreed to it, else the node's own
// env-resolved one (MODELS_DIR / NOO_DATA_ROOT / the default data root).
func effectiveModelsDir(t *tick) string {
	if t.modelsDir != "" {
		return t.modelsDir
	}
	return dockerpkg.ModelsDir()
}

// ggufPresent guards a start of a placed .gguf model: it reports whether the
// file is in the effective models dir. A missing file is not started (the
// container would crash-loop) and is a backend_start refusal that stands
// while the file is missing: clearBackendStart re-records it, so neither a
// container still running nor a later start that "succeeds" clears it. It is
// dropped here once the file is back; the start that follows clears the
// refusal the normal way. A check that cannot run lets the start go on.
func (r *Reconciler) ggufPresent(ctx context.Context, t *tick, p placement) bool {
	if !strings.HasSuffix(p.Model, ".gguf") {
		return true
	}
	dir := effectiveModelsDir(t)
	exists := r.ggufExists
	if exists == nil {
		if r.docker == nil {
			return true
		}
		exists = r.docker.HostFileExists
	}
	ok, err := exists(ctx, dir, p.Model)
	if err != nil {
		slog.Warn("reconcile.model_check_failed", "error", err)
		return true
	}
	if ok {
		delete(r.ggufMissing, p.Backend)
		return true
	}
	fix := "noo cluster sync-model-files " + r.cfg.NodeID + " -m " + p.Model
	reason := "model_missing: " + p.Model + " is not in " + dir + "; ship it: " + fix
	if aside := newestQuarantined(dir, p.Model); aside != "" {
		reason = "gguf_quarantined: " + p.Model + " was proven not to match the controller's record and moved aside to " +
			aside + "; ship the verified file: " + fix
	}
	slog.Error("reconcile.model_missing",
		"backend", p.Backend, "model", p.Model, "models_dir", dir, "reason", reason)
	if r.ggufMissing == nil {
		r.ggufMissing = map[string]string{}
	}
	r.ggufMissing[p.Backend] = reason
	refusals.Record("backend_start", p.Backend, reason)
	return false
}

// newestQuarantined returns the path of the newest `<model>.quarantined-<UTC
// stamp>` in dir (docker.ggufFetchOutcome's name; the stamp sorts by time),
// or "" when there is none or dir cannot be read.
func newestQuarantined(dir, model string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	newest := ""
	for _, e := range entries {
		if name := e.Name(); strings.HasPrefix(name, model+".quarantined-") && name > newest {
			newest = name
		}
	}
	if newest == "" {
		return ""
	}
	return filepath.Join(dir, newest)
}
