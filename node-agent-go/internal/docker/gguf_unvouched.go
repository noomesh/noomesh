// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// UnvouchedGGUF is one GGUF backend started with the file already on the node
// and without the controller's manifest to check it against. It is reported on
// the heartbeat as `gguf_unverified` and re-verified on each reconcile pass
// until the controller answers.
type UnvouchedGGUF struct {
	Backend string `json:"backend"`
	Model   string `json:"model"`
	Reason  string `json:"reason"`
	Since   string `json:"since"`
	dir     string
}

var (
	unvouchedMu   sync.Mutex
	unvouchedLive = map[string]UnvouchedGGUF{}
)

// recordUnvouchedGGUF notes that backend started with model's local file and
// no manifest. A repeat for the same model keeps the original Since and takes
// the newest reason.
func recordUnvouchedGGUF(backend, model, dir, reason string, now time.Time) {
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	rec := UnvouchedGGUF{Backend: backend, Model: model, Reason: reason, dir: dir,
		Since: now.UTC().Format(time.RFC3339)}
	if prev, ok := unvouchedLive[backend]; ok && prev.Model == model {
		rec.Since = prev.Since
	}
	unvouchedLive[backend] = rec
}

func clearUnvouchedGGUF(backend string) {
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	delete(unvouchedLive, backend)
}

// UnvouchedGGUFReport is the heartbeat's `gguf_unverified` provider: the
// backends running on a file the controller has not vouched for, sorted. nil
// when there are none, so the key is omitted.
func UnvouchedGGUFReport() any {
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	if len(unvouchedLive) == 0 {
		return nil
	}
	out := make([]UnvouchedGGUF, 0, len(unvouchedLive))
	for _, v := range unvouchedLive {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// ResetUnvouchedGGUF drops every record. Tests only.
func ResetUnvouchedGGUF() {
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	unvouchedLive = map[string]UnvouchedGGUF{}
}

// GGUFReverifyMismatchError: the local file a backend started with does not
// hash to the controller's manifest. The backend is stopped and the start is
// refused; the next start takes the normal path (a verified copy, or the
// refusal).
type GGUFReverifyMismatchError struct {
	Backend, Model, Path, Expected, Actual string
}

func (e *GGUFReverifyMismatchError) Error() string {
	return fmt.Sprintf("gguf_mismatch: %s started with %s (%s), but its sha256 is %s and the controller's manifest says %s; "+
		"the backend is stopped, and the next start fetches the verified copy from the controller's store",
		e.Backend, e.Model, e.Path, e.Actual, e.Expected)
}

// reverifyManifestFn and reverifyHashFn are the controller's answer and the
// file hash; variables so a test supplies both.
var (
	reverifyManifestFn = func(ctx context.Context, model string) (string, error) {
		m, err := lookupArtifactManifestWithin(ctx, "gguf", model, awaitManifestRequestTimeout)
		if err != nil {
			return "", err
		}
		return m.SHA256, nil
	}
	reverifyHashFn = preseed.HashFile
)

// ReverifyUnvouchedGGUF asks the controller's manifest once for the backend's
// unvouched GGUF (a 202 or any failure leaves it recorded for the next pass).
// On a manifest it hashes the local file: a match clears the record; a
// mismatch clears it and returns a *GGUFReverifyMismatchError for the caller
// to stop the backend and refuse. Nothing recorded for backend/model: (nil).
func ReverifyUnvouchedGGUF(ctx context.Context, backend, model string) *GGUFReverifyMismatchError {
	unvouchedMu.Lock()
	rec, ok := unvouchedLive[backend]
	unvouchedMu.Unlock()
	if !ok {
		return nil
	}
	if rec.Model != model {
		clearUnvouchedGGUF(backend) // the placement moved on; the next start decides afresh
		return nil
	}
	want, err := reverifyManifestFn(ctx, model)
	if err != nil {
		var h *hashingError
		if !errors.As(err, &h) {
			recordUnvouchedGGUF(backend, model, rec.dir, ggufManifestReason(model, err), time.Now())
		}
		return nil
	}
	path := filepath.Join(rec.dir, model)
	got, herr := reverifyHashFn(path)
	if herr != nil {
		slog.Warn("gguf re-verify could not hash the local file", "backend", backend, "model", model, "path", path, "error", herr)
		return nil
	}
	clearUnvouchedGGUF(backend)
	if got == want {
		slog.Info("verified against the controller's manifest", "backend", backend, "model", model, "sha256", want[:12]+"…")
		return nil
	}
	slog.Error("gguf refused: the file a backend started with does not match the controller's manifest",
		"backend", backend, "model", model, "path", path, "expected", want, "actual", got)
	return &GGUFReverifyMismatchError{Backend: backend, Model: model, Path: path, Expected: want, Actual: got}
}
