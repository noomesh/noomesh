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
	// State is "unverified", or "verifying" while the local file is being
	// hashed against the controller's manifest (VerifyingSince is when it
	// began).
	State          string `json:"state"`
	VerifyingSince string `json:"verifying_since,omitempty"`
	dir            string
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
		Since: now.UTC().Format(time.RFC3339), State: "unverified"}
	if prev, ok := unvouchedLive[backend]; ok && prev.Model == model {
		rec.Since = prev.Since
		rec.State, rec.VerifyingSince = prev.State, prev.VerifyingSince
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
	currentHash = nil
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
// file hash; variables so a test supplies both. reverifyHashTimeout bounds one
// hash (a test shortens it).
var (
	reverifyManifestFn = func(ctx context.Context, model string) (string, error) {
		m, err := lookupArtifactManifestWithin(ctx, "gguf", model, awaitManifestRequestTimeout)
		if err != nil {
			return "", err
		}
		return m.SHA256, nil
	}
	reverifyHashFn      = preseed.HashFileCtx
	reverifyHashTimeout = 30 * time.Minute
)

// hashRun is the one background hash a node runs at a time. It is owned by
// the registry (guarded by unvouchedMu); finished is closed when the
// goroutine has ended.
type hashRun struct {
	backend, model, path, want string
	done                       bool // sum is ready to be picked up
	sum                        string
	finished                   chan struct{}
}

var currentHash *hashRun

// unvouchedHashFinished is the running hash's end signal, nil when none. Tests.
func unvouchedHashFinished() <-chan struct{} {
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	if currentHash == nil {
		return nil
	}
	return currentHash.finished
}

// ReverifyUnvouchedGGUF is one reconcile pass's step for the backend's
// unvouched GGUF. It never waits on a hash:
//   - a finished hash is picked up: a match clears the record, a mismatch
//     clears it and returns a *GGUFReverifyMismatchError for the caller to
//     stop the backend and refuse;
//   - a running hash is left alone (the record reads "verifying");
//   - otherwise the controller's manifest is asked once (a 202 or a failure
//     keeps the record, with the reason), and when it answers a background
//     hash of the local file starts, at most one at a time on the node. The
//     hash's context derives from ctx (the agent's lifetime) and is bounded by
//     reverifyHashTimeout; an errored or cancelled hash returns the record to
//     "unverified" with the reason and a later pass tries again.
func ReverifyUnvouchedGGUF(ctx context.Context, backend, model string) *GGUFReverifyMismatchError {
	unvouchedMu.Lock()
	rec, ok := unvouchedLive[backend]
	if !ok {
		unvouchedMu.Unlock()
		return nil
	}
	if rec.Model != model {
		delete(unvouchedLive, backend) // the placement moved on; the next start decides afresh
		unvouchedMu.Unlock()
		return nil
	}
	if h := currentHash; h != nil {
		if h.backend != backend || !h.done {
			unvouchedMu.Unlock()
			return nil
		}
		currentHash = nil
		delete(unvouchedLive, backend)
		unvouchedMu.Unlock()
		if h.sum == h.want {
			slog.Info("verified against the controller's manifest", "backend", backend, "model", model, "sha256", h.want[:12]+"…")
			return nil
		}
		slog.Error("gguf refused: the file a backend started with does not match the controller's manifest",
			"backend", backend, "model", model, "path", h.path, "expected", h.want, "actual", h.sum)
		return &GGUFReverifyMismatchError{Backend: backend, Model: model, Path: h.path, Expected: h.want, Actual: h.sum}
	}
	unvouchedMu.Unlock()

	want, err := reverifyManifestFn(ctx, model)
	if err != nil {
		var h *hashingError
		if !errors.As(err, &h) {
			recordUnvouchedGGUF(backend, model, rec.dir, ggufManifestReason(model, err), time.Now())
		}
		return nil
	}
	path := filepath.Join(rec.dir, model)
	unvouchedMu.Lock()
	defer unvouchedMu.Unlock()
	if currentHash != nil { // another pass or backend started one meanwhile
		return nil
	}
	run := &hashRun{backend: backend, model: model, path: path, want: want, finished: make(chan struct{})}
	currentHash = run
	rec = unvouchedLive[backend]
	rec.State, rec.VerifyingSince = "verifying", time.Now().UTC().Format(time.RFC3339)
	unvouchedLive[backend] = rec
	hashFn := reverifyHashFn
	hctx, cancel := context.WithTimeout(ctx, reverifyHashTimeout)
	go func() {
		defer cancel()
		sum, herr := hashFn(hctx, path)
		unvouchedMu.Lock()
		defer unvouchedMu.Unlock()
		defer close(run.finished)
		if herr != nil {
			slog.Warn("gguf re-verify could not hash the local file; it stays unverified and is retried",
				"backend", backend, "model", model, "path", path, "error", herr)
			if currentHash == run {
				currentHash = nil
			}
			if r, ok := unvouchedLive[backend]; ok && r.Model == model {
				r.State, r.VerifyingSince = "unverified", ""
				r.Reason = "hashing the local file for verification did not finish: " + herr.Error()
				unvouchedLive[backend] = r
			}
			return
		}
		if r, ok := unvouchedLive[backend]; !ok || r.Model != model {
			// Cleared meanwhile (a verified start, or the placement moved on):
			// nothing waits for this result.
			if currentHash == run {
				currentHash = nil
			}
			return
		}
		run.sum, run.done = sum, true
	}()
	return nil
}
