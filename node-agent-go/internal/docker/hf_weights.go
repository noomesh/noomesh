// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// HF weights on a PLACED node: staged from the controller's store and
// started only on a snapshot whose every file is verified against the
// controller's `hf` artifact manifest (i675 F13).
//
// The order, and what each failure means:
//
//  1. Ask the gateway for the manifest (GET /api/artifacts/manifest/hf/
//     models--org--name), waiting out its 202 "hashing" answers.
//  2. Manifest in hand: mirror the snapshot from the model cache, each file
//     kept or landed only when it hashes to the manifest's sha256 (or the
//     verified-digest record vouches for that exact inode). Bytes that do
//     not match are REFUSED, never loaded. If the data plane cannot be
//     reached, the local copy is checked against the SAME manifest.
//  3. An older gateway (no `hf` kind): REFUSED with a message saying what
//     this node is waiting for — the controller's upgrade. Unless the local
//     copy matches the manifest this node last verified it against.
//  4. The store does not have the model (404): ModelNotStagedError.
//  5. The gateway refuses to vouch for its own copy (409: a blob whose bytes
//     do not match its HF oid): REFUSED with the gateway's reason.
//  6. The controller did not answer (timeout, TLS, 5xx): the local copy is
//     checked against the manifest this node last verified it against (kept
//     in the verified-digest record, outside every container mount); with
//     no such manifest, or on a mismatch, REFUSED.
//
// There is no "a snapshot directory exists, so start" path any more: the
// old hfRepoCachedLocally let a placed node start on whatever bytes its
// cache held. It is gone; the local fallback is VerifyHFRepoLocal.

// hfPreseedTimeout bounds one model's staging (verification and download).
// The first verification after an upgrade hashes the whole snapshot once,
// niced; 6.5 GB at even 150 MB/s is ~45 s, far inside this.
const hfPreseedTimeout = 15 * time.Minute

// hfManifestVersionFloor is the first stack release whose gateway serves the
// `hf` manifest kind.
const hfManifestVersionFloor = "0.6.25-rc.2"

// hfManifestFn asks the gateway for a repo's `hf` manifest. A seam for tests.
var hfManifestFn = awaitHFManifest

// awaitHFManifest is awaitArtifactManifest for the `hf` kind.
func awaitHFManifest(ctx context.Context, repoDir string) (*preseed.HFManifest, error) {
	return awaitManifest(ctx, awaitManifestBudget, func(ctx context.Context) (*preseed.HFManifest, error) {
		body, err := manifestRoundTrip(ctx, "hf", repoDir, awaitManifestRequestTimeout)
		if err != nil {
			return nil, err
		}
		return decodeHFManifest(body)
	})
}

// decodeHFManifest reads and validates an `hf` answer. A malformed one —
// a file with no digest included — is a refusal, not an absence.
func decodeHFManifest(body []byte) (*preseed.HFManifest, error) {
	var m preseed.HFManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: the hf manifest is not JSON: %v", ErrArtifactRefused, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArtifactRefused, err)
	}
	return &m, nil
}

// hfRecordPath is where this node's verified-digest record lives: the
// agent's own state dir, which no container mounts. A seam for tests.
var hfRecordPath = func() string {
	return filepath.Join(nodeconfig.Load().StateDir, "verified", "hf-weights.json")
}

// hfVerifiedRecord opens the record, refusing (disabling) it when it would
// sit under a directory a model container mounts.
func hfVerifiedRecord() *preseed.VerifiedRecord {
	return preseed.OpenVerifiedRecord(hfRecordPath(),
		resolveEnv(hfCacheSource), resolveEnv(modelsSource), resolveEnv(ollamaSource))
}

// HFWeightsRefusedError: a placed node will not start an HF backend because
// its weights could not be verified. Reason says why and what to do.
type HFWeightsRefusedError struct {
	Backend, Model, Reason string
	Err                    error
}

func (e *HFWeightsRefusedError) Error() string {
	return fmt.Sprintf("hf_weights_unverified: %s will not start %s: %s", e.Backend, e.Model, e.Reason)
}

func (e *HFWeightsRefusedError) Unwrap() error { return e.Err }

// hfGatewayTooOld is the plain message for an agent newer than its
// controller's gateway: what this node waits for, and that it will not
// start on unverified weights meanwhile.
func hfGatewayTooOld(backend, model string) error {
	return &HFWeightsRefusedError{
		Backend: backend, Model: model, Err: ErrArtifactKindUnknown,
		Reason: fmt.Sprintf("the controller's gateway predates verified HF weights (needs >= %s, which serves the `hf` artifact manifest); "+
			"upgrade the controller first (`noo upgrade` on the controller), and this node starts %s at its next reconcile. "+
			"Until then this node will not start %s on unverified weights", hfManifestVersionFloor, backend, backend),
	}
}

// stageHFModel makes the node's HF cache hold a VERIFIED snapshot of model,
// or returns why it cannot (see the order above). nil means: start the
// backend offline on it.
func (c *Client) stageHFModel(ctx context.Context, backend, model string) error {
	repo := preseed.RepoCacheDir(model)
	hfHost := resolveEnv(hfCacheSource)
	dest := filepath.Join(hfHost, "hub", repo)
	rec := hfVerifiedRecord()
	pc := preseed.New()
	pc.Record = rec
	line := newHFProgressLine(model)

	refused := func(err error, reason string) error {
		return &HFWeightsRefusedError{Backend: backend, Model: model, Reason: reason, Err: err}
	}
	// localAgainst checks the node's copy against m with no network.
	localAgainst := func(m *preseed.HFManifest) error {
		if err := pc.VerifyHFRepoLocal(dest, m, line.report); err != nil {
			return err
		}
		rec.SetRepoManifest(repo, m)
		return nil
	}

	m, merr := hfManifestFn(ctx, repo)
	switch {
	case merr == nil:
		cacheURL := preseed.CacheURL()
		var ferr error
		if cacheURL == "" {
			ferr = errors.New("NOO_MODEL_CACHE_URL is refused on this node (see the model_cache_url refusal)")
		} else {
			mctx, cancel := context.WithTimeout(ctx, hfPreseedTimeout)
			var n int
			n, ferr = pc.MirrorHFRepo(mctx, cacheURL+"/hf/"+repo+"/", dest, m, line.report)
			cancel()
			if ferr == nil {
				rec.SetRepoManifest(repo, m)
				slog.Info("hf weights verified from controller store", "model", model, "rev", m.Rev,
					"files", len(m.Files), "downloaded", n, "dest", dest)
				return nil
			}
		}
		if errors.Is(ferr, preseed.ErrDigestMismatch) {
			return refused(ferr, "a file from the controller's model cache does not hash to the controller's manifest ("+ferr.Error()+
				"); nothing unverified was kept — check the controller's HF cache and the path to it, then `noo cluster verify`")
		}
		if lerr := localAgainst(m); lerr == nil {
			slog.Warn("hf weights: the model cache could not be read, but the local snapshot verifies against the controller's manifest",
				"model", model, "rev", m.Rev, "store_error", ferr)
			return nil
		} else {
			reason := fmt.Sprintf("the model cache could not supply it (%v) and the local copy does not verify (%v)", ferr, lerr)
			if isPermissionErr(ferr) {
				reason += "; make " + hfHost + " writable by the agent's user (it is a declared host root; prep-host owns it)"
			}
			return refused(errors.Join(ferr, lerr), reason)
		}

	case errors.Is(merr, ErrArtifactKindUnknown):
		if sm, ok := rec.RepoManifest(repo); ok && localAgainst(sm) == nil {
			slog.Warn("hf weights: the controller's gateway predates the hf manifest; the local snapshot verifies against the manifest this node last verified",
				"model", model, "rev", sm.Rev, "needs", ">= "+hfManifestVersionFloor)
			return nil
		}
		err := hfGatewayTooOld(backend, model)
		slog.Error("hf weights: waiting for the controller's upgrade", "model", model, "backend", backend, "detail", err.Error())
		return err

	case errors.Is(merr, ErrArtifactAbsent):
		return &ModelNotStagedError{Backend: backend, Model: model}

	case errors.Is(merr, ErrArtifactRefused):
		return refused(merr, "the controller refuses to vouch for its copy: "+merr.Error())
	}

	// The controller was not heard from.
	sm, ok := rec.RepoManifest(repo)
	if !ok {
		return refused(merr, fmt.Sprintf("the controller's manifest could not be fetched (%v), and this node has never verified a snapshot of %s it could check its local copy against", merr, model))
	}
	if lerr := localAgainst(sm); lerr != nil {
		return refused(errors.Join(merr, lerr), fmt.Sprintf("the controller's manifest could not be fetched (%v), and the local copy does not verify against the last verified one (%v)", merr, lerr))
	}
	slog.Warn("hf weights: controller unreachable; the local snapshot verifies against the manifest this node last verified",
		"model", model, "rev", sm.Rev, "manifest_error", merr)
	return nil
}

// hfProgressLine logs "verifying <repo> weights: <n>/<total> GB" while a
// snapshot is hashed or fetched — the backend start waits on it, so the log
// says what it waits for. At most one line per hfProgressEvery, plus the
// last.
// A staging that finishes inside the first hfProgressEvery (every file
// vouched for by the record) logs nothing.
type hfProgressLine struct {
	model string
	mu    sync.Mutex
	start time.Time
	last  time.Time
}

const hfProgressEvery = 5 * time.Second

func newHFProgressLine(model string) *hfProgressLine {
	return &hfProgressLine{model: model, start: time.Now()}
}

func (p *hfProgressLine) report(done, total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if done >= total {
		if !p.last.IsZero() {
			slog.Info(hfProgressText(p.model, done, total))
		}
		return
	}
	since := p.last
	if since.IsZero() {
		since = p.start
	}
	if now.Sub(since) < hfProgressEvery {
		return
	}
	p.last = now
	slog.Info(hfProgressText(p.model, done, total))
}

func hfProgressText(model string, done, total int64) string {
	return fmt.Sprintf("verifying %s weights: %.1f/%.1f GB", model, float64(done)/1e9, float64(total)/1e9)
}
