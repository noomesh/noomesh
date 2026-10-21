// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"strings"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// The docker-facing steps of the image prefetch, as package vars so the
// selection is testable without a daemon.
var (
	placementImageFn = dockerpkg.BackendImageRef
	prefetchImagesFn = func(ctx context.Context, c *dockerpkg.Client, refs []string, placements int) dockerpkg.PrefetchResult {
		return c.PrefetchImages(ctx, refs, placements)
	}
)

// prefetchImages pulls, concurrently and before the ordered start loop, the
// images of every placement this tick is about to (re)start. Without it a
// node placed with several backends after a release pulled their multi-GB
// image tars one after another, each start waiting on the previous pull.
//
// It only selects and fetches; it never starts, stops or refuses anything.
// A pull that fails is logged by PrefetchImages and the placement's own
// start path (which still calls EnsureImage) reports the same error through
// its usual text and refusal record. Selection is deliberately a superset-
// safe approximation of the start loop (a placement a later guard skips may
// be prefetched; a placement whose image cannot be named is simply left to
// its start path).
func (r *Reconciler) prefetchImages(
	ctx context.Context,
	effective []placement,
	running map[string]string,
	specLabels map[string]string,
	floating map[string]string,
	native map[string]string,
) {
	if r.docker == nil {
		return
	}
	refs, n := imagesToPrefetch(effective, running, specLabels, floating, native, r.driftRecreated)
	if len(refs) == 0 {
		return
	}
	prefetchImagesFn(ctx, r.docker, refs, n)
}

// imagesToPrefetch returns the image refs of the placements the start loop
// will (re)start, in placement order, and how many placements that is.
// Dedup and "already local" are PrefetchImages' job.
func imagesToPrefetch(
	effective []placement,
	running map[string]string,
	specLabels map[string]string,
	floating map[string]string,
	native map[string]string,
	driftRecreated map[string]string,
) (refs []string, placements int) {
	for _, p := range effective {
		if p.Backend == "harness" || p.DesiredState != "running" {
			continue
		}
		if _, ok := native[p.Backend]; ok {
			continue
		}
		curModel, isRunning := running[p.Backend]
		if isRunning && modelMatches(curModel, p.Model) {
			curHash, hasLabel := specLabels[p.Backend]
			// Converged or stuck: the loop does not start it. Only a
			// recreate falls through to a start (read-only use of the
			// start loop's driftRecreated bookkeeping).
			if decideBackendDrift(hasLabel, curHash, specHash(p), driftRecreated[p.Backend], floating[p.Backend]) != driftRecreate {
				continue
			}
		}
		// Same guard as the start loop: this start can never happen.
		if p.Model != "" && dockerpkg.ExpectsGGUFModel(p.Backend) && !strings.HasSuffix(p.Model, ".gguf") {
			continue
		}
		ref := placementImageFn(p.Backend, p.Image)
		if ref == "" {
			continue
		}
		placements++
		refs = append(refs, ref)
	}
	return refs, placements
}
