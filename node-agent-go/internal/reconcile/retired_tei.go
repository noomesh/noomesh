// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"log/slog"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// The TEI engine was removed from core in 0.6.30 (i1182a). Two things follow
// for a node upgraded with TEI placed:
//
//   - its desired state may still carry an `embedding` placement. The spec is
//     gone, so StartBackend would answer "unknown backend", and an unknown
//     backend must not be a silent skip: retiredBackendRefusal gives the
//     backend_start refusal `noo cluster show` / verify prints, with the
//     replacement.
//   - the old agent's containers may still be running: noo-tei(-gpu) and its
//     noo-stunnel-tei(-gpu) door, or a noo-reranker on the TEI image. Nothing
//     in this loop can see them any more, so removeRetiredTEI stops and
//     removes them (only the ones this agent labelled, by exact name; see
//     dockerpkg.RemoveRetiredTEI).

// retiredBackendEmbedding is the placement backend name of the TEI engine.
const retiredBackendEmbedding = "embedding"

// retiredBackendRefusal is why a placement of a removed engine is refused, ""
// when the backend is not one.
func retiredBackendRefusal(backend, node string) string {
	if backend != retiredBackendEmbedding {
		return ""
	}
	return "the TEI embedding engine is no longer supported; nothing was started. " +
		"Replace the placement: noo cluster place " + node + " ollama <model> --role embed " +
		"(then `noo cluster unplace " + node + " embedding`)"
}

// retiredRerankerRefusal is why a reranker placement whose model is not a
// GGUF file is refused: the reranker is always llama.cpp now.
func retiredRerankerRefusal(node, model string) string {
	return "the reranker is llama.cpp and loads a GGUF file, not a HuggingFace repo id (" + model + "); " +
		"the TEI reranker is no longer supported. Replace the placement: noo cluster place " +
		node + " reranker <file>.gguf"
}

// retiredTEIRemovalLine is the one log line written per container removed.
func retiredTEIRemovalLine(rc dockerpkg.RetiredTEI, node string) string {
	switch {
	case rc.Reranker:
		return "removed " + rc.Name + ": it ran the TEI engine, which is no longer supported; replace the placement: " +
			"noo cluster place " + node + " reranker <file>.gguf"
	case rc.Name == "noo-stunnel-tei" || rc.Name == "noo-stunnel-tei-gpu":
		return "removed " + rc.Name + ": the door of the TEI engine, which is no longer supported"
	}
	return "removed " + rc.Name + ": the TEI engine is no longer supported; replace the placement: " +
		"noo cluster place " + node + " ollama <model> --role embed"
}

// removeRetiredTEI is the reconcile phase that stops and removes the TEI
// containers an older agent left. It runs before the placements are
// converged, so a TEI-image reranker is gone before the reranker placement is
// (a GGUF placement then starts on llama.cpp in the same pass; the stale
// running map reads the TEI one as a different model, so it is recreated
// either way). It succeeds once per agent run: only an agent older than this
// one can have made them, and a restart asks again. A docker error leaves it
// to the next pass.
func (r *Reconciler) removeRetiredTEI(ctx context.Context, t *tick) bool {
	if r.retiredTEIDone {
		return true
	}
	remove := r.removeRetiredTEIFn
	if remove == nil {
		if r.docker == nil {
			return true
		}
		remove = r.docker.RemoveRetiredTEI
	}
	removed, err := remove(ctx)
	if err != nil {
		slog.Warn("reconcile.retired_tei_check_failed", "error", err,
			"effect", "any leftover TEI container is looked for again on the next pass")
		return true
	}
	for _, rc := range removed {
		slog.Warn(retiredTEIRemovalLine(rc, r.cfg.NodeID), "container", rc.Name)
	}
	r.retiredTEIDone = true
	return true
}

// clearUnplacedRetiredRefusals drops the start refusal of a retired backend
// no placement wants running any more: the refusal's remedy IS the unplace.
func clearUnplacedRetiredRefusals(ps []placement) {
	wanted := false
	for _, p := range ps {
		if p.Backend == retiredBackendEmbedding && p.DesiredState == "running" {
			wanted = true
		}
	}
	if !wanted {
		refusals.Clear("backend_start", retiredBackendEmbedding)
	}
	// A reranker no placement wants running has nothing left to refuse: the
	// non-GGUF refusal's remedy is replacing or removing the placement.
	rerankerWanted := false
	for _, p := range ps {
		if p.Backend == "reranker" && p.DesiredState == "running" {
			rerankerWanted = true
		}
	}
	if !rerankerWanted {
		refusals.Clear("backend_start", "reranker")
	}
}
