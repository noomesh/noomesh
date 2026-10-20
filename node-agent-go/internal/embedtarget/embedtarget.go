// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package embedtarget records which local backend this node serves
// embeddings from, as declared by desired state.
//
// The /embed proxy used to hardcode http://noo-tei:80. That was fine while
// TEI was the only embedder, but it silently mis-routes the moment a node
// serves embeddings from anything else: host8 runs harrier on ollama and
// ALSO had a stray noo-tei container, so /embed returned 768-dim bge
// vectors while the placed embedder (harrier) answers at 1024. Nothing
// errored — the wrong vectors just came back.
//
// Container-name heuristics can't fix this. ollama is a general runtime;
// one instance may serve chat and another embeddings, which is exactly how
// harrier ended up in the chat candidate pool (migration 032). The only
// reliable signal is the placement's `role`, so the reconciler publishes
// the role=embed target here each tick and the proxy reads it.
package embedtarget

import (
	"strings"
	"sync/atomic"
)

// Target is the resolved embed backend for this node.
type Target struct {
	// BaseURL is the declared embedder's door as an agent-started backend
	// is created with it, e.g. "https://stunnel-ollama:11434". Empty means
	// desired state declares no embedder here, which callers must treat as
	// "unknown", NOT as "use the old default". The /embed proxy dials by
	// Backend (docker.BackendDialURL), not by this string, so a pre-door
	// container is still reached until the reconciler recreates it.
	BaseURL string
	// Backend is the placement's backend type ("ollama", "embedding", ...).
	// The proxy needs it because embedders speak different dialects: TEI
	// serves OpenAI /v1/embeddings plus native /embed, while ollama serves
	// OpenAI /v1/embeddings plus native /api/embed.
	Backend string
	// Model is the placement's model, injected into requests that omit it.
	// TEI serves one model and ignores the field; ollama rejects a request
	// without it — which is how a correctly-routed /embed still returned
	// "404 page not found" (ollama's own 404, proxied straight through).
	Model string
}

var current atomic.Value // []Target

// Set records a single embed target for this node (the zero Target clears
// it). Kept for callers that only ever name one embedder; the reconciler
// uses SetAll because a node may serve several embedding spaces.
func Set(t Target) {
	if t == (Target{}) {
		SetAll(nil)
		return
	}
	SetAll([]Target{t})
}

// SetAll records every embed target this node is declared to serve, primary
// first (one per embed model: a node can serve several embedding spaces).
// Called by the reconciler on every tick, so it converges after a placement
// edit without restarting the agent.
func SetAll(ts []Target) {
	current.Store(append([]Target(nil), ts...))
}

// All returns every recorded target, primary first. The slice is a copy.
func All() []Target {
	ts, _ := current.Load().([]Target)
	return append([]Target(nil), ts...)
}

// Get returns the primary (first) recorded target. A zero Target (empty
// BaseURL) means desired state has not declared an embedder (or has not
// been fetched yet).
func Get() Target {
	ts, _ := current.Load().([]Target)
	if len(ts) == 0 {
		return Target{}
	}
	return ts[0]
}

// For returns the target serving model, matched exactly but case-insensitively,
// and tolerating ollama's implicit ":latest" tag on either side (a placement
// naming "harrier" serves a request for "harrier:latest" and vice versa).
// ok=false when no recorded target serves that model; callers fall back to
// Get() for a request that names no model or an unknown one.
func For(model string) (Target, bool) {
	want := normalizeModel(model)
	if want == "" {
		return Target{}, false
	}
	ts, _ := current.Load().([]Target)
	for _, t := range ts {
		if normalizeModel(t.Model) == want {
			return t, true
		}
	}
	return Target{}, false
}

func normalizeModel(m string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m)), ":latest")
}
