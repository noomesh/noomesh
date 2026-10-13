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

import "sync/atomic"

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

var current atomic.Value // Target

// Set records the embed target for this node. Called by the reconciler on
// every tick, so it converges after a placement edit without restarting
// the agent.
func Set(t Target) {
	current.Store(t)
}

// Get returns the recorded target. A zero Target (empty BaseURL) means
// desired state has not declared an embedder (or has not been fetched yet).
func Get() Target {
	t, _ := current.Load().(Target)
	return t
}
