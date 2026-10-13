// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package modelpresence records, per placed backend, whether the node's
// model server actually HOLDS the placement's model.
//
// "Running" for an ollama placement used to mean the ollama container ran.
// On 2026-10-03 host9's `ollama harrier` placement read Running while its
// Ollama held only llama3.2:1b and gemma3:1b: every embed 404'd, the gateway
// kept offering the node, and nothing paged. The reconcile tick already asks
// `ollama list` (ensureOllamaModel) and then throws the answer away; this
// registry keeps it so the heartbeat can carry it to the controller.
//
// Absence is meaningful and must stay distinct from "not present": a backend
// with no entry is one this agent has not (or could not) check — the
// controller reads that as UNKNOWN and changes nothing. Only an explicit
// `present: false` is a negative. A check that fails (docker down, ollama
// not yet listening) therefore Clears the entry rather than recording false.
//
// A package-level singleton for the reason refusals is: the producer
// (reconcile) and the consumer (heartbeat) are wired at different points in
// agent startup.
package modelpresence

import "sync"

// Entry is one backend's answer.
type Entry struct {
	Model string `json:"model"`
	// Role is what the placement serves: chat | embed | rerank.
	Role string `json:"role"`
	// Present: the model server lists the model.
	Present bool `json:"present"`
	// ImportOnly: the model reaches nodes only through `noo cluster
	// import-model` (the controller store holds its Modelfile), so it can
	// never be fetched from the public registry.
	ImportOnly bool `json:"import_only,omitempty"`
}

var (
	mu   sync.Mutex
	live = map[string]Entry{}
)

// Set records the latest answer for a backend.
func Set(backend string, e Entry) {
	mu.Lock()
	defer mu.Unlock()
	live[backend] = e
}

// Clear drops a backend's entry: not checked, so unknown.
func Clear(backend string) {
	mu.Lock()
	defer mu.Unlock()
	delete(live, backend)
}

// Retain drops every entry whose backend is not in keep. Called at the end
// of a reconcile pass so a placement that was removed or stopped does not
// keep reporting a model it is no longer asked to hold.
func Retain(keep map[string]bool) {
	mu.Lock()
	defer mu.Unlock()
	for b := range live {
		if !keep[b] {
			delete(live, b)
		}
	}
}

// Report is the heartbeat's `model_presence`: backend -> Entry. Always a
// non-nil map ("{}" = nothing checked), so a beat from this build is
// distinguishable from an older agent's, which omits the key.
func Report() map[string]Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]Entry, len(live))
	for b, e := range live {
		out[b] = e
	}
	return out
}

// Reset clears everything (tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	live = map[string]Entry{}
}
