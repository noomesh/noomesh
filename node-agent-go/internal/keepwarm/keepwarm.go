// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package keepwarm is the node's declared keep-warm set: the ollama models
// whose placement carries `keep_warm` (`noo cluster place … --keep-warm`).
//
// The reconciler publishes it every pass from desired-config; the inference
// proxy reads it to add `keep_alive: -1` to a request for one of these models
// (only when the caller set none), the warm keeper reads it to preload and
// re-pin them, and a GPU yield or hold reads it to unload them. A package
// singleton for the reason lanes and modelpresence are one: producer
// (reconcile) and consumers (api, gpuyield hook) are wired at different points
// in startup.
//
// The flag is per MODEL on this node's ollama: it pins that model only. An
// embedder or another chat model sharing the daemon is not pinned by it.
package keepwarm

import (
	"strings"
	"sync"
)

// Warm is one declared-warm ollama model.
type Warm struct {
	Model string
	// Target is the placement's declared hardware ("cpu" | "gpu" | "").
	// A cpu model holds no GPU, so a GPU yield leaves it alone.
	Target string
}

// OnGPU reports whether the model may hold GPU memory (anything but an
// explicit cpu target).
func (w Warm) OnGPU() bool { return w.Target != "cpu" }

var (
	mu   sync.Mutex
	warm []Warm
)

// Set records the declared-warm models (the reconciler, every pass).
func Set(ws []Warm) {
	mu.Lock()
	defer mu.Unlock()
	warm = append([]Warm(nil), ws...)
}

// All is the last recorded set.
func All() []Warm {
	mu.Lock()
	defer mu.Unlock()
	return append([]Warm(nil), warm...)
}

// Lookup finds model in the declared set (SameModel's rule).
func Lookup(model string) (Warm, bool) {
	if strings.TrimSpace(model) == "" {
		return Warm{}, false
	}
	for _, w := range All() {
		if SameModel(w.Model, model) {
			return w, true
		}
	}
	return Warm{}, false
}

// SameModel is ollama's own naming rule for "the same model": a name with no
// tag is `:latest`, case does not matter. `gemma4` is `gemma4:latest`;
// `gemma4:12b` is not `gemma4`.
func SameModel(a, b string) bool {
	return Canonical(a) != "" && Canonical(a) == Canonical(b)
}

// Canonical is the name with ollama's implicit `:latest`, lower-cased.
func Canonical(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	// A tag is a colon after the last path separator (a registry host may
	// carry a port: `host:5000/ns/model`).
	last := n[strings.LastIndex(n, "/")+1:]
	if !strings.Contains(last, ":") {
		n += ":latest"
	}
	return n
}
