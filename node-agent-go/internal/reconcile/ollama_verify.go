// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Verifying the bytes of every placed Ollama model against the controller's
// store (docker/ollama_verify.go), off the reconcile tick.
//
// The first check after an upgrade hashes every blob once (GBs, niced); the
// VerifiedRecord turns each later check into a stat. Either way it runs in
// its own goroutine, one pass at a time, the way ollama pulls do
// (ollamaPulls): a tick only decides whether a pass is due and reads the last
// results.
//
// A REFUSED model (a mismatch whose repair from the controller failed) is
// recorded as a `backend_start` refusal on the ollama backend, the shape the
// controller already reads for a backend this node will not serve, and its
// presence is reported false so it is not routed here. The daemon is NOT
// stopped: it serves the node's other models, and the remedy
// (`noo models pull <model>`) needs it running. The refusal is recorded once
// per state change and kept across ticks; a tick that sees the container
// converged does not clear it (clearBackendStart).

// ollamaVerifyEvery is how often a placed model is re-checked. A check of
// unchanged blobs is a stat plus one controller lookup; a mismatch is
// repaired at most this often.
const ollamaVerifyEvery = 10 * time.Minute

type ollamaVerifyLoop struct {
	// verify checks one model on the given lane (native = report only).
	verify func(ctx context.Context, model string, native bool) dockerpkg.OllamaVerifyResult
	now    func() time.Time

	mu      sync.Mutex
	results map[string]dockerpkg.OllamaVerifyResult
	lastRun map[string]time.Time
	busy    bool
	// refusal is the standing backend_start reason ("" = none).
	refusal string
	// refusalsLogged counts transitions into a (new) refusal: what the
	// operator is told, once per state.
	refusalsLogged int
}

func newOllamaVerifyLoop(verify func(context.Context, string, bool) dockerpkg.OllamaVerifyResult) *ollamaVerifyLoop {
	return &ollamaVerifyLoop{
		verify:  verify,
		now:     time.Now,
		results: map[string]dockerpkg.OllamaVerifyResult{},
		lastRun: map[string]time.Time{},
	}
}

// due lists the models whose last check is older than ollamaVerifyEvery.
func (l *ollamaVerifyLoop) dueLocked(models []string) []string {
	var out []string
	now := l.now()
	for _, m := range models {
		if t, ok := l.lastRun[m]; !ok || now.Sub(t) >= ollamaVerifyEvery {
			out = append(out, m)
		}
	}
	return out
}

// schedule starts a pass over the due models in its own goroutine, unless
// one is running. ctx is the Run context: the pass outlives the tick.
func (l *ollamaVerifyLoop) schedule(ctx context.Context, models []string, native bool) {
	if l == nil || l.verify == nil {
		return
	}
	l.mu.Lock()
	if l.busy {
		l.mu.Unlock()
		return
	}
	due := l.dueLocked(models)
	if len(due) == 0 {
		l.mu.Unlock()
		return
	}
	l.busy = true
	l.mu.Unlock()
	go func() {
		defer func() {
			l.mu.Lock()
			l.busy = false
			l.mu.Unlock()
		}()
		l.runPass(ctx, due, native)
	}()
}

// runPass checks each model and publishes the results and the refusal.
func (l *ollamaVerifyLoop) runPass(ctx context.Context, models []string, native bool) {
	for _, m := range models {
		vctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
		res := l.verify(vctx, m, native)
		cancel()
		l.mu.Lock()
		prev, had := l.results[m]
		l.results[m] = res
		l.lastRun[m] = l.now()
		l.mu.Unlock()
		if !had || prev.State != res.State || prev.Blob != res.Blob {
			logVerifyResult(res)
		}
	}
	l.publishRefusal()
}

func logVerifyResult(res dockerpkg.OllamaVerifyResult) {
	attrs := []any{"model", res.Model, "state", res.State, "anchor", res.Anchor, "model_layer", res.ModelLayer, "reason", res.Reason}
	switch res.State {
	case dockerpkg.OllamaVerified:
		slog.Info("reconcile.ollama_verify", attrs...)
	case dockerpkg.OllamaRefused:
		slog.Error("reconcile.ollama_verify", attrs...)
	default:
		slog.Warn("reconcile.ollama_verify", attrs...)
	}
}

// publishRefusal records or clears the backend_start refusal when the set of
// refused models changes, and only then.
func (l *ollamaVerifyLoop) publishRefusal() {
	l.mu.Lock()
	var parts []string
	for _, m := range sortedResultKeys(l.results) {
		if r := l.results[m]; r.State == dockerpkg.OllamaRefused {
			parts = append(parts, r.Reason)
		}
	}
	msg := strings.Join(parts, "; ")
	changed := msg != l.refusal
	l.refusal = msg
	if changed && msg != "" {
		l.refusalsLogged++
	}
	l.mu.Unlock()
	if !changed {
		return
	}
	if msg == "" {
		refusals.Clear("backend_start", "ollama")
		slog.Info("reconcile.ollama_verify_refusal_cleared")
		return
	}
	refusals.Record("backend_start", "ollama", msg)
	slog.Error("reconcile.ollama_verify_refused", "reason", msg)
}

func sortedResultKeys(m map[string]dockerpkg.OllamaVerifyResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// retain forgets models no longer placed, and the refusal with them.
func (l *ollamaVerifyLoop) retain(models []string) {
	if l == nil {
		return
	}
	keep := map[string]bool{}
	for _, m := range models {
		keep[m] = true
	}
	l.mu.Lock()
	dropped := false
	for m := range l.results {
		if !keep[m] {
			delete(l.results, m)
			delete(l.lastRun, m)
			dropped = true
		}
	}
	l.mu.Unlock()
	if dropped {
		l.publishRefusal()
	}
}

// standingRefusal is the backend_start reason the loop holds ("" = none).
func (l *ollamaVerifyLoop) standingRefusal() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refusal
}

func (l *ollamaVerifyLoop) refused(model string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.results[model].State == dockerpkg.OllamaRefused
}

// report is the heartbeat's `ollama_verify`: one row per placed model
// checked, sorted; nil (key omitted) before any check.
func (l *ollamaVerifyLoop) report() any {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.results) == 0 {
		return nil
	}
	out := make([]dockerpkg.OllamaVerifyResult, 0, len(l.results))
	for _, m := range sortedResultKeys(l.results) {
		out = append(out, l.results[m])
	}
	return out
}

// OllamaVerifyReport is the heartbeat's `ollama_verify` provider.
func (r *Reconciler) OllamaVerifyReport() any { return r.ollamaVerify.report() }

// clearBackendStart clears a backend_start refusal on the success path,
// except the ollama verification refusal, which only the verification loop
// clears: a container that runs says nothing about the bytes it loads.
func (r *Reconciler) clearBackendStart(backend string) {
	if backend == "ollama" {
		if msg := r.ollamaVerify.standingRefusal(); msg != "" {
			refusals.Record("backend_start", backend, msg)
			return
		}
	}
	refusals.Clear("backend_start", backend)
}

// verifyOllamaModels runs after ensureOllamaModels: schedules a check of
// every placed model the server holds, and reports a refused one absent.
func (r *Reconciler) verifyOllamaModels(ctx context.Context, rows []placement, native bool) {
	if r.ollamaVerify == nil {
		return
	}
	ordered := orderPlacements(rows)
	if len(ordered) == 0 {
		r.ollamaVerify.retain(nil)
		return
	}
	primary := ordered[0]
	presence := modelpresence.Report()
	var placed, held []string
	seen := map[string]bool{}
	for _, p := range ordered {
		model := strings.TrimSpace(p.Model)
		if model == "" || seen[model] {
			continue
		}
		seen[model] = true
		placed = append(placed, model)
		if e, ok := presence[presenceKey(p.Backend, p, primary, ordered)]; ok && e.Present {
			held = append(held, model)
		}
	}
	r.ollamaVerify.retain(placed)
	r.ollamaVerify.schedule(ctx, held, native)
	for _, p := range ordered {
		model := strings.TrimSpace(p.Model)
		if !r.ollamaVerify.refused(model) {
			continue
		}
		key := presenceKey(p.Backend, p, primary, ordered)
		role := p.Role
		if role == "" {
			role = "chat"
		}
		modelpresence.Set(key, modelpresence.Entry{Model: model, Role: role, Present: false})
	}
}
