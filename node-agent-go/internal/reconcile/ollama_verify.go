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
	// verify checks one model on the given lane (dockerpkg.OllamaLane*:
	// the adopted lanes, native and stack, are report only).
	verify func(ctx context.Context, model string, lane string) dockerpkg.OllamaVerifyResult
	now    func() time.Time
	// nudge asks reconcile for a pass now (Reconciler.Nudge); nil = none.
	nudge func()

	mu      sync.Mutex
	results map[string]dockerpkg.OllamaVerifyResult
	lastRun map[string]time.Time
	// listed is the report's model set (model -> lane): every model the
	// node holds, or may hold, whether or not its check has run. report()
	// gives one row per model here (and per stored result), so the set
	// does not depend on which checks have finished since the agent
	// started (i1067).
	listed map[string]string
	busy   bool
	// refusal is the standing backend_start reason ("" = none).
	refusal string
	// refusalsLogged counts transitions into a (new) refusal: what the
	// operator is told, once per state.
	refusalsLogged int
	// missed: a schedule found due models while a pass was busy and could
	// not start them. The pass that ends clears it and nudges ONCE, so they
	// are checked on the next tick, not the next interval.
	missed bool
}

func newOllamaVerifyLoop(verify func(context.Context, string, string) dockerpkg.OllamaVerifyResult, nudge func()) *ollamaVerifyLoop {
	return &ollamaVerifyLoop{
		verify:  verify,
		nudge:   nudge,
		now:     time.Now,
		results: map[string]dockerpkg.OllamaVerifyResult{},
		lastRun: map[string]time.Time{},
		listed:  map[string]string{},
	}
}

// list replaces the report's model set: models (checked or not) on lane.
func (l *ollamaVerifyLoop) list(models []string, lane string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listed = make(map[string]string, len(models))
	for _, m := range models {
		l.listed[m] = lane
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
// one is running: then the due models are remembered as missed, and the
// running pass nudges reconcile when it ends (a pass that skipped nothing
// never nudges). ctx is the Run context: the pass outlives the tick.
func (l *ollamaVerifyLoop) schedule(ctx context.Context, models []string, lane string) {
	if l == nil || l.verify == nil {
		return
	}
	l.mu.Lock()
	// A model scheduled is a model the node holds: reported from now on,
	// pending until its check has run, whether or not a pass starts now.
	for _, m := range models {
		l.listed[m] = lane
	}
	if l.busy {
		if len(l.dueLocked(models)) > 0 {
			l.missed = true
		}
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
			missed := l.missed
			l.missed = false
			l.mu.Unlock()
			if missed && l.nudge != nil {
				l.nudge()
			}
		}()
		l.runPass(ctx, due, lane)
	}()
}

// runPass checks each model and publishes the results and the refusal.
func (l *ollamaVerifyLoop) runPass(ctx context.Context, models []string, lane string) {
	for _, m := range models {
		vctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
		res := l.verify(vctx, m, lane)
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
	for m := range l.listed {
		if !keep[m] {
			delete(l.listed, m)
		}
	}
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

// report is the heartbeat's `ollama_verify`: one row per listed model and
// per stored result, sorted. A listed model whose check has not run (after an
// agent restart, or before its first pass) is a pending row, never left out:
// the row's model set must not change with nothing changing on the box
// (i1067). nil (key omitted) when nothing is listed or checked.
func (l *ollamaVerifyLoop) report() any {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	names := map[string]bool{}
	for m := range l.results {
		names[m] = true
	}
	for m := range l.listed {
		names[m] = true
	}
	if len(names) == 0 {
		return nil
	}
	keys := make([]string, 0, len(names))
	for m := range names {
		keys = append(keys, m)
	}
	sort.Strings(keys)
	out := make([]dockerpkg.OllamaVerifyResult, 0, len(keys))
	for _, m := range keys {
		if res, ok := l.results[m]; ok {
			out = append(out, res)
			continue
		}
		out = append(out, dockerpkg.OllamaVerifyResult{
			Model:  m,
			State:  dockerpkg.OllamaPending,
			Reason: dockerpkg.OllamaPendingReason,
			Lane:   l.listed[m],
		})
	}
	return out
}

// OllamaVerifyReport is the heartbeat's `ollama_verify` provider.
func (r *Reconciler) OllamaVerifyReport() any { return r.ollamaVerify.report() }

// clearBackendStart clears a backend_start refusal on the success path,
// except the ollama verification refusal, which only the verification loop
// clears: a container that runs says nothing about the bytes it loads; and
// a missing gguf's refusal, which stands until ggufPresent sees the file.
func (r *Reconciler) clearBackendStart(backend string) {
	if msg := r.ggufMissing[backend]; msg != "" {
		refusals.Record("backend_start", backend, msg)
		return
	}
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
// lane is the Ollama checked (dockerpkg.OllamaLane*): the agent's container,
// or the adopted lane's Runtime() ("native", "stack"), whose store differs.
//
// The report's model set is every placed model NOT known absent: held, or
// unknown this tick. Unknown is ensureOllamaModel's "could not ask" (each
// model is its own /api/tags read, on the adopted lane with a 2 s probe
// timeout, and a failed read clears that model's presence): such a model is
// not checked this tick, but it stays in the report (its last result, or
// pending). Before i1067 the set was "models with a result", and a model
// whose read failed on the tick after a restart was missing from the report
// until a later tick read it: the row moved with nothing changed on the box.
func (r *Reconciler) verifyOllamaModels(ctx context.Context, rows []placement, lane string) {
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
	var placed, held, listed []string
	seen := map[string]bool{}
	for _, p := range ordered {
		model := strings.TrimSpace(p.Model)
		if model == "" || seen[model] {
			continue
		}
		seen[model] = true
		placed = append(placed, model)
		e, known := presence[presenceKey(p.Backend, p, primary, ordered)]
		if known && e.Present {
			held = append(held, model)
		}
		if !known || e.Present {
			listed = append(listed, model)
		}
	}
	r.ollamaVerify.retain(placed)
	r.ollamaVerify.list(listed, lane)
	r.ollamaVerify.schedule(ctx, held, lane)
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
