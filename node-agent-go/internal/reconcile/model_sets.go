// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// convergeModelSets fetches, verifies and prunes the model sets that
// desired-config's node_workloads name (i300 F4). It runs before
// settleEmptyState: a node with no placements still holds its sets.
//
//   - No node_workloads key (an older gateway): nothing happens.
//   - desired-config that does not validate: nothing is fetched and NOTHING IS
//     PRUNED. An error is never "nothing referenced" (i495): pruning on a
//     read failure would delete every set the node holds.
//   - Fetching runs off the tick, one set at a time (modelsets.Store.Sync).
func (r *Reconciler) convergeModelSets(ctx context.Context, t *tick) bool {
	if r.sets == nil {
		return true
	}
	// Before the empty check and before Sync: Sync is what restarts the
	// worker for the sets this clears.
	r.applyModelSetRetry(t.desired.ModelSetRetry)
	if len(t.desired.NodeWorkloads) == 0 {
		return true
	}
	want, keep, err := desiredSetRefs(t.desired.NodeWorkloads, r.cfg.NodeID)
	if err != nil {
		slog.Warn("reconcile.model_sets_desired_unreadable; fetching and pruning nothing", "error", err)
		return true
	}
	r.sets.Sync(ctx, want)
	if removed, err := r.sets.Prune(keep); err != nil {
		slog.Warn("reconcile.model_sets_prune_failed", "error", err, "removed", len(removed))
	}
	return true
}

// modelSetRetry is desired-config's top-level `model_set_retry` (i607b B3):
// the controller's per-node retry epoch, and the sets the last bump named as
// "<id>@<revision>" (empty = every refused set).
type modelSetRetry struct {
	Epoch uint64   `json:"epoch"`
	Sets  []string `json:"sets"`
}

// applyModelSetRetry clears the refused backoff once per epoch increase: when
// the controller's epoch is past the last one this agent applied, it resets
// the named refused sets (all of them when none are named) and records the
// epoch. The same epoch again, a lower one, or no key does nothing. It only
// ever ends a backoff: verified and fetching sets are not touched, and it
// never changes which sets are wanted. The caller runs Sync next, which wakes
// the worker for the sets it cleared.
func (r *Reconciler) applyModelSetRetry(rt *modelSetRetry) {
	if r.sets == nil || rt == nil || rt.Epoch <= r.retryEpoch.Load() {
		return
	}
	r.retryEpoch.Store(rt.Epoch)
	var refs []modelsets.Ref
	for _, raw := range rt.Sets {
		ref, ok := modelsets.ParseRef(raw)
		if !ok {
			slog.Warn("reconcile.model_set_retry_set_unreadable; skipped", "set", raw)
			continue
		}
		refs = append(refs, ref)
	}
	if len(rt.Sets) > 0 && len(refs) == 0 {
		// Every named set was unreadable: "none readable" is not "all".
		return
	}
	cleared := r.sets.ClearRefused(refs)
	slog.Info("reconcile.model_set_retry", "epoch", rt.Epoch, "named", len(rt.Sets), "cleared", len(cleared))
}

// ModelSetsReport is the heartbeat's `model_sets`, nil when the state cannot
// be read (the key is then omitted).
func (r *Reconciler) ModelSetsReport() any {
	if r.sets == nil {
		return nil
	}
	rows, ok := r.sets.Rows()
	if !ok {
		return nil
	}
	return rows
}

// ModelSetsFreeBytes is the heartbeat's `model_sets_free_bytes`: the free
// bytes of the filesystem the model-set disk check measures. ok is false (the
// key is omitted) when there is no store or the number cannot be read.
func (r *Reconciler) ModelSetsFreeBytes() (int64, bool) {
	if r.sets == nil {
		return 0, false
	}
	return r.sets.FreeBytes()
}

// desiredSetRefs reads the sets of every node_workloads entry through the
// contract's own validator. want is what to fetch (entries not absent); keep
// is what to retain (every entry's sets).
func desiredSetRefs(raw json.RawMessage, ownAgentCN string) (want []modelsets.Ref, keep map[modelsets.Ref]bool, err error) {
	frag, err := json.Marshal(map[string]json.RawMessage{"node_workloads": raw})
	if err != nil {
		return nil, nil, fmt.Errorf("node_workloads: %w", err)
	}
	entries, err := nodewl.ParseDesired(frag, ownAgentCN)
	if err != nil {
		return nil, nil, err
	}
	keep = map[modelsets.Ref]bool{}
	seen := map[modelsets.Ref]bool{}
	for _, e := range entries {
		for _, refs := range e.Sets {
			for _, s := range refs {
				ref := modelsets.Ref{ID: s.ID, Revision: s.Revision}
				keep[ref] = true
				if e.State != nodewl.StateAbsent && !seen[ref] {
					seen[ref] = true
					want = append(want, ref)
				}
			}
		}
	}
	return want, keep, nil
}
