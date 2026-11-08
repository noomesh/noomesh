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
	if r.sets == nil || len(t.desired.NodeWorkloads) == 0 {
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
