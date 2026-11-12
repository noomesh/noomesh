// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// countingRig is setsRig whose gateway counts how often each set's manifest
// was asked for. Every set is refused (not staged), so a count that moves is
// a refused set that was tried again.
func countingRig(t *testing.T) (*Reconciler, *modelsets.Store, func() map[modelsets.Ref]int) {
	t.Helper()
	r, st, _ := setsRig(t)
	var mu sync.Mutex
	calls := map[modelsets.Ref]int{}
	st.Manifest = func(_ context.Context, ref modelsets.Ref) (*modelsets.Signed, error) {
		mu.Lock()
		calls[ref]++
		mu.Unlock()
		return nil, modelsets.ErrNotStaged
	}
	snap := func() map[modelsets.Ref]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[modelsets.Ref]int, len(calls))
		for k, v := range calls {
			out[k] = v
		}
		return out
	}
	return r, st, snap
}

func pass(t *testing.T, r *Reconciler, st *modelsets.Store, retry *modelSetRetry) {
	t.Helper()
	r.convergeModelSets(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: fixture(t), ModelSetRetry: retry}})
	st.Wait()
}

func sum(m map[modelsets.Ref]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func TestRetryClearsRefusedOncePerEpochIncrease(t *testing.T) {
	r, st, calls := countingRig(t)
	pass(t, r, st, nil)
	first := sum(calls())
	if first == 0 {
		t.Fatal("the fixture's sets were never tried")
	}
	pass(t, r, st, nil)
	if got := sum(calls()); got != first {
		t.Fatalf("a refused set inside its backoff was tried again without a retry: %d -> %d", first, got)
	}

	pass(t, r, st, &modelSetRetry{Epoch: 1})
	second := sum(calls())
	if second != 2*first {
		t.Fatalf("epoch 1 (all) should try every refused set again: %d -> %d", first, second)
	}
	pass(t, r, st, &modelSetRetry{Epoch: 1})
	if got := sum(calls()); got != second {
		t.Fatalf("the same epoch cleared again: %d -> %d", second, got)
	}
	pass(t, r, st, &modelSetRetry{Epoch: 0})
	if got := sum(calls()); got != second {
		t.Fatalf("a lower epoch cleared: %d -> %d", second, got)
	}
	pass(t, r, st, &modelSetRetry{Epoch: 2})
	if got := sum(calls()); got != 3*first {
		t.Fatalf("epoch 2 should clear again: %d -> %d", second, got)
	}
}

func TestRetryNamingOneSetClearsOnlyThatSet(t *testing.T) {
	want, _, err := desiredSetRefs(fixture(t), "node-a")
	if err != nil || len(want) < 2 {
		t.Fatalf("the fixture must name two sets to prove this: %v %v", want, err)
	}
	r, st, calls := countingRig(t)
	pass(t, r, st, nil)
	before := calls()
	pass(t, r, st, &modelSetRetry{Epoch: 1, Sets: []string{want[0].String()}})
	after := calls()
	for _, ref := range want {
		delta := after[ref] - before[ref]
		if ref == want[0] && delta != 1 {
			t.Errorf("the named set %v was tried %d more times, want 1", ref, delta)
		}
		if ref != want[0] && delta != 0 {
			t.Errorf("%v was not named but was tried %d more times", ref, delta)
		}
	}
}

func TestRetryWithOnlyUnreadableSetsClearsNothing(t *testing.T) {
	r, st, calls := countingRig(t)
	pass(t, r, st, nil)
	before := sum(calls())
	pass(t, r, st, &modelSetRetry{Epoch: 1, Sets: []string{"not-a-ref", "@x"}})
	if got := sum(calls()); got != before {
		t.Fatalf("unreadable names were read as \"all\": %d -> %d", before, got)
	}
}

func TestRetryNeverChangesWhichSetsAreWanted(t *testing.T) {
	r, st, calls := countingRig(t)
	pass(t, r, st, &modelSetRetry{Epoch: 5, Sets: []string{"never-placed@r1"}})
	if _, ok := calls()[modelsets.Ref{ID: "never-placed", Revision: "r1"}]; ok {
		t.Fatal("a retry for a set nobody placed made the agent fetch it")
	}
}

// oldDesiredConfig is desiredConfig as it was before model_set_retry: the
// shape an agent from before this change decodes desired-config into.
type oldDesiredConfig struct {
	Node              *nodeConfig     `json:"node"`
	Placements        []placement     `json:"placements"`
	NodeWorkloads     json.RawMessage `json:"node_workloads"`
	WorkloadApprovals json.RawMessage `json:"workload_approvals"`
	HarnessProfile    json.RawMessage `json:"harness_profile"`
	DiskReclaim       json.RawMessage `json:"disk_reclaim"`
}

func TestAnOldShapedAgentStillDecodesDesiredConfigWithTheKey(t *testing.T) {
	doc := `{"node": {"node_id": "node-a"}, "placements": [], "node_workloads": [],
		"model_set_retry": {"epoch": 7, "sets": ["rh-main@r1"]}}`
	var old oldDesiredConfig
	if err := json.NewDecoder(strings.NewReader(doc)).Decode(&old); err != nil {
		t.Fatalf("an agent without the field must ignore the top-level key: %v", err)
	}
	if old.Node == nil || old.Node.NodeID != "node-a" {
		t.Fatalf("the rest of desired-config was lost: %+v", old)
	}
	var cur desiredConfig
	if err := json.NewDecoder(strings.NewReader(doc)).Decode(&cur); err != nil {
		t.Fatal(err)
	}
	if cur.ModelSetRetry == nil || cur.ModelSetRetry.Epoch != 7 || len(cur.ModelSetRetry.Sets) != 1 {
		t.Fatalf("the key was not read: %+v", cur.ModelSetRetry)
	}
	var none desiredConfig
	if err := json.Unmarshal([]byte(`{"placements": []}`), &none); err != nil || none.ModelSetRetry != nil {
		t.Fatalf("an absent key must leave the field nil: %+v %v", none.ModelSetRetry, err)
	}
}

// The same key INSIDE the strict node_workloads fragment is what an old agent
// would refuse (desired_invalid): the reason the key is top-level.
func TestTheKeyInsideTheStrictFragmentWouldBeRefused(t *testing.T) {
	var d struct {
		NW []map[string]any `json:"node_workloads"`
	}
	b := fixture(t)
	if err := json.Unmarshal(b, &d.NW); err != nil || len(d.NW) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	d.NW[0]["model_set_retry"] = map[string]any{"epoch": 1}
	raw, _ := json.Marshal(d.NW)
	frag, _ := json.Marshal(map[string]json.RawMessage{"node_workloads": raw})
	if _, err := nodewl.ParseDesired(frag, "node-a"); err == nil {
		t.Fatal("the strict decoder accepted an unknown field inside an entry; the top-level argument no longer holds")
	}
}
