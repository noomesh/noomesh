// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
)

// setsRig is a Reconciler holding only what convergeModelSets reads, and a
// Store whose gateway says "not staged" for everything (no network).
func setsRig(t *testing.T) (*Reconciler, *modelsets.Store, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "models", "sets")
	st := &modelsets.Store{
		Root: root,
		Manifest: func(context.Context, modelsets.Ref) (*modelsets.Signed, error) {
			return nil, modelsets.ErrNotStaged
		},
		CacheURL: func() string { return "" },
		Free:     func(string) (uint64, error) { return 1 << 50, nil },
		Now:      time.Now,
	}
	return &Reconciler{cfg: &config.Config{NodeID: "node-a"}, sets: st}, st, root
}

// leftover plants a set directory nobody references.
func leftover(t *testing.T, root string) string {
	t.Helper()
	d := filepath.Join(root, "old-set", "r0")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func fixture(t *testing.T) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("../nodewl/testdata/i300/desired-node-workloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		NW json.RawMessage `json:"node_workloads"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d.NW
}

func TestNoNodeWorkloadsKeyDoesNothing(t *testing.T) {
	r, st, root := setsRig(t)
	d := leftover(t, root)
	if !r.convergeModelSets(context.Background(), &tick{desired: &desiredConfig{}}) {
		t.Fatal("the pass must go on")
	}
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("a gateway without node_workloads got a set pruned: %v", err)
	}
	if rows, ok := st.Rows(); ok {
		t.Fatalf("rows %v reported though desired-config named nothing", rows)
	}
	if r.ModelSetsReport() != nil {
		t.Fatal("heartbeat provider must answer nil (omit)")
	}
}

func TestUnreadableDesiredNeverPrunesAndNeverFetches(t *testing.T) {
	for name, raw := range map[string]string{
		"bad entry":   `[{"addon": 1}]`,
		"not a list":  `"oops"`,
		"null":        `null`,
		"bad decl":    `[{"addon":"rhaddon","name":"worker"}]`,
		"empty array": `[`,
	} {
		t.Run(name, func(t *testing.T) {
			r, st, root := setsRig(t)
			d := leftover(t, root)
			r.convergeModelSets(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: json.RawMessage(raw)}})
			st.Wait()
			if _, err := os.Stat(d); err != nil {
				t.Fatalf("an unreadable desired-config pruned a set: %v", err)
			}
			if _, ok := st.Rows(); ok {
				t.Fatal("rows reported off an unreadable desired-config")
			}
		})
	}
}

func TestDesiredSetsAreFetchedOffTickAndUnreferencedArePruned(t *testing.T) {
	r, st, root := setsRig(t)
	d := leftover(t, root)
	r.convergeModelSets(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: fixture(t)}})
	st.Wait()
	if _, err := os.Stat(d); err == nil {
		t.Fatal("an unreferenced revision was kept")
	}
	rows, ok := r.ModelSetsReport().([]modelsets.Row)
	if !ok || len(rows) == 0 {
		t.Fatalf("report = %#v", r.ModelSetsReport())
	}
	found := false
	for _, row := range rows {
		if row.ID == "rh-s2s-7b" && row.Revision == "0123456789abcdef0123456789abcdef01234567" {
			found = true
			// The test gateway stages nothing: set_missing, not a silent drop.
			if row.State != "refused" || row.Reason != "set_missing" {
				t.Fatalf("row = %+v", row)
			}
		}
	}
	if !found {
		t.Fatalf("the fixture's main set is not reported: %+v", rows)
	}
}

func TestDesiredSetRefsFetchesLiveEntriesAndKeepsAll(t *testing.T) {
	want, keep, err := desiredSetRefs(fixture(t), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 || len(keep) < len(want) {
		t.Fatalf("want=%v keep=%v", want, keep)
	}
	if _, _, err := desiredSetRefs(fixture(t), "node-b"); err == nil {
		t.Fatal("another node's door CN must not validate")
	}
}
