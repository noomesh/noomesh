// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"
	"os"
	"testing"
)

func fixtureRows(t *testing.T) []map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/i300/desired-node-workloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NodeWorkloads []map[string]any `json:"node_workloads"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.NodeWorkloads
}

func fragment(t *testing.T, rows []map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"node_workloads": rows})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// One malformed row is that row's own refusal; the others are still read.
func TestParseDesiredRowsJudgesEachRowOnItsOwn(t *testing.T) {
	rows := fixtureRows(t)
	rows[1]["state"] = "bogus"
	got, err := ParseDesiredRows(fragment(t, rows), "node-a")
	if err != nil || len(got) != 2 {
		t.Fatalf("rows = %v, %v", got, err)
	}
	if got[0].Err != nil || got[0].Entry.Name != "worker" {
		t.Fatalf("the good row: %+v", got[0])
	}
	if CodeOf(got[1].Err) != ReasonDesiredInvalid || got[1].Addon != "rhaddon" || got[1].Name != "echo" {
		t.Fatalf("the bad row: %+v", got[1])
	}
	// ParseDesired keeps its all-or-nothing contract.
	if _, err := ParseDesired(fragment(t, rows), "node-a"); err == nil {
		t.Fatal("ParseDesired accepted a fragment with a bad row")
	}
}

func TestParseDesiredRowsRefusesBothCopiesOfADuplicate(t *testing.T) {
	rows := fixtureRows(t)
	got, err := ParseDesiredRows(fragment(t, append(rows, rows[0])), "node-a")
	if err != nil || len(got) != 3 {
		t.Fatalf("rows = %v, %v", got, err)
	}
	if CodeOf(got[0].Err) != ReasonDesiredInvalid || CodeOf(got[2].Err) != ReasonDesiredInvalid {
		t.Fatalf("a listed-twice row stayed valid: %v / %v", got[0].Err, got[2].Err)
	}
	if got[1].Err != nil {
		t.Fatalf("an unrelated row was refused: %v", got[1].Err)
	}
}

func TestParseDesiredRowsFragmentFailuresHaveNoRows(t *testing.T) {
	for name, b := range map[string][]byte{"not json": []byte("{"), "key absent": []byte(`{}`)} {
		if rows, err := ParseDesiredRows(b, "node-a"); err == nil {
			t.Errorf("%s: rows = %v, want an error", name, rows)
		}
	}
	// A row whose identity cannot be read has nothing to be reported against.
	got, err := ParseDesiredRows([]byte(`{"node_workloads":[{"addon":1}]}`), "node-a")
	if err != nil || len(got) != 0 {
		t.Errorf("unidentifiable row: %v, %v", got, err)
	}
}
