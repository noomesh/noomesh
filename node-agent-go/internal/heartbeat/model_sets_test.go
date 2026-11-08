// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
)

// i300 F4: `model_sets` is omitted whenever the state is unknown, never a
// default or an empty list standing in for "could not read".
func TestHeartbeatOmitsModelSetsWhenUnknown(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	// Not wired.
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["model_sets"]; ok {
		t.Fatal("an unwired reporter sent model_sets")
	}

	// Wired, but the state cannot be read.
	r.SetModelSets(func() any { return nil })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["model_sets"]; ok {
		t.Fatalf("an unknown state sent model_sets = %v", v)
	}

	// Read, and there are none: a real empty list.
	r.SetModelSets(func() any { return []modelsets.Row{} })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["model_sets"].([]any); !ok || len(v) != 0 {
		t.Fatalf("a known-empty state = %v present=%v", cap.last(&cap.beats)["model_sets"], ok)
	}

	// Read, with rows: the contract's exact keys.
	r.SetModelSets(func() any {
		return []modelsets.Row{
			{ID: "a", Revision: "r1", State: "verified"},
			{ID: "b", Revision: "r2", State: "refused", Reason: "disk"},
		}
	})
	r.SendHeartbeat()
	rows, _ := cap.last(&cap.beats)["model_sets"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	a, b := rows[0].(map[string]any), rows[1].(map[string]any)
	if a["id"] != "a" || a["revision"] != "r1" || a["state"] != "verified" {
		t.Fatalf("row a = %v", a)
	}
	if _, has := a["reason"]; has {
		t.Fatalf("a verified row carries a reason: %v", a)
	}
	if b["state"] != "refused" || b["reason"] != "disk" {
		t.Fatalf("row b = %v", b)
	}

	// Back to unknown: the key disappears again.
	r.SetModelSets(func() any { return nil })
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["model_sets"]; ok {
		t.Fatal("model_sets lingered after the state became unknown")
	}
}
