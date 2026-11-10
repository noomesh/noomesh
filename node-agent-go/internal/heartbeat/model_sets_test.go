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

// i607b: `model_sets_free_bytes` is the free space of the filesystem the
// agent's disk check reads. Sent when known (0 included), omitted otherwise.
func TestHeartbeatModelSetsFreeBytes(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["model_sets_free_bytes"]; ok {
		t.Fatal("an unwired reporter sent model_sets_free_bytes")
	}

	r.SetModelSetsFreeBytes(func() (int64, bool) { return 0, false })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["model_sets_free_bytes"]; ok {
		t.Fatalf("an unknown value sent model_sets_free_bytes = %v", v)
	}

	r.SetModelSetsFreeBytes(func() (int64, bool) { return 9_000_000_000, true })
	r.SetModelSets(func() any { return nil }) // independent of model_sets
	r.SendHeartbeat()
	beat := cap.last(&cap.beats)
	if v, ok := beat["model_sets_free_bytes"].(float64); !ok || v != 9_000_000_000 {
		t.Fatalf("model_sets_free_bytes = %v", beat["model_sets_free_bytes"])
	}
	if _, ok := beat["model_sets"]; ok {
		t.Fatal("model_sets sent while unreadable")
	}

	// A full disk is a fact, not an unknown.
	r.SetModelSetsFreeBytes(func() (int64, bool) { return 0, true })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["model_sets_free_bytes"].(float64); !ok || v != 0 {
		t.Fatalf("a full disk reported %v", cap.last(&cap.beats)["model_sets_free_bytes"])
	}
}
