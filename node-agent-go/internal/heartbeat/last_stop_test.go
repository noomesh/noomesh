// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/stopdrain"
)

// The previous stop's drain record rides the beats until one carrying it is
// delivered, then it is removed: reported once, never again.
func TestTheLastStopIsReportedOnceThenRemoved(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, stopdrain.RecordFile)
	if err := os.WriteFile(rec, []byte(`{"drained":2,"cut_marked":1,"cut_at_bound":0,"bound_hit":false,"at_unix":1763400000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Reporter{cfg: &config.Config{StateDir: dir}}
	p := map[string]any{}
	secLastStop.add(r, p)
	raw, ok := p["last_stop"].(json.RawMessage)
	if !ok {
		t.Fatalf("the beat does not carry last_stop: %v", p)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["drained"] != float64(2) {
		t.Fatalf("record %v", got)
	}
	// Not delivered yet: still pending, the file still there.
	p2 := map[string]any{}
	secLastStop.add(r, p2)
	if _, ok := p2["last_stop"]; !ok {
		t.Fatal("an undelivered report must ride the next beat too")
	}
	r.lastStopDelivered()
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Fatalf("the delivered record must be removed: %v", err)
	}
	p3 := map[string]any{}
	secLastStop.add(r, p3)
	if _, ok := p3["last_stop"]; ok {
		t.Fatal("reported once, never again")
	}
}

// No record (a first start, an agent that never drained): nothing is sent.
func TestNoRecordNoLastStop(t *testing.T) {
	r := &Reporter{cfg: &config.Config{StateDir: t.TempDir()}}
	p := map[string]any{}
	secLastStop.add(r, p)
	if _, ok := p["last_stop"]; ok {
		t.Fatal("no record, no key")
	}
}
