// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/stopdrain"
)

// A stop drains and leaves its record where the next start's first beat
// reports it from.
func TestAStopDrainsAndLeavesItsRecord(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: &config.Config{StateDir: dir}, drain: stopdrain.New(func(*http.Request) bool { return false })}
	a.drainOnStop()
	b, err := os.ReadFile(filepath.Join(dir, stopdrain.RecordFile))
	if err != nil {
		t.Fatalf("no record: %v", err)
	}
	var res stopdrain.Result
	if err := json.Unmarshal(b, &res); err != nil || res.AtUnix == 0 || res.BoundHit {
		t.Fatalf("record %s (%v)", b, err)
	}
}

// The wiring, by source: the gate is on the server and follows the
// controller's features; once serving, a signal no longer cancels the run
// at once (the tunnel and heartbeat run on it), the drain runs first and
// the run is cancelled after it.
func TestTheStopDrainIsWired(t *testing.T) {
	raw, err := os.ReadFile("agent.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"drain := stopdrain.New(api.IsController)",
		"server.SetDrain(drain)",
		"rec.SetGatewayFeaturesSink(a.drain.SetFeatures)",
		"if !a.serving.Load() {",
		"a.serving.Store(true)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("agent.go does not wire %q", want)
		}
	}
	stop := strings.Index(src, "slog.Info(\"shutting down\", \"signal\", sig)")
	drain := strings.Index(src, "a.drainOnStop()")
	cancelAfter := strings.Index(src[drain:], "cancel()")
	if stop < 0 || drain < stop || cancelAfter < 0 {
		t.Fatal("the stop must drain before it cancels the run")
	}
}
