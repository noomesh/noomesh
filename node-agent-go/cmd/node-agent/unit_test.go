// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/stopdrain"
)

// The shipped unit must be able to recover a node WITHOUT anything reaching
// in from the controller.
//
// This is a policy test, not a formatting one. Until 2026-09-05 the unit
// carried StartLimitBurst=5/60s, so five quick failures parked it in
// `failed` and systemd stopped trying. The only thing that cleared that
// state was the controller's revive_node proposal SSHing in to run
// `systemctl restart` — an inbound privileged path the mesh is removing.
// Restoring a burst limit here would quietly restore that dependency.
func TestUnitCanAlwaysRecoverWithoutTheController(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/noo-node-agent.service")
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	unit := string(raw)

	directive := func(key string) string {
		for _, line := range strings.Split(unit, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, key+"=") {
				return strings.TrimPrefix(line, key+"=")
			}
		}
		return ""
	}

	if got := directive("Restart"); got != "always" {
		t.Errorf("Restart=%q — only `always` covers an unintended clean exit", got)
	}
	// A non-zero burst is a terminal state waiting to happen.
	if got := directive("StartLimitBurst"); got != "0" {
		t.Errorf("StartLimitBurst=%q — must be 0, or the unit can park in `failed`", got)
	}

	// Spacing is what replaces the burst limit, so it has to be real: a
	// short RestartSec with no burst cap is the crash-loop-too-fast-to-read
	// problem the 2026-08-14 comment was written about.
	if got := directive("RestartSec"); got != "30" {
		t.Errorf("RestartSec=%q — expected 30s, the ceiling that replaced 5/60s", got)
	}
}

// The stop drain (stopdrain.Bound) must finish before systemd's SIGKILL:
// TimeoutStopSec is the bound plus 20 s for the rest of the shutdown.
func TestUnitStopTimeoutOutlastsTheDrain(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/noo-node-agent.service")
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	got := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "TimeoutStopSec="); ok {
			got = v
		}
	}
	secs, err := strconv.Atoi(got)
	if err != nil {
		t.Fatalf("TimeoutStopSec=%q: must be whole seconds", got)
	}
	if want := int((stopdrain.Bound + 20*time.Second).Seconds()); secs != want {
		t.Errorf("TimeoutStopSec=%d, want %d (the stop drain bound + 20 s)", secs, want)
	}
}

// The node's own declarations are applied before anything reads the
// environment: before the legacy-root adoption and before config.Load.
func TestNodeLocalDeclarationsAreAppliedBeforeTheEnvironmentIsRead(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	at, adopt, load := strings.Index(src, "nodelocal.Apply()"), strings.Index(src, "dataroots.AdoptLegacyRoot("), strings.Index(src, "cfg := config.Load()")
	if at < 0 || adopt < 0 || load < 0 || at > adopt || at > load {
		t.Fatalf("nodelocal.Apply() at %d must come before AdoptLegacyRoot (%d) and config.Load (%d)", at, adopt, load)
	}
}
