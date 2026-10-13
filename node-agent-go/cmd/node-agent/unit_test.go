// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"os"
	"strings"
	"testing"
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
