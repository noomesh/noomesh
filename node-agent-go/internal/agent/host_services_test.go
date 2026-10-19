// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
)

// The heartbeat names the harness's RUNNING kind, so the controller (and the
// eval's readiness check) can tell which loop is live; a harness that is not
// running, or whose kind this agent never learned, reports none.
func TestHostServicesReportNamesTheRunningKind(t *testing.T) {
	h := hostServicesReport(hostsvc.Running, "systemd", "copilot")["harness"].(map[string]any)
	if h["state"] != "running" || h["runtime"] != "systemd" || h["kind"] != "copilot" {
		t.Fatalf("running: %v", h)
	}
	for _, c := range []struct {
		state hostsvc.State
		kind  string
	}{{hostsvc.Stopped, "copilot"}, {hostsvc.Absent, "noo"}, {hostsvc.Running, ""}} {
		h := hostServicesReport(c.state, "systemd", c.kind)["harness"].(map[string]any)
		if _, ok := h["kind"]; ok {
			t.Fatalf("%s with kind %q must report no kind: %v", c.state, c.kind, h)
		}
		if h["state"] != string(c.state) {
			t.Fatalf("state: %v", h)
		}
	}
}
