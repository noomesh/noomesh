// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
)

// Against a REAL systemd whose noo-harness unit runs with no egress hold
// (tests/ci/harness-egress-systemd.sh, after its fail-safe step): the node
// agent's real reader reads it as unenforced, and a Codex harness is refused
// on it while the other kinds are not.
func TestRealSystemdUnenforcedRefusesCodex(t *testing.T) {
	if os.Getenv("NOO_REAL_SYSTEMD_UNENFORCED") != "1" {
		t.Skip("set NOO_REAL_SYSTEMD_UNENFORCED=1 to run against a real, unheld noo-harness unit")
	}
	eg := hostsvc.DefaultEgressReader().Read(context.Background())
	if eg.State != hostsvc.EgressUnenforced || eg.Reason != "the harness unit has no IPAddressDeny=any" {
		t.Fatalf("live unit: state %q reason %q, want unenforced: the harness unit has no IPAddressDeny=any", eg.State, eg.Reason)
	}
	chat := []placement{{Backend: "ollama", Model: "gemma", DesiredState: "running"}}
	h := func(kind string) placement {
		return placement{Backend: "harness", Model: "auto", Role: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": kind}}
	}
	present := func(string) bool { return true }
	got := harnessKindRefusalProfiled(h("codex"), chat, present, present, nil, "n", &eg)
	if !strings.HasPrefix(got, `harness kind "codex": this node's harness is not held off the internet (the harness unit has no IPAddressDeny=any)`) {
		t.Fatalf("codex on the live unheld unit: got %q", got)
	}
	for _, k := range []string{"copilot", "claude-code", "noo"} {
		if why := harnessKindRefusalProfiled(h(k), chat, present, present, nil, "n", &eg); why != "" {
			t.Fatalf("%s must not be gated by egress: %q", k, why)
		}
	}
}
