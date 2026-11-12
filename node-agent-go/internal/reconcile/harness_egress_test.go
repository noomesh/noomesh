// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
)

func TestEgressGateRefusesCodexOnlyWhenUnenforced(t *testing.T) {
	chat := []placement{{Backend: "ollama", Model: "gemma", DesiredState: "running"}}
	h := func(kind string) placement {
		return placement{Backend: "harness", Model: "auto", Role: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": kind}}
	}
	present := func(string) bool { return true }
	eg := func(state string) *hostsvc.Egress {
		return &hostsvc.Egress{State: state, Reason: "the harness unit has no IPAddressDeny=any"}
	}
	const want = `harness kind "codex": this node's harness is not held off the internet (the harness unit has no IPAddressDeny=any), and Codex resolves api.github.com and chatgpt.com at start; the node's state: noo cluster verify (row "harness egress")`

	if got := harnessKindRefusalProfiled(h("codex"), chat, present, present, nil, "n", eg("unenforced")); got != want {
		t.Fatalf("codex on unenforced:\n got %q\nwant %q", got, want)
	}
	for _, st := range []*hostsvc.Egress{eg("unknown"), eg("enforced"), nil} {
		if got := harnessKindRefusalProfiled(h("codex"), chat, present, present, nil, "n", st); got != "" {
			t.Fatalf("codex must be allowed on %v: %q", st, got)
		}
	}
	for _, k := range []string{"copilot", "claude-code", "noo"} {
		if got := harnessKindRefusalProfiled(h(k), chat, present, present, nil, "n", eg("unenforced")); got != "" {
			t.Fatalf("%s must not be gated by egress: %q", k, got)
		}
	}
}

func TestEgressViewReadsOnlyForGatedKinds(t *testing.T) {
	calls := 0
	r := &Reconciler{harnessEgress: func(_ context.Context) hostsvc.Egress { calls++; return hostsvc.Egress{State: "unenforced"} }}
	if r.egressView(context.Background(), "copilot") != nil || calls != 0 {
		t.Fatalf("a kind that needs no hold-off must not trigger a read")
	}
	if e := r.egressView(context.Background(), "codex"); e == nil || e.State != "unenforced" || calls != 1 {
		t.Fatalf("codex must read once: %v %d", e, calls)
	}
}
