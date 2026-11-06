// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package config

import "testing"

func TestAddonWorkloadsPolicyDefaultsToNoneAndFailsClosed(t *testing.T) {
	for in, want := range map[string]struct{ policy, asked string }{
		"":          {"none", ""},
		"none":      {"none", ""},
		" Approve ": {"approve", ""},
		"AUTO":      {"auto", ""},
		"yes":       {"none", "yes"}, // not a mode: closed, and reported
		"1":         {"none", "1"},
		"autoo":     {"none", "autoo"},
	} {
		if p, a := addonWorkloadsPolicy(in); p != want.policy || a != want.asked {
			t.Errorf("addonWorkloadsPolicy(%q) = %q, %q; want %q, %q", in, p, a, want.policy, want.asked)
		}
	}
}

func TestLoadReadsTheNodeWorkloadSettings(t *testing.T) {
	t.Setenv("NOO_ADDON_WORKLOADS", "")
	t.Setenv("NOO_ADDON_WORKLOADS_ON_CONTROLLER", "")
	t.Setenv("NOO_SELF_NODE", "")
	c := Load()
	if c.AddonWorkloadsPolicy != "none" || c.AddonWorkloadsOnController || c.SelfNode {
		t.Fatalf("defaults = %q on-controller=%v self=%v, want none, off, off", c.AddonWorkloadsPolicy, c.AddonWorkloadsOnController, c.SelfNode)
	}

	t.Setenv("NOO_ADDON_WORKLOADS", "approve")
	t.Setenv("NOO_ADDON_WORKLOADS_ON_CONTROLLER", "1")
	// controller_host is the existing self-node marker (NOO_SELF_NODE), not a
	// second one: the heartbeat's controller_host IS Config.SelfNode.
	t.Setenv("NOO_SELF_NODE", "1")
	c = Load()
	if c.AddonWorkloadsPolicy != "approve" || !c.AddonWorkloadsOnController || !c.SelfNode {
		t.Fatalf("set = %q on-controller=%v self=%v", c.AddonWorkloadsPolicy, c.AddonWorkloadsOnController, c.SelfNode)
	}
}
