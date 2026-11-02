// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"sort"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func ctrIn(id, name, netMode string) container.Summary {
	s := container.Summary{ID: id, Names: []string{"/" + name}}
	s.HostConfig.NetworkMode = netMode
	return s
}

// i317 e1: the controller's compose-only doors front children no
// backendDoors entry names, so the engine heal never saw them. doorChildren
// must pick exactly those, and leave the agent's own engines to the
// existing path (no double restart).
func TestDoorChildrenPicksTheComposeOnlyChildren(t *testing.T) {
	ctrs := []container.Summary{
		ctrIn("d1", "noo-stunnel-ollama-embed", "noo-cluster"),
		ctrIn("d2", "noo-stunnel-ollama-embed-cpu", "noo-cluster"),
		ctrIn("d3", "noo-stunnel-vllm-secondary", "noo-cluster"),
		ctrIn("d4", "noo-stunnel-llamacpp", "noo-cluster"),
		ctrIn("c1", "noo-ollama-embed", "container:d1"),
		ctrIn("c2", "noo-ollama-embed-cpu", "container:noo-stunnel-ollama-embed-cpu"),
		ctrIn("c3", "noo-vllm-secondary", "container:d3"),
		// The agent's own fronted engine: readDeclaredTLS judges it.
		ctrIn("e1", "noo-llamacpp", "container:d4"),
		// Not in any namespace, or in a non-door one: not a child.
		ctrIn("g1", "noo-gateway", "noo-cluster"),
		ctrIn("x1", "noo-sidekick", "container:g1"),
		ctrIn("x2", "noo-host-net", "host"),
	}
	doors, children := doorChildren(ctrs)
	if len(doors) != 4 {
		t.Fatalf("doors = %v, want the four noo-stunnel-* containers", doors)
	}
	var got []string
	for _, c := range children {
		got = append(got, c.ID)
	}
	sort.Strings(got)
	// x1 is selected here (a namespace child the backend path does not
	// judge); judgeEngineDoor then finds no door behind it and the heal
	// leaves it alone (see the next test).
	want := []string{"c1", "c2", "c3", "x1"}
	if len(got) != len(want) {
		t.Fatalf("children = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("children = %v, want %v", got, want)
		}
	}
}

// The restart list: a child is stranded only when its namespace owner is a
// running door that started after it. A child of a non-door owner, a child
// started after its door, and one whose times are unknown are left alone.
func TestStrandedDoorChildren(t *testing.T) {
	early, late := "2026-10-31T10:00:00Z", "2026-10-31T10:05:00Z"
	ctrs := []container.Summary{
		ctrIn("d1", "noo-stunnel-ollama-embed", "noo-cluster"),
		ctrIn("d2", "noo-stunnel-ollama-embed-cpu", "noo-cluster"),
		ctrIn("d3", "noo-stunnel-vllm-secondary", "noo-cluster"),
		ctrIn("d4", "noo-stunnel-llamacpp", "noo-cluster"),
		ctrIn("g1", "noo-gateway", "noo-cluster"),
		ctrIn("c1", "noo-ollama-embed", "container:d1"),                               // door restarted after it
		ctrIn("c2", "noo-ollama-embed-cpu", "container:noo-stunnel-ollama-embed-cpu"), // same, by name
		ctrIn("c3", "noo-vllm-secondary", "container:d3"),                             // started after its door
		ctrIn("e1", "noo-llamacpp", "container:d4"),                                   // the engine path's
		ctrIn("x1", "noo-sidekick", "container:g1"),                                   // owner is not a door
	}
	times := map[string]string{
		"d1": late, "c1": early,
		"noo-stunnel-ollama-embed-cpu": late, "c2": early,
		"d3": early, "c3": late,
		"d4": late, "e1": early,
		"g1": late, "x1": early,
	}
	got := strandedDoorChildren(ctrs, func(id string) string { return times[id] })
	want := map[string]string{"noo-ollama-embed": "c1", "noo-ollama-embed-cpu": "c2"}
	if len(got) != len(want) {
		t.Fatalf("stranded = %v, want %v", got, want)
	}
	for name, id := range want {
		if got[name] != id {
			t.Fatalf("stranded = %v, want %v", got, want)
		}
	}
	if s := strandedDoorChildren(ctrs, func(string) string { return "" }); len(s) != 0 {
		t.Errorf("unknown start times restarted %v; want nothing", s)
	}
}
