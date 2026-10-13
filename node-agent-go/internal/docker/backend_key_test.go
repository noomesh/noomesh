// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// The host8 reranker recreate loop: backendKeyFromName had no
// case for "reranker", so a healthy noo-reranker was invisible to
// RunningBackends(). The reconciler recreated it every tick
// (was_running=false) and the heartbeat reported it missing, firing
// node_placement_drift alerts hourly while the container served fine.
func TestBackendKeyFromName(t *testing.T) {
	cases := map[string]string{
		"noo-vllm":           "vllm",
		"noo-vllm-secondary": "vllm-secondary",
		"noo-llamacpp":       "llamacpp",
		"noo-airllm":         "airllm",
		"noo-ollama":         "ollama",
		"noo-tei":            "embedding",
		// Both reranker engines keep this container name — the key must not
		// depend on which engine is inside.
		"noo-reranker": "reranker",
		// Not a PAI backend.
		"noo-node-agent": "",
		"postgres":       "",
	}
	for name, want := range cases {
		if got := backendKeyFromName(name); got != want {
			t.Errorf("backendKeyFromName(%q) = %q, want %q", name, got, want)
		}
	}
}

// The harness is NOT a container: it is a host service the
// reconciler drives through hostsvc. Nothing here may key it, name a
// container for it, or carry a spec for it — a leftover would make the
// reconciler try to `docker run` it again.
func TestHarnessIsNotAContainerBackend(t *testing.T) {
	if got := backendKeyFromName("noo-harness"); got != "" {
		t.Fatalf("noo-harness must not key a backend, got %q", got)
	}
	if ContainerNameFor("harness") != "" {
		t.Fatalf("ContainerNameFor(harness) = %q, want none", ContainerNameFor("harness"))
	}
	if _, ok := backendSpecs["harness"]; ok {
		t.Fatal("backendSpecs must carry no harness")
	}
	if ContainerNameFor("nope") != "" {
		t.Fatal("unknown backend must have no container name")
	}
}
