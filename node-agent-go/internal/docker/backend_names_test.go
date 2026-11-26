// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// Every container name the agent gives a backend is recognised, derived from
// backendSpecs so a backend added there without a recognised name fails here.
func TestEveryBackendSpecNameIsRecognised(t *testing.T) {
	if len(backendSpecs) == 0 {
		t.Fatal("no backend specs")
	}
	for key, spec := range backendSpecs {
		if spec.ContainerName == "" {
			t.Errorf("spec %q has no container name", key)
			continue
		}
		if got := backendKeyFromName(spec.ContainerName); got != key {
			t.Errorf("spec %q container %q recognised as %q", key, spec.ContainerName, got)
		}
		if got := backendKeyFromName(ContainerNameFor(key)); got != key {
			t.Errorf("ContainerNameFor(%q) not recognised: %q", key, got)
		}
	}
}

// The names the compose stack gives its backends (docker-compose.cluster.yml
// container_name, default instance prefix), plus the secondary vLLM.
func TestComposeBackendNamesAreRecognised(t *testing.T) {
	for name, want := range map[string]string{
		"noo-vllm":           "vllm",
		"noo-vllm-secondary": "vllm-secondary",
		"noo-llamacpp":       "llamacpp",
		"noo-airllm":         "airllm",
		"noo-ollama":         "ollama",
		"noo-reranker":       "reranker",
	} {
		if got := backendKeyFromName(name); got != want {
			t.Errorf("%q -> %q, want %q", name, got, want)
		}
	}
}

// A name that merely CONTAINS a backend's name is not that backend: it is
// another project's, an add-on's or a rehearsal's container.
func TestLookAlikeNamesAreNotBackends(t *testing.T) {
	for _, name := range []string{
		"ollama", "vllm", "llamacpp", "reranker", "airllm",
		"other-ollama", "myvllm", "my-ollama-ui",
		"noo-ollama-backup", "noo-ollama-embed", "noo-ollama-embed-cpu",
		"x-noo-vllm-1", "noo-vllm-1", "noo-vllm-secondary-2",
		"noo-rhaddon-ollama", "noo-llamacpp-a1b2c3d4e5f6", "noo-llamacpp-agent",
		"noo-tei", "tei", "embed-ollama", "foo-noo-reranker",
		"Noo-Ollama", "noo-ollama ", "/noo-ollama",
		// rename-orphans and sidecars
		"a1b2c3d4e5f6_noo-llamacpp", "noo-stunnel-ollama", "noo-stunnel-vllm-secondary",
		// An instance-prefixed compose name is not this agent's backend: the
		// agent starts, stops and dials `noo-<backend>` only.
		"alt-ollama", "alt-vllm",
		"", "einstein", "zealous_neumann",
	} {
		if got := backendKeyFromName(name); got != "" {
			t.Errorf("%q must not be a backend, got %q", name, got)
		}
	}
}

// Stunnel sidecars still map back to the backend they front, by exact name.
func TestStunnelBackendKeyIsExact(t *testing.T) {
	for name, want := range map[string]string{
		"noo-stunnel-vllm":           "vllm",
		"noo-stunnel-vllm-secondary": "vllm-secondary",
		"noo-stunnel-llamacpp":       "llamacpp",
		"noo-stunnel-ollama":         "ollama",
		"noo-stunnel-reranker":       "reranker",
		"noo-stunnel-ollama-embed":   "",
		"other-stunnel-ollama":       "",
		"stunnel-ollama":             "",
		"noo-ollama":                 "",
	} {
		if got := stunnelBackendKey(name); got != want {
			t.Errorf("stunnelBackendKey(%q) = %q, want %q", name, got, want)
		}
	}
}
