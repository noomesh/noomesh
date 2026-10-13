// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// The bug this replaced: a bare `pai-assistant/` prefix check, left behind
// when the rename campaign updated clean's CONTAINER half to `noo-`. On a
// --dist install every image is `ghcr.io/noomesh/…`, so it matched nothing
// and reported `images_removed: 0` — which reads as "nothing to remove".
func TestIsStackImageTag(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		tag    string
		want   bool
	}{
		// The shape that used to be missed entirely.
		{"dist install", "ghcr.io/noomesh", "ghcr.io/noomesh/gateway:v0.2.20", true},
		{"dist install, other service", "ghcr.io/noomesh", "ghcr.io/noomesh/node-agent:v0.2.20", true},
		// The local build name, which is compose's fallback.
		{"source build", "", "pai-assistant/gateway:latest", true},
		{"source build, explicit prefix", "pai-assistant", "pai-assistant/worker:latest", true},
		// Prefix-less images the stack builds for itself.
		{"unprefixed noo image", "ghcr.io/noomesh", "noo-sandbox-base:latest", true},
		{"unprefixed noo image, source build", "", "noo-browser:latest", true},

		// Everything else must survive: these are upstream images the node
		// pulled, and removing them turns a clean into a re-download.
		{"upstream vllm", "ghcr.io/noomesh", "vllm/vllm-openai:v0.25.0", false},
		{"upstream ollama", "", "ollama/ollama:latest", false},
		{"upstream python", "", "python:3.12-slim", false},
		{"upstream nats", "", "nats:latest", false},
		{"upstream llama.cpp", "", "ghcr.io/ggml-org/llama.cpp:server", false},
		// A different deployment's images on a shared host.
		{"another prefix", "ghcr.io/noomesh", "ghcr.io/someone-else/gateway:1", false},
		// Near-misses on the unprefixed rule.
		{"not ours despite noo in the name", "", "vendor/noo-thing:1", false},
		{"empty tag", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NOO_IMAGE_PREFIX", tc.prefix)
			if got := IsStackImageTag(tc.tag); got != tc.want {
				t.Errorf("IsStackImageTag(%q) with prefix %q = %v, want %v",
					tc.tag, tc.prefix, got, tc.want)
			}
		})
	}
}

// The old check, kept as an explicit record of what it missed. If someone
// reintroduces a hardcoded prefix, this says why that is wrong.
func TestTheOldPrefixCheckMissedEveryDistInstall(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	for _, tag := range []string{
		"ghcr.io/noomesh/gateway:v0.2.20",
		"noo-sandbox-base:latest",
	} {
		if !IsStackImageTag(tag) {
			t.Errorf("%s must be recognised as ours", tag)
		}
	}
}
