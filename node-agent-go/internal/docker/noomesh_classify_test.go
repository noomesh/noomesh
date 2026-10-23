// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

func TestClassifyNoomesh(t *testing.T) {
	tests := []struct {
		name         string
		ctr          string
		labels       map[string]string
		owned, orphn bool
	}{
		{"compose stack embedder", "noo-ollama-embed", map[string]string{"com.docker.compose.project": "noomesh"}, true, false},
		{"stack container with a custom prefix", "acme-tei", map[string]string{"com.docker.compose.project": "noomesh"}, true, false},
		{"agent backend", "noo-vllm", map[string]string{"noo.managed-by": "node-agent-go", "com.docker.compose.project": "pai-assistant"}, true, false},
		{"older container, name only", "noo-ollama", nil, true, true},
		{"pai-voice", "pai-voice", map[string]string{"com.docker.compose.project": "pai-voice"}, false, false},
		{"foreign container that merely mentions ollama", "my-ollama", nil, false, false},
		{"buildx builder", "buildx_buildkit_x0", map[string]string{}, false, false},
	}
	for _, tc := range tests {
		o, or := ClassifyNoomesh(tc.ctr, tc.labels, "")
		if o != tc.owned || or != tc.orphn {
			t.Errorf("%s: got owned=%v orphan=%v", tc.name, o, or)
		}
	}
}
