// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import "testing"

// The discovery offer must name the address the controller can dial (the
// agent's registered proxy URL), never the backend's container-internal URL.
func TestMeshBackendInfos_OffersReachableAgentURL(t *testing.T) {
	got := meshBackendInfos(map[string]string{"vllm": "m", "ollama": "o"}, "https://192.0.2.1:8081", "https")
	if len(got) != 2 {
		t.Fatalf("want 2 offers, got %v", got)
	}
	for bt, info := range got {
		if info.URL != "https://192.0.2.1:8081" {
			t.Errorf("%s offered %q, want the node-agent proxy address", bt, info.URL)
		}
	}
}

// No dialable host IP: nothing better to name, so the legacy container URL is
// offered (the gateway treats it as advisory) rather than going undiscoverable.
func TestMeshBackendInfos_NoDialableAddressKeepsLegacyURL(t *testing.T) {
	got := meshBackendInfos(map[string]string{"vllm": "m"}, "", "https")
	if got["vllm"].URL == "" {
		t.Fatal("backend must still be offered when the node has no dialable address")
	}
}

func TestMeshBackendInfos_SkipsUnknownBackends(t *testing.T) {
	if got := meshBackendInfos(map[string]string{"nonesuch": "m"}, "https://1.2.3.4:8081", "https"); len(got) != 0 {
		t.Fatalf("unknown backend offered: %v", got)
	}
}
