// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// `node_local` carries the node's own declarations report once wired.
func TestHeartbeatCarriesNodeLocal(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["node_local"]; ok {
		t.Fatal("an unwired reporter sent node_local")
	}
	r.SetNodeLocal(func() any {
		return map[string]any{"state": "read", "declared": []string{"NOO_ALLOW_OLLAMA_REGISTRY_PULL"}, "refused": []any{}, "ignored": []string{}}
	})
	r.SendHeartbeat()
	nl, _ := cap.last(&cap.beats)["node_local"].(map[string]any)
	if d, _ := nl["declared"].([]any); len(d) != 1 || d[0] != "NOO_ALLOW_OLLAMA_REGISTRY_PULL" {
		t.Fatalf("node_local = %v", cap.last(&cap.beats)["node_local"])
	}
}
