// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// `backend_caps` is omitted where it is not wired (no Docker backends), then
// carries the provider's report, the refused names included.
func TestHeartbeatCarriesBackendCaps(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["backend_caps"]; ok {
		t.Fatal("an unwired reporter sent backend_caps")
	}
	r.SetBackendCaps(func() any {
		return map[string]any{"source": "env", "granted": []string{"CHOWN"}, "refused": []string{"SYS_ADMIN"}, "allowed": []string{"CHOWN"}}
	})
	r.SendHeartbeat()
	bc, _ := cap.last(&cap.beats)["backend_caps"].(map[string]any)
	refused, _ := bc["refused"].([]any)
	if len(refused) != 1 || refused[0] != "SYS_ADMIN" {
		t.Fatalf("backend_caps = %v", cap.last(&cap.beats)["backend_caps"])
	}
}
