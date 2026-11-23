// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// `gguf_unverified` is omitted while no backend runs on an unvouched file,
// then carries {backend, model, reason, since}.
func TestHeartbeatCarriesGGUFUnverified(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SetGGUFUnverified(func() any { return nil })
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["gguf_unverified"]; ok {
		t.Fatal("none unvouched, but gguf_unverified was sent")
	}
	r.SetGGUFUnverified(func() any {
		return []map[string]string{{"backend": "llamacpp", "model": "m.gguf", "reason": "r", "since": "t"}}
	})
	r.SendHeartbeat()
	rows, _ := cap.last(&cap.beats)["gguf_unverified"].([]any)
	if len(rows) != 1 {
		t.Fatalf("gguf_unverified = %v", cap.last(&cap.beats)["gguf_unverified"])
	}
	if row, _ := rows[0].(map[string]any); row["backend"] != "llamacpp" || row["model"] != "m.gguf" || row["reason"] != "r" {
		t.Fatalf("row = %v", rows[0])
	}
}
