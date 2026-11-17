// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// `ollama_verify` is omitted until a check has run, then carries the rows.
func TestHeartbeatCarriesOllamaVerify(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["ollama_verify"]; ok {
		t.Fatal("an unwired reporter sent ollama_verify")
	}
	r.SetOllamaVerify(func() any { return nil })
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["ollama_verify"]; ok {
		t.Fatal("nothing checked yet, but ollama_verify was sent")
	}
	r.SetOllamaVerify(func() any {
		return []map[string]string{{"model": "harrier", "state": "verified", "anchor": "gguf", "model_layer": "sha256:ab"}}
	})
	r.SendHeartbeat()
	rows, _ := cap.last(&cap.beats)["ollama_verify"].([]any)
	if len(rows) != 1 {
		t.Fatalf("ollama_verify = %v", cap.last(&cap.beats)["ollama_verify"])
	}
	if row, _ := rows[0].(map[string]any); row["model_layer"] != "sha256:ab" || row["state"] != "verified" {
		t.Fatalf("row = %v", rows[0])
	}
}
