// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// `llamacpp_offload` is omitted where it is not wired or nothing started on
// the GPU, then carries the provider's report as sent.
func TestHeartbeatCarriesLlamacppOffload(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "GTX 1080", vram: 8, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["llamacpp_offload"]; ok {
		t.Fatal("an unwired reporter sent llamacpp_offload")
	}
	r.SetLlamacppOffload(func() any { return nil })
	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["llamacpp_offload"]; ok {
		t.Fatal("no GPU start, yet llamacpp_offload was sent")
	}
	r.SetLlamacppOffload(func() any {
		return []map[string]any{{"backend": "llamacpp", "model": "m.gguf", "target": "gpu", "state": "cpu",
			"cuda_devices": 0, "failure": "CUDA driver version is insufficient for CUDA runtime version", "checked_at": "t"}}
	})
	r.SendHeartbeat()
	lo, _ := cap.last(&cap.beats)["llamacpp_offload"].([]any)
	if len(lo) != 1 {
		t.Fatalf("llamacpp_offload = %v", cap.last(&cap.beats)["llamacpp_offload"])
	}
	if e, _ := lo[0].(map[string]any); e["state"] != "cpu" || e["failure"] == "" {
		t.Fatalf("entry = %v", lo[0])
	}
}
