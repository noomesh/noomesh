// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// i1036: the beat carries `image_store_free_bytes` when known (0 included)
// and omits it when unknown or not wired, never sending 0 for unknown.
func TestHeartbeatImageStoreFreeBytes(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["image_store_free_bytes"]; ok {
		t.Fatal("an unwired reporter sent image_store_free_bytes")
	}

	r.SetImageStoreFreeBytes(func() (int64, bool) { return 0, false })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["image_store_free_bytes"]; ok {
		t.Fatalf("an unknown value sent image_store_free_bytes = %v", v)
	}

	r.SetImageStoreFreeBytes(func() (int64, bool) { return 7_100_000_000, true })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["image_store_free_bytes"].(float64); !ok || v != 7_100_000_000 {
		t.Fatalf("image_store_free_bytes = %v", cap.last(&cap.beats)["image_store_free_bytes"])
	}

	r.SetImageStoreFreeBytes(func() (int64, bool) { return 0, true })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["image_store_free_bytes"].(float64); !ok || v != 0 {
		t.Fatalf("a full disk reported %v", cap.last(&cap.beats)["image_store_free_bytes"])
	}
}
