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

// i1036: `held_images` rides the beat as the provider answers it, and is
// omitted when not wired or when the answer is empty (Docker unavailable).
func TestHeartbeatHeldImages(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	if _, ok := cap.last(&cap.beats)["held_images"]; ok {
		t.Fatal("an unwired reporter sent held_images")
	}
	r.SetHeldImages(func() map[string]bool { return nil })
	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["held_images"]; ok {
		t.Fatalf("Docker unavailable sent held_images = %v", v)
	}
	r.SetHeldImages(func() map[string]bool {
		return map[string]bool{"reg.example/acme/llamacpp-cuda:v1": false, "reg.example/acme/ollama:v1": true}
	})
	r.SendHeartbeat()
	got, ok := cap.last(&cap.beats)["held_images"].(map[string]any)
	if !ok || len(got) != 2 || got["reg.example/acme/llamacpp-cuda:v1"] != false || got["reg.example/acme/ollama:v1"] != true {
		t.Fatalf("held_images = %v", cap.last(&cap.beats)["held_images"])
	}
}
