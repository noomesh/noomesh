// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import "testing"

// SetModelSets(nil) installs a nil provider. That is "not wired", not a
// provider to call: calling it would panic inside the heartbeat.
func TestNilModelSetsProviderReportsUnknown(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedGPU{model: "RTX 4090", vram: 24, count: 1}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })
	r.SetModelSets(nil)

	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("a nil provider was called: %v", p)
			}
		}()
		if got := r.modelSetsReport(); got != nil {
			t.Errorf("modelSetsReport = %v, want nil", got)
		}
	}()

	r.SendHeartbeat()
	if v, ok := cap.last(&cap.beats)["model_sets"]; ok {
		t.Errorf("a nil provider sent model_sets = %v", v)
	}
}
