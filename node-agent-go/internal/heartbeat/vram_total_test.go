// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"errors"
	"reflect"
	"testing"
)

// scriptedCardsGPU answers the per-card probe too (a two-card node).
type scriptedCardsGPU struct {
	scriptedGPU
	cards []float64
}

func (g *scriptedCardsGPU) DetectVRAMCards() (float64, []float64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return 0, nil, g.err
	}
	return g.vram, g.cards, nil
}

func TestHeartbeatCarriesVRAMTotalBesideVRAMGB(t *testing.T) {
	srv, cap := captureServer(t)
	gpu := &scriptedCardsGPU{scriptedGPU: scriptedGPU{model: "Tesla P40", vram: 24, count: 2}, cards: []float64{24, 24}}
	r := newReporterWith(srv.URL, gpu, func() (map[string]string, error) { return map[string]string{}, nil })

	r.SendHeartbeat()
	beat := cap.last(&cap.beats)
	if beat["vram_gb"] != float64(24) {
		t.Fatalf("vram_gb must stay one card: %v", beat["vram_gb"])
	}
	if beat["vram_total_gb"] != float64(48) {
		t.Fatalf("vram_total_gb = %v, want 48", beat["vram_total_gb"])
	}
	if got := beat["gpu_vram_gb"]; !reflect.DeepEqual(got, []any{float64(24), float64(24)}) {
		t.Fatalf("gpu_vram_gb = %#v", got)
	}

	// A failed probe omits them with vram_gb.
	gpu.set("", 0, 0, errors.New("nvidia-smi memory.total: context deadline exceeded"))
	r.SendHeartbeat()
	beat = cap.last(&cap.beats)
	for _, k := range []string{"vram_gb", "vram_total_gb", "gpu_vram_gb"} {
		if _, ok := beat[k]; ok {
			t.Fatalf("a failed probe must omit %s: %v", k, beat[k])
		}
	}
}
