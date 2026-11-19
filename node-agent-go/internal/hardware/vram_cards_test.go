// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"errors"
	"reflect"
	"runtime"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// A node with two 24 GB cards (Tesla P40s): vram_gb stays ONE card, the
// per-card list and the total come from the same memory.total query.

func TestDetectVRAMCardsSumsEveryLine(t *testing.T) {
	fakeSmi(t, `case "$1" in
--query-gpu=memory.total) printf '24576\n24576\n';;
esac`)
	vram, cards, err := NewGPUDetector().DetectVRAMCards()
	if err != nil {
		t.Fatal(err)
	}
	if vram != 24 {
		t.Fatalf("vram_gb must stay one card: got %v", vram)
	}
	if !reflect.DeepEqual(cards, []float64{24, 24}) {
		t.Fatalf("cards = %v, want [24 24]", cards)
	}
	if got := SumVRAM(cards); got != 48 {
		t.Fatalf("vram_total_gb = %v, want 48", got)
	}
}

// A line that is not a number makes the list unknown (nil), never a partial
// list; vram_gb (the first line) stands as before.
func TestDetectVRAMCardsUnparseableLaterLineDropsOnlyTheList(t *testing.T) {
	fakeSmi(t, `case "$1" in
--query-gpu=memory.total) printf '24576\n[N/A]\n';;
esac`)
	vram, cards, err := NewGPUDetector().DetectVRAMCards()
	if err != nil || vram != 24 || cards != nil {
		t.Fatalf("got (%v, %v, %v), want (24, nil, nil)", vram, cards, err)
	}
}

type cardsGPU struct {
	fakeGPU
	cards []float64
}

func (c cardsGPU) DetectVRAMCards() (float64, []float64, error) {
	return c.vram, c.cards, c.err
}

// Detect's cases use 2 GB cards: Detect reads the host's RAM, and a card as
// large as the RAM reads as unified memory (one pool, no list), so a 24 GB
// card on a small test host would test the host, not the code.
func discreteHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("Detect treats every darwin host as unified memory")
	}
}

func TestDetectVRAMTotalIsTheSumOfTheCards(t *testing.T) {
	discreteHost(t)
	gpu := cardsGPU{fakeGPU: fakeGPU{vram: 2, count: 2, model: "Tesla P40"}, cards: []float64{2, 2}}
	caps, err := Detect(&config.Config{}, gpu, nil)
	if err != nil {
		t.Fatal(err)
	}
	if caps.VRAMGB != 2 || caps.VRAMTotalGB != 4 || !reflect.DeepEqual(caps.GPUVRAMGB, []float64{2, 2}) {
		t.Fatalf("vram_gb=%v vram_total_gb=%v gpu_vram_gb=%v", caps.VRAMGB, caps.VRAMTotalGB, caps.GPUVRAMGB)
	}
}

// A failed probe with nothing earlier: vram_gb is 0 and both new fields are
// omitted, as vram_gb is.
func TestDetectVRAMTotalOmittedOnProbeFailure(t *testing.T) {
	discreteHost(t)
	gpu := cardsGPU{fakeGPU: fakeGPU{err: errors.New("nvidia-smi memory.total: context deadline exceeded")}, cards: []float64{24, 24}}
	caps, err := Detect(&config.Config{}, gpu, nil)
	if err == nil {
		t.Fatal("want the probe error")
	}
	if caps.VRAMTotalGB != 0 || caps.GPUVRAMGB != nil {
		t.Fatalf("a failed probe must omit the total and the list: %v %v", caps.VRAMTotalGB, caps.GPUVRAMGB)
	}
}

// A configured VRAM_GB names one card: total = that, no list.
func TestDetectVRAMTotalConfiguredIsOneCard(t *testing.T) {
	discreteHost(t)
	gpu := cardsGPU{fakeGPU: fakeGPU{vram: 2, count: 2, model: "Tesla P40"}, cards: []float64{2, 2}}
	caps, err := Detect(&config.Config{VRAMGB: 3}, gpu, nil)
	if err != nil {
		t.Fatal(err)
	}
	if caps.VRAMGB != 3 || caps.VRAMTotalGB != 3 || caps.GPUVRAMGB != nil {
		t.Fatalf("vram_gb=%v vram_total_gb=%v gpu_vram_gb=%v", caps.VRAMGB, caps.VRAMTotalGB, caps.GPUVRAMGB)
	}
}

// The list survives a restart whose probe is slow, like vram_gb.
func TestLastGPUKeepsTheCardList(t *testing.T) {
	discreteHost(t)
	dir := t.TempDir()
	if err := SaveLastGPU(dir, Capabilities{GPUModel: "Tesla P40", VRAMGB: 2, GPUCount: 2, VRAMTotalGB: 4, GPUVRAMGB: []float64{2, 2}}); err != nil {
		t.Fatal(err)
	}
	prev := LoadLastGPU(dir)
	gpu := cardsGPU{fakeGPU: fakeGPU{err: errors.New("slow")}}
	caps, _ := Detect(&config.Config{}, gpu, prev)
	if caps.VRAMTotalGB != 4 || !reflect.DeepEqual(caps.GPUVRAMGB, []float64{2, 2}) {
		t.Fatalf("after a failed probe: vram_total_gb=%v gpu_vram_gb=%v", caps.VRAMTotalGB, caps.GPUVRAMGB)
	}
}
