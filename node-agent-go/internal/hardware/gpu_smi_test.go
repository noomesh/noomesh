// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"encoding/json"
	"strings"
	"testing"
)

// nvidia-smi prints [N/A] for a sensor it cannot read. That is unknown, not 0.
func TestSmiFloatNAIsUnknown(t *testing.T) {
	for _, raw := range []string{"[N/A]", "N/A", "", "garbage"} {
		if got := smiFloat("temperature.gpu", raw); got != nil {
			t.Errorf("smiFloat(%q) = %v, want nil", raw, *got)
		}
	}
	if got := smiFloat("temperature.gpu", " 0 "); got == nil || *got != 0 {
		t.Errorf("a reported zero must stay 0, got %v", got)
	}
}

func TestGPUMetricsUnknownFieldIsAbsentOnTheWire(t *testing.T) {
	v := 41.0
	b, err := json.Marshal(&GPUMetrics{TemperatureC: &v})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"temperature_c":41`) || strings.Contains(s, "gpu_utilization_percent") {
		t.Errorf("unexpected wire shape: %s", s)
	}
}
