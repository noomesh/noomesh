// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"reflect"
	"testing"
)

// The probe itself, over a fake nvidia-smi script on a temp PATH (the host's
// real nvidia-smi is never run; see pinSmi).
func TestDetectComputeCapsOverAFakeNvidiaSmi(t *testing.T) {
	g := NewGPUDetector(nil, "http")

	fakeSmi(t, `printf '8.6\n8.9\n'`)
	if got, err := g.DetectComputeCaps(); err != nil || !reflect.DeepEqual(got, []string{"8.6", "8.9"}) {
		t.Fatalf("two GPUs = %v, %v", got, err)
	}

	// A failed probe is unknown: an error, not "no GPU".
	fakeSmi(t, `echo "field compute_cap is not valid" >&2; exit 2`)
	if got, err := g.DetectComputeCaps(); err == nil {
		t.Fatalf("a failing nvidia-smi = %v, nil; want an error (an old driver lacks the field)", got)
	}

	// [N/A] is not a capability.
	fakeSmi(t, `echo '[N/A]'`)
	if got, err := g.DetectComputeCaps(); err == nil {
		t.Fatalf("[N/A] = %v, nil; want an error", got)
	}

	// No nvidia-smi at all is the one clean "no GPU": nothing, and no error.
	noSmi(t)
	if got, err := g.DetectComputeCaps(); err != nil || len(got) != 0 {
		t.Fatalf("no nvidia-smi = %v, %v; want nothing and no error", got, err)
	}
}
