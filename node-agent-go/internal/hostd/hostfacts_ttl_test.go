// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"testing"
	"time"
)

// A reading that says tailscale is not connected is re-read within a minute;
// a healthy one keeps the five-minute cache.
func TestFactsTTLRereadsANotConnectedTailscaleSooner(t *testing.T) {
	on, off := true, false
	cases := []struct {
		name string
		f    *HostFacts
		want time.Duration
	}{
		{"no facts yet", nil, 0},
		{"running and online", &HostFacts{TailscaleState: "Running", TailscaleOnline: &on}, hostFactsInterval},
		{"no tailscale on this host", &HostFacts{}, hostFactsInterval},
		{"booting: NoState", &HostFacts{TailscaleState: "NoState", TailscaleOnline: &off}, hostFactsRecheckInterval},
		{"starting", &HostFacts{TailscaleState: "Starting"}, hostFactsRecheckInterval},
		{"running but offline", &HostFacts{TailscaleState: "Running", TailscaleOnline: &off}, hostFactsRecheckInterval},
	}
	for _, c := range cases {
		if got := factsTTL(c.f); got != c.want {
			t.Errorf("%s: factsTTL = %v, want %v", c.name, got, c.want)
		}
	}
	if hostFactsRecheckInterval >= hostFactsInterval {
		t.Fatalf("the re-check must be sooner than the normal interval")
	}
}
