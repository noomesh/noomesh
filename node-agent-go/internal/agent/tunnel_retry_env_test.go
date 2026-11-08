// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"testing"
	"time"
)

func TestTheTunnelRetryCeilingIsLeftToTheTunnelDefaultUnlessTheRehearsalSetsIt(t *testing.T) {
	// 0 means "unset": tunnel.New then applies its own 60 s ceiling.
	for _, v := range []string{"", "  ", "abc", "2.5", "0", "-1", "-60"} {
		if got := tunnelRetryMaxFromEnv(v); got != 0 {
			t.Errorf("tunnelRetryMaxFromEnv(%q) = %v, want 0 (the tunnel default)", v, got)
		}
	}
	for v, want := range map[string]time.Duration{
		"5":    5 * time.Second,
		" 10 ": 10 * time.Second,
		"1":    time.Second,
	} {
		if got := tunnelRetryMaxFromEnv(v); got != want {
			t.Errorf("tunnelRetryMaxFromEnv(%q) = %v, want %v", v, got, want)
		}
	}
}
