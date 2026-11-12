// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"testing"
	"time"
)

func TestTheReconcileIntervalIsFiveMinutesUnlessTheRehearsalSetsIt(t *testing.T) {
	if defaultInterval != 5*time.Minute {
		t.Fatalf("the production interval moved: %v", defaultInterval)
	}
	for _, v := range []string{"", "  ", "abc", "1.5", "0", "-5", "-1"} {
		if got := intervalFromEnv(v); got != defaultInterval {
			t.Errorf("intervalFromEnv(%q) = %v, want the default %v", v, got, defaultInterval)
		}
	}
	for v, want := range map[string]time.Duration{
		"20":   20 * time.Second,
		" 45 ": 45 * time.Second,
		"1":    time.Second,
	} {
		if got := intervalFromEnv(v); got != want {
			t.Errorf("intervalFromEnv(%q) = %v, want %v", v, got, want)
		}
	}
}
