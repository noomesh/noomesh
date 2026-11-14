// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import "testing"

// i658: "no harness placement" is only an answer after a desired-config has
// been applied; before that the agent does not know.
func TestHarnessPlacementIsUnknownUntilTheFirstDesiredConfig(t *testing.T) {
	r := &Reconciler{}
	if r.HarnessPlacementKnown() {
		t.Fatal("a fresh agent must not claim to know its harness placement")
	}
	if _, _, _, placed := r.HarnessPlacementView(); placed {
		t.Fatal("nothing is placed before the first desired-config")
	}
	r.recordHarnessPlacement([]placement{{Backend: "ollama"}})
	if !r.HarnessPlacementKnown() {
		t.Fatal("after a desired-config with no harness, the answer is known: not placed")
	}
	if _, _, _, placed := r.HarnessPlacementView(); placed {
		t.Fatal("no harness placement was desired")
	}
	r.recordHarnessPlacement([]placement{{Backend: "harness", DesiredState: "running"}})
	if _, _, _, placed := r.HarnessPlacementView(); !placed || !r.HarnessPlacementKnown() {
		t.Fatal("a desired harness is known and placed")
	}
}
