// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package refusals

import "testing"

// A refusal the controller never hears about is a wall the operator will
// debug as a bug. These are the properties the heartbeat contract depends
// on.
func TestRecordClearAndStability(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	if got := List(); len(got) != 0 {
		t.Fatalf("expected an empty registry, got %+v", got)
	}

	Record("models_dir", "/etc/noo", "outside the declared roots")
	first := List()
	if len(first) != 1 || first[0].Scope != "models_dir" || first[0].Since == "" {
		t.Fatalf("got %+v", first)
	}

	// Re-recorded every tick: the reason may sharpen, the clock must not
	// restart, or a standing problem looks brand new on every heartbeat.
	Record("models_dir", "/etc/noo", "outside the declared roots (still)")
	again := List()
	if len(again) != 1 {
		t.Fatalf("re-recording must not duplicate: %+v", again)
	}
	if again[0].Since != first[0].Since {
		t.Errorf("Since must survive a re-record: %q -> %q", first[0].Since, again[0].Since)
	}
	if again[0].Reason == first[0].Reason {
		t.Errorf("the reason should have been refreshed")
	}

	// Sorted, so an unchanged set produces an unchanged heartbeat body.
	Record("placement_env", "llamacpp/LD_PRELOAD", "not a tuning key")
	Record("mcp_server", "evil", "command not allow-listed")
	l := List()
	for i := 1; i < len(l); i++ {
		if l[i-1].Scope > l[i].Scope {
			t.Fatalf("List must be sorted: %+v", l)
		}
	}

	// A fixed problem stops being reported — a registry that could only
	// grow would train operators to ignore the field.
	Clear("models_dir", "/etc/noo")
	for _, r := range List() {
		if r.Scope == "models_dir" {
			t.Fatalf("cleared refusal is still reported: %+v", r)
		}
	}
}
