// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import "testing"

// An unknown load must not be announced as 0: the key is left out, which the
// gateway reads as fully loaded.
func TestGossipAnnouncement_UnknownLoadIsAbsent(t *testing.T) {
	got := gossipAnnouncement(map[string]any{"hostname": "n"}, nil)
	if v, ok := got["load"]; ok {
		t.Errorf("load = %v announced for an unknown load, want the key absent", v)
	}
}

func TestGossipAnnouncement_KnownLoadIsAnnounced(t *testing.T) {
	l := 0.42
	got := gossipAnnouncement(map[string]any{"hostname": "n"}, &l)
	if got["load"] != 0.42 {
		t.Errorf("load = %v, want 0.42", got["load"])
	}
}
