// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"os"
	"strings"
	"testing"
)

// GET /harness/placement answers from the reconciler's tables: the decided
// Ollama contexts and the engine windows (i1411). Both copies are wiring, so
// the wiring is pinned here.
func TestHarnessPlacementCarriesTheChatTables(t *testing.T) {
	src, err := os.ReadFile("agent.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hp.ChatContexts = rec.ChatContexts()", "hp.ChatWindows = rec.ChatWindows()"} {
		if !strings.Contains(string(src), want) {
			t.Errorf("agent.go does not set %q on the harness placement", want)
		}
	}
}
