// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"os"
	"strings"
	"testing"
)

// The declared keep-warm models are kept loaded by the API server's keeper,
// and a GPU yield or hold unloads them through the pause hook. Both are wiring
// only, so the wiring is pinned here.
func TestKeepWarmIsWiredToTheKeeperAndTheGPUPause(t *testing.T) {
	src, err := os.ReadFile("agent.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"gy.OnPause(a.server.UnloadWarm)", "go a.server.RunKeepWarm(ctx)"} {
		if !strings.Contains(string(src), want) {
			t.Errorf("agent.go does not wire %q", want)
		}
	}
}
