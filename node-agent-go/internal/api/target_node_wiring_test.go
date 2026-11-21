// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"os"
	"strings"
	"testing"
)

// i1174: both HTTPS listeners serve through the target-node check, so a
// call addressed to another node is refused before any route sees it.
func TestEveryListenerChecksTheTargetNode(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	if n := strings.Count(code, "Handler:   auth.TargetNode(s.cfg)(s.mux),"); n != 2 {
		t.Fatalf("listeners wrapped in auth.TargetNode: %d, want 2", n)
	}
	if strings.Contains(code, "Handler:   s.mux,") {
		t.Fatal("a listener serves s.mux without the target-node check")
	}
}
