// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"regexp"
	"testing"
)

// The applier parses exactly this shape (noo-apply.sh hostd_generation_of).
func TestHostdGenerationMarkerShape(t *testing.T) {
	if !regexp.MustCompile(`^noo-hostd-generation=[0-9]{2};$`).MatchString(hostdGenerationMarker) {
		t.Fatalf("marker %q is not noo-hostd-generation=NN;", hostdGenerationMarker)
	}
}
