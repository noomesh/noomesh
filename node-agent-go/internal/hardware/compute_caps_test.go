// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"reflect"
	"testing"
)

// nvidia-smi is never run here: this is the parser behind the probe.
func TestParseComputeCaps(t *testing.T) {
	got, err := parseComputeCaps("8.6\n 10.0 \n\n")
	if err != nil || !reflect.DeepEqual(got, []string{"8.6", "10.0"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := parseComputeCaps(""); err != nil || len(got) != 0 {
		t.Fatalf("empty output = %v, %v", got, err)
	}
	for _, bad := range []string{"[N/A]", "8", "8.6.1", "8,6", "abc", "8.6\n[N/A]"} {
		if got, err := parseComputeCaps(bad); err == nil {
			t.Errorf("parseComputeCaps(%q) = %v, want an error (unknown, not a value)", bad, got)
		}
	}
}
