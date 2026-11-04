// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelname

import "testing"

func TestMatches(t *testing.T) {
	for _, c := range []struct {
		cur, want string
		ok        bool
	}{
		{"", "", true},
		{"", "m", false},
		{"m", "", false},
		{"x.gguf", "/models/x.gguf", true},
		{"/models/x.gguf", "x.gguf", true},
		{"org/m", "org/m", true},
		{"org/a", "org/b", false},
		{"gemma4:12b", "gemma4:12b", true},
	} {
		if got := Matches(c.cur, c.want); got != c.ok {
			t.Errorf("Matches(%q,%q)=%v want %v", c.cur, c.want, got, c.ok)
		}
	}
}
