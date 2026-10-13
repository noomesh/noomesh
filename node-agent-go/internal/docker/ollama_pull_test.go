// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

func TestOllamaListHas(t *testing.T) {
	list := "NAME              ID              SIZE      MODIFIED\n" +
		"llama3.2:3b       a80c4f17acd5    2.0 GB    33 hours ago\n" +
		"harrier:latest    81eab6d62d1b    396 MB    3 days ago\n"
	cases := []struct {
		name string
		want bool
	}{
		{"llama3.2:3b", true},
		{"harrier", true}, // bare name matches :latest (import-model's shape)
		{"harrier:latest", true},
		{"llama3.2", false}, // bare name is NOT the :3b tag
		{"gemma4:12b", false},
		{"NAME", false},
	}
	for _, c := range cases {
		if got := ollamaListHas(list, c.name); got != c.want {
			t.Errorf("ollamaListHas(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOllamaTagPattern(t *testing.T) {
	for _, ok := range []string{"gemma4:12b", "nemotron-3-nano:30b-a3b-q4_K_M", "harrier", "hf.co/org/repo:Q4_K_M", "llama3.2:3b"} {
		if !ollamaTagPattern.MatchString(ok) {
			t.Errorf("%q should be a valid ref", ok)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a;b", "/abs", "name:", "$(x)"} {
		if ollamaTagPattern.MatchString(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
