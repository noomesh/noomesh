// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package harnessprofile

import (
	"encoding/json"
	"testing"
)

func TestParseAbsentAndNullAreNoProfile(t *testing.T) {
	for _, raw := range []string{"", "null"} {
		p, err := Parse(json.RawMessage(raw))
		if p != nil || err != nil {
			t.Errorf("Parse(%q) = %v, %v; want nil, nil", raw, p, err)
		}
	}
}

func TestParseTheResolvedShape(t *testing.T) {
	raw := `{"tier": 2, "first_byte_secs": 600, "stream_idle_secs": 300, "thinking": "off", "context": 32768,
	 "claude_prompt": "slim", "foreign_kinds": ["claude-code","codex"],
	 "sources": {"first_byte_secs": "measured"}, "bench": null, "future_field": 1}`
	p, err := Parse(json.RawMessage(raw))
	if err != nil || p == nil {
		t.Fatalf("Parse: %v %v", p, err)
	}
	if p.Tier != 2 || p.FirstByteSecs != 600 || p.Context != 32768 || p.Thinking != "off" ||
		p.ClaudePrompt != "slim" || p.Sources["first_byte_secs"] != "measured" {
		t.Errorf("parsed %+v", p)
	}
	if !p.Offers("codex") || p.Offers("copilot") {
		t.Errorf("Offers: %v", p.ForeignKinds)
	}
	// The raw object is kept whole for the harness, unknown fields included.
	var back map[string]any
	if err := json.Unmarshal(p.Raw, &back); err != nil || back["future_field"] != float64(1) {
		t.Errorf("raw not kept: %s", p.Raw)
	}
}

func TestParseRefusesAMalformedProfileAndDropsNonPositiveNumbers(t *testing.T) {
	if _, err := Parse(json.RawMessage(`{"first_byte_secs": "soon"}`)); err == nil {
		t.Error("a malformed profile must be an error (the caller keeps the last good one)")
	}
	p, err := Parse(json.RawMessage(`{"first_byte_secs": -5, "context": -1}`))
	if err != nil || p.FirstByteSecs != 0 || p.Context != 0 {
		t.Errorf("non-positive numbers must read as unset: %+v %v", p, err)
	}
}

// A controller older than 0.6.13 names the context `ollama_context` (i226
// decision 1); a newer one sends both, and `context` wins.
func TestParseReadsTheContextUnderEitherName(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{`{"ollama_context": 16384}`, 16384},
		{`{"context": 32768, "ollama_context": 32768}`, 32768},
		{`{"context": 8192, "ollama_context": 4096}`, 8192},
		{`{"ollama_context": -1}`, 0},
	} {
		p, err := Parse(json.RawMessage(tc.raw))
		if err != nil || p.Context != tc.want {
			t.Errorf("Parse(%s).Context = %v (%v), want %d", tc.raw, p.Context, err, tc.want)
		}
	}
}

func TestSetAndCurrent(t *testing.T) {
	t.Cleanup(func() { Set(nil) })
	Set(nil)
	if Current() != nil {
		t.Fatal("no profile by default")
	}
	Set(&Profile{FirstByteSecs: 600})
	if Current().FirstByteSecs != 600 {
		t.Fatal("Set not seen")
	}
	Set(nil)
	if Current() != nil {
		t.Fatal("Set(nil) must clear")
	}
}
