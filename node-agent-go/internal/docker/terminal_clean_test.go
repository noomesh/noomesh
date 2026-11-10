// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"
)

// The start of the "ollama model created" detail the outside tester pasted
// from `noo cluster logs` on 0.6.21 (JSON-escaped there): an OSC 11
// background-colour query ended by ST, a CSI 6n cursor-position query, then
// the renderer's synchronized-output and cursor-hide sequences.
const testerDetailStart = "\x1b]11;?\x1b\\\x1b[6n\x1b[?2026h\x1b[?25l"

// What Ollama 0.40.5's progress renderer (progress/progress.go) writes around
// each frame.
var ollamaRenderer = []string{
	"\x1b[?2026h", "\x1b[?2026l", "\x1b[?25l", "\x1b[?25h",
	"\x1b[A", "\x1b[1G", "\x1b[K", "\x1b[2K\x1b[1G",
}

func TestTheTestersDetailCleansToTheLastStatus(t *testing.T) {
	out := testerDetailStart +
		"gathering model components \x1b[K\r" +
		"copying file sha256:4f2a 100% \x1b[K\n" +
		"\x1b[A\x1b[2K\x1b[1Gparsing GGUF \x1b[K\n" +
		"writing manifest \x1b[K\n" +
		"success \x1b[K\x1b[?25h\x1b[?2026l"
	got := lastLine(out)
	if got != "success" {
		t.Fatalf("lastLine = %q, want %q", got, "success")
	}
	if strings.ContainsAny(cleanTerminal(out), "\x1b\x07") {
		t.Fatalf("an escape survived: %q", cleanTerminal(out))
	}
}

func TestEveryRendererSequenceIsRemoved(t *testing.T) {
	for _, seq := range append(ollamaRenderer, testerDetailStart) {
		if got := cleanTerminal("a" + seq + "b"); got != "ab" {
			t.Errorf("cleanTerminal(a %q b) = %q, want \"ab\"", seq, got)
		}
	}
}

// The two queries make a terminal answer back. OSC may end with BEL as well
// as ST, and an unterminated one must not leak the rest of the line.
func TestQueriesAreRemovedWhateverEndsThem(t *testing.T) {
	cases := map[string]string{
		"OSC 11 ended by ST":  "a\x1b]11;?\x1b\\b",
		"OSC 11 ended by BEL": "a\x1b]11;?\x07b",
		"CSI 6n":              "a\x1b[6nb",
		"title OSC 0 by BEL":  "a\x1b]0;noo-ollama\x07b",
		"DCS ended by ST":     "a\x1bP1$r0m\x1b\\b",
	}
	for name, in := range cases {
		if got := cleanTerminal(in); got != "ab" {
			t.Errorf("%s: cleanTerminal(%q) = %q, want \"ab\"", name, in, got)
		}
	}
	if got := cleanTerminal("ok\x1b]11;?"); got != "ok" {
		t.Errorf("unterminated OSC: %q, want \"ok\"", got)
	}
}

func TestSpinnerFramesKeepTheLastFrameAndCRLFIsALineEnding(t *testing.T) {
	if got := cleanTerminal("⠋ copying\r⠙ copying\r⠹ copying 40%"); got != "⠹ copying 40%" {
		t.Errorf("spinner: %q", got)
	}
	if got := cleanTerminal("first\r\nsecond\r\n"); got != "first\nsecond\n" {
		t.Errorf("CRLF: %q", got)
	}
}

func TestPlainOutputIsUnchanged(t *testing.T) {
	plain := "Loaded image: noomesh/llamacpp:0.6.21\ntab\there ünïcode"
	if got := cleanTerminal(plain); got != plain {
		t.Errorf("plain output changed: %q", got)
	}
	if got := lastLine("Loaded image: noomesh/llamacpp:0.6.21\n\n"); got != "Loaded image: noomesh/llamacpp:0.6.21" {
		t.Errorf("trailing blank lines: %q", got)
	}
	if got := lastLine(""); got != "" {
		t.Errorf("empty: %q", got)
	}
}
