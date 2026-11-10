// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "strings"

// cleanTerminal removes what a terminal program writes for a terminal, not
// for a log: escape sequences, spinner frames and other control bytes.
//
// An exec's output ends up in the journal and in `noo cluster logs`. Run with
// a TTY, `ollama create` began its output with a background-colour query
// (OSC 11), a cursor-position query (CSI 6n) and its renderer's
// synchronized-output and cursor sequences. Those are queries a terminal
// answers, so they must never reach an operator's terminal verbatim.
//
// Removed:
//   - CSI: ESC [ parameter bytes, intermediate bytes, one final byte;
//   - OSC, DCS, SOS, PM and APC strings: ESC ] / P / X / ^ / _ up to BEL or
//     ST (ESC \); an unterminated one runs to the end of the input;
//   - any other two-byte escape (ESC 7, ESC =, a lone ESC \);
//   - spinner frames: on each line only the text after the last carriage
//     return is kept (a CRLF line ending is not a frame);
//   - every other C0 control byte and DEL, except newline and tab.
func cleanTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b {
			i = skipEscape(s, i)
			continue
		}
		if c == '\n' || c == '\t' || c == '\r' {
			b.WriteByte(c)
			continue
		}
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	lines := strings.Split(b.String(), "\n")
	for k, line := range lines {
		line = strings.TrimRight(line, "\r")
		if j := strings.LastIndexByte(line, '\r'); j >= 0 {
			line = line[j+1:]
		}
		lines[k] = line
	}
	return strings.Join(lines, "\n")
}

// skipEscape returns the index of the last byte of the escape sequence that
// starts at s[i] (an ESC).
func skipEscape(s string, i int) int {
	if i+1 >= len(s) {
		return i
	}
	switch s[i+1] {
	case '[':
		j := i + 2
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			return j
		}
		return j - 1
	case ']', 'P', 'X', '^', '_':
		for j := i + 2; j < len(s); j++ {
			if s[j] == 0x07 {
				return j
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 1
			}
		}
		return len(s) - 1
	default:
		return i + 1
	}
}

// lastLine is the last non-empty line of a command's output, cleaned of
// terminal control (cleanTerminal), for a one-line log detail or error.
func lastLine(s string) string {
	lines := strings.Split(s, "\n")
	for k := len(lines) - 1; k >= 0; k-- {
		if l := strings.TrimSpace(lines[k]); l != "" {
			return l
		}
	}
	return ""
}
