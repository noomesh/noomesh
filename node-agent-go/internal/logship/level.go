// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"regexp"
	"strings"
)

// Level extraction is a cheap classifier, not a parser. It exists so a
// LogQL `{level="error"}` works across a fleet whose lines come from
// tracing (`2026-… WARN gateway: …`), structlog (`[warning  ]`), Python
// logging (`WARNING`), vLLM (`INFO 09-28 …`), llama.cpp (`warn: …`), slog
// JSON (`"level":"WARN"`) and logfmt (`level=error`). Anything it cannot
// place is "unknown" — an honest unknown, never a guessed "info".
var (
	jsonLevelRe = regexp.MustCompile(`"level"\s*:\s*"([A-Za-z]+)"`)
	kvLevelRe   = regexp.MustCompile(`(?:^|[\s,{])level=([A-Za-z]+)`)
	// Up to three leading tokens (timestamps, a pid, a bracket) before the
	// level word, so `2026-09-28T10:00:00Z  INFO …` and `INFO 09-28 …` both
	// match; the word must end there (`INFOrmation` does not).
	leadLevelRe = regexp.MustCompile(`(?i)^(?:\S+\s+){0,3}\[?\s*(trace|debug|dbg|info|warn|warning|error|err|critical|fatal)\b`)
)

// ExtractLevel classifies one line as debug|info|warn|error or "unknown".
func ExtractLevel(line string) string {
	if len(line) > 512 {
		line = line[:512]
	}
	if m := jsonLevelRe.FindStringSubmatch(line); m != nil {
		return normaliseLevel(m[1])
	}
	if m := kvLevelRe.FindStringSubmatch(line); m != nil {
		return normaliseLevel(m[1])
	}
	if m := leadLevelRe.FindStringSubmatch(line); m != nil {
		return normaliseLevel(m[1])
	}
	return LevelUnknown
}

func normaliseLevel(s string) string {
	switch strings.ToLower(s) {
	case "trace", "debug", "dbg":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error", "err", "critical", "fatal":
		return "error"
	}
	return LevelUnknown
}

// levelFromPriority maps a journald PRIORITY (syslog severity) to the same
// four values, for journal records whose MESSAGE carries no level word.
func levelFromPriority(p string) string {
	switch p {
	case "0", "1", "2", "3":
		return "error"
	case "4":
		return "warn"
	case "5", "6":
		return "info"
	case "7":
		return "debug"
	}
	return LevelUnknown
}
