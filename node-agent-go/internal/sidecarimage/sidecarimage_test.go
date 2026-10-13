// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package sidecarimage

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func newTracker(buf *bytes.Buffer) *Tracker {
	return &Tracker{log: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
}

// Taking the fallback twice logs exactly ONE warning, naming the published
// image that was missing, and the heartbeat value is fallback-alpine.
func TestFallbackTwiceWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	tr := newTracker(&buf)
	if got := tr.Report(); got != "" {
		t.Fatalf("Report before any choice = %q, want \"\" (key omitted)", got)
	}
	missing := []string{"ghcr.io/noomesh/stunnel:v0.2.80: manifest unknown"}
	tr.Chose("alpine:3.20", true, missing)
	tr.Chose("alpine:3.20", true, missing)
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("WARN lines = %d, want exactly 1:\n%s", n, out)
	}
	for _, want := range []string{"ghcr.io/noomesh/stunnel:v0.2.80", "alpine mirror", "EVERY sidecar start"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not name %q:\n%s", want, out)
		}
	}
	if got := tr.Report(); got != FallbackAlpine {
		t.Errorf("Report = %q, want %q", got, FallbackAlpine)
	}
}

// A published image is reported as such, logs nothing, and a later
// published choice replaces an earlier fallback (the value is the LAST
// start's image, not a sticky flag).
func TestPublishedIsReportedAndSilent(t *testing.T) {
	var buf bytes.Buffer
	tr := newTracker(&buf)
	tr.Chose("ghcr.io/noomesh/stunnel:v0.2.80", false, nil)
	if got := tr.Report(); got != Published {
		t.Errorf("Report = %q, want %q", got, Published)
	}
	if buf.Len() != 0 {
		t.Errorf("published choice logged:\n%s", buf.String())
	}
	tr.Chose("alpine:3.20", true, nil)
	if got := tr.Report(); got != FallbackAlpine {
		t.Errorf("Report after fallback = %q", got)
	}
	tr.Chose("noomesh/stunnel:latest", false, nil)
	if got := tr.Report(); got != Published {
		t.Errorf("Report after published again = %q, want %q", got, Published)
	}
}
