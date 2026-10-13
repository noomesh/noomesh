// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logring

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRingKeepsTheLastLinesInOrder(t *testing.T) {
	r := New(3)
	for _, l := range []string{"a", "b"} {
		r.Add(l)
	}
	if got := strings.Join(r.Tail(0), ","); got != "a,b" {
		t.Fatalf("before wrap: %q", got)
	}
	for _, l := range []string{"c", "d", "e"} {
		r.Add(l)
	}
	if got := strings.Join(r.Tail(0), ","); got != "c,d,e" {
		t.Fatalf("after wrap: %q", got)
	}
	if got := strings.Join(r.Tail(2), ","); got != "d,e" {
		t.Fatalf("tail 2: %q", got)
	}
	if got := strings.Join(r.Tail(50), ","); got != "c,d,e" {
		t.Fatalf("tail beyond held: %q", got)
	}
}

func TestTeeWritesTheSameRecordToStdoutAndTheRing(t *testing.T) {
	var out bytes.Buffer
	ring := New(10)
	h := NewTee(
		slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewJSONHandler(ring, &slog.HandlerOptions{Level: slog.LevelInfo}),
	)
	log := slog.New(h).With("node", "host3")
	log.Info("reconcile.start_failed", "backend", "ollama")
	log.Debug("ignored below level")
	lines := ring.Tail(0)
	if len(lines) != 1 || !strings.Contains(lines[0], "reconcile.start_failed") || !strings.Contains(lines[0], `"node":"host3"`) {
		t.Fatalf("ring = %v", lines)
	}
	if !strings.Contains(out.String(), "reconcile.start_failed") {
		t.Fatalf("stdout = %q", out.String())
	}
}
