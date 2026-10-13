// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package logring keeps the agent's own recent log lines in memory so the
// controller can read them over the same authenticated API it reads a
// container's logs from.
//
// The agent has been a host process since the fleet hardening (systemd
// unit on Linux, launchd on macOS), but `noo cluster logs <node>` still
// asked the agent for a CONTAINER named noo-node-agent — HTTP 500 "No such
// container" on every node, and nothing to read when a placement did not
// converge. Reading the journal from the unprivileged agent
// is not portable (journal group on Linux, a file path on darwin); a ring
// the agent fills itself is, and it is the same lines the journal holds.
package logring

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Ring is a fixed-capacity buffer of formatted log lines, newest last.
type Ring struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

// New returns a ring that keeps the last `capacity` lines.
func New(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{lines: make([]string, capacity)}
}

// Add appends one line, evicting the oldest when full.
func (r *Ring) Add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines[r.next] = strings.TrimRight(line, "\n")
	r.next = (r.next + 1) % len(r.lines)
	if r.next == 0 {
		r.full = true
	}
}

// Tail returns the last n lines in order (all of them when n <= 0 or n
// exceeds what is held).
func (r *Ring) Tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	if r.full {
		out = append(out, r.lines[r.next:]...)
		out = append(out, r.lines[:r.next]...)
	} else {
		out = append(out, r.lines[:r.next]...)
	}
	if n > 0 && n < len(out) {
		out = out[len(out)-n:]
	}
	return out
}

// Write lets the ring sit behind a slog handler as an io.Writer: each
// Write is one formatted record (slog's handlers write whole lines).
func (r *Ring) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			r.Add(line)
		}
	}
	return len(p), nil
}

// Tee is a slog.Handler that hands every record to two handlers — the
// process's normal output and a handler writing into the ring — so the
// journal and the ring hold the same lines.
type Tee struct {
	a, b slog.Handler
}

// NewTee returns a handler that forwards to both a and b.
func NewTee(a, b slog.Handler) *Tee { return &Tee{a: a, b: b} }

func (t *Tee) Enabled(ctx context.Context, l slog.Level) bool {
	return t.a.Enabled(ctx, l) || t.b.Enabled(ctx, l)
}

func (t *Tee) Handle(ctx context.Context, rec slog.Record) error {
	var first error
	if t.a.Enabled(ctx, rec.Level) {
		first = t.a.Handle(ctx, rec.Clone())
	}
	if t.b.Enabled(ctx, rec.Level) {
		if err := t.b.Handle(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (t *Tee) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Tee{a: t.a.WithAttrs(attrs), b: t.b.WithAttrs(attrs)}
}

func (t *Tee) WithGroup(name string) slog.Handler {
	return &Tee{a: t.a.WithGroup(name), b: t.b.WithGroup(name)}
}
