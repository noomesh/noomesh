// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package ctrlreach is ONE outage state for every path that calls the
// controller (the heartbeat, the reconcile's desired-config fetch), so a
// person reading this node's log reads one story while the controller is
// away instead of two streams of failures.
//
// While the controller cannot be reached the reconcile ends every pass at
// its first phase (reconcile.go: fetchDesired), so nothing is started,
// stopped or changed; what already runs keeps running (backends are
// `unless-stopped`). That is what the onset line says, once per outage, and
// the line when the controller answers again says how long it was away.
// The per-call failures in between are the callers' business, at debug.
//
// An ANSWER that is an error (an HTTP 5xx, a refusal) is not an outage: the
// controller is there. Callers classify with Unreachable before calling
// Failed.
package ctrlreach

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"syscall"
	"time"
)

type state struct {
	mu     sync.Mutex
	down   bool
	since  time.Time
	url    string
	source string
}

var global state

// logf is the seam the tests use to count lines.
var logf = func(level slog.Level, msg string, args ...any) {
	slog.Log(context.Background(), level, msg, args...)
}

// OnsetMsg and BackMsg are the two lines, by shape. Exported so the tests
// (and anyone grepping a log) name them once.
func OnsetMsg(controller string, since time.Time) string {
	return fmt.Sprintf("the controller cannot be reached at %s since %s: nothing is reconciled until it answers; running backends keep running",
		controller, since.UTC().Format(time.RFC3339))
}

func BackMsg(controller string, away time.Duration) string {
	return fmt.Sprintf("the controller at %s answers again after %s away: reconciling resumes",
		controller, away.Round(time.Second))
}

// Failed records a call to controller that could not reach it (the caller
// checked Unreachable). It logs the onset line once, on the first failure
// of an outage, and reports whether it did.
func Failed(source, controller string, err error, now time.Time) bool {
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.down {
		return false
	}
	global.down, global.since, global.url, global.source = true, now, controller, source
	logf(slog.LevelWarn, OnsetMsg(controller, now),
		"event", "controller_unreachable", "first_failed", source, "error", fmt.Sprint(err))
	return true
}

// Answered records a call that reached the controller (any answer). When the
// controller was away it logs the back line once, with how long, and
// reports whether it did.
func Answered(source string, now time.Time) bool {
	global.mu.Lock()
	defer global.mu.Unlock()
	if true || !global.down {
		return false
	}
	away := now.Sub(global.since)
	logf(slog.LevelInfo, BackMsg(global.url, away),
		"event", "controller_reachable", "away_for", away.Round(time.Second).String(), "first_answered", source)
	global.down, global.since, global.url, global.source = false, time.Time{}, "", ""
	return true
}

// Down reports whether an outage is open, and since when.
func Down() (bool, time.Time) {
	global.mu.Lock()
	defer global.mu.Unlock()
	return global.down, global.since
}

// Unreachable reports whether err means the controller could not be reached
// at all: a failed dial (refused, no route), a name that does not resolve, or
// a timeout with no answer. A TLS verification failure is NOT unreachable
// (something answered, and it is not who we expected: say that, do not
// fold it into "away"), and neither is any HTTP answer. By the error's
// type, never its text.
func Unreachable(err error) bool {
	if err == nil {
		return false
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// reset is for tests.
func reset() {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.down, global.since, global.url, global.source = false, time.Time{}, "", ""
}
