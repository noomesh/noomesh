// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"syscall"
	"time"
)

// 0.6.28-rc.3, a hosted host-mode agent: the readiness nudge (#1382) fired
// 1.7 s after noo-ollama started, because `ollama list` answered INSIDE the
// container. The import it brought dials Ollama's API through the mTLS door,
// the separate noo-stunnel-ollama sidecar, which was not yet a resolvable
// container: "lookup noo-stunnel-ollama ... no such host", and the failure
// took the 10-minute import backoff. Two rules since:
//
//   - ready means the import's own path answers: an HTTP answer through
//     the door the import will dial (importDoorReady);
//   - an import that failed because that door could not be dialled
//     (doorNotUp, typed errors only) is retried quickly, a bounded few
//     times (importDoorRetryAfter), before the normal backoff applies.

// importDoorRetryAfter spaces the quick retries after a dial-level import
// failure: one nudge each, 56 s in all. A door still not up after the last
// one takes the normal backoff (ollamaPullRetryAfter) with its refusal.
var importDoorRetryAfter = []time.Duration{
	3 * time.Second, 6 * time.Second, 12 * time.Second, 15 * time.Second, 20 * time.Second,
}

// doorNotUp says whether err is the import failing to reach Ollama at all:
// the door's name did not resolve, the dial failed, or it was refused. It
// reads the error's TYPE, never its message: an HTTP failure whose text says
// "lookup" is an answer from the door, not a door that is not up.
func doorNotUp(err error) bool {
	if err == nil {
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
	return errors.Is(err, syscall.ECONNREFUSED)
}

// importDoorReady is the one definition of "a started ollama is ready": the
// Ollama API the import dials answers through its door (door is
// docker.Client.OllamaImportDoorAnswers in production).
func importDoorReady(door func(context.Context) error) func(context.Context, string, string) bool {
	return func(ctx context.Context, backend, model string) bool {
		if backend != "ollama" || door == nil {
			return false
		}
		if derr := door(ctx); derr != nil {
			slog.Debug("reconcile.backend_ready_door_not_yet", "backend", backend, "model", model, "error", derr)
			return false
		}
		return true
	}
}

// after runs f once d from now (time.AfterFunc; injected for tests).
func (r *Reconciler) after(d time.Duration, f func()) {
	if r.afterFunc != nil {
		r.afterFunc(d, f)
		return
	}
	time.AfterFunc(d, f)
}
