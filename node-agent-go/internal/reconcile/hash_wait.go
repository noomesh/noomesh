// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"fmt"
	"log/slog"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// A roll hands a node the new image pin before the new gateway has hashed
// the staged tar (i1167a): the controller answers 202 "hashing", the start
// is not made, and the running container keeps serving. That is a wait, not
// a refusal, so:
//
//   - the start is retried after the gateway's Retry-After (clamped to
//     hashWaitMin..hashWaitMax) by a nudge, not on the 5 minute tick;
//   - no backend_start refusal (and so no operator alert) is recorded while
//     the quick retries last: hashWaitRetries of them, about 6 minutes at
//     the slowest spacing;
//   - once they are spent the failure is recorded as any start failure is,
//     with its own text.
const (
	hashWaitMin     = 5 * time.Second
	hashWaitMax     = 30 * time.Second
	hashWaitRetries = 12
)

// hashWait clamps the gateway's Retry-After into the quick-retry spacing.
func hashWait(d time.Duration) time.Duration {
	return min(max(d, hashWaitMin), hashWaitMax)
}

// recordBackendStartFailure is what a failed backend start becomes: a
// refusal the heartbeat carries, except a controller still hashing the image
// tar inside its quick-retry window, which logs at info and nudges later.
func (r *Reconciler) recordBackendStartFailure(backend string, err error) {
	h, ok := dockerpkg.AsImageHashing(err)
	if !ok {
		delete(r.hashWaits, backend)
		refusals.Record("backend_start", backend, err.Error())
		return
	}
	if r.hashWaits == nil {
		r.hashWaits = map[string]int{}
	}
	if r.hashWaits[backend] < hashWaitRetries {
		r.hashWaits[backend]++
		wait := hashWait(h.RetryAfter)
		slog.Info("reconcile.start_waiting_on_hash", "backend", backend, "image", h.Ref, "tar", h.Tar,
			"quick_retry", r.hashWaits[backend], "of", hashWaitRetries, "retry_in", wait.String(),
			"detail", "the controller is still hashing the image tar; the running container is untouched; retrying shortly")
		r.after(wait, r.Nudge)
		return
	}
	refusals.Record("backend_start", backend, fmt.Sprintf(
		"%s (still hashing after %d quick retries; the next reconcile pass tries again)", err.Error(), hashWaitRetries))
}
