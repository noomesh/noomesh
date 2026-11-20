// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// A first placement's `ollama pull` used to fail once on a registry blip and
// leave the node Pending for ollamaPullRetryAfter (10 minutes). This is the
// short in-pull retry in front of that backoff, and the classifier that says
// whether a failure is worth another try. It is the Go twin of
// noo-cli/src/commands/pull_retry.rs: the marker tables, the status rules
// and the bounds below are held equal to the Rust ones by
// tests/test_pull_retry_tables_match.py — change both together.

// pullTries is the tries in all: the first plus two retries.
const pullTries = 3

// pullMaxTotalWaitSecs caps the total wait across all retries.
const pullMaxTotalWaitSecs = 1000

// pullDelaysSecs is the wait before try 2 and before try 3.
var pullDelaysSecs = []int{10, 30}

// pullPermanentMarkers fail at once: waiting changes nothing.
var pullPermanentMarkers = []string{
	"not found",
	"manifest unknown",
	"file does not exist",
	"unauthorized",
	"pull access denied",
	"denied",
	"forbidden",
}

// pullPermanentStatuses are the HTTP statuses that fail at once.
var pullPermanentStatuses = []int{401, 403, 404}

// pullNetworkMarkers are connect/timeout failures worth another try.
var pullNetworkMarkers = []string{
	"connection refused",
	"connection reset",
	"connection timeout",
	"i/o timeout",
	"timed out",
	"timeout",
	"deadline exceeded",
	"tls handshake",
	"unexpected eof",
	"dial tcp",
}

// classifyPullFailure says why a failed pull is worth retrying, or "" when it
// is not. Pure: it reads only the pull's output text. Only the last line that
// starts with "error" counts, so a layer hash in the progress lines can never
// pass for a status code.
func classifyPullFailure(output string) string {
	lines := strings.Split(output, "\n")
	line := ""
	found := false
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.ToLower(strings.TrimSpace(lines[i]))
		if strings.HasPrefix(l, "error") {
			line, found = l, true
			break
		}
	}
	if !found {
		return ""
	}
	for _, p := range pullPermanentMarkers {
		if strings.Contains(line, p) {
			return ""
		}
	}
	status := 0
	for _, tok := range strings.Fields(line) {
		tok = strings.TrimRight(tok, ":")
		if len(tok) == 3 && tok[0] >= '0' && tok[0] <= '9' && tok[1] >= '0' && tok[1] <= '9' && tok[2] >= '0' && tok[2] <= '9' {
			status = int(tok[0]-'0')*100 + int(tok[1]-'0')*10 + int(tok[2]-'0')
			break
		}
	}
	for _, s := range pullPermanentStatuses {
		if status == s {
			return ""
		}
	}
	if status >= 500 && status <= 599 {
		return fmt.Sprintf("registry answered %d (a registry-side problem)", status)
	}
	for _, p := range pullNetworkMarkers {
		if strings.Contains(line, p) {
			return "the registry could not be reached (a network problem)"
		}
	}
	return ""
}

// classifyPullError classifies a failed pull from what the two lanes return:
// the container exec error carries ollama's own last line ("... exited 1 in
// c: Error: ..."), the native lane's error carries the API's message with no
// "Error" prefix. The error text is classified as one "Error:" line.
func classifyPullError(out string, err error) string {
	return classifyPullFailure(out + "\nError: " + strings.ReplaceAll(err.Error(), "\n", " "))
}

// nextPullDelay is the wait before try tried+1, or false when the tries or
// the total-wait cap are spent. tried counts the tries made so far.
func nextPullDelay(tried, waitedSecs int) (int, bool) {
	if tried >= pullTries || tried < 1 || tried-1 >= len(pullDelaysSecs) {
		return 0, false
	}
	d := pullDelaysSecs[tried-1]
	if waitedSecs+d > pullMaxTotalWaitSecs {
		return 0, false
	}
	return d, true
}

// sleepCtx waits d, or returns early with the context's error.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pullWithRetry runs one pull up to pullTries times, retrying only what
// classifyPullError allows, each retry logged on its own line with the
// reason. It returns the last attempt's result; what still fails then takes
// the caller's ollamaPullRetryAfter backoff. sleep is injected for tests.
func pullWithRetry(
	ctx context.Context,
	model string,
	pull func(context.Context, string) (string, error),
	sleep func(context.Context, time.Duration) error,
) (string, error) {
	waited, tried := 0, 0
	for {
		out, err := pull(ctx, model)
		tried++
		if err == nil || ctx.Err() != nil {
			return out, err
		}
		reason := classifyPullError(out, err)
		if reason == "" {
			return out, err
		}
		delay, ok := nextPullDelay(tried, waited)
		if !ok {
			return out, err
		}
		slog.Warn("reconcile.ollama_pull_retry", "model", model, "reason", reason,
			"retry_in", fmt.Sprintf("%ds", delay), "try", tried+1, "of", pullTries, "error", err)
		if serr := sleep(ctx, time.Duration(delay)*time.Second); serr != nil {
			return out, err
		}
		waited += delay
	}
}
