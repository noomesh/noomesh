// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestClassifyPullFailureRetried(t *testing.T) {
	for _, e := range []string{
		"pulling manifest\nError: pull model manifest: 503: upstream connect error or disconnect/reset before headers. reset reason: connection timeout",
		"Error: 503: ",
		"Error: pull model manifest: 500: internal",
		"Error: pull model manifest: 502: bad gateway",
		"Error: pull model manifest: Get \"https://registry.example/v2/x\": dial tcp 192.0.2.1:443: connect: connection refused",
		"Error: max retries exceeded: read tcp 100.64.0.2:5000->192.0.2.1:443: i/o timeout",
		"Error: context deadline exceeded",
		"Error: net/http: TLS handshake timeout",
		"Error: read: connection reset by peer",
		"Error: unexpected EOF",
		"Error: request timed out",
	} {
		if classifyPullFailure(e) == "" {
			t.Errorf("should retry: %q", e)
		}
	}
	if r := classifyPullFailure("Error: 503: "); !strings.Contains(r, "503") {
		t.Errorf("5xx reason should name the status, got %q", r)
	}
}

func TestClassifyPullFailurePermanentAndUnknown(t *testing.T) {
	for _, e := range []string{
		"Error: pull model manifest: file does not exist",
		"Error: pull model manifest: 404: not found",
		"Error: pull model manifest: 401: unauthorized",
		"Error: pull model manifest: 403: forbidden",
		"Error: 404: ",
		"Error: pull model manifest: 401: ",
		"Error: 403: ",
		// The status alone is permanent, even beside a transient word.
		"Error: 404: edge connection timeout",
		"Error: 401: tls handshake",
		"Error: 403: i/o timeout",
		"Error: pull access denied for x",
		"Error: pull model manifest: manifest unknown",
		"Error: pull model manifest: 404: not found (after a connection timeout)",
		"Error: something nobody has seen",
		"Error response from daemon: container is not running",
		"",
		"pulling 970aa74c0c503: 12%\nverifying sha256 digest",
		// Only the LAST Error line counts.
		"Error: 503: \nError: file does not exist",
	} {
		if r := classifyPullFailure(e); r != "" {
			t.Errorf("should not retry: %q (%s)", e, r)
		}
	}
	if classifyPullFailure("Error: file does not exist\nError: 503: ") == "" {
		t.Error("the last Error line is the one that counts")
	}
}

func TestClassifyPullErrorBothLanes(t *testing.T) {
	// Docker lane: the exec error carries ollama's last line.
	d := errors.New("ollama pull x exited 1 in noo-ollama: Error: pull model manifest: 503: busy")
	if classifyPullError("pulling manifest", d) == "" {
		t.Error("docker 503 should retry")
	}
	// Native lane: the API message has no Error prefix.
	n := errors.New("ollama pull x: dial tcp 192.0.2.1:443: i/o timeout")
	if classifyPullError("", n) == "" {
		t.Error("native timeout should retry")
	}
	if classifyPullError("", errors.New("ollama pull x: pull model manifest: file does not exist")) != "" {
		t.Error("native missing model must not retry")
	}
}

func TestNextPullDelayBounded(t *testing.T) {
	cases := []struct {
		tried, waited, want int
		ok                  bool
	}{
		{1, 0, 10, true}, {2, 10, 30, true}, {3, 40, 0, false}, {2, 20, 0, false}, {0, 0, 0, false},
	}
	for _, c := range cases {
		got, ok := nextPullDelay(c.tried, c.waited)
		if got != c.want || ok != c.ok {
			t.Errorf("nextPullDelay(%d,%d) = %d,%v want %d,%v", c.tried, c.waited, got, ok, c.want, c.ok)
		}
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestPullWithRetryBlipThenSuccessLogsEachRetry(t *testing.T) {
	buf := captureLog(t)
	calls := 0
	var slept []time.Duration
	out, err := pullWithRetry(context.Background(), "gemma:1b",
		func(context.Context, string) (string, error) {
			calls++
			if calls < 3 {
				return "", errors.New("ollama pull gemma:1b exited 1 in c: Error: pull model manifest: 503: busy")
			}
			return "success", nil
		},
		func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil })
	if err != nil || out != "success" || calls != 3 {
		t.Fatalf("out=%q err=%v calls=%d", out, err, calls)
	}
	if len(slept) != 2 || slept[0] != 10*time.Second || slept[1] != 30*time.Second {
		t.Fatalf("slept %v", slept)
	}
	log := buf.String()
	if n := strings.Count(log, "reconcile.ollama_pull_retry"); n != 2 {
		t.Fatalf("want 2 retry lines, got %d:\n%s", n, log)
	}
	if !strings.Contains(log, "503") || !strings.Contains(log, "try=2") || !strings.Contains(log, "try=3") {
		t.Fatalf("retry lines lack the reason or try:\n%s", log)
	}
}

func TestPullWithRetryPermanentErrorIsNotRetried(t *testing.T) {
	buf := captureLog(t)
	calls := 0
	_, err := pullWithRetry(context.Background(), "nope",
		func(context.Context, string) (string, error) {
			calls++
			return "", errors.New("ollama pull nope exited 1 in c: Error: pull model manifest: file does not exist")
		},
		func(context.Context, time.Duration) error { t.Fatal("must not wait"); return nil })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if strings.Contains(buf.String(), "ollama_pull_retry") {
		t.Fatal("a permanent failure logged a retry")
	}
}

func TestPullWithRetryIsBounded(t *testing.T) {
	calls := 0
	slept := time.Duration(0)
	_, err := pullWithRetry(context.Background(), "m",
		func(context.Context, string) (string, error) { calls++; return "", errors.New("Error: 503: ") },
		func(_ context.Context, d time.Duration) error { slept += d; return nil })
	if err == nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want 3 tries", err, calls)
	}
	if slept > 45*time.Second {
		t.Fatalf("waited %v, cap is 45s", slept)
	}
}

func TestPullWithRetryStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := pullWithRetry(ctx, "m",
		func(context.Context, string) (string, error) {
			calls++
			cancel()
			return "", errors.New("Error: 503: ")
		},
		func(context.Context, time.Duration) error { t.Fatal("must not wait after shutdown"); return nil })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
