// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package ctrlreach

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

type line struct {
	level slog.Level
	msg   string
}

func capture(t *testing.T) *[]line {
	t.Helper()
	reset()
	var got []line
	prev := logf
	logf = func(level slog.Level, msg string, _ ...any) { got = append(got, line{level, msg}) }
	t.Cleanup(func() { logf = prev; reset() })
	return &got
}

const ctl = "https://ctrl:8080"

var refused = &url.Error{Op: "Get", URL: ctl, Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}

// One outage, many failed calls from both callers: ONE onset line, ONE back
// line, the back line naming how long the controller was away.
func TestOneOnsetAndOneBackLinePerOutage(t *testing.T) {
	got := capture(t)
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		src := "heartbeat"
		if i%2 == 1 {
			src = "reconcile"
		}
		Failed(src, ctl, refused, t0.Add(time.Duration(i)*10*time.Second))
	}
	if n := len(*got); n != 1 {
		t.Fatalf("an outage of 30 failed calls logged %d lines, want exactly 1: %v", n, *got)
	}
	if !strings.Contains((*got)[0].msg, "nothing is reconciled until it answers; running backends keep running") ||
		!strings.Contains((*got)[0].msg, ctl) || (*got)[0].level != slog.LevelWarn {
		t.Fatalf("onset line: %+v", (*got)[0])
	}
	if !Answered("reconcile", t0.Add(5*time.Minute)) {
		t.Fatal("the first answer after an outage must log the back line")
	}
	Answered("heartbeat", t0.Add(5*time.Minute+time.Second))
	if n := len(*got); n != 2 {
		t.Fatalf("want onset + one back line, got %d: %v", n, *got)
	}
	if b := (*got)[1].msg; !strings.Contains(b, "answers again after 5m0s away") {
		t.Fatalf("back line: %q", b)
	}
	if down, _ := Down(); down {
		t.Fatal("the outage is over after an answer")
	}
	// A second outage gets its own onset.
	Failed("heartbeat", ctl, refused, t0.Add(time.Hour))
	if n := len(*got); n != 3 {
		t.Fatalf("a second outage logs its own onset: %v", *got)
	}
}

func TestAnAnswerWithNoOutageLogsNothing(t *testing.T) {
	got := capture(t)
	if Answered("heartbeat", time.Now()) || len(*got) != 0 {
		t.Fatalf("no outage, no line: %v", *got)
	}
}

// Could not reach: a failed dial, a name that does not resolve, a timeout.
// Not unreachable: a TLS verification failure (something else answered), an
// HTTP answer, nil.
func TestUnreachableIsByTypeAndOnlyForNoAnswer(t *testing.T) {
	yes := []error{
		refused,
		&url.Error{Op: "Get", URL: ctl, Err: &net.DNSError{Err: "no such host", Name: "ctrl", IsNotFound: true}},
		fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}),
		&url.Error{Op: "Get", URL: ctl, Err: context.DeadlineExceeded},
		context.DeadlineExceeded,
	}
	for _, e := range yes {
		if !Unreachable(e) {
			t.Errorf("want unreachable: %v", e)
		}
	}
	no := []error{
		nil,
		errors.New("desired-config HTTP 503: hashing"),
		&url.Error{Op: "Get", URL: ctl, Err: &tls.CertificateVerificationError{Err: errors.New("x509: unknown authority")}},
		&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
	}
	for _, e := range no {
		if Unreachable(e) {
			t.Errorf("want NOT unreachable: %v", e)
		}
	}
}
