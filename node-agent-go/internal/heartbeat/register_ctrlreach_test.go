// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlreach"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ctrlreach.Answered("test-reset", time.Now())
	t.Cleanup(func() { slog.SetDefault(prev); ctrlreach.Answered("test-reset", time.Now()) })
	return &buf
}

func answer(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}
}

// An agent that starts while the controller is away logs the outage once and
// when it answers again; the retries in between are debug, never ERROR.
func TestRegister_StartDuringOutageLogsOnceAndWhenBack(t *testing.T) {
	buf := captureSlog(t)
	tries := 0
	r := newTestReporter(t, "http://ctrl.invalid:8080", nil)
	r.client = &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		tries++
		if tries <= 4 {
			return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
		}
		return answer(200), nil
	})}
	caps := hardware.Capabilities{CPUCores: 1}
	for i := 0; i < 4; i++ {
		if r.register(caps, "10.0.0.1") {
			t.Fatal("register succeeded while the controller was away")
		}
	}
	if !r.register(caps, "10.0.0.1") {
		t.Fatal("register failed once the controller answered")
	}
	out := buf.String()
	if n := strings.Count(out, "event=controller_unreachable"); n != 1 {
		t.Fatalf("onset lines = %d, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "event=controller_reachable"); n != 1 {
		t.Fatalf("back lines = %d, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Fatalf("an unreachable try must not log ERROR:\n%s", out)
	}
	if n := strings.Count(out, "level=DEBUG"); n != 4 {
		t.Fatalf("debug lines = %d, want 4:\n%s", n, out)
	}
}

// An HTTP answer that is an error is not an outage: the controller is there.
func TestRegister_AnErrorAnswerStaysAnErrorAndOpensNoOutage(t *testing.T) {
	buf := captureSlog(t)
	r := newTestReporter(t, "http://ctrl.invalid:8080", nil)
	r.client = &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) { return answer(500), nil })}
	if r.register(hardware.Capabilities{CPUCores: 1}, "10.0.0.1") {
		t.Fatal("a 500 must not register")
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "registration failed") {
		t.Fatalf("a 500 must log ERROR:\n%s", out)
	}
	if down, _ := ctrlreach.Down(); down || strings.Contains(out, "controller_unreachable") {
		t.Fatalf("a 500 must not open an outage:\n%s", out)
	}
}

// A controller that comes back and refuses the node: the outage closes (one
// "answers again" line) and the refusal still logs at ERROR. The
// once-per-outage state never swallows a real failure that follows it.
func TestRegister_AFailureAfterAnOutageStillLogsError(t *testing.T) {
	buf := captureSlog(t)
	tries := 0
	r := newTestReporter(t, "http://ctrl.invalid:8080", nil)
	r.client = &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		tries++
		if tries == 1 {
			return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
		}
		return answer(401), nil
	})}
	caps := hardware.Capabilities{CPUCores: 1}
	if r.register(caps, "10.0.0.1") {
		t.Fatal("register succeeded while the controller was away")
	}
	if down, _ := ctrlreach.Down(); !down {
		t.Fatal("a refused dial must open the outage")
	}
	if r.register(caps, "10.0.0.1") {
		t.Fatal("a 401 must not register")
	}
	out := buf.String()
	if n := strings.Count(out, "event=controller_reachable"); n != 1 {
		t.Fatalf("back lines = %d, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "registration failed") || !strings.Contains(out, "status=401") {
		t.Fatalf("a 401 after an outage must log ERROR registration failed status=401:\n%s", out)
	}
	if down, _ := ctrlreach.Down(); down {
		t.Fatalf("an answer must close the outage:\n%s", out)
	}
}
