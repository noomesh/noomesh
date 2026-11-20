// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func newRetry() *retryState {
	return &retryState{bo: backoff{min: time.Second, max: 60 * time.Second}, notOffered: 10 * time.Minute}
}

// refusedDial is the error a dial to a port nobody listens on really produces.
func refusedDial(t *testing.T) error {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, err = net.Dial("tcp", addr)
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	return &dialError{fmt.Errorf("dial wss://x: %w", err)}
}

func TestDialRefusedClassifiesRealErrorShapes(t *testing.T) {
	opErr := func(e error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
	}
	dial := func(e error) error { return &dialError{fmt.Errorf("dial wss://x: %w", e)} }
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"real refused dial", refusedDial(t), true},
		{"refused", dial(opErr(syscall.ECONNREFUSED)), true},
		{"reset during dial", dial(opErr(syscall.ECONNRESET)), true},
		{"eof on the dial", dial(io.EOF), true},
		{"unexpected eof on the dial", dial(io.ErrUnexpectedEOF), true},
		{"dial timeout", dial(opErr(syscall.ETIMEDOUT)), false},
		{"tls failure", dial(errors.New("tls: failed to verify certificate")), false},
		{"bad handshake status", dial(errors.New("websocket: bad handshake")), false},
		{"eof after the dial (handshake)", fmt.Errorf("tunnel handshake: no challenge from the gateway: %w", io.EOF), false},
		{"reset after the dial (session)", fmt.Errorf("serve: %w", syscall.ECONNRESET), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := dialRefused(c.err); got != c.want {
			t.Errorf("%s: dialRefused = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFourQuickGatewayRestartsRedialWithinTheCap(t *testing.T) {
	r := newRetry()
	// Earlier sick-gateway failures have grown the backoff to its top.
	for i := 0; i < 8; i++ {
		r.bo.next()
	}
	for i := 0; i < 4; i++ {
		// A short session, then the redial is refused while the gateway restarts.
		_ = r.nextDelay(true, 10*time.Second, io.ErrUnexpectedEOF)
		d := r.nextDelay(false, 0, refusedDial(t))
		if d > 5*time.Second || d < 2500*time.Millisecond {
			t.Fatalf("restart %d: redial in %v, want within [2.5s, 5s]", i, d)
		}
	}
}

func TestRefusedNeverExceedsTheCapAndDoesNotGrow(t *testing.T) {
	r := newRetry()
	for i := 0; i < 50; i++ {
		if d := r.nextDelay(false, 0, refusedDial(t)); d > refusedRetryCap {
			t.Fatalf("refused #%d waited %v, over the %v cap", i, d, refusedRetryCap)
		}
	}
	if r.bo.cur != 0 {
		t.Fatalf("refused dials grew the backoff to %v", r.bo.cur)
	}
	small := &retryState{bo: backoff{min: 100 * time.Millisecond, max: 2 * time.Second}}
	if d := small.nextDelay(false, 0, refusedDial(t)); d > 2*time.Second {
		t.Fatalf("cap exceeded RetryMax: %v", d)
	}
}

func TestATimeoutOrTLSOrAuthFailureStillBacksOffToTheMax(t *testing.T) {
	for _, err := range []error{
		&dialError{fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded})},
		&dialError{errors.New("tls: failed to verify certificate")},
		errors.New("tunnel handshake: the gateway refused the node"),
	} {
		r := newRetry()
		var last time.Duration
		for i := 0; i < 10; i++ {
			last = r.nextDelay(false, 0, err)
		}
		if last < 30*time.Second || last > 60*time.Second {
			t.Errorf("%v: after 10 failures the wait is %v, want in [30s, 60s]", err, last)
		}
	}
}

func TestAReadyThenDroppedShortSessionDoesNotDouble(t *testing.T) {
	r := newRetry()
	r.nextDelay(false, 0, errors.New("tls")) // 1s
	r.nextDelay(false, 0, errors.New("tls")) // 2s
	cur := r.bo.cur
	for i := 0; i < 6; i++ {
		d := r.nextDelay(true, 5*time.Second, io.ErrUnexpectedEOF)
		if d > cur || d < cur/2 {
			t.Fatalf("short session waited %v, want within [%v, %v]", d, cur/2, cur)
		}
	}
	if r.bo.cur != cur {
		t.Fatalf("short ready sessions moved the backoff from %v to %v", cur, r.bo.cur)
	}
	fresh := newRetry()
	if d := fresh.nextDelay(true, time.Second, io.EOF); d > time.Second || d < 500*time.Millisecond {
		t.Fatalf("with no prior delay the wait is %v, want the min", d)
	}
}

func TestASessionOverThirtySecondsResetsTheBackoff(t *testing.T) {
	r := newRetry()
	for i := 0; i < 8; i++ {
		r.nextDelay(false, 0, errors.New("tls"))
	}
	d := r.nextDelay(true, 31*time.Second, io.ErrUnexpectedEOF)
	if d > time.Second || r.bo.cur != time.Second {
		t.Fatalf("after a long session: wait %v, cur %v, want the min", d, r.bo.cur)
	}
}

func TestNotOfferedKeepsItsLongRetry(t *testing.T) {
	r := newRetry()
	d := r.nextDelay(false, 0, &notOfferedError{status: 404})
	if d < 5*time.Minute || d > 10*time.Minute {
		t.Fatalf("notOffered waited %v, want [5m, 10m]", d)
	}
	if r.bo.cur != 0 {
		t.Fatalf("notOffered touched the backoff: %v", r.bo.cur)
	}
}
