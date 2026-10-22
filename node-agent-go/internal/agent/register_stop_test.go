// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package agent

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 0.6.8 rehearsal (F3): a controller refusing registration (401 every try)
// held the agent in its retry loop, and SIGTERM went unanswered until
// systemd's SIGKILL. A cancelled ctx must end the loop at the next wait.
func TestRegisterUntil_AStopEndsARefusedRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var tries atomic.Int32
	done := make(chan bool, 1)
	go func() {
		done <- registerUntil(ctx, func() bool { tries.Add(1); return false }, time.Hour)
	}()
	for tries.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("registerUntil reported success for a refused registration")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("registerUntil did not give way to a cancelled ctx")
	}
}

func TestRegisterUntil_RetriesUntilAccepted(t *testing.T) {
	n := 0
	if !registerUntil(context.Background(), func() bool { n++; return n == 3 }, time.Millisecond) || n != 3 {
		t.Fatalf("want success on the third try, got n=%d", n)
	}
}

// Structural: in Run, only the signal goroutine reads sigCh, and it cancels
// ctx; the registration wait is registerUntil on that ctx. Reading sigCh
// only at step 5 is what left a stop unread during registration.
func TestRun_ASignalCancelsCtxBeforeRegistration(t *testing.T) {
	src, err := os.ReadFile("agent.go")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.SplitN(strings.SplitN(string(src), "func (a *Agent) Run() error {", 2)[1], "\nfunc ", 2)[0]
	if n := strings.Count(body, "<-sigCh"); n != 1 {
		t.Fatalf("Run reads sigCh %d times; only the signal goroutine may", n)
	}
	reader := strings.Index(body, "case sig := <-sigCh:")
	register := strings.Index(body, "registerUntil(ctx,")
	if reader < 0 || register < 0 || reader > register {
		t.Fatal("the signal goroutine must be started before the registration wait, and that wait must be registerUntil(ctx, …)")
	}
	if !strings.Contains(body[reader:register], "cancel()") {
		t.Fatal("the signal goroutine must cancel ctx")
	}
}
