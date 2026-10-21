// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package occupancy

import (
	"context"
	"testing"
	"time"
)

func TestAdmitCountsAndQueuesInOrder(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetSlots(map[string]int{"ollama": 2})

	r1, err := Admit(context.Background(), "ollama")
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := Admit(context.Background(), "ollama")
	if busy, ahead := Busy("ollama"); !busy || ahead != 0 {
		t.Fatalf("2 of 2 in flight: busy=%v ahead=%d", busy, ahead)
	}
	if e := Report()["ollama"]; e.InFlight != 2 || e.Slots != 2 || e.Queued != 0 {
		t.Fatalf("report: %+v", e)
	}

	// Two waiters, first come first served.
	got := make(chan int, 2)
	wait := func(n int) {
		rel, err := Admit(context.Background(), "ollama")
		if err != nil {
			t.Error(err)
			return
		}
		got <- n
		rel()
	}
	go wait(3)
	time.Sleep(20 * time.Millisecond)
	go wait(4)
	time.Sleep(20 * time.Millisecond)
	if e := Report()["ollama"]; e.Queued != 2 {
		t.Fatalf("two queued: %+v", e)
	}
	if _, ahead := Busy("ollama"); ahead != 2 {
		t.Fatalf("ahead=%d", ahead)
	}
	r1()
	if n := <-got; n != 3 {
		t.Fatalf("the first waiter goes first, got %d", n)
	}
	r2()
	if n := <-got; n != 4 {
		t.Fatalf("then the second, got %d", n)
	}
	time.Sleep(10 * time.Millisecond)
	if e := Report()["ollama"]; e.InFlight != 0 || e.Queued != 0 {
		t.Fatalf("all released: %+v", e)
	}
}

func TestAdmitWithoutDeclaredSlotsNeverWaits(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	for i := 0; i < 5; i++ {
		if _, err := Admit(context.Background(), "vllm"); err != nil {
			t.Fatal(err)
		}
	}
	if busy, _ := Busy("vllm"); busy {
		t.Fatal("unknown slots: never busy")
	}
	if e := Report()["vllm"]; e.InFlight != 5 || e.Slots != 0 {
		t.Fatalf("counted all the same: %+v", e)
	}
}

func TestAWaiterThatGivesUpLeavesTheQueue(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetSlots(map[string]int{"ollama": 1})
	rel, _ := Admit(context.Background(), "ollama")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := Admit(ctx, "ollama"); err == nil {
		t.Fatal("full backend, short deadline: must return the context error")
	}
	if e := Report()["ollama"]; e.Queued != 0 || e.InFlight != 1 {
		t.Fatalf("the waiter left no trace: %+v", e)
	}
	rel()
	if _, err := Admit(context.Background(), "ollama"); err != nil {
		t.Fatalf("after release the next request is admitted at once: %v", err)
	}
}

func TestRaisingSlotsAdmitsWaiters(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetSlots(map[string]int{"ollama": 1})
	_, _ = Admit(context.Background(), "ollama")
	done := make(chan struct{})
	go func() {
		if _, err := Admit(context.Background(), "ollama"); err == nil {
			close(done)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	SetSlots(map[string]int{"ollama": 2})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a raised slot count must admit the waiter")
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	rel, _ := Admit(context.Background(), "ollama")
	rel()
	rel()
	if e := Report()["ollama"]; e.InFlight != 0 {
		t.Fatalf("double release must not go negative or double-count: %+v", e)
	}
}

func TestAnnotateWritesOntoTheHeartbeatEntries(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetSlots(map[string]int{"ollama": 2})
	_, _ = Admit(context.Background(), "ollama")
	m := map[string]any{"ollama": map[string]any{"running": true}, "vllm": "not a map"}
	Annotate(m)
	e := m["ollama"].(map[string]any)
	if e["in_flight"] != 1 || e["slots"] != 2 || e["queued"] != 0 || e["running"] != true {
		t.Fatalf("entry: %v", e)
	}
	if m["vllm"] != "not a map" {
		t.Fatal("a non-map entry is left alone")
	}
}

func TestWaitIdleEndsWhenTheLastRequestFinishesAndNamesWhatRemains(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetSlots(map[string]int{"vllm": 2, "ollama": 1})
	relA, _ := Admit(context.Background(), "vllm")
	relB, _ := Admit(context.Background(), "vllm")
	relC, _ := Admit(context.Background(), "ollama")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	idle, rem := WaitIdle(ctx, []string{"vllm", "ollama"})
	if idle || rem["vllm"] != 2 || rem["ollama"] != 1 {
		t.Fatalf("still running: idle=%v rem=%v", idle, rem)
	}
	done := make(chan bool, 1)
	go func() {
		idle, _ := WaitIdle(context.Background(), []string{"vllm", "ollama"})
		done <- idle
	}()
	relA()
	relB()
	select {
	case <-done:
		t.Fatal("ollama still runs: must not be idle")
	case <-time.After(20 * time.Millisecond):
	}
	relC()
	select {
	case idle := <-done:
		if !idle {
			t.Fatal("want idle")
		}
	case <-time.After(time.Second):
		t.Fatal("WaitIdle never returned after the last release")
	}
}

func TestDrainingClosesAdmissionAndReset(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	SetDraining([]string{"vllm"}, true)
	if !Draining("vllm") || Draining("ollama") {
		t.Fatal("only the named backend drains")
	}
	SetDraining([]string{"vllm"}, false)
	if Draining("vllm") {
		t.Fatal("reopened")
	}
	SetDraining([]string{"vllm"}, true)
	Reset()
	if Draining("vllm") {
		t.Fatal("Reset clears draining")
	}
}
