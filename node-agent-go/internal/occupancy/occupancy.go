// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package occupancy counts the requests in flight on each local backend
// against that backend's slots, so a full backend is BUSY, never "wedged".
//
// An engine serves a fixed number of sequences at once (Ollama's
// OLLAMA_NUM_PARALLEL, llama.cpp's --parallel, vLLM's max-num-seqs) and
// queues the rest silently: a queued request sees no headers and no bytes
// until a slot frees, which the gateway reads as a stall and answers with a
// failover and an "engine may be wedged" alert (noomesh-internal i159). The
// agent is the one process that sees every request to the backend, so it
// is where the count lives. The proxy admits a request through Admit, the
// reconciler publishes the slots it placed through SetSlots, and the
// heartbeat carries Report on each backend's entry.
//
// Slots unknown (0): requests are counted but never queued here; the
// backend's own queue applies, as before.
package occupancy

import (
	"context"
	"sync"
)

// Entry is one backend's occupancy as the heartbeat reports it.
type Entry struct {
	// InFlight is how many requests the proxy has admitted to the backend
	// and not yet seen finish.
	InFlight int `json:"in_flight"`
	// Slots is the backend's declared concurrency; 0 = not declared.
	Slots int `json:"slots"`
	// Queued is how many requests wait here for a slot.
	Queued int `json:"queued"`
}

var (
	mu       sync.Mutex
	cond     = sync.NewCond(&mu)
	slots    = map[string]int{}
	inFlight = map[string]int{}
	queue    = map[string][]uint64{}
	ticket   uint64
	// draining: backends whose admission is closed for a GPU hold's drain
	// (gpuyield): a new request is refused at once, never queued, so
	// in_flight can only fall and WaitIdle ends.
	draining = map[string]bool{}
)

// SetSlots replaces the declared slots per backend (the reconciler's view
// of what it placed). Waiters are re-evaluated: a raised count admits them.
func SetSlots(m map[string]int) {
	mu.Lock()
	defer mu.Unlock()
	slots = map[string]int{}
	for b, n := range m {
		if n > 0 {
			slots[b] = n
		}
	}
	cond.Broadcast()
}

// Slots is a backend's declared concurrency, 0 when not declared.
func Slots(backend string) int {
	mu.Lock()
	defer mu.Unlock()
	return slots[backend]
}

// Busy reports whether a new request on the backend would have to wait,
// and how many already wait ahead of it.
func Busy(backend string) (busy bool, ahead int) {
	mu.Lock()
	defer mu.Unlock()
	return busyLocked(backend), len(queue[backend])
}

func busyLocked(backend string) bool {
	n := slots[backend]
	return n > 0 && inFlight[backend] >= n
}

// Admit counts one request in flight on the backend, waiting its turn
// (first come, first served) when every declared slot is taken. It returns
// when the request holds a slot, or with ctx's error when the caller gave
// up first; release must be called exactly once after a nil error.
func Admit(ctx context.Context, backend string) (release func(), err error) {
	mu.Lock()
	defer mu.Unlock()
	if !busyLocked(backend) && len(queue[backend]) == 0 {
		inFlight[backend]++
		return releaseFor(backend), nil
	}
	ticket++
	my := ticket
	queue[backend] = append(queue[backend], my)
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		cond.Broadcast()
		mu.Unlock()
	})
	defer stop()
	for {
		if ctx.Err() != nil {
			dequeue(backend, my)
			return nil, ctx.Err()
		}
		q := queue[backend]
		if len(q) > 0 && q[0] == my && !busyLocked(backend) {
			queue[backend] = q[1:]
			inFlight[backend]++
			// The next in line may also fit (slots raised, or several
			// released at once).
			cond.Broadcast()
			return releaseFor(backend), nil
		}
		cond.Wait()
	}
}

func releaseFor(backend string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			if inFlight[backend] > 0 {
				inFlight[backend]--
			}
			cond.Broadcast()
			mu.Unlock()
		})
	}
}

func dequeue(backend string, t uint64) {
	q := queue[backend]
	for i, x := range q {
		if x == t {
			queue[backend] = append(q[:i:i], q[i+1:]...)
			break
		}
	}
	if len(queue[backend]) == 0 {
		delete(queue, backend)
	}
	cond.Broadcast()
}

// SetDraining closes (on) or reopens (off) admission on the named backends.
// While closed the proxy answers 503 backend_draining instead of admitting
// or queueing; requests already in flight run to their end.
func SetDraining(backends []string, on bool) {
	mu.Lock()
	defer mu.Unlock()
	for _, b := range backends {
		if on {
			draining[b] = true
		} else {
			delete(draining, b)
		}
	}
	cond.Broadcast()
}

// Draining reports whether the backend's admission is closed.
func Draining(backend string) bool {
	mu.Lock()
	defer mu.Unlock()
	return draining[backend]
}

// InFlight is how many admitted requests the backend still has running.
func InFlight(backend string) int {
	mu.Lock()
	defer mu.Unlock()
	return inFlight[backend]
}

// WaitIdle blocks until no request is in flight on any of the backends, or
// ctx ends. It returns whether they went idle and, when not, what was still
// running per backend (only the non-zero ones). Nothing is cancelled: a
// request in flight finishes on its own.
func WaitIdle(ctx context.Context, backends []string) (idle bool, remaining map[string]int) {
	mu.Lock()
	defer mu.Unlock()
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		cond.Broadcast()
		mu.Unlock()
	})
	defer stop()
	for {
		remaining = map[string]int{}
		for _, b := range backends {
			if inFlight[b] > 0 {
				remaining[b] = inFlight[b]
			}
		}
		if len(remaining) == 0 {
			return true, nil
		}
		if ctx.Err() != nil {
			return false, remaining
		}
		cond.Wait()
	}
}

// Report is every backend with a declared slot count, a request in flight,
// or a request waiting.
func Report() map[string]Entry {
	mu.Lock()
	defer mu.Unlock()
	out := map[string]Entry{}
	for b := range slots {
		out[b] = Entry{}
	}
	for b := range inFlight {
		out[b] = Entry{}
	}
	for b := range queue {
		out[b] = Entry{}
	}
	for b := range out {
		out[b] = Entry{InFlight: inFlight[b], Slots: slots[b], Queued: len(queue[b])}
	}
	return out
}

// Annotate writes each reported backend's occupancy onto its entry in the
// heartbeat's `backend_containers` map (`in_flight`, `slots`, `queued`), so
// the counts ride a key the controller already carries. Entries that are
// not maps, and backends with no entry, are left alone.
func Annotate(m map[string]any) {
	for b, e := range Report() {
		entry, ok := m[b].(map[string]any)
		if !ok {
			continue
		}
		entry["in_flight"] = e.InFlight
		entry["slots"] = e.Slots
		entry["queued"] = e.Queued
	}
}

// Reset clears every count (tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	slots = map[string]int{}
	inFlight = map[string]int{}
	queue = map[string][]uint64{}
	draining = map[string]bool{}
	cond.Broadcast()
}
