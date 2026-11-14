// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"
	"time"
)

// A container that exits between RunningBackends' list and its inspect
// failed the whole call, and the proxy answered 503 docker_unavailable: 132
// first-attempt failures in 7 days on the live fleet, the latest
// "inspecting container zealous_neumann" (a throwaway `docker run`).

const backendsAndAThrowaway = `[
 {"Id":"aaa","Names":["/noo-llamacpp"],"Image":"ghcr.io/x/llama:latest","Labels":{}},
 {"Id":"ccc","Names":["/zealous_neumann"],"Image":"alpine","Labels":{}},
 {"Id":"bbb","Names":["/noo-vllm"],"Image":"vllm/vllm-openai:v0.25.0","Labels":{}}
]`

func countCalls(f *listFakeDaemon, suffix string) int {
	n := 0
	for _, c := range f.seen() {
		if strings.HasSuffix(c, suffix) {
			n++
		}
	}
	return n
}

// A container that is not a backend is never inspected, so its exit cannot
// fail the call.
func TestRunningBackendsNeverInspectsANonBackend(t *testing.T) {
	f := healthyListDaemon()
	f.listBody = backendsAndAThrowaway
	f.inspectStatus = map[string]int{"ccc": 404}
	c := newFakeDaemon(t, f)
	got, err := c.RunningBackends(t.Context())
	if err != nil {
		t.Fatalf("a throwaway container failed the call: %v", err)
	}
	if len(got) != 2 || got["llamacpp"] != "qwen.gguf" || got["vllm"] != "google/gemma" {
		t.Fatalf("got %v", got)
	}
	if n := countCalls(f, "/containers/ccc/json"); n != 0 {
		t.Fatalf("the non-backend was inspected %d time(s)", n)
	}
}

// A BACKEND that is gone between the list and its inspect is not running: it
// is left out and the others are returned.
func TestRunningBackendsSkipsABackendGoneBeforeItsInspect(t *testing.T) {
	f := healthyListDaemon()
	f.inspectStatus = map[string]int{"aaa": 404}
	c := newFakeDaemon(t, f)
	got, err := c.RunningBackends(t.Context())
	if err != nil {
		t.Fatalf("a vanished backend failed the call: %v", err)
	}
	if len(got) != 1 || got["vllm"] != "google/gemma" {
		t.Fatalf("got %v, want only vllm", got)
	}
}

// The proxy's cache: one listing serves the requests inside the TTL, a
// fresh one is made after it, and an error is never cached.
func TestRunningBackendsCachedServesTheTTLAndNeverCachesAnError(t *testing.T) {
	f := healthyListDaemon()
	c := newFakeDaemon(t, f)
	now := time.Unix(1_800_000_000, 0)
	c.proxyNow = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		got, err := c.RunningBackendsCached(t.Context())
		if err != nil || len(got) != 2 {
			t.Fatalf("call %d: %v %v", i, got, err)
		}
		got["vllm"] = "mutated by a caller"
	}
	if n := countCalls(f, "/containers/json"); n != 1 {
		t.Fatalf("3 calls inside the TTL listed %d times, want 1", n)
	}
	if got, _ := c.RunningBackendsCached(t.Context()); got["vllm"] != "google/gemma" {
		t.Fatalf("a caller's change leaked into the cache: %v", got)
	}

	now = now.Add(proxyCacheTTL)
	f.mu.Lock()
	f.listStatus, f.listBody = 500, `{"message":"daemon busy"}`
	f.mu.Unlock()
	if got, err := c.RunningBackendsCached(t.Context()); err == nil {
		t.Fatalf("an expired cache answered instead of the failing daemon: %v", got)
	}
	f.mu.Lock()
	f.listStatus, f.listBody = 200, twoBackends
	f.mu.Unlock()
	before := countCalls(f, "/containers/json")
	if got, err := c.RunningBackendsCached(t.Context()); err != nil || len(got) != 2 {
		t.Fatalf("after the error: %v %v", got, err)
	}
	if countCalls(f, "/containers/json") != before+1 {
		t.Fatal("the error was cached: the next call did not list again")
	}
}

func TestContainerNamesCachedServesTheTTL(t *testing.T) {
	f := healthyListDaemon()
	c := newFakeDaemon(t, f)
	now := time.Unix(1_800_000_000, 0)
	c.proxyNow = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if got := c.ContainerNamesCached(t.Context()); len(got) != 2 {
			t.Fatalf("names %v", got)
		}
	}
	if n := countCalls(f, "/containers/json"); n != 1 {
		t.Fatalf("listed %d times, want 1", n)
	}
	now = now.Add(proxyCacheTTL)
	c.ContainerNamesCached(t.Context())
	if n := countCalls(f, "/containers/json"); n != 2 {
		t.Fatalf("after the TTL listed %d times, want 2", n)
	}
}
