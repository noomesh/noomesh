// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"testing"
	"time"
)

// clearRig is a Store holding in-memory states only: no disk, no network.
func clearRig() (*Store, time.Time) {
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Now: func() time.Time { return now }, want: map[Ref]bool{}}
	return s, now
}

func (s *Store) setForTest(ref Ref, m memState) {
	s.mu.Lock()
	s.want[ref] = true
	s.setMem(ref, m)
	s.mu.Unlock()
}

var (
	retryA = Ref{ID: "set-a", Revision: "r1"}
	retryB = Ref{ID: "set-b", Revision: "r1"}
	retryC = Ref{ID: "set-c", Revision: "r1"}
)

func TestClearRefusedMakesARefusedSetEligibleBeforeItsBackoffEnds(t *testing.T) {
	s, now := clearRig()
	s.setForTest(retryA, memState{state: StateRefused, reason: "disk", until: now.Add(refusedRetry)})
	if _, ok := s.next(map[Ref]bool{}); ok {
		t.Fatal("a refused set inside its backoff was offered")
	}
	s.mu.Lock()
	s.running = true // next() clears it when it finds nothing
	s.mu.Unlock()
	if got := s.ClearRefused(nil); len(got) != 1 || got[0] != retryA {
		t.Fatalf("cleared %v, want [%v]", got, retryA)
	}
	ref, ok := s.next(map[Ref]bool{})
	if !ok || ref != retryA {
		t.Fatalf("next() = %v, %v; want the cleared set before its until", ref, ok)
	}
}

func TestClearRefusedWithANamedSetLeavesTheOtherRefusedSetsAlone(t *testing.T) {
	s, now := clearRig()
	for _, r := range []Ref{retryA, retryB} {
		s.setForTest(r, memState{state: StateRefused, reason: "disk", until: now.Add(refusedRetry)})
	}
	if got := s.ClearRefused([]Ref{retryA}); len(got) != 1 || got[0] != retryA {
		t.Fatalf("cleared %v, want only %v", got, retryA)
	}
	if ref, ok := s.next(map[Ref]bool{}); !ok || ref != retryA {
		t.Fatalf("next() = %v, %v; want %v", ref, ok, retryA)
	}
	// B is still waiting out its backoff: with A tried, nothing is offered.
	if ref, ok := s.next(map[Ref]bool{retryA: true}); ok {
		t.Fatalf("the unnamed refused set %v was cleared too", ref)
	}
	if m := s.mem[retryB]; m.state != StateRefused || !m.until.Equal(now.Add(refusedRetry)) {
		t.Fatalf("the unnamed set's entry changed: %+v", m)
	}
}

func TestClearRefusedNeverTouchesVerifiedOrFetchingEntries(t *testing.T) {
	s, now := clearRig()
	s.setForTest(retryA, memState{state: StateVerified})
	s.setForTest(retryB, memState{state: StateFetching})
	s.setForTest(retryC, memState{state: StateRefused, reason: "disk", until: now.Add(refusedRetry)})
	for _, only := range [][]Ref{nil, {retryA, retryB, retryC}} {
		s.ClearRefused(only)
		for ref, want := range map[Ref]State{retryA: StateVerified, retryB: StateFetching} {
			if m, ok := s.mem[ref]; !ok || m.state != want {
				t.Fatalf("clearing %v disturbed %v: %+v (present %v)", only, ref, m, ok)
			}
		}
		if _, ok := s.mem[retryC]; ok {
			t.Fatalf("the refused entry survived clearing %v", only)
		}
		s.setForTest(retryC, memState{state: StateRefused, reason: "disk", until: now.Add(refusedRetry)})
	}
}

func TestClearRefusedWithNothingRefusedReturnsNothing(t *testing.T) {
	s, _ := clearRig()
	if got := s.ClearRefused(nil); len(got) != 0 {
		t.Fatalf("cleared %v from an empty store", got)
	}
}

func TestParseRef(t *testing.T) {
	if r, ok := ParseRef("rh-main@abc123"); !ok || r != (Ref{ID: "rh-main", Revision: "abc123"}) {
		t.Fatalf("ParseRef = %v, %v", r, ok)
	}
	for _, bad := range []string{"", "x", "@r", "x@", "x@r@s"} {
		if _, ok := ParseRef(bad); ok {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}
