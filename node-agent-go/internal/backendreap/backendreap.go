// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package backendreap holds what the reconciler's unplace reaper reports on
// the heartbeat:
//
//   - `reaped_backends`: each backend container the agent removed on an
//     explicit unplace (`{backend, at, unplaced_at}`), kept 24 h. The
//     controller deletes the tombstone an entry names (its acknowledgement)
//     and `noo cluster verify` notes it.
//   - `orphan_backends`: each container the agent owns that no placement
//     wants and no unplace names (`{backend, container, since}`). Reported,
//     NEVER removed: an absent placement is not an instruction.
//
// A package-level singleton for the reason modelpresence is one: the
// producer (reconcile) and the consumer (heartbeat) are wired at different
// points in agent startup.
package backendreap

import (
	"sort"
	"sync"
	"time"
)

// Keep is how long a reaped entry stays on the heartbeat.
const Keep = 24 * time.Hour

// Reaped is one backend removed on an explicit unplace.
type Reaped struct {
	Backend    string `json:"backend"`
	At         string `json:"at"`
	UnplacedAt string `json:"unplaced_at"`
	at         time.Time
}

// Orphan is one container the agent owns that nothing wants. Since is the
// container's creation time (RFC 3339).
type Orphan struct {
	Backend   string `json:"backend"`
	Container string `json:"container"`
	Since     string `json:"since"`
}

var (
	mu       sync.Mutex
	reaped   []Reaped
	orphans  []Orphan
	judgedOK bool
)

// RecordReaped adds one removal at now.
func RecordReaped(backend, unplacedAt string, now time.Time) {
	mu.Lock()
	defer mu.Unlock()
	reaped = append(reaped, Reaped{Backend: backend, At: now.UTC().Format(time.RFC3339), UnplacedAt: unplacedAt, at: now})
}

// SetOrphans replaces the orphan list with the latest judgement (an empty
// list is "none": it is then sent as `[]`).
func SetOrphans(list []Orphan) {
	mu.Lock()
	defer mu.Unlock()
	orphans = append([]Orphan{}, list...)
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Container < orphans[j].Container })
	judgedOK = true
}

// Report is what the heartbeat sends: the removals of the last 24 h, and the
// orphans with whether a judgement has been made yet (false: omit the key,
// an agent that has not looked says nothing).
func Report(now time.Time) (rs []Reaped, os []Orphan, judged bool) {
	mu.Lock()
	defer mu.Unlock()
	kept := reaped[:0]
	for _, r := range reaped {
		if now.Sub(r.at) <= Keep {
			kept = append(kept, r)
		}
	}
	reaped = kept
	return append([]Reaped{}, reaped...), append([]Orphan{}, orphans...), judgedOK
}

// Reset is for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	reaped, orphans, judgedOK = nil, nil, false
}
