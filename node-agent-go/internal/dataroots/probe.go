// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProbeTimeout bounds each disk probe of a data root (the heartbeat's
// data_roots, its GGUF listing and free-space figure, the reconcile tick's
// listing, the per-use gates). 5 s: a healthy local disk answers in
// milliseconds and a spun-down one wakes in a few seconds; three distinct
// paths (the root, MODELS_DIR, a quarantine listing) at 5 s each still fit
// well inside the 30 s heartbeat interval, so a hung disk never costs a beat.
// A var for tests.
var ProbeTimeout = 5 * time.Second

// NotAnsweringError is a probe that did not return within ProbeTimeout, or
// whose earlier probe is still stuck.
type NotAnsweringError struct {
	Path  string
	Since time.Time
	Took  time.Duration
}

func (e *NotAnsweringError) Error() string {
	return fmt.Sprintf("data root %s not answering: no reply within %s since %s (a hung mount or a failing disk); "+
		"the agent keeps beating and refuses backend starts and fetches into it until it answers",
		e.Path, e.Took, e.Since.UTC().Format(time.RFC3339))
}

type probeState struct {
	mu                 sync.Mutex
	finished, timedOut bool
	since              time.Time
}

var (
	probeMu   sync.Mutex
	probeHung = map[string]*probeState{}
)

// Bounded runs fn (a disk probe of path) and waits at most ProbeTimeout.
// Go cannot cancel a syscall stuck in the kernel, so a probe that times out
// keeps its goroutine; until it returns, further probes of the same path
// answer "not answering" at once instead of stacking more stuck goroutines.
// Concurrent probes of a healthy path run independently.
func Bounded[T any](path string, fn func() T) (T, error) {
	var zero T
	key := filepath.Clean(path)
	probeMu.Lock()
	if st, hung := probeHung[key]; hung {
		probeMu.Unlock()
		return zero, &NotAnsweringError{Path: key, Since: st.since, Took: ProbeTimeout}
	}
	probeMu.Unlock()

	st := &probeState{since: time.Now()}
	ch := make(chan T, 1)
	go func() {
		v := fn()
		ch <- v
		st.mu.Lock()
		st.finished = true
		late := st.timedOut
		st.mu.Unlock()
		if late {
			probeMu.Lock()
			if probeHung[key] == st {
				delete(probeHung, key)
			}
			probeMu.Unlock()
		}
	}()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v, nil
	case <-timer.C:
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.finished {
		return <-ch, nil
	}
	st.timedOut = true
	probeMu.Lock()
	probeHung[key] = st
	probeMu.Unlock()
	return zero, &NotAnsweringError{Path: key, Since: st.since, Took: ProbeTimeout}
}

// ReadDirBounded is os.ReadDir under Bounded.
func ReadDirBounded(dir string) ([]os.DirEntry, error) {
	type res struct {
		e   []os.DirEntry
		err error
	}
	got, err := Bounded(dir, func() res { e, err := os.ReadDir(dir); return res{e, err} })
	if err != nil {
		return nil, err
	}
	return got.e, got.err
}

// Gate is the per-use check of this process's roots, bounded: nil when a
// backend may start on them. It is Refusal(Current()), re-evaluated on every
// use, so a refusal clears itself once the mount is back.
func Gate() error {
	r := Resolve(os.Getenv)
	probs, err := Bounded(r.NooDataRoot, Current)
	if err != nil {
		return err
	}
	return Refusal(probs)
}

// mkdirAll is os.MkdirAll; tests count its calls.
var mkdirAll = os.MkdirAll

// MkdirAll is os.MkdirAll for the fetch paths (a GGUF pull, a preseed, a
// model set), gated on the data roots' filesystem: a directory under a root
// that is not on its recorded filesystem (an empty mount point, the disk not
// mounted), whose declared mount is not there, or that does not answer is
// NOT created, so nothing lands on the root disk to be shadowed by the mount
// later. A directory under no root is left to the caller as before.
func MkdirAll(dir string, perm os.FileMode) error {
	if err := fsGate(dir); err != nil {
		return err
	}
	return mkdirAll(dir, perm)
}

// fsGate refuses dir when a root holding it has a filesystem problem.
func fsGate(dir string) error {
	r := Resolve(os.Getenv)
	clean := filepath.Clean(dir)
	var holding []string
	for _, p := range fsPaths(r) {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			holding = append(holding, p)
		}
	}
	if len(holding) == 0 {
		return nil
	}
	finds, err := Bounded(r.NooDataRoot, func() []fsFinding { return checkFilesystems(r) })
	if err != nil {
		return fmt.Errorf("not creating %s: %w", dir, err)
	}
	for _, f := range finds {
		for _, h := range holding {
			if f.path == h {
				return fmt.Errorf("not creating %s: data root refused (%s): %s", dir, f.Code, f.Detail)
			}
		}
	}
	return nil
}

// WaitProbeForTest waits up to d for a stuck probe of path to return, and
// reports whether it did. Tests call it before restoring a seam the stuck
// probe still reads. Never called by the agent.
func WaitProbeForTest(path string, d time.Duration) bool {
	key := filepath.Clean(path)
	for deadline := time.Now().Add(d); ; time.Sleep(5 * time.Millisecond) {
		probeMu.Lock()
		_, hung := probeHung[key]
		probeMu.Unlock()
		if !hung {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}
