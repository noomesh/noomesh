// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package preseed

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// Hashing a present weight at LOWER priority than the backends this node
// serves. A first verification after the upgrade hashes a whole snapshot
// (gemma-4-12B: ~6.5 GB) once; on a box that also serves vLLM to the fleet
// that must yield, not compete.
//
// Go cannot renice a goroutine — it migrates between OS threads, and a
// setpriority on "the current thread" would stick to whatever goroutine runs
// there next. So the hash runs on a goroutine LOCKED to its own thread, the
// thread is reniced (CPU nice hashNice) and given best-effort IO class level
// 7 (the lowest best-effort level: honoured by BFQ/CFQ, ignored by none/
// mq-deadline), and the goroutine returns WITHOUT unlocking: the runtime
// then terminates that thread instead of reusing it, so the lowered
// priority can never leak to other work. Every read the hash makes is a
// blocking syscall on that thread, so the IO priority covers it.
//
// Nice 10 rather than 19: sha256 uses one core either way (SHA-NI on
// amd64), and under contention nice 10 still gets ~1/10 of a nice-0 hog's
// share — enough that a loaded box finishes the hash inside the preseed
// budget, where nice 19 (~1/70) could starve it into a timeout.
const hashNice = 10

const (
	ioprioWhoProcess = 1 // IOPRIO_WHO_PROCESS: a tid on Linux
	ioprioClassBE    = 2 // IOPRIO_CLASS_BE
	ioprioClassShift = 13
	ioprioLowestBE   = 7
)

// lowerThreadPriority is a seam: tests read the nice the hash ran at.
var lowerThreadPriority = func() {
	tid := unix.Gettid()
	// The raw getpriority returns 20-nice. Only ever LOWER priority: an
	// agent already running nicer than hashNice keeps its nice (and a root
	// agent must not raise its own thread's priority by "setting" 10).
	if p, err := unix.Getpriority(unix.PRIO_PROCESS, tid); err == nil && 20-p < hashNice {
		_ = unix.Setpriority(unix.PRIO_PROCESS, tid, hashNice)
	}
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid),
		uintptr(ioprioClassBE<<ioprioClassShift|ioprioLowestBE))
}

// hashNiced runs fn on its own lowered-priority OS thread and returns its
// result. The caller blocks until fn is done.
func hashNiced(fn func() (string, error)) (string, error) {
	type result struct {
		sum string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread, on purpose (see above): the thread dies with
		// this goroutine.
		lowerThreadPriority()
		s, err := fn()
		ch <- result{s, err}
	}()
	r := <-ch
	return r.sum, r.err
}
