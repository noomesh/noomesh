// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// composeLockPath must match scripts/lib-compose-lock.sh EXACTLY. The whole
// point of the lock is that this daemon and the launcher scripts contend for
// the same one; a different path means two owners who each believe they hold
// single-flight, which is precisely the failure that took a fleet down.
func composeLockPath() string {
	tmp := os.Getenv("TMPDIR")
	if tmp == "" {
		tmp = "/tmp"
	}
	if p := os.Getenv("COMPOSE_LOCK_FILE"); p != "" {
		return p
	}
	return filepath.Join(tmp, "noo-compose.lock")
}

func composeLockWait() time.Duration {
	return 600 * time.Second
}

// acquireComposeLock blocks until the shared compose lock is held, the wait
// budget expires, or ctx is cancelled. Returns a release func.
//
// Blocking rather than refusing, matching the bash library: an operator's
// instinct during an incident is to re-run the command, and queueing that
// harmlessly beats either racing (the outage) or erroring (which invites a
// third, angrier attempt).
//
// A lock file that cannot be OPENED degrades to running unlocked, also
// matching bash. That is the lesser evil: refusing every recreate because
// /tmp is odd would make the guard itself the outage.
func acquireComposeLock(ctx context.Context) (func(), error) {
	path := composeLockPath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func() {}, nil
	}

	deadline := time.Now().Add(composeLockWait())
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("gave up waiting for the compose lock after %s", composeLockWait())
		}
		if !sleepCtx(ctx, 500*time.Millisecond) {
			_ = f.Close()
			return nil, ctx.Err()
		}
	}
}
