// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package hostd

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// rc.1 rehearsal: a lock file this process cannot WRITE (created 0644 by
// another user; modelled here as 0444) must still be locked, not skipped.
// Before, the write-open failed and the recreate ran unlocked.
func TestComposeLockHoldsAFileItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a 0444 file anyway; the case is a non-root owner")
	}
	p := filepath.Join(t.TempDir(), "noo-compose.lock")
	if err := os.WriteFile(p, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMPOSE_LOCK_FILE", p)
	release, err := acquireComposeLock(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()
	other, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("the lock was not held: a 0444 lock file ran unlocked")
	}
}
