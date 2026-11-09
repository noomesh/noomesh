// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package nodepolicy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO (or any other non-regular file) with one link, owned by the
// expected owner and writable by no one else is still not an opt-in: only a
// regular file root wrote counts. (A symlink and a directory are refused by
// the mode and link checks too; this one is the regular-file check alone.)
func TestAnOptInThatIsAFIFOIsNotAnOptIn(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, OptInFile)
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := optedIn(dir, uint32(os.Getuid())); ok || err == nil {
		t.Fatalf("a FIFO opt-in: %v %v", ok, err)
	}
}
