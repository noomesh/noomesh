// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Path-keyed wrappers over spoolDir for call sites that name a spool
// directory and a file in it. Each opens the directory with O_NOFOLLOW for
// the one operation (see spool_fd_unix.go), so no caller resolves a
// user-controllable name through a path.

// spoolWriteFile atomically writes data to dir/name (tmp + fsync + renameat).
func spoolWriteFile(dir, name string, data []byte, perm uint32) error {
	d, err := openSpoolDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.writeFileAtomic(name, data, perm)
}

// spoolOpenAppend opens dir/name for appending, creating it, without
// following a symlink.
func spoolOpenAppend(dir, name string) (*os.File, error) {
	d, err := openSpoolDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.openAppend(name, 0o644)
}

// spoolReadFile reads dir/name: regular file only, size-capped, no symlink.
func spoolReadFile(dir, name string, max int64) ([]byte, time.Time, error) {
	d, err := openSpoolDir(dir)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer d.Close()
	return d.readFile(name, max)
}

// spoolRename renames within dir.
func spoolRename(dir, oldName, newName string) error {
	d, err := openSpoolDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.rename(oldName, newName)
}

// spoolNamesWithSuffix lists entries of dir ending in suffix.
func spoolNamesWithSuffix(dir, suffix string) ([]string, error) {
	d, err := openSpoolDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	all, err := d.names()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range all {
		if strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}
	return out, nil
}

// spoolRemoveSuffix unlinks every entry of dir ending in suffix and returns
// how many it removed.
func spoolRemoveSuffix(dir, suffix string) int {
	d, err := openSpoolDir(dir)
	if err != nil {
		return 0
	}
	defer d.Close()
	all, err := d.names()
	if err != nil {
		return 0
	}
	n := 0
	for _, name := range all {
		if strings.HasSuffix(name, suffix) && d.remove(name) == nil {
			n++
		}
	}
	return n
}

// cmdFileRe is the shape of a command file name every producer mints
// (<time_ns>-<hex>.cmd.json, or a caller-chosen stem of the same alphabet).
// Anything else in the spool is ignored.
var cmdFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}` + regexp.QuoteMeta(cmdSuffix) + `$`)

// splitSpoolPath splits dir/name for the path-keyed APIs.
func splitSpoolPath(path string) (dir, name string) {
	return filepath.Dir(path), filepath.Base(path)
}
