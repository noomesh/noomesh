// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package hostd

// Descriptor-relative spool access (followup i515 / 970b).
//
// On a Mac the spool directory belongs to the unprivileged user while
// noo-hostd runs as root. A path-based write (os.WriteFile = O_CREAT|O_TRUNC)
// follows a symlink the user planted at a name hostd writes, so root would
// truncate and overwrite any file on the machine. Every spool access in this
// package therefore goes through a directory descriptor:
//
//   - the spool is opened with O_DIRECTORY|O_NOFOLLOW (a symlink or a
//     non-directory is refused);
//   - names are resolved with openat/renameat/unlinkat against that fd, and
//     every open carries O_NOFOLLOW, so a planted symlink is never followed;
//   - writes create the temp file with O_CREAT|O_EXCL after unlinking any
//     leftover, fsync, then renameat onto the final name (which replaces a
//     symlink at that name; it never writes through it);
//   - reads of user-written files require a regular file and cap the size.
//
// The descriptor is opened per operation rather than held for the process
// lifetime: the user owns the directory and may rename it away and plant a
// new one, so a fresh NOFOLLOW open each time keeps hostd pointed at what
// the path names NOW (the previous code resolved the path every time too).

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// maxSpoolCommandBytes bounds a user-written command file. Real commands are
// a few hundred bytes (op, service, a handful of args, an optional rollback
// file list); 256 KiB is three orders of magnitude of headroom while keeping
// a planted multi-gigabyte file from being read into root's memory.
const maxSpoolCommandBytes = 256 << 10

// maxSpoolSmallReadBytes bounds the other files hostd reads back from a
// user-owned directory (the journal cursor is a single line).
const maxSpoolSmallReadBytes = 4 << 10

// spoolDir is an open, NOFOLLOW directory descriptor.
type spoolDir struct {
	fd   int
	path string
}

// openSpoolDir opens path as a directory without following a symlink at the
// final component.
func openSpoolDir(path string) (*spoolDir, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("spool %s refused: it is a symlink or not a directory: %w", path, err)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("spool %s refused: not a directory", path)
	}
	return &spoolDir{fd: fd, path: path}, nil
}

func (d *spoolDir) Close() { _ = unix.Close(d.fd) }

func (d *spoolDir) perr(op, name string, err error) error {
	return &os.PathError{Op: op, Path: filepath.Join(d.path, name), Err: err}
}

// names lists the entries of the directory the descriptor refers to.
func (d *spoolDir) names() ([]string, error) {
	// A fresh descriptor for the listing: a dup would share the read offset
	// and a second listing would return nothing.
	fd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, d.perr("readdir", ".", err)
	}
	f := os.NewFile(uintptr(fd), d.path)
	defer f.Close()
	return f.Readdirnames(-1)
}

// writeFileAtomic writes data to name via a temp file and renameat, never
// following a symlink at either name.
func (d *spoolDir) writeFileAtomic(name string, data []byte, perm uint32) error {
	tmp := "." + name + ".tmp"
	// A leftover temp (a crashed write, or a planted symlink/file) is
	// unlinked, not opened: unlinkat removes a symlink itself.
	if err := unix.Unlinkat(d.fd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return d.perr("unlink", tmp, err)
	}
	fd, err := unix.Openat(d.fd, tmp,
		unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC, perm)
	if err != nil {
		return d.perr("open", tmp, err)
	}
	cleanup := func() { _ = unix.Unlinkat(d.fd, tmp, 0) }
	for off := 0; off < len(data); {
		n, werr := unix.Write(fd, data[off:])
		if werr != nil {
			if errors.Is(werr, unix.EINTR) {
				continue
			}
			_ = unix.Close(fd)
			cleanup()
			return d.perr("write", tmp, werr)
		}
		off += n
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		cleanup()
		return d.perr("fsync", tmp, err)
	}
	if err := unix.Close(fd); err != nil {
		cleanup()
		return d.perr("close", tmp, err)
	}
	if err := unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		cleanup()
		return d.perr("rename", name, err)
	}
	return nil
}

// openAppend opens name for append (creating it), refusing a symlink and any
// non-regular file.
func (d *spoolDir) openAppend(name string, perm uint32) (*os.File, error) {
	// O_NONBLOCK so a planted FIFO cannot hang the open; it is rejected by
	// the fstat below. It is a no-op on a regular file.
	fd, err := unix.Openat(d.fd, name,
		unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, d.perr("open", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, d.perr("fstat", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, d.perr("open", name, errNotRegular)
	}
	return os.NewFile(uintptr(fd), filepath.Join(d.path, name)), nil
}

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file exceeds the size cap")
)

// readFile reads name without following a symlink. The entry must be a
// regular file no larger than max bytes; anything else is an error and is
// never read. It also returns the file's modification time.
func (d *spoolDir) readFile(name string, max int64) ([]byte, time.Time, error) {
	// O_NONBLOCK so a planted FIFO cannot hang the open.
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, time.Time{}, d.perr("open", name, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, d.perr("fstat", name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, time.Time{}, d.perr("read", name, errNotRegular)
	}
	if st.Size() > max {
		return nil, time.Time{}, d.perr("read", name, errTooLarge)
	}
	// Read at most max+1 so a file that grows after the fstat is caught.
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, time.Time{}, d.perr("read", name, err)
	}
	if int64(len(b)) > max {
		return nil, time.Time{}, d.perr("read", name, errTooLarge)
	}
	return b, st.ModTime(), nil
}

func (d *spoolDir) rename(oldName, newName string) error {
	if err := unix.Renameat(d.fd, oldName, d.fd, newName); err != nil {
		return d.perr("rename", oldName, err)
	}
	return nil
}

// remove unlinks name (a symlink is removed itself, never followed).
func (d *spoolDir) remove(name string) error {
	if err := unix.Unlinkat(d.fd, name, 0); err != nil {
		return d.perr("unlink", name, err)
	}
	return nil
}
