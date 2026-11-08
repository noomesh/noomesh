// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !unix

package hostd

import (
	"errors"
	"os"
	"time"
)

// noo-hostd targets Linux and macOS. This stub only keeps the package
// compiling on a developer's Windows machine; the spool is unusable there.

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file exceeds the size cap")
	errNoSpoolFD  = errors.New("descriptor-relative spool access needs a unix host")
)

const (
	maxSpoolCommandBytes   = 256 << 10
	maxSpoolSmallReadBytes = 4 << 10
)

type spoolDir struct{}

func openSpoolDir(string) (*spoolDir, error)                     { return nil, errNoSpoolFD }
func (d *spoolDir) Close()                                       {}
func (d *spoolDir) names() ([]string, error)                     { return nil, errNoSpoolFD }
func (d *spoolDir) writeFileAtomic(string, []byte, uint32) error { return errNoSpoolFD }
func (d *spoolDir) openAppend(string, uint32) (*os.File, error)  { return nil, errNoSpoolFD }
func (d *spoolDir) readFile(string, int64) ([]byte, time.Time, error) {
	return nil, time.Time{}, errNoSpoolFD
}
func (d *spoolDir) rename(string, string) error { return errNoSpoolFD }
func (d *spoolDir) remove(string) error         { return errNoSpoolFD }
