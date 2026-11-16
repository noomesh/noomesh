// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package preseed

import "syscall"

// statID is the identity a verified-digest record hit must match, for the
// regular file at path (links followed: what a backend opening path reads).
func statID(path string) (fileID, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fileID{}, false
	}
	return fileID{
		Dev:     uint64(st.Dev),
		Ino:     uint64(st.Ino),
		Size:    int64(st.Size),
		MtimeNs: int64(st.Mtim.Sec)*1e9 + int64(st.Mtim.Nsec),
		CtimeNs: int64(st.Ctim.Sec)*1e9 + int64(st.Ctim.Nsec),
	}, true
}
