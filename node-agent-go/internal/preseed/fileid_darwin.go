// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build darwin

package preseed

import "syscall"

// statID: see fileid_linux.go.
func statID(path string) (fileID, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fileID{}, false
	}
	return fileID{
		Dev:     uint64(st.Dev),
		Ino:     st.Ino,
		Size:    st.Size,
		MtimeNs: st.Mtimespec.Sec*1e9 + st.Mtimespec.Nsec,
		CtimeNs: st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec,
	}, true
}
