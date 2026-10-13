// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

import "syscall"

func init() {
	statfsBytes = func(path string) (total, free uint64, ok bool) {
		var st syscall.Statfs_t
		if syscall.Statfs(path, &st) != nil {
			return 0, 0, false
		}
		bs := uint64(st.Bsize)
		return st.Blocks * bs, st.Bavail * bs, true
	}
}
