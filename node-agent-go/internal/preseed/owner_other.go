// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !unix

package preseed

import "os"

// ownerUID: no uid on this OS.
func ownerUID(os.FileInfo) (int, bool) { return 0, false }
