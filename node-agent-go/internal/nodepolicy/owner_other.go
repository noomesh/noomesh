// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !unix

package nodepolicy

import "io/fs"

// fileOwner cannot say who owns a file here, so no opt-in is ever read as
// root's.
func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }
