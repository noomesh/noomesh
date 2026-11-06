// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !unix

package modelsets

import "errors"

func freeBytes(string) (uint64, error) {
	return 0, errors.New("free space is not readable on this platform")
}

func ownerUID(string) (uint32, bool) { return 0, false }
