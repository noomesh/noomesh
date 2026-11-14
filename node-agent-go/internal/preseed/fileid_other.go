// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux && !darwin

package preseed

// statID: no identity to compare on this OS, so a record never hits and
// every present file is hashed.
func statID(string) (fileID, bool) { return fileID{}, false }
