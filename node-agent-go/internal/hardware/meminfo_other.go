// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux && !darwin

package hardware

// readMemory has no implementation on this platform. ok=false means UNKNOWN:
// callers report absence rather than inventing a figure.
func readMemory() (totalKB int64, availKB int64, ok bool) { return 0, 0, false }
