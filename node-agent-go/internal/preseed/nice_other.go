// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package preseed

// hashNiced: no per-thread priority here (macOS nodes run no HF backends);
// the hash runs as is.
func hashNiced(fn func() (string, error)) (string, error) { return fn() }
