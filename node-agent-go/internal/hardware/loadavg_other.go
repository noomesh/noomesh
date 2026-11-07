// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux && !darwin

package hardware

// readLoad1 has no implementation on this platform: the load is UNKNOWN.
func readLoad1() (float64, bool) { return 0, false }
