// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import "os"

// readLoad1 reads the 1-minute load average from /proc/loadavg.
func readLoad1() (float64, bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	return parseProcLoadavg(string(data))
}
