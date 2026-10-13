// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import (
	"os"
	"strings"
)

// deviceTreePath is a var so tests can point it at a fixture.
var deviceTreePath = "/proc/device-tree/model"

// DeviceTreeModel returns the raw SBC model string from
// /proc/device-tree/model, or "" when the file is absent or unreadable.
//
// The RAW string is reported deliberately — the agent does NOT classify it
// into an SBC family. The canonical model→family mapping lives in exactly
// one place (`sbc_family_from_model` in noo-cli's provisioner), and
// copying that table here would recreate the declared-vs-derived drift this
// field exists to fix: two mappings, one quietly stale. The
// controller maps; the agent reports what the hardware says.
//
// The file exists on every ARM SBC and never on x86, so a non-empty value
// is itself a strong SBC signal. It is NUL-terminated (device-tree string
// convention), hence the explicit trim.
func DeviceTreeModel() string {
	data, err := os.ReadFile(deviceTreePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.Trim(string(data), "\x00"))
}
