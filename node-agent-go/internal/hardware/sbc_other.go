// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hardware

// DeviceTreeModel reports "" off Linux: /proc/device-tree is a Linux
// device-tree mount, and macOS/Windows hosts are never SBCs.
func DeviceTreeModel() string {
	return ""
}
