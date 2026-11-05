// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build darwin

package hardware

import (
	"context"
	"os/exec"
	"time"
)

// readLoad1 asks the kernel for vm.loadavg: macOS has no /proc/loadavg,
// which is how every Mac reported a CPU load of 0. golang.org/x/sys is only
// an indirect dependency here and the stdlib has no raw sysctl, so this
// execs sysctl under a deadline.
func readLoad1() (float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0, false
	}
	return parseDarwinLoadavg(string(out))
}
