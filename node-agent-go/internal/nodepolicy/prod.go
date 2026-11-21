// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"fmt"
	"os"

	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// FreeGB is the free space, in GB, under root as usages reports it. No answer
// for root (statfs failed, or this platform reports none) is an error: the
// space is unknown, not zero.
func FreeGB(root string, usages func([]string) []hardware.DiskUsage) (float64, error) {
	if root == "" {
		return 0, fmt.Errorf("no data root")
	}
	us := usages([]string{root})
	if len(us) == 0 {
		return 0, fmt.Errorf("no filesystem figures for %s", root)
	}
	return us[0].AvailGB, nil
}

// DataRootFreeGB is FreeGB for this process's resolved data root, bounded
// (dataroots.Bounded): a statfs on a hung mount blocks in the kernel, and the
// heartbeat that waits on it goes silent. On timeout the figure is omitted.
func DataRootFreeGB() (float64, error) {
	root := dataroots.Resolve(os.Getenv).NooDataRoot
	type res struct {
		gb  float64
		err error
	}
	got, err := dataroots.Bounded(root, func() res { gb, err := FreeGB(root, hardware.DiskUsages); return res{gb, err} })
	if err != nil {
		return 0, err
	}
	return got.gb, got.err
}
