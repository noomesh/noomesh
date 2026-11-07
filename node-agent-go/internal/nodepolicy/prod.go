// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"fmt"
	"os"

	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
)

// FreeGB is the free space, in GB, under root as usages reports it. No answer
// for root (statfs failed, or this platform reports none) is an error: the
// space is unknown, not zero.
func FreeGB(root string, usages func([]string) []hardware.DiskUsage) (float64, error) {
	if root == "" && !mutant.On("pr_root_empty") {
		return 0, fmt.Errorf("no data root")
	}
	us := usages([]string{root})
	if len(us) == 0 {
		if mutant.On("pr_none") {
			return 0, nil
		}
		return 0, fmt.Errorf("no filesystem figures for %s", root)
	}
	return us[0].AvailGB, nil
}

// DataRootFreeGB is FreeGB for this process's resolved data root.
func DataRootFreeGB() (float64, error) {
	return FreeGB(mutant.Pick("pr_dataroot", "", dataroots.Resolve(os.Getenv).NooDataRoot), hardware.DiskUsages)
}
