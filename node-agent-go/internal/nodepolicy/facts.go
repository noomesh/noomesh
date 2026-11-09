// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// MinComputeCap is the lowest of the GPUs' compute capabilities, compared
// numerically as (major, minor) ("10.0" is above "8.0", "8.10" above "8.9").
// No GPU, or any value that does not parse, is an error: the minimum cannot
// be stated, so the fact is unknown (the i495 rule).
func MinComputeCap(caps []string) (string, error) {
	if len(caps) == 0 {
		return "", fmt.Errorf("no GPU reported a compute capability")
	}
	min := caps[0]
	for _, c := range caps {
		atLeast, err := nodewl.ComputeCapAtLeast(c, min)
		if err != nil {
			return "", err
		}
		if !atLeast { // c is below the lowest so far
			min = c
		}
	}
	return min, nil
}

// Facts reports what this node is, for the heartbeat. A fact whose probe fails
// is OMITTED, never defaulted: an error must not become a fact.
type Facts struct {
	Mode      Mode
	Approvals *Approvals
	// Controller is the controller's signed approval set (i596): reported
	// as addon_workloads_controller, and, on a node whose owner opted in,
	// its entries join addon_workloads_approvals with source "controller".
	Controller     *ControllerApprovals
	ControllerHost bool
	// ComputeCaps lists each GPU's compute capability. NvidiaRuntime says
	// whether the nvidia runtime is registered. DataRootFreeGB is the free
	// space under the data root. Each returns an error when it cannot say.
	ComputeCaps    func() ([]string, error)
	NvidiaRuntime  func(ctx context.Context) (bool, error)
	DataRootFreeGB func() (float64, error)

	mu     sync.Mutex
	capVal string
}

// MinComputeCap is the cached lowest compute capability. A compute capability
// does not change under a running agent, so a good answer is kept; a failure
// is not cached and the next call probes again.
func (f *Facts) MinComputeCap() (string, error) {
	if f.ComputeCaps == nil {
		return "", fmt.Errorf("no compute capability probe")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.capVal != "" {
		return f.capVal, nil
	}
	caps, err := f.ComputeCaps()
	if err != nil {
		return "", err
	}
	v, err := MinComputeCap(caps)
	if err != nil {
		return "", err
	}
	f.capVal = v
	return v, nil
}

// Report is the node-fact keys of the heartbeat that are known right now.
// `nvidia_driver_caps_ok` is never among them: no sound check of the driver's
// ability to grant compute,utility exists on a host that must not run a
// container to find out, and a guess would be a fact the node did not
// establish.
func (f *Facts) Report(ctx context.Context) map[string]any {
	out := map[string]any{"addon_workloads_policy": string(f.Mode), "controller_host": f.ControllerHost}
	if f.Approvals != nil {
		if list, err := f.Approvals.List(); err != nil {
			slog.Warn("heartbeat omits addon_workloads_approvals: unreadable", "error", err)
		} else {
			out["addon_workloads_approvals"] = f.withController(list)
		}
	}
	if f.Controller != nil {
		out["addon_workloads_controller"] = f.Controller.Status()
	}
	if v, err := f.MinComputeCap(); err != nil {
		slog.Debug("heartbeat omits gpu_compute_cap", "error", err)
	} else {
		out["gpu_compute_cap"] = v
	}
	if f.NvidiaRuntime != nil {
		if ok, err := f.NvidiaRuntime(ctx); err != nil {
			slog.Debug("heartbeat omits nvidia_runtime", "error", err)
		} else {
			out["nvidia_runtime"] = ok
		}
	}
	if f.DataRootFreeGB != nil {
		if gb, err := f.DataRootFreeGB(); err != nil || math.IsNaN(gb) || math.IsInf(gb, 0) || gb < 0 {
			slog.Debug("heartbeat omits data_root_free_gb", "error", err)
		} else {
			out["data_root_free_gb"] = math.Round(gb*10) / 10
		}
	}
	return out
}

// maxReportedApprovals is the gateway's cap on addon_workloads_approvals: a
// longer list is dropped whole, as unknown.
const maxReportedApprovals = 256

// reportedApproval is a row of addon_workloads_approvals that the controller's
// set admitted; the owner's own rows carry no source.
type reportedApproval struct {
	Addon  string `json:"addon"`
	Digest string `json:"digest"`
	Source string `json:"source"`
}

// withController is the owner's approvals, then (on a node whose owner opted
// in) each controller-approved add-on and digest the owner did not approve
// too, marked source "controller", up to the gateway's cap. A controller set
// that does not verify adds nothing. Without controller rows the list is
// returned as it is.
func (f *Facts) withController(local []Approval) any {
	if f.Controller == nil {
		return local
	}
	ctl, _, err := f.Controller.List()
	if err != nil {
		slog.Warn("heartbeat: addon_workloads_approvals carries no controller rows; the set does not verify", "error", err)
		return local
	}
	have := map[Approval]bool{}
	for _, x := range local {
		have[x] = true
	}
	var extra []reportedApproval
	for _, x := range ctl {
		if !have[x] {
			extra = append(extra, reportedApproval{Addon: x.Addon, Digest: x.Digest, Source: "controller"})
		}
	}
	if len(extra) == 0 {
		return local
	}
	out := make([]any, 0, len(local)+len(extra))
	for _, x := range local {
		out = append(out, x)
	}
	for _, x := range extra {
		if len(out) >= maxReportedApprovals {
			slog.Warn("heartbeat: addon_workloads_approvals is at the gateway's cap; some controller rows are not reported", "cap", maxReportedApprovals)
			break
		}
		out = append(out, x)
	}
	return out
}
