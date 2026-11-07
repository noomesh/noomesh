// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// MinComputeCap is the lowest of the GPUs' compute capabilities, compared
// numerically as (major, minor) ("10.0" is above "8.0", "8.10" above "8.9").
// No GPU, or any value that does not parse, is an error: the minimum cannot
// be stated, so the fact is unknown (the i495 rule).
func MinComputeCap(caps []string) (string, error) {
	if len(caps) == 0 {
		if mutant.On("fc_min_empty") {
			return "", nil
		}
		return "", fmt.Errorf("no GPU reported a compute capability")
	}
	min := caps[0]
	for _, c := range caps {
		atLeast, err := nodewl.ComputeCapAtLeast(c, min)
		if err != nil && !mutant.On("fc_min_parse") {
			return "", err
		}
		if !atLeast != mutant.On("fc_min_dir") { // c is below the lowest so far
			min = c
		}
	}
	return min, nil
}

// Facts reports what this node is, for the heartbeat. A fact whose probe fails
// is OMITTED, never defaulted: an error must not become a fact.
type Facts struct {
	Mode           Mode
	Approvals      *Approvals
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
		if mutant.On("fc_nilprobe") {
			return "", nil
		}
		return "", fmt.Errorf("no compute capability probe")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.capVal != "" && !mutant.On("fc_cache") {
		return f.capVal, nil
	}
	caps, err := f.ComputeCaps()
	if err != nil {
		if mutant.On("fc_err_cached") {
			f.capVal = "0.0"
		}
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
	out := map[string]any{}
	if !mutant.On("fc_rep_policy") {
		out["addon_workloads_policy"] = string(f.Mode)
	}
	if !mutant.On("fc_rep_ctrl") {
		out["controller_host"] = f.ControllerHost
	}
	if f.Approvals != nil {
		if list, err := f.Approvals.List(); err != nil {
			slog.Warn("heartbeat omits addon_workloads_approvals: unreadable", "error", err)
			if mutant.On("fc_rep_appr_err") {
				out["addon_workloads_approvals"] = []Approval{}
			}
		} else {
			out["addon_workloads_approvals"] = list
		}
	} else if mutant.On("fc_rep_appr_nil") {
		out["addon_workloads_approvals"] = []Approval{}
	}
	if v, err := f.MinComputeCap(); err != nil {
		slog.Debug("heartbeat omits gpu_compute_cap", "error", err)
		if mutant.On("fc_rep_cap_err") {
			out["gpu_compute_cap"] = ""
		}
	} else {
		out["gpu_compute_cap"] = v
	}
	if f.NvidiaRuntime != nil {
		if ok, err := f.NvidiaRuntime(ctx); err != nil {
			slog.Debug("heartbeat omits nvidia_runtime", "error", err)
			if mutant.On("fc_rep_nv_err") {
				out["nvidia_runtime"] = false
			}
		} else {
			out["nvidia_runtime"] = ok
		}
	} else if mutant.On("fc_rep_nv_nil") {
		out["nvidia_runtime"] = false
	}
	if f.DataRootFreeGB != nil {
		if gb, err := f.DataRootFreeGB(); (err != nil && !mutant.On("fc_df_err")) || (math.IsNaN(gb) && !mutant.On("fc_df_nan")) || (math.IsInf(gb, 0) && !mutant.On("fc_df_inf")) || (gb < 0 && !mutant.On("fc_df_neg")) {
			slog.Debug("heartbeat omits data_root_free_gb", "error", err)
		} else {
			out["data_root_free_gb"] = mutant.Pick("fc_df_round", gb, math.Round(gb*10)/10)
		}
	} else if mutant.On("fc_rep_df_nil") {
		out["data_root_free_gb"] = 0.0
	}
	return out
}
