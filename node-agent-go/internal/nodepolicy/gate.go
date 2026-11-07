// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Gate is the node's re-check of a placement before anything is provisioned
// or started. A refusal is a *nodewl.Error whose Code is the reason the row
// reports, spelled as the contract spells it (and as the gateway's own
// placement refusal), and it changes no container.
type Gate struct {
	Mode      Mode
	Approvals *Approvals
	// ControllerHost: this node is the controller's host. OnController: its
	// owner opted in to running node workloads there (a single-box install).
	ControllerHost bool
	OnController   bool
	// NvidiaRuntime says whether the nvidia container runtime is registered.
	// An error is UNKNOWN, never "missing".
	NvidiaRuntime func(ctx context.Context) (bool, error)
	// ComputeCap is the lowest compute capability across this node's GPUs.
	// An error is UNKNOWN, never "low".
	ComputeCap func() (string, error)
	// MainSet returns the manifest of a set this node holds verified, for the
	// profile's min_compute. An error means "not available yet": the
	// provisioner has its own verdict on the set.
	MainSet func(id, revision string) (nodewl.ModelSet, error)
}

func refuse(code, format string, a ...any) error {
	return &nodewl.Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Check returns nil when the node agrees to run e, else the refusal. The
// consent verdict comes first and alone: an entry the owner has not agreed to
// is not examined any further.
func (g *Gate) Check(ctx context.Context, e nodewl.Entry) error {
	if err := g.consent(e); err != nil {
		return err
	}
	if g.ControllerHost && !g.OnController {
		return refuse(nodewl.ReasonControllerHost, "this node is the controller's host and its owner has not opted in to node workloads here")
	}
	if e.Decl.Accel.GPU > 0 && g.NvidiaRuntime != nil {
		ok, err := g.NvidiaRuntime(ctx)
		switch {
		case err != nil:
			slog.Warn("node workload gate: nvidia runtime unknown; not refusing on it", "error", err)
		case !ok:
			return refuse(nodewl.ReasonNvidiaRuntimeMissing, "the nvidia container runtime is not registered with docker")
		}
	}
	return g.profile(e)
}

func (g *Gate) consent(e nodewl.Entry) error {
	switch g.Mode {
	case ModeAuto:
		return nil
	case ModeApprove:
		if g.Approvals == nil {
			return refuse(nodewl.ReasonConsentUnapproved, "no approvals are kept on this node")
		}
		ok, err := g.Approvals.Has(e.Addon, e.Image.Digest)
		if err != nil {
			// Consent that cannot be read is consent that cannot be shown.
			slog.Warn("node workload gate: approvals unreadable; refusing", "error", err)
			return refuse(nodewl.ReasonConsentUnapproved, "the approvals file cannot be read")
		}
		if !ok {
			return refuse(nodewl.ReasonConsentUnapproved, "%s at %s is not approved on this node", e.Addon, e.Image.Digest)
		}
		return nil
	default: // ModeNone, and any value nothing recognises
		return refuse(nodewl.ReasonConsentNone, "this node's addon_workloads_policy is none")
	}
}

// profile judges the entry's chosen profile against the main slot's set (when
// this node holds that set) and the GPU's compute capability against the
// profile's min_compute.
func (g *Gate) profile(e nodewl.Entry) error {
	if g.MainSet == nil || len(e.Decl.Models) == 0 {
		return nil
	}
	refs := e.Sets[e.Decl.Models[0].Slot]
	if len(refs) == 0 {
		return nil
	}
	set, err := g.MainSet(refs[0].ID, refs[0].Revision)
	if err != nil || len(set.Needs.Profiles) == 0 {
		return nil
	}
	if err := nodewl.CheckProfile(e, set); err != nil {
		return err
	}
	if e.Decl.Accel.GPU == 0 || g.ComputeCap == nil {
		return nil
	}
	var min string
	for _, p := range set.Needs.Profiles {
		if p.Name == *e.Profile {
			min = p.MinCompute
		}
	}
	if min == "" {
		return nil
	}
	have, err := g.ComputeCap()
	if err != nil {
		slog.Warn("node workload gate: compute capability unknown; not refusing on it", "error", err)
		return nil
	}
	ok, err := nodewl.ComputeCapAtLeast(have, min)
	if err != nil {
		slog.Warn("node workload gate: compute capability unparseable; treated as unknown", "have", have, "need", min, "error", err)
		return nil
	}
	if !ok {
		return refuse(nodewl.ReasonComputeCapLow, "this node's GPU is compute capability %s, profile %q needs %s", have, *e.Profile, min)
	}
	return nil
}
