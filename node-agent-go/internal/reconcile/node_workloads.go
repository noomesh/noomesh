// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// nodeWorkloads is the lifecycle the reconciler drives (*docker.NodeWorkloads
// in production, a fake in tests).
type nodeWorkloads interface {
	Converge(ctx context.Context, e nodewl.Entry)
	Refuse(addon, name string, err error)
	Retain(keep map[string]bool)
	ReleaseOrphans(ctx context.Context, keep map[string]bool)
	MarkRead()
	Rows() []dockerpkg.Row
	IsManaged(ctx context.Context, addon, name string) (bool, error)
	StartManaged(ctx context.Context, e nodewl.Entry) error
	StopManaged(ctx context.Context, e nodewl.Entry) error
	ManagedStatus(ctx context.Context, addon, name string) (dockerpkg.ManagedState, error)
}

// newNodeWorkloads builds the lifecycle, the node's gate and its facts from
// the agent's config. The policy is the config's, default none; a value that
// is not a mode was already turned into none by config.Load, and is said so.
func newNodeWorkloads(cfg *config.Config, docker *dockerpkg.Client, sets *modelsets.Store) (nodeWorkloads, *nodepolicy.Facts) {
	mode, _ := nodepolicy.ParseMode(cfg.AddonWorkloadsPolicy)
	if cfg.AddonWorkloadsPolicyAsked != "" {
		slog.Warn("NOO_ADDON_WORKLOADS is not none, approve or auto; add-on node workloads stay refused (none)",
			"value", cfg.AddonWorkloadsPolicyAsked)
	}
	approvals := nodepolicy.NewApprovals(cfg.StateDir)
	var nvidia func(context.Context) (bool, error)
	if docker != nil {
		nvidia = docker.NvidiaRuntimeKnown
	}
	facts := &nodepolicy.Facts{
		Mode: mode, Approvals: approvals, ControllerHost: cfg.SelfNode,
		ComputeCaps:    (&hardware.GPUDetector{}).DetectComputeCaps,
		NvidiaRuntime:  nvidia,
		DataRootFreeGB: nodepolicy.DataRootFreeGB,
	}
	if docker == nil {
		return nil, facts
	}
	gate := &nodepolicy.Gate{
		Mode: mode, Approvals: approvals,
		ControllerHost: cfg.SelfNode, OnController: cfg.AddonWorkloadsOnController,
		NvidiaRuntime: nvidia,
		ComputeCap:    facts.MinComputeCap,
		MainSet: func(id, revision string) (nodewl.ModelSet, error) {
			return sets.VerifiedManifest(modelsets.Ref{ID: id, Revision: revision})
		},
	}
	nw := dockerpkg.NewNodeWorkloads(docker, sets)
	nw.SetAdmit(gate.Check)
	return nw, facts
}

// convergeNodeWorkloads drives every node workload desired-config names toward
// its state (i300 F5b). It runs before settleEmptyState: a node placed nothing
// else still holds its add-on's workloads.
//
//   - No node_workloads key (an older gateway): nothing happens and nothing
//     is reported (unknown, not "holds none"). An explicit empty list is READ:
//     the rows of workloads no longer listed are dropped and `node_workloads`
//     is reported as a known-empty list.
//   - desired-config that does not validate as a whole: nothing is touched.
//   - A read that succeeded and parsed, but no longer lists a workload this
//     agent created: that workload is `absent` (drained first if running).
//   - A row that does not validate is refused alone, with its own reason; the
//     others converge.
//   - Each workload converges on its own goroutine, one at a time per
//     workload: an image pull or a drain must not hold up the pass.
func (r *Reconciler) convergeNodeWorkloads(ctx context.Context, t *tick) bool {
	if r.nodeWL == nil || len(t.desired.NodeWorkloads) == 0 {
		return true
	}
	rows, err := parseNodeWorkloadRows(t.desired.NodeWorkloads, r.cfg.NodeID)
	if err != nil {
		slog.Warn("reconcile.node_workloads_desired_unreadable; touching nothing", "error", err)
		return true
	}
	r.nodeWL.MarkRead()
	keep := map[string]bool{}
	for _, row := range rows {
		keep[row.Addon+"/"+row.Name] = true
		if row.Err != nil {
			r.nodeWL.Refuse(row.Addon, row.Name, row.Err)
			slog.Warn("reconcile.node_workload_refused", "addon", row.Addon, "workload", row.Name,
				"reason", nodewl.CodeOf(row.Err), "error", row.Err)
			continue
		}
		r.goConverge(ctx, row.Entry)
	}
	// Reached only when desired-config was read AND parsed as a whole: a
	// failed or unparseable read returned above and removes nothing (i495).
	// A workload this agent created that the list no longer names is `absent`.
	// A row whose addon/name cannot be read is skipped by the parser; it may
	// name a workload on this node, so the sweep waits for a list it can trust.
	var listed []json.RawMessage
	if json.Unmarshal(t.desired.NodeWorkloads, &listed) == nil && len(listed) == len(rows) {
		r.nodeWL.ReleaseOrphans(ctx, keep)
	} else {
		slog.Warn("reconcile.node_workloads_row_unnameable; removing no orphan this pass")
	}
	r.nodeWL.Retain(keep)
	return true
}

func parseNodeWorkloadRows(raw json.RawMessage, ownAgentCN string) ([]nodewl.DesiredRow, error) {
	frag, err := json.Marshal(map[string]json.RawMessage{"node_workloads": raw})
	if err != nil {
		return nil, fmt.Errorf("node_workloads: %w", err)
	}
	return nodewl.ParseDesiredRows(frag, ownAgentCN)
}

func (r *Reconciler) goConverge(ctx context.Context, e nodewl.Entry) {
	k := e.Addon + "/" + e.Name
	r.nwMu.Lock()
	if r.nwBusy[k] {
		r.nwMu.Unlock()
		return
	}
	if r.nwBusy == nil {
		r.nwBusy = map[string]bool{}
	}
	r.nwBusy[k] = true
	r.nwMu.Unlock()
	r.nwWG.Add(1)
	go func() {
		defer r.nwWG.Done()
		defer func() {
			r.nwMu.Lock()
			delete(r.nwBusy, k)
			r.nwMu.Unlock()
		}()
		r.nodeWL.Converge(ctx, e)
	}()
}

// NodeFacts is the heartbeat's node-workload keys: the node facts and consent
// policy (omitting every fact whose probe failed) and, once desired-config has
// been read, `node_workloads`.
func (r *Reconciler) NodeFacts() map[string]any {
	out := map[string]any{}
	if r.facts != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out = r.facts.Report(ctx)
	}
	if r.nodeWL != nil {
		if rows := r.nodeWL.Rows(); rows != nil {
			out["node_workloads"] = rows
		}
	}
	return out
}

// ---- the actuator's view (dockerpkg.ManagedControl) ---------------------

// NodeWorkloadControl is the actuator's handle on agent-managed workloads, nil
// when this agent has no lifecycle (tests built without one).
func (r *Reconciler) NodeWorkloadControl() dockerpkg.ManagedControl {
	if r.nodeWL == nil {
		return nil
	}
	return managedControl{r}
}

type managedControl struct{ r *Reconciler }

func (m managedControl) Managed(ctx context.Context, addon, workload string) (bool, error) {
	return m.r.nodeWL.IsManaged(ctx, addon, workload)
}

func (m managedControl) Status(ctx context.Context, addon, workload string) (dockerpkg.ManagedState, error) {
	return m.r.nodeWL.ManagedStatus(ctx, addon, workload)
}

// desiredEntry reads desired-config afresh and returns the entry for
// addon/workload: the actuator is called right after the gateway wrote the
// row, so the last tick's copy is not good enough.
func (r *Reconciler) desiredEntry(ctx context.Context, addon, workload string) (nodewl.Entry, error) {
	d, err := r.fetch(ctx)
	if err != nil {
		return nodewl.Entry{}, &dockerpkg.ManagedError{HTTP: 502, Code: "desired_unreadable", Detail: err.Error()}
	}
	if len(d.NodeWorkloads) == 0 {
		return nodewl.Entry{}, &dockerpkg.ManagedError{HTTP: 404, Code: "not_desired", Detail: "desired-config places no node workload here"}
	}
	rows, err := parseNodeWorkloadRows(d.NodeWorkloads, r.cfg.NodeID)
	if err != nil {
		return nodewl.Entry{}, &dockerpkg.ManagedError{HTTP: 409, Code: nodewl.CodeOf(err), Detail: err.Error()}
	}
	for _, row := range rows {
		if row.Addon != addon || row.Name != workload {
			continue
		}
		if row.Err != nil {
			return nodewl.Entry{}, &dockerpkg.ManagedError{HTTP: 409, Code: nodewl.CodeOf(row.Err), Detail: row.Err.Error()}
		}
		return row.Entry, nil
	}
	return nodewl.Entry{}, &dockerpkg.ManagedError{HTTP: 404, Code: "not_desired", Detail: "desired-config does not list this workload"}
}

// Start is the actuator's start of an agent-managed workload. desired-config
// must already say `running`: the agent starts what the gateway placed, never
// something the gateway has not asked for.
func (m managedControl) Start(ctx context.Context, addon, workload string) (dockerpkg.ManagedState, error) {
	e, err := m.r.desiredEntry(ctx, addon, workload)
	if err != nil {
		return dockerpkg.ManagedState{}, err
	}
	if e.State != nodewl.StateRunning {
		return dockerpkg.ManagedState{}, &dockerpkg.ManagedError{HTTP: 409, Code: "not_running_in_desired",
			Detail: fmt.Sprintf("desired-config has this workload %s; set it to running first", e.State)}
	}
	if err := m.r.nodeWL.StartManaged(ctx, e); err != nil {
		return dockerpkg.ManagedState{}, managedErr(err, "start_failed")
	}
	return m.r.nodeWL.ManagedStatus(ctx, addon, workload)
}

// Stop is the actuator's stop: the release order. desired-config must already
// be back at `provisioned` (or `absent`); the worker is drained, and only then
// stopped. A drain that does not finish is a 409 and the worker keeps running.
func (m managedControl) Stop(ctx context.Context, addon, workload string) (dockerpkg.ManagedState, error) {
	e, err := m.r.desiredEntry(ctx, addon, workload)
	if err != nil {
		return dockerpkg.ManagedState{}, err
	}
	if e.State == nodewl.StateRunning {
		return dockerpkg.ManagedState{}, &dockerpkg.ManagedError{HTTP: 409, Code: "still_running_in_desired",
			Detail: "desired-config still has this workload running; release it (provisioned) first"}
	}
	if err := m.r.nodeWL.StopManaged(ctx, e); err != nil {
		return dockerpkg.ManagedState{}, managedErr(err, "stop_failed")
	}
	return m.r.nodeWL.ManagedStatus(ctx, addon, workload)
}

// managedErr maps a lifecycle error to the actuator's refusal. A reason code
// is a 409 (the node declined); a drain that did not finish is a 409 named
// drain_timeout; anything else is the daemon's, a 502.
func managedErr(err error, fallback string) error {
	var me *dockerpkg.ManagedError
	if errors.As(err, &me) {
		return err
	}
	if code := nodewl.CodeOf(err); code != "" {
		return &dockerpkg.ManagedError{HTTP: 409, Code: code, Detail: err.Error()}
	}
	if errors.Is(err, dockerpkg.ErrSetsPending) {
		return &dockerpkg.ManagedError{HTTP: 409, Code: "sets_pending", Detail: err.Error()}
	}
	if errors.Is(err, dockerpkg.ErrDrainIncomplete) {
		return &dockerpkg.ManagedError{HTTP: 409, Code: nodewl.ReasonDrainTimeout, Detail: err.Error()}
	}
	return &dockerpkg.ManagedError{HTTP: 502, Code: fallback, Detail: err.Error()}
}
