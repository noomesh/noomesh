// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

// The operator hold as an owned lease, and the drain before it.
//
// A hold used to be a reason label: any release from anyone ended it, a
// stale retry of one operator's release could end another's, and the hold
// stopped every GPU backend after a 30 s grace with requests still in
// flight (noomesh-internal i163 parts C and D; the first consumer is the
// pai-voice handoff, which must never cut an unrelated model request to
// start a voice worker).
//
// Lease: a hold names an operation id and an owner and is given the node's
// next generation. A release must quote that operation id and generation
// (compare-and-set); a mismatch is refused with the current lease, so the
// caller sees whose hold it is. An operator force-release ends any hold and
// is audited as such by the gateway. One hold or release runs at a time on
// a node (ErrTransition for a second one). A force hold on a held node is
// the hand-over primitive: the lease changes owner in one step and the
// backends stay paused, so the pool never gets the GPU in between.
//
// Drain (the default mode): admission on the GPU backends closes at once
// (the proxy answers 503 backend_draining; internal/occupancy), the hold
// waits until no request is in flight on any of them, then stops them as
// before. A drain that outlasts its timeout aborts the hold: admission
// reopens, nothing was stopped, and the caller is told what still runs
// (needs_attention). Mode immediate is the old behaviour, for emergencies.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// Hold modes.
const (
	ModeDrain     = "drain"
	ModeImmediate = "immediate"
)

// PurposeUser marks a hold as the operator's own use of the GPU (VR,
// experiments): `noo cluster gpu mode <node> user` sets it, and the mode is
// read back from the lease (i344b). The only purpose there is; a workload
// hold is named by Workload instead.
const PurposeUser = "user"

// DefaultDrainTimeout bounds a drain hold whose request named no timeout.
const DefaultDrainTimeout = 120 * time.Second

// MaxDrainTimeout caps a caller's drain timeout.
const MaxDrainTimeout = 15 * time.Minute

// Lease is the current hold's identity, reported in gpu_contention.lease.
type Lease struct {
	Owner       string `json:"owner"`
	OperationID string `json:"operation_id"`
	// Workload names what the GPU went to (`<addon>/<workload>`, the
	// reservation layer's key); empty for a plain operator hold.
	Workload string `json:"workload,omitempty"`
	// Purpose is PurposeUser for the operator's own use; empty otherwise.
	Purpose    string `json:"purpose,omitempty"`
	Generation uint64 `json:"generation"`
	Mode       string `json:"mode"`
	Reason     string `json:"reason,omitempty"`
	Since      string `json:"since"`
	// DrainStarted / DrainedAt bracket the drain of a mode-drain hold.
	DrainStarted string `json:"drain_started,omitempty"`
	DrainedAt    string `json:"drained_at,omitempty"`
}

func (l *Lease) clone() *Lease {
	if l == nil {
		return nil
	}
	c := *l
	return &c
}

// Drainer is the admission side of a drain (internal/occupancy): close the
// named backends to new requests, and wait for what runs to finish.
type Drainer interface {
	SetDraining(backends []string, on bool)
	WaitIdle(ctx context.Context, backends []string) (idle bool, remaining map[string]int)
}

// SetDrainer installs the admission hook (the agent wires occupancy).
func (c *Controller) SetDrainer(d Drainer) {
	c.mu.Lock()
	c.drainer = d
	c.mu.Unlock()
}

// HoldRequest is what POST /gpu/hold carries.
type HoldRequest struct {
	Reason      string
	Owner       string
	OperationID string
	Workload    string
	// Purpose: "" or PurposeUser; never together with Workload.
	Purpose string
	// Mode: ModeDrain (default) or ModeImmediate.
	Mode string
	// Timeout bounds the drain; 0 = DefaultDrainTimeout.
	Timeout time.Duration
	// Force takes over a hold owned by another operation (audited by the
	// gateway). A legacy hold (no operation id) is a force.
	Force bool
}

// ReleaseRequest is what POST /gpu/release carries.
type ReleaseRequest struct {
	OperationID string
	Generation  uint64
	// Force ends any hold regardless of owner (a legacy release is one).
	Force bool
	// ResumeNow starts the paused backends at once instead of waiting for
	// the GPU to stay clear for the resume window.
	ResumeNow bool
}

// ErrHeld: the node is held by another operation; Current says whose.
type ErrHeld struct{ Current Lease }

func (e *ErrHeld) Error() string {
	return fmt.Sprintf("held by %s (operation %s, generation %d)", e.Current.Owner, e.Current.OperationID, e.Current.Generation)
}

// ErrTransition: a hold or release is already in progress on the node.
var ErrTransition = errors.New("a GPU hold or release is already in progress on this node")

// ErrNotHeld: a release with ids, but the node holds no lease.
var ErrNotHeld = errors.New("the node's GPU is not held")

// ErrDrainTimeout: the drain did not finish; the hold was aborted.
type ErrDrainTimeout struct {
	Timeout   time.Duration
	Remaining map[string]int // backend -> requests still in flight
}

func (e *ErrDrainTimeout) Error() string {
	parts := make([]string, 0, len(e.Remaining))
	for b, n := range e.Remaining {
		parts = append(parts, fmt.Sprintf("%s: %d", b, n))
	}
	sort.Strings(parts)
	return fmt.Sprintf("still in flight after %s (%s); the hold was not applied", e.Timeout, strings.Join(parts, ", "))
}

// Hold takes the node's GPU for the request's operation: drains (unless
// mode immediate), pauses the GPU backends and keeps them paused until
// Release. The returned Contention carries the lease.
func (c *Controller) Hold(ctx context.Context, req HoldRequest) (Contention, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = ModeDrain
	}
	if mode != ModeDrain && mode != ModeImmediate {
		return c.Report(), fmt.Errorf("unknown hold mode %q", req.Mode)
	}
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose != "" && purpose != PurposeUser {
		return c.Report(), fmt.Errorf("unknown hold purpose %q (only %q)", req.Purpose, PurposeUser)
	}
	if purpose != "" && strings.TrimSpace(req.Workload) != "" {
		return c.Report(), fmt.Errorf("a hold for workload %q has no purpose; purpose %q is the operator's own use", req.Workload, purpose)
	}
	if req.OperationID == "" {
		req.Force = true
		req.OperationID = "legacy-" + c.now().UTC().Format("20060102T150405Z")
	}
	if req.Owner == "" {
		req.Owner = "operator"
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "operator hold"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = c.drainTimeout
	}
	if timeout > MaxDrainTimeout {
		timeout = MaxDrainTimeout
	}

	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	backends, err := c.docker.GPUBackendContainers(lctx)
	cancel()
	if err != nil {
		slog.Warn("gpuyield: hold could not list GPU backends", "error", err)
	}

	c.mu.Lock()
	if c.transition {
		c.mu.Unlock()
		return c.Report(), ErrTransition
	}
	c.refreshGPUSetLocked(backends)
	if c.lease != nil && (c.state == StateHeld || c.state == StateDraining) {
		if c.lease.OperationID == req.OperationID {
			// The same operation asking again: already its hold.
			c.mu.Unlock()
			return c.Report(), nil
		}
		if !req.Force {
			cur := *c.lease
			c.mu.Unlock()
			return c.Report(), &ErrHeld{Current: cur}
		}
		slog.Warn("gpuyield: GPU hold taken over", "from", c.lease.Owner, "from_operation", c.lease.OperationID,
			"by", req.Owner, "operation", req.OperationID)
	}
	c.transition = true
	c.generation++
	now := c.now()
	c.lease = &Lease{Owner: req.Owner, OperationID: req.OperationID, Workload: strings.TrimSpace(req.Workload),
		Purpose: purpose, Generation: c.generation, Mode: mode, Reason: reason, Since: now.UTC().Format(time.RFC3339)}
	drain := mode == ModeDrain && c.drainer != nil
	var gpuBackends []string
	if drain {
		gpuBackends = sortedKeys(c.gpuSet)
		// Snapshot for the abort path: the hold must leave no trace.
		prevState, prevSince, prevReason := c.state, c.since, c.reason
		prevPaused := map[string]bool{}
		for k, v := range c.paused {
			prevPaused[k] = v
		}
		for _, b := range gpuBackends {
			c.paused[b] = true // reconcile must not start one while we drain
		}
		c.state = StateDraining
		c.since = now
		c.reason = reason
		c.lease.DrainStarted = c.lease.Since
		c.saveLocked()
		drainer := c.drainer
		c.mu.Unlock()

		slog.Warn("gpuyield: GPU hold draining", "operation", req.OperationID, "owner", req.Owner,
			"backends", gpuBackends, "timeout", timeout)
		drainer.SetDraining(gpuBackends, true)
		wctx, wcancel := context.WithTimeout(ctx, timeout)
		idle, remaining := drainer.WaitIdle(wctx, gpuBackends)
		wcancel()
		if !idle {
			drainer.SetDraining(gpuBackends, false)
			c.mu.Lock()
			c.state, c.since, c.reason = prevState, prevSince, prevReason
			c.paused = prevPaused
			c.lease = nil
			c.transition = false
			c.saveLocked()
			c.mu.Unlock()
			slog.Warn("gpuyield: GPU hold aborted: backends did not go idle", "operation", req.OperationID,
				"timeout", timeout, "in_flight", remaining)
			return c.Report(), &ErrDrainTimeout{Timeout: timeout, Remaining: remaining}
		}
		c.mu.Lock()
		c.lease.DrainedAt = c.now().UTC().Format(time.RFC3339)
	}
	slog.Warn("gpuyield: operator GPU hold", "reason", reason, "operation", req.OperationID, "owner", req.Owner, "mode", mode)
	act := c.pauseLocked(backends, StateHeld, reason)
	c.mu.Unlock()
	c.execute(ctx, act)
	if drain {
		// The backends are stopped; a request to one now fails as
		// unreachable, which the gateway already routes around.
		c.drainer.SetDraining(gpuBackends, false)
	}
	c.mu.Lock()
	c.transition = false
	c.mu.Unlock()
	return c.Report(), nil
}

// Release ends the hold the request names: the node returns to the
// automatic policy, which resumes once the GPU has stayed clear for the
// resume window, or at once with ResumeNow.
func (c *Controller) Release(ctx context.Context, req ReleaseRequest) (Contention, error) {
	c.mu.Lock()
	if c.transition {
		c.mu.Unlock()
		return c.Report(), ErrTransition
	}
	if c.state != StateHeld {
		c.mu.Unlock()
		if req.Force {
			return c.Report(), nil // nothing to end; the legacy answer
		}
		return c.Report(), ErrNotHeld
	}
	if !req.Force && (c.lease == nil || c.lease.OperationID != req.OperationID || c.lease.Generation != req.Generation) {
		var cur Lease
		if c.lease != nil {
			cur = *c.lease
		}
		c.mu.Unlock()
		return c.Report(), &ErrHeld{Current: cur}
	}
	c.lease = nil
	var act actions
	if req.ResumeNow {
		slog.Info("gpuyield: operator GPU hold released; resuming now", "operation", req.OperationID)
		act = c.resumeLocked("hold released, resume now")
	} else {
		slog.Info("gpuyield: operator GPU hold released; automatic policy resumes when the GPU is free", "operation", req.OperationID)
		c.state = StateYielded
		c.since = c.now()
		c.reason = "hold released; resuming when the GPU is free"
		c.clearAt = time.Time{}
		if len(c.paused) == 0 {
			c.state = StateFree
			c.reason = ""
		}
		c.saveLocked()
	}
	c.mu.Unlock()
	c.execute(ctx, act)
	return c.Report(), nil
}
