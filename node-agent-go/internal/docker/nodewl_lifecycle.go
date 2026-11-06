// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// The lifecycle of a node workload (i300 F5b): start, readiness, crash
// detection, release (drain, then recreate), removal, and the rows the
// heartbeat reports. The state machine is docs/reference/node-workloads.md,
// "State machine"; this file is its only implementation.
//
// Rules this file keeps:
//
//   - A refusal never changes a container. The row reports its last good state
//     with a reason.
//   - A worker that has not finished draining is never stopped. A drain that
//     does not finish is needs_attention / drain_timeout, and the worker keeps
//     running.
//   - The worker has restart policy "no". A worker that exited while it should
//     run is `crashed`, reported, and not restarted by this agent: it starts
//     again only when the desired state changes (a new provision, or an
//     explicit start through the actuator).
//   - Nothing here blocks the reconcile pass. A drain and a readiness wait run
//     on goroutines the pass starts.

// DrainCompletion is the rule that says a worker has finished draining
// (docs/reference/node-workloads.md, "The worker's drain"). A 2xx answer to the
// drain POST only means the drain was ACCEPTED; the worker is drained when
// GET drain.done_path answers 200, polled every drainPollEvery. Anything else
// (a non-200, a connection error, an unreachable door) is "not yet".
// drain.timeout_secs bounds the whole drain, the POST plus the polling.
const DrainCompletion = "GET drain.done_path answers 200 within drain.timeout_secs"

// drainPollEvery is how often done_path is polled.
const drainPollEvery = 2 * time.Second

// stopGrace is the SIGTERM grace for a worker that has already drained.
const stopGrace = 30

// ManagedState is what the actuator reports for an agent-managed workload.
type ManagedState struct {
	State   string // provisioned, running, absent, needs_attention
	Running bool   // the worker container is running
	Ready   bool   // health.ready answered 200 through the door
	Reason  string // a nodewl.Reason* code, or ""
}

// ManagedError is a refusal the actuator maps to an HTTP status.
type ManagedError struct {
	HTTP   int
	Code   string
	Detail string
}

func (e *ManagedError) Error() string { return e.Code + ": " + e.Detail }

// ManagedControl is what the add-on workload actuator (internal/api) uses for
// a workload this agent provisioned (label noo.managed-by=agent). It reads the
// desired state afresh on every call, so the gateway's start call sees the row
// the gateway just wrote.
type ManagedControl interface {
	Managed(ctx context.Context, addon, workload string) (bool, error)
	Start(ctx context.Context, addon, workload string) (ManagedState, error)
	Stop(ctx context.Context, addon, workload string) (ManagedState, error)
	Status(ctx context.Context, addon, workload string) (ManagedState, error)
}

// Row is one `node_workloads` row of the heartbeat. Key names and shapes are
// the contract's; model, reservation and reason are omitted when unknown or
// none. `slots` is not reported: the agent does not know it (see the PR).
type Row struct {
	Addon       string `json:"addon"`
	Name        string `json:"name"`
	State       string `json:"state"`
	Ready       bool   `json:"ready"`
	Model       string `json:"model,omitempty"`
	DoorPort    int    `json:"door_port"`
	Reservation string `json:"reservation,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type lifeState struct {
	entry    nodewl.Entry
	hasEntry bool
	state    string // last good state: provisioned, running, absent, needs_attention
	ready    bool
	reason   string
	// releasing: a release is in flight (its drain may take an hour).
	releasing bool
	watching  bool
}

// lifeCycle is the lifecycle's state inside NodeWorkloads. The zero value is
// ready to use.
type lifeCycle struct {
	// Admit is the node's gate (internal/nodepolicy): consent and the
	// placement-side refusals. It runs before anything is provisioned or
	// started. nil is a closed gate (consent_none), never an open one.
	Admit func(ctx context.Context, e nodewl.Entry) error

	// doorCall is one HTTP call through the door: addr is host:port,
	// serverName the door's DNS name. It returns the status code. Tests
	// replace it; NewNodeWorkloads sets the mTLS one.
	doorCall func(ctx context.Context, addr, serverName, method, path string) (int, error)

	now       func() time.Time
	pollFast  time.Duration // readiness poll until ready or timed out
	pollSlow  time.Duration // after that, and once ready
	pollDrain time.Duration // done_path poll; drainPollEvery when zero

	mu    sync.Mutex
	lives map[string]*lifeState
	wg    sync.WaitGroup
	once  sync.Once
	done  chan struct{}
}

func (p *NodeWorkloads) lc0() *lifeCycle {
	p.lc.once.Do(func() { p.lc.done = make(chan struct{}) })
	return &p.lc
}

func (p *NodeWorkloads) clock() time.Time {
	if p.lc.now != nil {
		return p.lc.now()
	}
	return time.Now()
}

func (p *NodeWorkloads) polls() (fast, slow time.Duration) {
	fast, slow = p.lc.pollFast, p.lc.pollSlow
	if fast <= 0 {
		fast = 2 * time.Second
	}
	if slow <= 0 {
		slow = 10 * time.Second
	}
	return
}

// Wait blocks until every goroutine the lifecycle started has ended (tests).
func (p *NodeWorkloads) Wait() { p.lc.wg.Wait() }

// Close ends the readiness watchers. A release in flight is not cut: it ends
// with the drain it is waiting on.
func (p *NodeWorkloads) Close() {
	lc := p.lc0()
	select {
	case <-lc.done:
	default:
		close(lc.done)
	}
}

func (p *NodeWorkloads) with(addon, name string, f func(ls *lifeState)) {
	lc := p.lc0()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.lives == nil {
		lc.lives = map[string]*lifeState{}
	}
	k := wlKey(addon, name)
	ls := lc.lives[k]
	if ls == nil {
		ls = &lifeState{}
		lc.lives[k] = ls
	}
	f(ls)
}

func (p *NodeWorkloads) read(addon, name string) (cp lifeState, ok bool) {
	lc := p.lc0()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	ls := lc.lives[wlKey(addon, name)]
	if ls == nil {
		return lifeState{}, false
	}
	return *ls, true
}

// Rows is the heartbeat's node_workloads: one row per workload this agent has
// been told about, sorted. nil means "not known yet" (no desired-config read):
// the caller omits the key.
func (p *NodeWorkloads) Rows() []Row {
	lc := p.lc0()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.lives == nil {
		return nil
	}
	rows := make([]Row, 0, len(lc.lives))
	for k, ls := range lc.lives {
		addon, name, _ := strings.Cut(k, "/")
		st := ls.state
		if st == "" {
			st = nodewl.StateAbsent
		}
		r := Row{Addon: addon, Name: name, State: st, Ready: ls.ready && st == nodewl.StateRunning,
			DoorPort: WorkloadDoorPort, Reason: ls.reason}
		if ls.hasEntry {
			if ls.entry.Reservation != nil {
				r.Reservation = *ls.entry.Reservation
			}
			if len(ls.entry.Decl.Models) > 0 {
				if refs := ls.entry.Sets[ls.entry.Decl.Models[0].Slot]; len(refs) > 0 {
					r.Model = refs[0].ID
				}
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Addon != rows[j].Addon {
			return rows[i].Addon < rows[j].Addon
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// MarkRead says desired-config was read and held no node workload: Rows is
// then a known-empty list, not an unknown one.
func (p *NodeWorkloads) MarkRead() {
	lc := p.lc0()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.lives == nil {
		lc.lives = map[string]*lifeState{}
	}
}

// Retain drops the rows of workloads that desired-config no longer lists
// (keep holds their addon/name keys). It touches no container. A row that is
// mid-release or needs attention stays: it is still on the node and still
// being reported.
func (p *NodeWorkloads) Retain(keep map[string]bool) {
	lc := p.lc0()
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for k, ls := range lc.lives {
		if !keep[k] && !ls.releasing && ls.state != nodewl.StateNeedsAttention {
			delete(lc.lives, k)
		}
	}
}

// ReleaseOrphans treats every workload this agent created and that keep (the
// addon/name keys desired-config lists) does not name as `absent`: a running
// worker is drained first, then everything is removed. It must be called only
// after a desired-config read that SUCCEEDED and parsed (the i495 rule): a
// failed or unparseable read says nothing about what is wanted, and must never
// reach here. Containers are found by the noo.managed-by=agent label, not by
// memory, so an agent restart forgets nothing.
//
// The drain config comes from the last desired entry this process saw, else
// from the labels the worker was created with. A worker with neither cannot be
// drained, so it is not stopped: it ends needs_attention / drain_timeout.
func (p *NodeWorkloads) ReleaseOrphans(ctx context.Context, keep map[string]bool) {
	refs, err := p.api.ListManaged(ctx)
	if err != nil {
		slog.Warn("node workload: cannot list the workloads on the node; removing none", "error", err)
		return
	}
	for _, ref := range refs {
		if keep[wlKey(ref.Addon, ref.Name)] {
			continue
		}
		e := orphanEntry(ref)
		if cur, ok := p.read(ref.Addon, ref.Name); ok && cur.hasEntry {
			e = cur.entry
			e.State, e.Reservation = nodewl.StateAbsent, nil
		}
		slog.Info("node workload no longer in desired-config; removing", "addon", ref.Addon, "workload", ref.Name)
		p.Converge(ctx, e)
	}
}

// orphanEntry is an `absent` entry that carries only what removal needs: the
// name and the drain config the worker was labelled with.
func orphanEntry(ref managedRef) nodewl.Entry {
	secs, _ := strconv.ParseInt(ref.Labels[LabelDrainTimeout], 10, 64)
	return nodewl.Entry{
		Addon: ref.Addon, Name: ref.Name, State: nodewl.StateAbsent,
		Drain: nodewl.Drain{Path: ref.Labels[LabelDrainPath], DonePath: ref.Labels[LabelDrainDone], TimeoutSecs: secs},
	}
}

// Refuse records that a desired row was refused whole (it did not parse): the
// row reports its reason and no container is touched.
func (p *NodeWorkloads) Refuse(addon, name string, err error) {
	code := nodewl.CodeOf(err)
	if code == "" {
		return
	}
	p.with(addon, name, func(ls *lifeState) { ls.reason = code })
}

func ours(c *ctrInfo) bool { return c != nil && c.Labels[LabelManagedBy] == ManagedByAgent }

func exited(c *ctrInfo) bool { return c != nil && (c.Status == "exited" || c.Status == "dead") }

func (p *NodeWorkloads) gate(ctx context.Context, e nodewl.Entry) error {
	if p.lc.Admit == nil {
		return &nodewl.Error{Code: nodewl.ReasonConsentNone, Detail: "no consent policy is wired"}
	}
	return p.lc.Admit(ctx, e)
}

// Converge advances one entry toward its desired state. It returns without
// waiting for a drain or for readiness.
func (p *NodeWorkloads) Converge(ctx context.Context, e nodewl.Entry) {
	p.with(e.Addon, e.Name, func(ls *lifeState) { ls.entry, ls.hasEntry = e, true })
	if err := p.adopt(ctx, e); err != nil {
		slog.Warn("node workload: cannot read the node", "addon", e.Addon, "workload", e.Name, "error", err)
		return
	}
	switch e.State {
	case nodewl.StateAbsent:
		p.convergeAbsent(ctx, e)
	case nodewl.StateProvisioned:
		p.convergeProvisioned(ctx, e)
	case nodewl.StateRunning:
		p.convergeRunning(ctx, e)
	}
}

// adopt gives a workload with no memory in this process (an agent restart) the
// state its containers are in.
func (p *NodeWorkloads) adopt(ctx context.Context, e nodewl.Entry) error {
	if ls, _ := p.read(e.Addon, e.Name); ls.state != "" {
		return nil
	}
	w, err := p.api.InspectContainer(ctx, WorkloadContainerName(e.Addon, e.Name))
	if err != nil {
		return err
	}
	st := nodewl.StateAbsent
	switch {
	case !ours(w):
	case w.Running:
		st = nodewl.StateRunning
	default:
		st = nodewl.StateProvisioned
	}
	p.with(e.Addon, e.Name, func(ls *lifeState) {
		if ls.state == "" {
			ls.state = st
		}
	})
	return nil
}

func (p *NodeWorkloads) setState(e nodewl.Entry, state, reason string) {
	p.with(e.Addon, e.Name, func(ls *lifeState) {
		ls.state, ls.reason = state, reason
		if state != nodewl.StateRunning {
			ls.ready = false
		}
	})
}

// refused records a verdict against a row without moving its state.
func (p *NodeWorkloads) refused(e nodewl.Entry, err error) {
	if errors.Is(err, ErrSetsPending) || errors.Is(err, ErrWorkerRunning) {
		return
	}
	code := nodewl.CodeOf(err)
	if code == "" {
		slog.Warn("node workload: not converged", "addon", e.Addon, "workload", e.Name, "error", err)
		return
	}
	p.with(e.Addon, e.Name, func(ls *lifeState) { ls.reason = code })
}

func (p *NodeWorkloads) convergeAbsent(ctx context.Context, e nodewl.Entry) {
	w, err := p.api.InspectContainer(ctx, WorkloadContainerName(e.Addon, e.Name))
	if err != nil {
		slog.Warn("node workload: inspect", "addon", e.Addon, "workload", e.Name, "error", err)
		return
	}
	if ours(w) && w.Running {
		// Even for removal a worker is drained first: its sessions are not cut.
		p.goRelease(ctx, e, thenDeprovision)
		return
	}
	if err := p.Deprovision(ctx, e.Addon, e.Name); err != nil {
		p.refused(e, err)
		return
	}
	p.setState(e, nodewl.StateAbsent, "")
}

func (p *NodeWorkloads) convergeProvisioned(ctx context.Context, e nodewl.Entry) {
	w, err := p.api.InspectContainer(ctx, WorkloadContainerName(e.Addon, e.Name))
	if err != nil {
		slog.Warn("node workload: inspect", "addon", e.Addon, "workload", e.Name, "error", err)
		return
	}
	if ours(w) && w.Running {
		// Release: the worker drains, and only then is it stopped.
		p.goRelease(ctx, e, thenProvision)
		return
	}
	if cur, _ := p.read(e.Addon, e.Name); cur.releasing {
		return
	}
	if err := p.gate(ctx, e); err != nil {
		p.refused(e, err)
		return
	}
	if ours(w) && exited(w) {
		// It ran and is gone (crashed, or stopped after a drain): a released
		// workload is always recreated fresh and stopped.
		if err := p.removeWorkload(ctx, e); err != nil {
			p.refused(e, err)
			return
		}
	}
	switch err := p.Provision(ctx, e); {
	case err == nil:
		p.setState(e, nodewl.StateProvisioned, "")
	case errors.Is(err, ErrWorkerRunning):
		p.goRelease(ctx, e, thenProvision)
	default:
		p.refused(e, err)
	}
}

func (p *NodeWorkloads) convergeRunning(ctx context.Context, e nodewl.Entry) {
	if cur, _ := p.read(e.Addon, e.Name); cur.releasing {
		return
	}
	if err := p.ensureRunning(ctx, e); err != nil {
		p.refused(e, err)
	}
}

// ensureRunning is the move to `running`: gate, provision when needed, start
// the door and then the worker, and watch it for readiness. A worker that has
// run and exited is crashed and is left exactly as it is.
func (p *NodeWorkloads) ensureRunning(ctx context.Context, e nodewl.Entry) error {
	if err := p.gate(ctx, e); err != nil {
		return err
	}
	if err := p.Provision(ctx, e); err != nil && !errors.Is(err, ErrWorkerRunning) {
		return err
	}
	workerName, doorName := WorkloadContainerName(e.Addon, e.Name), WorkloadDoorName(e.Addon, e.Name)
	w, err := p.api.InspectContainer(ctx, workerName)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", workerName, err)
	}
	d, err := p.api.InspectContainer(ctx, doorName)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", doorName, err)
	}
	if !ours(w) || !ours(d) {
		return fmt.Errorf("%s/%s is not on the node after provisioning", e.Addon, e.Name)
	}
	switch {
	case w.Running && d.Running:
	case w.Status == "created" && (d.Status == "created" || d.Running):
		if !d.Running {
			if err := p.api.StartContainer(ctx, doorName); err != nil {
				return fmt.Errorf("start %s: %w", doorName, err)
			}
		}
		if err := p.api.StartContainer(ctx, workerName); err != nil {
			return fmt.Errorf("start %s: %w", workerName, err)
		}
		slog.Info("node workload started", "addon", e.Addon, "workload", e.Name)
	default:
		p.with(e.Addon, e.Name, func(ls *lifeState) { ls.state, ls.ready, ls.reason = nodewl.StateRunning, false, nodewl.ReasonCrashed })
		return nil
	}
	p.with(e.Addon, e.Name, func(ls *lifeState) {
		ls.state, ls.reason = nodewl.StateRunning, ""
	})
	p.goWatch(ctx, e)
	return nil
}

// removeWorkload stops and removes the pair, the scratch and the network of a
// workload that is not running (or that has drained).
func (p *NodeWorkloads) removeWorkload(ctx context.Context, e nodewl.Entry) error {
	defer p.lock(e.Addon, e.Name)()
	return p.teardown(ctx, e.Addon, e.Name)
}

// ---- readiness and crash watch -----------------------------------------

func (p *NodeWorkloads) goWatch(parent context.Context, e nodewl.Entry) {
	started := false
	p.with(e.Addon, e.Name, func(ls *lifeState) {
		if !ls.watching {
			ls.watching, started = true, true
		}
	})
	if !started {
		return
	}
	lc := p.lc0()
	lc.wg.Add(1)
	go func() {
		defer lc.wg.Done()
		defer p.with(e.Addon, e.Name, func(ls *lifeState) { ls.watching = false })
		// The watch outlives the call that started the worker (an actuator
		// request ends in milliseconds), not the agent: it ends on Close.
		p.watch(context.WithoutCancel(parent), e)
	}()
}

// watch polls health.ready through the door until the workload leaves
// `running`: faster until it is ready or has outrun start_secs, slower after.
// It ends when the worker is not running, desired-config no longer says
// running, or the agent closes.
func (p *NodeWorkloads) watch(ctx context.Context, e nodewl.Entry) {
	lc := p.lc0()
	fast, slow := p.polls()
	for {
		cur, ok := p.read(e.Addon, e.Name)
		if !ok || !cur.hasEntry || cur.entry.State != nodewl.StateRunning || cur.releasing {
			return
		}
		w, err := p.api.InspectContainer(ctx, WorkloadContainerName(e.Addon, e.Name))
		if err == nil {
			if !ours(w) {
				return
			}
			if !w.Running {
				if exited(w) {
					p.with(e.Addon, e.Name, func(ls *lifeState) { ls.ready, ls.reason = false, nodewl.ReasonCrashed })
				}
				return
			}
			ready := p.probeReady(ctx, e)
			timedOut := !ready && !w.StartedAt.IsZero() && p.clock().Sub(w.StartedAt) > time.Duration(e.StartSecs)*time.Second
			p.with(e.Addon, e.Name, func(ls *lifeState) {
				if ls.releasing || ls.state != nodewl.StateRunning {
					return
				}
				ls.ready = ready
				switch {
				case ready:
					ls.reason = ""
				case timedOut:
					ls.reason = nodewl.ReasonStartTimeout
				}
			})
			if ready || timedOut {
				select {
				case <-lc.done:
					return
				case <-time.After(slow):
				}
				continue
			}
		}
		select {
		case <-lc.done:
			return
		case <-time.After(fast):
		}
	}
}

// probeReady is one GET of health.ready through the door: only a 200 is ready.
func (p *NodeWorkloads) probeReady(ctx context.Context, e nodewl.Entry) bool {
	if p.lc.doorCall == nil {
		return false
	}
	addr, err := p.DoorAddr(ctx, e.Addon, e.Name)
	if err != nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	code, err := p.lc.doorCall(cctx, addr, WorkloadDoorName(e.Addon, e.Name), http.MethodGet, e.Decl.Health.Ready)
	return err == nil && code == http.StatusOK
}

// ---- release ------------------------------------------------------------

type releaseThen int

const (
	thenProvision releaseThen = iota
	thenDeprovision
)

var errReleaseBusy = errors.New("a release of this workload is already in flight")

func (p *NodeWorkloads) goRelease(ctx context.Context, e nodewl.Entry, then releaseThen) {
	if cur, _ := p.read(e.Addon, e.Name); cur.releasing {
		return
	}
	lc := p.lc0()
	lc.wg.Add(1)
	// The release outlives the reconcile pass that started it, not the agent.
	go func() {
		defer lc.wg.Done()
		if err := p.release(ctx, e, then); err != nil && !errors.Is(err, errReleaseBusy) {
			slog.Warn("node workload: release did not complete", "addon", e.Addon, "workload", e.Name, "error", err)
		}
	}()
}

// release returns a workload to rest: drain the worker through the door, wait
// for the drain to finish (DrainCompletion), only then stop it, and remove the
// worker with its scratch; then recreate it fresh and stopped (thenProvision)
// or remove everything (thenDeprovision). A drain that does not finish leaves
// the worker running and the row needs_attention / drain_timeout.
func (p *NodeWorkloads) release(ctx context.Context, e nodewl.Entry, then releaseThen) error {
	busy := false
	p.with(e.Addon, e.Name, func(ls *lifeState) {
		if ls.releasing {
			busy = true
			return
		}
		ls.releasing, ls.ready = true, false
	})
	if busy {
		return errReleaseBusy
	}
	defer p.with(e.Addon, e.Name, func(ls *lifeState) { ls.releasing = false })

	workerName := WorkloadContainerName(e.Addon, e.Name)
	w, err := p.api.InspectContainer(ctx, workerName)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", workerName, err)
	}
	if ours(w) && w.Running {
		switch err := p.drain(ctx, e); {
		case err == nil:
			if err := p.api.StopContainer(ctx, workerName, stopGrace); err != nil {
				return fmt.Errorf("stop %s: %w", workerName, err)
			}
		case errors.Is(err, errWorkerExited):
			// It is gone, so there is nothing to wait for or to stop: report
			// the crash and go on to recreate it fresh and stopped.
			slog.Warn("node workload: the worker exited during its drain", "addon", e.Addon, "workload", e.Name)
			p.with(e.Addon, e.Name, func(ls *lifeState) { ls.state, ls.ready, ls.reason = nodewl.StateRunning, false, nodewl.ReasonCrashed })
		default:
			// Not drained (only a timeout gets here): the worker is NOT stopped.
			p.setState(e, nodewl.StateNeedsAttention, nodewl.ReasonDrainTimeout)
			return err
		}
	}
	if then == thenDeprovision {
		if err := p.Deprovision(ctx, e.Addon, e.Name); err != nil {
			p.refused(e, err)
			return err
		}
		p.setState(e, nodewl.StateAbsent, "")
		return nil
	}
	if err := p.removeWorkload(ctx, e); err != nil {
		p.refused(e, err)
		return err
	}
	p.setState(e, nodewl.StateAbsent, "")
	if err := p.gate(ctx, e); err != nil {
		p.refused(e, err)
		return err
	}
	if err := p.Provision(ctx, e); err != nil {
		p.refused(e, err)
		return err
	}
	p.setState(e, nodewl.StateProvisioned, "")
	return nil
}

// drain drains the worker through the door (DrainCompletion). It POSTs
// drain.path until a 2xx says the drain was accepted (the endpoint is
// idempotent, so a refused or unanswered POST is simply sent again), reports
// the row `draining` from then on, and polls GET drain.done_path until it
// answers 200. Every other outcome of a call is "not yet". It returns nil only
// on that 200, errWorkerExited if the worker is gone, and ErrDrainIncomplete
// when drain.timeout_secs, which bounds the POST and the polling together,
// runs out.
func (p *NodeWorkloads) drain(ctx context.Context, e nodewl.Entry) error {
	if p.lc.doorCall == nil {
		return fmt.Errorf("%w: no door client", ErrDrainIncomplete)
	}
	dctx, cancel := context.WithTimeout(ctx, time.Duration(e.Drain.TimeoutSecs)*time.Second)
	defer cancel()
	every := p.lc.pollDrain
	if every <= 0 {
		every = drainPollEvery
	}
	workerName := WorkloadContainerName(e.Addon, e.Name)
	accepted := false
	last := "no answer yet"
	for {
		if w, err := p.api.InspectContainer(dctx, workerName); err == nil && (!ours(w) || !w.Running) {
			return errWorkerExited
		}
		if !accepted {
			code, err := p.callDoor(dctx, e, http.MethodPost, e.Drain.Path)
			switch {
			case err != nil:
				last = fmt.Sprintf("POST %s: %v", e.Drain.Path, err)
			case code < 200 || code > 299:
				last = fmt.Sprintf("POST %s answered HTTP %d", e.Drain.Path, code)
			default:
				accepted = true
				p.setState(e, nodewl.StateDraining, "")
			}
		}
		if accepted {
			code, err := p.callDoor(dctx, e, http.MethodGet, e.Drain.DonePath)
			switch {
			case err != nil:
				last = fmt.Sprintf("GET %s: %v", e.Drain.DonePath, err)
			case code == http.StatusOK:
				return nil
			default:
				last = fmt.Sprintf("GET %s answered HTTP %d", e.Drain.DonePath, code)
			}
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("%w within %d s (%s)", ErrDrainIncomplete, e.Drain.TimeoutSecs, last)
		case <-time.After(every):
		}
	}
}

// callDoor is one call through the worker's door, capped at 5 s so a hung
// answer cannot outlast a poll by much. A door that cannot be found is an
// error like any other failed call.
func (p *NodeWorkloads) callDoor(ctx context.Context, e nodewl.Entry, method, path string) (int, error) {
	addr, err := p.DoorAddr(ctx, e.Addon, e.Name)
	if err != nil {
		return 0, err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.lc.doorCall(cctx, addr, WorkloadDoorName(e.Addon, e.Name), method, path)
}

// ErrDrainIncomplete: the worker was not drained in time (DrainCompletion not
// met). The worker is left running.
var ErrDrainIncomplete = errors.New("the worker did not finish draining")

// errWorkerExited: the worker stopped running during its drain.
var errWorkerExited = errors.New("the worker exited during its drain")

// ---- the actuator's entry points ---------------------------------------

// StartManaged is the actuator's start: e is the freshly read desired entry,
// already known to be `running`. It starts and returns; readiness is watched.
func (p *NodeWorkloads) StartManaged(ctx context.Context, e nodewl.Entry) error {
	p.with(e.Addon, e.Name, func(ls *lifeState) { ls.entry, ls.hasEntry = e, true })
	if err := p.adopt(ctx, e); err != nil {
		return err
	}
	if cur, _ := p.read(e.Addon, e.Name); cur.releasing {
		return errReleaseBusy
	}
	err := p.ensureRunning(ctx, e)
	if err != nil {
		p.refused(e, err)
	}
	return err
}

// StopManaged is the actuator's stop: e is the freshly read desired entry,
// already known to be `provisioned` or `absent`. It waits for the drain (up to
// drain.timeout_secs or ctx) and returns the drain's failure, leaving the
// worker running.
func (p *NodeWorkloads) StopManaged(ctx context.Context, e nodewl.Entry) error {
	p.with(e.Addon, e.Name, func(ls *lifeState) { ls.entry, ls.hasEntry = e, true })
	then := thenProvision
	if e.State == nodewl.StateAbsent {
		then = thenDeprovision
	}
	return p.release(ctx, e, then)
}

// ManagedStatus is the actuator's status for a workload: the row, plus the
// worker's own running state.
func (p *NodeWorkloads) ManagedStatus(ctx context.Context, addon, name string) (ManagedState, error) {
	w, err := p.api.InspectContainer(ctx, WorkloadContainerName(addon, name))
	if err != nil {
		return ManagedState{}, err
	}
	ms := ManagedState{State: nodewl.StateAbsent, Running: ours(w) && w.Running}
	if cur, ok := p.read(addon, name); ok {
		ms.State, ms.Ready, ms.Reason = cur.state, cur.ready, cur.reason
		if ms.State == "" {
			ms.State = nodewl.StateAbsent
		}
	}
	return ms, nil
}

// IsManaged reports whether addon/workload has a worker this agent created.
func (p *NodeWorkloads) IsManaged(ctx context.Context, addon, name string) (bool, error) {
	w, err := p.api.InspectContainer(ctx, WorkloadContainerName(addon, name))
	if err != nil {
		return false, err
	}
	return ours(w), nil
}

// ---- the door client ----------------------------------------------------

// newDoorCaller is the production doorCall: HTTPS to the door with the agent's
// own node leaf as the client certificate, the cluster CA as the only root, and
// the door's DNS name as the server name (the address is a bridge IP). It
// follows no redirect and reads at most 1 MiB of the answer.
func newDoorCaller() func(ctx context.Context, addr, serverName, method, path string) (int, error) {
	return func(ctx context.Context, addr, serverName, method, path string) (int, error) {
		return doorRequest(ctx, ctrlenv.TLSCA(), ctrlenv.TLSCert(), ctrlenv.TLSKey(), addr, serverName, method, path)
	}
}

func doorRequest(ctx context.Context, caPath, certPath, keyPath, addr, serverName, method, path string) (int, error) {
	if !strings.HasPrefix(path, "/") {
		return 0, fmt.Errorf("path %q is not absolute", path)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return 0, fmt.Errorf("cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return 0, errors.New("cluster CA holds no certificate")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return 0, fmt.Errorf("node leaf: %w", err)
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: serverName, Certificates: []tls.Certificate{cert}},
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}
