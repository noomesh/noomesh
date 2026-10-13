// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package diskreclaim lets a node relieve its OWN disk.
//
// The controller's reclaim ladder (noo-hostd `disk-reclaim`) only
// ever ran on the controller host: it is queued into the controller's spool,
// and a worker's disk was out of its reach. A full node could only raise an
// alert telling the operator what to run by hand — host2 sat at 85% for a day
// on 2026-10-02, and host3 at 92% starved vLLM of disk on 2026-10-03.
//
// The agent already measures its disks for /health. When one crosses the
// watermark, it queues the same `disk-reclaim` op into its LOCAL hostd spool
// (worker mode serves it since this change): the rail stays pull-only, the
// controller never reaches into the node. The POLICY — whether to act, dry-run
// or not, the watermark, the build-cache cap — comes from the controller in
// desired-config, from the same `disk_watermark` location the controller's own
// ladder reads, so one setting governs the fleet. Absent policy (an older
// gateway) means do nothing.
package diskreclaim

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// OpName is the hostd op this package queues.
const OpName = "disk-reclaim"

// Policy is the controller's reclaim setting for nodes (desired-config
// `disk_reclaim`). The zero value acts on nothing.
type Policy struct {
	Enabled       bool  `json:"enabled"`
	DryRun        bool  `json:"dry_run"`
	Watermark     int   `json:"watermark"`
	CacheCapBytes int64 `json:"cache_cap_bytes,omitempty"`
}

// Interval between disk checks — the controller's evaluator cadence.
const Interval = 15 * time.Minute

// MinGap is the least time between two queued reclaims, matching the
// controller's one-per-hour dedup: a disk the ladder could not bring under
// the watermark must not get an identical command every check.
const MinGap = time.Hour

// Paths are the filesystems measured — the same set /health reports.
var Paths = []string{"/", "/var/lib/containerd", "/var/lib/docker"}

// Decide reports whether a reclaim should be queued now, and why not when it
// should not. Pure, so the policy is testable without a disk or a spool.
func Decide(p *Policy, disks []hardware.DiskUsage, lastQueued, now time.Time) (bool, string) {
	if p == nil {
		return false, "no policy from the controller (older gateway) — not acting"
	}
	if !p.Enabled {
		return false, "disabled (disk_watermark location: enabled_action is false)"
	}
	w := p.Watermark
	if w < 1 || w > 100 {
		w = 85
	}
	worst := -1.0
	for _, d := range disks {
		if d.UsedPercent > worst {
			worst = d.UsedPercent
		}
	}
	if worst < 0 {
		return false, "no disk measurement on this platform"
	}
	if worst < float64(w) {
		return false, fmt.Sprintf("below watermark (%.0f%% < %d%%)", worst, w)
	}
	if !lastQueued.IsZero() && now.Sub(lastQueued) < MinGap {
		return false, fmt.Sprintf("over watermark (%.0f%%), last reclaim %s ago — waiting %s between runs",
			worst, now.Sub(lastQueued).Round(time.Minute), MinGap)
	}
	return true, fmt.Sprintf("over watermark (%.0f%% >= %d%%)", worst, w)
}

// Args is the command the op receives — the same allowlist the controller
// sends (hostd opDiskReclaim).
func Args(p *Policy) []string {
	w := p.Watermark
	if w < 1 || w > 100 {
		w = 85
	}
	args := []string{"dry_run=" + strconv.FormatBool(p.DryRun), "watermark=" + strconv.Itoa(w)}
	if p.CacheCapBytes > 0 {
		args = append(args, "cache_cap_bytes="+strconv.FormatInt(p.CacheCapBytes, 10))
	}
	return args
}

// Reclaimer runs the check loop and keeps what /health reports.
type Reclaimer struct {
	spool string
	disks func() []hardware.DiskUsage

	mu         sync.Mutex
	policy     *Policy
	pending    string
	lastQueued time.Time
	status     string
	last       map[string]any
}

// New watches the worker hostd spool at spool.
func New(spool string) *Reclaimer {
	return &Reclaimer{spool: spool, disks: func() []hardware.DiskUsage { return hardware.DiskUsages(Paths) },
		status: "waiting for policy from the controller"}
}

// SetPolicy installs the controller's policy (nil clears it).
func (r *Reclaimer) SetPolicy(p *Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p == nil {
		r.policy = nil
		return
	}
	cp := *p
	r.policy = &cp
}

// ResultPoll is how often a queued run's result is looked for. A run takes
// seconds to minutes; waiting for the next Interval left /health saying
// "queued" for up to 15 minutes after hostd had already failed it.
const ResultPoll = 30 * time.Second

// Run checks every Interval until ctx ends, and collects a queued run's
// result every ResultPoll in between.
func (r *Reclaimer) Run(ctx context.Context) {
	// First check soon after start (the reconciler's first pass delivers the
	// policy at ~30 s), then every Interval.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	r.check(time.Now())
	t := time.NewTicker(Interval)
	defer t.Stop()
	poll := time.NewTicker(ResultPoll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-poll.C:
			r.mu.Lock()
			r.collect(now)
			r.mu.Unlock()
		case <-t.C:
			r.check(time.Now())
		}
	}
}

func (r *Reclaimer) check(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Collect a finished run first, so its result is what /health shows.
	if r.collect(now) {
		return
	}
	queue, why := Decide(r.policy, r.disks(), r.lastQueued, now)
	r.status = why
	if !queue {
		return
	}
	hb, err := hostd.ReadHeartbeat(r.spool)
	if err != nil {
		// The controller host runs hostd in controller mode, whose own
		// ladder (queued by the gateway) already covers this disk.
		r.status = "over watermark, but no worker hostd here — the controller's own ladder covers a controller disk"
		return
	}
	if hb.Stale(now.UTC()) {
		r.status = "over watermark, but hostd's heartbeat is stale (" + hb.TS + ")"
		return
	}
	if !hb.Supports(OpName) {
		r.status = "over watermark, but this node's hostd predates disk-reclaim — run `noo upgrade --nodes`"
		return
	}
	name := fmt.Sprintf("disk-reclaim-%d", now.UTC().UnixNano())
	if err := hostd.WriteCommand(r.spool, name, hostd.Command{
		Op: OpName, Service: "noo-node-agent", Args: Args(r.policy), RequestedBy: "node-agent:diskreclaim",
	}); err != nil {
		r.status = "cannot queue disk-reclaim: " + err.Error()
		return
	}
	r.pending, r.lastQueued = name, now
	r.status = "reclaim queued — " + why
	slog.Warn("diskreclaim.queued", "reason", why, "dry_run", r.policy.DryRun)
}

// collect records a queued run's result once hostd has written it, and
// reports whether a run is still pending. Callers hold r.mu.
func (r *Reclaimer) collect(now time.Time) (pending bool) {
	if r.pending == "" {
		return false
	}
	res, err := hostd.ReadResult(r.spool, r.pending)
	if err != nil {
		r.status = "reclaim queued, waiting for hostd"
		return true
	}
	_ = os.Remove(filepath.Join(r.spool, r.pending+".result.json"))
	r.last = map[string]any{"finished": now.UTC().Format(time.RFC3339), "ok": res.OK,
		"report": res.Stderr}
	r.pending = ""
	if res.OK {
		r.status = "last reclaim finished"
		slog.Info("diskreclaim.finished", "ok", true, "report", res.Stderr)
	} else {
		r.status = "last reclaim FAILED — see last_result"
		slog.Warn("diskreclaim.failed", "report", res.Stderr)
	}
	return false
}

// State is the /health `disk_reclaim` object: the policy in force, what the
// last check decided, and the last finished run's report.
func (r *Reclaimer) State() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]any{"status": r.status}
	if r.policy != nil {
		out["policy"] = *r.policy
	}
	if !r.lastQueued.IsZero() {
		out["last_queued"] = r.lastQueued.UTC().Format(time.RFC3339)
	}
	if r.last != nil {
		out["last_result"] = r.last
	}
	return out
}
