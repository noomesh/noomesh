// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package diskreclaim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

func disks(pcts ...float64) []hardware.DiskUsage {
	out := make([]hardware.DiskUsage, 0, len(pcts))
	for _, p := range pcts {
		out = append(out, hardware.DiskUsage{Path: "/", UsedPercent: p})
	}
	return out
}

func TestDecide(t *testing.T) {
	now := time.Now()
	on := &Policy{Enabled: true, DryRun: true, Watermark: 85}
	cases := []struct {
		name   string
		p      *Policy
		d      []hardware.DiskUsage
		last   time.Time
		want   bool
		reason string
	}{
		{"no policy (older gateway)", nil, disks(99), time.Time{}, false, "no policy"},
		{"disabled", &Policy{Watermark: 85}, disks(99), time.Time{}, false, "disabled"},
		{"below", on, disks(40, 84), time.Time{}, false, "below watermark"},
		{"no measurement", on, nil, time.Time{}, false, "no disk measurement"},
		{"over: worst disk counts", on, disks(40, 92), time.Time{}, true, "over watermark"},
		{"over but ran 10m ago", on, disks(92), now.Add(-10 * time.Minute), false, "waiting"},
		{"over and ran 2h ago", on, disks(92), now.Add(-2 * time.Hour), true, "over watermark"},
		{"junk watermark falls back to 85", &Policy{Enabled: true, Watermark: 0}, disks(86), time.Time{}, true, ">= 85%"},
	}
	for _, c := range cases {
		got, why := Decide(c.p, c.d, c.last, now)
		if got != c.want || !strings.Contains(why, c.reason) {
			t.Errorf("%s: Decide = %v %q, want %v containing %q", c.name, got, why, c.want, c.reason)
		}
	}
}

func TestArgsCarryThePolicy(t *testing.T) {
	got := strings.Join(Args(&Policy{Enabled: true, DryRun: false, Watermark: 80, CacheCapBytes: 25e9}), " ")
	if got != "dry_run=false watermark=80 cache_cap_bytes=25000000000" {
		t.Fatalf("Args = %q", got)
	}
	if got := strings.Join(Args(&Policy{DryRun: true}), " "); got != "dry_run=true watermark=85" {
		t.Fatalf("Args default = %q", got)
	}
}

func writeHB(t *testing.T, spool string, ops []string, ts time.Time) {
	t.Helper()
	hb := hostd.Heartbeat{TS: ts.UTC().Format("2006-01-02T15:04:05Z"), Interval: 15, Ops: ops}
	b, _ := json.Marshal(hb)
	if err := os.WriteFile(filepath.Join(spool, hostd.HeartbeatFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func cmds(t *testing.T, spool string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(spool, "disk-reclaim-*.cmd.json"))
	return m
}

// A full cycle against a real spool: queue once, collect the result into
// /health, do not queue again inside the gap.
func TestReclaimerQueuesCollectsAndWaits(t *testing.T) {
	spool := t.TempDir()
	r := New(spool)
	r.disks = func() []hardware.DiskUsage { return disks(92) }
	now := time.Now()

	r.check(now)
	if !strings.Contains(r.State()["status"].(string), "no policy") {
		t.Fatalf("acted without a policy: %v", r.State())
	}

	r.SetPolicy(&Policy{Enabled: true, DryRun: true, Watermark: 85})
	writeHB(t, spool, []string{"journal-follow", OpName}, now)
	r.check(now)
	queued := cmds(t, spool)
	if len(queued) != 1 {
		t.Fatalf("expected one queued command, got %v", queued)
	}
	raw, _ := os.ReadFile(queued[0])
	c, err := hostd.ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Op != OpName || strings.Join(c.Args, " ") != "dry_run=true watermark=85" {
		t.Fatalf("command = %+v", c)
	}

	name := strings.TrimSuffix(filepath.Base(queued[0]), ".cmd.json")
	_ = os.Remove(queued[0])
	if err := hostd.WriteResult(spool, name, hostd.Result{OK: true, Op: OpName, Stderr: "DRY RUN (nothing removed) — target=/"}); err != nil {
		t.Fatal(err)
	}
	r.check(now.Add(Interval))
	st := r.State()
	last, _ := st["last_result"].(map[string]any)
	if last == nil || !strings.Contains(last["report"].(string), "DRY RUN") {
		t.Fatalf("result not collected into /health: %v", st)
	}
	if len(cmds(t, spool)) != 0 {
		t.Fatalf("queued again inside the one-hour gap: %v", cmds(t, spool))
	}
	if !strings.Contains(st["status"].(string), "waiting") {
		t.Fatalf("status should say it is waiting out the gap: %v", st["status"])
	}
}

// Over the watermark with no way to act says why, and queues nothing.
func TestReclaimerExplainsWhyItCannotAct(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name string
		hb   func(spool string)
		want string
	}{
		{"controller host: no worker hostd", func(string) {}, "controller's own ladder"},
		{"old hostd", func(s string) { writeHB(t, s, []string{"journal-follow"}, now) }, "noo upgrade --nodes"},
		{"stale hostd", func(s string) { writeHB(t, s, []string{OpName}, now.Add(-time.Hour)) }, "stale"},
	} {
		spool := t.TempDir()
		c.hb(spool)
		r := New(spool)
		r.disks = func() []hardware.DiskUsage { return disks(95) }
		r.SetPolicy(&Policy{Enabled: true, Watermark: 85})
		r.check(now)
		if s := r.State()["status"].(string); !strings.Contains(s, c.want) {
			t.Errorf("%s: status = %q, want it to mention %q", c.name, s, c.want)
		}
		if len(cmds(t, spool)) != 0 {
			t.Errorf("%s: queued a command it cannot run", c.name)
		}
	}
}

// v0.2.88 rehearsal: hostd failed the run within seconds, but /health said
// "reclaim queued" until the next 15-minute check. The poll path collects it,
// and a failure is what the status says.
func TestAFailedRunSurfacesOnThePollNotTheNextCheck(t *testing.T) {
	spool := t.TempDir()
	r := New(spool)
	r.disks = func() []hardware.DiskUsage { return disks(92) }
	now := time.Now()
	r.SetPolicy(&Policy{Enabled: true, DryRun: true, Watermark: 40})
	writeHB(t, spool, []string{OpName}, now)
	r.check(now)
	queued := cmds(t, spool)
	if len(queued) != 1 {
		t.Fatalf("expected one queued command, got %v", queued)
	}

	r.mu.Lock()
	still := r.collect(now.Add(ResultPoll))
	r.mu.Unlock()
	if !still {
		t.Fatal("collect reported nothing pending before hostd wrote a result")
	}

	name := strings.TrimSuffix(filepath.Base(queued[0]), ".cmd.json")
	_ = os.Remove(queued[0])
	report := "disk-reclaim: cannot measure usage of /var/lib/containerd"
	if err := hostd.WriteResult(spool, name, hostd.Result{OK: false, Op: OpName, RC: 1, Stderr: report}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	still = r.collect(now.Add(2 * ResultPoll))
	r.mu.Unlock()
	if still {
		t.Fatal("result written but still pending")
	}
	st := r.State()
	last, _ := st["last_result"].(map[string]any)
	if last == nil || last["ok"] != false || last["report"] != report {
		t.Fatalf("failure not surfaced in /health: %v", st)
	}
	if !strings.Contains(st["status"].(string), "FAILED") {
		t.Fatalf("status = %q, want it to say the run failed", st["status"])
	}
	if ResultPoll >= Interval {
		t.Fatalf("ResultPoll %v must be well under Interval %v", ResultPoll, Interval)
	}
}
