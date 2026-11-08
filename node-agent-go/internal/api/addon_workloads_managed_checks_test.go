// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// probeManaged is a lifecycle that records what the actuator asked of it: the
// time each call was given, and how often it was called at all.
type probeManaged struct {
	mu        sync.Mutex
	managedFn func(addon, wl string) (bool, error)
	state     dockerpkg.ManagedState
	err       error
	budget    map[string]time.Duration
	calls     []string
}

func (p *probeManaged) note(kind string, ctx context.Context, addon, wl string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.budget == nil {
		p.budget = map[string]time.Duration{}
	}
	if dl, ok := ctx.Deadline(); ok {
		p.budget[kind] = time.Until(dl)
	}
	p.calls = append(p.calls, kind+":"+addon+"/"+wl)
}

func (p *probeManaged) Managed(_ context.Context, addon, wl string) (bool, error) {
	if p.managedFn == nil {
		return true, nil
	}
	return p.managedFn(addon, wl)
}
func (p *probeManaged) Start(ctx context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	p.note("start", ctx, addon, wl)
	return p.state, p.err
}
func (p *probeManaged) Stop(ctx context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	p.note("stop", ctx, addon, wl)
	return p.state, p.err
}
func (p *probeManaged) Status(ctx context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	p.note("status", ctx, addon, wl)
	return p.state, p.err
}

func managedRig(t *testing.T, p *probeManaged) (*Server, *fakeWorkloads) {
	t.Helper()
	addonwl.SetDeclared(nil)
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "x"}}
	return &Server{workloadOps: f, managed: p}, f
}

// A managed start may load an image, a managed stop waits out a drain of up
// to an hour, and a status is a quick read: each call gets its own budget.
func TestEachManagedCallGetsItsOwnTimeBudget(t *testing.T) {
	p := &probeManaged{state: dockerpkg.ManagedState{State: "running"}}
	s, _ := managedRig(t, p)
	m := workloadMux(s)
	call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/start", "")
	call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/stop", "")
	call(t, m, "GET", "/api/addon-workloads/rhaddon/worker", "")
	for kind, want := range map[string][2]time.Duration{
		"start":  {9*time.Minute + 30*time.Second, 10 * time.Minute},
		"stop":   {64 * time.Minute, time.Hour + 5*time.Minute},
		"status": {19 * time.Second, 20 * time.Second},
	} {
		if got := p.budget[kind]; got < want[0] || got > want[1] {
			t.Errorf("%s was given %v, want within (%v, %v]", kind, got, want[0], want[1])
		}
	}
}

// A refusal keeps the lifecycle's own status, code and detail; any other error
// is a 502 workload_error.
func TestAManagedRefusalKeepsItsStatusCodeAndDetail(t *testing.T) {
	p := &probeManaged{}
	s, _ := managedRig(t, p)
	m := workloadMux(s)

	p.err = &dockerpkg.ManagedError{HTTP: 404, Code: "not_desired", Detail: "desired-config does not list this workload"}
	code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/start", "")
	if code != 404 || out["error"] != "not_desired" || out["detail"] != "desired-config does not list this workload" || out["status"] != "refused" || out["managed"] != true {
		t.Fatalf("a managed refusal: %d %v", code, out)
	}

	p.err = errors.New("docker said no")
	code, out = call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/start", "")
	if code != 502 || out["error"] != "workload_error" || out["detail"] != "docker said no" || out["status"] != "refused" {
		t.Fatalf("any other error: %d %v", code, out)
	}
}

// What the gateway's ready wait reads: running and ready as the lifecycle
// says them, docker's health word for each case, the reason only when there is
// one.
func TestAManagedAnswerReportsTheStateExactly(t *testing.T) {
	p := &probeManaged{}
	s, _ := managedRig(t, p)
	m := workloadMux(s)
	for name, tc := range map[string]struct {
		st      dockerpkg.ManagedState
		running bool
		ready   bool
		health  string
		reason  any
	}{
		"ready":       {dockerpkg.ManagedState{State: "running", Running: true, Ready: true}, true, true, "healthy", nil},
		"starting":    {dockerpkg.ManagedState{State: "running", Running: true}, true, false, "starting", nil},
		"crashed":     {dockerpkg.ManagedState{State: "running", Reason: "crashed"}, false, false, "", "crashed"},
		"provisioned": {dockerpkg.ManagedState{State: "provisioned"}, false, false, "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			p.state = tc.st
			code, out := call(t, m, "GET", "/api/addon-workloads/rhaddon/worker", "")
			if code != 200 || out["state"] != tc.st.State || out["running"] != tc.running || out["ready"] != tc.ready || out["health"] != tc.health || out["reason"] != tc.reason {
				t.Fatalf("answer = %d %v", code, out)
			}
			if _, has := out["reason"]; has != (tc.reason != nil) {
				t.Fatalf("reason present = %v in %v", has, out)
			}
		})
	}
}

// Either name that the container path refuses stays with the container path,
// even for a lifecycle that would claim the workload.
func TestABadAddonOrWorkloadNameNeverReachesTheLifecycle(t *testing.T) {
	p := &probeManaged{} // claims every workload
	s, _ := managedRig(t, p)
	m := workloadMux(s)
	for _, path := range []string{"/api/addon-workloads/Bad.Addon/worker/start", "/api/addon-workloads/rhaddon/Bad_Workload/start"} {
		if code, out := call(t, m, "POST", path, ""); code != 400 || out["error"] != "bad_name" {
			t.Errorf("%s: %d %v", path, code, out)
		}
	}
	if len(p.calls) != 0 {
		t.Fatalf("the lifecycle was asked about a bad name: %v", p.calls)
	}
}

// A lifecycle that cannot say whether it owns the workload (the daemon
// failed) does not claim it: the container path decides, as it always did.
func TestAWorkloadTheLifecycleCannotConfirmGoesToTheContainerPath(t *testing.T) {
	addonwl.SetDeclared([]addonwl.Decl{{Addon: "rhaddon", Name: "voice-worker", Container: "noo-rhaddon-worker"}})
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	p := &probeManaged{managedFn: func(string, string) (bool, error) { return true, errors.New("docker unreachable") }}
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "noo-rhaddon-worker"}}
	m := workloadMux(&Server{workloadOps: f, managed: p})
	code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/voice-worker/start", "")
	if code != 200 || out["managed"] != nil || len(f.starts) != 1 || len(p.calls) != 0 {
		t.Fatalf("%d %v starts=%v lifecycle calls=%v", code, out, f.starts, p.calls)
	}
}
