// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

type fakeManaged struct {
	managed map[string]bool
	calls   []string
	state   dockerpkg.ManagedState
	err     error
}

func (f *fakeManaged) Managed(_ context.Context, addon, wl string) (bool, error) {
	return f.managed[addon+"/"+wl], nil
}
func (f *fakeManaged) Start(_ context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	f.calls = append(f.calls, "start:"+addon+"/"+wl)
	return f.state, f.err
}
func (f *fakeManaged) Stop(_ context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	f.calls = append(f.calls, "stop:"+addon+"/"+wl)
	return f.state, f.err
}
func (f *fakeManaged) Status(_ context.Context, addon, wl string) (dockerpkg.ManagedState, error) {
	f.calls = append(f.calls, "status:"+addon+"/"+wl)
	return f.state, f.err
}

// A start for an agent-managed node workload goes through the node workload
// lifecycle; the container actuator is not consulted (it has no declaration for
// it and would answer 404 not_declared).
func TestActuatorStartRoutesManagedWorkloadsThroughTheLifecycle(t *testing.T) {
	addonwl.SetDeclared(nil)
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "x"}}
	mc := &fakeManaged{managed: map[string]bool{"rhaddon/worker": true}, state: dockerpkg.ManagedState{State: "running", Running: true}}
	s := &Server{workloadOps: f, managed: mc}
	m := workloadMux(s)

	code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/start", "")
	if code != 200 || out["status"] != "started" || out["managed"] != true || out["health"] != "starting" || out["state"] != "running" {
		t.Fatalf("managed start: %d %v", code, out)
	}
	if len(mc.calls) != 1 || mc.calls[0] != "start:rhaddon/worker" {
		t.Fatalf("lifecycle calls = %v", mc.calls)
	}
	if len(f.starts) != 0 {
		t.Fatalf("the container actuator started something: %v", f.starts)
	}

	// Ready shows as docker's "healthy", which the gateway's ready wait reads.
	mc.state = dockerpkg.ManagedState{State: "running", Running: true, Ready: true}
	if _, out := call(t, m, "GET", "/api/addon-workloads/rhaddon/worker", ""); out["health"] != "healthy" || out["ready"] != true {
		t.Fatalf("managed status: %v", out)
	}
	mc.state = dockerpkg.ManagedState{State: "running", Running: true, Reason: "crashed"}
	if _, out := call(t, m, "GET", "/api/addon-workloads/rhaddon/worker", ""); out["reason"] != "crashed" || out["health"] != "starting" {
		t.Fatalf("crashed status: %v", out)
	}

	// Stop is the release: routed to the lifecycle, and a refusal keeps its status.
	mc.state = dockerpkg.ManagedState{State: "provisioned"}
	if code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/stop", ""); code != 200 || out["status"] != "stopped" || out["state"] != "provisioned" {
		t.Fatalf("managed stop: %d %v", code, out)
	}
	mc.err = &dockerpkg.ManagedError{HTTP: 409, Code: "drain_timeout", Detail: "the worker did not finish draining"}
	if code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/stop", ""); code != 409 || out["error"] != "drain_timeout" || out["status"] != "refused" {
		t.Fatalf("refused stop: %d %v", code, out)
	}
	mc.err = &dockerpkg.ManagedError{HTTP: 409, Code: "consent_none", Detail: "policy is none"}
	if code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/start", ""); code != 409 || out["error"] != "consent_none" {
		t.Fatalf("refused start: %d %v", code, out)
	}
	if len(f.starts)+len(f.stops) != 0 {
		t.Fatalf("the container actuator acted on a managed workload: %v %v", f.starts, f.stops)
	}
}

// Pre-created (i163) workloads are not agent-managed: their path is exactly what
// it was, and the lifecycle is never asked to act on them.
func TestActuatorLeavesPreCreatedWorkloadsOnTheContainerPath(t *testing.T) {
	addonwl.SetDeclared([]addonwl.Decl{{Addon: "pai-voice", Name: "voice-worker", Container: "noo-pai-voice-worker"}})
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "noo-pai-voice-worker"}}
	mc := &fakeManaged{managed: map[string]bool{"rhaddon/worker": true}}
	m := workloadMux(&Server{workloadOps: f, managed: mc})

	code, out := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", "")
	if code != 200 || out["status"] != "started" || out["container"] != "noo-pai-voice-worker" || out["managed"] != nil {
		t.Fatalf("pre-created start: %d %v", code, out)
	}
	if len(f.starts) != 1 || f.starts[0] != "c1" {
		t.Fatalf("container starts = %v", f.starts)
	}
	if code, out := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/stop", `{"timeout_secs":12}`); code != 200 || out["status"] != "stopped" || f.grace != 12 {
		t.Fatalf("pre-created stop: %d %v grace %d", code, out, f.grace)
	}
	if len(mc.calls) != 0 {
		t.Fatalf("the lifecycle acted on a pre-created workload: %v", mc.calls)
	}
	// Without a lifecycle at all the old path is the only path.
	m = workloadMux(&Server{workloadOps: f})
	if code, _ := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", ""); code != 200 {
		t.Fatalf("no lifecycle: %d", code)
	}
	// A name the old path refuses is still refused by it.
	m = workloadMux(&Server{workloadOps: f, managed: mc})
	if code, out := call(t, m, "POST", "/api/addon-workloads/Pai.Voice/x/start", ""); code != 400 || out["error"] != "bad_name" {
		t.Fatalf("bad name: %d %v", code, out)
	}
}
