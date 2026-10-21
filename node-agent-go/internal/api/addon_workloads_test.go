// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
)

type fakeWorkloads struct {
	ctr     *dockerpkg.WorkloadState
	findErr error
	starts  []string
	stops   []string
	grace   int
}

func (f *fakeWorkloads) FindWorkloadContainer(_ context.Context, _, _, _ string) (*dockerpkg.WorkloadState, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	c := *f.ctr
	return &c, nil
}
func (f *fakeWorkloads) StartContainer(_ context.Context, id string) error {
	f.starts = append(f.starts, id)
	f.ctr.Running = true
	return nil
}
func (f *fakeWorkloads) StopContainerGraceful(_ context.Context, id string, grace int) error {
	f.stops = append(f.stops, id)
	f.grace = grace
	f.ctr.Running = false
	return nil
}

func workloadMux(s *Server) *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/addon-workloads/{addon}/{workload}", s.handleWorkloadStatus)
	m.HandleFunc("POST /api/addon-workloads/{addon}/{workload}/start", s.handleWorkloadStart)
	m.HandleFunc("POST /api/addon-workloads/{addon}/{workload}/stop", s.handleWorkloadStop)
	return m
}

func call(t *testing.T, m *http.ServeMux, method, path, body string) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// heldGPU installs a gpuyield controller in the held state for the test.
func heldGPU(t *testing.T, held bool) {
	t.Helper()
	c := gpuyield.New(gpuyield.ConfigFromEnv(func(string) string { return "" }), nil, &noDocker{}, "")
	gpuyield.SetDefault(c)
	t.Cleanup(func() { gpuyield.SetDefault(nil) })
	if held {
		if _, err := c.Hold(context.Background(), gpuyield.HoldRequest{OperationID: "res-1", Mode: gpuyield.ModeImmediate}); err != nil {
			t.Fatal(err)
		}
	}
}

// noDocker: a gpuyield Docker with nothing to list or stop.
type noDocker struct{}

func (noDocker) GPUBackendContainers(context.Context) ([]dockerpkg.GPUBackend, error) {
	return nil, nil
}
func (noDocker) StopContainerGraceful(context.Context, string, int) error { return nil }
func (noDocker) StartContainer(context.Context, string) error             { return nil }
func (noDocker) NoomeshContainers(context.Context) ([]dockerpkg.NoomeshContainer, error) {
	return nil, nil
}

func TestWorkloadActuatorActsOnlyOnADeclaredLabelledContainer(t *testing.T) {
	addonwl.SetDeclared(nil)
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "noo-pai-voice-worker"}}
	s := &Server{workloadOps: f}
	m := workloadMux(s)

	// Undeclared: refused before docker is touched.
	code, out := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", "")
	if code != 404 || out["error"] != "not_declared" {
		t.Fatalf("undeclared: %d %v", code, out)
	}
	// A bad name never reaches the lookup.
	if code, out := call(t, m, "POST", "/api/addon-workloads/Pai.Voice/x/start", ""); code != 400 || out["error"] != "bad_name" {
		t.Fatalf("bad name: %d %v", code, out)
	}

	addonwl.SetDeclared([]addonwl.Decl{{Addon: "pai-voice", Name: "voice-worker", Container: "noo-pai-voice-worker", GPU: true, NeedMB: 11264}})
	// Declared, but no such labelled container on this node.
	f.findErr = errors.New("no container labelled noo.addon=pai-voice noo.workload=voice-worker named noo-pai-voice-worker")
	if code, out := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", ""); code != 404 || out["error"] != "no_container" {
		t.Fatalf("no container: %d %v", code, out)
	}
	f.findErr = nil

	// A GPU workload does not start while the pool owns the GPU.
	heldGPU(t, false)
	code, out = call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", "")
	if code != 409 || out["error"] != "gpu_not_held" || len(f.starts) != 0 {
		t.Fatalf("gpu not held: %d %v starts=%v", code, out, f.starts)
	}
	if len(f.starts) != 0 {
		t.Fatal("nothing started")
	}
}

func TestWorkloadStartStopAndStatusUnderAHold(t *testing.T) {
	addonwl.SetDeclared([]addonwl.Decl{{Addon: "pai-voice", Name: "voice-worker", Container: "noo-pai-voice-worker", GPU: true, NeedMB: 11264}})
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	heldGPU(t, true)
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "noo-pai-voice-worker"}}
	s := &Server{workloadOps: f}
	m := workloadMux(s)

	code, out := call(t, m, "GET", "/api/addon-workloads/pai-voice/voice-worker", "")
	if code != 200 || out["running"] != false || out["gpu_held"] != true || out["need_mb"] != float64(11264) {
		t.Fatalf("status: %d %v", code, out)
	}
	code, out = call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", "")
	if code != 200 || out["status"] != "started" || out["running"] != true || len(f.starts) != 1 || f.starts[0] != "c1" {
		t.Fatalf("start: %d %v starts=%v", code, out, f.starts)
	}
	// Starting again is a no-op that reports the state.
	code, out = call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/start", "")
	if code != 200 || len(f.starts) != 1 {
		t.Fatalf("idempotent start: %d %v starts=%v", code, out, f.starts)
	}
	code, out = call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/stop", `{"timeout_secs": 45}`)
	if code != 200 || out["status"] != "stopped" || out["running"] != false || len(f.stops) != 1 || f.grace != 45 {
		t.Fatalf("stop: %d %v stops=%v grace=%d", code, out, f.stops, f.grace)
	}
	// Stopping a stopped container: nothing to do.
	if code, _ := call(t, m, "POST", "/api/addon-workloads/pai-voice/voice-worker/stop", ""); code != 200 || len(f.stops) != 1 {
		t.Fatalf("idempotent stop: %d stops=%v", code, f.stops)
	}
	// A CPU workload needs no hold.
	addonwl.SetDeclared([]addonwl.Decl{{Addon: "pai-voice", Name: "cpu-side", Container: "noo-pai-voice-worker"}})
	gpuyield.SetDefault(nil)
	if code, out := call(t, m, "POST", "/api/addon-workloads/pai-voice/cpu-side/start", ""); code != 200 {
		t.Fatalf("cpu workload: %d %v", code, out)
	}
}

func TestDeclarationsReplaceAndValidate(t *testing.T) {
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	addonwl.SetDeclared([]addonwl.Decl{
		{Addon: " pai-voice ", Name: "voice-worker", Container: "noo-pai-voice-worker", GPU: true},
		{Addon: "", Name: "x", Container: "y"},
	})
	d, ok := addonwl.Lookup("pai-voice", "voice-worker")
	if !ok || !d.GPU || d.Addon != "pai-voice" {
		t.Fatalf("trimmed and kept: %+v %v", d, ok)
	}
	if len(addonwl.Declared()) != 1 {
		t.Fatalf("the blank one is dropped: %+v", addonwl.Declared())
	}
	addonwl.SetDeclared(nil)
	if _, ok := addonwl.Lookup("pai-voice", "voice-worker"); ok {
		t.Fatal("cleared")
	}
	for name, want := range map[string]bool{"pai-voice": true, "voice_worker2": true, "": false, "Voice": false, "1x": false, "a.b": false, strings.Repeat("a", 33): false} {
		if addonwl.NameOK(name) != want {
			t.Fatalf("NameOK(%q) = %v", name, !want)
		}
	}
}
