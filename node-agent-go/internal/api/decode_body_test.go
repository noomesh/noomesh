// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
)

// Followup i495 item 3: a malformed body on an action route is a 400 and the
// action does not run; an empty body keeps the legacy "no fields" meaning.

var badBodies = map[string]string{
	"syntax":    `{"force": tru`,
	"truncated": `{"operation_id":"op-1"`,
	"wrongtype": `{"force":"yes","operation_id":7,"owner":5,"dry_run":"yes","max_size_mb":"x","deep":"yes","remove_folder":1,"timeout_secs":"x"}`,
	"notobject": `[1,2]`,
	"trailing":  `{} garbage`,
	"toobig":    `{"reason":"` + strings.Repeat("a", 5000) + `"}`,
}

func wantInvalidBody(t *testing.T, name string, code int, out map[string]any) {
	t.Helper()
	if code != http.StatusBadRequest || out["error"] != "invalid_body" || out["detail"] == "" || out["detail"] == nil {
		t.Fatalf("%s: want 400 invalid_body with a detail, got %d %v", name, code, out)
	}
}

func TestGPUReleaseMalformedBodyIs400AndReleasesNothing(t *testing.T) {
	var calls []gpuyield.ReleaseRequest
	s := &Server{}
	s.SetGPUHold(nil, func(_ context.Context, req gpuyield.ReleaseRequest) (gpuyield.Contention, error) {
		calls = append(calls, req)
		return gpuyield.Contention{State: "free"}, nil
	})
	m := http.NewServeMux()
	m.HandleFunc("POST /gpu/release", s.handleGPURelease)
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/gpu/release", body)
		wantInvalidBody(t, name, code, out)
	}
	if len(calls) != 0 {
		t.Fatalf("a malformed body must never release (it would force-release any owner's hold): %+v", calls)
	}
	// Empty body: the documented legacy release = force.
	if code, out := call(t, m, "POST", "/gpu/release", ""); code != 200 || len(calls) != 1 || !calls[0].Force {
		t.Fatalf("empty body: %d %v %+v", code, out, calls)
	}
	// A well-formed body still carries its ids and does not force.
	if code, _ := call(t, m, "POST", "/gpu/release", `{"operation_id":"op-1","generation":3}`); code != 200 || len(calls) != 2 || calls[1].Force || calls[1].OperationID != "op-1" || calls[1].Generation != 3 {
		t.Fatalf("well-formed body: %d %+v", code, calls)
	}
}

func TestGPUHoldMalformedBodyIs400AndHoldsNothing(t *testing.T) {
	var calls []gpuyield.HoldRequest
	s := &Server{}
	s.SetGPUHold(func(_ context.Context, req gpuyield.HoldRequest) (gpuyield.Contention, error) {
		calls = append(calls, req)
		return gpuyield.Contention{State: "held"}, nil
	}, nil)
	m := http.NewServeMux()
	m.HandleFunc("POST /gpu/hold", s.handleGPUHold)
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/gpu/hold", body)
		wantInvalidBody(t, name, code, out)
	}
	if len(calls) != 0 {
		t.Fatalf("a malformed body must never create an ownerless hold: %+v", calls)
	}
	if code, out := call(t, m, "POST", "/gpu/hold", ""); code != 200 || len(calls) != 1 || calls[0].OperationID != "" {
		t.Fatalf("empty body (legacy hold): %d %v %+v", code, out, calls)
	}
}

// fakeDockerd answers the docker API on a loopback port and counts every call
// but /_ping, so a test can see whether an action reached the daemon.
type fakeDockerd struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeDockerd) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// newFakeDockerServer points DOCKER_HOST (the SDK's own variable, not a new
// knob) at a fake daemon and returns a real dockerpkg.Client built on it.
func newFakeDockerServer(t *testing.T) (*Server, *fakeDockerd) {
	t.Helper()
	f := &fakeDockerd{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	dc, err := dockerpkg.NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	return &Server{docker: dc}, f
}

func TestCleanupImagesMalformedBodyIs400AndTouchesNothing(t *testing.T) {
	s, d := newFakeDockerServer(t)
	m := http.NewServeMux()
	m.HandleFunc("POST /cleanup/images", s.handleCleanupImages)
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/cleanup/images", body)
		wantInvalidBody(t, name, code, out)
	}
	if got := d.seen(); len(got) != 0 {
		t.Fatalf("a malformed body must not reach docker (it would be a real delete): %v", got)
	}
	// Empty body: legacy full (non-dry) run reaches the daemon.
	code, out := call(t, m, "POST", "/cleanup/images", "")
	if code != 200 || out["dry_run"] != false || len(d.seen()) == 0 {
		t.Fatalf("empty body: %d %v %v", code, out, d.seen())
	}
}

func TestCleanupLogsMalformedBodyIs400AndTouchesNothing(t *testing.T) {
	s, d := newFakeDockerServer(t)
	m := http.NewServeMux()
	m.HandleFunc("POST /cleanup/logs", s.handleCleanupLogs)
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/cleanup/logs", body)
		wantInvalidBody(t, name, code, out)
	}
	if got := d.seen(); len(got) != 0 {
		t.Fatalf("a malformed body must not reach docker (it would be a real truncate): %v", got)
	}
	code, out := call(t, m, "POST", "/cleanup/logs", "")
	if code != 200 || out["dry_run"] != false || len(d.seen()) == 0 {
		t.Fatalf("empty body: %d %v %v", code, out, d.seen())
	}
}

func TestCleanMalformedBodyIs400AndStopsNothing(t *testing.T) {
	s, d := newFakeDockerServer(t)
	m := http.NewServeMux()
	m.HandleFunc("POST /clean", s.handleClean)
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/clean", body)
		wantInvalidBody(t, name, code, out)
	}
	if got := d.seen(); len(got) != 0 {
		t.Fatalf("a malformed body must not stop containers: %v", got)
	}
	if code, _ := call(t, m, "POST", "/clean", ""); code != 200 || len(d.seen()) == 0 {
		t.Fatalf("empty body (legacy clean) must run: %d %v", code, d.seen())
	}
}

func TestWorkloadStopMalformedBodyIs400AndStopsNothing(t *testing.T) {
	addonwl.SetDeclared([]addonwl.Decl{{Addon: "rhaddon", Name: "worker", Container: "noo-rhaddon-worker"}})
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	f := &fakeWorkloads{ctr: &dockerpkg.WorkloadState{ID: "c1", Name: "noo-rhaddon-worker", Running: true}}
	m := workloadMux(&Server{workloadOps: f})
	for name, body := range badBodies {
		code, out := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/stop", body)
		wantInvalidBody(t, name, code, out)
	}
	if len(f.stops) != 0 {
		t.Fatalf("a malformed body must not stop the workload: %v", f.stops)
	}
	if code, _ := call(t, m, "POST", "/api/addon-workloads/rhaddon/worker/stop", ""); code != 200 || len(f.stops) != 1 {
		t.Fatalf("empty body: %d %v", code, f.stops)
	}
}
