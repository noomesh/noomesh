// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

type fakeNW struct {
	mu        sync.Mutex
	converged []string
	refused   map[string]string
	retained  map[string]bool
	swept     []map[string]bool // the keep set of each orphan sweep
	read      bool
	rows      []dockerpkg.Row
	managed   bool
	started   []nodewl.Entry
	stopped   []nodewl.Entry
	stopErr   error
	startErr  error
}

func (f *fakeNW) Converge(_ context.Context, e nodewl.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.converged = append(f.converged, e.Addon+"/"+e.Name+":"+e.State)
}
func (f *fakeNW) Refuse(addon, name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refused == nil {
		f.refused = map[string]string{}
	}
	f.refused[addon+"/"+name] = nodewl.CodeOf(err)
}
func (f *fakeNW) Retain(keep map[string]bool) { f.mu.Lock(); f.retained = keep; f.mu.Unlock() }
func (f *fakeNW) MarkRead()                   { f.mu.Lock(); f.read = true; f.mu.Unlock() }
func (f *fakeNW) ReleaseOrphans(_ context.Context, keep map[string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swept = append(f.swept, keep)
}
func (f *fakeNW) Rows() []dockerpkg.Row { return f.rows }
func (f *fakeNW) IsManaged(context.Context, string, string) (bool, error) {
	return f.managed, nil
}
func (f *fakeNW) StartManaged(_ context.Context, e nodewl.Entry) error {
	f.started = append(f.started, e)
	return f.startErr
}
func (f *fakeNW) StopManaged(_ context.Context, e nodewl.Entry) error {
	f.stopped = append(f.stopped, e)
	return f.stopErr
}
func (f *fakeNW) ManagedStatus(context.Context, string, string) (dockerpkg.ManagedState, error) {
	return dockerpkg.ManagedState{State: nodewl.StateRunning, Running: true}, nil
}

func nwRig(t *testing.T, nw *fakeNW) *Reconciler {
	t.Helper()
	return &Reconciler{cfg: &config.Config{NodeID: "node-a"}, nodeWL: nw}
}

func TestEachDesiredRowConvergesAndTheUnlistedAreDropped(t *testing.T) {
	nw := &fakeNW{}
	r := nwRig(t, nw)
	if !r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: fixture(t)}}) {
		t.Fatal("the pass must go on")
	}
	r.nwWG.Wait()
	sort.Strings(nw.converged)
	want := []string{"rhaddon/echo:running", "rhaddon/worker:provisioned"}
	if !reflect.DeepEqual(nw.converged, want) {
		t.Fatalf("converged %v, want %v", nw.converged, want)
	}
	if !nw.read || !nw.retained["rhaddon/worker"] || !nw.retained["rhaddon/echo"] || len(nw.retained) != 2 {
		t.Fatalf("read=%v retained=%v", nw.read, nw.retained)
	}
}

func TestOneMalformedRowIsRefusedAloneAndTheOthersConverge(t *testing.T) {
	var rows []map[string]any
	if err := json.Unmarshal(fixture(t), &rows); err != nil {
		t.Fatal(err)
	}
	rows[1]["state"] = "bogus"
	raw, _ := json.Marshal(rows)
	nw := &fakeNW{}
	r := nwRig(t, nw)
	r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: raw}})
	r.nwWG.Wait()
	if !reflect.DeepEqual(nw.converged, []string{"rhaddon/worker:provisioned"}) {
		t.Fatalf("converged %v", nw.converged)
	}
	if nw.refused["rhaddon/echo"] != nodewl.ReasonDesiredInvalid {
		t.Fatalf("refused = %v", nw.refused)
	}
}

func TestNoNodeWorkloadsKeyTouchesNothingAndReportsNothing(t *testing.T) {
	nw := &fakeNW{}
	r := nwRig(t, nw)
	r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{}})
	r.nwWG.Wait()
	if len(nw.converged) != 0 || nw.read || len(nw.refused) != 0 {
		t.Fatalf("an older gateway's desired-config moved the lifecycle: %+v", nw)
	}
	if _, has := r.NodeFacts()["node_workloads"]; has {
		t.Fatal("node_workloads reported with nothing read")
	}
}

// An explicit empty list is the gateway saying "none here": that is read, and
// it releases the rows of workloads that are no longer listed.
func TestAnEmptyListIsReadNotMissing(t *testing.T) {
	nw := &fakeNW{}
	r := nwRig(t, nw)
	r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: json.RawMessage(`[]`)}})
	r.nwWG.Wait()
	if !nw.read || nw.retained == nil || len(nw.retained) != 0 || len(nw.converged) != 0 {
		t.Fatalf("lifecycle = %+v", nw)
	}
}

func TestUnreadableDesiredTouchesNothing(t *testing.T) {
	nw := &fakeNW{}
	r := nwRig(t, nw)
	r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: json.RawMessage(`{"not":"a list"}`)}})
	r.nwWG.Wait()
	if len(nw.converged) != 0 || nw.read || nw.retained != nil {
		t.Fatalf("an unreadable fragment moved the lifecycle: %+v", nw)
	}
}

// ---- orphans (i300 F5b): the reconciler's half --------------------------------

// A desired-config that read and parsed sweeps for orphans with the keys it
// lists, an explicit empty list included. The sweep is the lifecycle's; this
// pins that the reconciler asks for it, with the right keep set.
func TestASuccessfulReadSweepsForOrphansWithTheListedKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  json.RawMessage
		keep int
	}{"listed rows": {fixture(t), 2}, "explicit empty list": {json.RawMessage(`[]`), 0}} {
		t.Run(name, func(t *testing.T) {
			nw := &fakeNW{}
			r := nwRig(t, nw)
			r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: tc.raw}})
			r.nwWG.Wait()
			if len(nw.swept) != 1 || len(nw.swept[0]) != tc.keep {
				t.Fatalf("sweeps = %v, want one with %d keys", nw.swept, tc.keep)
			}
		})
	}
}

// A read that failed, a body that is not desired-config, a fragment that does
// not parse, and a row whose name cannot be read all say nothing about what is
// wanted: none of them may sweep (the i495 rule).
func TestAFailedOrUnparseableReadSweepsNothing(t *testing.T) {
	t.Run("the fetch fails", func(t *testing.T) {
		for name, h := range map[string]http.HandlerFunc{
			"HTTP 500":      func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) },
			"not JSON":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
			"cut off reply": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"node_workloads":[`)) },
		} {
			t.Run(name, func(t *testing.T) {
				srv := httptest.NewServer(h)
				defer srv.Close()
				nw := &fakeNW{}
				r := &Reconciler{cfg: &config.Config{NodeID: "node-a", ControllerURL: srv.URL}, client: srv.Client(), nodeWL: nw}
				r.Once(context.Background())
				r.nwWG.Wait()
				if len(nw.swept) != 0 || len(nw.converged) != 0 || nw.read {
					t.Fatalf("a failed read moved the lifecycle: %+v", nw)
				}
			})
		}
	})
	for name, raw := range map[string]json.RawMessage{
		"a fragment that is not a list": json.RawMessage(`{"not":"a list"}`),
		"a row with no name":            json.RawMessage(`[{"addon":"rhaddon"}]`),
	} {
		t.Run(name, func(t *testing.T) {
			nw := &fakeNW{}
			r := nwRig(t, nw)
			r.convergeNodeWorkloads(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: raw}})
			r.nwWG.Wait()
			if len(nw.swept) != 0 {
				t.Fatalf("an untrustworthy list swept for orphans: %v", nw.swept)
			}
		})
	}
}

// A converge still in flight for a workload is not started a second time.
func TestAWorkloadInFlightIsNotConvergedTwice(t *testing.T) {
	block, release := make(chan struct{}), make(chan struct{})
	nw := &blockingNW{fakeNW: &fakeNW{}, block: block, release: release}
	r := &Reconciler{cfg: &config.Config{NodeID: "node-a"}, nodeWL: nw}
	tk := &tick{desired: &desiredConfig{NodeWorkloads: fixture(t)}}
	r.convergeNodeWorkloads(context.Background(), tk)
	<-block // worker is converging
	r.convergeNodeWorkloads(context.Background(), tk)
	close(release)
	r.nwWG.Wait()
	nw.mu.Lock()
	defer nw.mu.Unlock()
	n := 0
	for _, c := range nw.converged {
		if c == "rhaddon/worker:provisioned" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("worker converged %d times while the first was in flight: %v", n, nw.converged)
	}
}

type blockingNW struct {
	*fakeNW
	block, release chan struct{}
	once           sync.Once
}

func (b *blockingNW) Converge(ctx context.Context, e nodewl.Entry) {
	if e.Name == "worker" {
		b.once.Do(func() { close(b.block) })
		<-b.release
	}
	b.fakeNW.Converge(ctx, e)
}

// ---- the heartbeat's keys ---------------------------------------------------

func TestNodeFactsCarryPolicyFactsAndRows(t *testing.T) {
	nw := &fakeNW{rows: []dockerpkg.Row{{Addon: "rhaddon", Name: "worker", State: "provisioned", DoorPort: 8443}}}
	r := nwRig(t, nw)
	r.facts = &nodepolicy.Facts{Mode: nodepolicy.ModeAuto, ControllerHost: true}
	got := r.NodeFacts()
	if got["addon_workloads_policy"] != "auto" || got["controller_host"] != true {
		t.Fatalf("facts = %v", got)
	}
	if rows, _ := got["node_workloads"].([]dockerpkg.Row); len(rows) != 1 {
		t.Fatalf("node_workloads = %v", got["node_workloads"])
	}
	nw.rows = nil // unknown: omitted
	if _, has := r.NodeFacts()["node_workloads"]; has {
		t.Fatal("unknown rows were reported")
	}
}

// ---- the actuator's view ------------------------------------------------------

func desiredServer(t *testing.T, mutate func(rows []map[string]any)) *Reconciler {
	t.Helper()
	var rows []map[string]any
	if err := json.Unmarshal(fixture(t), &rows); err != nil {
		t.Fatal(err)
	}
	mutate(rows)
	raw, _ := json.Marshal(rows)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"node_workloads": json.RawMessage(raw)})
	}))
	t.Cleanup(srv.Close)
	return &Reconciler{cfg: &config.Config{NodeID: "node-a", ControllerURL: srv.URL}, client: srv.Client(), nodeWL: &fakeNW{managed: true}}
}

func TestActuatorStartReadsDesiredFreshAndRequiresRunning(t *testing.T) {
	r := desiredServer(t, func(rows []map[string]any) {})
	mc := r.NodeWorkloadControl()
	nw := r.nodeWL.(*fakeNW)

	// echo is running in desired-config: started.
	if st, err := mc.Start(context.Background(), "rhaddon", "echo"); err != nil || st.State != nodewl.StateRunning {
		t.Fatalf("start echo = %+v, %v", st, err)
	}
	if len(nw.started) != 1 || nw.started[0].Name != "echo" {
		t.Fatalf("started = %v", nw.started)
	}
	// worker is only provisioned: the agent starts nothing the gateway has not asked for.
	_, err := mc.Start(context.Background(), "rhaddon", "worker")
	var me *dockerpkg.ManagedError
	if !errors.As(err, &me) || me.HTTP != 409 || me.Code != "not_running_in_desired" {
		t.Fatalf("start worker err = %v", err)
	}
	if len(nw.started) != 1 {
		t.Fatalf("a workload desired provisioned was started: %v", nw.started)
	}
	// Unknown workloads are 404.
	if _, err := mc.Start(context.Background(), "rhaddon", "nope"); !errors.As(err, &me) || me.HTTP != 404 {
		t.Fatalf("unknown workload: %v", err)
	}
}

func TestActuatorStopFollowsTheReleaseOrder(t *testing.T) {
	r := desiredServer(t, func(rows []map[string]any) {})
	mc := r.NodeWorkloadControl()
	nw := r.nodeWL.(*fakeNW)
	var me *dockerpkg.ManagedError

	// echo is still running in desired-config: release it first.
	if _, err := mc.Stop(context.Background(), "rhaddon", "echo"); !errors.As(err, &me) || me.Code != "still_running_in_desired" || me.HTTP != 409 {
		t.Fatalf("stop of a desired-running workload: %v", err)
	}
	if len(nw.stopped) != 0 {
		t.Fatalf("a workload desired running was stopped: %v", nw.stopped)
	}
	// worker is provisioned: stop drains.
	if _, err := mc.Stop(context.Background(), "rhaddon", "worker"); err != nil {
		t.Fatal(err)
	}
	if len(nw.stopped) != 1 {
		t.Fatalf("stopped = %v", nw.stopped)
	}
	// A drain that did not finish is a 409 drain_timeout.
	nw.stopErr = errors.Join(errors.New("x"), dockerpkg.ErrDrainIncomplete)
	if _, err := mc.Stop(context.Background(), "rhaddon", "worker"); !errors.As(err, &me) || me.Code != nodewl.ReasonDrainTimeout || me.HTTP != 409 {
		t.Fatalf("incomplete drain: %v", err)
	}
	// The node's refusal is a 409 with its reason.
	nw.startErr = &nodewl.Error{Code: nodewl.ReasonConsentNone}
	if _, err := mc.Start(context.Background(), "rhaddon", "echo"); !errors.As(err, &me) || me.Code != nodewl.ReasonConsentNone || me.HTTP != 409 {
		t.Fatalf("refused start: %v", err)
	}
}

func TestNoLifecycleMeansNoControl(t *testing.T) {
	if mc := (&Reconciler{}).NodeWorkloadControl(); mc != nil {
		t.Fatalf("a reconciler with no lifecycle offers control: %v", mc)
	}
}
