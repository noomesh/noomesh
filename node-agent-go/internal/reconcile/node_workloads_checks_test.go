// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Single-check tests of the reconciler's half of the node workloads (see
// node_gate_wiring_test.go and node_workloads_test.go).

// A workload is converged again once its last converge has ended.
func TestAWorkloadIsConvergedAgainOnceTheLastConvergeEnded(t *testing.T) {
	nw := &fakeNW{}
	r := nwRig(t, nw)
	e := nodewl.Entry{Addon: "rhaddon", Name: "worker", State: nodewl.StateRunning}
	r.goConverge(context.Background(), e)
	r.nwWG.Wait()
	r.goConverge(context.Background(), e)
	r.nwWG.Wait()
	if len(nw.converged) != 2 {
		t.Fatalf("converged %v; a finished converge must not block the next pass", nw.converged)
	}
}

// ---- the actuator reads desired-config afresh and says why it cannot ----------

func desiredReturning(t *testing.T, status int, body string) *Reconciler {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Reconciler{cfg: &config.Config{NodeID: "node-a", ControllerURL: srv.URL}, client: srv.Client(), nodeWL: &fakeNW{managed: true}}
}

func managedErrOf(t *testing.T, err error) *dockerpkg.ManagedError {
	t.Helper()
	var me *dockerpkg.ManagedError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want a *ManagedError", err)
	}
	return me
}

func TestTheActuatorSaysWhyDesiredConfigCannotAnswer(t *testing.T) {
	var rows []map[string]any
	if err := json.Unmarshal(fixture(t), &rows); err != nil {
		t.Fatal(err)
	}
	rows[1]["state"] = "bogus" // echo
	badRow, _ := json.Marshal(map[string]any{"node_workloads": rows})
	good, _ := json.Marshal(map[string]any{"node_workloads": json.RawMessage(fixture(t))})

	for name, tc := range map[string]struct {
		status   int
		body     string
		addon    string
		workload string
		http     int
		code     string
	}{
		"desired-config cannot be read": {500, `nope`, "rhaddon", "echo", 502, "desired_unreadable"},
		"an older gateway, no key":      {200, `{}`, "rhaddon", "echo", 404, "not_desired"},
		"an empty list":                 {200, `{"node_workloads":[]}`, "rhaddon", "echo", 404, "not_desired"},
		"not a list":                    {200, `{"node_workloads":{"not":"a list"}}`, "rhaddon", "echo", 409, nodewl.ReasonDesiredInvalid},
		"the row is malformed":          {200, string(badRow), "rhaddon", "echo", 409, nodewl.ReasonDesiredInvalid},
		"another add-on, same name":     {200, string(good), "otheraddon", "echo", 404, "not_desired"},
		"another name, same add-on":     {200, string(good), "rhaddon", "nope", 404, "not_desired"},
	} {
		t.Run(name, func(t *testing.T) {
			r := desiredReturning(t, tc.status, tc.body)
			for verb, f := range map[string]func() error{
				"start": func() error {
					_, err := r.NodeWorkloadControl().Start(context.Background(), tc.addon, tc.workload)
					return err
				},
				"stop": func() error {
					_, err := r.NodeWorkloadControl().Stop(context.Background(), tc.addon, tc.workload)
					return err
				},
			} {
				me := managedErrOf(t, f())
				if me.HTTP != tc.http || me.Code != tc.code {
					t.Errorf("%s: %d %s (%s), want %d %s", verb, me.HTTP, me.Code, me.Detail, tc.http, tc.code)
				}
			}
			nw := r.nodeWL.(*fakeNW)
			if len(nw.started)+len(nw.stopped) != 0 {
				t.Errorf("the lifecycle was driven although desired-config gave no entry: %v %v", nw.started, nw.stopped)
			}
		})
	}
}

// What the lifecycle fails with reaches the gateway as the lifecycle's own
// status and code, or a reason, or sets_pending, or a 502 with the verb's name.
func TestTheActuatorMapsEachLifecycleFailure(t *testing.T) {
	r := desiredServer(t, func(rows []map[string]any) {})
	mc := r.NodeWorkloadControl()
	nw := r.nodeWL.(*fakeNW)
	for name, tc := range map[string]struct {
		err  error
		http int
		code string
	}{
		"its own refusal, untouched": {&dockerpkg.ManagedError{HTTP: 429, Code: "busy", Detail: "later"}, 429, "busy"},
		"a node reason":              {&nodewl.Error{Code: nodewl.ReasonNvidiaRuntimeMissing, Detail: "x"}, 409, nodewl.ReasonNvidiaRuntimeMissing},
		"sets still arriving":        {dockerpkg.ErrSetsPending, 409, "sets_pending"},
		"a drain that did not end":   {dockerpkg.ErrDrainIncomplete, 409, nodewl.ReasonDrainTimeout},
		"anything else":              {errors.New("docker said no"), 502, ""}, // start_failed / stop_failed
	} {
		t.Run(name, func(t *testing.T) {
			nw.startErr, nw.stopErr = tc.err, tc.err
			_, errStart := mc.Start(context.Background(), "rhaddon", "echo")
			_, errStop := mc.Stop(context.Background(), "rhaddon", "worker")
			for verb, err := range map[string]error{"start": errStart, "stop": errStop} {
				me := managedErrOf(t, err)
				want := tc.code
				if want == "" {
					want = verb + "_failed"
				}
				if me.HTTP != tc.http || me.Code != want {
					t.Errorf("%s: %d %s (%s), want %d %s", verb, me.HTTP, me.Code, me.Detail, tc.http, want)
				}
			}
			if tc.code == "busy" && managedErrOf(t, errStart) != tc.err {
				t.Errorf("the lifecycle's own refusal was rewrapped")
			}
		})
	}
}

// ---- the facts the agent builds from its config ------------------------------------

func TestTheNodeFactsAreBuiltFromTheConfig(t *testing.T) {
	dir := t.TempDir()
	if err := nodepolicy.NewApprovals(dir).Add("rhaddon", gateDigest); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AddonWorkloadsPolicy: "approve", SelfNode: true, StateDir: dir}
	nw, facts := newNodeWorkloads(cfg, nil, nil)
	if nw != nil {
		t.Fatalf("a lifecycle without a docker client: %v", nw)
	}
	if facts.Mode != nodepolicy.ModeApprove || !facts.ControllerHost {
		t.Fatalf("facts mode %q controller_host %v, want approve and true (the config's)", facts.Mode, facts.ControllerHost)
	}
	if facts.Approvals == nil {
		t.Fatal("the facts keep no approvals")
	}
	if list, err := facts.Approvals.List(); err != nil || len(list) != 1 || list[0].Addon != "rhaddon" {
		t.Fatalf("approvals = %v, %v; they live under the config's StateDir", list, err)
	}
	if facts.ComputeCaps == nil || facts.DataRootFreeGB == nil {
		t.Fatalf("a probe is not wired: caps=%v disk=%v", facts.ComputeCaps != nil, facts.DataRootFreeGB != nil)
	}
	if facts.NvidiaRuntime != nil {
		t.Fatal("an nvidia runtime probe without docker")
	}
	// Defaults: nothing set is approve (nothing approved, so nothing runs),
	// and not the controller's host.
	_, facts = newNodeWorkloads(&config.Config{StateDir: dir}, nil, nil)
	if facts.Mode != nodepolicy.ModeApprove || facts.ControllerHost {
		t.Fatalf("defaults = %q %v", facts.Mode, facts.ControllerHost)
	}
}

// A policy value that is not a mode is none, and the agent says so: the owner
// is told their setting was not taken.
func TestAPolicyThatIsNotAModeIsSaidSoInTheLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	newNodeWorkloads(&config.Config{AddonWorkloadsPolicy: "none", AddonWorkloadsPolicyAsked: "yes please", StateDir: t.TempDir()}, nil, nil)
	if out := buf.String(); !strings.Contains(out, "NOO_ADDON_WORKLOADS") || !strings.Contains(out, "yes please") {
		t.Fatalf("log = %q", out)
	}
	buf.Reset()
	newNodeWorkloads(&config.Config{AddonWorkloadsPolicy: "auto", StateDir: t.TempDir()}, nil, nil)
	if strings.Contains(buf.String(), "NOO_ADDON_WORKLOADS") {
		t.Fatalf("a good policy was reported as wrong: %q", buf.String())
	}
}
