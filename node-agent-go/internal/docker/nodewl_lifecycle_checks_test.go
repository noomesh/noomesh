// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Checks of the F5b lifecycle that the broader tests could not see on their
// own: a neighbouring layer gave the same answer, or the fake could not
// express the failure. Each test names the check it pins; the mutant branch
// proves it by switching that one check off.

// chaosProv is the fake daemon with failures a test can aim: an inspect that
// fails (by name and count), and a remove that fails.
type chaosProv struct {
	*fakeProv
	cm          sync.Mutex
	inspects    int
	inspectFail func(name string, n int) error // n: inspects so far, this one included
	removeErr   error
	createErr   error
	stopErr     error
}

func (c *chaosProv) CreateContainer(ctx context.Context, s createSpec) error {
	if c.createErr != nil {
		return c.createErr
	}
	return c.fakeProv.CreateContainer(ctx, s)
}

func (c *chaosProv) StopContainer(ctx context.Context, name string, grace int) error {
	if c.stopErr != nil {
		return c.stopErr
	}
	return c.fakeProv.StopContainer(ctx, name, grace)
}

func (c *chaosProv) InspectContainer(ctx context.Context, name string) (*ctrInfo, error) {
	c.cm.Lock()
	c.inspects++
	n, fail := c.inspects, c.inspectFail
	c.cm.Unlock()
	if fail != nil {
		if err := fail(name, n); err != nil {
			return nil, err
		}
	}
	return c.fakeProv.InspectContainer(ctx, name)
}

func (c *chaosProv) RemoveContainer(ctx context.Context, name string) error {
	if c.removeErr != nil {
		return c.removeErr
	}
	return c.fakeProv.RemoveContainer(ctx, name)
}

func (c *chaosProv) inspectCount() int {
	c.cm.Lock()
	defer c.cm.Unlock()
	return c.inspects
}

func (h *lifeHarness) chaos() *chaosProv {
	c := &chaosProv{fakeProv: h.api}
	h.p.api = c
	return c
}

var errDaemon = errors.New("docker daemon unreachable")

func (h *lifeHarness) noMutation(what string) {
	h.t.Helper()
	calls := h.api.callList()
	for _, c := range calls {
		if changesTheNode(c) {
			h.t.Fatalf("%s, but the node was changed: %v", what, calls)
		}
	}
}

func changesTheNode(call string) bool {
	for _, p := range []string{"create:", "rm:", "net:", "rmnet:", "stop:", "start:", "door:"} {
		if strings.HasPrefix(call, p) {
			return true
		}
	}
	return false
}

// ---- identity ---------------------------------------------------------------

// ours(): a container is the agent's only by its noo.managed-by=agent label.
// One that merely sits on the workload's name is never drained, stopped,
// removed or reported as the workload's, whatever the desired state is.
func TestAContainerThatIsNotOursIsNeverDrainedStoppedOrRemoved(t *testing.T) {
	for _, state := range []string{nodewl.StateRunning, nodewl.StateProvisioned, nodewl.StateAbsent} {
		t.Run(state, func(t *testing.T) {
			h := newLife(t)
			h.door.status("POST", drainPostP, 200)
			h.door.status("GET", doneP, 200)
			foreign := &ctrInfo{ID: "f1", Labels: map[string]string{"app": "someone-elses"}, Running: true, Status: "running"}
			h.api.mu.Lock()
			h.api.ctrs[wName] = foreign
			h.api.mu.Unlock()

			e := h.running()
			if state == nodewl.StateProvisioned {
				e = h.provisioned()
			}
			if state == nodewl.StateAbsent {
				e = h.provisioned()
				e.State = nodewl.StateAbsent
			}
			h.p.Converge(context.Background(), e)
			h.p.Wait()
			h.settled()

			for _, c := range h.api.callList() {
				if c == "stop:"+wName || c == "rm:"+wName || c == "start:"+wName || c == "create:"+wName {
					t.Fatalf("%s: a container the agent did not create was changed: %v", state, h.api.callList())
				}
			}
			if countOf(h.api.callList(), "door:") != 0 {
				t.Fatalf("%s: a foreign container was sent a drain: %v", state, h.api.callList())
			}
			if c := h.api.ctr(wName); c == nil || !c.Running || c.ID != "f1" {
				t.Fatalf("%s: the foreign container is now %+v", state, c)
			}
		})
	}
}

func TestStatusAndManagedSeeOnlyAgentContainers(t *testing.T) {
	h := newLife(t)
	h.api.mu.Lock()
	h.api.ctrs[wName] = &ctrInfo{ID: "f1", Labels: map[string]string{}, Running: true, Status: "running"}
	h.api.mu.Unlock()
	if ok, err := h.p.IsManaged(context.Background(), "rhaddon", "worker"); err != nil || ok {
		t.Fatalf("IsManaged(foreign) = %v, %v", ok, err)
	}
	if st, err := h.p.ManagedStatus(context.Background(), "rhaddon", "worker"); err != nil || st.Running || st.State != nodewl.StateAbsent {
		t.Fatalf("ManagedStatus(foreign) = %+v, %v; a foreign container is not our running worker", st, err)
	}
	// And an absent one is a known state, not an empty one.
	h2 := newLife(t)
	if st, err := h2.p.ManagedStatus(context.Background(), "rhaddon", "worker"); err != nil || st.State != nodewl.StateAbsent || st.Running {
		t.Fatalf("ManagedStatus(absent) = %+v, %v", st, err)
	}
	h2.p.Converge(context.Background(), h2.provisioned())
	h2.p.lc.mu.Lock()
	h2.p.lc.lives["rhaddon/worker"].state = "" // a row that has no state yet reads as absent
	h2.p.lc.mu.Unlock()
	if st, _ := h2.p.ManagedStatus(context.Background(), "rhaddon", "worker"); st.State != nodewl.StateAbsent {
		t.Fatalf("a row with no state = %q, want absent", st.State)
	}
}

// ---- adoption: the state an agent restart finds ----------------------------

func TestAdoptGivesAWorkloadTheStateItsContainersAreIn(t *testing.T) {
	ours := map[string]string{LabelManagedBy: ManagedByAgent}
	for name, tc := range map[string]struct {
		ctr  *ctrInfo
		want string
	}{
		"no container":            {nil, nodewl.StateAbsent},
		"ours, running":           {&ctrInfo{ID: "1", Labels: ours, Running: true, Status: "running"}, nodewl.StateRunning},
		"ours, created":           {&ctrInfo{ID: "1", Labels: ours, Status: "created"}, nodewl.StateProvisioned},
		"ours, exited":            {&ctrInfo{ID: "1", Labels: ours, Status: "exited"}, nodewl.StateProvisioned},
		"not ours, running":       {&ctrInfo{ID: "1", Labels: map[string]string{}, Running: true, Status: "running"}, nodewl.StateAbsent},
		"managed by someone else": {&ctrInfo{ID: "1", Labels: map[string]string{LabelManagedBy: "other"}, Running: true, Status: "running"}, nodewl.StateAbsent},
	} {
		t.Run(name, func(t *testing.T) {
			h := newLife(t)
			if tc.ctr != nil {
				h.api.mu.Lock()
				h.api.ctrs[wName] = tc.ctr
				h.api.mu.Unlock()
			}
			e := h.provisioned()
			if err := h.p.adopt(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if cur, _ := h.p.read("rhaddon", "worker"); cur.state != tc.want {
				t.Fatalf("adopted as %q, want %q", cur.state, tc.want)
			}
		})
	}
}

// A workload whose state is known is not inspected again by adopt.
func TestAdoptDoesNotAskTheDaemonAgainOnceTheStateIsKnown(t *testing.T) {
	h := newLife(t)
	cp := h.chaos()
	e := h.provisioned()
	if err := h.p.adopt(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	first := cp.inspectCount()
	cp.inspectFail = func(string, int) error { return errDaemon }
	if err := h.p.adopt(context.Background(), e); err != nil {
		t.Fatalf("adopt of a known workload asked the daemon: %v", err)
	}
	if cp.inspectCount() != first {
		t.Fatalf("inspects %d -> %d", first, cp.inspectCount())
	}
}

// ---- a daemon that cannot answer is "cannot tell", never "absent" -----------

func TestAnInspectThatFailsChangesNothing(t *testing.T) {
	t.Run("on adopt, the first look", func(t *testing.T) {
		h := newLife(t)
		cp := h.chaos()
		cp.inspectFail = func(_ string, n int) error {
			if n == 1 {
				return errDaemon
			}
			return nil
		}
		h.p.Converge(context.Background(), h.running())
		h.p.Wait()
		h.noMutation("the daemon could not be read")
	})
	t.Run("converging to absent", func(t *testing.T) {
		h := newLife(t)
		h.p.Converge(context.Background(), h.provisioned())
		cp := h.chaos()
		cp.inspectFail = func(string, int) error { return errDaemon }
		before := len(h.api.callList())
		e := h.provisioned()
		e.State = nodewl.StateAbsent
		h.p.Converge(context.Background(), e)
		h.p.Wait()
		if got := h.api.callList(); len(got) != before {
			t.Fatalf("removed on a daemon that could not say what runs: %v", got[before:])
		}
		if r := h.row(); r.State != nodewl.StateProvisioned {
			t.Fatalf("row = %+v; an unread node is not an absent workload", r)
		}
	})
	t.Run("converging to provisioned while the worker runs", func(t *testing.T) {
		h := newLife(t)
		h.door.status("GET", "/health/ready", 200)
		h.door.status("POST", drainPostP, 200)
		h.door.status("GET", doneP, 200)
		h.p.Converge(context.Background(), h.running())
		eventually(t, "ready", func() bool { return h.row().Ready })
		cp := h.chaos()
		cp.inspectFail = func(string, int) error { return errDaemon }
		before := len(h.api.callList())
		h.p.Converge(context.Background(), h.provisioned())
		h.p.Wait()
		for _, c := range h.api.callList()[before:] {
			if changesTheNode(c) {
				t.Fatalf("released a worker on a daemon that could not be read: %v", h.api.callList()[before:])
			}
		}
	})
}

func TestARemovalThatFailsIsNotReportedAsDone(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		h := newLife(t)
		h.p.Converge(context.Background(), h.provisioned())
		cp := h.chaos()
		cp.removeErr = errDaemon
		e := h.provisioned()
		e.State = nodewl.StateAbsent
		h.p.Converge(context.Background(), e)
		h.p.Wait()
		if r := h.row(); r.State == nodewl.StateAbsent {
			t.Fatalf("row = %+v: the containers are still there", r)
		}
	})
	t.Run("a crashed worker that must be recreated", func(t *testing.T) {
		h := newLife(t)
		h.p.Converge(context.Background(), h.provisioned())
		h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = false, "exited" })
		cp := h.chaos()
		cp.removeErr = errDaemon
		creates := countOf(h.api.callList(), "create:")
		h.p.Converge(context.Background(), h.provisioned())
		h.p.Wait()
		if got := countOf(h.api.callList(), "create:"); got != creates {
			t.Fatalf("recreated over a worker that could not be removed (%d -> %d creates)", creates, got)
		}
	})
}

// ---- reasons ----------------------------------------------------------------

// A verdict with no reason code is not a row reason, and a refusal that is not
// the node's own (a set still arriving, a worker that must drain first) never
// replaces the reason a row already has.
func TestOnlyAReasonCodeChangesTheReasonOfARow(t *testing.T) {
	h := newLife(t)
	e := h.provisioned()
	set := func(reason string) { h.p.with("rhaddon", "worker", func(ls *lifeState) { ls.reason = reason }) }
	reason := func() string { cur, _ := h.p.read("rhaddon", "worker"); return cur.reason }

	set(nodewl.ReasonCrashed)
	h.p.refused(e, errors.New("plain failure, no code"))
	if reason() != nodewl.ReasonCrashed {
		t.Fatalf("a failure with no code replaced the reason: %q", reason())
	}
	h.p.refused(e, ErrSetsPending)
	h.p.refused(e, ErrWorkerRunning)
	if reason() != nodewl.ReasonCrashed {
		t.Fatalf("%v replaced the reason: %q", ErrWorkerRunning, reason())
	}
	h.p.refused(e, &nodewl.Error{Code: nodewl.ReasonConsentNone, Detail: "x"})
	if reason() != nodewl.ReasonConsentNone {
		t.Fatalf("a coded refusal did not become the reason: %q", reason())
	}

	set(nodewl.ReasonCrashed)
	h.p.Refuse("rhaddon", "worker", errors.New("plain failure, no code"))
	if reason() != nodewl.ReasonCrashed {
		t.Fatalf("Refuse with no code replaced the reason: %q", reason())
	}
	h.p.Refuse("rhaddon", "worker", &nodewl.Error{Code: nodewl.ReasonDesiredInvalid, Detail: "x"})
	if reason() != nodewl.ReasonDesiredInvalid {
		t.Fatalf("Refuse with a code: %q", reason())
	}
}

// ---- the door ---------------------------------------------------------------

// A door with no address cannot be asked anything, whatever a door client
// would answer to an empty address.
func TestADoorWithNoAddressIsNeitherReadyNorDrained(t *testing.T) {
	h := newLife(t)
	var mu sync.Mutex
	asked := 0
	h.p.lc.doorCall = func(_ context.Context, addr, _, _, _ string) (int, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		return 200, nil // anything, from anywhere
	}
	e := mustRunning(h)
	h.api.setCtr(dName, func(c *ctrInfo) { c.IPs = map[string]string{} })
	h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = true, "running" })

	if h.p.probeReady(context.Background(), e) {
		t.Error("a door with no address was probed ready")
	}
	if err := h.p.drain(context.Background(), e); !errors.Is(err, ErrDrainIncomplete) {
		t.Errorf("drain = %v; a door that cannot be reached must leave the drain incomplete", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 0 {
		t.Errorf("%d calls went out with no door address", asked)
	}
}

// A call that errors is not ready, even when it carries a 200.
func TestAProbeThatErrorsIsNotReady(t *testing.T) {
	h := newLife(t)
	h.p.lc.doorCall = func(context.Context, string, string, string, string) (int, error) {
		return 200, errors.New("tls: handshake failure")
	}
	if h.p.probeReady(context.Background(), mustRunning(h)) {
		t.Fatal("a failed call counted as ready")
	}
}

// ---- orphans: memory first, labels when memory is gone ----------------------

// The drain config the agent last saw wins over the labels: a worker created
// by an older agent may carry none.
func TestAnOrphanIsDrainedFromMemoryWhenItsLabelsCarryNoDrainConfig(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	h.api.setCtr(wName, func(c *ctrInfo) {
		delete(c.Labels, LabelDrainPath)
		delete(c.Labels, LabelDrainDone)
		delete(c.Labels, LabelDrainTimeout)
	})
	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.p.Wait()
	calls := h.api.callList()
	if indexOf(calls, "door:POST "+drainPostP) < 0 || indexOf(calls, "stop:"+wName) < 0 || h.api.ctr(wName) != nil {
		t.Fatalf("an orphan the agent remembers was not drained and removed: %v", calls)
	}
}

// After a restart the drain window is the labelled one: the orphan is polled
// for its drain.timeout_secs, not given up on at once.
func TestAnOrphanAfterARestartIsPolledForItsLabelledTimeout(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.forgetEverything()
	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.settled()
	if n := countOf(h.api.callList(), "door:GET "+doneP); n < 5 {
		t.Fatalf("done_path was polled %d times; a 1 s window at 1 ms polls takes many more", n)
	}
	if countOf(h.api.callList(), "stop:") != 0 {
		t.Fatalf("an undrained orphan was stopped: %v", h.api.callList())
	}
}
