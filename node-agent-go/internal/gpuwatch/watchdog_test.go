// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuwatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

type fakeDocker struct {
	containers []docker.GPUContainer
	listErr    error
	// probe results keyed by container ID
	probeCode  map[string]int
	probeErr   map[string]error
	restarts   []string
	probes     []string
	restartErr error
}

func (f *fakeDocker) GPUContainers(context.Context) ([]docker.GPUContainer, error) {
	return f.containers, f.listErr
}
func (f *fakeDocker) ExecProbe(_ context.Context, id string, _ []string) (int, error) {
	f.probes = append(f.probes, id)
	if err := f.probeErr[id]; err != nil {
		return 127, err
	}
	return f.probeCode[id], nil
}
func (f *fakeDocker) RestartContainer(_ context.Context, id string) error {
	if f.restartErr != nil {
		return f.restartErr
	}
	f.restarts = append(f.restarts, id)
	return nil
}

func newTestWatchdog(f *fakeDocker, hostOK bool) *Watchdog {
	w := New(f, func() bool { return hostOK })
	// deterministic clock, advanced manually
	base := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return base }
	return w
}

func ctr(name string) docker.GPUContainer {
	return docker.GPUContainer{ID: "id-" + name, Name: name, Managed: true}
}

// A GPU-requesting container the cluster does not own (CI's buildx builder,
// found live on host8) is reported for visibility and NEVER probed,
// restarted, or faulted — the watchdog only polices the cluster's own.
func TestUnmanagedContainerIsObservedNeverTouched(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{
			{ID: "id-buildx", Name: "buildx_buildkit_noo-builder0", Managed: false},
		},
		probeCode: map[string]int{"id-buildx": 9},
	}
	w := newTestWatchdog(f, true)
	for i := 0; i < 3; i++ {
		w.Check(context.Background())
	}
	st := w.State()
	if len(st.Containers) != 1 || st.Containers[0].Status != statusUnmanaged {
		t.Fatalf("expected unmanaged verdict, got %+v", st.Containers)
	}
	if len(f.probes) != 0 || len(f.restarts) != 0 || len(st.Faults) != 0 {
		t.Fatal("unmanaged containers must never be probed, restarted, or faulted")
	}
}

func TestHealthyContainerIsOK(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-ollama")},
		probeCode:  map[string]int{"id-noo-ollama": 0},
	}
	w := newTestWatchdog(f, true)
	w.Check(context.Background())

	st := w.State()
	if st.HostGPU != "ok" || len(st.Containers) != 1 || st.Containers[0].Status != statusOK {
		t.Fatalf("expected ok verdict, got %+v", st)
	}
	if len(st.Faults) != 0 || len(f.restarts) != 0 {
		t.Fatalf("healthy container must not fault or restart: %+v", st)
	}
}

func TestHostGPUDownSkipsContainerChecks(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-ollama")},
		probeCode:  map[string]int{"id-noo-ollama": 1},
	}
	w := newTestWatchdog(f, false)
	w.Check(context.Background())

	st := w.State()
	if st.HostGPU != "unavailable" {
		t.Fatalf("expected host_gpu unavailable, got %q", st.HostGPU)
	}
	// Restarting containers cannot heal a wedged bus — gpu_health owns it.
	if len(st.Containers) != 0 || len(f.restarts) != 0 || len(st.Faults) != 0 {
		t.Fatalf("host-down cycle must not probe, restart, or fault: %+v", st)
	}
}

func TestTransientFailureIsSuspectNotRestart(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-llamacpp")},
		probeCode:  map[string]int{"id-noo-llamacpp": 9},
	}
	w := newTestWatchdog(f, true)
	w.Check(context.Background())

	st := w.State()
	if st.Containers[0].Status != statusSuspect {
		t.Fatalf("first failure must be suspect, got %q", st.Containers[0].Status)
	}
	if len(f.restarts) != 0 {
		t.Fatal("must not restart on a single failed probe")
	}
	// Recovery clears the streak: an ok probe then a new failure is
	// suspect again, not an instant restart.
	f.probeCode["id-noo-llamacpp"] = 0
	w.Check(context.Background())
	f.probeCode["id-noo-llamacpp"] = 9
	w.Check(context.Background())
	if got := w.State().Containers[0].Status; got != statusSuspect {
		t.Fatalf("failure after recovery must be suspect, got %q", got)
	}
	if len(f.restarts) != 0 {
		t.Fatal("must not have restarted across recovery")
	}
}

func TestConfirmedFailureRestartsOnceThenFaults(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-llamacpp")},
		probeCode:  map[string]int{"id-noo-llamacpp": 9},
	}
	w := newTestWatchdog(f, true)

	w.Check(context.Background()) // suspect
	w.Check(context.Background()) // confirmed -> restart
	if len(f.restarts) != 1 || f.restarts[0] != "id-noo-llamacpp" {
		t.Fatalf("expected one restart, got %v", f.restarts)
	}
	st := w.State()
	if st.Containers[0].Status != statusRestarted || st.Restarts != 1 {
		t.Fatalf("expected restarted verdict, got %+v", st)
	}
	if len(st.Faults) != 0 {
		t.Fatal("restart cycle itself is not yet a fault")
	}

	// Still broken after the restart: suspect again, then FAULT (cooldown
	// blocks a second restart) — this is what the controller alerts on.
	w.Check(context.Background()) // suspect
	w.Check(context.Background()) // would restart, but cooldown -> fault
	st = w.State()
	if st.Containers[0].Status != statusFault {
		t.Fatalf("expected fault after failed remediation, got %+v", st.Containers[0])
	}
	if len(st.Faults) != 1 {
		t.Fatalf("fault must be listed for the controller, got %v", st.Faults)
	}
	if len(f.restarts) != 1 {
		t.Fatalf("cooldown must prevent a restart loop, got %v", f.restarts)
	}
}

func TestProbeImpossibleIsUnverifiableNeverFault(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-vllm")},
		probeErr:   map[string]error{"id-noo-vllm": errors.New("probe binary unavailable in container (exit 127)")},
	}
	w := newTestWatchdog(f, true)
	for i := 0; i < 4; i++ {
		w.Check(context.Background())
	}
	st := w.State()
	if st.Containers[0].Status != statusUnverifiable {
		t.Fatalf("expected unverifiable, got %+v", st.Containers[0])
	}
	if len(st.Faults) != 0 || len(f.restarts) != 0 {
		t.Fatal("an unverifiable probe must never fault or restart")
	}
}

func TestFailedRestartIsImmediateFault(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-llamacpp")},
		probeCode:  map[string]int{"id-noo-llamacpp": 9},
		restartErr: errors.New("docker daemon says no"),
	}
	w := newTestWatchdog(f, true)
	w.Check(context.Background()) // suspect
	w.Check(context.Background()) // restart attempt fails -> fault
	st := w.State()
	if st.Containers[0].Status != statusFault || len(st.Faults) != 1 {
		t.Fatalf("failed restart must fault, got %+v", st)
	}
}

func TestDepartedContainerStateIsDropped(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-llamacpp")},
		probeCode:  map[string]int{"id-noo-llamacpp": 9},
	}
	w := newTestWatchdog(f, true)
	w.Check(context.Background()) // suspect (streak 1)

	f.containers = nil
	w.Check(context.Background())
	if len(w.failStreak) != 0 {
		t.Fatalf("bookkeeping for departed containers must be dropped: %v", w.failStreak)
	}

	// The container comes back (recreated): it starts from a clean slate.
	f.containers = []docker.GPUContainer{ctr("noo-llamacpp")}
	w.Check(context.Background())
	if got := w.State().Containers[0].Status; got != statusSuspect {
		t.Fatalf("recreated container must start at suspect, got %q", got)
	}
}

// The live case this guard exists for.
//
// `nvidia-smi -L` inside the vLLM container exited non-zero on two consecutive
// cycles, so the watchdog restarted it — while the container was serving chat
// normally. Verified by hand afterwards: the probe passed both inside the
// container and on the host, each listing the card. The restart cost minutes of
// 9.6 GB weight reload during which every request failed, and surfaced to the
// operator as "backend unreachable", which points at the wrong subsystem.
func TestAServingBackendIsNotRestartedOnAFailedGPUProbe(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-vllm")},
		probeCode:  map[string]int{"id-noo-vllm": 9},
	}
	w := newTestWatchdog(f, true)
	w.SetServingProbe(func(context.Context, string) bool { return true })

	for i := 0; i < 3; i++ {
		w.Check(context.Background())
	}

	if len(f.restarts) != 0 {
		t.Fatalf("a backend that answers must not be restarted: %v", f.restarts)
	}
	st := w.State()
	if st.Containers[0].Status != statusServing {
		t.Fatalf("expected the serving verdict, got %+v", st.Containers[0])
	}
	// Still reported, because a GPU probe that keeps failing is worth seeing.
	if st.Containers[0].Detail == "" {
		t.Error("the verdict must say why it did not restart")
	}
}

// The other half: the subsystem still does its job. A container that can
// neither see a GPU nor answer a request is exactly what it is for.
func TestADeadBackendWithNoGPUIsStillRestarted(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-vllm")},
		probeCode:  map[string]int{"id-noo-vllm": 9},
	}
	w := newTestWatchdog(f, true)
	w.SetServingProbe(func(context.Context, string) bool { return false })

	w.Check(context.Background()) // streak 1: suspect
	w.Check(context.Background()) // streak 2: restart

	if len(f.restarts) != 1 {
		t.Fatalf("expected exactly one restart, got %v", f.restarts)
	}
	if w.State().Containers[0].Status != statusRestarted {
		t.Fatalf("expected the restarted verdict, got %+v", w.State().Containers[0])
	}
}

// No probe wired (an older agent build, or a backend the agent cannot address)
// must not become a licence to never restart: absence of evidence is not
// evidence of health.
func TestWithoutAServingProbeTheOldBehaviourStands(t *testing.T) {
	f := &fakeDocker{
		containers: []docker.GPUContainer{ctr("noo-vllm")},
		probeCode:  map[string]int{"id-noo-vllm": 9},
	}
	w := newTestWatchdog(f, true)

	w.Check(context.Background())
	w.Check(context.Background())

	if len(f.restarts) != 1 {
		t.Fatalf("with no serving probe the watchdog must still restart: %v", f.restarts)
	}
}
