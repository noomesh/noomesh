// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

func harnessRefusal() string {
	for _, r := range refusals.List() {
		if r.Scope == "backend_start" && r.Target == harnessRefusalTarget {
			return r.Reason
		}
	}
	return ""
}

// placed = running: a stopped-but-installed harness is
// started; a running one is left alone and any earlier refusal cleared.
func TestHarnessPlacementStartsTheService(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Stopped}
	r := &Reconciler{harness: f}
	refusals.Record("backend_start", harnessRefusalTarget, "stale")

	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
	if f.Cur != hostsvc.Running || len(f.Calls) != 1 || f.Calls[0] != "start" {
		t.Fatalf("expected one start, got calls=%v state=%s", f.Calls, f.Cur)
	}
	if harnessRefusal() != "" {
		t.Fatalf("a successful start must clear the refusal, got %q", harnessRefusal())
	}
	// Idempotent: a second tick starts nothing.
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
	if len(f.Calls) != 1 {
		t.Fatalf("a running harness must not be started again: %v", f.Calls)
	}
}

// An absent unit is never started, and the refusal says WHERE the agent
// looked — never "run noo upgrade --nodes". On host6 the
// harness was installed, in the system launchd domain, while the agent
// looked in the user's LaunchAgents; the old hint would have sent the
// operator round the same loop and changed nothing.
func TestHarnessAbsentIsARefusalNotAStart(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Absent}
	r := &Reconciler{harness: f}
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
	if len(f.Calls) != 0 {
		t.Fatalf("must not call the service when the unit is absent: %v", f.Calls)
	}
	got := harnessRefusal()
	if !strings.Contains(got, "where this agent looks") {
		t.Fatalf("refusal must say the unit is absent where this agent looks, got %q", got)
	}
	if strings.Contains(got, "upgrade") {
		t.Fatalf("refusal carries a ready-made wrong explanation (upgrade does not fix a path mismatch): %q", got)
	}
}

// A start this node cannot perform must produce a refusal that tells the
// operator WHICH thing to fix. There are three distinct causes and they
// need three distinct instructions: the helper is down, the helper is too
// old, or the node refused the request. Before the design's lifecycle
// moved off sudo this was one case ("the sudoers grant"); the grant could
// not work under NoNewPrivileges and is gone, so a refusal naming it would
// now send an operator to a file that no longer exists.
func TestHarnessStartFailuresEachNameTheirOwnCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string // a phrase only THIS cause produces
	}{
		{"helper down", hostsvc.ErrNoHostd, "noo-hostd"},
		{"helper too old", hostsvc.ErrOpUnsupported, "upgrade --nodes"},
		{"node refused", hostsvc.ErrNoGrant, "harness-start"},
		{"unit missing", hostsvc.ErrAbsent, "not installed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusals.Reset()
			t.Cleanup(refusals.Reset)
			f := &hostsvc.Fake{Cur: hostsvc.Stopped, Fail: map[string]error{"start": tc.err}}
			r := &Reconciler{harness: f}
			r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
			got := harnessRefusal()
			if got == "" {
				t.Fatal("no refusal recorded — the controller would see a harness that simply never started")
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("refusal must name this cause (%q), got %q", tc.want, got)
			}
		})
	}
}

// The failure that started all of this: sudo under NoNewPrivileges. The
// agent no longer calls sudo, so nothing in a refusal should send an
// operator looking for a sudoers file.
func TestNoHarnessRefusalSendsTheOperatorToSudoers(t *testing.T) {
	for _, err := range []error{
		hostsvc.ErrNoHostd, hostsvc.ErrOpUnsupported, hostsvc.ErrNoGrant, hostsvc.ErrAbsent,
	} {
		refusals.Reset()
		f := &hostsvc.Fake{Cur: hostsvc.Stopped, Fail: map[string]error{"start": err}}
		r := &Reconciler{harness: f}
		r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
		if got := harnessRefusal(); strings.Contains(got, "sudoers.d") {
			t.Fatalf("refusal points at a file noo-apply now deletes: %q", got)
		}
		refusals.Reset()
	}
}

// A withdrawn placement stops a running harness, and does nothing to one
// that is not running.
func TestHarnessStoppedPlacementStopsOnlyARunningService(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Running}
	r := &Reconciler{harness: f}
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "stopped"}, nil)
	if f.Cur != hostsvc.Stopped || len(f.Calls) != 1 || f.Calls[0] != "stop" {
		t.Fatalf("expected one stop, got calls=%v state=%s", f.Calls, f.Cur)
	}
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "stopped"}, nil)
	if len(f.Calls) != 1 {
		t.Fatalf("a stopped harness must not be stopped again: %v", f.Calls)
	}
}

// PINNED: a foreign harness kind is checked
// against the backend it would talk to, and refused until its runner
// ships — both loudly, at placement time.
func TestHarnessKindCompatibility(t *testing.T) {
	if err := harnessKindCompatible("noo", "llamacpp"); err != nil {
		t.Fatal(err)
	}
	if err := harnessKindCompatible("claude-code", "ollama"); err != nil {
		t.Fatal(err)
	}
	// The loopback translator lets claude-code use every chat backend.
	if err := harnessKindCompatible("claude-code", "llamacpp"); err != nil {
		t.Fatal(err)
	}
	if err := harnessKindCompatible("claude-code", "tei"); err == nil {
		t.Fatal("tei is not a chat backend; claude-code must be refused on it")
	}
	if err := harnessKindCompatible("copilot", "vllm"); err != nil {
		t.Fatal(err)
	}
	if err := harnessKindCompatible("hermes", "ollama"); err == nil {
		t.Fatal("unknown kinds must be refused")
	}
	// A compatible foreign kind is refused until its runner ships; the
	// refusal is recorded at placement time and nothing is started.
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Stopped}
	r := &Reconciler{harness: f, runnerInstalled: func(string) bool { return true }, cliInstalled: func(string) bool { return false }}
	chat := []placement{{Backend: "ollama", Model: "gemma", DesiredState: "running"}}
	h := placement{Backend: "harness", Model: "auto", Role: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": "claude-code"}}
	r.convergeHarness(context.Background(), h, chat)
	if len(f.Calls) != 0 || !strings.Contains(harnessRefusal(), "command is not installed on this node") {
		t.Fatalf("a compatible foreign kind must be refused until its CLI is installed: calls=%v refusal=%q", f.Calls, harnessRefusal())
	}
	// An incompatible kind names the backends that would do.
	h.Env["NOO_HARNESS_KIND"] = "claude-code"
	r.convergeHarness(context.Background(), h, []placement{{Backend: "tei", Model: "m", DesiredState: "running"}})
	if len(f.Calls) != 0 || !strings.Contains(harnessRefusal(), "cannot use a tei backend") {
		t.Fatalf("incompatible kind: calls=%v refusal=%q", f.Calls, harnessRefusal())
	}
	// The native kind starts.
	h.Env["NOO_HARNESS_KIND"] = "noo"
	r.convergeHarness(context.Background(), h, chat)
	if f.Cur != hostsvc.Running || harnessRefusal() != "" {
		t.Fatalf("noo kind must start and clear the refusal: state=%s refusal=%q", f.Cur, harnessRefusal())
	}
}

// A start that SUCCEEDS and then dies must not read as a healthy harness.
//
// On host3 (2026-09-19, first live roll of the hostd lifecycle) the agent
// started the harness every five minutes, recorded nothing, and the
// controller saw a harness that was never running and never refused. The
// unit is Type=simple with Restart=always, RestartSec=30 and the start
// limit disabled, so `systemctl start` returns 0 the moment systemd forks
// and `is-active` cycles forever afterwards — which is why detection is the
// restart COUNTER and not any point-in-time state check.
func TestACrashLoopIsRefusedRatherThanRestartedForever(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Stopped}
	f.SetStartDies("result=exit-code exit_status=127")
	r := &Reconciler{harness: f}
	p := placement{Backend: "harness", DesiredState: "running"}

	// Tick 1: nothing to compare against — remember, do not judge.
	f.NRestarts = 4
	r.convergeHarness(context.Background(), p, nil)
	if got := harnessRefusal(); got != "" {
		t.Fatalf("first observation must not refuse, got %q", got)
	}

	// Tick 2: the counter climbed — a loop, named with systemd's words.
	f.NRestarts = 6
	r.convergeHarness(context.Background(), p, nil)
	got := harnessRefusal()
	if got == "" {
		t.Fatal("a climbing restart counter must be refused, got nothing")
	}
	for _, want := range []string{"keeps exiting", "exit_status=127"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal must contain %q, got %q", want, got)
		}
	}

	// Tick 3: steady and up — the loop stopped, so the refusal clears.
	f.Cur = hostsvc.Running
	r.convergeHarness(context.Background(), p, nil)
	if got := harnessRefusal(); got != "" {
		t.Errorf("a steady harness must clear the refusal, got %q", got)
	}
}

// A healthy harness is not refused, and a platform with no restart counter
// (darwin) is not refused either — absent is not zero.
func TestNoCounterAndNoClimbAreNotRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		fake *hostsvc.Fake
	}{
		{"steady counter", &hostsvc.Fake{Cur: hostsvc.Running, NRestarts: 9}},
		{"no counter (darwin)", &hostsvc.Fake{Cur: hostsvc.Running, NoCounter: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusals.Reset()
			t.Cleanup(refusals.Reset)
			r := &Reconciler{harness: tc.fake}
			p := placement{Backend: "harness", DesiredState: "running"}
			for i := 0; i < 3; i++ {
				r.convergeHarness(context.Background(), p, nil)
			}
			if got := harnessRefusal(); got != "" {
				t.Errorf("must not refuse, got %q", got)
			}
		})
	}
}

// `noo cluster unplace <node> harness` deletes the row rather than
// setting it to stopped, and the converge loop only walks placements that
// exist — so the service kept running with nothing left to converge or
// report it. Removing the placement has to mean the thing stops.
func TestAnUnplacedHarnessIsStopped(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Running}
	r := &Reconciler{harness: f}
	refusals.Record("backend_start", harnessRefusalTarget, "from when it was placed")

	// A desired state that still has OTHER placements — this is an
	// unplace, not an empty answer from the controller.
	r.reapUnplacedHarness(context.Background(), []placement{
		{Backend: "vllm", DesiredState: "running"},
	})

	if f.Cur != hostsvc.Stopped {
		t.Fatalf("an unplaced harness must be stopped, state=%s calls=%v", f.Cur, f.Calls)
	}
	if harnessRefusal() != "" {
		t.Fatalf("the refusal belongs to a placement that is gone, got %q", harnessRefusal())
	}
}

// Still placed: the reaper must keep its hands off. convergeHarness owns
// a harness that has a placement, in either desired state.
func TestAPlacedHarnessIsNotReaped(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	for _, state := range []string{"running", "stopped"} {
		f := &hostsvc.Fake{Cur: hostsvc.Running}
		r := &Reconciler{harness: f}
		r.reapUnplacedHarness(context.Background(), []placement{
			{Backend: "vllm", DesiredState: "running"},
			{Backend: "harness", DesiredState: state},
		})
		if len(f.Calls) != 0 || f.Cur != hostsvc.Running {
			t.Fatalf("desired_state=%s: the reaper touched a placed harness: %v", state, f.Calls)
		}
	}
}

// A harness that is not running needs no stopping, and asking the
// privileged helper on every tick for a service that is already gone is
// noise the operator would have to read past.
func TestReapingAnAlreadyStoppedHarnessIsSilent(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	for _, cur := range []hostsvc.State{hostsvc.Stopped, hostsvc.Absent} {
		f := &hostsvc.Fake{Cur: cur}
		r := &Reconciler{harness: f}
		r.reapUnplacedHarness(context.Background(), nil)
		if len(f.Calls) != 0 {
			t.Fatalf("state=%s: expected no calls, got %v", cur, f.Calls)
		}
	}
}

// A stop this node cannot perform must leave the refusal standing. The
// reaper clears the refusal row on its way out, and clearing it after a
// FAILED stop would report "gone" for a harness still running — the
// silent-success shape, one layer along.
func TestAFailedReapKeepsItsRefusal(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{
		Cur:  hostsvc.Running,
		Fail: map[string]error{"stop": hostsvc.ErrNoHostd},
	}
	r := &Reconciler{harness: f}
	r.reapUnplacedHarness(context.Background(), nil)
	if f.Cur != hostsvc.Running {
		t.Fatalf("the fake must model a stop that did not happen, state=%s", f.Cur)
	}
	if harnessRefusal() == "" {
		t.Fatal("a harness still running after a failed stop must be refused, not cleared")
	}
}

// A kind the gateway accepts must have decided its vendor telemetry
// switches (docs/security/telemetry.md, "Agent harnesses"). A new entry in
// harnessKinds with no row in harnessTelemetryOff fails here.
func TestEveryHarnessKindDeclaresItsTelemetrySwitches(t *testing.T) {
	for kind := range harnessKinds {
		if _, ok := HarnessTelemetryEnv(kind); !ok {
			t.Errorf("harness kind %q has no entry in harnessTelemetryOff", kind)
		}
	}
	for kind := range harnessTelemetryOff {
		if _, ok := harnessKinds[kind]; !ok {
			t.Errorf("harnessTelemetryOff names %q, which is not a harness kind", kind)
		}
	}
	if _, ok := HarnessTelemetryEnv("no-such-kind"); ok {
		t.Error("an unknown kind must not read as 'nothing to switch off'")
	}
}

func TestForeignHarnessKindsCarryTheirVendorSwitches(t *testing.T) {
	claude, _ := HarnessTelemetryEnv("claude-code")
	for k, want := range map[string]string{
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":             "1",
		"DISABLE_TELEMETRY":                                    "1",
		"DISABLE_ERROR_REPORTING":                              "1",
		"DISABLE_FEEDBACK_COMMAND":                             "1",
		"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
	} {
		if claude[k] != want {
			t.Errorf("claude-code: %s = %q, want %q", k, claude[k], want)
		}
	}
	cp, _ := HarnessTelemetryEnv("copilot")
	if cp["COPILOT_OFFLINE"] != "true" {
		t.Errorf("copilot: COPILOT_OFFLINE = %q, want true", cp["COPILOT_OFFLINE"])
	}
	// The returned map is a copy: a caller's edit must not change the table.
	claude["DISABLE_TELEMETRY"] = "0"
	again, _ := HarnessTelemetryEnv("claude-code")
	if again["DISABLE_TELEMETRY"] != "1" {
		t.Error("HarnessTelemetryEnv handed out the table itself")
	}
}

// The node agent's embedded table is a COPY of config/harness-kinds.json
// (go:embed cannot reach outside the module). Equal after JSON
// normalisation, or a kind added to the shipped file is one the gateway
// accepts and this agent calls unknown.
func TestHarnessKindsTableMatchesTheShippedFile(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "harness-kinds.json"))
	if err != nil {
		t.Fatalf("config/harness-kinds.json: %v", err)
	}
	var a, b any
	if err := json.Unmarshal(shipped, &a); err != nil {
		t.Fatalf("config/harness-kinds.json: %v", err)
	}
	if err := json.Unmarshal(harnessKindsJSON, &b); err != nil {
		t.Fatalf("embedded harness_kinds.json: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("node-agent-go/internal/reconcile/harness_kinds.json differs from config/harness-kinds.json: copy the shipped file over the embedded one")
	}
	if len(harnessKindTable) == 0 || harnessKindTable[0].Kind != "noo" || harnessKindTable[0].Runner == nil {
		t.Fatalf("`noo` must be the first kind and have a runner: %+v", harnessKindTable)
	}
	if got := knownHarnessKinds(); got != "noo, claude-code, copilot, codex" {
		t.Fatalf("known kinds = %q", got)
	}
}

// Refusal by absence: a kind is refused because its runner does not ship
// (runner null in the table), is not installed on this node, or because the
// vendor CLI it launches is not on PATH, never because its name is not `noo`.
func TestHarnessKindIsRefusedForAnAbsentRunnerOrCLI(t *testing.T) {
	chat := []placement{{Backend: "ollama", Model: "gemma", DesiredState: "running"}}
	h := func(kind string) placement {
		return placement{Backend: "harness", Model: "auto", Role: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": kind}}
	}
	present := func(string) bool { return true }
	var asked []string
	absent := func(r string) bool { asked = append(asked, r); return false }
	var askedCLI []string
	cliAbsent := func(c string) bool { askedCLI = append(askedCLI, c); return false }

	if got := harnessKindRefusal(h("noo"), chat, present, cliAbsent); got != "" {
		t.Fatalf("noo with its runner installed must not be refused (it needs no CLI): %q", got)
	}
	if len(askedCLI) != 0 {
		t.Fatalf("noo has no vendor CLI to look for: %v", askedCLI)
	}
	got := harnessKindRefusal(h("noo"), chat, absent, present)
	if got != `harness kind "noo": its runner "noo-gateway" is not installed on this node` {
		t.Fatalf("noo without its runner: %q", got)
	}
	if len(asked) != 1 || asked[0] != "noo-gateway" {
		t.Fatalf("the check must ask for the table's runner, asked %v", asked)
	}
	// Every runner is noo-gateway; a foreign kind with the runner but not
	// its CLI is refused for the CLI, after the runner check.
	asked, askedCLI = nil, nil
	if got := harnessKindRefusal(h("copilot"), chat, present, cliAbsent); got != `harness kind "copilot": its runner is present but the "copilot" command is not installed on this node` {
		t.Fatalf("copilot without its CLI: %q", got)
	}
	if len(askedCLI) != 1 || askedCLI[0] != "copilot" {
		t.Fatalf("asked for CLI %v", askedCLI)
	}
	// The runner is checked FIRST: no runner means the CLI is not asked for.
	askedCLI = nil
	if got := harnessKindRefusal(h("copilot"), chat, absent, cliAbsent); got != `harness kind "copilot": its runner "noo-gateway" is not installed on this node` {
		t.Fatalf("copilot without runner: %q", got)
	}
	if len(askedCLI) != 0 {
		t.Fatalf("CLI looked for before the runner: %v", askedCLI)
	}
	if got := harnessKindRefusal(h("copilot"), chat, present, present); got != "" {
		t.Fatalf("copilot with runner and CLI: %q", got)
	}
	// A kind whose runner does not ship (none in the table now) is refused
	// before anything looks at the disk. Synthetic kind for the code path.
	saved := harnessKindTable
	harnessKindTable = append(append([]harnessKind(nil), saved...), harnessKind{Kind: "synthetic", Wires: []string{"ollama"}, TelemetryOff: map[string]string{}})
	harnessKinds["synthetic"] = []string{"ollama"}
	restore := func() { harnessKindTable = saved; delete(harnessKinds, "synthetic") }
	t.Cleanup(restore)
	asked, askedCLI = nil, nil
	if got := harnessKindRefusal(h("synthetic"), chat, absent, cliAbsent); got != `harness kind "synthetic": its runner is not shipped yet` {
		t.Fatalf("synthetic: %q", got)
	}
	if len(asked) != 0 || len(askedCLI) != 0 {
		t.Fatalf("a kind with no runner must not be looked for on disk: %v %v", asked, askedCLI)
	}
	restore()
	// A kind whose wire no node backend serves (none in the table now:
	// codex's Responses API is translated since i83 E2) is refused from the
	// table rather than listing nothing. Synthetic kind for the code path.
	harnessKindTable = append(append([]harnessKind(nil), saved...), harnessKind{Kind: "wireless", Wire: "a future API", Wires: []string{}, TelemetryOff: map[string]string{}})
	harnessKinds["wireless"] = []string{}
	t.Cleanup(func() { harnessKindTable = saved; delete(harnessKinds, "wireless") })
	got = harnessKindRefusal(h("wireless"), chat, present, present)
	if !strings.Contains(got, `no chat backend on this node can serve harness kind "wireless" (it needs a future API)`) ||
		!strings.Contains(got, "its wire is not served by any backend yet") {
		t.Fatalf("wireless: %q", got)
	}
	harnessKindTable = saved
	delete(harnessKinds, "wireless")
	// codex runs on every node backend through the loopback translator; with
	// its runner and CLI present it is not refused, without its CLI it is.
	if got := harnessKindRefusal(h("codex"), chat, present, present); got != "" {
		t.Fatalf("codex with runner and CLI: %q", got)
	}
	if got := harnessKindRefusal(h("codex"), chat, present, cliAbsent); got != `harness kind "codex": its runner is present but the "codex" command is not installed on this node` {
		t.Fatalf("codex without its CLI: %q", got)
	}
	// An unknown kind lists the table's kinds.
	if got := harnessKindRefusal(h("hermes"), nil, present, present); got != `unknown harness kind "hermes" (known: noo, claude-code, copilot, codex)` {
		t.Fatalf("unknown kind: %q", got)
	}
	// Telemetry: codex has an entry, empty until its switches are declared.
	if env, ok := HarnessTelemetryEnv("codex"); !ok || len(env) != 0 {
		t.Fatalf("codex telemetry entry: %v %v", env, ok)
	}
}

// Every kind declares a lane (an object, maybe empty); the returned map is
// a copy; and a unit that merges lane env must do so AFTER placement env, as
// for telemetry_off. The merge order is pinned here on the helper the
// launcher uses: a placement value for a lane key is overwritten.
func TestHarnessLaneEnvIsDeclaredCopiedAndWinsOverPlacement(t *testing.T) {
	for _, k := range harnessKindTable {
		if k.Lane == nil {
			t.Errorf("kind %q has no lane object", k.Kind)
		}
		if _, ok := HarnessLaneEnv(k.Kind); !ok {
			t.Errorf("HarnessLaneEnv(%q) not ok", k.Kind)
		}
	}
	if _, ok := HarnessLaneEnv("no-such-kind"); ok {
		t.Error("an unknown kind must not read as 'no lane'")
	}
	// Foreign kinds: the lane is merged after the placement env.
	for _, k := range harnessKindTable {
		if k.Kind == "noo" {
			continue
		}
		lane, _ := HarnessLaneEnv(k.Kind)
		tel, _ := HarnessTelemetryEnv(k.Kind)
		env := map[string]string{"NOO_HARNESS_KIND": k.Kind}
		for key := range lane {
			env[key] = "placement-says-otherwise"
		}
		for key := range tel {
			env[key] = "placement-says-otherwise"
		}
		for key, v := range lane {
			env[key] = v
		}
		for key, v := range tel {
			env[key] = v
		}
		for key, v := range lane {
			if env[key] != v {
				t.Errorf("%s: lane %s = %q, want %q", k.Kind, key, env[key], v)
			}
		}
	}
	// Copy, not the table itself.
	synth := map[string]string{"X": "1"}
	harnessLane["synthetic-lane"] = synth
	t.Cleanup(func() { delete(harnessLane, "synthetic-lane") })
	got, _ := HarnessLaneEnv("synthetic-lane")
	got["X"] = "2"
	if synth["X"] != "1" {
		t.Error("HarnessLaneEnv handed out the table itself")
	}
}

// Through the reconciler: a missing runner is a refusal and nothing starts.
func TestAMissingRunnerIsARefusalNotAStart(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Stopped}
	r := &Reconciler{harness: f, runnerInstalled: func(string) bool { return false }}
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
	if len(f.Calls) != 0 || !strings.Contains(harnessRefusal(), `its runner "noo-gateway" is not installed on this node`) {
		t.Fatalf("calls=%v refusal=%q", f.Calls, harnessRefusal())
	}
	r.runnerInstalled = func(string) bool { return true }
	r.convergeHarness(context.Background(), placement{Backend: "harness", DesiredState: "running"}, nil)
	if f.Cur != hostsvc.Running || harnessRefusal() != "" {
		t.Fatalf("installed runner must start and clear the refusal: state=%s refusal=%q", f.Cur, harnessRefusal())
	}
}

func TestHarnessKindDecisionIsRestartOnlyOnAChange(t *testing.T) {
	for _, c := range []struct{ started, desired, want string }{
		{"noo", "noo", "keep"},
		{"noo", "copilot", "restart"},
		{"copilot", "noo", "restart"},
		{"claude-code", "claude-code", "keep"},
		{"", "copilot", "keep"}, // unknown started kind: adopt, never bounce
	} {
		if got := harnessKindDecision(c.started, c.desired); got != c.want {
			t.Errorf("(%q,%q) = %s, want %s", c.started, c.desired, got, c.want)
		}
	}
}

// A running harness whose placement kind changes is restarted once, through
// the service's restart, and the new kind is recorded.
func TestAKindChangeRestartsTheRunningHarness(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &hostsvc.Fake{Cur: hostsvc.Stopped}
	r := &Reconciler{harness: f, runnerInstalled: func(string) bool { return true }, cliInstalled: func(string) bool { return true }}
	chat := []placement{{Backend: "ollama", Model: "gemma", DesiredState: "running"}}
	h := func(kind string) placement {
		return placement{Backend: "harness", Model: "auto", Role: "harness", DesiredState: "running", Env: map[string]string{"NOO_HARNESS_KIND": kind}}
	}
	ctx := context.Background()
	r.convergeHarness(ctx, h("noo"), chat)
	if f.Cur != hostsvc.Running || r.harnessStartedKind != "noo" {
		t.Fatalf("start: state=%s started=%q", f.Cur, r.harnessStartedKind)
	}
	r.convergeHarness(ctx, h("noo"), chat)
	if len(f.Calls) != 1 {
		t.Fatalf("same kind must not restart: %v", f.Calls)
	}
	r.convergeHarness(ctx, h("copilot"), chat)
	if len(f.Calls) != 2 || f.Calls[1] != "restart" || r.harnessStartedKind != "copilot" {
		t.Fatalf("kind change: calls=%v started=%q", f.Calls, r.harnessStartedKind)
	}
	r.convergeHarness(ctx, h("copilot"), chat)
	if len(f.Calls) != 2 {
		t.Fatalf("restarted again for nothing: %v", f.Calls)
	}
}

func TestHarnessPlacementViewHidesSecretsAndReportsUnplaced(t *testing.T) {
	r := &Reconciler{}
	if _, _, _, placed := r.HarnessPlacementView(); placed {
		t.Fatal("no placement recorded must read as unplaced")
	}
	r.recordHarnessPlacement([]placement{
		{Backend: "ollama", DesiredState: "running"},
		{Backend: "harness", DesiredState: "running", Env: map[string]string{
			"NOO_HARNESS_KIND": "copilot", "NOO_HARNESS_MAX_TURNS": "4",
			"SOME_API_KEY": "x", "NOO_CLUSTER_SECRET": "x", "BEARER_TOKEN": "x",
		}},
	})
	kind, env, ds, placed := r.HarnessPlacementView()
	if !placed || kind != "copilot" || ds != "running" {
		t.Fatalf("view: %q %q %v", kind, ds, placed)
	}
	if len(env) != 2 || env["NOO_HARNESS_KIND"] != "copilot" || env["NOO_HARNESS_MAX_TURNS"] != "4" {
		t.Fatalf("env must keep only non-secret keys: %v", env)
	}
	r.recordHarnessPlacement([]placement{{Backend: "ollama", DesiredState: "running"}})
	if _, _, _, placed := r.HarnessPlacementView(); placed {
		t.Fatal("a removed placement must read as unplaced")
	}
	r.recordHarnessPlacement([]placement{{Backend: "harness", DesiredState: "running"}})
	if kind, _, _, _ := r.HarnessPlacementView(); kind != "noo" {
		t.Fatalf("no kind in env must read as noo, got %q", kind)
	}
}
