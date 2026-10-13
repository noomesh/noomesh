// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// workerEngine builds an Engine pointed at a temp "live binary" via the
// NOO_AGENT_BIN/NOO_AGENT_UNIT env overrides, so no test can ever restart the
// developer's real agent (the same discipline that put Capture on the Runner
// interface).
func workerEngine(t *testing.T) (*Engine, *fakeRunner, string) {
	t.Helper()
	dir := t.TempDir()
	live := filepath.Join(dir, "noo-node-agent")
	t.Setenv("NOO_AGENT_BIN", live)
	t.Setenv("NOO_AGENT_UNIT", "noo-node-agent-test")
	r := &fakeRunner{rc: map[string]int{}}
	e := &Engine{
		Mode:           ModeWorker,
		Spool:          t.TempDir(),
		Runner:         r,
		HealthTimeout:  50 * time.Millisecond,
		HealthInterval: 5 * time.Millisecond,
		Logf:           t.Logf,
	}
	return e, r, live
}

func shaOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func stage(t *testing.T, live string, content []byte) {
	t.Helper()
	if err := os.WriteFile(live+".next", content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestModeSelectsOpTable(t *testing.T) {
	if _, ok := LookupOpFor(ModeWorker, "swap-agent"); !ok {
		t.Fatal("worker table must serve swap-agent")
	}
	if _, ok := LookupOpFor(ModeWorker, "recreate"); ok {
		t.Fatal("worker table must NOT serve controller compose ops")
	}
	if _, ok := LookupOpFor(ModeController, "swap-agent"); ok {
		t.Fatal("controller table must NOT serve swap-agent")
	}
	// Unknown/empty mode falls back to controller, never to an empty table.
	if _, ok := LookupOpFor("", "restart"); !ok {
		t.Fatal("empty mode must behave as controller (pre-step-4 installs)")
	}
	// The heartbeat advertises this list and producers gate on it, so the
	// set is a contract, not an implementation detail.
	ops := SupportedOpsFor(ModeWorker)
	// harness-start / harness-stop: the agent cannot sudo —
	// NoNewPrivileges makes setuid inert — so the harness lifecycle is a
	// named op here instead of a sudoers grant.
	// journal-follow (fleet log shipping): the agent cannot read the
	// journal, so the read-only follower lives here too.
	// disk-reclaim: the controller's bounded ladder, queued by this node's
	// agent when its own disk crosses the watermark (the controller's
	// ladder cannot reach a worker's disk).
	want := []string{"disk-reclaim", "fetch-bundle", "harness-start", "harness-stop", "journal-follow", "restart-agent", "swap-agent", "unit-logs"}
	if len(ops) != len(want) {
		t.Fatalf("worker heartbeat ops = %v, want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("worker heartbeat ops = %v, want %v", ops, want)
		}
	}
}

// swap-agent is RETIRED. The op name is kept only to be
// refused, so an agent or gateway older than the retirement gets the reason.
// This test fails on the pre-retirement daemon, which swapped the binary and
// restarted the unit — and it must hold with NOO_HOSTD_ALLOW_UNSIGNED=1 too,
// the old escape that trusted an agent-claimed digest.
func TestSwapAgentIsRefused(t *testing.T) {
	for _, unsigned := range []string{"", "1"} {
		e, r, live := workerEngine(t)
		t.Setenv("NOO_HOSTD_ALLOW_UNSIGNED", unsigned)
		if err := os.WriteFile(live, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
		next := []byte("attacker-binary")
		stage(t, live, next)
		var logged []string
		e.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }

		op, ok := LookupOpFor(ModeWorker, "swap-agent")
		if !ok {
			t.Fatal("swap-agent must stay NAMED in the worker table so old producers get the refusal")
		}
		rc, msg := op.Run(context.Background(), e, "t1",
			&Command{Op: "swap-agent", Service: "noo-node-agent", RequestedBy: "old-agent", Args: []string{"sha256=" + shaOf(next)}})
		if rc == 0 {
			t.Fatalf("NOO_HOSTD_ALLOW_UNSIGNED=%q: swap-agent must be refused, got rc=0", unsigned)
		}
		if !strings.Contains(msg, "retired") || !strings.Contains(msg, "noo cluster provision") {
			t.Fatalf("refusal must say it is retired and name the rail: %q", msg)
		}
		got, _ := os.ReadFile(live)
		if string(got) != "old" {
			t.Fatalf("live binary changed by a refused swap: %q", got)
		}
		if len(r.joined()) != 0 {
			t.Fatalf("a refused swap ran commands: %v", r.joined())
		}
		if len(logged) == 0 || !strings.Contains(strings.Join(logged, " "), "REFUSED") {
			t.Fatalf("refusal must be logged loudly: %v", logged)
		}
	}
}

func TestWorkerUnitRenders(t *testing.T) {
	body, err := render(workerUnitTmpl, unitVars{Bin: "/usr/local/bin/noo-hostd", Spool: WorkerSpoolDir, System: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"run --mode worker", "User=root", "multi-user.target", WorkerSpoolDir} {
		if !strings.Contains(body, want) {
			t.Fatalf("worker unit missing %q:\n%s", want, body)
		}
	}
}

func TestWorkerTableServesFetchBundle(t *testing.T) {
	// The poke rail's root half. If this op disappears, `push-secrets` and
	// every other stage-and-poke caller silently degrades to waiting on the
	// 60s timer — which still works, and so would hide the regression.
	if _, ok := LookupOpFor(ModeWorker, "fetch-bundle"); !ok {
		t.Fatal("worker table must serve fetch-bundle")
	}
	// Controller mode drives compose, not a node's fetch timer.
	if _, ok := LookupOpFor(ModeController, "fetch-bundle"); ok {
		t.Fatal("controller table must NOT serve fetch-bundle")
	}
}

func TestFetchBundleTakesNoCallerArguments(t *testing.T) {
	// The contract that makes the poke safe: timing comes from the
	// controller, content never does. An op that accepted a URL or a node
	// id would be taking content from the network-facing side.
	t.Setenv("NOO_CONF_DIR", t.TempDir()) // armExpectBundle must not touch the real /etc/noo
	op, ok := LookupOpFor(ModeWorker, "fetch-bundle")
	if !ok {
		t.Fatal("fetch-bundle missing")
	}
	f := &fakeRunner{}
	e := &Engine{Mode: ModeWorker, Runner: f}
	op.Run(context.Background(), e, "", &Command{
		Op:      "fetch-bundle",
		Service: "noo-node-agent",
		// A caller trying to smuggle content in:
		Args: []string{"url=https://evil.example/bundle.tar"},
	})
	for _, argv := range f.calls {
		if strings.Contains(strings.Join(argv, " "), "evil.example") {
			t.Fatalf("caller args reached the command line: %v", argv)
		}
	}
	// And it did do the one thing it is for.
	if len(f.calls) != 1 || !strings.Contains(strings.Join(f.calls[0], " "), "noo-fetch.service") {
		t.Fatalf("expected one `systemctl start noo-fetch.service`, got %v", f.calls)
	}
}

func TestFetchBundleArmsExpectBundleBeforeStarting(t *testing.T) {
	// A poked run landed on noo-fetch.sh's steady-state throttle
	// (fetch only every 3rd tick) and exited 0 without fetching — the
	// controller's wait window covered nothing. The op must re-arm the
	// marker noo-fetch.sh reads BEFORE starting the unit, in the exact
	// format prep-host seeds at enrollment.
	dir := t.TempDir()
	t.Setenv("NOO_CONF_DIR", dir)
	op, ok := LookupOpFor(ModeWorker, "fetch-bundle")
	if !ok {
		t.Fatal("fetch-bundle missing")
	}
	f := &fakeRunner{}
	e := &Engine{Mode: ModeWorker, Runner: f}
	op.Run(context.Background(), e, "", &Command{Op: "fetch-bundle", Service: "noo-node-agent"})

	path := filepath.Join(dir, "expect-bundle")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expect-bundle not written: %v", err)
	}
	if string(got) != "10\n" {
		t.Fatalf("expect-bundle = %q, want %q (fast-tick countdown, matching prep-host's format)", got, "10\n")
	}
}

// Darwin harness-start: loading and starting are different things on
// launchd, and the plist's RunAtLoad=false means bootstrap alone leaves the
// job loaded and idle. The op must reach RUNNING from every state.
func TestDarwinHarnessStartReachesRunningFromEveryState(t *testing.T) {
	installed := func() bool { return true }
	target := "system/" + HarnessLaunchdLabel

	// Not loaded: bootstrap, then start it.
	r := &fakeRunner{rc: map[string]int{"print " + target: 113}, stdout: map[string]string{}}
	calls := 0
	r.stdout["print "+target] = ""
	// After bootstrap the print must succeed and show the job idle; the
	// fake cannot change its answer over time, so emulate with a wrapper.
	seq := &sequencedRunner{inner: r, printAnswers: []printAnswer{{113, ""}, {0, "state = waiting"}}}
	rc, msg := darwinHarnessStart(context.Background(), seq, installed)
	if rc != 0 {
		t.Fatalf("not loaded → bootstrap+kickstart must succeed, got rc=%d %q", rc, msg)
	}
	calls = len(seq.inner.calls)
	joined := strings.Join(seq.inner.joined(), " | ")
	if !strings.Contains(joined, "bootstrap system "+HarnessLaunchdPlist) || !strings.Contains(joined, "kickstart "+target) {
		t.Fatalf("expected bootstrap then kickstart, got %v", seq.inner.joined())
	}
	_ = calls

	// Loaded but idle — the host6 state: no bootstrap (that is the EIO),
	// just kickstart.
	r = &fakeRunner{rc: map[string]int{}, stdout: map[string]string{"print " + target: "state = waiting"}}
	rc, msg = darwinHarnessStart(context.Background(), r, installed)
	if rc != 0 {
		t.Fatalf("loaded+idle → kickstart must succeed, got rc=%d %q", rc, msg)
	}
	joined = strings.Join(r.joined(), " | ")
	if strings.Contains(joined, "bootstrap") {
		t.Fatalf("a loaded job must not be bootstrapped again (launchd answers EIO), got %v", r.joined())
	}
	if !strings.Contains(joined, "kickstart "+target) {
		t.Fatalf("a loaded idle job must be kickstarted, got %v", r.joined())
	}

	// Loaded and running: nothing to do.
	r = &fakeRunner{rc: map[string]int{}, stdout: map[string]string{"print " + target: "state = running"}}
	if rc, _ := darwinHarnessStart(context.Background(), r, installed); rc != 0 {
		t.Fatal("running → ok")
	}
	if strings.Contains(strings.Join(r.joined(), " | "), "kickstart") {
		t.Fatalf("a running job must not be kickstarted, got %v", r.joined())
	}

	// Bootstrap genuinely failing surfaces launchd's words, named.
	r = &fakeRunner{rc: map[string]int{"print " + target: 113, "bootstrap": 5}, stdout: map[string]string{}}
	rc, msg = darwinHarnessStart(context.Background(), r, installed)
	if rc != 5 || !strings.HasPrefix(msg, "launchctl bootstrap:") {
		t.Fatalf("bootstrap failure must surface with its step named, got rc=%d %q", rc, msg)
	}

	// No plist: says where it looked.
	rc, msg = darwinHarnessStart(context.Background(), &fakeRunner{rc: map[string]int{}}, func() bool { return false })
	if rc != 1 || !strings.Contains(msg, HarnessLaunchdPlist) {
		t.Fatalf("missing plist must name the path, got rc=%d %q", rc, msg)
	}
}

type printAnswer struct {
	rc  int
	out string
}

// sequencedRunner answers successive `launchctl print` calls from a list,
// so a test can say "not loaded, then loaded" — the fake's substring maps
// cannot change their mind between calls.
type sequencedRunner struct {
	inner            *fakeRunner
	printAnswers     []printAnswer
	printCalls       int
	bootstrapAnswers []printAnswer
	bootstrapCalls   int
}

func (s *sequencedRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (int, string) {
	if name == "launchctl" && len(args) > 0 && args[0] == "bootstrap" && len(s.bootstrapAnswers) > 0 {
		s.inner.calls = append(s.inner.calls, append([]string{name}, args...))
		i := s.bootstrapCalls
		s.bootstrapCalls++
		if i >= len(s.bootstrapAnswers) {
			i = len(s.bootstrapAnswers) - 1
		}
		return s.bootstrapAnswers[i].rc, s.bootstrapAnswers[i].out
	}
	return s.inner.Run(ctx, dir, env, name, args...)
}

func (s *sequencedRunner) Capture(ctx context.Context, dir string, name string, args ...string) (int, string) {
	argv := append([]string{name}, args...)
	if name == "launchctl" && len(args) > 0 && args[0] == "print" {
		s.inner.calls = append(s.inner.calls, argv)
		i := s.printCalls
		s.printCalls++
		if i < len(s.printAnswers) {
			return s.printAnswers[i].rc, s.printAnswers[i].out
		}
		last := s.printAnswers[len(s.printAnswers)-1]
		return last.rc, last.out
	}
	return s.inner.Capture(ctx, dir, name, args...)
}

// A bootstrap that lands while launchd is still tearing the previous
// instance down fails with the SAME words as a refused plist. The op waits
// it out, boundedly, and only then believes the error.
func TestDarwinHarnessStartOutwaitsATearingDownJob(t *testing.T) {
	bootstrapRetrySleep = func() {}
	defer func() { bootstrapRetrySleep = func() { time.Sleep(time.Second) } }()
	target := "system/" + HarnessLaunchdLabel

	// Two EIOs, then it loads: the op must not have given up.
	r := &fakeRunner{rc: map[string]int{"print " + target: 113}, stdout: map[string]string{}}
	seq := &sequencedRunner{
		inner:            r,
		printAnswers:     []printAnswer{{113, ""}, {0, "state = running"}},
		bootstrapAnswers: []printAnswer{{5, "Bootstrap failed: 5: Input/output error"}, {5, "Bootstrap failed: 5: Input/output error"}, {0, ""}},
	}
	rc, msg := darwinHarnessStart(context.Background(), seq, func() bool { return true })
	if rc != 0 {
		t.Fatalf("a bootstrap that succeeds on the third try must succeed, got rc=%d %q", rc, msg)
	}
	if n := strings.Count(strings.Join(seq.inner.joined(), " | "), "bootstrap system"); n != 3 {
		t.Fatalf("expected three bootstrap attempts, got %d: %v", n, seq.inner.joined())
	}

	// EIO that never clears is reported as such, after the bound.
	r = &fakeRunner{rc: map[string]int{"print " + target: 113}, stdout: map[string]string{}}
	seq = &sequencedRunner{
		inner:            r,
		printAnswers:     []printAnswer{{113, ""}},
		bootstrapAnswers: []printAnswer{{5, "Bootstrap failed: 5: Input/output error"}},
	}
	rc, msg = darwinHarnessStart(context.Background(), seq, func() bool { return true })
	if rc != 5 || !strings.Contains(msg, "not a teardown race") {
		t.Fatalf("persistent EIO must surface after the retries, got rc=%d %q", rc, msg)
	}
	if n := strings.Count(strings.Join(r.joined(), " | "), "bootstrap system"); n != bootstrapRetries+1 {
		t.Fatalf("expected %d attempts, got %d", bootstrapRetries+1, n)
	}

	// A different bootstrap error is not retried at all.
	r = &fakeRunner{rc: map[string]int{"print " + target: 113, "bootstrap": 37}, stdout: map[string]string{}}
	rc, _ = darwinHarnessStart(context.Background(), r, func() bool { return true })
	if n := strings.Count(strings.Join(r.joined(), " | "), "bootstrap system"); rc != 37 || n != 1 {
		t.Fatalf("a non-EIO failure must not be retried, got rc=%d attempts=%d", rc, n)
	}
}

// The fetch poke picks its verb by OS: systemctl has no darwin build, and a
// Mac poke failed on `exec: "systemctl"`.
func TestFetchKickArgvByOS(t *testing.T) {
	t.Setenv("NOO_FETCH_UNIT", "")
	if got := strings.Join(fetchKickArgv("darwin"), " "); got != "launchctl kickstart system/net.noomesh.fetch" {
		t.Fatalf("darwin: %q", got)
	}
	if got := strings.Join(fetchKickArgv("linux"), " "); got != "systemctl start noo-fetch.service" {
		t.Fatalf("linux: %q", got)
	}
	t.Setenv("NOO_FETCH_UNIT", "custom.service")
	if got := strings.Join(fetchKickArgv("linux"), " "); got != "systemctl start custom.service" {
		t.Fatalf("linux override: %q", got)
	}
}

// The Mac fetcher reads expect-bundle from /Users/<--user>/noomesh, not
// /etc/noo (every poke logged "could not arm /etc/noo/expect-bundle"
// on host6). hostd derives the base from the fetch plist's --user, the same
// source the fetcher is launched with.
func TestExpectBundleDirByOS(t *testing.T) {
	t.Setenv("NOO_CONF_DIR", "/tmp/conf")
	if d, err := expectBundleDir("linux"); err != nil || d != "/tmp/conf" {
		t.Fatalf("linux: %q %v", d, err)
	}
	plist := filepath.Join(t.TempDir(), "fetch.plist")
	body := `<key>ProgramArguments</key><array>
    <string>/usr/local/bin/noo</string><string>node</string><string>fetch</string><string>--user</string><string>alice</string>
  </array>`
	if err := os.WriteFile(plist, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOO_FETCH_PLIST", plist)
	if d, err := expectBundleDir("darwin"); err != nil || d != "/Users/alice/noomesh" {
		t.Fatalf("darwin: %q %v", d, err)
	}
	for _, bad := range []string{"<string>--user</string><string>../x</string>", "<string>node</string>", "<string>--user</string><string></string>"} {
		if err := os.WriteFile(plist, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if d, err := expectBundleDir("darwin"); err == nil {
			t.Fatalf("%q should not resolve, got %q", bad, d)
		}
	}
	t.Setenv("NOO_FETCH_PLIST", filepath.Join(t.TempDir(), "missing.plist"))
	if _, err := expectBundleDir("darwin"); err == nil {
		t.Fatal("missing plist should error")
	}
}

// noo-apply accepts a newly delivered hostd only when a heartbeat written
// after the install contains the marker it greps for (scripts/noo-apply.sh,
// the hostd-binary block: `grep -q '<marker>' "$HB"`). Today that marker is
// `swap-agent`, which is why the design kept the op NAMED after retiring
// it. Every applier already on a node checks this, so a heartbeat without
// the marker makes that applier revert this binary. The test reads the
// marker out of the applier rather than hard-coding it, so it follows a
// future switch to a dedicated marker.
func TestWorkerHeartbeatCarriesTheAppliersHostdMarker(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "noo-apply.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`grep -q '([A-Za-z0-9_.-]+)' "\$HB"`).FindSubmatch(src)
	if m == nil {
		t.Fatal(`noo-apply.sh no longer probes the hostd heartbeat with grep -q '<marker>' "$HB" — this guard is reading the wrong thing; update it`)
	}
	marker := string(m[1])
	hb, err := json.Marshal(Heartbeat{Ops: SupportedOpsFor(ModeWorker), Features: FeaturesFor(ModeWorker)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hb), marker) {
		t.Fatalf("the worker heartbeat %s lacks %q — every deployed noo-apply would revert this hostd", hb, marker)
	}
	if marker == "swap-agent" {
		op, ok := LookupOpFor(ModeWorker, "swap-agent")
		if !ok || op.Run == nil {
			t.Fatal("swap-agent must stay in the worker table (refusing) while it is the applier's marker")
		}
	}
}
