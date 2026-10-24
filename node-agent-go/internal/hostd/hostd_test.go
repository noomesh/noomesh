// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRunner records argv instead of running it. The bash watcher had no such
// seam — every one of its dispatch decisions (which flags, in which order,
// whether a failed stop still runs start) was only ever exercised in
// production against a live docker daemon.
type fakeRunner struct {
	calls [][]string
	dirs  []string
	// envs records the extraEnv of each Run, parallel to calls.
	envs [][]string
	// rc maps a substring of the joined argv to the exit code to return, so a
	// test can make one specific step fail.
	rc map[string]int
	// stdout maps a substring of the joined argv to canned Capture output.
	stdout map[string]string
	// stderr maps a substring of the joined argv to the stderr a SUCCESSFUL
	// Run returns (what a script prints to fd 2 on its way to exit 0).
	stderr map[string]string
}

func (f *fakeRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) (int, string) {
	f.envs = append(f.envs, env)
	f.dirs = append(f.dirs, dir)
	argv := append([]string{name}, args...)
	f.calls = append(f.calls, argv)
	joined := strings.Join(argv, " ")
	for frag, code := range f.rc {
		if strings.Contains(joined, frag) {
			return code, "boom: " + frag
		}
	}
	for frag, text := range f.stderr {
		if strings.Contains(joined, frag) {
			return 0, text
		}
	}
	return 0, ""
}

func (f *fakeRunner) Capture(_ context.Context, dir string, name string, args ...string) (int, string) {
	f.dirs = append(f.dirs, dir)
	argv := append([]string{name}, args...)
	f.calls = append(f.calls, argv)
	joined := strings.Join(argv, " ")
	for frag, out := range f.stdout {
		if strings.Contains(joined, frag) {
			return 0, out
		}
	}
	for frag, code := range f.rc {
		if strings.Contains(joined, frag) {
			return code, ""
		}
	}
	return 0, ""
}

func (f *fakeRunner) joined() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func testEngine(t *testing.T) (*Engine, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	spool := filepath.Join(dir, ".noo-host-spool")
	if err := os.MkdirAll(spool, 0o755); err != nil {
		t.Fatal(err)
	}
	// A compose file so composeArgs resolves the same way it does in a real
	// checkout; the override is deliberately absent (the fresh-install case).
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.cluster.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{
		rc: map[string]int{},
		// df must answer, or the reclaim ladder bails at "cannot measure
		// usage" before exercising anything worth asserting on.
		stdout: map[string]string{
			"df -P": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 90 10 90% /",
		},
	}
	return &Engine{
		Root: dir, Spool: spool, GatewayPort: "8080", Runner: fr,
		HealthWake: 0, HealthTimeout: 0, HealthInterval: 0,
		Logf: func(string, ...any) {},
	}, fr
}

// write a command file the way the producers do, and drain it.
func queue(t *testing.T, e *Engine, name string, c Command) Result {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Spool, name+".cmd.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	e.ScanOnce(context.Background())
	return readResult(t, e.Spool, name)
}

func readResult(t *testing.T, spool, name string) Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(spool, name+".result.json"))
	if err != nil {
		t.Fatalf("no result file for %s: %v", name, err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("result for %s is not valid JSON: %v", name, err)
	}
	return r
}

// ── validation ─────────────────────────────────────────────────────────────

// A service name is spliced into a docker command line. If it can start with a
// dash, docker reads it as an OPTION: "--volumes" passed where a container
// name belongs is the difference between restarting a service and issuing a
// command nobody wrote.
func TestServiceNamesThatWouldBecomeDockerFlagsAreRejected(t *testing.T) {
	for _, bad := range []string{"", "-rf", "--volumes", "noo;rm -rf /", "noo postgres", strings.Repeat("a", 64)} {
		if err := ValidateService(bad); err == nil {
			t.Errorf("ValidateService(%q) accepted a name it must reject", bad)
		}
	}
	for _, ok := range []string{"gateway", "noo-postgres", "noo_app.1", "docker", "stack", "pki"} {
		if err := ValidateService(ok); err != nil {
			t.Errorf("ValidateService(%q) rejected a legitimate service: %v", ok, err)
		}
	}
}

func TestUnknownOpIsRejectedWithAResultRatherThanSilence(t *testing.T) {
	e, fr := testEngine(t)
	r := queue(t, e, "cmd1", Command{Op: "delete-everything", Service: "gateway"})
	if r.OK || r.Stderr != "invalid op" {
		t.Fatalf("expected an invalid-op result, got %+v", r)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("a rejected op must not execute anything, ran: %v", fr.joined())
	}
	// The caller polls for a result file. Rejecting without writing one is the
	// failure mode where a bad request is indistinguishable from a slow one.
	if r.Status != "done" {
		t.Errorf("rejected commands must still reach a terminal status, got %q", r.Status)
	}
}

func TestUnparseableCommandDoesNotWedgeTheSpool(t *testing.T) {
	e, _ := testEngine(t)
	if err := os.WriteFile(filepath.Join(e.Spool, "junk.cmd.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.ScanOnce(context.Background())
	if r := readResult(t, e.Spool, "junk"); r.OK {
		t.Error("invalid JSON reported success")
	}
	// The claimed file must be gone; a command that survives its own rejection
	// is retried forever.
	if _, err := os.Stat(filepath.Join(e.Spool, "junk.cmd.json.processing")); !os.IsNotExist(err) {
		t.Error("rejected command left its .processing file behind — it will never be cleaned up")
	}
}

// ── dispatch ───────────────────────────────────────────────────────────────

func TestRecreateBuildsTheComposeInvocationTheLaunchersUse(t *testing.T) {
	e, fr := testEngine(t)
	r := queue(t, e, "c", Command{Op: "recreate", Service: "gateway"})
	if !r.OK {
		t.Fatalf("recreate failed: %+v", r)
	}
	got := fr.joined()[0]
	// Through the secrets path: bash, lib-secrets.sh, load_secrets, then the
	// compose argv shell-quoted word by word.
	if fr.calls[0][0] != "bash" || !strings.Contains(got, "lib-secrets.sh") || !strings.Contains(got, "load_secrets") {
		t.Errorf("recreate did not run under withSecrets — an unset secret source makes compose remove the container and fail to create it\n  got: %s", got)
	}
	for _, want := range []string{"'docker' 'compose'", "'-f'", "docker-compose.cluster.yml",
		"'--profile' 'controller'", "'up' '-d' '--force-recreate' '--' 'gateway'"} {
		if !strings.Contains(got, want) {
			t.Errorf("recreate argv missing %q\n  got: %s", want, got)
		}
	}
	// "--" before the service is what keeps a future validation gap from
	// becoming option injection.
	if strings.Contains(got, "docker-compose.override.yml") {
		t.Error("included an override file that does not exist — compose errors out on a missing -f")
	}
}

func TestRebuildDoesNotStartAContainerWhoseStopFailed(t *testing.T) {
	e, fr := testEngine(t)
	fr.rc["docker stop"] = 1
	r := queue(t, e, "c", Command{Op: "rebuild", Service: "noo-gateway"})
	if r.OK {
		t.Fatal("rebuild reported success despite a failed stop")
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected to stop after the failed stop, ran: %v", fr.joined())
	}
}

func TestRebuildIsStopThenStartNotRestart(t *testing.T) {
	e, fr := testEngine(t)
	if r := queue(t, e, "c", Command{Op: "rebuild", Service: "noo-gateway"}); !r.OK {
		t.Fatalf("rebuild failed: %+v", r)
	}
	calls := fr.joined()
	if len(calls) != 2 || !strings.Contains(calls[0], "docker stop") || !strings.Contains(calls[1], "docker start") {
		t.Fatalf("rebuild must be stop-then-start, got: %v", calls)
	}
}

// ── stack-rebuild ──────────────────────────────────────────────────────────

// Dropping an unrecognised argument would run a DIFFERENT rebuild than the one
// requested and report success for it — e.g. silently ignoring --no-cache and
// reusing the poisoned layer the caller was trying to get rid of.
func TestStackRebuildRefusesAnArgumentItCannotVouchFor(t *testing.T) {
	e, _ := testEngine(t)
	r := queue(t, e, "c", Command{Op: "stack-rebuild", Service: "stack",
		Args: []string{"--quick", "; rm -rf /"}})
	if r.OK {
		t.Fatal("accepted an argument outside the allowlist")
	}
	if !strings.Contains(r.Stderr, "invalid rebuild arg") {
		t.Errorf("unhelpful rejection message: %q", r.Stderr)
	}
}

func TestStackRebuildIsSingleFlight(t *testing.T) {
	e, _ := testEngine(t)
	if err := os.WriteFile(filepath.Join(e.Spool, "other.rebuild.running"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r := queue(t, e, "c", Command{Op: "stack-rebuild", Service: "stack"})
	if r.OK || !strings.Contains(r.Stderr, "already running") {
		t.Fatalf("a second concurrent rebuild must be refused, got %+v", r)
	}
}

// A rebuild marker outliving its process permanently wedges every future
// rebuild as "already running" — one unclean restart, and the op is dead until
// somebody finds the file.
func TestStartupClearsStaleRebuildMarkers(t *testing.T) {
	e, _ := testEngine(t)
	marker := filepath.Join(e.Spool, "old.rebuild.running")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = e.Run(ctx, 50*time.Millisecond, 50*time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("stale rebuild marker survived startup — every future rebuild is now rejected")
	}
}

// ── disk-reclaim ───────────────────────────────────────────────────────────

// The safe default here is the opposite of stack-rebuild's: a mangled argument
// must degrade to PREVIEWING, never to deleting.
func TestDiskReclaimDefaultsToDryRunOnJunkArguments(t *testing.T) {
	e, fr := testEngine(t)
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=maybe", "watermark=nope", "watermark=999"}})
	if !r.OK {
		t.Fatalf("disk-reclaim errored on junk args instead of falling back: %+v", r)
	}
	if !strings.Contains(r.Stderr, "DRY RUN") {
		t.Errorf("junk args must degrade to a dry run, report was: %q", r.Stderr)
	}
	for _, c := range fr.joined() {
		if strings.Contains(c, "prune") || strings.Contains(c, "docker rm") {
			t.Errorf("a dry run removed something: %s", c)
		}
	}
}

func TestDiskReclaimNeverPrunesVolumesOrTaggedImages(t *testing.T) {
	e, fr := testEngine(t)
	// Force the ladder to run every rung: usage is unmeasurable in the test
	// env, so it falls back to `before`, which is below no watermark we can
	// set — assert on what it DID run instead.
	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})
	for _, c := range fr.joined() {
		// Rung 4 may LIST labelled volumes and rm them one by one; it may
		// never prune, never force, and never act on an unlabelled listing.
		if strings.Contains(c, "volume prune") || (strings.Contains(c, "volume rm") && strings.Contains(c, "-f")) {
			t.Errorf("reclaim pruned or force-removed volumes: %s", c)
		}
		if strings.Contains(c, "volume ls") && !strings.Contains(c, "label=noo.cargo-docker-src") {
			t.Errorf("reclaim listed volumes without the build-cache label: %s", c)
		}
		if strings.Contains(c, "image prune") && strings.Contains(c, "-a") {
			t.Errorf("reclaim used `prune -a`, which deletes tagged images: %s", c)
		}
		if strings.Contains(c, "docker rm") && strings.Contains(c, "-f") {
			t.Errorf("reclaim force-removed a container: %s", c)
		}
	}
}

// buildxLS is what `docker buildx ls` prints on a host with the multi-arch
// release builder: a docker-driver "default" plus a docker-CONTAINER driver
// whose cache `docker system df` cannot see. Node rows are INDENTED and are
// not addressable via --builder.
const buildxLS = `NAME/NODE          DRIVER/ENDPOINT      STATUS   BUILDKIT  PLATFORMS
noo-builder*       docker-container
 \_ noo-builder0    \_ unix:///var/run/docker.sock  running v0.31.2 linux/amd64
default            docker
 \_ default         \_ default            running  v0.30.0   linux/amd64`

// Regression: a buildx container-driver builder's cache is invisible to both
// `docker builder prune` and `docker system df`. A host can sit at
// 82% disk with system df reporting 1.2 GB of build cache while the
// noo-builder container-driver builder held 96.9 GB in its own volume. This
// rung would have run, freed nearly nothing, and reported success — worse
// than no ladder, because the report reads like the disk was examined.
func TestReclaimPrunesEveryBuilderNotJustTheDockerDriver(t *testing.T) {
	e, fr := testEngine(t)
	fr.stdout["buildx ls"] = buildxLS
	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})

	pruned := map[string]bool{}
	for _, c := range fr.joined() {
		if !strings.Contains(c, "buildx prune") || !strings.Contains(c, "--builder") {
			continue
		}
		f := strings.Fields(c)
		for i, tok := range f {
			if tok == "--builder" && i+1 < len(f) {
				pruned[f[i+1]] = true
			}
		}
	}
	for _, want := range []string{"default", "noo-builder"} {
		if !pruned[want] {
			t.Errorf("builder %q was never pruned; pruned=%v", want, pruned)
		}
	}
	// Node rows are not builders — passing one yields empty output and a
	// failed prune, so they must be filtered out of the enumeration.
	if pruned["noo-builder0"] {
		t.Error("pruned a NODE name (noo-builder0), which is not addressable via --builder")
	}
}

// The cap must stay off unless the operator sets it.
func TestReclaimCacheCapIsOffByDefault(t *testing.T) {
	e, fr := testEngine(t)
	fr.stdout["buildx ls"] = buildxLS
	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})
	for _, c := range fr.joined() {
		if strings.Contains(c, "--max-used-space") {
			t.Errorf("cache cap fired without being configured: %s", c)
		}
	}
}

// `until=168h` filters on LAST USED, not created. A base layer that every
// build reuses is touched hourly, so it is never 7 days idle and rung 2 can
// never evict it however large it grows. rung 2 can free 276 MB of
// 96.9 GB where capping size frees 82 GB (82% -> 50%). An age policy cannot bound
// build cache; a size policy can.
func TestReclaimCacheCapEvictsWhatTheAgeFilterStructurallyCannot(t *testing.T) {
	e, fr := testEngine(t)
	e.CacheCapBytes = 20_000_000_000
	fr.stdout["buildx ls"] = buildxLS
	fr.stdout["buildx prune --help"] = "      --max-used-space bytes   Maximum amount of disk space allowed"
	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})

	capped := map[string]bool{}
	var order []string
	for _, c := range fr.joined() {
		if !strings.Contains(c, "buildx prune") || strings.Contains(c, "--help") {
			continue
		}
		order = append(order, c)
		if !strings.Contains(c, "--max-used-space") {
			continue
		}
		f := strings.Fields(c)
		for i, tok := range f {
			if tok == "--builder" && i+1 < len(f) {
				capped[f[i+1]] = true
			}
		}
	}
	for _, want := range []string{"default", "noo-builder"} {
		if !capped[want] {
			t.Errorf("builder %q was never capped; capped=%v", want, capped)
		}
	}
	// The cap runs AFTER the age filter, never instead of it.
	if len(order) == 0 || !strings.Contains(order[0], "until=168h") {
		t.Errorf("age filter must run first, got %v", order)
	}
	if !strings.Contains(order[len(order)-1], "--max-used-space") {
		t.Errorf("cap must run last, got %v", order)
	}
}

// An older buildx has no --max-used-space; passing it would fail the rung, so
// the ladder must report a skip and carry on.
func TestReclaimCacheCapSkipsWhenBuildxTooOld(t *testing.T) {
	e, fr := testEngine(t)
	e.CacheCapBytes = 20_000_000_000
	fr.stdout["buildx ls"] = buildxLS
	// --help returns nothing resembling the flag.
	fr.stdout["buildx prune --help"] = "      --filter filter   Provide filter values"
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})
	for _, c := range fr.joined() {
		if strings.Contains(c, "--max-used-space") {
			t.Errorf("used a flag this buildx does not support: %s", c)
		}
	}
	if !strings.Contains(r.Stderr, "rung2b skipped") {
		t.Errorf("skip must be reported, got %q", r.Stderr)
	}
}

// The dry run must not quote system df's docker-driver-only figure.
func TestReclaimDryRunReportsRealPerBuilderCache(t *testing.T) {
	e, fr := testEngine(t)
	fr.stdout["buildx ls"] = buildxLS
	fr.stdout["buildx du --builder noo-builder"] = "Reclaimable:\t96.9GB\nTotal:\t99.9GB"
	fr.stdout["buildx du --builder default"] = "Reclaimable:\t2.6GB\nTotal:\t2.6GB"
	fr.stdout["system df"] = "Build Cache\t9.9GB"
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=true", "watermark=1"}})
	for _, want := range []string{"default: 2.6GB", "noo-builder: 96.9GB"} {
		if !strings.Contains(r.Stderr, want) {
			t.Errorf("dry run must report %q, got %q", want, r.Stderr)
		}
	}
	if strings.Contains(r.Stderr, "9.9GB") {
		t.Errorf("system df's blind figure must not be reported: %q", r.Stderr)
	}
}

// ── heartbeat ──────────────────────────────────────────────────────────────

// This is the fix for a concrete failure: the watcher had been
// running since the 1st, `db-resync` was added to the script on the 4th, and
// the gateway spent two days queueing an op its running watcher had never
// heard of while telling the operator a repair was on its way.
func TestHeartbeatPublishesTheRunningBinarysOpsNotTheSourceTrees(t *testing.T) {
	e, _ := testEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = e.Run(ctx, 50*time.Millisecond, 50*time.Millisecond)

	hb, err := ReadHeartbeat(e.Spool)
	if err != nil {
		t.Fatalf("no heartbeat published: %v", err)
	}
	if hb.PID != os.Getpid() {
		t.Errorf("heartbeat pid = %d, want %d", hb.PID, os.Getpid())
	}
	if !hb.Supports("db-resync") {
		t.Error("heartbeat omits db-resync — a caller could not tell this daemon can repair credentials")
	}
	if hb.Supports("op-that-does-not-exist") {
		t.Error("heartbeat claims an op the binary does not implement")
	}
	if hb.Stale(nowUTC()) {
		t.Error("a heartbeat written moments ago reads as stale")
	}
}

func TestAStoppedDaemonReadsAsStaleRatherThanAlive(t *testing.T) {
	hb := &Heartbeat{TS: "2020-01-01T00:00:00Z", Interval: 15, Ops: []string{"db-resync"}}
	if !hb.Stale(time.Now().UTC()) {
		t.Fatal("a heartbeat from 2020 reads as alive — callers would promise repairs to a dead daemon")
	}
	// Two intervals of lateness is an ordinary scheduling hiccup, not death;
	// flagging it would produce false "host daemon down" alerts in the middle
	// of a repair that is working.
	recent := &Heartbeat{TS: time.Now().UTC().Add(-30 * time.Second).Format("2006-01-02T15:04:05Z"), Interval: 15}
	if recent.Stale(time.Now().UTC()) {
		t.Error("a heartbeat two intervals old reads as stale — too twitchy")
	}
	// An unparseable timestamp must fail CLOSED. "I cannot tell" and "it is
	// alive" are not the same answer.
	if !(&Heartbeat{TS: "garbage", Interval: 15}).Stale(time.Now().UTC()) {
		t.Error("an unreadable heartbeat timestamp read as alive")
	}
}

func TestStatusRefusesToVouchForASpoolWithNoDaemon(t *testing.T) {
	dir := t.TempDir()
	if _, err := Status(context.Background(), dir); err == nil {
		t.Fatal("Status vouched for a spool that has never had a daemon")
	}
}

// ── result plumbing ────────────────────────────────────────────────────────

// A command that could not be STARTED has no exit code. Reporting 0 there
// means "binary missing" is indistinguishable from success — and every caller
// reads 0 as success.
func TestAMissingBinaryReportsFailureNotSuccess(t *testing.T) {
	rc, _ := ExecRunner{}.Run(context.Background(), t.TempDir(), nil, "definitely-not-a-real-binary-xyz")
	if rc == 0 {
		t.Fatal("a command that could not be started reported exit code 0")
	}
	if rc != 127 {
		t.Errorf("exit code = %d, want 127 (the shell convention for command-not-found)", rc)
	}
}

func TestResultStderrIsCappedSoOneBadOpCannotDrownAnAlert(t *testing.T) {
	spool := t.TempDir()
	if err := WriteResult(spool, "c", Result{Stderr: strings.Repeat("x", 50_000)}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(spool, "c.result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Stderr) != stderrCap {
		t.Errorf("stderr len = %d, want capped at %d", len(r.Stderr), stderrCap)
	}
}

// A newer gateway adding a field must not brick an older daemon: the field is
// ignored, the command still runs. Rejecting the whole command would turn a
// forward-compatible addition into a fleet-wide outage.
func TestAnUnknownFieldFromANewerProducerIsIgnoredNotFatal(t *testing.T) {
	c, err := ParseCommand([]byte(`{"op":"restart","service":"gateway","future_field":{"x":1}}`))
	if err != nil {
		t.Fatalf("a command with an unknown field was rejected: %v", err)
	}
	if c.Op != "restart" || c.Service != "gateway" {
		t.Fatalf("known fields lost: %+v", c)
	}
}

// The producers order filenames by time (<nanos>-<hex>). Glob order is
// unspecified, so without an explicit sort a restart/recreate pair can run
// backwards and leave the container down.
func TestCommandsExecuteInTheOrderTheyWereQueued(t *testing.T) {
	e, fr := testEngine(t)
	for _, n := range []string{"3-c", "1-a", "2-b"} {
		b, _ := json.Marshal(Command{Op: "restart", Service: "svc" + n[:1]})
		if err := os.WriteFile(filepath.Join(e.Spool, n+".cmd.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.ScanOnce(context.Background())
	got := fr.joined()
	if len(got) != 3 {
		t.Fatalf("expected 3 commands, ran %d: %v", len(got), got)
	}
	for i, want := range []string{"svc1", "svc2", "svc3"} {
		if !strings.Contains(got[i], want) {
			t.Errorf("position %d = %q, want %s", i, got[i], want)
		}
	}
}

// Written after `go test` on this very package ran a real `docker image prune
// -f` against the developer's own daemon: the reclaim ladder called a
// package-level exec helper instead of the Runner, so the tests looked
// hermetic and were not. exec.Command belongs in exactly one file; anywhere
// else it is a hole in the seam, and a test suite that can reach the host is
// one bad default away from doing something irreversible on a workstation.
func TestNothingExecsOutsideTheRunnerSeam(t *testing.T) {
	allowed := map[string]bool{
		"exec.go":    true, // the seam itself
		"watch.go":   true, // runStreaming: the detached rebuild's log tee
		"install.go": true, // systemctl/launchctl, an operator-invoked path
		// at-rest create-volume (i10a PR-C): sudo by a person, never the
		// spool; every binary it runs is a VolumeConfig field, and its tests
		// set each to a fake.
		"atrest_volume_linux.go": true,
		// at-rest (i10a): sudo by a person, never the spool; every binary it
		// runs is an AtRestConfig field, and its tests set each to a fake.
		"atrest_linux.go": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		n := ent.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || allowed[n] {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "exec.Command") {
			t.Errorf("%s calls exec.Command directly — route it through Engine.Runner "+
				"so tests cannot reach the host's docker daemon", n)
		}
	}
}

// The heartbeat file lives in the spool. If the scan loop treated it as work
// it would reject itself as an invalid op, forever, once per poll.
func TestTheHeartbeatFileIsNotMistakenForACommand(t *testing.T) {
	e, fr := testEngine(t)
	e.writeHeartbeat(stamp(), DefaultHeartbeatInterval)
	e.ScanOnce(context.Background())
	if len(fr.calls) != 0 {
		t.Fatalf("scan executed something from a spool containing only a heartbeat: %v", fr.joined())
	}
	if _, err := os.Stat(filepath.Join(e.Spool, HeartbeatFile)); err != nil {
		t.Error("the scan consumed the heartbeat file")
	}
}

// A standalone controller has no <root>/venv: the rotate op must run the
// native noo binary, not exit 127 looking for the retired Python CLI.
func TestRotateRunsTheNativeCLIWhenThereIsNoVenv(t *testing.T) {
	root := t.TempDir()
	cli := filepath.Join(t.TempDir(), "noo")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOO_CLI_BIN", cli)
	r := &fakeRunner{}
	e := &Engine{Root: root, Runner: r}
	rc, out := opRotate(context.Background(), e, "", &Command{})
	if rc != 0 {
		t.Fatalf("rotate rc=%d (%s), want 0 with the native CLI present", rc, out)
	}
	if len(r.calls) != 1 || r.calls[0][0] != cli ||
		strings.Join(r.calls[0][1:], " ") != "security pki rotate-all --force" {
		t.Fatalf("rotate ran %v, want %s security pki rotate-all --force", r.calls, cli)
	}
}

func TestRotateSaysWhatItLookedForWhenNoCLIExists(t *testing.T) {
	t.Setenv("NOO_CLI_BIN", filepath.Join(t.TempDir(), "absent"))
	e := &Engine{Root: t.TempDir(), Runner: &fakeRunner{}}
	rc, out := opRotate(context.Background(), e, "", &Command{})
	if rc != 127 || !strings.Contains(out, "NOO_CLI_BIN") || !strings.Contains(out, "venv") {
		t.Fatalf("rc=%d out=%q, want 127 naming what was tried", rc, out)
	}
}

// Rung 4 removes a labelled build-cache volume only when its checkout is gone
// or it has been idle for a week. One host had 98 such volumes held
// ~117 GB beside unlabelled dangling volumes that were real databases.
func TestReclaimRemovesOnlyStaleLabelledBuildVolumes(t *testing.T) {
	e, fr := testEngine(t)
	root := t.TempDir()
	live := filepath.Join(root, "checkout-live")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	mount := func(name string, age time.Duration) string {
		d := filepath.Join(root, "vol-"+name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-age)
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
		return d
	}
	fr.stdout["volume ls"] = "vol-gone\nvol-idle\nvol-fresh\n"
	fr.stdout["vol-gone"] = filepath.Join(root, "checkout-deleted") + "|" + mount("gone", time.Hour)
	fr.stdout["vol-idle"] = live + "|" + mount("idle", 8*24*time.Hour)
	fr.stdout["vol-fresh"] = live + "|" + mount("fresh", time.Hour)

	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1"}})

	removed := map[string]bool{}
	for _, c := range fr.joined() {
		if strings.HasPrefix(c, "docker volume rm -- ") {
			removed[strings.TrimPrefix(c, "docker volume rm -- ")] = true
		}
	}
	if !removed["vol-gone"] || !removed["vol-idle"] {
		t.Errorf("stale build volumes were kept: removed=%v", removed)
	}
	if removed["vol-fresh"] {
		t.Errorf("a recently used build volume was removed: removed=%v", removed)
	}
}

// A worker's hostd serves disk-reclaim, so the node's agent can relieve its
// own disk — the controller's ladder cannot reach it.
func TestWorkerModeServesDiskReclaim(t *testing.T) {
	if _, ok := opsFor(ModeWorker)["disk-reclaim"]; !ok {
		t.Fatal("worker mode has no disk-reclaim op")
	}
}

// The caller can set the cache cap per run; the engine default stays 0 (off).
func TestReclaimCacheCapFromTheCommand(t *testing.T) {
	e, fr := testEngine(t)
	fr.stdout["buildx ls"] = buildxLS
	fr.stdout["buildx prune --help"] = "      --max-used-space bytes   Maximum amount of disk space allowed"
	queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "watermark=1", "cache_cap_bytes=25000000000"}})
	found := false
	for _, c := range fr.joined() {
		if strings.Contains(c, "--max-used-space 25000000000") {
			found = true
		}
	}
	if !found {
		t.Fatalf("cache_cap_bytes did not reach rung 2b: %v", fr.joined())
	}
}

// removing containerd leases by age deleted the rw snapshots
// of RUNNING containers on host3. No rung may touch leases or snapshots, live
// or dry — pinned across the whole ladder, every rung forced to run.
func TestReclaimNeverTouchesContainerdLeasesOrSnapshots(t *testing.T) {
	e, fr := testEngine(t)
	e.CacheCapBytes = 1
	fr.stdout["buildx ls"] = buildxLS
	fr.stdout["buildx prune --help"] = "      --max-used-space bytes"
	for _, args := range [][]string{{"dry_run=false", "watermark=1"}, {"dry_run=true", "watermark=1"}} {
		queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker", Args: args})
	}
	// Not vacuous: every rung actually ran, live and dry.
	all := strings.Join(fr.joined(), "\n")
	for _, ran := range []string{"image prune", "buildx prune", "--max-used-space", "ps -a", "volume ls"} {
		if !strings.Contains(all, ran) {
			t.Fatalf("ladder never ran %q, so this test checked nothing:\n%s", ran, all)
		}
	}
	for _, c := range fr.joined() {
		l := strings.ToLower(c)
		if strings.HasPrefix(l, "ctr ") || strings.Contains(l, "lease") || strings.Contains(l, "snapshot") ||
			strings.Contains(l, "containerd") && !strings.HasPrefix(l, "df ") {
			t.Errorf("reclaim touched containerd internals: %s", c)
		}
	}
}

// v0.2.88 rehearsal: on a worker the project root does not exist, and every
// ladder command ran with cmd.Dir set to it, so exec failed before df started.
// The ladder must not depend on the project root, live or dry.
func TestReclaimRunsWithoutAProjectRoot(t *testing.T) {
	for _, dry := range []string{"dry_run=true", "dry_run=false"} {
		e, fr := testEngine(t)
		e.Root = filepath.Join(t.TempDir(), "absent")
		e.CacheCapBytes = 1
		fr.stdout["buildx ls"] = buildxLS
		queue(t, e, "c", Command{Op: "disk-reclaim", Service: "noo-node-agent",
			Args: []string{dry, "watermark=1"}})
		if len(fr.dirs) == 0 {
			t.Fatalf("%s: the ladder ran no commands", dry)
		}
		for i, d := range fr.dirs {
			if d != "/" {
				t.Fatalf("%s: %v ran in %q, want /", dry, fr.calls[i], d)
			}
		}
	}
}

// A command that could not start must say why, not just rc=127.
func TestAMissingWorkingDirIsReportedNotSilent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	rc, stderr := ExecRunner{}.Run(context.Background(), missing, nil, "true")
	if rc == 0 {
		t.Fatal("a command in a missing dir reported success")
	}
	if !strings.Contains(stderr, "absent") {
		t.Fatalf("stderr = %q, want the reason naming the missing dir", stderr)
	}
}

// ── backup artifact ────────────────────────────────────────────────────────

// A backup's result must name the dump and its size, so the gateway checks the
// artifact and not just an exit code; the marker line must not leak into the
// operator-facing stderr.
func TestBackupResultNamesTheDumpAndItsSize(t *testing.T) {
	e, fr := testEngine(t)
	dump := filepath.Join(t.TempDir(), "pg_20260101_033000.sql.gz.enc")
	if err := os.WriteFile(dump, []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr.stderr = map[string]string{"backup-controller.sh": "WARNING: something minor\n" + backupArtifactMarker + dump}
	r := queue(t, e, "b", Command{Op: "backup", Service: "noo-postgres"})
	if !r.OK || r.Artifact != dump || r.Bytes != 8 {
		t.Fatalf("result must be ok and name the dump and its size: %+v", r)
	}
	if strings.Contains(r.Stderr, backupArtifactMarker) || !strings.Contains(r.Stderr, "WARNING") {
		t.Errorf("marker line must be stripped and other stderr kept: %q", r.Stderr)
	}
}

// rc=0 with a marker whose file is empty or gone is NOT a backup.
func TestBackupWithAnEmptyOrMissingDumpIsAFailure(t *testing.T) {
	for name, make := range map[string]func(string){
		"empty":   func(p string) { _ = os.WriteFile(p, nil, 0o600) },
		"missing": func(string) {},
	} {
		e, fr := testEngine(t)
		dump := filepath.Join(t.TempDir(), "pg.sql.gz.enc")
		make(dump)
		fr.stderr = map[string]string{"backup-controller.sh": backupArtifactMarker + dump}
		r := queue(t, e, "b", Command{Op: "backup", Service: "noo-postgres"})
		if r.OK || r.RC == 0 {
			t.Errorf("%s dump reported as a good backup: %+v", name, r)
		}
	}
}

// A script that exits 0 but names no dump (it skipped the dump) did not make a
// backup, and must not be reported as one.
func TestBackupThatExitsZeroButNamesNoDumpIsAFailure(t *testing.T) {
	e, fr := testEngine(t)
	fr.stderr = map[string]string{"backup-controller.sh": "WARNING: nothing to do"}
	r := queue(t, e, "b", Command{Op: "backup", Service: "noo-postgres"})
	if r.OK || r.RC == 0 || r.Artifact != "" {
		t.Fatalf("a zero exit with no dump was reported as a backup: %+v", r)
	}
	if !strings.Contains(r.Stderr, "named no dump") {
		t.Errorf("the failure must say why: %q", r.Stderr)
	}
}

// The reboot path: tmpfs secret files are gone, dockerd could not start the
// containers that bind them and does not retry, so the daemon rewrites the files
// (load_secrets) and starts exactly the stopped containers that bind from the
// directory. Worker mode and a populated directory do nothing.
func TestBootRestoreWritesFilesThenStartsOnlyBoundContainers(t *testing.T) {
	e, fr := testEngine(t)
	e.BootRestore(context.Background())
	got := strings.Join(fr.joined(), "\n")
	for _, want := range []string{"lib-secrets.sh", "secret_rundir", "load_secrets", "--filter status=created", "docker start", `grep -q "^$d/"`, "is populated; nothing to do"} {
		if !strings.Contains(got, want) {
			t.Fatalf("boot-restore script lacks %q:\n%s", want, got)
		}
	}
	// the populated check comes BEFORE the write, and the start after it
	if !(strings.Index(got, "populated") < strings.Index(got, "load_secrets >/dev/null") && strings.Index(got, "load_secrets >/dev/null") < strings.Index(got, "docker start")) {
		t.Fatalf("wrong order:\n%s", got)
	}
	if strings.Contains(got, "up -d") || strings.Contains(got, "pull") || strings.Contains(got, "--force-recreate") {
		t.Fatalf("boot-restore must not recreate or pull:\n%s", got)
	}
}

// i10a: when the state lives on the encrypted volume and it did not open at
// boot, the restore refuses before writing secrets or starting anything.
func TestBootRestoreChecksTheStateVolumeBeforeStarting(t *testing.T) {
	e, fr := testEngine(t)
	e.BootRestore(context.Background())
	got := strings.Join(fr.joined(), "\n")
	check := strings.Index(got, "check_state_volume_open")
	if !strings.Contains(got, "lib-state-volume.sh") || check < 0 {
		t.Fatalf("boot-restore does not check the state volume:\n%s", got)
	}
	if !(strings.Index(got, "populated") < check && check < strings.Index(got, "load_secrets >/dev/null") && check < strings.Index(got, "docker start")) {
		t.Fatalf("the volume check must come before the write and the start:\n%s", got)
	}
	if !strings.Contains(got, "exit 3") {
		t.Fatalf("a closed volume must fail the attempt:\n%s", got)
	}
}

func TestBootRestoreDoesNothingForAWorker(t *testing.T) {
	e, fr := testEngine(t)
	e.Mode = ModeWorker
	e.BootRestore(context.Background())
	if len(fr.calls) != 0 {
		t.Fatalf("worker ran %v", fr.calls)
	}
}

func TestTheDaemonRunsBootRestoreAtStart(t *testing.T) {
	src, _ := os.ReadFile("../../cmd/noo-hostd/main.go")
	if !strings.Contains(string(src), "RestoreOnBoot:  true") {
		t.Fatal("noo-hostd main must enable RestoreOnBoot")
	}
}

// The 2026-10-24 near miss, on the reboot path: dockerd restarted the stack
// without a launcher while the data disk had not come back. BootRestore runs
// the REAL guard (lib-data-root-mount.sh) against a fake mount table and a fake
// docker: it stops postgres first, stops the rest, records why, and never
// starts anything, secrets populated or not.
func TestBootRestoreStopsTheStackWhenTheDataRootIsNotOnItsFilesystem(t *testing.T) {
	root := t.TempDir()
	scripts := filepath.Join(root, "scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	lib, err := os.ReadFile("../../../scripts/lib-data-root-mount.sh")
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(scripts, "lib-data-root-mount.sh"), lib, 0o644))
	// A secrets lib that would write files and a marker if it were reached.
	reached := filepath.Join(root, "secrets-reached")
	must(os.WriteFile(filepath.Join(scripts, "lib-secrets.sh"),
		[]byte("secret_rundir() { echo '"+root+"/rundir'; }\nload_secrets() { touch '"+reached+"'; }\n"), 0o644))

	data := filepath.Join(root, "mnt", "noo")
	must(os.MkdirAll(filepath.Join(data, "postgres"), 0o755))
	must(os.WriteFile(filepath.Join(data, "postgres", "PG_VERSION"), []byte("16\n"), 0o644))

	bin := filepath.Join(root, "bin")
	must(os.MkdirAll(bin, 0o755))
	dlog := filepath.Join(root, "docker.log")
	must(os.WriteFile(filepath.Join(bin, "findmnt"), []byte("#!/bin/sh\nf=\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && f=$2; shift; done\neval \"printf '%s\\n' \\\"\\$FAKE_$f\\\"\"\n"), 0o755))
	must(os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$@\" >> '"+dlog+"'\n[ \"$1\" = ps ] && printf '%s\\n' noo-redis noo-postgres noo-gateway\nexit 0\n"), 0o755))

	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("COMPOSE_LOCK_FILE", filepath.Join(root, "lock"))
	t.Setenv("NOO_DATA_ROOT", data)
	t.Setenv("FAKE_UUID", "aaaa-1111")
	t.Setenv("FAKE_SOURCE", "/dev/nvme1n1p1")
	t.Setenv("FAKE_TARGET", filepath.Join(root, "mnt"))
	t.Setenv("FAKE_FSTYPE", "ext4")

	var logs []string
	e := &Engine{Root: root, Spool: filepath.Join(root, "spool"), Runner: ExecRunner{}, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	boot := func() {
		// One attempt only: cancel as soon as the script returns, so the retry
		// sleep does not run.
		ctx, cancel := context.WithCancel(context.Background())
		e.Runner = cancelAfterRun{ExecRunner{}, cancel}
		e.BootRestore(ctx)
	}

	// 1. First boot on a good mount records the identity, and the restore goes on.
	boot()
	if _, err := os.Stat(filepath.Join(root, ".noo-data-root-id")); err != nil {
		t.Fatalf("the identity was not recorded: %v (logs %v)", err, logs)
	}
	if _, err := os.Stat(reached); err != nil {
		t.Fatalf("a healthy mount must not stop the secret restore: %v", err)
	}
	if b, _ := os.ReadFile(dlog); strings.Contains(string(b), "stop") {
		t.Fatalf("a healthy mount stopped containers:\n%s", b)
	}
	must(os.Remove(reached))
	_ = os.Remove(dlog)

	// 2. The disk does not come back: a different filesystem under the root.
	t.Setenv("FAKE_UUID", "rootfs-9999")
	t.Setenv("FAKE_SOURCE", "/dev/sda2")
	t.Setenv("FAKE_TARGET", "/")
	logs = nil
	boot()
	b, err := os.ReadFile(dlog)
	must(err)
	calls := strings.Split(strings.TrimSpace(string(b)), "\n")
	var stops []string
	for _, c := range calls {
		if strings.HasPrefix(c, "stop ") {
			stops = append(stops, c)
		}
		if strings.HasPrefix(c, "start") || strings.HasPrefix(c, "run") || strings.Contains(c, "compose") || strings.HasPrefix(c, "up") {
			t.Fatalf("the refused boot path started something: %q", c)
		}
	}
	if len(stops) != 3 || stops[0] != "stop noo-postgres" {
		t.Fatalf("postgres must be stopped first, then the rest; got %v", stops)
	}
	if _, err := os.Stat(reached); err == nil {
		t.Fatal("secrets were written for a stack that must not start")
	}
	why, err := os.ReadFile(filepath.Join(root, ".noo-data-root-refused"))
	must(err)
	if !strings.Contains(string(why), "REFUSED") || !strings.Contains(string(why), "aaaa-1111") {
		t.Fatalf("the reason was not recorded:\n%s", why)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "BOOT-RESTORE attempt 1 failed (exit 3)") {
		t.Fatalf("the refusal must fail the attempt with exit 3: %v", logs)
	}
}

// cancelAfterRun cancels the context once the script has run, so BootRestore's
// retry loop stops after one attempt instead of sleeping.
type cancelAfterRun struct {
	ExecRunner
	cancel context.CancelFunc
}

func (c cancelAfterRun) Run(ctx context.Context, dir string, env []string, name string, args ...string) (int, string) {
	rc, se := c.ExecRunner.Run(ctx, dir, env, name, args...)
	c.cancel()
	return rc, se
}
