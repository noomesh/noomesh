// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every test in the package keeps the filesystem record in a temp dir: the
// real /var/lib/noo-node-agent is never read or written by a test.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dataroots-record-")
	if err != nil {
		panic(err)
	}
	os.Setenv("NOO_AGENT_STATE", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var (
	dataFS = FSID{Target: "/data", Source: "/dev/sdb1", FSType: "ext4", UUID: "u-data", Dev: "8:17"}
	rootFS = FSID{Target: "/", Source: "/dev/sda1", FSType: "ext4", UUID: "u-root", Dev: "8:1"}
)

// fakeDisk is a data disk mounted at /data, or not (its mount point then an
// empty directory on the root filesystem).
type fakeDisk struct{ mounted bool }

func (d *fakeDisk) identity(p string) (FSID, string, error) {
	if d.mounted && (p == "/data" || strings.HasPrefix(p, "/data/")) {
		return dataFS, rootFS.Dev, nil
	}
	return rootFS, rootFS.Dev, nil
}

// fakeFSCheck installs the fake disk, a temp record, no fstab, and a
// MkdirAll that only counts. Returns the disk and the MkdirAll counter.
func fakeFSCheck(t *testing.T) (*fakeDisk, *int) {
	t.Helper()
	disk := &fakeDisk{}
	dir := t.TempDir()
	calls := 0
	prevID, prevOS, prevEval, prevStat, prevRec, prevFstab, prevMk :=
		fsIdentity, fsCheckOS, fsEvalPath, fsStatDir, recordPath, fstabPath, mkdirAll
	fsIdentity, fsCheckOS = disk.identity, "linux"
	fsEvalPath = func(p string) (string, error) { return p, nil }
	fsStatDir = func(string) bool { return true }
	recordPath = func() string { return filepath.Join(dir, RecordFileName) }
	fstabPath = filepath.Join(dir, "no-fstab")
	mkdirAll = func(string, os.FileMode) error { calls++; return nil }
	resetRecordCache()
	t.Cleanup(func() {
		fsIdentity, fsCheckOS, fsEvalPath, fsStatDir, recordPath, fstabPath, mkdirAll =
			prevID, prevOS, prevEval, prevStat, prevRec, prevFstab, prevMk
		resetRecordCache()
	})
	t.Setenv("NOO_DATA_ROOT", "/data/noo")
	t.Setenv(PolicyEnv, "")
	t.Setenv(FSEnv, "")
	for _, k := range []string{"HF_CACHE_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR"} {
		t.Setenv(k, "")
	}
	return disk, &calls
}

func resetRecordCache() {
	recordMu.Lock()
	recordCache, recordStamp, recordWarn = fsRecordFile{}, "", ""
	recordMu.Unlock()
}

func fsCodes(r Roots) []string {
	var out []string
	for _, f := range checkFilesystems(r) {
		out = append(out, f.Code)
	}
	return out
}

// First run: a root on the root filesystem's device is NOT recorded (it may
// be an empty mount point whose disk is late); on its own disk it is.
func TestFirstRunRecordsOnlyOffTheRootFilesystem(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("nothing recorded, nothing declared: no problem, got %v", c)
	}
	if recorded("/data/noo") {
		t.Fatal("a root on the root filesystem was recorded on a first look")
	}
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
	if !recorded("/data/noo") {
		t.Fatal("a root on its own disk was not recorded")
	}
	b, err := os.ReadFile(recordPath())
	if err != nil || !strings.Contains(string(b), `"uuid": "u-data"`) || !strings.Contains(string(b), `"/data/noo"`) {
		t.Fatalf("record file: %v %s", err, b)
	}
	if got := FilesystemReport(r)["meant"]; got != "mount" {
		t.Fatalf("a root recorded on its own disk is meant to be a mount, got %v", got)
	}
}

// The empty mount point: recorded on its disk, the disk now absent. Refused
// in warn mode, NOTHING created; cleared when the mount is back.
func TestAnEmptyMountPointIsRefusedAndNothingIsCreated(t *testing.T) {
	disk, calls := fakeFSCheck(t)
	disk.mounted = true
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r) // a known-good start records it
	disk.mounted = false

	c := fsCodes(r)
	if len(c) == 0 || c[0] != "not_on_recorded_fs" {
		t.Fatalf("an empty mount point must be refused as not_on_recorded_fs, got %v", c)
	}
	if err := Refusal(Current()); err == nil {
		t.Fatal("warn mode must refuse a root that is not on its recorded filesystem")
	}
	if err := Gate(); err == nil || !strings.Contains(err.Error(), "not_on_recorded_fs") {
		t.Fatalf("Gate: %v", err)
	}
	for _, d := range []string{"/data/noo/models", "/data/noo/hf-cache/hub/models--x", "/data/noo/ollama"} {
		if err := MkdirAll(d, 0o755); err == nil {
			t.Fatalf("MkdirAll(%s) on an empty mount point was allowed", d)
		}
	}
	if *calls != 0 {
		t.Fatalf("MkdirAll created %d directories on an empty mount point", *calls)
	}
	// A path under no root is not this check's business.
	if err := MkdirAll("/srv/elsewhere/x", 0o755); err != nil || *calls != 1 {
		t.Fatalf("a dir outside every root: %v, %d calls", err, *calls)
	}

	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("the mount is back: the refusal must clear by itself, got %v", c)
	}
	if err := MkdirAll("/data/noo/models", 0o755); err != nil || *calls != 2 {
		t.Fatalf("mount back: MkdirAll %v, %d calls", err, *calls)
	}
	if err := Gate(); err != nil && strings.Contains(err.Error(), "not_on_recorded_fs") {
		t.Fatalf("mount back: Gate still refuses: %v", err)
	}
}

// A root declared a plain directory is recorded where it is, root fs or not.
func TestADeclaredDirectoryIsRecordedOnTheRootFilesystem(t *testing.T) {
	_, _ = fakeFSCheck(t)
	t.Setenv(FSEnv, "directory")
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("%v", c)
	}
	if !recorded("/data/noo") {
		t.Fatal("a declared plain directory was not recorded")
	}
	if got := FilesystemReport(r)["meant"]; got != "directory" {
		t.Fatalf("meant = %v", got)
	}
}

// NOO_DATA_ROOT_FS=mount with nothing recorded: the root fs is refused.
func TestADeclaredMountOnTheRootFilesystemIsRefused(t *testing.T) {
	disk, calls := fakeFSCheck(t)
	t.Setenv(FSEnv, "mount")
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 1 || c[0] != "mount_missing" {
		t.Fatalf("got %v", c)
	}
	if err := MkdirAll("/data/noo/models", 0o755); err == nil || *calls != 0 {
		t.Fatalf("declared mount absent: %v, %d calls", err, *calls)
	}
	if recorded("/data/noo") {
		t.Fatal("recorded the root filesystem for a declared mount")
	}
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
}

// An /etc/fstab mount above the root that is not mounted: refused on a
// first run too, without any declaration.
func TestAnFstabMountThatIsNotThereIsRefused(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	if err := os.WriteFile(fstabPath, []byte("# x\nUUID=u-root / ext4 defaults 0 1\nUUID=u-data /data ext4 defaults,nofail 0 2\n/swapfile none swap sw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 1 || c[0] != "mount_missing" {
		t.Fatalf("got %v", c)
	}
	if got := FilesystemReport(r)["meant"]; got != "mount" {
		t.Fatalf("meant = %v", got)
	}
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
}

func TestParseMountinfoFindsTheContainingMount(t *testing.T) {
	mi := strings.Join([]string{
		"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
		"40 22 8:17 / /data rw,relatime shared:2 - ext4 /dev/sdb1 rw",
		"41 22 0:50 / /my\\040disk rw - xfs /dev/sdc1 rw",
		"42 22 0:51 / /auto rw - autofs systemd-1 rw",
		"43 22 0:52 / /data rw - nfs4 srv:/x rw",
	}, "\n")
	ms := parseMountinfo(mi)
	if len(ms) != 5 || ms[2].target != "/my disk" {
		t.Fatalf("%+v", ms)
	}
	if m, _ := containing(ms, "/data/noo"); m.fstype != "nfs4" {
		t.Fatalf("an overmount: the later one is on top, got %+v", m)
	}
	if m, _ := containing(ms, "/auto/noo"); m.target != "/" {
		t.Fatalf("an untriggered autofs trap is not the filesystem, got %+v", m)
	}
	if m, _ := containing(ms, "/database"); m.target != "/" {
		t.Fatalf("/database is not under /data, got %+v", m)
	}
}

func TestSameFSIsTheControllersComparison(t *testing.T) {
	a := dataFS
	b := a
	b.Source = "/dev/sdc1" // renamed at boot, same UUID
	if !sameFS(a, b) {
		t.Fatal("same UUID, renamed device: same filesystem")
	}
	if sameFS(a, rootFS) {
		t.Fatal("different UUIDs")
	}
	a.UUID, b.UUID = "", ""
	if sameFS(a, b) {
		t.Fatal("no UUID: the source is part of the identity")
	}
}

// A hung disk: the probe answers "not answering" within the bound, a second
// probe of the same path answers at once, and it clears when the disk does.
func TestAHungProbeAnswersWithinTheBound(t *testing.T) {
	prev := ProbeTimeout
	ProbeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { ProbeTimeout = prev })
	release := make(chan struct{})
	key := t.TempDir()
	done := make(chan error, 1)
	go func() {
		_, err := Bounded(key, func() int { <-release; return 1 })
		done <- err
	}()
	select {
	case err := <-done:
		var na *NotAnsweringError
		if !errors.As(err, &na) || !strings.Contains(err.Error(), "not answering") {
			t.Fatalf("want NotAnsweringError, got %v", err)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("a hung probe held its caller past the bound")
	}
	start := time.Now()
	if _, err := Bounded(key, func() int { return 2 }); err == nil || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("a second probe while one is stuck must answer at once: %v after %v", err, time.Since(start))
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if v, err := Bounded(key, func() int { return 3 }); err == nil && v == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the probe did not clear after the disk answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The heartbeat's data_roots on a hung disk: it still returns, inside the
// bound, with the root reported not answering.
func TestAHungRootIsReportedNotAnswering(t *testing.T) {
	_, _ = fakeFSCheck(t)
	prev := ProbeTimeout
	ProbeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { ProbeTimeout = prev })
	release := make(chan struct{})
	root := t.TempDir()
	// Release the stuck probe and wait for it to finish before the seams are
	// restored: it still reads them once the "disk" answers.
	t.Cleanup(func() {
		close(release)
		WaitProbeForTest(root, 3*time.Second)
	})
	fsIdentity = func(string) (FSID, string, error) { <-release; return rootFS, rootFS.Dev, nil }
	t.Setenv("NOO_DATA_ROOT", root)
	got := make(chan map[string]any, 1)
	go func() {
		got <- Report(Resolve(os.Getenv), func() (map[string][]string, error) { return map[string][]string{"vllm": {root}}, nil })
	}()
	var out map[string]any
	select {
	case out = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("Report waited on a hung disk past the bound")
	}
	pol := out["policy"].(map[string]any)
	probs := pol["problems"].([]Problem)
	if pol["ok"] != false || len(probs) != 1 || probs[0].Code != "not_answering" ||
		!strings.Contains(probs[0].Detail, "data root "+root+" not answering") {
		t.Fatalf("policy: %+v", pol)
	}
	if _, ok := out["running_mounts"]; !ok || out["noo_data_root"] != root {
		t.Fatalf("the paths and docker's mounts still go out: %+v", out)
	}
	if err := Gate(); err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("Gate on a hung root: %v", err)
	}
}

// A legacy root whose mount is late is kept (it is recorded), not swapped
// for the default; the policy says why.
func TestALateLegacyMountIsKeptAndRefused(t *testing.T) {
	defer func() { adoptedLegacy, adoptedLate = "", false }()
	prev := legacyRecorded
	legacyRecorded = func(d string) bool { return d == "/data/noo" }
	t.Cleanup(func() { legacyRecorded = prev })
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	set := func(k, v string) error { env[k] = v; return nil }
	if got := adoptLegacyRoot("linux", get, set, func(string) bool { return false }); got != "/data/noo" || !AdoptedLate() {
		t.Fatalf("adopted %q late=%v, want /data/noo late", got, AdoptedLate())
	}
	r := Resolve(get)
	if r.NooDataRootSource != "legacy_default" {
		t.Fatalf("%+v", r)
	}
	probs := Check(r, "linux", "", 0)
	if len(probs) == 0 || probs[0].Code != "undeclared_root" || !strings.Contains(probs[0].Detail, "mount was late") {
		t.Fatalf("%v", probs)
	}
	// Never recorded: the old behaviour (nothing adopted).
	adoptedLegacy, adoptedLate, env = "", false, map[string]string{}
	legacyRecorded = func(string) bool { return false }
	if got := adoptLegacyRoot("linux", get, set, func(string) bool { return false }); got != "" || AdoptedLate() {
		t.Fatalf("adopted %q", got)
	}
}

// The three fetch paths create directories through the gate, and backend
// starts and host paths check through the bounded Gate.
func TestTheFetchPathsAndStartsAreGated(t *testing.T) {
	for file, want := range map[string]string{
		"../docker/model_artifact.go": "dataroots.MkdirAll(dir, 0o755)",
		"../preseed/preseed.go":       "dataroots.MkdirAll(filepath.Dir(dest), 0o755)",
		"../modelsets/modelsets.go":   "dataroots.MkdirAll(dir, 0o755)",
		"../docker/backends.go":       "if err := dataroots.Gate(); err != nil {",
		"../docker/hostroots.go":      "if err := dataroots.Gate(); err != nil {",
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s does not call %q", file, want)
		}
	}
	for _, file := range []string{"../docker/model_artifact.go", "../modelsets/modelsets.go"} {
		b, _ := os.ReadFile(file)
		if strings.Contains(string(b), "os.MkdirAll(dir, 0o755)") {
			t.Errorf("%s still creates its dir ungated", file)
		}
	}
}
