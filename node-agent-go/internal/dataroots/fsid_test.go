// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"bytes"
	"errors"
	"log/slog"
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
	// A late legacy root is adopted only from a record; no test reads the
	// machine's own (a real /data/noo on a dev box would be recorded).
	legacyRecorded = func(string) bool { return false }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var (
	dataFS  = FSID{Target: "/data", Source: "/dev/sdb1", FSType: "ext4", UUID: "u-data", Dev: "8:17"}
	rootFS  = FSID{Target: "/", Source: "/dev/sda1", FSType: "ext4", UUID: "u-root", Dev: "8:1"}
	otherFS = FSID{Target: "/data", Source: "/dev/sdc1", FSType: "ext4", UUID: "u-other", Dev: "8:33"}
)

// fakeDisk is a data disk mounted at /data, or not (its mount point then an
// empty directory on the root filesystem).
// other: a different disk is mounted there instead.
type fakeDisk struct{ mounted, other bool }

func (d *fakeDisk) identity(p string) (FSID, string, error) {
	if d.mounted && (p == "/data" || strings.HasPrefix(p, "/data/")) {
		if d.other {
			return otherFS, rootFS.Dev, nil
		}
		return dataFS, rootFS.Dev, nil
	}
	return rootFS, rootFS.Dev, nil
}

// fakeFSCheck installs the fake disk, a temp record, no fstab, no mount
// units, an empty mount table for autofs, a trigger that only counts, and a
// MkdirAll that only counts. Returns the disk and the MkdirAll counter.
func fakeFSCheck(t *testing.T) (*fakeDisk, *int) {
	t.Helper()
	disk := &fakeDisk{}
	dir := t.TempDir()
	calls := 0
	prevID, prevOS, prevEval, prevStat, prevRec, prevFstab, prevMk :=
		fsIdentity, fsCheckOS, fsEvalPath, fsStatDir, recordPath, fstabPath, mkdirAll
	prevUnits, prevMI, prevTrig, prevCount := mountUnitDirs, mountinfoPath, automountTrigger, countEntries
	fsIdentity, fsCheckOS = disk.identity, "linux"
	fsEvalPath = func(p string) (string, error) { return p, nil }
	fsStatDir = func(string) bool { return true }
	recordPath = func() string { return filepath.Join(dir, RecordFileName) }
	fstabPath = filepath.Join(dir, "fstab")
	if err := os.WriteFile(fstabPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(dir, "units")
	if err := os.Mkdir(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mountUnitDirs = func() []string { return []string{unitDir} }
	mountinfoPath = filepath.Join(dir, "no-mountinfo")
	automountTrigger = func(string) {}
	countEntries = func(string) (int, bool) { return 0, false }
	mkdirAll = func(string, os.FileMode) error { calls++; return nil }
	resetRecordCache()
	t.Cleanup(func() {
		fsIdentity, fsCheckOS, fsEvalPath, fsStatDir, recordPath, fstabPath, mkdirAll =
			prevID, prevOS, prevEval, prevStat, prevRec, prevFstab, prevMk
		mountUnitDirs, mountinfoPath, automountTrigger, countEntries = prevUnits, prevMI, prevTrig, prevCount
		resetRecordCache()
	})
	t.Setenv("NOO_DATA_ROOT", "/data/noo")
	t.Setenv(PolicyEnv, "")
	resetRecordCache()
	for _, k := range []string{"HF_CACHE_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR"} {
		t.Setenv(k, "")
	}
	return disk, &calls
}

// writeUnit writes a systemd unit into the fake unit directory and enables
// it (a link in local-fs.target.wants, as `systemctl enable` makes).
func writeUnit(t *testing.T, name, body string) {
	t.Helper()
	writeUnitOnly(t, name, body)
	dir := mountUnitDirs()[0]
	wants := filepath.Join(dir, "local-fs.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, name), filepath.Join(wants, name)); err != nil {
		t.Fatal(err)
	}
}

// writeUnitOnly writes a unit without enabling it.
func writeUnitOnly(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(mountUnitDirs()[0], name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// allCodes: every root path (the data root and its three stores) reports
// exactly want.
func allCodes(t *testing.T, r Roots, c []string, want string) {
	t.Helper()
	if len(c) != len(fsPaths(r)) {
		t.Fatalf("want %s on each of %d paths, got %v", want, len(fsPaths(r)), c)
	}
	for _, code := range c {
		if code != want {
			t.Fatalf("want %s, got %v", want, c)
		}
	}
}

func writeFstab(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(fstabPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func resetRecordCache() {
	recordMu.Lock()
	recordCache, recordStamp, recordWarn = fsRecordFile{}, "", ""
	recordMu.Unlock()
	refusedMu.Lock()
	refused = map[string]bool{}
	refusedMu.Unlock()
}

func fsCodes(r Roots) []string {
	var out []string
	for _, f := range checkFilesystems(r) {
		out = append(out, f.Code)
	}
	return out
}

// First run, no boot-time mount covers the root: it is a plain directory,
// recorded where it is (root filesystem included).
func TestFirstRunRecordsAPlainDirectoryWhereItIs(t *testing.T) {
	_, _ = fakeFSCheck(t)
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("no boot mount: no problem, got %v", c)
	}
	if !recorded("/data/noo") {
		t.Fatal("a plain directory on the root filesystem was not recorded")
	}
	if got := FilesystemReport(r); got["meant"] != "directory" || got["by"] != "" {
		t.Fatalf("a plain directory: %v", got)
	}
}

// First run on its own disk with no boot mount declared (a hand mount):
// recorded, and reported as a mount by its record.
func TestFirstRunRecordsADisk(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	disk.mounted = true
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
	b, err := os.ReadFile(recordPath())
	if err != nil || !strings.Contains(string(b), `"uuid": "u-data"`) || !strings.Contains(string(b), `"/data/noo"`) {
		t.Fatalf("record file: %v %s", err, b)
	}
	if got := FilesystemReport(r); got["meant"] != "mount" || got["by"] != "recorded" {
		t.Fatalf("a root recorded on its own disk: %v", got)
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

// An /etc/fstab mount above the root that is not mounted: refused on a
// first run, nothing recorded, cleared when it mounts.
func TestAnFstabMountThatIsNotThereIsRefused(t *testing.T) {
	disk, calls := fakeFSCheck(t)
	writeFstab(t, "# x\nUUID=u-root / ext4 defaults 0 1\nUUID=u-data /data ext4 defaults,nofail 0 2\n/swapfile none swap sw 0 0\n")
	r := Resolve(os.Getenv)
	allCodes(t, r, fsCodes(r), "mount_missing")
	if err := MkdirAll("/data/noo/models", 0o755); err == nil || *calls != 0 {
		t.Fatalf("fstab mount absent: %v, %d calls", err, *calls)
	}
	if recorded("/data/noo") {
		t.Fatal("recorded the root filesystem under an fstab mount")
	}
	if got := FilesystemReport(r); got["meant"] != "mount" || got["by"] != "fstab" {
		t.Fatalf("%v", got)
	}
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
}

// `noauto` in fstab is not a boot-time mount: the root is a plain directory.
func TestAnFstabNoautoEntryIsNotABootMount(t *testing.T) {
	_, _ = fakeFSCheck(t)
	writeFstab(t, "UUID=u-data /data ext4 nofail,noauto 0 2\n")
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("noauto: not a boot mount, got %v", c)
	}
	if !recorded("/data/noo") {
		t.Fatal("a root under a noauto entry was not recorded as a plain directory")
	}
	if got := FilesystemReport(r)["meant"]; got != "directory" {
		t.Fatalf("meant = %v", got)
	}
}

// A systemd mount unit (read by Where=) that is not mounted: mount_missing.
func TestAMountUnitThatIsNotThereIsRefused(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	writeUnit(t, "data.mount", "[Unit]\nDescription=data\n\n[Mount]\nWhat=/dev/disk/by-uuid/u-data\nWhere=/data\nType=ext4\nOptions=defaults\n")
	r := Resolve(os.Getenv)
	allCodes(t, r, fsCodes(r), "mount_missing")
	if recorded("/data/noo") {
		t.Fatal("recorded the root filesystem under a mount unit")
	}
	if got := FilesystemReport(r); got["meant"] != "mount" || got["by"] != "systemd unit" {
		t.Fatalf("%v", got)
	}
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
}

// A mount unit with no Where= is named by its escaped path; a noauto unit
// does not count.
func TestAMountUnitIsReadByItsName(t *testing.T) {
	if got := unescapeUnitPath(`srv-my\x2ddisk`); got != "/srv/my-disk" {
		t.Fatalf("unescape: %q", got)
	}
	_, _ = fakeFSCheck(t)
	writeUnit(t, "data.mount", "[Mount]\nWhat=/dev/sdb1\nType=ext4\n")
	writeUnit(t, "srv.mount", "[Mount]\nWhat=/dev/sdc1\nWhere=/srv\nOptions=noauto\n")
	if m, err := bootMountFor("/data/noo"); err != nil || m.where != "/data" || m.by != "systemd unit" {
		t.Fatalf("by name: %+v %v", m, err)
	}
	if m, err := bootMountFor("/srv/noo"); err != nil || m.where != "" {
		t.Fatalf("a noauto unit counted: %+v %v", m, err)
	}
}

// An automount (x-systemd.automount) is touched once, bounded, before it is
// called missing: not mounted, touched, mounted, fine.
func TestAnAutomountIsTouchedBeforeItIsMissing(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	writeFstab(t, "srv:/x /data nfs4 noauto,x-systemd.automount,_netdev 0 0\n")
	touched := 0
	automountTrigger = func(p string) { touched++; disk.mounted = true }
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("an automount that mounts when touched: %v", c)
	}
	if touched != 1 || !recorded("/data/noo") {
		t.Fatalf("touched %d, recorded %v", touched, recorded("/data/noo"))
	}
}

// An autofs trap in the mount table (no fstab line) is touched the same way.
func TestAnAutofsTrapIsTouched(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	if err := os.WriteFile(mountinfoPath, []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n42 22 0:51 / /data rw - autofs systemd-1 rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	touched := 0
	automountTrigger = func(string) { touched++; disk.mounted = true }
	if c := fsCodes(Resolve(os.Getenv)); len(c) != 0 || touched != 1 {
		t.Fatalf("autofs trap: %v, touched %d", c, touched)
	}
}

// An automount whose touch hangs (a dead NFS server) is not_answering
// within the bound; the agent is never held.
func TestAHungAutomountIsNotAnswering(t *testing.T) {
	_, _ = fakeFSCheck(t)
	writeFstab(t, "srv:/x /data nfs4 x-systemd.automount 0 0\n")
	prev := ProbeTimeout
	ProbeTimeout = 100 * time.Millisecond
	release := make(chan struct{})
	automountTrigger = func(string) { <-release }
	t.Cleanup(func() {
		close(release)
		WaitProbeForTest("/data", 3*time.Second)
		ProbeTimeout = prev
	})
	got := make(chan []string, 1)
	r := Resolve(os.Getenv)
	go func() { got <- fsCodes(r) }()
	select {
	case c := <-got:
		allCodes(t, r, c, "not_answering")
	case <-time.After(3 * time.Second):
		t.Fatal("a hung automount held the check past the bound")
	}
}

// A late network mount (nofail, _netdev): refused at start, re-checked on
// every use, cleared by itself when it arrives, with ONE log line.
func TestALateNetworkMountClearsByItself(t *testing.T) {
	disk, calls := fakeFSCheck(t)
	writeFstab(t, "srv:/export /data nfs4 nofail,_netdev 0 0\n")
	var buf bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prevLog) })
	r := Resolve(os.Getenv)
	f := checkFilesystems(r)
	if len(f) != len(fsPaths(r)) || f[0].Code != "mount_missing" || !strings.Contains(f[0].Detail, "network mount") {
		t.Fatalf("at start: %+v", f)
	}
	if err := MkdirAll("/data/noo/models", 0o755); err == nil || *calls != 0 {
		t.Fatalf("refused: %v, %d calls", err, *calls)
	}
	disk.mounted = true
	for i := 0; i < 3; i++ {
		if c := fsCodes(r); len(c) != 0 {
			t.Fatalf("the mount arrived: %v", c)
		}
	}
	if n := strings.Count(buf.String(), clearedLine("/data/noo")); n != 1 {
		t.Fatalf("the cleared line was logged %d times, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(clearedLine("/data/noo"), "data root /data/noo is mounted now; the refusal is cleared") {
		t.Fatal(clearedLine("/data/noo"))
	}
}

// captureLog sends slog to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// A root recorded on the root filesystem (empty at the first look) whose disk
// then arrives: accepted, re-recorded, one plain line.
func TestADiskArrivingOverAnEmptyDirectoryIsAccepted(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r) // recorded on the root filesystem
	buf := captureLog(t)
	disk.mounted = true
	for i := 0; i < 3; i++ {
		if c := fsCodes(r); len(c) != 0 {
			t.Fatalf("the disk arrived over a root-fs record: accept, got %v", c)
		}
	}
	b, _ := os.ReadFile(recordPath())
	if !strings.Contains(string(b), `"uuid": "u-data"`) {
		t.Fatalf("not re-recorded: %s", b)
	}
	want := "data root /data/noo is now on its own filesystem (/dev/sdb1, was on the root filesystem); recorded"
	if n := strings.Count(buf.String(), want); n != 1 || strings.Contains(buf.String(), "hidden") {
		t.Fatalf("want the plain line once, got %d:\n%s", n, buf.String())
	}
	if got := FilesystemReport(r); got["meant"] != "mount" || got["hidden_entries"] != nil {
		t.Fatalf("%v", got)
	}
}

// The same with 3 entries under the root at the first look: they are hidden
// under the mount now. The line and the report say so, with the date, and
// the report drops the note by itself after HiddenNoteFor.
func TestADiskArrivingOverFilesSaysTheyAreHidden(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	now := t0
	prevNow := fsNow
	fsNow = func() time.Time { return now }
	t.Cleanup(func() { fsNow = prevNow })
	countEntries = func(string) (int, bool) { return 3, false }
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r)
	buf := captureLog(t)
	disk.mounted = true
	for i := 0; i < 2; i++ {
		if c := fsCodes(r); len(c) != 0 {
			t.Fatalf("accept, got %v", c)
		}
	}
	note := "the disk is now mounted at /data/noo since 2026-11-22: 3 files written before it was mounted are hidden under the mount point " +
		"on the root filesystem: unmount to recover or remove them; this note clears by itself on 2026-11-29"
	if n := strings.Count(buf.String(), note); n != 1 {
		t.Fatalf("want the hidden-files line once, got %d:\n%s", n, buf.String())
	}
	for _, day := range []int{0, 6} {
		now = t0.Add(time.Duration(day) * 24 * time.Hour)
		if got := FilesystemReport(r); got["hidden_note"] != note || got["hidden_entries"] != 3 {
			t.Fatalf("day %d: the note must still show: %v", day, got)
		}
	}
	now = t0.Add(8 * 24 * time.Hour)
	if got := FilesystemReport(r); got["hidden_note"] != nil || got["hidden_entries"] != nil {
		t.Fatalf("day 8: the note must have cleared by itself: %v", got)
	}
	if got := HiddenNote("/x", 10000, true, t0); !strings.Contains(got, "at least 10000 files") {
		t.Fatal(got)
	}
}

// Recorded on its own disk, now on the root filesystem: refused.
func TestARecordedDiskNowOnTheRootFilesystemIsRefused(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	disk.mounted = true
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r)
	disk.mounted = false
	f := checkFilesystems(r)
	if len(f) != len(fsPaths(r)) || f[0].Code != "not_on_recorded_fs" || !strings.Contains(f[0].Detail, "the ROOT filesystem") {
		t.Fatalf("%+v", f)
	}
}

// Recorded on disk A, now on disk B: refused, and the detail says another
// disk is mounted there.
func TestADifferentDiskIsRefused(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	disk.mounted = true
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r)
	disk.other = true
	f := checkFilesystems(r)
	if len(f) != len(fsPaths(r)) || f[0].Code != "not_on_recorded_fs" || !strings.Contains(f[0].Detail, "on a different filesystem") {
		t.Fatalf("%+v", f)
	}
	b, _ := os.ReadFile(recordPath())
	if !strings.Contains(string(b), `"uuid": "u-data"`) {
		t.Fatalf("a different disk was recorded: %s", b)
	}
}

// A unit that is not enabled, and a masked one (a link to /dev/null, the
// hosted runner's tmp.mount), are not boot-time mounts.
func TestADisabledOrMaskedMountUnitDoesNotCount(t *testing.T) {
	_, _ = fakeFSCheck(t)
	writeUnitOnly(t, "data.mount", "[Mount]\nWhat=/dev/sdb1\nWhere=/data\nType=ext4\n")
	dir := mountUnitDirs()[0]
	if err := os.Symlink(os.DevNull, filepath.Join(dir, "srv.mount")); err != nil {
		t.Fatal(err)
	}
	wants := filepath.Join(dir, "local-fs.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "srv.mount"), filepath.Join(wants, "srv.mount")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/data/noo", "/srv/noo"} {
		if m, err := bootMountFor(p); err != nil || m.where != "" {
			t.Fatalf("%s: a disabled or masked unit counted: %+v %v", p, m, err)
		}
	}
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("%v", c)
	}
}

// "Cannot tell" never refuses: an unreadable mount table, even with a
// record, is reported as not checked.
func TestAnUnreadableMountTableIsNotChecked(t *testing.T) {
	disk, calls := fakeFSCheck(t)
	disk.mounted = true
	r := Resolve(os.Getenv)
	_ = checkFilesystems(r) // recorded on its disk
	fsIdentity = readFSIdentity
	mountinfoPath = filepath.Join(t.TempDir(), "absent")
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("an unreadable mount table refused: %v", c)
	}
	if err := MkdirAll("/data/noo/models", 0o755); err != nil || *calls != 1 {
		t.Fatalf("an unreadable mount table blocked a fetch: %v", err)
	}
	if why, _ := FilesystemReport(r)["not_checked"].(string); !strings.Contains(why, "cannot tell which filesystem holds /data/noo") {
		t.Fatalf("not_checked = %q", why)
	}
	// Garbage is the same.
	if err := os.WriteFile(mountinfoPath, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("an unparsable mount table refused: %v", c)
	}
}

// An unreadable or unparsable fstab, and an unreadable unit directory: on the
// root filesystem with nothing recorded, neither refused nor recorded. Each
// input EXISTS but cannot be read (EISDIR, ENOTDIR: unreadable as root too);
// an absent one declares nothing (TestAbsentBootDeclarationsMeanNone).
func TestUnreadableBootDeclarationsAreNotChecked(t *testing.T) {
	for name, set := range map[string]func(t *testing.T){
		"fstab unreadable": func(t *testing.T) { fstabPath = t.TempDir() },
		"fstab garbage":    func(t *testing.T) { writeFstab(t, "garbage\n") },
		"unit dir": func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "a-file")
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			mountUnitDirs = func() []string { return []string{f} }
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, calls := fakeFSCheck(t)
			set(t)
			r := Resolve(os.Getenv)
			if c := fsCodes(r); len(c) != 0 {
				t.Fatalf("cannot tell, refused: %v", c)
			}
			if recorded("/data/noo") {
				t.Fatal("recorded a root on the root filesystem without its boot declarations")
			}
			if err := MkdirAll("/data/noo/models", 0o755); err != nil || *calls != 1 {
				t.Fatalf("blocked a fetch: %v", err)
			}
			got := FilesystemReport(r)
			if why, _ := got["not_checked"].(string); why == "" || got["meant"] != "unknown" {
				t.Fatalf("report: %v", got)
			}
		})
	}
}

// No /etc/fstab and no unit directory (a container, a host without systemd):
// nothing is declared, so the root is a plain directory, recorded where it
// is, and the check is not "not checked".
func TestAbsentBootDeclarationsMeanNone(t *testing.T) {
	_, calls := fakeFSCheck(t)
	fstabPath = filepath.Join(t.TempDir(), "absent-fstab")
	d := filepath.Join(t.TempDir(), "absent-units")
	mountUnitDirs = func() []string { return []string{d} }
	r := Resolve(os.Getenv)
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("nothing declared: no problem, got %v", c)
	}
	if !recorded("/data/noo") {
		t.Fatal("absent declarations: a plain directory was not recorded")
	}
	if err := MkdirAll("/data/noo/models", 0o755); err != nil || *calls != 1 {
		t.Fatalf("blocked a fetch: %v", err)
	}
	got := FilesystemReport(r)
	if _, ok := got["not_checked"]; ok || got["meant"] != "directory" {
		t.Fatalf("absent declarations are none, not \"cannot tell\": %v", got)
	}
}

// An absent unit directory does not discard a readable fstab: its mount is
// still checked.
func TestAnAbsentUnitDirKeepsTheFstabCheck(t *testing.T) {
	disk, _ := fakeFSCheck(t)
	d := filepath.Join(t.TempDir(), "absent-units")
	mountUnitDirs = func() []string { return []string{d} }
	writeFstab(t, "UUID=u-data /data ext4 defaults 0 2\n")
	r := Resolve(os.Getenv)
	allCodes(t, r, fsCodes(r), "mount_missing")
	disk.mounted = true
	if c := fsCodes(r); len(c) != 0 {
		t.Fatalf("mounted: %v", c)
	}
}

// darwin: the check is a no-op (the policy's other rules still apply).
func TestTheFilesystemCheckIsLinuxOnly(t *testing.T) {
	_, _ = fakeFSCheck(t)
	fsCheckOS = "darwin"
	r := Resolve(os.Getenv)
	if f := checkFilesystems(r); f != nil {
		t.Fatalf("darwin: %v", f)
	}
	if got := FilesystemReport(r)["meant"]; got != "unknown" {
		t.Fatalf("darwin meant = %v", got)
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
