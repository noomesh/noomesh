// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake rsync: logs its argv; copies the tree for real unless --dry-run;
// under --dry-run it prints $FAKE_DIFFS (itemized changes) when set.
const migFakeRsync = `#!/bin/sh
echo "rsync $*" >> "$FAKE_LOG"
[ "$FAKE_FAIL" = rsync ] && exit 23
for a in "$@"; do last_prev="$last"; last="$a"; done
src="$last_prev"; dst="$last"
case "$*" in
*--dry-run*) [ -n "$FAKE_DIFFS" ] && printf '%s\n' "$FAKE_DIFFS"; exit 0 ;;
esac
case "$*" in *--delete*) rm -rf "$dst"/* ;; esac
cp -a "$src"/. "$dst"/
exit 0
`

const migFakeFstrim = `#!/bin/sh
echo "fstrim $*" >> "$FAKE_LOG"
[ "$FAKE_FAIL" = fstrim ] && exit 1
exit 0
`

type migRig struct {
	cfg  MigrateConfig
	mnt  string // the "mounted volume"
	src  string // a plaintext state dir
	log  string
	root string
}

func newMigRig(t *testing.T, mounted, root bool) *migRig {
	t.Helper()
	dir := t.TempDir()
	r := &migRig{root: dir, mnt: filepath.Join(dir, "state"), src: filepath.Join(dir, "plain", "postgres"), log: filepath.Join(dir, "log")}
	for _, d := range []string{r.mnt, r.src, filepath.Join(dir, "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(r.src, "PG_VERSION"), []byte("16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	_ = os.MkdirAll(bin, 0o755)
	for n, body := range map[string]string{"rsync": migFakeRsync, "fstrim": migFakeFstrim} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_LOG", r.log)
	t.Setenv("FAKE_FAIL", "")
	t.Setenv("FAKE_DIFFS", "")
	euid := 0
	if !root {
		euid = 1000
	}
	r.cfg = MigrateConfig{
		Volume:  VolumeConfig{EtcNoo: filepath.Join(dir, "etc"), MapperDir: filepath.Join(dir, "mapper"), Geteuid: func() int { return euid }},
		Rsync:   filepath.Join(bin, "rsync"),
		Fstrim:  filepath.Join(bin, "fstrim"),
		Mounted: func(string) bool { return mounted },
	}
	man, _ := json.Marshal(map[string]any{"volume_mountpoint": r.mnt})
	if err := os.WriteFile(filepath.Join(dir, "etc", "at-rest.json"), man, 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *migRig) run(args ...string) (string, string, error) {
	var out, errb bytes.Buffer
	err := runAtRestMigrate(r.cfg, args, &out, &errb)
	return out.String(), errb.String(), err
}

func (r *migRig) logged() string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

func TestMigrateVerbsAreDispatchedByTheVolumeVerbCheck(t *testing.T) {
	// main.go routes on IsAtRestVolumeVerb: copy and wipe must be claimed.
	for _, v := range []string{"create-volume", "copy", "wipe"} {
		if !IsAtRestVolumeVerb([]string{v}) {
			t.Errorf("%s is not routed", v)
		}
	}
	if IsAtRestVolumeVerb([]string{"frobnicate"}) {
		t.Error("an unknown verb was claimed")
	}
}

func TestCopyPreThenFinalThenVerifyCleanSucceeds(t *testing.T) {
	r := newMigRig(t, true, true)
	for _, mode := range []string{"pre", "final", "verify"} {
		out, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", mode)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if !strings.Contains(out, `"ok":true`) || !strings.Contains(out, `"mode":"`+mode+`"`) {
			t.Errorf("%s: result line %q", mode, out)
		}
	}
	b, err := os.ReadFile(filepath.Join(r.mnt, "postgres", "PG_VERSION"))
	if err != nil || string(b) != "16\n" {
		t.Fatalf("not copied: %v %q", err, b)
	}
	log := r.logged()
	want := []string{
		"rsync -aHAXS --numeric-ids " + r.src + "/ " + filepath.Join(r.mnt, "postgres") + "/",
		"rsync -aHAXS --numeric-ids --delete " + r.src + "/",
		"rsync -aHAXS --numeric-ids --checksum --dry-run --delete --itemize-changes " + r.src + "/",
	}
	for _, w := range want {
		if !strings.Contains(log, w) {
			t.Errorf("rsync argv missing %q in:\n%s", w, log)
		}
	}
}

func TestCopyVerifyFailsOnAnyDifference(t *testing.T) {
	r := newMigRig(t, true, true)
	if _, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "pre"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DIFFS", ">fc.t...... base/1/1259")
	out, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "verify")
	if err == nil || !strings.Contains(err.Error(), "1 difference") || !strings.Contains(err.Error(), "base/1/1259") {
		t.Fatalf("a difference must fail the verify naming it: %v", err)
	}
	if out != "" {
		t.Errorf("no result line on failure, got %q", out)
	}
}

func TestCopyNeverWritesOutsideTheVolumeAndRefusesBadInput(t *testing.T) {
	r := newMigRig(t, true, true)
	link := filepath.Join(r.root, "plain", "link")
	if err := os.Symlink(r.src, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"unknown name":     {"copy", "--src", r.src, "--name", "../etc", "--mode", "pre"},
		"unknown mode":     {"copy", "--src", r.src, "--name", "postgres", "--mode", "mirror"},
		"relative src":     {"copy", "--src", "plain/postgres", "--name", "postgres", "--mode", "pre"},
		"symlink src":      {"copy", "--src", link, "--name", "postgres", "--mode", "pre"},
		"src is the vol":   {"copy", "--src", r.mnt, "--name", "postgres", "--mode", "pre"},
		"src under vol":    {"copy", "--src", filepath.Join(r.mnt, "postgres"), "--name", "postgres", "--mode", "pre"},
		"missing src":      {"copy", "--src", filepath.Join(r.root, "nope", "x"), "--name", "postgres", "--mode", "pre"},
		"verify no target": {"copy", "--src", r.src, "--name", "loki", "--mode", "verify"},
	}
	for name, args := range cases {
		if _, _, err := r.run(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if strings.Contains(r.logged(), "rsync") {
		t.Errorf("rsync ran for refused input:\n%s", r.logged())
	}
}

func TestCopyRefusesWhenNotRootOrVolumeClosedOrNoManifest(t *testing.T) {
	args := func(r *migRig) []string {
		return []string{"copy", "--src", r.src, "--name", "postgres", "--mode", "pre"}
	}
	r := newMigRig(t, true, false)
	if _, _, err := r.run(args(r)...); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("non-root: %v", err)
	}
	r = newMigRig(t, false, true)
	if _, _, err := r.run(args(r)...); err == nil || !strings.Contains(err.Error(), "not open") {
		t.Errorf("closed volume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.mnt, "postgres")); err == nil {
		t.Error("a destination was created on a closed volume")
	}
	r = newMigRig(t, true, true)
	_ = os.Remove(filepath.Join(r.root, "etc", "at-rest.json"))
	if _, _, err := r.run(args(r)...); err == nil || !strings.Contains(err.Error(), "records no encrypted state volume") {
		t.Errorf("no manifest: %v", err)
	}
	if strings.Contains(r.logged(), "rsync") {
		t.Error("rsync ran")
	}
}

func TestCopyReportsARsyncFailureAndLeavesTheSource(t *testing.T) {
	r := newMigRig(t, true, true)
	t.Setenv("FAKE_FAIL", "rsync")
	_, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "pre")
	if err == nil || !strings.Contains(err.Error(), "rsync failed") {
		t.Fatalf("%v", err)
	}
	if _, e := os.Stat(filepath.Join(r.src, "PG_VERSION")); e != nil {
		t.Error("the source was touched")
	}
}

func TestWipeRemovesOnlyAfterTheEncryptedCopyExists(t *testing.T) {
	r := newMigRig(t, true, true)
	entry := r.src + "=postgres"
	if _, _, err := r.run("wipe", "--entry", entry); err == nil || !strings.Contains(err.Error(), "no encrypted counterpart") {
		t.Fatalf("wipe without a copy: %v", err)
	}
	if _, e := os.Stat(r.src); e != nil {
		t.Fatal("the only copy was removed")
	}
	if _, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "pre"); err != nil {
		t.Fatal(err)
	}
	out, _, err := r.run("wipe", "--entry", entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(r.src); e == nil {
		t.Error("the plaintext dir is still there")
	}
	if _, e := os.Stat(filepath.Join(r.mnt, "postgres", "PG_VERSION")); e != nil {
		t.Error("the encrypted copy was damaged")
	}
	if !strings.Contains(out, `"fstrim":"ok"`) || !strings.Contains(r.logged(), "fstrim -v "+filepath.Dir(r.src)) {
		t.Errorf("fstrim: %q\n%s", out, r.logged())
	}
}

func TestWipeValidatesEveryEntryBeforeRemovingAny(t *testing.T) {
	r := newMigRig(t, true, true)
	if _, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "pre"); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(r.root, "plain", "stuff")
	_ = os.MkdirAll(other, 0o755)
	for name, args := range map[string][]string{
		"unknown name":       {"wipe", "--entry", r.src + "=postgres", "--entry", other + "=home"},
		"no equals":          {"wipe", "--entry", r.src},
		"inside volume":      {"wipe", "--entry", filepath.Join(r.mnt, "postgres") + "=postgres"},
		"the volume":         {"wipe", "--entry", r.mnt + "=postgres"},
		"shallow":            {"wipe", "--entry", "/tmp=pki"},
		"no entries":         {"wipe"},
		"second has no copy": {"wipe", "--entry", r.src + "=postgres", "--entry", other + "=loki"},
	} {
		if _, _, err := r.run(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, e := os.Stat(r.src); e != nil {
			t.Fatalf("%s: the first entry was removed before the second was validated", name)
		}
	}
}

func TestWipeIsRootAndMountedOnly(t *testing.T) {
	r := newMigRig(t, false, true)
	if _, _, err := r.run("wipe", "--entry", r.src+"=postgres"); err == nil {
		t.Error("wiped with the volume closed")
	}
	r = newMigRig(t, true, false)
	if _, _, err := r.run("wipe", "--entry", r.src+"=postgres"); err == nil {
		t.Error("wiped as non-root")
	}
}

func TestWipeFstrimFailureIsNotFatalButSaid(t *testing.T) {
	r := newMigRig(t, true, true)
	if _, _, err := r.run("copy", "--src", r.src, "--name", "postgres", "--mode", "pre"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_FAIL", "fstrim")
	out, _, err := r.run("wipe", "--entry", r.src+"=postgres")
	if err != nil || !strings.Contains(out, `"fstrim":"failed"`) {
		t.Fatalf("%v %q", err, out)
	}
}
