// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The empty mount point against a REAL kernel mount (i1160), no seams: a
// loop-mounted ext4 is the data root; the check records it; it is unmounted,
// leaving an empty directory on the root filesystem; the policy must refuse
// and create nothing under it; remounted, the refusal must clear by itself.
//
// Runs only as root with NOO_REAL_MOUNT_DEV (a loop device holding an ext4,
// attached without autoclear so it survives the unmount) and
// NOO_REAL_MOUNT_AT (where it is mounted) set: the
// dataroot-mount-real workflow does that on a hosted runner. Skipped
// everywhere else.
func TestRealLoopMountEmptyMountPoint(t *testing.T) {
	dev, at := os.Getenv("NOO_REAL_MOUNT_DEV"), os.Getenv("NOO_REAL_MOUNT_AT")
	if dev == "" || at == "" || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root, NOO_REAL_MOUNT_DEV and NOO_REAL_MOUNT_AT (the dataroot-mount-real workflow)")
	}
	resetRecordCache()
	t.Cleanup(resetRecordCache)
	t.Setenv("NOO_AGENT_STATE", t.TempDir())
	t.Setenv("NOO_DATA_ROOT", at)
	t.Setenv(PolicyEnv, "")
	for _, k := range []string{"HF_CACHE_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR"} {
		t.Setenv(k, "")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}
	r := Resolve(os.Getenv)

	// 1. A known-good start: on the loop filesystem, recorded.
	if f := checkFilesystems(r); len(f) != 0 {
		t.Fatalf("mounted: %v", f)
	}
	if !recorded(at) {
		t.Fatalf("%s on its loop filesystem was not recorded", at)
	}
	b, _ := os.ReadFile(recordPath())
	t.Logf("record: %s", b)
	if !strings.Contains(string(b), `"fstype": "ext4"`) || !strings.Contains(string(b), `"target": "`+at+`"`) {
		t.Fatalf("record does not name the loop ext4 at %s: %s", at, b)
	}

	// 2. Unmounted: an empty mount point on the root filesystem.
	run("umount", at)
	if err := Gate(); err == nil || !strings.Contains(err.Error(), "not_on_recorded_fs") {
		t.Fatalf("Gate on an empty mount point (warn mode): %v", err)
	}
	for _, d := range []string{filepath.Join(at, "models"), filepath.Join(at, "hf-cache", "hub")} {
		if err := MkdirAll(d, 0o755); err == nil {
			t.Fatalf("MkdirAll(%s) on an empty mount point was allowed", d)
		}
	}
	if left, err := os.ReadDir(at); err != nil || len(left) != 0 {
		t.Fatalf("the empty mount point must stay empty: %v %v", left, err)
	}

	// 3. Remounted: the refusal clears by itself, and the directory lands on
	// the loop filesystem.
	run("mount", dev, at)
	if err := Gate(); err != nil {
		t.Fatalf("Gate with the mount back: %v", err)
	}
	if err := MkdirAll(filepath.Join(at, "models"), 0o755); err != nil {
		t.Fatalf("MkdirAll with the mount back: %v", err)
	}
	now, _, err := readFSIdentity(filepath.Join(at, "models"))
	if err != nil || now.Target != at || now.FSType != "ext4" {
		t.Fatalf("models dir is on %+v (%v), want the loop ext4 at %s", now, err, at)
	}
}
