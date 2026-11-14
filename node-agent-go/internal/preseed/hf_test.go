// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── fixtures ────────────────────────────────────────────

const testRev = "0123456789abcdef0123456789abcdef01234567"

// storeTree writes the controller side of a repo to a REAL directory and
// serves it with http.FileServer — the transport is mocked, the files are
// not. Returns the repo's base URL (…/hf/models--org--m/) and a hit counter.
func storeTree(t *testing.T, files map[string]string) (string, *atomic.Int32) {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, "hf", "models--org--m", "snapshots", testRev, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var hits atomic.Int32
	fs := http.FileServer(http.Dir(root))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fs.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/hf/models--org--m/", &hits
}

func manifestFor(files map[string]string) *HFManifest {
	m := &HFManifest{Rev: testRev}
	for p, body := range files {
		m.Files = append(m.Files, HFFile{Path: p, Bytes: int64(len(body)), SHA256: shaHex([]byte(body))})
	}
	return m
}

var released = map[string]string{
	"config.json":           `{"model_type":"gemma"}`,
	"model.safetensors":     "RELEASED-WEIGHT-BYTES-0001",
	"1_Pooling/config.json": `{"pooling":"mean"}`,
}

func snapFile(dest, p string) string {
	return filepath.Join(dest, "snapshots", testRev, filepath.FromSlash(p))
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ── MirrorHFRepo ────────────────────────────────────────

// The mock-the-transport test: real files on both ends, a real HTTP server,
// the real verify-while-streaming path.
func TestMirrorHFRepoLandsTheVerifiedSnapshotFromRealFiles(t *testing.T) {
	base, _ := storeTree(t, released)
	dest := filepath.Join(t.TempDir(), "hub", "models--org--m")
	// A stray planted in the snapshot dir: not part of the verified snapshot.
	stray := snapFile(dest, "extra.py")
	if err := os.MkdirAll(filepath.Dir(stray), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("import os"), 0o644); err != nil {
		t.Fatal(err)
	}
	var lastDone, lastTotal int64
	n, err := New().MirrorHFRepo(context.Background(), base, dest, manifestFor(released), func(d, tot int64) { lastDone, lastTotal = d, tot })
	if err != nil {
		t.Fatalf("MirrorHFRepo: %v", err)
	}
	if n != len(released) {
		t.Errorf("downloaded %d, want %d", n, len(released))
	}
	for p, body := range released {
		if got := readFile(t, snapFile(dest, p)); got != body {
			t.Errorf("%s = %q", p, got)
		}
	}
	if got := readFile(t, filepath.Join(dest, "refs", "main")); got != testRev {
		t.Errorf("refs/main = %q", got)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Error("an unlisted file in the snapshot must be removed")
	}
	if lastDone != lastTotal || lastTotal != manifestFor(released).TotalBytes() {
		t.Errorf("progress ended at %d/%d", lastDone, lastTotal)
	}
}

// THE bug: a same-size local file with different bytes used to be kept.
func TestMirrorHFRepoSameSizeTamperedFileIsRefetchedAndReplaced(t *testing.T) {
	base, _ := storeTree(t, released)
	dest := filepath.Join(t.TempDir(), "models--org--m")
	w := snapFile(dest, "model.safetensors")
	tampered := strings.Repeat("X", len(released["model.safetensors"]))
	if err := os.MkdirAll(filepath.Dir(w), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().MirrorHFRepo(context.Background(), base, dest, manifestFor(released), nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, w); got != released["model.safetensors"] {
		t.Fatalf("a same-size tampered weight was kept: %q", got)
	}
}

func TestMirrorHFRepoWithoutAManifestTouchesNothing(t *testing.T) {
	base, hits := storeTree(t, released)
	dest := filepath.Join(t.TempDir(), "models--org--m")
	noDigest := manifestFor(released)
	noDigest.Files[0].SHA256 = ""
	for name, m := range map[string]*HFManifest{"nil": nil, "a file without a digest": noDigest, "no files": {Rev: testRev}} {
		if _, err := New().MirrorHFRepo(context.Background(), base, dest, m, nil); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if !errors.Is(func() error { _, err := New().MirrorHFRepo(context.Background(), base, dest, nil, nil); return err }(), ErrNoManifest) {
		t.Error("a nil manifest is ErrNoManifest")
	}
	if hits.Load() != 0 {
		t.Errorf("the store was contacted %d time(s) without a usable manifest", hits.Load())
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("nothing may be written without a usable manifest")
	}
}

// The store serves bytes that do not match the manifest: refused, the
// destination keeps what it had, and refs/main is not (re)pointed.
func TestMirrorHFRepoBytesThatDoNotMatchTheManifestAreRefusedDestUnchanged(t *testing.T) {
	served := map[string]string{"config.json": released["config.json"], "model.safetensors": "EVIL-WEIGHT-BYTES-0000000"}
	base, _ := storeTree(t, served)
	dest := filepath.Join(t.TempDir(), "models--org--m")
	w := snapFile(dest, "model.safetensors")
	if err := os.MkdirAll(filepath.Dir(w), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := manifestFor(map[string]string{"config.json": released["config.json"], "model.safetensors": released["model.safetensors"]})
	_, err := New().MirrorHFRepo(context.Background(), base, dest, m, nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	if got := readFile(t, w); got != "OLD" {
		t.Fatalf("dest changed to %q", got)
	}
	if _, err := os.Stat(w + ".partial"); !os.IsNotExist(err) {
		t.Fatal("the mismatching partial must be removed")
	}
	if _, err := os.Stat(filepath.Join(dest, "refs", "main")); !os.IsNotExist(err) {
		t.Fatal("refs/main must not point at a snapshot that did not verify")
	}
}

// A model container plants a symlink where a snapshot directory belongs;
// the mirror must not write through it.
func TestMirrorHFRepoDoesNotWriteThroughAPlantedLink(t *testing.T) {
	base, _ := storeTree(t, released)
	dest := filepath.Join(t.TempDir(), "models--org--m")
	outside := t.TempDir()
	snap := filepath.Join(dest, "snapshots", testRev)
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(snap, "1_Pooling")); err != nil {
		t.Fatal(err)
	}
	if _, err := New().MirrorHFRepo(context.Background(), base, dest, manifestFor(released), nil); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("wrote through the planted link: %v", ents)
	}
	if fi, err := os.Lstat(filepath.Join(snap, "1_Pooling")); err != nil || !fi.IsDir() {
		t.Fatalf("1_Pooling must be a real directory now: %v %v", fi, err)
	}
}

// ── VerifyHFRepoLocal (the controller-unreachable fallback) ──

func mirrored(t *testing.T) (string, *HFManifest) {
	t.Helper()
	base, _ := storeTree(t, released)
	dest := filepath.Join(t.TempDir(), "models--org--m")
	m := manifestFor(released)
	if _, err := New().MirrorHFRepo(context.Background(), base, dest, m, nil); err != nil {
		t.Fatal(err)
	}
	return dest, m
}

func TestVerifyHFRepoLocalAcceptsOnlyAVerifiedCopy(t *testing.T) {
	dest, m := mirrored(t)
	if err := New().VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatalf("an intact copy must verify: %v", err)
	}
	// Same size, different bytes: refused, by hash.
	w := snapFile(dest, "model.safetensors")
	if err := os.WriteFile(w, []byte(strings.Repeat("Y", len(released["model.safetensors"]))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().VerifyHFRepoLocal(dest, m, nil); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a tampered local copy must be refused with ErrDigestMismatch, got %v", err)
	}
	// A snapshot directory that merely exists is not a verified copy.
	if err := New().VerifyHFRepoLocal(dest, nil, nil); err == nil {
		t.Fatal("no manifest, no local verification")
	}
}

func TestVerifyHFRepoLocalRefusesAnotherRevision(t *testing.T) {
	dest, m := mirrored(t)
	if err := os.WriteFile(filepath.Join(dest, "refs", "main"), []byte(strings.Repeat("b", 40)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().VerifyHFRepoLocal(dest, m, nil); err == nil || !strings.Contains(err.Error(), "refs/main") {
		t.Fatalf("refs/main pointing elsewhere must be refused, got %v", err)
	}
}

// ── the verified-digest record ──────────────────────────

func newRecord(t *testing.T) *VerifiedRecord {
	t.Helper()
	return OpenVerifiedRecord(filepath.Join(t.TempDir(), "state", "verified", "hf-weights.json"))
}

func withRecord(r *VerifiedRecord) *Client { c := New(); c.Record = r; return c }

func TestRecordHitSkipsTheRehash(t *testing.T) {
	dest, m := mirrored(t)
	rec := newRecord(t)
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	before := hashCalls.Load()
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	if got := hashCalls.Load() - before; got != 0 {
		t.Fatalf("a record hit re-hashed %d file(s)", got)
	}
	// The record survives a restart (a fresh in-memory copy of the same file).
	fresh := &VerifiedRecord{path: rec.path}
	before = hashCalls.Load()
	if err := withRecord(fresh).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	if got := hashCalls.Load() - before; got != 0 {
		t.Fatalf("a reloaded record re-hashed %d file(s)", got)
	}
	if fi, err := os.Stat(rec.path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record file must be 0600: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(rec.path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("record dir must be 0700: %v %v", fi, err)
	}
}

// Every identity field is load-bearing: change any one and it is a miss.
func TestRecordMissesOnAnyChangedIdentityField(t *testing.T) {
	dest, m := mirrored(t)
	rec := newRecord(t)
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	w := snapFile(dest, "model.safetensors")
	want := shaHex([]byte(released["model.safetensors"]))
	if !rec.Verified(w, want) {
		t.Fatal("precondition: a hit")
	}
	key := recordKey(w)
	orig := rec.data.Files[key]
	for name, mut := range map[string]func(*recordEntry){
		"dev":    func(e *recordEntry) { e.Dev++ },
		"inode":  func(e *recordEntry) { e.Ino++ },
		"size":   func(e *recordEntry) { e.Size++ },
		"mtime":  func(e *recordEntry) { e.MtimeNs++ },
		"ctime":  func(e *recordEntry) { e.CtimeNs++ },
		"sha256": func(e *recordEntry) { e.SHA256 = strings.Repeat("0", 64) },
	} {
		e := orig
		mut(&e)
		rec.data.Files[key] = e
		if rec.Verified(w, want) {
			t.Errorf("a record whose %s differs must not hit", name)
		}
	}
	rec.data.Files[key] = orig
	if rec.Verified(w, strings.Repeat("1", 64)) {
		t.Error("a record hit must be for the digest asked for")
	}
}

// A same-size, same-inode rewrite with mtime set back: ctime moved, so the
// record misses, the file is re-hashed, and the copy is REFUSED.
func TestAChangedFileWithAStaleRecordIsRehashedAndRefused(t *testing.T) {
	dest, m := mirrored(t)
	rec := newRecord(t)
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	w := snapFile(dest, "model.safetensors")
	fi, err := os.Stat(w)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)        // past a coarse timestamp tick
	f, err := os.OpenFile(w, os.O_WRONLY, 0) // in place: same inode
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("Z"), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chtimes(w, fi.ModTime(), fi.ModTime()); err != nil { // mtime set back
		t.Fatal(err)
	}
	before := hashCalls.Load()
	err = withRecord(rec).VerifyHFRepoLocal(dest, m, nil)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a rewritten weight under a stale record must be refused, got %v", err)
	}
	if hashCalls.Load() == before {
		t.Fatal("the changed file was not re-hashed")
	}
	if rec.Verified(w, shaHex([]byte(released["model.safetensors"]))) {
		t.Fatal("the stale entry must be forgotten")
	}
}

func TestRecordReplacedByACopyIsRehashedAndStillVerifies(t *testing.T) {
	dest, m := mirrored(t)
	rec := newRecord(t)
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	w := snapFile(dest, "model.safetensors")
	// Same bytes, new inode.
	if err := os.Remove(w); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w, []byte(released["model.safetensors"]), 0o644); err != nil {
		t.Fatal(err)
	}
	before := hashCalls.Load()
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	if hashCalls.Load()-before != 1 {
		t.Fatalf("exactly the replaced file must be re-hashed, got %d", hashCalls.Load()-before)
	}
}

func TestARecordNotOnlyOursIsIgnored(t *testing.T) {
	dest, m := mirrored(t)
	path := filepath.Join(t.TempDir(), "state", "hf-weights.json")
	rec := OpenVerifiedRecord(path)
	if err := withRecord(rec).VerifyHFRepoLocal(dest, m, nil); err != nil {
		t.Fatal(err)
	}
	w := snapFile(dest, "model.safetensors")
	want := shaHex([]byte(released["model.safetensors"]))

	reload := func() *VerifiedRecord { return &VerifiedRecord{path: path} }
	if !reload().Verified(w, want) {
		t.Fatal("precondition: a reloaded trusted record hits")
	}
	// Group-writable file: someone else could have written it.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if reload().Verified(w, want) {
		t.Error("a group-writable record must be ignored")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Group-writable directory: the file could be swapped by rename.
	if err := os.Chmod(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	if reload().Verified(w, want) {
		t.Error("a record in a group-writable directory must be ignored")
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// A link in place of the file.
	real := path + ".real"
	if err := os.Rename(path, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if reload().Verified(w, want) {
		t.Error("a record that is a symlink must be ignored")
	}
	_ = os.Remove(path)
	_ = os.Rename(real, path)
	// Owned by someone else (needs root to set up).
	if os.Getuid() == 0 {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if reload().Verified(w, want) {
			t.Error("a record owned by another uid must be ignored")
		}
	}
}

func TestARecordUnderAContainerMountIsNeverUsed(t *testing.T) {
	hfCache := t.TempDir()
	rec := OpenVerifiedRecord(filepath.Join(hfCache, "hub", ".noo-verified.json"), "/elsewhere", hfCache)
	if rec.Disabled() == "" {
		t.Fatal("a record under a directory mounted into model containers must be disabled")
	}
	f := filepath.Join(hfCache, "w")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec.Remember(f, shaHex([]byte("x")))
	if rec.Verified(f, shaHex([]byte("x"))) {
		t.Fatal("a disabled record must never hit")
	}
	if _, err := os.Stat(rec.Path()); !os.IsNotExist(err) {
		t.Fatal("a disabled record must never be written")
	}
	// Reached through a symlink into the mount: still under it.
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(hfCache, link); err != nil {
		t.Fatal(err)
	}
	if OpenVerifiedRecord(filepath.Join(link, "r.json"), hfCache).Disabled() == "" {
		t.Fatal("a record reached through a link into the mount must be disabled")
	}
	if OpenVerifiedRecord(filepath.Join(t.TempDir(), "r.json"), hfCache).Disabled() != "" {
		t.Fatal("a record outside the mounts must be usable")
	}
}

// ── manifest shape ──────────────────────────────────────

func TestHFManifestValidateRefusesEveryUnverifiableShape(t *testing.T) {
	good := func() *HFManifest { return manifestFor(map[string]string{"a/b.json": "x"}) }
	if err := good().Validate(); err != nil {
		t.Fatalf("good manifest: %v", err)
	}
	for name, mut := range map[string]func(*HFManifest){
		"short rev":       func(m *HFManifest) { m.Rev = "abc" },
		"empty digest":    func(m *HFManifest) { m.Files[0].SHA256 = "" },
		"non-hex digest":  func(m *HFManifest) { m.Files[0].SHA256 = strings.Repeat("z", 64) },
		"dotdot path":     func(m *HFManifest) { m.Files[0].Path = "../x" },
		"absolute path":   func(m *HFManifest) { m.Files[0].Path = "/etc/x" },
		"empty segment":   func(m *HFManifest) { m.Files[0].Path = "a//b" },
		"duplicate":       func(m *HFManifest) { m.Files = append(m.Files, m.Files[0]) },
		"negative size":   func(m *HFManifest) { m.Files[0].Bytes = -1 },
		"no files at all": func(m *HFManifest) { m.Files = nil },
	} {
		m := good()
		mut(m)
		if m.Validate() == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// ── lowered priority ────────────────────────────────────

func TestHashRunsOnALoweredPriorityThread(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-thread nice is Linux-only")
	}
	var nice int
	_, err := hashNiced(func() (string, error) {
		b, err := os.ReadFile("/proc/thread-self/stat")
		if err != nil {
			return "", err
		}
		// Field 19 is nice; fields after the ")" of comm start at 3.
		rest := string(b[strings.LastIndexByte(string(b), ')')+2:])
		fields := strings.Fields(rest)
		nice, err = strconv.Atoi(fields[19-3])
		return "", err
	})
	if err != nil {
		t.Fatal(err)
	}
	if nice < 10 {
		t.Fatalf("the hash ran at nice %d, want >= 10", nice)
	}
}
