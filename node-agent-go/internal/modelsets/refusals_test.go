// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// Each test here pins ONE refusal or guard of the F4 fetch/seal/prune path so
// that removing that check alone turns it red. The outer layers (the manifest
// parser, the signature) refuse most bad input first; these tests plant the
// bad state past them, or assert the exact reason/detail only the inner check
// gives.

// countManifest wraps the rig's gateway answer with a call counter.
func countManifest(r *rig) *atomic.Int64 {
	var n atomic.Int64
	inner := r.store.Manifest
	r.store.Manifest = func(ctx context.Context, ref Ref) (*Signed, error) {
		n.Add(1)
		return inner(ctx, ref)
	}
	return &n
}

// sealed is a rig with refA fetched and sealed, then reopened for planting.
func sealed(t *testing.T) (*rig, string) {
	t.Helper()
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	dir := r.store.dir(refA)
	if st := r.store.State(refA); st.State != StateVerified {
		t.Fatalf("setup: state = %+v", st)
	}
	if err := makeWritable(dir); err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func wantUnverified(t *testing.T, s *Store, ref Ref, what string) {
	t.Helper()
	if st := s.State(ref); st.State != StateRefused || st.Reason != nodewl.ReasonSetUnverified {
		t.Errorf("%s: state = %+v, want refused/%s", what, st, nodewl.ReasonSetUnverified)
	}
}

// ---- Fetch: what is refused before anyone is asked ----------------------

func TestMalformedSetRefIsRefusedAsSlotInvalid(t *testing.T) {
	for _, ref := range []Ref{
		{"", "r1"},
		{"UPPER", "r1"},
		{"rh-stt-small", ""},
		{"rh-stt-small", "../r1"},
		{"../escape", "r1"},
		{"a/b", "r1"},
	} {
		r := newRig(t)
		asked := countManifest(r)
		err := r.store.Fetch(context.Background(), ref)
		rf, ok := err.(*Refusal)
		if !ok {
			t.Errorf("%+v: want a *Refusal, got %v", ref, err)
			continue
		}
		if rf.Reason != nodewl.ReasonSetSlotInvalid {
			t.Errorf("%+v: reason = %s, want %s", ref, rf.Reason, nodewl.ReasonSetSlotInvalid)
		}
		if asked.Load() != 0 {
			t.Errorf("%+v: the gateway was asked for a malformed ref", ref)
		}
		if _, err := os.Lstat(r.store.Root); err == nil {
			t.Errorf("%+v: the sets root was created for a malformed ref", ref)
		}
	}
}

func TestASetBeingFetchedIsNotFetchedAgain(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	asked := countManifest(r)
	r.store.mu.Lock()
	r.store.setMem(refA, memState{state: StateFetching})
	r.store.mu.Unlock()

	err := r.store.Fetch(context.Background(), refA)
	if err == nil || !strings.Contains(err.Error(), "already being fetched") {
		t.Fatalf("err = %v, want 'already being fetched'", err)
	}
	if _, isRefusal := err.(*Refusal); isRefusal {
		t.Errorf("a duplicate fetch is not a refusal about the set: %v", err)
	}
	if asked.Load() != 0 || r.hits.Load() != 0 {
		t.Errorf("a second fetch started: manifest asks %d, file hits %d", asked.Load(), r.hits.Load())
	}
	if st := r.store.State(refA); st.State != StateFetching {
		t.Errorf("the running fetch's state was disturbed: %+v", st)
	}
}

func TestSymlinkedIDDirIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	asked := countManifest(r)
	outside := t.TempDir()
	if err := os.MkdirAll(r.store.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.store.Root, refA.ID)); err != nil {
		t.Fatal(err)
	}

	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, "symlink") {
		t.Errorf("refusal = %+v", rf)
	}
	if asked.Load() != 0 || r.hits.Load() != 0 {
		t.Errorf("work started under a symlinked path: manifest asks %d, file hits %d", asked.Load(), r.hits.Load())
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("something was written through the symlink: %v", ents)
	}
}

// ---- Fetch: the answer's encoding ---------------------------------------

func TestNotBase64ManifestOrSignatureIsRefusedAsSuch(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(s *Signed)
		detail string
	}{
		{"manifest garbage", func(s *Signed) { s.ManifestB64 = "!!!not base64!!!" }, "manifest_b64"},
		{"manifest empty", func(s *Signed) { s.ManifestB64 = "" }, "manifest_b64"},
		{"signature garbage", func(s *Signed) { s.SigB64 = "!!!not base64!!!" }, "sig_b64"},
		{"signature empty", func(s *Signed) { s.SigB64 = "" }, "sig_b64"},
	} {
		r := newRig(t)
		r.stage(refA, filesA, r.key)
		r.mu.Lock()
		c.mutate(r.manifest[refA])
		r.mu.Unlock()

		err := r.store.Fetch(context.Background(), refA)
		rf, ok := err.(*Refusal)
		if !ok {
			t.Errorf("%s: want a *Refusal, got %v", c.name, err)
			continue
		}
		if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, c.detail+" is not base64") {
			t.Errorf("%s: refusal = %+v, want %q named as not base64", c.name, rf, c.detail)
		}
		if r.hits.Load() != 0 {
			t.Errorf("%s: files were fetched", c.name)
		}
	}
}

// ---- Fetch: the path rule at the point of use ---------------------------

func TestSetFileDestAppliesTheMountPathRule(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "set")
	for _, p := range []string{
		"", ".", "..", "../evil.bin", "a/../b.bin", "/abs.bin", "./x.bin",
		"a//b.bin", "a/b/c.bin", "sp ace.bin", "tab\t.bin", "back\\slash.bin",
		strings.Repeat("a", 130),
	} {
		dest, err := setFileDest(dir, p)
		rf, ok := err.(*Refusal)
		if !ok || rf.Reason != nodewl.ReasonSetUnverified {
			t.Errorf("%q: dest %q err %v, want a set_unverified refusal", p, dest, err)
		}
	}
	for p, want := range map[string]string{
		"model.bin":    filepath.Join(dir, "model.bin"),
		"cfg/tok.json": filepath.Join(dir, "cfg", "tok.json"),
	} {
		if dest, err := setFileDest(dir, p); err != nil || dest != want {
			t.Errorf("%q: dest %q err %v, want %q", p, dest, err, want)
		}
	}
}

// ---- Fetch: what is on disk after the transfer --------------------------

// within is the containment guard behind ValidSetPath / ValidSetRef; both mask
// it today, so it is pinned here directly. A path is judged lexically (Rel
// cleans it), so one that cleans back inside the dir is inside.
func TestWithinRefusesEverythingOutsideTheDir(t *testing.T) {
	dir := filepath.FromSlash("/a/b")
	for _, c := range []struct {
		p    string
		want bool
	}{
		{"/a/b", false}, // the dir itself is not a file under it
		{"/a", false},
		{"/a/b/..", false},
		{"/a/b/../x", false},
		{"/a/b/../../x", false},
		{"/a/bc/x", false}, // shares a prefix, is not under it
		{"/a/bc", false},
		{"/x/y", false},
		{"/", false},
		{"x/y", false}, // relative against an absolute dir
		{"/a/b/x", true},
		{"/a/b/v/x.pt", true},
		{"/a/b/v/../x", true}, // cleans back inside
	} {
		if got := within(dir, filepath.FromSlash(c.p)); got != c.want {
			t.Errorf("within(%q, %q) = %v, want %v", dir, c.p, got, c.want)
		}
	}
}

// planting returns a Files fetcher that does the real download, then lets the
// test do something to the directory.
func planting(r *rig, after func(dest string)) fetcherFunc {
	real := &preseed.Client{HTTP: r.srv.Client()}
	return func(ctx context.Context, u, dest, sha string) (bool, error) {
		ok, err := real.FetchOneVerified(ctx, u, dest, sha)
		if err == nil {
			after(dest)
		}
		return ok, err
	}
}

func TestSymlinkAppearingDuringTheFetchIsRefused(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	outside := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(outside, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := r.store.dir(refA)
	var once sync.Once
	r.store.Files = planting(r, func(string) {
		once.Do(func() { _ = os.Symlink(outside, filepath.Join(dir, "sneaky")) })
	})

	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, "symlink") {
		t.Errorf("refusal = %+v", rf)
	}
	noMarker(t, r.store, refA)
	if b, err := os.ReadFile(outside); err != nil || string(b) != "precious" {
		t.Errorf("the symlink target was touched: %q %v", b, err)
	}
}

func TestAFileThatIsNotTheManifestsSizeOrKindIsNeverSealed(t *testing.T) {
	want := filesA["model.bin"]
	for _, c := range []struct {
		name  string
		plant func(t *testing.T, dest string)
	}{
		{"too short", func(t *testing.T, dest string) {
			if err := os.WriteFile(dest, want[:len(want)-1], 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"too long", func(t *testing.T, dest string) {
			if err := os.WriteFile(dest, append(append([]byte(nil), want...), 'x'), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory", func(t *testing.T, dest string) {
			if err := os.RemoveAll(dest); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		r := newRig(t)
		r.stage(refA, filesA, r.key)
		r.store.Files = planting(r, func(dest string) {
			if filepath.Base(dest) == "model.bin" {
				c.plant(t, dest)
			}
		})

		err := r.store.Fetch(context.Background(), refA)
		rf, ok := err.(*Refusal)
		if !ok {
			t.Errorf("%s: want a *Refusal, got %v", c.name, err)
			continue
		}
		if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, "regular bytes on disk") {
			t.Errorf("%s: refusal = %+v", c.name, rf)
		}
		if _, err := os.Stat(filepath.Join(r.store.dir(refA), MarkerName)); err == nil {
			t.Errorf("%s: a .verified marker was written", c.name)
		}
	}
}

// ---- State: the disk is judged, not the marker alone --------------------

func TestVerifiedSetThatGrewASymlinkReadsUnverified(t *testing.T) {
	t.Run("a link inside the set", func(t *testing.T) {
		r, dir := sealed(t)
		if err := os.Symlink(filepath.Join(dir, "model.bin"), filepath.Join(dir, "alias")); err != nil {
			t.Fatal(err)
		}
		wantUnverified(t, r.store, refA, "symlink inside")
	})
	t.Run("the id directory replaced by a link", func(t *testing.T) {
		r, _ := sealed(t)
		idDir := filepath.Join(r.store.Root, refA.ID)
		moved := filepath.Join(t.TempDir(), "moved")
		if err := os.Rename(idDir, moved); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = makeWritable(moved) })
		if err := os.Symlink(moved, idDir); err != nil {
			t.Fatal(err)
		}
		wantUnverified(t, r.store, refA, "symlinked id dir")
	})
}

func TestVerifiedSetWhoseMarkerNoLongerMatchesTheManifestReadsUnverified(t *testing.T) {
	t.Run("the marker holds another digest", func(t *testing.T) {
		r, dir := sealed(t)
		other := sha256.Sum256([]byte("another manifest"))
		if err := os.WriteFile(filepath.Join(dir, MarkerName), []byte(hex.EncodeToString(other[:])+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		wantUnverified(t, r.store, refA, "foreign marker")
	})
	t.Run("the manifest bytes changed under the marker", func(t *testing.T) {
		r, dir := sealed(t)
		p := filepath.Join(dir, ManifestName)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// Still the same document, one byte longer: only the digest knows.
		if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		wantUnverified(t, r.store, refA, "edited manifest")
	})
}

func TestVerifiedSetHoldingAnotherRevisionsManifestReadsUnverified(t *testing.T) {
	r, dir := sealed(t)
	// A genuine, self-consistent r2 manifest and its matching marker, in r1's
	// directory: the digest and the files all agree, only the identity is wrong.
	other := manifestJSON(t, Ref{refA.ID, "r2"}, filesA)
	sum := sha256.Sum256(other)
	if err := os.WriteFile(filepath.Join(dir, ManifestName), other, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, MarkerName), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantUnverified(t, r.store, refA, "r2 manifest in r1's dir")
}

// ---- Rows ---------------------------------------------------------------

func TestRowsSkipALeftoverPartialNobodyAskedFor(t *testing.T) {
	r := newRig(t)
	r.store.Sync(context.Background(), nil)
	r.store.Wait()
	d := filepath.Join(r.store.Root, "old-set", "r0")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "model.bin.partial"), []byte("half"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, ok := r.store.Rows()
	if !ok || len(rows) != 0 {
		t.Fatalf("rows = %+v ok=%v, want a real empty list (the partial was never asked for)", rows, ok)
	}
}

func TestRowsUnknownWhenAnIDDirIsUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions do not stop root (or Windows): no unreadable directory can be made")
	}
	r := newRig(t)
	r.store.Sync(context.Background(), nil)
	r.store.Wait()
	d := filepath.Join(r.store.Root, "some-set")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
	if rows, ok := r.store.Rows(); ok {
		t.Fatalf("an unreadable id directory reported rows %v", rows)
	}
}

// ---- Prune --------------------------------------------------------------

func TestPruneLeavesARevisionSymlinkAlone(t *testing.T) {
	r := newRig(t)
	outside := t.TempDir()
	precious := filepath.Join(outside, "precious")
	if err := os.WriteFile(precious, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	idDir := filepath.Join(r.store.Root, "old-set")
	if err := os.MkdirAll(idDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(idDir, "r9")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	removed, err := r.store.Prune(map[Ref]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v, a symlinked revision is not ours to remove", removed)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the symlink was removed: %v", err)
	}
	if _, err := os.Stat(precious); err != nil {
		t.Errorf("the link's target was touched: %v", err)
	}
}

func TestPruneSkipsASetBeingFetched(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once, closeRelease sync.Once
	releaseNow := func() { closeRelease.Do(func() { close(release) }) }
	defer releaseNow()
	real := &preseed.Client{HTTP: r.srv.Client()}
	r.store.Files = fetcherFunc(func(ctx context.Context, u, dest, sha string) (bool, error) {
		once.Do(func() { close(entered) })
		<-release
		return real.FetchOneVerified(ctx, u, dest, sha)
	})
	r.store.Sync(context.Background(), []Ref{refA})
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the fetch never started")
	}

	removed, err := r.store.Prune(map[Ref]bool{})
	if err != nil {
		t.Error(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v, a set mid-fetch must be left alone", removed)
	}
	if _, err := os.Stat(r.store.dir(refA)); err != nil {
		t.Errorf("the set directory was pulled from under its fetch: %v", err)
	}

	releaseNow()
	r.store.Wait()
	if st := r.store.State(refA); st.State != StateVerified {
		t.Errorf("state after the fetch finished = %+v", st)
	}
}
