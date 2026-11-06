// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

const huge = uint64(1) << 50

// rig is a Store wired to a test key, a fake gateway answer and an httptest
// model cache. Nothing here touches the network or the real data root.
type rig struct {
	t      *testing.T
	store  *Store
	key    *ecdsa.PrivateKey
	files  map[string][]byte // what the cache serves, by set path
	srv    *httptest.Server
	hits   atomic.Int64 // file requests the cache answered
	failOn atomic.Value // a path the cache answers 500 for ("" = none)

	mu       sync.Mutex
	manifest map[Ref]*Signed // what the gateway answers
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writePub(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "signing.pub")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sign is `openssl dgst -sha256 -sign`: DER ECDSA over the SHA-256 digest.
func sign(t *testing.T, k *ecdsa.PrivateKey, b []byte) []byte {
	t.Helper()
	d := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// manifestJSON is a valid noo-model-set/1 document over files.
func manifestJSON(t *testing.T, ref Ref, files map[string][]byte) []byte {
	t.Helper()
	var fl []map[string]any
	for p, b := range files {
		sum := sha256.Sum256(b)
		fl = append(fl, map[string]any{"path": p, "bytes": len(b), "sha256": hex.EncodeToString(sum[:])})
	}
	doc := map[string]any{
		"format": "noo-model-set/1", "id": ref.ID, "revision": ref.Revision,
		"kind": "voice", "modality": "stt", "runtime": []string{"rh-stt"},
		"source":  map[string]any{"local": map[string]any{"verified": true}},
		"license": map[string]any{"id": "MIT", "url": "https://example.invalid/mit", "accept": "none"},
		"files":   fl,
		"needs": map[string]any{
			"profiles":     []map[string]any{{"name": "cpu", "accel": "cpu"}},
			"cpu_fallback": true, "arch": []string{"amd64"},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, key: newKey(t), files: map[string][]byte{}, manifest: map[Ref]*Signed{}}
	r.failOn.Store("")
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// /sets/<id>/<rev>/<path...>
		parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/sets/"), "/", 3)
		if len(parts) != 3 {
			http.NotFound(w, req)
			return
		}
		r.hits.Add(1)
		if parts[2] == r.failOn.Load().(string) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		b, ok := r.files[parts[2]]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	r.store = &Store{
		Root:       filepath.Join(t.TempDir(), "models", "sets"),
		SigningPub: writePub(t, r.key),
		Files:      &preseed.Client{HTTP: r.srv.Client()},
		CacheURL:   func() string { return r.srv.URL },
		Free:       func(string) (uint64, error) { return huge, nil },
		Now:        func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	r.store.Manifest = func(_ context.Context, ref Ref) (*Signed, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if s, ok := r.manifest[ref]; ok {
			return s, nil
		}
		return nil, ErrNotStaged
	}
	// Sealed sets are 0555: reopen them so TempDir can remove them.
	t.Cleanup(func() {
		r.store.Wait()
		_ = makeWritable(filepath.Dir(r.store.Root))
	})
	return r
}

// stage publishes a set: the cache serves files, the gateway answers a
// manifest signed by key.
func (r *rig) stage(ref Ref, files map[string][]byte, key *ecdsa.PrivateKey) []byte {
	r.t.Helper()
	m := manifestJSON(r.t, ref, files)
	for p, b := range files {
		r.files[p] = b
	}
	r.mu.Lock()
	r.manifest[ref] = &Signed{
		ID: ref.ID, Revision: ref.Revision,
		ManifestB64: base64.StdEncoding.EncodeToString(m),
		SigB64:      base64.StdEncoding.EncodeToString(sign(r.t, key, m)),
	}
	r.mu.Unlock()
	return m
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want a *Refusal, got %v", err)
	}
	return r
}

func noMarker(t *testing.T, s *Store, ref Ref) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s.dir(ref), MarkerName)); err == nil {
		t.Fatalf("%s has a .verified marker, it must not", ref)
	}
	if st := s.State(ref); st.State == StateVerified {
		t.Fatalf("%s reads verified without a marker", ref)
	}
}

var (
	refA   = Ref{"rh-stt-small", "r1"}
	filesA = map[string][]byte{"model.bin": []byte("weights-of-the-model"), "cfg/tok.json": []byte(`{"t":1}`)}
)

func TestHappyPathVerifiesSealsAndReports(t *testing.T) {
	r := newRig(t)
	m := r.stage(refA, filesA, r.key)

	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	if st := r.store.State(refA); st.State != StateVerified {
		t.Fatalf("state = %+v", st)
	}
	dir := r.store.dir(refA)
	got, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil || string(got) != string(m) {
		t.Fatalf("model-set.json is not the exact signed bytes: %v", err)
	}
	sum := sha256.Sum256(m)
	if mk, _ := os.ReadFile(filepath.Join(dir, MarkerName)); strings.TrimSpace(string(mk)) != hex.EncodeToString(sum[:]) {
		t.Fatalf("marker = %q", mk)
	}
	for p, b := range filesA {
		fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || fi.Mode().Perm() != 0o444 {
			t.Fatalf("%s: %v mode %v, want 0444", p, err, fi)
		}
		if c, _ := os.ReadFile(filepath.Join(dir, p)); string(c) != string(b) {
			t.Fatalf("%s: wrong bytes", p)
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, "cfg")} {
		if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() != 0o555 {
			t.Fatalf("%s: %v mode %v, want 0555", d, err, fi)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "model.bin.partial")); err == nil {
		t.Fatal("a .partial survived")
	}
	// Already verified: a second Fetch asks nobody.
	hits := r.hits.Load()
	r.store.Manifest = func(context.Context, Ref) (*Signed, error) {
		t.Fatal("manifest asked for a verified set")
		return nil, nil
	}
	if err := r.store.Fetch(context.Background(), refA); err != nil || r.hits.Load() != hits {
		t.Fatalf("second fetch: %v hits %d->%d", err, hits, r.hits.Load())
	}
}

func TestBadSignatureIsRefusedBeforeAnyFileMoves(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, newKey(t)) // signed by a key the node does not hold

	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
	if r.hits.Load() != 0 {
		t.Fatalf("%d files were fetched under a bad signature", r.hits.Load())
	}
	noMarker(t, r.store, refA)
	if st := r.store.State(refA); st.State != StateRefused || st.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("state = %+v", st)
	}
}

func TestSignatureCoversTheExactBytes(t *testing.T) {
	r := newRig(t)
	m := r.stage(refA, filesA, r.key)
	// Same JSON, one added space: a re-serialisation the signature must catch.
	re := append([]byte(nil), m...)
	re = append(re, ' ')
	r.mu.Lock()
	r.manifest[refA].ManifestB64 = base64.StdEncoding.EncodeToString(re)
	r.mu.Unlock()
	if rf := refusalOf(t, r.store.Fetch(context.Background(), refA)); rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
}

func TestNoSigningKeyIsUnverified(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	r.store.SigningPub = filepath.Join(t.TempDir(), "absent.pub")
	if rf := refusalOf(t, r.store.Fetch(context.Background(), refA)); rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
	r.store.SigningPub = ""
	r.store.clearMem(refA)
	if rf := refusalOf(t, r.store.Fetch(context.Background(), refA)); rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
}

func TestSigningKeyMustBeP384(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(writePub(t, k)); err == nil {
		t.Fatal("a P-256 key was accepted")
	}
}

func TestManifestIDRevisionMismatchIsRefused(t *testing.T) {
	r := newRig(t)
	other := Ref{"rh-stt-small", "r2"}
	// The gateway answers r1's request with a validly signed r2 manifest.
	r.stage(other, filesA, r.key)
	r.mu.Lock()
	r.manifest[refA] = r.manifest[other]
	r.mu.Unlock()

	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, "asked for") {
		t.Fatalf("refusal = %+v", rf)
	}
	if r.hits.Load() != 0 {
		t.Fatal("files fetched for the wrong revision")
	}
	noMarker(t, r.store, refA)
}

func TestTamperedFileByteIsRefusedAndNeverVerified(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	r.files["model.bin"] = []byte("weights-of-the-modeL") // same length, one byte changed

	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
	noMarker(t, r.store, refA)
	if _, err := os.Stat(filepath.Join(r.store.dir(refA), "model.bin")); err == nil {
		t.Fatal("the tampered file landed under its final name")
	}
}

func TestDotDotPathIsRefused(t *testing.T) {
	r := newRig(t)
	files := map[string][]byte{"../evil.bin": []byte("x")}
	r.stage(refA, files, r.key)
	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("reason = %s", rf.Reason)
	}
	if r.hits.Load() != 0 {
		t.Fatal("a file was fetched for a manifest with a .. path")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.store.dir(refA)), "evil.bin")); err == nil {
		t.Fatal("a file escaped the set directory")
	}
	noMarker(t, r.store, refA)
}

func TestNotEnoughDiskIsRefusedAsDisk(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	var asked string
	r.store.Free = func(p string) (uint64, error) { asked = p; return DiskMarginMin, nil } // the margin and nothing more
	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonDisk {
		t.Fatalf("reason = %s", rf.Reason)
	}
	if asked == "" || !strings.HasPrefix(asked, filepath.Dir(r.store.Root)) {
		t.Fatalf("free space was read at %q, not under the data root", asked)
	}
	if r.hits.Load() != 0 {
		t.Fatal("files fetched with no room for them")
	}
	if st := r.store.State(refA); st.State != StateRefused || st.Reason != nodewl.ReasonDisk {
		t.Fatalf("state = %+v", st)
	}
	// Room for the files plus the margin: proceeds.
	r.store.clearMem(refA)
	r.store.Free = func(string) (uint64, error) { return DiskMarginMin + 1<<20, nil }
	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
}

func TestMarginIsTheLargerOfFloorAndPercent(t *testing.T) {
	if margin(1<<20) != DiskMarginMin {
		t.Fatal("small sets get the floor")
	}
	if got := margin(100 << 30); got != 10<<30 {
		t.Fatalf("100 GiB set margin = %d, want 10 GiB", got)
	}
}

func TestCrashMidFetchLeavesNoMarkerAndTheNextTryCompletes(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	r.failOn.Store("model.bin") // the transfer dies partway through the set

	err := r.store.Fetch(context.Background(), refA)
	if err == nil {
		t.Fatal("a failed transfer reported success")
	}
	var rf *Refusal
	if errors.As(err, &rf) {
		t.Fatalf("a transport failure is not a refusal about the set: %v", err)
	}
	noMarker(t, r.store, refA)
	if st := r.store.State(refA); st.State == StateVerified || st.State == StateRefused {
		t.Fatalf("state after a crash = %+v", st)
	}

	// A process that died holding the lock leaves the same disk: simulate it
	// with a fresh Store over the same Root.
	fresh := &Store{Root: r.store.Root, SigningPub: r.store.SigningPub, Manifest: r.store.Manifest,
		Files: r.store.Files, CacheURL: r.store.CacheURL, Free: r.store.Free, Now: r.store.Now}
	r.failOn.Store("")
	if err := fresh.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	if st := fresh.State(refA); st.State != StateVerified {
		t.Fatalf("state = %+v", st)
	}
}

func TestADirectoryWithoutMarkerIsNeverVerified(t *testing.T) {
	r := newRig(t)
	m := r.stage(refA, filesA, r.key)
	dir := r.store.dir(refA)
	if err := os.MkdirAll(filepath.Join(dir, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, ManifestName), m, 0o444)
	for p, b := range filesA {
		_ = os.WriteFile(filepath.Join(dir, p), b, 0o444)
	}
	if st := r.store.State(refA); st.State != StateAbsent {
		t.Fatalf("complete files, no marker: state = %+v", st)
	}
}

func TestVerifiedSetThatChangedOnDiskReadsUnverified(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	dir := r.store.dir(refA)
	if err := makeWritable(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "model.bin")); err != nil {
		t.Fatal(err)
	}
	if st := r.store.State(refA); st.State != StateRefused || st.Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("state = %+v", st)
	}
	// And it heals: the next Fetch re-fetches the missing file.
	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	if st := r.store.State(refA); st.State != StateVerified {
		t.Fatalf("state = %+v", st)
	}
}

func TestSymlinkUnderTheSetIsRefused(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	dir := r.store.dir(refA)
	outside := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "cfg")); err != nil {
		t.Fatal(err)
	}
	rf := refusalOf(t, r.store.Fetch(context.Background(), refA))
	if rf.Reason != nodewl.ReasonSetUnverified || !strings.Contains(rf.Detail, "symlink") {
		t.Fatalf("refusal = %+v", rf)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("a file was written through the symlink")
	}
	noMarker(t, r.store, refA)
}

func TestNotStagedIsSetMissing(t *testing.T) {
	r := newRig(t)
	if rf := refusalOf(t, r.store.Fetch(context.Background(), refA)); rf.Reason != nodewl.ReasonSetMissing {
		t.Fatalf("reason = %s", rf.Reason)
	}
}

func TestControllerStagedCopyIsNeverTouched(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	dir := r.store.dir(refA)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, railSigName), []byte("sig"), 0o644)
	if rf := refusalOf(t, r.store.Fetch(context.Background(), refA)); rf.Reason != nodewl.ReasonControllerHost {
		t.Fatalf("reason = %s", rf.Reason)
	}
	if removed, err := r.store.Prune(map[Ref]bool{}); err != nil || len(removed) != 0 {
		t.Fatalf("prune removed the rail's staging: %v %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, railSigName)); err != nil {
		t.Fatal(err)
	}
}

func TestPruneKeepsReferencedAndTouchesNothingOutsideSets(t *testing.T) {
	r := newRig(t)
	r1, r2 := Ref{"rh-stt-small", "r1"}, Ref{"rh-stt-small", "r2"}
	r.stage(r1, filesA, r.key)
	r.stage(r2, filesA, r.key)
	for _, ref := range []Ref{r1, r2} {
		if err := r.store.Fetch(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	// Neighbours of Root: a gguf beside sets/, and a file in sets/ itself.
	models := filepath.Dir(r.store.Root)
	gguf := filepath.Join(models, "weights.gguf")
	stray := filepath.Join(r.store.Root, "notes.txt")
	// A symlinked id dir that points outside must be left alone, target included.
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "precious"), []byte("x"), 0o644)
	_ = os.WriteFile(gguf, []byte("g"), 0o644)
	_ = os.WriteFile(stray, []byte("n"), 0o644)
	if err := os.Symlink(outside, filepath.Join(r.store.Root, "linked-id")); err != nil {
		t.Fatal(err)
	}

	removed, err := r.store.Prune(map[Ref]bool{r2: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != r1 {
		t.Fatalf("removed = %v, want [%s]", removed, r1)
	}
	if st := r.store.State(r1); st.State != StateAbsent {
		t.Fatalf("pruned set state = %+v", st)
	}
	if st := r.store.State(r2); st.State != StateVerified {
		t.Fatalf("kept set state = %+v", st)
	}
	for _, p := range []string{gguf, stray, filepath.Join(outside, "precious")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("prune touched %s: %v", p, err)
		}
	}
	// Nothing referenced is a decision the CALLER makes; an empty keep removes the rest.
	if removed, _ := r.store.Prune(map[Ref]bool{}); len(removed) != 1 {
		t.Fatalf("removed = %v", removed)
	}
	if _, err := os.Stat(filepath.Join(r.store.Root, r1.ID)); err == nil {
		t.Fatal("an emptied id directory was left behind")
	}
}

func TestPruneWithMissingRootIsNotAnError(t *testing.T) {
	r := newRig(t)
	if removed, err := r.store.Prune(map[Ref]bool{}); err != nil || removed != nil {
		t.Fatalf("%v %v", removed, err)
	}
}

func TestRowsAreUnknownUntilDesiredConfigWasRead(t *testing.T) {
	r := newRig(t)
	if rows, ok := r.store.Rows(); ok || rows != nil {
		t.Fatalf("before any desired-config: rows=%v ok=%v, want unknown", rows, ok)
	}
	r.store.Sync(context.Background(), nil)
	r.store.Wait()
	if rows, ok := r.store.Rows(); !ok || rows == nil || len(rows) != 0 {
		t.Fatalf("armed and empty: rows=%#v ok=%v, want a real empty list", rows, ok)
	}
}

func TestRowsUnknownWhenTheSetsDirIsUnreadable(t *testing.T) {
	r := newRig(t)
	r.store.Sync(context.Background(), nil)
	r.store.Wait()
	// Root is a regular file: ReadDir fails with something other than not-exist.
	if err := os.MkdirAll(filepath.Dir(r.store.Root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.store.Root, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rows, ok := r.store.Rows(); ok {
		t.Fatalf("unreadable state reported rows %v", rows)
	}
}

func TestSyncFetchesOneAtATimeAndRowsReportThem(t *testing.T) {
	r := newRig(t)
	r2 := Ref{"rh-stt-small", "r2"}
	r.stage(refA, filesA, r.key)
	r.stage(r2, filesA, r.key)
	var inflight, peak atomic.Int64
	r.store.Files = fetcherFunc(func(ctx context.Context, u, dest, sha string) (bool, error) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		defer inflight.Add(-1)
		return (&preseed.Client{HTTP: r.srv.Client()}).FetchOneVerified(ctx, u, dest, sha)
	})
	// Two Syncs back to back: the second must not start a second worker.
	r.store.Sync(context.Background(), []Ref{refA, r2})
	r.store.Sync(context.Background(), []Ref{refA, r2})
	if rows, ok := r.store.Rows(); !ok || len(rows) != 2 {
		t.Fatalf("rows while fetching = %v ok=%v", rows, ok)
	}
	r.store.Wait()
	if peak.Load() != 1 {
		t.Fatalf("%d fetches ran at once", peak.Load())
	}
	rows, _ := r.store.Rows()
	for _, row := range rows {
		if row.State != "verified" || row.Reason != "" {
			t.Fatalf("row = %+v", row)
		}
	}
}

func TestRefusedRowCarriesTheReasonAndWaitsBeforeRetrying(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, newKey(t)) // bad signature
	var asked atomic.Int64
	inner := r.store.Manifest
	r.store.Manifest = func(ctx context.Context, ref Ref) (*Signed, error) { asked.Add(1); return inner(ctx, ref) }
	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()
	rows, _ := r.store.Rows()
	if len(rows) != 1 || rows[0].State != "refused" || rows[0].Reason != nodewl.ReasonSetUnverified {
		t.Fatalf("rows = %+v", rows)
	}
	raw, _ := json.Marshal(rows)
	if !strings.Contains(string(raw), `"reason":"set_unverified"`) || !strings.Contains(string(raw), `"revision":"r1"`) {
		t.Fatalf("wire shape = %s", raw)
	}
	// The next tick inside the retry window asks nobody.
	r.store.Sync(context.Background(), []Ref{refA})
	r.store.Wait()
	if asked.Load() != 1 {
		t.Fatalf("manifest asked %d times, want 1 (refusal backoff)", asked.Load())
	}
}

func TestVerifiedRowOmitsReason(t *testing.T) {
	raw, _ := json.Marshal(Row{ID: "a", Revision: "r", State: "verified"})
	if strings.Contains(string(raw), "reason") {
		t.Fatalf("%s", raw)
	}
}

func TestSigningPubIsLocatedNextToTheClusterCA(t *testing.T) {
	cfg := configWithCA("/etc/noo/pki/ca.crt")
	if got := signingPubPath(cfg); got != "/etc/noo/pki/signing.pub" {
		t.Fatalf("got %q", got)
	}
}

type fetcherFunc func(ctx context.Context, u, dest, sha string) (bool, error)

func (f fetcherFunc) FetchOneVerified(ctx context.Context, u, dest, sha string) (bool, error) {
	return f(ctx, u, dest, sha)
}
