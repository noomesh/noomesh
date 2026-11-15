// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package modelsets

// F10: a new revision of a set reuses, by hard link, every file a verified
// sibling revision on the same disk already holds with the same sha256 and
// size; Prune keeps that sibling until the new revision verifies.

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

var (
	refR1 = Ref{"rh-stt-small", "r1"}
	refR2 = Ref{"rh-stt-small", "r2"}
	// filesR2 keeps model.bin byte for byte and changes cfg/tok.json.
	filesR2 = map[string][]byte{"model.bin": filesA["model.bin"], "cfg/tok.json": []byte(`{"t":2}`)}
)

// logBuf captures the default slog logger for one test (the worker goroutine
// logs too, hence the lock).
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLog(t *testing.T) *logBuf {
	t.Helper()
	l := &logBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(l, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return l
}

// withR1 is a rig holding r1 verified and sealed, r2 staged.
func withR1(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.stage(refR1, filesA, r.key)
	if err := r.store.Fetch(context.Background(), refR1); err != nil {
		t.Fatal(err)
	}
	r.stage(refR2, filesR2, r.key)
	return r
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(fa, fb)
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func mustVerified(t *testing.T, s *Store, ref Ref) {
	t.Helper()
	if st := s.State(ref); st.State != StateVerified {
		t.Fatalf("%s: state = %+v, want verified", ref, st)
	}
}

// progressProbe is a Fetcher that records the store's bytes_done at its first
// call, then delegates.
type progressProbe struct {
	Fetcher
	s     *Store
	ref   Ref
	once  sync.Once
	first int64
}

func (p *progressProbe) FetchOneVerified(ctx context.Context, u, dest, sha string) (bool, error) {
	p.once.Do(func() {
		p.s.mu.Lock()
		if m := p.s.mem[p.ref]; m.prog != nil {
			p.first = m.prog.done.Load()
		}
		p.s.mu.Unlock()
	})
	return p.Fetcher.FetchOneVerified(ctx, u, dest, sha)
}

func TestUnchangedFilesAreLinkedFromTheVerifiedSiblingNotFetched(t *testing.T) {
	r := withR1(t)
	probe := &progressProbe{Fetcher: r.store.Files, s: r.store, ref: refR2, first: -1}
	r.store.Files = probe
	before := r.hits.Load()
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR2)
	if got := r.hits.Load() - before; got != 1 {
		t.Fatalf("the cache served %d files for r2, want 1 (only the changed cfg/tok.json)", got)
	}
	if !sameFile(t, filepath.Join(r.store.dir(refR2), "model.bin"), filepath.Join(r.store.dir(refR1), "model.bin")) {
		t.Fatal("the unchanged model.bin is not a hard link of r1's")
	}
	if sameFile(t, filepath.Join(r.store.dir(refR2), "cfg", "tok.json"), filepath.Join(r.store.dir(refR1), "cfg", "tok.json")) {
		t.Fatal("the changed cfg/tok.json was linked")
	}
	if want := int64(len(filesA["model.bin"])); probe.first != want {
		t.Fatalf("bytes_done at the first file call = %d, want the linked %d", probe.first, want)
	}
}

func TestSiblingStaysSealedAndVerifiedThroughAForcedRefetch(t *testing.T) {
	r := withR1(t)
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	sib := filepath.Join(r.store.dir(refR1), "model.bin")
	if m := modeOf(t, sib); m != 0o444 {
		t.Fatalf("after r2 verified, r1's model.bin is %v, want 0444", m)
	}
	mustVerified(t, r.store, refR1)

	// Force a re-fetch of r2 that stops before sealing: the window in which a
	// file chmod in makeWritable would leave the shared inode writable.
	d2 := r.store.dir(refR2)
	if err := makeWritable(d2); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{MarkerName, "cfg/tok.json"} {
		if err := os.Remove(filepath.Join(d2, filepath.FromSlash(p))); err != nil {
			t.Fatal(err)
		}
	}
	r.failOn.Store("cfg/tok.json")
	if err := r.store.Fetch(context.Background(), refR2); err == nil {
		t.Fatal("the re-fetch was meant to fail")
	}
	if m := modeOf(t, sib); m != 0o444 {
		t.Fatalf("a re-fetch of r2 reopened r1's model.bin to %v (shared inode)", m)
	}
	mustVerified(t, r.store, refR1)
	r.failOn.Store("")
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR2)
	mustVerified(t, r.store, refR1)
	if m := modeOf(t, sib); m != 0o444 {
		t.Fatalf("after the re-fetch r1's model.bin is %v", m)
	}
}

func TestCorruptSiblingFileFallsBackToAFetchAndIsLeftAlone(t *testing.T) {
	r := withR1(t)
	sib := filepath.Join(r.store.dir(refR1), "model.bin")
	bad := bytes.Repeat([]byte("x"), len(filesA["model.bin"])) // same size: diskStatus still reads verified
	if err := os.Chmod(sib, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sib, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sib, 0o444); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR1)
	before := r.hits.Load()
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR2)
	if got := r.hits.Load() - before; got != 2 {
		t.Fatalf("cache hits = %d, want 2 (the corrupt link re-fetched)", got)
	}
	got, err := os.ReadFile(filepath.Join(r.store.dir(refR2), "model.bin"))
	if err != nil || !bytes.Equal(got, filesA["model.bin"]) {
		t.Fatalf("r2 model.bin = %q, %v", got, err)
	}
	if b, _ := os.ReadFile(sib); !bytes.Equal(b, bad) {
		t.Fatal("the fall-back wrote into r1's file")
	}
}

func TestLinkRefusesASymlinkSourceAndAPathThatLeaves(t *testing.T) {
	r := newRig(t)
	s := r.store
	sibDir := s.dir(refR1)
	if err := os.MkdirAll(filepath.Join(sibDir, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, filesA["model.bin"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sibDir, "model.bin")); err != nil {
		t.Fatal(err)
	}
	want := nodewl.File{Path: "model.bin", Bytes: int64(len(filesA["model.bin"]))}
	dest := filepath.Join(s.dir(refR2), "model.bin")

	// A symlink entry, of the very size the manifest asks (Lstat of a
	// symlink is the length of its target), so only the type checks stop it.
	lw := nodewl.File{Path: "model.bin", Bytes: int64(len(target))}
	src := linkSrc{from: refR1, dir: sibDir, path: filepath.Join(sibDir, "model.bin"), bytes: lw.Bytes}
	if why := s.linkOne(src, dest, lw); why == "" {
		t.Fatal("a symlink was accepted as a link source")
	}
	// A FIFO (not a regular file, no symlink anywhere).
	fifo := filepath.Join(sibDir, "cfg", "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	src = linkSrc{from: refR1, dir: sibDir, path: fifo, bytes: 0}
	if why := s.linkOne(src, dest, nodewl.File{Path: "model.bin", Bytes: 0}); why == "" {
		t.Fatal("a FIFO was accepted as a link source")
	}
	if _, err := os.Lstat(dest); err == nil {
		t.Fatal("a refused link left a destination")
	}
	src = linkSrc{from: refR1, dir: sibDir, path: filepath.Join(sibDir, "model.bin"), bytes: want.Bytes}
	if _, err := os.Lstat(dest); err == nil {
		t.Fatal("a refused link left a destination")
	}
	// A symlinked directory on the source's path.
	if err := os.Symlink(filepath.Dir(target), filepath.Join(sibDir, "lnk")); err != nil {
		t.Fatal(err)
	}
	src.path = filepath.Join(sibDir, "lnk", "elsewhere")
	if why := s.linkOne(src, dest, want); why == "" {
		t.Fatal("a source under a symlinked directory was accepted")
	}
	// A path that leaves the sibling's directory.
	src.path = target
	if why := s.linkOne(src, dest, want); why == "" {
		t.Fatal("a source outside its revision directory was accepted")
	}
	// Inside Root, a regular file, but in another revision's directory.
	other := filepath.Join(s.Root, refR1.ID, "r9", "model.bin")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, filesA["model.bin"], 0o644); err != nil {
		t.Fatal(err)
	}
	src.path = other
	if why := s.linkOne(src, dest, want); why == "" {
		t.Fatal("a source in another revision's directory was accepted")
	}
	// A manifest row with `..` never enters the index.
	idx := map[string]linkSrc{}
	siblingIndex(idx, refR1, sibDir, &nodewl.ModelSet{Files: []nodewl.File{
		{Path: "../r9/model.bin", Bytes: 1, SHA256: strings.Repeat("a", 64)},
		{Path: "/abs", Bytes: 1, SHA256: strings.Repeat("b", 64)},
	}})
	if len(idx) != 0 {
		t.Fatalf("an escaping manifest path was indexed: %+v", idx)
	}
	// And a size that differs between the manifests is not linked.
	ok := filepath.Join(sibDir, "cfg", "tok.json")
	if err := os.WriteFile(ok, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	src = linkSrc{from: refR1, dir: sibDir, path: ok, bytes: 5}
	if why := s.linkOne(src, dest, nodewl.File{Path: "model.bin", Bytes: 6}); why == "" {
		t.Fatal("a source of another size was linked")
	}
	if err := os.WriteFile(ok, []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	src.bytes = 5 // the disk agrees with the wanted row, the sibling's manifest does not
	if why := s.linkOne(src, dest, nodewl.File{Path: "model.bin", Bytes: 6}); why == "" {
		t.Fatal("a source whose manifest row has another size was linked")
	}
	if err := os.WriteFile(ok, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	src.bytes = 6 // the manifests agree, the disk does not
	if why := s.linkOne(src, dest, nodewl.File{Path: "model.bin", Bytes: 6}); why == "" {
		t.Fatal("a source whose size on disk differs was linked")
	}
}

func TestSymlinkedSiblingIsNotALinkSource(t *testing.T) {
	r := withR1(t)
	d1 := r.store.dir(refR1)
	if err := makeWritable(d1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(d1, "model.bin")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "w")
	if err := os.WriteFile(target, filesA["model.bin"], 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d1, "model.bin")); err != nil {
		t.Fatal(err)
	}
	before := r.hits.Load()
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR2)
	if got := r.hits.Load() - before; got != 2 {
		t.Fatalf("cache hits = %d, want 2: a sibling with a symlink is no link source", got)
	}
}

func TestLinkGoesThroughATempNameAndAStrayTempIsRemoved(t *testing.T) {
	r := withR1(t)
	var names []string
	r.store.Link = func(o, n string) error {
		names = append(names, n)
		return os.Link(o, n)
	}
	// A crash between link and rename in an earlier attempt left a temp link
	// for a file that is NOT linked this time (it changed).
	d2 := r.store.dir(refR2)
	if err := os.MkdirAll(filepath.Join(d2, "cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(d2, "cfg", "tok.json"+linkTmpSuffix)
	if err := os.Link(filepath.Join(r.store.dir(refR1), "cfg", "tok.json"), stray); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Fetch(context.Background(), refR2); err != nil {
		t.Fatal(err)
	}
	mustVerified(t, r.store, refR2)
	if len(names) != 1 || names[0] != filepath.Join(d2, "model.bin")+linkTmpSuffix {
		t.Fatalf("links made at %v, want one at model.bin%s", names, linkTmpSuffix)
	}
	if _, err := os.Lstat(stray); err == nil {
		t.Fatal("the stray temp link survived the seal")
	}
	if nodewl.ValidSetPath("model.bin" + linkTmpSuffix) {
		t.Fatal("the temp suffix must be outside the set-path charset")
	}
}

func TestLinkErrorFallsBackToAFetch(t *testing.T) {
	for name, errno := range map[string]syscall.Errno{"EXDEV": syscall.EXDEV, "EPERM": syscall.EPERM} {
		t.Run(name, func(t *testing.T) {
			r := withR1(t)
			logs := captureLog(t)
			calls := 0
			r.store.Link = func(o, n string) error {
				calls++
				return &os.LinkError{Op: "link", Old: o, New: n, Err: errno}
			}
			before := r.hits.Load()
			if err := r.store.Fetch(context.Background(), refR2); err != nil {
				t.Fatal(err)
			}
			mustVerified(t, r.store, refR2)
			if got := r.hits.Load() - before; got != 2 {
				t.Fatalf("cache hits = %d, want 2", got)
			}
			if calls != 1 {
				t.Fatalf("link tried %d times", calls)
			}
			if sameFile(t, filepath.Join(r.store.dir(refR2), "model.bin"), filepath.Join(r.store.dir(refR1), "model.bin")) {
				t.Fatal("linked despite the error")
			}
			if !strings.Contains(logs.String(), "not linked") || !strings.Contains(logs.String(), errno.Error()) {
				t.Fatalf("no fall-back line with the reason:\n%s", logs)
			}
		})
	}
}

// ---- Prune holds the link source ----------------------------------------

func TestPruneKeepsTheNewestVerifiedSiblingUntilTheNewRevisionVerifies(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r0 := Ref{refR1.ID, "r0"}
	r.stage(r0, filesA, r.key)
	if err := r.store.Fetch(ctx, r0); err != nil {
		t.Fatal(err)
	}
	r.stage(refR1, filesA, r.key)
	if err := r.store.Fetch(ctx, refR1); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(r.store.dir(r0), MarkerName), old, old); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)

	// r2 is wanted but not staged yet: it cannot verify this tick.
	want := []Ref{refR2}
	keep := map[Ref]bool{refR2: true}
	r.store.Sync(ctx, want)
	removed, err := r.store.Prune(keep)
	if err != nil {
		t.Fatal(err)
	}
	r.store.Wait()
	if len(removed) != 1 || removed[0] != r0 {
		t.Fatalf("removed %v, want only the older r0", removed)
	}
	mustVerified(t, r.store, refR1)
	if !strings.Contains(logs.String(), "kept r1 as link source until r2 verifies") {
		t.Fatalf("no held line:\n%s", logs)
	}
	rows, _ := r.store.Rows()
	var held int
	for _, row := range rows {
		if row.LinkSourceFor != "" {
			held++
			if row.Revision != "r1" || row.LinkSourceFor != "r2" {
				t.Fatalf("row %+v", row)
			}
		}
	}
	if held != 1 {
		t.Fatalf("rows %+v: want one link_source_for", rows)
	}
	// A second tick while r2 is still unverified keeps it, and does not log again.
	if removed, _ := r.store.Prune(keep); len(removed) != 0 {
		t.Fatalf("second tick removed %v", removed)
	}
	if n := strings.Count(logs.String(), "as link source until"); n != 1 {
		t.Fatalf("held line logged %d times", n)
	}

	// r2 lands and verifies; the next tick prunes r1.
	r.stage(refR2, filesR2, r.key)
	r.store.ClearRefused(nil)
	r.store.Sync(ctx, want)
	r.store.Wait()
	mustVerified(t, r.store, refR2)
	removed, err = r.store.Prune(keep)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != refR1 {
		t.Fatalf("removed %v, want r1 once r2 verified", removed)
	}
	if !strings.Contains(logs.String(), "link source released") {
		t.Fatalf("no release line:\n%s", logs)
	}
	// The linked file outlives its source.
	if b, err := os.ReadFile(filepath.Join(r.store.dir(refR2), "model.bin")); err != nil || !bytes.Equal(b, filesA["model.bin"]) {
		t.Fatalf("r2 model.bin after r1 pruned: %q %v", b, err)
	}
}

func TestPruneWithoutAVerifiedSiblingHoldsNothing(t *testing.T) {
	r := newRig(t)
	// An unverified leftover of the same set is no link source, even with a
	// marker: this one does not match its manifest (diskStatus: refused).
	d := r.store.dir(refR1)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ManifestName), manifestJSON(t, refR1, filesA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, MarkerName), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := r.store.State(refR1); st.State == StateVerified {
		t.Fatalf("setup: %+v", st)
	}
	r.store.Sync(context.Background(), []Ref{refR2})
	removed, err := r.store.Prune(map[Ref]bool{refR2: true})
	r.store.Wait()
	if err != nil || len(removed) != 1 || removed[0] != refR1 {
		t.Fatalf("removed %v, %v", removed, err)
	}
}

// ---- source guard (condition 4) -----------------------------------------

// TestNothingWritesIntoAnExistingFileOrChmodsOne reads the write paths a
// linked file can meet and pins that none of them writes into, or chmods, an
// existing file (which, on a shared inode, would change the sibling too).
//
// Allowed, and why:
//   - os.OpenFile with a write flag, os.WriteFile and os.Create only on a
//     variable named `tmp`: a temp name that is renamed over the destination
//     afterwards (writeAtomic; preseed's dest+".partial"), so the old inode is
//     replaced, never written.
//   - os.Chmod only in sealFiles (0444: a no-op on an already sealed shared
//     inode), sealDirs and makeWritable (directories; the forced re-fetch
//     test pins that makeWritable leaves files alone), and fetch's chmod of
//     the marker (written by this node, never a manifest file, never linked).
//   - os.Truncate, os.Chown, os.Lchown: never.
//
// preseed.go is scanned with the same rules and no os.Chmod at all.
func TestNothingWritesIntoAnExistingFileOrChmodsOne(t *testing.T) {
	type rule struct {
		file      string
		chmodOK   map[string]bool
		mustWrite int // tmp writes the scan must see, so it cannot pass blind
	}
	for _, rl := range []rule{
		{"modelsets.go", map[string]bool{"sealFiles": true, "sealDirs": true, "makeWritable": true}, 1},
		{"../preseed/preseed.go", nil, 1},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, rl.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		text := func(n ast.Node) string {
			var b bytes.Buffer
			_ = printer.Fprint(&b, fset, n)
			return b.String()
		}
		var tmpWrites, chmods int
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "os" {
					return true
				}
				at := fset.Position(call.Pos())
				firstIsTmp := len(call.Args) > 0 && text(call.Args[0]) == "tmp"
				switch sel.Sel.Name {
				case "OpenFile":
					flags := text(call.Args[1])
					writes := flags == "flags" || strings.ContainsAny(flags, "|") ||
						strings.Contains(flags, "WRONLY") || strings.Contains(flags, "RDWR") ||
						strings.Contains(flags, "APPEND") || strings.Contains(flags, "TRUNC")
					if writes && !firstIsTmp {
						t.Errorf("%s: %s opens a non-temp path for writing", at, text(call))
					}
					if writes {
						tmpWrites++
					}
				case "WriteFile", "Create":
					if !firstIsTmp {
						t.Errorf("%s: %s writes a non-temp path", at, text(call))
					}
					tmpWrites++
				case "Truncate", "Chown", "Lchown":
					t.Errorf("%s: %s is never allowed here", at, text(call))
				case "Chmod":
					chmods++
					switch {
					case rl.chmodOK[fn.Name.Name]:
					case rl.chmodOK != nil && fn.Name.Name == "fetch" && strings.Contains(text(call.Args[0]), "MarkerName"):
					default:
						t.Errorf("%s: %s chmods outside sealing (in %s)", at, text(call), fn.Name.Name)
					}
				}
				return true
			})
		}
		if tmpWrites < rl.mustWrite {
			t.Errorf("%s: saw %d temp writes, want >= %d: the scan is blind", rl.file, tmpWrites, rl.mustWrite)
		}
		if rl.chmodOK != nil && chmods < 4 {
			t.Errorf("%s: saw %d chmods, want the 4 sealing ones: the scan is blind", rl.file, chmods)
		}
	}
}
