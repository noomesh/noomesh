// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// The cache's trust rules against REAL files: symlinks, FIFOs, directories
// and (when the test runs as root, as noo-batch does) another uid's files.

const otherUID = 65534 // nobody

func lstatOf(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func TestGGUFCacheDisk_TrustRulesOnRealFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(dir, "file-link")
	if err := os.Symlink(regular, fileLink); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "dir-link")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ggufCacheFileTrusted(lstatOf(t, regular)); err != nil {
		t.Fatalf("our own 0600 file refused: %v", err)
	}
	if err := ggufCacheDirTrusted(lstatOf(t, realDir)); err != nil {
		t.Fatalf("our own 0700 dir refused: %v", err)
	}
	for name, p := range map[string]string{"symlink": fileLink, "fifo": fifo, "directory": realDir} {
		if err := ggufCacheFileTrusted(lstatOf(t, p)); err == nil {
			t.Errorf("file check accepted a %s", name)
		}
	}
	for name, p := range map[string]string{"symlink to a dir": dirLink, "regular file": regular, "fifo": fifo} {
		if err := ggufCacheDirTrusted(lstatOf(t, p)); err == nil {
			t.Errorf("dir check accepted a %s", name)
		}
	}

	t.Run("another uid", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skip("needs root to chown to another uid; TestGGUFCache_TrustRules covers the uid rule with a fake FileInfo")
		}
		f := filepath.Join(dir, "theirs-file")
		if err := os.WriteFile(f, []byte("w"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, "theirs-dir")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{f, d} {
			if err := os.Lchown(p, otherUID, otherUID); err != nil {
				t.Fatal(err)
			}
		}
		if err := ggufCacheFileTrusted(lstatOf(t, f)); err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Errorf("file owned by uid %d: err = %v, want an ownership refusal", otherUID, err)
		}
		if err := ggufCacheDirTrusted(lstatOf(t, d)); err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Errorf("dir owned by uid %d: err = %v, want an ownership refusal", otherUID, err)
		}
	})
}

// End to end: an import does not use (or block on, or follow) what it finds
// at the cache's names.

func TestGGUFCacheDisk_ImportRefetchesOverAFIFOEntry(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	if err := os.Remove(r.entry()); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(r.entry(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (a FIFO at the entry name must not be used)", n)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("ollama was handed the wrong bytes")
	}
}

func TestGGUFCacheDisk_ImportIgnoresAFIFOPartial(t *testing.T) {
	r := newCacheRig(t)
	if err := os.Mkdir(ggufCacheDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(r.entry()+".partial", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("ollama was handed the wrong bytes")
	}
}

func TestGGUFCacheDisk_ImportRefetchesOverADirectoryEntry(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	if err := os.Remove(r.entry()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.entry(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (a directory at the entry name must not be used)", n)
	}
}

// A symlinked cache dir pointing at a dir that holds a VALID entry: the
// entry must not be reused through the link, and the target must be left
// alone.
func TestGGUFCacheDisk_ImportDoesNotFollowASymlinkedCacheDir(t *testing.T) {
	r := newCacheRig(t)
	target := t.TempDir()
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(target, filepath.Base(r.entry()))
	if err := os.WriteFile(planted, r.weight, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ggufCacheDir()); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("import: %v", err)
	}
	if n := r.ggufFetches(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (the entry behind a symlinked dir must not be reused)", n)
	}
	if fi := lstatOf(t, ggufCacheDir()); !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("cache dir is still %s", fi.Mode())
	}
	if b, err := os.ReadFile(planted); err != nil || !bytes.Equal(b, r.weight) {
		t.Fatalf("the symlink's target was touched: %v", err)
	}
}

func TestGGUFCacheDisk_ImportRefetchesAnotherUIDsEntryAndDir(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown to another uid; TestGGUFCache_TrustRules covers the uid rule with a fake FileInfo")
	}
	for _, which := range []string{"entry", "dir"} {
		t.Run(which, func(t *testing.T) {
			r := newCacheRig(t)
			r.failOnce(t)
			p := r.entry()
			if which == "dir" {
				p = ggufCacheDir()
			}
			if err := os.Lchown(p, otherUID, otherUID); err != nil {
				t.Fatal(err)
			}
			if err := r.pull(t); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if n := r.ggufFetches(); n != 2 {
				t.Fatalf("fetches = %d, want 2 (a %s owned by uid %d must not be used)", n, which, otherUID)
			}
		})
	}
}

// Cross-device: the link fails with EXDEV and the weight is COPIED.

func failLinkEXDEV(t *testing.T) {
	t.Helper()
	old := linkFile
	linkFile = func(o, n string) error { return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EXDEV} }
	t.Cleanup(func() { linkFile = old })
}

func TestGGUFCacheDisk_CrossDeviceLinkFallsBackToACopy(t *testing.T) {
	failLinkEXDEV(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	body := []byte("GGUF-cross-device")
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "dest")
	if err := linkOrCopy(src, dest); err != nil {
		t.Fatalf("linkOrCopy: %v", err)
	}
	b, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(b, body) {
		t.Fatalf("dest = %q, %v; want the source bytes", b, err)
	}
	sfi, dfi := lstatOf(t, src), lstatOf(t, dest)
	if os.SameFile(sfi, dfi) {
		t.Fatal("dest is the same inode: a copy was expected")
	}
	if dfi.Mode().Perm() != 0o600 || !dfi.Mode().IsRegular() {
		t.Fatalf("dest mode %s, want a 0600 regular file", dfi.Mode())
	}
	// O_EXCL: an existing dest is refused, not overwritten.
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := linkOrCopy(src, existing); err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("copy over an existing dest: err = %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Fatalf("an existing dest was overwritten: %q", b)
	}
}

func TestGGUFCacheDisk_ImportAcrossDevicesStillCreates(t *testing.T) {
	failLinkEXDEV(t)
	r := newCacheRig(t)
	r.failOnce(t)
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("ollama was handed the wrong bytes")
	}
}

// Concurrency: the cache lock.

type slowStore struct {
	mu        sync.Mutex
	files     map[string][]byte
	downloads map[string]int
	inflight  int
	maxFlight int
}

// newSlowStore serves /gguf/<name> over mTLS, slowly enough that two
// unserialised downloads overlap, and records how many ran at once.
func newSlowStore(t *testing.T, files map[string][]byte) (*slowStore, string) {
	t.Helper()
	clearImageEnv(t)
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	s := &slowStore{files: files, downloads: map[string]int{}}
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/gguf/")
		b, ok := s.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		s.downloads[name]++
		s.inflight++
		if s.inflight > s.maxFlight {
			s.maxFlight = s.inflight
		}
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.inflight--; s.mu.Unlock() }()
		half := len(b) / 2
		_, _ = w.Write(b[:half])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write(b[half:])
	}))
	t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())
	return s, srv.URL
}

func (s *slowStore) counts(name string) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads[name], s.maxFlight
}

func stageConcurrently(t *testing.T, srcs, wants []string) []string {
	t.Helper()
	work := t.TempDir()
	dests := make([]string, len(srcs))
	errs := make([]error, len(srcs))
	var wg sync.WaitGroup
	for i := range srcs {
		dests[i] = filepath.Join(work, "w"+string(rune('0'+i)))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = stageGGUFViaCache(context.Background(), srcs[i], dests[i], wants[i])
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	return dests
}

func TestGGUFCacheConcurrent_SameWeightDownloadsOnce(t *testing.T) {
	w := ggufBytes()
	s, url := newSlowStore(t, map[string][]byte{"a.gguf": w})
	dests := stageConcurrently(t, []string{url + "/gguf/a.gguf", url + "/gguf/a.gguf"}, []string{sha(w), sha(w)})
	if n, _ := s.counts("a.gguf"); n != 1 {
		t.Fatalf("two concurrent imports of one weight downloaded it %d times, want 1", n)
	}
	for i, d := range dests {
		if b, err := os.ReadFile(d); err != nil || !bytes.Equal(b, w) {
			t.Fatalf("caller %d got %q, %v", i, b, err)
		}
	}
}

func TestGGUFCacheConcurrent_DifferentWeightsAreSerialisedAndKept(t *testing.T) {
	setCacheBounds(t, 24*time.Hour, 2)
	wa := append(ggufBytes(), 'A')
	wb := append(ggufBytes(), 'B')
	s, url := newSlowStore(t, map[string][]byte{"a.gguf": wa, "b.gguf": wb})
	dests := stageConcurrently(t, []string{url + "/gguf/a.gguf", url + "/gguf/b.gguf"}, []string{sha(wa), sha(wb)})
	if _, most := s.counts(""); most != 1 {
		t.Fatalf("%d downloads ran at once, want them serialised", most)
	}
	for i, want := range [][]byte{wa, wb} {
		if b, err := os.ReadFile(dests[i]); err != nil || !bytes.Equal(b, want) {
			t.Fatalf("caller %d got %q, %v", i, b, err)
		}
	}
	// Neither prune removed the other's entry, and no partial was left.
	for _, want := range [][]byte{wa, wb} {
		e := filepath.Join(ggufCacheDir(), sha(want)+".gguf")
		if b, err := os.ReadFile(e); err != nil || !bytes.Equal(b, want) {
			t.Fatalf("entry %s: %v", filepath.Base(e), err)
		}
		if _, err := os.Lstat(e + ".partial"); !os.IsNotExist(err) {
			t.Fatalf("a partial was left beside %s", filepath.Base(e))
		}
	}
}
