// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// i675 F9: an import whose `ollama create` keeps failing must not re-download
// its multi-GB weight at every reconcile retry, and what it reuses must be
// the controller's verified bytes.

const cacheWeight = "harrier-q8.gguf"

type cacheRig struct {
	fc       *fakeController
	weight   []byte
	exitFile string // the fake ollama's exit code
	seen     string // the weight bytes the fake ollama was handed
}

// newCacheRig is stageController with a plain store model and a fake ollama
// whose exit code the test sets, which records the weight it was given.
func newCacheRig(t *testing.T) *cacheRig {
	t.Helper()
	w := ggufBytes()
	fc := stageController(t, map[string][]byte{
		"harrier.Modelfile": []byte("FROM ./" + cacheWeight + "\n"),
		cacheWeight:         w,
	})
	bin := filepath.Dir(fc.create)
	r := &cacheRig{fc: fc, weight: w, exitFile: filepath.Join(bin, "exit"), seen: filepath.Join(bin, "seen")}
	script := "#!/bin/sh\ncat " + cacheWeight + " > '" + r.seen + "'\nexit $(cat '" + r.exitFile + "')\n"
	if err := os.WriteFile(filepath.Join(bin, "ollama"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.setExit(t, 0)
	return r
}

func (r *cacheRig) setExit(t *testing.T, code int) {
	t.Helper()
	if err := os.WriteFile(r.exitFile, []byte{byte('0' + code)}, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *cacheRig) ggufFetches() int {
	r.fc.mu.Lock()
	defer r.fc.mu.Unlock()
	n := 0
	for _, h := range r.fc.hits {
		if h == "/gguf/"+cacheWeight {
			n++
		}
	}
	return n
}

func (r *cacheRig) entry() string { return filepath.Join(ggufCacheDir(), sha(r.weight)+".gguf") }

func (r *cacheRig) pull(t *testing.T) error {
	t.Helper()
	_, err := (&Client{}).PullOllamaModel(t.Context(), "harrier")
	return err
}

func (r *cacheRig) seenBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(r.seen)
	if err != nil {
		t.Fatalf("ollama was never handed a weight: %v", err)
	}
	return b
}

// failOnce runs one import whose create fails, leaving the cache entry.
func (r *cacheRig) failOnce(t *testing.T) {
	t.Helper()
	r.setExit(t, 1)
	if err := r.pull(t); err == nil || !strings.Contains(err.Error(), "ollama create failed on the host binary") {
		t.Fatalf("first attempt: want the create failure, got %v", err)
	}
	if _, err := os.Lstat(r.entry()); err != nil {
		t.Fatalf("a failed create must leave the verified weight cached: %v", err)
	}
	r.setExit(t, 0)
}

// T1
func TestGGUFCache_FailedCreateThenRetryFetchesTheWeightOnce(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	fi, err := os.Lstat(r.entry())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache entry mode: %v %v, want 0600", fi, err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 1 {
		t.Fatalf("the weight was fetched %d times across a failed create and its retry, want 1", n)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("the retry handed ollama the wrong bytes")
	}
}

// T2 (host binary)
func TestGGUFCache_SuccessRemovesTheEntry(t *testing.T) {
	r := newCacheRig(t)
	if err := r.pull(t); err != nil {
		t.Fatalf("import: %v", err)
	}
	ents, err := os.ReadDir(ggufCacheDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), sha(r.weight)) {
			t.Fatalf("a successful create left %s in the cache", e.Name())
		}
	}
}

// T2 (container): the same clean-up when the create runs in noo-ollama.
func TestGGUFCache_ContainerSuccessRemovesTheEntry(t *testing.T) {
	r := newCacheRig(t)
	t.Setenv("PATH", t.TempDir())
	old := ollamaHostPaths
	ollamaHostPaths = nil
	t.Cleanup(func() { ollamaHostPaths = old })
	c := newExecOKDaemon(t)
	res, err := c.PullOllamaModel(t.Context(), "harrier")
	if err != nil || res.Via != "container" {
		t.Fatalf("container import: %v %+v", err, res)
	}
	if _, err := os.Lstat(r.entry()); !os.IsNotExist(err) {
		t.Fatalf("a successful container create left the cache entry: %v", err)
	}
}

// T3
func TestGGUFCache_AnEntryThatNoLongerHashesIsRefetched(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	// Same length, different bytes, still ours and 0600.
	bad := bytes.Repeat([]byte("X"), len(r.weight))
	if err := os.WriteFile(r.entry(), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (a corrupt entry must be fetched again)", n)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("ollama was handed the corrupt cached bytes")
	}
}

// T4 (file)
func TestGGUFCache_AWritableEntryIsNotUsed(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	if err := os.Chmod(r.entry(), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (a group/other-writable entry must not be used)", n)
	}
}

// T4 (dir)
func TestGGUFCache_AWritableCacheDirIsNotUsed(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	if err := os.Chmod(ggufCacheDir(), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (an entry in a world-writable dir must not be used)", n)
	}
	if fi, err := os.Lstat(ggufCacheDir()); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir after start-over: %v %v, want 0700", fi, err)
	}
}

// T5
func TestGGUFCache_ASymlinkAtTheEntryIsNotFollowed(t *testing.T) {
	r := newCacheRig(t)
	r.failOnce(t)
	// The target holds the RIGHT bytes, so only the symlink check refuses it.
	target := filepath.Join(t.TempDir(), "elsewhere.gguf")
	if err := os.WriteFile(target, r.weight, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.entry()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, r.entry()); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := r.ggufFetches(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (a symlink must not be used)", n)
	}
	if b, err := os.ReadFile(target); err != nil || !bytes.Equal(b, r.weight) {
		t.Fatalf("the symlink's target was touched: %v", err)
	}
}

// T5 (partial): FetchOneVerified resumes from <entry>.partial and would write
// through a symlink there; one that is not ours is removed first.
func TestGGUFCache_ASymlinkAtThePartialIsNotWrittenThrough(t *testing.T) {
	r := newCacheRig(t)
	if err := os.Mkdir(ggufCacheDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, r.entry()+".partial"); err != nil {
		t.Fatal(err)
	}
	if err := r.pull(t); err != nil {
		t.Fatalf("import: %v", err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "precious" {
		t.Fatalf("the fetch wrote through the partial's symlink: %q %v", b, err)
	}
	if !bytes.Equal(r.seenBytes(t), r.weight) {
		t.Fatal("ollama was handed the wrong bytes")
	}
}

// The partial check on its own (the prune would otherwise mask it): a symlink
// or a writable partial is removed, our own partial is kept for the resume.
func TestGGUFCache_DropUntrustedPartial(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.partial")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(dir, "w.partial")
	if err := os.WriteFile(writable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	ours := filepath.Join(dir, "ours.partial")
	if err := os.WriteFile(ours, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, writable, ours} {
		dropUntrustedPartial(p)
	}
	for _, p := range []string{link, writable} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s was kept", filepath.Base(p))
		}
	}
	if _, err := os.Lstat(ours); err != nil {
		t.Errorf("our own partial was removed: %v", err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the symlink's target was removed: %v", err)
	}
}

// The prune drops anything at a cache name that is not a regular file.
func TestGGUFCache_PruneRemovesNonRegularEntries(t *testing.T) {
	setCacheBounds(t, 1000*time.Hour, 10)
	dir := t.TempDir()
	target := writeAged(t, t.TempDir(), "target", time.Minute)
	link := filepath.Join(dir, shaName('a')+".partial")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, shaName('b'))
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	pruneGGUFCache(dir)
	for _, p := range []string{link, sub} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the prune", filepath.Base(p))
		}
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the symlink's target was removed: %v", err)
	}
}

// The trust rules on their own, for what an unprivileged test cannot make on
// disk: a non-regular entry with owner-only bits, another uid's file or dir.
type fakeFI struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeFI) Name() string       { return "x" }
func (f fakeFI) Size() int64        { return 0 }
func (f fakeFI) Mode() fs.FileMode  { return f.mode }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFI) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestGGUFCache_TrustRules(t *testing.T) {
	me := uint32(os.Getuid())
	other := me + 1
	cases := []struct {
		name    string
		check   func(fs.FileInfo) error
		fi      fakeFI
		trusted bool
	}{
		{"file ours 0600", ggufCacheFileTrusted, fakeFI{0o600, me}, true},
		{"file symlink 0600", ggufCacheFileTrusted, fakeFI{fs.ModeSymlink | 0o600, me}, false},
		{"file fifo 0600", ggufCacheFileTrusted, fakeFI{fs.ModeNamedPipe | 0o600, me}, false},
		{"file dir 0700", ggufCacheFileTrusted, fakeFI{fs.ModeDir | 0o700, me}, false},
		{"file group-writable", ggufCacheFileTrusted, fakeFI{0o620, me}, false},
		{"file other uid", ggufCacheFileTrusted, fakeFI{0o600, other}, false},
		{"dir ours 0700", ggufCacheDirTrusted, fakeFI{fs.ModeDir | 0o700, me}, true},
		{"dir symlink 0700", ggufCacheDirTrusted, fakeFI{fs.ModeSymlink | 0o700, me}, false},
		{"dir regular file", ggufCacheDirTrusted, fakeFI{0o700, me}, false},
		{"dir world-writable", ggufCacheDirTrusted, fakeFI{fs.ModeDir | 0o777, me}, false},
		{"dir other uid", ggufCacheDirTrusted, fakeFI{fs.ModeDir | 0o700, other}, false},
	}
	for _, tc := range cases {
		if err := tc.check(tc.fi); (err == nil) != tc.trusted {
			t.Errorf("%s: err = %v, want trusted=%v", tc.name, err, tc.trusted)
		}
	}
}

func writeAged(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("w"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	return p
}

func setCacheBounds(t *testing.T, ttl time.Duration, max int) {
	t.Helper()
	oldTTL, oldMax := ggufCacheTTL, ggufCacheMaxEntries
	ggufCacheTTL, ggufCacheMaxEntries = ttl, max
	t.Cleanup(func() { ggufCacheTTL, ggufCacheMaxEntries = oldTTL, oldMax })
}

func shaName(c byte) string { return strings.Repeat(string(c), 64) + ".gguf" }

// T6 (TTL), with a count limit too high to matter.
func TestGGUFCache_PruneRemovesEntriesOlderThanTheTTL(t *testing.T) {
	setCacheBounds(t, 24*time.Hour, 10)
	dir := t.TempDir()
	old := writeAged(t, dir, shaName('a'), 25*time.Hour)
	oldPartial := writeAged(t, dir, shaName('b')+".partial", 25*time.Hour)
	fresh := writeAged(t, dir, shaName('c'), time.Hour)
	junk := writeAged(t, dir, "ollama-leftover.tmp", time.Minute)
	pruneGGUFCache(dir)
	for _, p := range []string{old, oldPartial, junk} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the prune", filepath.Base(p))
		}
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Errorf("a fresh entry was pruned: %v", err)
	}
}

// T6 (count), with a TTL too long to matter.
func TestGGUFCache_PruneKeepsOnlyTheNewestEntries(t *testing.T) {
	setCacheBounds(t, 1000*time.Hour, 2)
	dir := t.TempDir()
	oldest := writeAged(t, dir, shaName('a'), 3*time.Hour)
	older := writeAged(t, dir, shaName('b'), 2*time.Hour)
	newer := writeAged(t, dir, shaName('c'), time.Hour)
	newest := writeAged(t, dir, shaName('d'), time.Minute)
	pruneGGUFCache(dir)
	for _, p := range []string{oldest, older} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived; only the newest 2 should", filepath.Base(p))
		}
	}
	for _, p := range []string{newer, newest} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was pruned: %v", filepath.Base(p), err)
		}
	}
}

// T6 (wired): an import prunes before it uses the cache, so a failed import
// of another weight does not outlive the TTL.
func TestGGUFCache_AnImportPrunesTheCache(t *testing.T) {
	setCacheBounds(t, 24*time.Hour, 2)
	r := newCacheRig(t)
	if err := os.Mkdir(ggufCacheDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := writeAged(t, ggufCacheDir(), shaName('e'), 25*time.Hour)
	if err := r.pull(t); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("an import left an entry older than the TTL: %v", err)
	}
}

// newExecOKDaemon fakes the Docker API for a container create that succeeds:
// noo-ollama running, the copy accepted, every exec exiting 0.
func newExecOKDaemon(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"c1","Name":"/` + OllamaContainer + `","State":{"Status":"running","Running":true}}`))
		case r.Method == http.MethodPut && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/archive"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/exec"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"e1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/exec/e1/start"):
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = buf.Flush()
			_ = conn.Close()
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/exec/e1/json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ID":"e1","Running":false,"ExitCode":0}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"not faked: ` + r.Method + " " + p + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
