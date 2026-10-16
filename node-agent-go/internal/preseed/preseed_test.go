// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRepoCacheDir(t *testing.T) {
	cases := map[string]string{
		"google/gemma-4-E4B-it":  "models--google--gemma-4-E4B-it",
		"BAAI/bge-small-en-v1.5": "models--BAAI--bge-small-en-v1.5",
		"/leading-slash/x/":      "models--leading-slash--x",
		"single":                 "models--single",
	}
	for in, want := range cases {
		if got := RepoCacheDir(in); got != want {
			t.Errorf("RepoCacheDir(%q) = %q, want %q", in, got, want)
		}
	}
}

// serveTree stands up a mini nginx-JSON-autoindex server over an in-memory tree.
func serveTree(tree map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// Directory request → JSON listing of immediate children.
		if p == "" || p[len(p)-1] == '/' {
			seen := map[string]string{}
			for f := range tree {
				if !hasPrefixDir(f, p) {
					continue
				}
				rest := f[len(p):]
				if i := indexByte(rest, '/'); i >= 0 {
					seen[rest[:i]] = "directory"
				} else if rest != "" {
					seen[rest] = "file"
				}
			}
			var entries []entry
			for name, typ := range seen {
				entries = append(entries, entry{Name: name, Type: typ})
			}
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		// File request.
		if body, ok := tree[p]; ok {
			w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
}

func hasPrefixDir(f, dir string) bool { return len(f) >= len(dir) && f[:len(dir)] == dir }
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func TestMirror_RecursiveTree(t *testing.T) {
	// A miniature HF model cache dir: snapshots/<rev>/... + blobs/ + refs/.
	tree := map[string]string{
		"/hf/models--org--name/refs/main":                          "abc123",
		"/hf/models--org--name/snapshots/abc123/config.json":       `{"n":1}`,
		"/hf/models--org--name/snapshots/abc123/model.safetensors": "WEIGHTS-BYTES",
		"/hf/models--org--name/blobs/deadbeef":                     "BLOB",
	}
	srv := serveTree(tree)
	defer srv.Close()

	dest := t.TempDir()
	n, err := New().Mirror(context.Background(), srv.URL+"/hf/models--org--name/", dest)
	if err != nil {
		t.Fatalf("Mirror: %v", err)
	}
	if n != 4 {
		t.Errorf("wrote %d files, want 4", n)
	}
	// Spot-check the layout + content landed correctly.
	got, err := os.ReadFile(filepath.Join(dest, "snapshots", "abc123", "config.json"))
	if err != nil || string(got) != `{"n":1}` {
		t.Errorf("config.json = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "blobs", "deadbeef")); err != nil {
		t.Errorf("blob missing: %v", err)
	}
}

func TestMirrorHFRepo_OnlyRefsPointedSnapshot(t *testing.T) {
	// A real-ish HF cache repo: two snapshot revs, a blobs/ dir, and a
	// .no_exist/ negative-cache marker. refs/main points at rev "aaa".
	tree := map[string]string{
		"/hf/models--org--name/refs/main":                       "aaa",
		"/hf/models--org--name/snapshots/aaa/config.json":       `{"rev":"aaa"}`,
		"/hf/models--org--name/snapshots/aaa/model.safetensors": "WEIGHTS-AAA",
		"/hf/models--org--name/snapshots/bbb/config.json":       `{"rev":"bbb"}`,
		"/hf/models--org--name/snapshots/bbb/model.safetensors": "WEIGHTS-BBB",
		"/hf/models--org--name/blobs/deadbeef":                  "WEIGHTS-AAA",
		"/hf/models--org--name/.no_exist/aaa/added_tokens.json": "",
	}
	srv := serveTree(tree)
	defer srv.Close()

	dest := t.TempDir()
	n, err := New().MirrorHFRepo(context.Background(), srv.URL+"/hf/models--org--name/", dest)
	if err != nil {
		t.Fatalf("MirrorHFRepo: %v", err)
	}
	// refs/main is written separately (not counted); the two files of the
	// "aaa" snapshot are the only downloads.
	if n != 2 {
		t.Errorf("wrote %d files, want 2 (only the refs-pointed snapshot)", n)
	}
	// refs/main persisted.
	if b, err := os.ReadFile(filepath.Join(dest, "refs", "main")); err != nil || string(b) != "aaa" {
		t.Errorf("refs/main = %q, %v; want %q", b, err, "aaa")
	}
	// The pointed snapshot landed with real content.
	if b, err := os.ReadFile(filepath.Join(dest, "snapshots", "aaa", "config.json")); err != nil || string(b) != `{"rev":"aaa"}` {
		t.Errorf("snapshots/aaa/config.json = %q, %v", b, err)
	}
	// The other revision, blobs/, and .no_exist/ must NOT be copied.
	for _, skipped := range []string{"snapshots/bbb", "blobs", ".no_exist"} {
		if _, err := os.Stat(filepath.Join(dest, skipped)); !os.IsNotExist(err) {
			t.Errorf("%s should not have been mirrored (stat err=%v)", skipped, err)
		}
	}
}

func TestMirrorHFRepo_FallsBackWithoutRefs(t *testing.T) {
	// No refs/main → unknown layout → full recursive mirror rather than fail.
	tree := map[string]string{"/hf/models--x--y/some/file.bin": "DATA"}
	srv := serveTree(tree)
	defer srv.Close()
	dest := t.TempDir()
	n, err := New().MirrorHFRepo(context.Background(), srv.URL+"/hf/models--x--y/", dest)
	if err != nil {
		t.Fatalf("MirrorHFRepo fallback: %v", err)
	}
	if n != 1 {
		t.Errorf("fallback wrote %d, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dest, "some", "file.bin")); err != nil {
		t.Errorf("fallback file missing: %v", err)
	}
}

func TestFetchOne_WritesThenResumes(t *testing.T) {
	tree := map[string]string{"/gguf/gemma-4-E2B-it-Q4_K_M.gguf": "GGUF-BYTES"}
	srv := serveTree(tree)
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "gemma-4-E2B-it-Q4_K_M.gguf")
	// First fetch writes it.
	wrote, err := New().FetchOne(context.Background(), srv.URL+"/gguf/gemma-4-E2B-it-Q4_K_M.gguf", dest)
	if err != nil || !wrote {
		t.Fatalf("FetchOne first: wrote=%v err=%v", wrote, err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "GGUF-BYTES" {
		t.Errorf("content = %q", b)
	}
	// Second fetch sees same-size file and skips.
	wrote, err = New().FetchOne(context.Background(), srv.URL+"/gguf/gemma-4-E2B-it-Q4_K_M.gguf", dest)
	if err != nil || wrote {
		t.Errorf("FetchOne resume: wrote=%v err=%v, want wrote=false", wrote, err)
	}
}

func TestMirror_ResumeSkipsExisting(t *testing.T) {
	tree := map[string]string{"/m/a.txt": "hello"}
	srv := serveTree(tree)
	defer srv.Close()
	dest := t.TempDir()
	// First run writes it.
	if n, _ := New().Mirror(context.Background(), srv.URL+"/m/", dest); n != 1 {
		t.Fatalf("first run wrote %d, want 1", n)
	}
	// Second run sees same-size file and skips (0 written).
	if n, _ := New().Mirror(context.Background(), srv.URL+"/m/", dest); n != 0 {
		t.Errorf("second run wrote %d, want 0 (resume)", n)
	}
}

// ── FetchOneVerified ──────────────────────────────────

func verifiedServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestFetchOneVerifiedLandsMatchingBytes(t *testing.T) {
	body := []byte("gguf-bytes")
	srv := verifiedServer(t, body)
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	wrote, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body))
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(body) {
		t.Fatalf("dest content %q", got)
	}
}

func TestFetchOneVerifiedMismatchNeverTouchesDest(t *testing.T) {
	srv := verifiedServer(t, []byte("tampered"))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	_, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex([]byte("expected")))
	if err == nil {
		t.Fatal("mismatch must error")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("dest must not exist after a mismatch")
	}
	if _, statErr := os.Stat(dest + ".partial"); !os.IsNotExist(statErr) {
		t.Fatal("partial must be removed after a mismatch")
	}
}

func TestFetchOneVerifiedExistingFileIsRehashedNotSizeTrusted(t *testing.T) {
	good := []byte("released-weights")
	// Same LENGTH, different bytes — exactly what the size shortcut misses.
	corrupt := []byte("corrupted-weight")
	if len(good) != len(corrupt) {
		t.Fatal("test needs equal lengths")
	}
	srv := verifiedServer(t, good)
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	wrote, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(good))
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("same-size corrupt file must be re-downloaded, not size-trusted")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(good) {
		t.Fatalf("dest still corrupt: %q", got)
	}
}

func TestFetchOneVerifiedMatchingExistingIsANoop(t *testing.T) {
	body := []byte("already-here")
	// Server that fails the test if contacted: a verified-present file must
	// short-circuit before any network traffic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made for a verified-present file")
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, body, 0o644); err != nil {
		t.Fatal(err)
	}
	wrote, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body))
	if err != nil || wrote {
		t.Fatalf("wrote=%v err=%v — must be a verified no-op", wrote, err)
	}
}

func TestFetchOneVerifiedRejectsMalformedDigest(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "m.gguf")
	for _, bad := range []string{"", "abc", "zz" + shaHex([]byte("x"))[2:] + "!"} {
		if _, err := New().FetchOneVerified(context.Background(), "http://unused", dest, bad); err == nil {
			t.Errorf("digest %q must be rejected", bad)
		}
	}
}

// ── FetchOneVerified resume ───────────────────────────

// rangeServer serves body with Range support. cutAfter>0 makes the FIRST
// non-range request send that many bytes and then drop the connection.
// mode: "range" honours Range (206), "ignore" always answers 200, "416"
// answers 416 to any Range request.
type rangeServer struct {
	*httptest.Server
	mu     sync.Mutex
	ranges []string
}

func newRangeServer(t *testing.T, body []byte, mode string, cutAfter int) *rangeServer {
	t.Helper()
	rs := &rangeServer{}
	cut := cutAfter
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if rg := r.Header.Get("Range"); rg != "" {
			rs.ranges = append(rs.ranges, rg)
			var from int
			fmt.Sscanf(rg, "bytes=%d-", &from)
			switch mode {
			case "416":
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			case "range":
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(body)-1, len(body)))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(body[from:])
				return
			}
		}
		if cut > 0 {
			n := cut
			cut = 0
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write(body[:n])
			w.(http.Flusher).Flush()
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func resumeBody() []byte { return bytes.Repeat([]byte("0123456789abcdef"), 4096) }

func TestFetchOneVerifiedResumesAfterATransportCut(t *testing.T) {
	body := resumeBody()
	srv := newRangeServer(t, body, "range", 20000)
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if _, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body)); err == nil {
		t.Fatal("a cut connection must error")
	}
	st, err := os.Stat(dest + ".partial")
	if err != nil || st.Size() == 0 || st.Size() >= int64(len(body)) {
		t.Fatalf("partial must be kept with the received prefix: %v %v", st, err)
	}
	kept := st.Size()
	wrote, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body))
	if err != nil || !wrote {
		t.Fatalf("resume: wrote=%v err=%v", wrote, err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, body) {
		t.Fatal("resumed file differs from the source")
	}
	if len(srv.ranges) != 1 || srv.ranges[0] != fmt.Sprintf("bytes=%d-", kept) {
		t.Fatalf("want exactly one Range bytes=%d-, saw %v", kept, srv.ranges)
	}
	if _, err := os.Stat(dest + ".partial"); !os.IsNotExist(err) {
		t.Fatal("partial must be gone after the rename")
	}
}

func TestFetchOneVerifiedRangeAnswers(t *testing.T) {
	body := resumeBody()
	for _, mode := range []string{"ignore", "416"} {
		t.Run(mode, func(t *testing.T) {
			srv := newRangeServer(t, body, mode, 0)
			dest := filepath.Join(t.TempDir(), "m.gguf")
			// A genuine prefix, so only the server's answer decides the outcome.
			if err := os.WriteFile(dest+".partial", body[:1000], 0o644); err != nil {
				t.Fatal(err)
			}
			wrote, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body))
			if err != nil || !wrote {
				t.Fatalf("wrote=%v err=%v", wrote, err)
			}
			got, _ := os.ReadFile(dest)
			if !bytes.Equal(got, body) {
				t.Fatal("restarted download differs from the source")
			}
			if len(srv.ranges) != 1 {
				t.Fatalf("want one Range attempt, saw %v", srv.ranges)
			}
		})
	}
}

func TestFetchOneVerifiedCorruptPartialIsDiscardedOnMismatch(t *testing.T) {
	body := resumeBody()
	srv := newRangeServer(t, body, "range", 0)
	dest := filepath.Join(t.TempDir(), "m.gguf")
	bad := append([]byte(nil), body[:1000]...)
	bad[10] ^= 0xff
	if err := os.WriteFile(dest+".partial", bad, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex(body))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	if _, e := os.Stat(dest + ".partial"); !os.IsNotExist(e) {
		t.Fatal("a corrupt partial must be removed")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("dest must not exist")
	}
}

func TestFetchOneVerifiedHTTPErrorKeepsPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	_ = os.WriteFile(dest+".partial", []byte("prefix"), 0o644)
	if _, err := New().FetchOneVerified(context.Background(), srv.URL, dest, shaHex([]byte("x"))); err == nil {
		t.Fatal("503 must error")
	}
	if _, e := os.Stat(dest + ".partial"); e != nil {
		t.Fatal("a 503 is transient; the partial must stay")
	}
}
