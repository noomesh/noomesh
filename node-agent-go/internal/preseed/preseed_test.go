// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// i607b: the progress callback reports bytes of the file on disk, at most
// once per ProgressStep, ends on the full size, and never goes backwards.
func TestFetchOneVerifiedProgressAdvancesToTheFullSize(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789abcdef"), (3*ProgressStep+12345)/16)
	srv := verifiedServer(t, body)
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	var seen []int64
	wrote, err := New().FetchOneVerifiedProgress(context.Background(), srv.URL, dest, shaHex(body), func(n int64) { seen = append(seen, n) })
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	if len(seen) < 2 || len(seen) > len(body)/ProgressStep+2 {
		t.Fatalf("progress calls = %d for %d bytes", len(seen), len(body))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("progress went %d -> %d", seen[i-1], seen[i])
		}
	}
	if seen[len(seen)-1] != int64(len(body)) {
		t.Fatalf("last progress = %d, want %d", seen[len(seen)-1], len(body))
	}
}

// A file already present and verified writes nothing and reports nothing.
func TestFetchOneVerifiedProgressSilentWhenAlreadyPresent(t *testing.T) {
	body := []byte("gguf-bytes")
	srv := verifiedServer(t, body)
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, body, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	wrote, err := New().FetchOneVerifiedProgress(context.Background(), srv.URL, dest, shaHex(body), func(int64) { called = true })
	if err != nil || wrote || called {
		t.Fatalf("wrote=%v err=%v called=%v", wrote, err, called)
	}
}
