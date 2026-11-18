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
	"testing"
)

func failingStore(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "store down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A file that is there and hashes to something else, and a store that cannot
// send the right bytes: the error says the present file is PROVEN wrong, and
// the file is left where it was (the caller decides what to do with it).
func TestAPresentFileProvenWrongWithAFailedRefetchIsReported(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New().FetchOneVerified(context.Background(), failingStore(t).URL, dest, shaHex([]byte("expected")))
	if !errors.Is(err, ErrPresentMismatch) {
		t.Fatalf("err = %v, want ErrPresentMismatch", err)
	}
	if b, rerr := os.ReadFile(dest); rerr != nil || string(b) != "tampered" {
		t.Fatalf("the present file must be left in place for the caller: %q %v", b, rerr)
	}
	// It unwraps to the fetch error only: callers that test ErrDigestMismatch
	// (a corrupt TRANSFER) see what they saw before.
	if errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a transport failure must not read as a transfer digest mismatch: %v", err)
	}
}

// No file, and a failed fetch: nothing was proven wrong, so this is the
// ordinary miss, never ErrPresentMismatch.
func TestAnAbsentFileAndAFailedFetchIsNotAProvenMismatch(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "m.gguf")
	_, err := New().FetchOneVerified(context.Background(), failingStore(t).URL, dest, shaHex([]byte("expected")))
	if err == nil || errors.Is(err, ErrPresentMismatch) {
		t.Fatalf("err = %v, want a plain fetch failure", err)
	}
}

// A file that MATCHES and a store that is down: nothing to fetch, no error.
func TestAMatchingFileNeedsNoStore(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, []byte("expected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().FetchOneVerified(context.Background(), failingStore(t).URL, dest, shaHex([]byte("expected"))); err != nil {
		t.Fatalf("err = %v", err)
	}
}
