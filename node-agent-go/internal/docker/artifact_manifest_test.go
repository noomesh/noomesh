// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

// askVia returns an injected request against srv with the given timeout,
// going through the real classifier (doArtifactManifest).
func askVia(srv *httptest.Server, timeout time.Duration) func(context.Context) (*artifactManifest, error) {
	return func(ctx context.Context) (*artifactManifest, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		c := srv.Client()
		c.Timeout = timeout
		return doArtifactManifest(c, req)
	}
}

func TestAwaitManifestFollows202UntilReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"hashing"}`))
			return
		}
		_, _ = w.Write([]byte(`{"sha256":"` + strings.ToUpper(testSHA) + `"}`))
	}))
	defer srv.Close()

	m, err := awaitManifest(context.Background(), time.Minute, askVia(srv, 5*time.Second))
	if err != nil {
		t.Fatalf("await: %v", err)
	}
	if m.SHA256 != testSHA {
		t.Fatalf("sha = %q, want lowercased %q", m.SHA256, testSHA)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 (two 202s, then 200)", got)
	}
}

func TestA202IsHashingNeverAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// One probe (the reconcile form): a 202 is "still hashing", with the
	// Retry-After capped.
	_, err := askVia(srv, 5*time.Second)(context.Background())
	var h *hashingError
	if !errors.As(err, &h) || !errors.Is(err, ErrArtifactHashing) || errors.Is(err, ErrArtifactAbsent) {
		t.Fatalf("err = %v, want ErrArtifactHashing and not absent", err)
	}
	if h.retryAfter != maxManifestRetryAfter {
		t.Fatalf("retryAfter = %v, want the cap %v", h.retryAfter, maxManifestRetryAfter)
	}
	// Waiting it out with no budget left: a timeout, not "absent".
	_, err = awaitManifest(context.Background(), 0, askVia(srv, 5*time.Second))
	if !errors.Is(err, ErrArtifactManifestTimeout) || errors.Is(err, ErrArtifactAbsent) {
		t.Fatalf("err = %v, want ErrArtifactManifestTimeout", err)
	}
}

func TestASlowAnswerSaysTimedOut(t *testing.T) {
	// An older gateway hashing inside the request — the 2026-10-10 failure.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	_, err := awaitManifest(context.Background(), time.Minute, askVia(srv, 100*time.Millisecond))
	if !errors.Is(err, ErrArtifactManifestTimeout) {
		t.Fatalf("err = %v, want ErrArtifactManifestTimeout", err)
	}
	msg := modelManifestError("gemma-4-E2B_q4_0-it.gguf", err).Error()
	if !strings.Contains(msg, "timed out") || strings.Contains(msg, "does not have it") {
		t.Fatalf("message must say timed out and must not claim the store lacks it: %q", msg)
	}
}

func TestModelManifestErrorWordsEachCause(t *testing.T) {
	if msg := modelManifestError("x.gguf", ErrArtifactAbsent).Error(); !strings.Contains(msg, "does not have it") {
		t.Fatalf("absent: %q", msg)
	}
	other := modelManifestError("x.gguf", errors.New("manifest request answered HTTP 500")).Error()
	if strings.Contains(other, "does not have it") || strings.Contains(other, "timed out") || !strings.Contains(other, "HTTP 500") {
		t.Fatalf("other: %q", other)
	}
}
