// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func manifestReq(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// The three answers reconcile and import-model must tell apart: the store
// has it, the store said it does not, and the question went unanswered.
func TestDoArtifactManifest_ClassifiesTheAnswer(t *testing.T) {
	sha := strings.Repeat("AB", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/present"):
			_, _ = w.Write([]byte(`{"sha256":"` + sha + `"}`))
		case strings.HasSuffix(r.URL.Path, "/absent"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/oldgateway"):
			http.Error(w, "unknown artifact kind 'modelfile'", http.StatusBadRequest)
		case strings.HasSuffix(r.URL.Path, "/broken"):
			http.Error(w, "boom", http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/slow"):
			time.Sleep(300 * time.Millisecond)
		}
	}))
	defer srv.Close()

	m, err := doArtifactManifest(srv.Client(), manifestReq(t, srv.URL+"/present"))
	if err != nil || m == nil || m.SHA256 != strings.ToLower(sha) {
		t.Fatalf("present: m=%+v err=%v, want the lowercased digest", m, err)
	}
	for _, p := range []string{"/absent", "/oldgateway"} {
		if _, err := doArtifactManifest(srv.Client(), manifestReq(t, srv.URL+p)); !errors.Is(err, ErrArtifactAbsent) {
			t.Errorf("%s: err=%v, want ErrArtifactAbsent", p, err)
		}
	}
	if _, err := doArtifactManifest(srv.Client(), manifestReq(t, srv.URL+"/broken")); err == nil || errors.Is(err, ErrArtifactAbsent) {
		t.Errorf("a 500 is not an answer that the store lacks it: %v", err)
	}
	slow := &http.Client{Timeout: 50 * time.Millisecond}
	_, err = doArtifactManifest(slow, manifestReq(t, srv.URL+"/slow"))
	if err == nil || errors.Is(err, ErrArtifactAbsent) || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("a timeout must say so and must not read as absent: %v", err)
	}
}

// A registry tag never asks the store: it cannot be a store artifact.
func TestModelInStore_RegistryTagIsNotAsked(t *testing.T) {
	t.Setenv("CONTROLLER_URL", "")
	in, err := ModelInStore(t.Context(), "llama3.2:1b")
	if in || err != nil {
		t.Fatalf("registry tag: in=%v err=%v, want (false, nil) without asking", in, err)
	}
	// A bare name with no controller to ask is "could not ask", not "absent".
	if _, err := ModelInStore(t.Context(), "harrier"); err == nil {
		t.Fatal("no controller URL must be an error, not an answer")
	}
}
