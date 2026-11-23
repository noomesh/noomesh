// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func unvouchedFor(t *testing.T, backend string) *UnvouchedGGUF {
	t.Helper()
	rep, _ := UnvouchedGGUFReport().([]UnvouchedGGUF)
	for i := range rep {
		if rep[i].Backend == backend {
			return &rep[i]
		}
	}
	return nil
}

// A backend that starts on the local file because the controller could not
// vouch is recorded with its model, the reason and when it began.
func TestTheLocalFileStartRecordsTheUnvouchedBackend(t *testing.T) {
	ResetUnvouchedGGUF()
	t.Cleanup(ResetUnvouchedGGUF)
	dir := ggufStore(t, "m.gguf", ggufBytes(), func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) })
	if err := os.WriteFile(filepath.Join(dir, "m.gguf"), ggufBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Client{}).ggufStartGate(t.Context(), "llamacpp", "m.gguf", ""); err != nil {
		t.Fatalf("a present file must start: %v", err)
	}
	got := unvouchedFor(t, "llamacpp")
	if got == nil {
		t.Fatal("the local-file start was not recorded")
	}
	if got.Model != "m.gguf" || got.Since == "" || !strings.Contains(got.Reason, "no artifact manifest for m.gguf") {
		t.Fatalf("record = %+v", got)
	}
}

// A start whose preseed was verified clears the record.
func TestAVerifiedPreseedStartClearsTheUnvouchedRecord(t *testing.T) {
	ResetUnvouchedGGUF()
	t.Cleanup(ResetUnvouchedGGUF)
	w := ggufBytes()
	dir := ggufStore(t, "m.gguf", w, func(rw http.ResponseWriter, r *http.Request) { _, _ = rw.Write([]byte(ggufManifestJSON(w))) })
	recordUnvouchedGGUF("llamacpp", "m.gguf", dir, "earlier", time.Now())
	if err := (&Client{}).ggufStartGate(t.Context(), "llamacpp", "m.gguf", ""); err != nil {
		t.Fatal(err)
	}
	if unvouchedFor(t, "llamacpp") != nil {
		t.Fatal("a verified start left the record standing")
	}
}

func stubReverify(t *testing.T, sha string, merr error, file []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.gguf"), file, 0o600); err != nil {
		t.Fatal(err)
	}
	oldM, oldH := reverifyManifestFn, reverifyHashFn
	reverifyManifestFn = func(_ context.Context, _ string) (string, error) { return sha, merr }
	t.Cleanup(func() { reverifyManifestFn, reverifyHashFn = oldM, oldH })
	ResetUnvouchedGGUF()
	t.Cleanup(ResetUnvouchedGGUF)
	recordUnvouchedGGUF("llamacpp", "m.gguf", dir, "the controller is still hashing m.gguf", time.Now())
	return dir
}

// A manifest that matches the local file clears the state; the file is kept.
func TestAReverifyThatMatchesClearsTheUnvouchedState(t *testing.T) {
	w := ggufBytes()
	dir := stubReverify(t, sha(w), nil, w)
	if mm := ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf"); mm != nil {
		t.Fatalf("a matching file was refused: %v", mm)
	}
	if unvouchedFor(t, "llamacpp") != nil {
		t.Fatal("the state stands after a match")
	}
	if _, err := os.Stat(filepath.Join(dir, "m.gguf")); err != nil {
		t.Fatalf("the file must stay: %v", err)
	}
}

// A manifest that does not match refuses, naming the expected and actual
// sha256, and leaves the file in place for the verified copy to replace.
func TestAReverifyThatMismatchesRefusesNamingBothDigests(t *testing.T) {
	w := ggufBytes()
	want := strings.Repeat("ab", 32)
	dir := stubReverify(t, want, nil, w)
	mm := ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	if mm == nil {
		t.Fatal("a mismatching file was not refused")
	}
	for _, s := range []string{"m.gguf", "llamacpp", want, sha(w), "stopped"} {
		if !strings.Contains(mm.Error(), s) {
			t.Errorf("refusal %q lacks %q", mm.Error(), s)
		}
	}
	if mm.Expected != want || mm.Actual != sha(w) {
		t.Fatalf("expected/actual = %q/%q", mm.Expected, mm.Actual)
	}
	if unvouchedFor(t, "llamacpp") != nil {
		t.Fatal("the backend is stopped, so its unvouched state is cleared")
	}
	if _, err := os.Stat(filepath.Join(dir, "m.gguf")); err != nil {
		t.Fatalf("the file must not be deleted: %v", err)
	}
}

// While the controller does not answer, the state stands (reason refreshed)
// and the file is not hashed.
func TestAReverifyWithNoManifestKeepsTheStateAndDoesNotHash(t *testing.T) {
	dir := stubReverify(t, "", ErrArtifactAbsent, ggufBytes())
	_ = dir
	reverifyHashFn = func(string) (string, error) { t.Fatal("hashed without a manifest"); return "", nil }
	if mm := ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf"); mm != nil {
		t.Fatal(mm)
	}
	got := unvouchedFor(t, "llamacpp")
	if got == nil || !strings.Contains(got.Reason, "no artifact manifest") {
		t.Fatalf("state = %+v", got)
	}
}

// The gateway's typed 409 maps to ErrArtifactUnreadable carrying the path,
// owner and mode; any other 409 stays a refusal to vouch.
func TestTheUnreadable409MapsToATypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		if strings.HasSuffix(r.URL.Path, "/unreadable") {
			_, _ = w.Write([]byte(`{"status":"unreadable","kind":"gguf","name":"m.gguf","path":"/artifacts/models/m.gguf","owner":"1000:1000","mode":"0600","error":"open: Permission denied (os error 13)","fix":"make it readable by the gateway (uid 65532), e.g. chmod 0644 /artifacts/models/m.gguf"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"oid mismatch"}`))
	}))
	defer srv.Close()
	_, err := doArtifactManifest(srv.Client(), manifestReq(t, srv.URL+"/unreadable"))
	var un *ArtifactUnreadableError
	if !errors.Is(err, ErrArtifactUnreadable) || !errors.As(err, &un) {
		t.Fatalf("err = %v, want ErrArtifactUnreadable", err)
	}
	if un.Path != "/artifacts/models/m.gguf" || un.Owner != "1000:1000" || un.Mode != "0600" {
		t.Fatalf("carried %+v", un)
	}
	_, err = doArtifactManifest(srv.Client(), manifestReq(t, srv.URL+"/refused"))
	if !errors.Is(err, ErrArtifactRefused) || errors.Is(err, ErrArtifactUnreadable) {
		t.Fatalf("a plain 409 must stay a refusal: %v", err)
	}
}

func TestTheUnreadableReasonNamesPathOwnerModeAndFix(t *testing.T) {
	err := &ArtifactUnreadableError{Path: "/artifacts/models/m.gguf", Owner: "1000:1000", Mode: "0600",
		Fix: "make it readable by the gateway (uid 65532), e.g. chmod 0644 /artifacts/models/m.gguf"}
	want := "the controller cannot read /artifacts/models/m.gguf (owner 1000:1000, mode 0600): make it readable by the gateway (uid 65532), e.g. chmod 0644 /artifacts/models/m.gguf"
	if got := ggufManifestReason("m.gguf", err); got != want {
		t.Fatalf("reason = %q\nwant     %q", got, want)
	}
	if got := ggufManifestReason("m.gguf", &ArtifactUnreadableError{Path: "/p"}); !strings.HasPrefix(got, "the controller cannot read /p: ") {
		t.Fatalf("without owner and mode: %q", got)
	}
}
