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
	"sync/atomic"
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

// stubReverify records an unvouched backend over a file and stubs the
// manifest answer and the hash. hash nil = the real hash.
func stubReverify(t *testing.T, sha string, merr error, file []byte, hash func(context.Context, string) (string, error)) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.gguf"), file, 0o600); err != nil {
		t.Fatal(err)
	}
	oldM, oldH, oldT := reverifyManifestFn, reverifyHashFn, reverifyHashTimeout
	reverifyManifestFn = func(_ context.Context, _ string) (string, error) { return sha, merr }
	if hash != nil {
		reverifyHashFn = hash
	}
	ResetUnvouchedGGUF()
	t.Cleanup(func() {
		if done := unvouchedHashFinished(); done != nil {
			<-done
		}
		reverifyManifestFn, reverifyHashFn, reverifyHashTimeout = oldM, oldH, oldT
		ResetUnvouchedGGUF()
	})
	recordUnvouchedGGUF("llamacpp", "m.gguf", dir, "the controller is still hashing m.gguf", time.Now())
	return dir
}

// pass runs one reconcile step, then waits for the background hash to end (if
// one was started) so the next pass sees its result.
func pass(t *testing.T) *GGUFReverifyMismatchError {
	t.Helper()
	mm := ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	if done := unvouchedHashFinished(); done != nil {
		<-done
	}
	return mm
}

// A manifest that matches the local file clears the state on the pass that
// picks up the hash; the file is kept.
func TestAReverifyThatMatchesClearsTheUnvouchedState(t *testing.T) {
	w := ggufBytes()
	dir := stubReverify(t, sha(w), nil, w, nil)
	if mm := pass(t); mm != nil {
		t.Fatalf("a matching file was refused: %v", mm)
	}
	if got := unvouchedFor(t, "llamacpp"); got == nil || got.State != "verifying" {
		t.Fatalf("after the starting pass the state is %+v, want verifying", got)
	}
	if mm := pass(t); mm != nil {
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
	dir := stubReverify(t, want, nil, w, nil)
	if mm := pass(t); mm != nil {
		t.Fatalf("the starting pass must not decide: %v", mm)
	}
	mm := pass(t)
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
	stubReverify(t, "", ErrArtifactAbsent, ggufBytes(), func(context.Context, string) (string, error) {
		t.Error("hashed without a manifest")
		return "", nil
	})
	if mm := pass(t); mm != nil {
		t.Fatal(mm)
	}
	got := unvouchedFor(t, "llamacpp")
	if got == nil || got.State != "unverified" || !strings.Contains(got.Reason, "no artifact manifest") {
		t.Fatalf("state = %+v", got)
	}
}

// A pass returns promptly while a (blocking) hash runs, and the record reads
// "verifying since <t>".
func TestAPassReturnsPromptlyWhileTheHashRuns(t *testing.T) {
	release := make(chan struct{})
	stubReverify(t, "x", nil, ggufBytes(), func(ctx context.Context, _ string) (string, error) {
		select {
		case <-release:
			return "x", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	})
	defer close(release)
	passes := make(chan struct{})
	go func() {
		ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
		ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf") // a running hash: still no wait
		close(passes)
	}()
	select {
	case <-passes:
	case <-time.After(2 * time.Second):
		t.Fatal("a pass was still waiting on the running hash after 2s")
	}
	got := unvouchedFor(t, "llamacpp")
	if got == nil || got.State != "verifying" || got.VerifyingSince == "" {
		t.Fatalf("record = %+v, want verifying with a start time", got)
	}
}

// The result is picked up by a LATER pass once the hash finishes.
func TestTheFinishedHashIsPickedUpByALaterPass(t *testing.T) {
	release := make(chan struct{})
	good := strings.Repeat("a", 64)
	stubReverify(t, good, nil, ggufBytes(), func(context.Context, string) (string, error) {
		<-release
		return good, nil
	})
	ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	if unvouchedFor(t, "llamacpp") == nil {
		t.Fatal("cleared before the hash finished")
	}
	close(release)
	<-unvouchedHashFinished()
	if mm := ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf"); mm != nil {
		t.Fatal(mm)
	}
	if unvouchedFor(t, "llamacpp") != nil {
		t.Fatal("the later pass did not pick up the match")
	}
}

// A cancelled context ends the hash and leaves the record unverified, with
// the reason, never stuck at verifying; a later pass tries again.
func TestACancelledContextEndsTheHashAndLeavesTheStateUnverified(t *testing.T) {
	stubReverify(t, "x", nil, ggufBytes(), func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	ReverifyUnvouchedGGUF(ctx, "llamacpp", "m.gguf")
	done := unvouchedHashFinished()
	cancel()
	<-done
	got := unvouchedFor(t, "llamacpp")
	if got == nil || got.State != "unverified" || got.VerifyingSince != "" || !strings.Contains(got.Reason, "did not finish") {
		t.Fatalf("record = %+v, want unverified with the reason", got)
	}
	if unvouchedHashFinished() != nil {
		t.Fatal("the dead hash still holds the node's one hash slot")
	}
}

// A hash past its timeout ends the same way.
func TestAHashPastItsTimeoutReturnsToUnverified(t *testing.T) {
	stubReverify(t, "x", nil, ggufBytes(), func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	reverifyHashTimeout = 50 * time.Millisecond
	ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	<-unvouchedHashFinished()
	if got := unvouchedFor(t, "llamacpp"); got == nil || got.State != "unverified" {
		t.Fatalf("record = %+v", got)
	}
}

// Only one hash runs at a time on a node: a second backend waits its turn.
func TestOnlyOneHashRunsAtATime(t *testing.T) {
	var running, peak atomic.Int32
	release := make(chan struct{})
	stubReverify(t, "x", nil, ggufBytes(), func(ctx context.Context, _ string) (string, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer running.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return "x", nil
	})
	recordUnvouchedGGUF("reranker", "m.gguf", t.TempDir(), "r", time.Now())
	ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	ReverifyUnvouchedGGUF(t.Context(), "reranker", "m.gguf")
	ReverifyUnvouchedGGUF(t.Context(), "llamacpp", "m.gguf")
	if r := unvouchedFor(t, "reranker"); r == nil || r.State != "unverified" {
		t.Fatalf("the second backend started a hash: %+v", r)
	}
	close(release)
	<-unvouchedHashFinished()
	if peak.Load() != 1 {
		t.Fatalf("%d hashes ran at once", peak.Load())
	}
}

// The gateway's typed 409 maps to ErrArtifactUnreadable carrying the path,
// owner and mode; any other 409 stays a refusal to vouch.
func TestTheUnreadable409MapsToATypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		if strings.HasSuffix(r.URL.Path, "/unreadable") {
			_, _ = w.Write([]byte(`{"status":"unreadable","kind":"gguf","name":"m.gguf","path":"/artifacts/models/m.gguf","path_is":"the gateway container's view (/artifacts/models)","owner":"1000:1000","mode":"0600","error":"open: Permission denied (os error 13)","fix":"run noo cluster verify on the controller"}`))
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

func TestTheUnreadableReasonNamesModelOwnerModeAndWhereTheHostPathIs(t *testing.T) {
	err := &ArtifactUnreadableError{Path: "/artifacts/models/m.gguf", Owner: "1000:1000", Mode: "0600"}
	want := "the controller cannot read m.gguf (owner 1000:1000, mode 0600; /artifacts/models/m.gguf is the gateway container's view): `noo cluster verify` on the controller names its host path and the fix (`model store readable`)"
	got := ggufManifestReason("m.gguf", err)
	if got != want {
		t.Fatalf("reason = %q\nwant     %q", got, want)
	}
	if strings.Contains(got, "chmod") {
		t.Fatalf("a host command from the container's path: %q", got)
	}
	if got := ggufManifestReason("m.gguf", &ArtifactUnreadableError{Path: "/p"}); !strings.HasPrefix(got, "the controller cannot read m.gguf (/p is the gateway container's view): ") {
		t.Fatalf("without owner and mode: %q", got)
	}
}
