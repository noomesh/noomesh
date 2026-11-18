// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

var quarantineNow = time.Date(2026, 11, 18, 3, 4, 5, 0, time.UTC)

func provenMismatch(dest string) error {
	return &preseed.PresentMismatchError{
		Mismatch: errors.New("digest mismatch: " + dest + " holds aaa, the manifest says bbb"),
		Fetch:    errors.New("503 store down"),
	}
}

// A GGUF proven wrong that could not be re-fetched: moved aside (not
// deleted), and the start is refused naming the file and the remedy.
func TestAProvenMismatchIsQuarantinedAndTheStartRefused(t *testing.T) {
	t.Setenv("NODE_ID", "gpu-2")
	dest := filepath.Join(t.TempDir(), "qwen3-4b.gguf")
	if err := os.WriteFile(dest, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ggufFetchOutcome("llamacpp", "qwen3-4b.gguf", dest, provenMismatch(dest), quarantineNow)
	var refusal *GGUFMismatchError
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a GGUFMismatchError refusal", err)
	}
	if _, serr := os.Stat(dest); !os.IsNotExist(serr) {
		t.Fatalf("the wrong file must not stay where llama.cpp loads it: %v", serr)
	}
	aside := dest + ".quarantined-20261118T030405Z"
	if b, rerr := os.ReadFile(aside); rerr != nil || string(b) != "tampered" {
		t.Fatalf("the file must be moved aside intact, not deleted: %q %v", b, rerr)
	}
	msg := err.Error()
	for _, want := range []string{"gguf_mismatch", dest, aside, "noo cluster sync-model-files gpu-2 -m qwen3-4b.gguf"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal %q lacks %q", msg, want)
		}
	}
}

// If the file cannot be moved aside the start is STILL refused, and the
// message says the file is still there and is not loaded.
func TestAProvenMismatchThatCannotBeMovedIsStillRefused(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "gone", "m.gguf") // rename fails: no such file
	err := ggufFetchOutcome("llamacpp", "m.gguf", dest, provenMismatch(dest), quarantineNow)
	var refusal *GGUFMismatchError
	if !errors.As(err, &refusal) || refusal.QuarantineErr == "" || !strings.Contains(err.Error(), "could NOT be moved aside") {
		t.Fatalf("err = %v, want a refusal that says the move failed", err)
	}
}

// No proof of a mismatch (no manifest, an unreachable controller, a plain
// miss): no refusal, and the local file stays to be loaded (availability).
func TestNoProofOfAMismatchStillLoadsTheLocalFile(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(dest, []byte("local"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, e := range []error{nil, errors.New("dial tcp: connection refused"), preseed.ErrDigestMismatch} {
		if got := ggufFetchOutcome("llamacpp", "m.gguf", dest, e, quarantineNow); got != nil {
			t.Fatalf("err %v: got refusal %v, want none", e, got)
		}
		if _, serr := os.Stat(dest); serr != nil {
			t.Fatalf("err %v: the local file must stay: %v", e, serr)
		}
	}
}

// The start path RETURNS preseedGGUF's refusal (it used to call it for its
// side effect and ignore the result): a refused GGUF never reaches llama.cpp,
// and the error takes the ordinary backend-start failure path (failover).
func TestTheStartPathReturnsTheGGUFRefusal(t *testing.T) {
	raw, err := os.ReadFile("backends.go")
	if err != nil {
		t.Fatal(err)
	}
	want := "if _, err := c.preseedGGUF(ctx, backend, model); err != nil {\n\t\treturn err\n\t}"
	if !strings.Contains(string(raw), want) {
		t.Fatalf("backends.go must return preseedGGUF's refusal from the start path:\n%s", want)
	}
	if strings.Count(string(raw), "c.preseedGGUF(") != 1 {
		t.Fatalf("preseedGGUF must have exactly one caller, the start path")
	}
}
