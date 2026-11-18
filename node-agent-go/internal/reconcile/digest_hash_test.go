// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"os"
	"strings"
	"testing"
)

// Proposal i935: a roll that only re-tags an image recreates nothing. The
// 0.6.24-0.6.26 locks pin the same ollama and stunnel digests; the spec hash
// keyed the tags, so every roll recreated node-b's and node-pi's Ollama twice.

const (
	dOllama  = "sha256:dd46912abd4946a5c580c4a85883a559736b48f6f2c4e24162b77b307b74ea9f"
	eOllama  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dStunnel = "sha256:04ff82dc284420add2ae9f23db1e8db60f8b96b9d5a7bf50ad979d8b5dda838d"
)

// vouched keys a digest-pinned ref by repo@digest and every stunnel tag by
// the digest the controller's manifest states (the same for each release).
func vouched(ref string) (string, bool) {
	if strings.Contains(ref, "@sha256:") {
		return offlineContentKey(ref)
	}
	if strings.HasPrefix(ref, "ghcr.io/noomesh/stunnel:") {
		return "ghcr.io/noomesh/stunnel@" + dStunnel, true
	}
	return ref, true
}

func ollamaAt(tag, digest string) placement {
	return placement{Backend: "ollama", Model: "harrier", Port: 11434, DesiredState: "running",
		Image: "ghcr.io/noomesh/ollama:" + tag + "@" + digest}
}

func TestSpecHashWith_ATagOnlyRollChangesNothing(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	rollTo(t, "v0.6.25")
	before, ok := specHashWith(ollamaAt("v0.6.25", dOllama), vouched)
	if !ok {
		t.Fatal("known keys gave an unknown hash")
	}
	rollTo(t, "v0.6.26")
	after, _ := specHashWith(ollamaAt("v0.6.26", dOllama), vouched)
	if before != after {
		t.Fatal("the gateway's new tag and the agent's own sidecar tag moved, the digests did not, yet the hash changed")
	}
	if got := decideBackendDrift(true, before, after, "", ""); got != driftConverged {
		t.Fatalf("a tag-only roll must leave the backend converged, got %v", got)
	}
	changed, _ := specHashWith(ollamaAt("v0.6.26", eOllama), vouched)
	if changed == before {
		t.Fatal("a new image digest must still change the hash")
	}
}

func TestSpecHashWith_AnUnvouchedSidecarStillFollowsItsTag(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	tagOnly := func(ref string) (string, bool) { return offlineContentKey(ref) }
	rollTo(t, "v0.6.25")
	before, _ := specHashWith(ollamaAt("v0.6.25", dOllama), tagOnly)
	rollTo(t, "v0.6.26")
	after, _ := specHashWith(ollamaAt("v0.6.26", dOllama), tagOnly)
	if before == after {
		t.Fatal("with no controller digest for the sidecar, its tag must still be hashed (today's behaviour)")
	}
}

func TestSpecHashWith_AnUnknownKeyIsNoDecision(t *testing.T) {
	t.Setenv("STUNNEL_IMAGE", "")
	rollTo(t, "v0.6.26")
	unknownSidecar := func(ref string) (string, bool) {
		if strings.HasPrefix(ref, "ghcr.io/noomesh/stunnel:") {
			return "", false
		}
		return vouched(ref)
	}
	if sum, ok := specHashWith(ollamaAt("v0.6.26", dOllama), unknownSidecar); ok || sum != "" {
		t.Fatalf("an unknown sidecar key must make the hash unknown, got %q, %v", sum, ok)
	}
}

func TestSpecHashWith_TheAgentsOwnGenerationsStillDrift(t *testing.T) {
	src, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func specHashWith(")
	end := strings.Index(body[start:], "\n}\n")
	fn := body[start : start+end]
	for _, want := range []string{`"door=%d\n", dockerpkg.BackendDoorGeneration`, `"envgen=%d\n", dockerpkg.BackendEnvGeneration`} {
		if !strings.Contains(fn, want) {
			t.Errorf("specHashWith no longer folds %s: a change in how the agent builds a backend must still recreate it", want)
		}
	}
}

// Build requirement (a): the hash stamped at creation is the content-keyed
// hash the tick decided on (StartBackend's SpecHash), so a running
// backend's label names the digest it was vouched for; and an unknown key
// never recreates a running backend.
func TestReconcileStampsTheContentKeyedHashItDecidedOn(t *testing.T) {
	src, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	decide := strings.Index(s, "desiredHash, hashKnown := specHashWith(p, func(ref string) (string, bool) { return dockerpkg.ContentKey(ctx, ref) })")
	unknown := strings.Index(s, `slog.Info("reconcile.spec_hash_unknown"`)
	drift := strings.Index(s, "switch decideBackendDrift(hasLabel, curHash, desiredHash, r.driftRecreated[p.Backend], t.floating[p.Backend])")
	stamp := strings.Index(s, "SpecHash:    desiredHash,")
	if decide < 0 || unknown < 0 || drift < 0 || stamp < 0 {
		t.Fatalf("reconcile no longer decides on and stamps the content-keyed hash (decide %d unknown %d drift %d stamp %d)", decide, unknown, drift, stamp)
	}
	if !(decide < unknown && unknown < drift && drift < stamp) {
		t.Fatal("order: content-keyed hash, then the unknown guard, then the drift decision, then the stamp")
	}
	// The exact guard: an unknown key, a running backend with its model ->
	// return, no decision.
	want := "\t\tif !hashKnown {\n\t\t\tif isRunning && modelname.Matches(curModel, p.Model) {"
	g := strings.Index(s, want)
	if g < 0 || g > unknown || g < decide {
		t.Fatal("the unknown-key guard is not `if !hashKnown { if isRunning && modelname.Matches(...) {` right after the hash")
	}
	if !strings.Contains(s[unknown:drift], "\t\t\t\treturn\n") {
		t.Fatal("an unknown key on a running backend must return before any drift decision")
	}
}
