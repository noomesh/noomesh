// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"testing"
	"time"
)

func basePlacement() placement {
	return placement{
		Backend: "vllm",
		Model:   "google/gemma-4-12B-it",
		Image:   "vllm/vllm-openai:latest",
		Port:    8000,
		TLS:     false,
		Env: map[string]string{
			"VLLM_TOOL_PARSER":   "pythonic",
			"VLLM_MAX_MODEL_LEN": "16384",
		},
		DesiredState: "running",
	}
}

// Stability: the same spec hashes identically across repeated calls, and is
// independent of Env map construction order. This is the critical correctness
// property — an unchanged placement must not churn the hash and trigger an
// endless recreate loop.
func TestSpecHash_Stable(t *testing.T) {
	p := basePlacement()
	first := specHash(p)
	for i := 0; i < 100; i++ {
		if got := specHash(p); got != first {
			t.Fatalf("hash not stable across calls: %q != %q", got, first)
		}
	}

	// A placement carrying the same fields but with the env map built in a
	// different insertion order must hash the same (keys are sorted).
	q := basePlacement()
	q.Env = map[string]string{}
	q.Env["VLLM_MAX_MODEL_LEN"] = "16384"
	q.Env["VLLM_TOOL_PARSER"] = "pythonic"
	if got := specHash(q); got != first {
		t.Fatalf("hash depends on env insertion order: %q != %q", got, first)
	}
}

// Sensitivity: a change to any hashed field yields a different hash.
func TestSpecHash_Sensitive(t *testing.T) {
	base := specHash(basePlacement())

	cases := map[string]func(p *placement){
		"model": func(p *placement) { p.Model = "google/gemma-4-27B-it" },
		"image": func(p *placement) { p.Image = "vllm/vllm-openai:v0.25.0" },
		"port":  func(p *placement) { p.Port = 8001 },
		"tls":   func(p *placement) { p.TLS = true },
		"env_value_change": func(p *placement) {
			p.Env["VLLM_TOOL_PARSER"] = "hermes"
		},
		"env_new_key": func(p *placement) {
			p.Env["VLLM_REASONING_PARSER"] = "deepseek_r1"
		},
		"env_remove_key": func(p *placement) {
			delete(p.Env, "VLLM_TOOL_PARSER")
		},
	}

	for name, mutate := range cases {
		p := basePlacement()
		mutate(&p)
		if got := specHash(p); got == base {
			t.Errorf("%s: hash unchanged after mutation, expected drift", name)
		}
	}
}

// The reported host8 incident: setting VLLM_REASONING_PARSER must change the
// hash so the reconciler recreates the container.
func TestSpecHash_ReasoningParserTriggersDrift(t *testing.T) {
	before := basePlacement()
	after := basePlacement()
	after.Env["VLLM_REASONING_PARSER"] = "deepseek_r1"
	if specHash(before) == specHash(after) {
		t.Fatal("adding VLLM_REASONING_PARSER did not change the spec hash")
	}
}

// Volatile keys are excluded: their presence or value must not move the hash,
// otherwise agent-injected/node-dependent env would report false drift on a
// placement the operator never touched.
func TestSpecHash_VolatileKeysExcluded(t *testing.T) {
	base := specHash(basePlacement())

	for key := range volatileEnvKeys {
		p := basePlacement()
		p.Env[key] = "some-injected-value"
		if got := specHash(p); got != base {
			t.Errorf("volatile key %q changed the hash (%q != %q)", key, got, base)
		}

		// And changing an already-present volatile key's value is a no-op too.
		q := basePlacement()
		q.Env[key] = "value-a"
		r := basePlacement()
		r.Env[key] = "value-b"
		if specHash(q) != specHash(r) {
			t.Errorf("volatile key %q value change moved the hash", key)
		}
	}
}

// A non-volatile env key still counts even if it shares a prefix with real
// config — only the exact volatile keys are excluded.
func TestSpecHash_NonVolatileEnvCounts(t *testing.T) {
	base := specHash(basePlacement())
	p := basePlacement()
	p.Env["N_CTX"] = "8192" // not in the volatile set
	if specHash(p) == base {
		t.Fatal("non-volatile env key N_CTX did not affect the hash")
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
	if got := shortHash("abcdef12345"); got != "abcdef12" {
		t.Errorf("long: got %q, want abcdef12", got)
	}
	if got := shortHash("abc"); got != "abc" {
		t.Errorf("short: got %q, want abc", got)
	}
}

// decideSpecDrift covers the recreate/converge/stuck state machine, including
// the absent-label adoption path (a container predating this feature) and the
// restart-loop guard.
func TestDecideSpecDrift(t *testing.T) {
	const desired = "deadbeefcafe0000"

	cases := []struct {
		name          string
		hasLabel      bool
		curHash       string
		lastRecreated string
		want          driftDecision
	}{
		{"converged", true, desired, "", driftConverged},
		{"converged_ignores_stale_bookkeeping", true, desired, "oldhash", driftConverged},
		{"absent_label_first_seen", false, "", "", driftRecreate},
		{"absent_label_after_recreate_is_stuck", false, "", desired, driftStuck},
		{"mismatch_first_seen", true, "oldhash", "", driftRecreate},
		{"mismatch_after_recreate_is_stuck", true, "oldhash", desired, driftStuck},
		{"mismatch_stuck_only_for_same_desired", true, "oldhash", "otherdesired", driftRecreate},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideSpecDrift(tc.hasLabel, tc.curHash, desired, tc.lastRecreated)
			if got != tc.want {
				t.Errorf("decideSpecDrift(%v,%q,%q,%q) = %d, want %d",
					tc.hasLabel, tc.curHash, desired, tc.lastRecreated, got, tc.want)
			}
		})
	}
}

// The absent-label adoption path, end to end through the decision +
// bookkeeping: first pass recreates, and once the new container carries the
// matching label the next pass converges (and clears bookkeeping).
func TestDriftBookkeeping_AbsentLabelAdoption(t *testing.T) {
	desired := specHash(basePlacement())
	book := map[string]string{}

	// Tick 1: running, model matches, no label (legacy container).
	d := decideSpecDrift(false, "", desired, book["vllm"])
	if d != driftRecreate {
		t.Fatalf("tick1: want driftRecreate, got %d", d)
	}
	book["vllm"] = desired // reconciler records the recreate

	// Tick 2 (recreate succeeded — container now stamped with the label):
	d = decideSpecDrift(true, desired, desired, book["vllm"])
	if d != driftConverged {
		t.Fatalf("tick2: want driftConverged, got %d", d)
	}
	delete(book, "vllm") // reconciler clears on convergence
	if _, ok := book["vllm"]; ok {
		t.Fatal("bookkeeping not cleared on convergence")
	}
}

// A native backend must never reach the container drift machinery.
//
// This documents WHY the reconciler skips natively-served backends explicitly
// rather than relying on what the drift logic happens to do with them. A
// native backend has no container, so BackendLabels reports no spec hash for
// it, and decideSpecDrift then sees hasLabel=false:
func TestNativeBackendWouldOtherwiseBeRecreatedForever(t *testing.T) {
	// First tick: no label, nothing recreated yet -> recreate.
	if got := decideSpecDrift(false, "", "spec-abc", ""); got != driftRecreate {
		t.Fatalf("decideSpecDrift(no label) = %v, want driftRecreate", got)
	}
	// The recreate would be ContainerCreate against a backend that is not a
	// container — on a Mac, against a Docker daemon that is not even running.
	// The drift-stuck guard bounds it to one attempt per spec...
	if got := decideSpecDrift(false, "", "spec-abc", "spec-abc"); got != driftStuck {
		t.Fatalf("decideSpecDrift(already tried) = %v, want driftStuck", got)
	}
	// ...but that guard is INCIDENTAL protection: it was written for a
	// container whose label failed to stamp, not for a runtime that can never
	// produce one, and any change to the desired spec re-arms the loop.
	if got := decideSpecDrift(false, "", "spec-xyz", "spec-abc"); got != driftRecreate {
		t.Fatalf("decideSpecDrift(new spec) = %v, want driftRecreate — the loop re-arms", got)
	}
	// Hence the explicit skip in Converge, which is the behaviour under test
	// everywhere else in this file. If that skip is ever removed, a Mac
	// running a native ollama tries to create a container on every placement
	// change, forever, and the only symptom is a log line.
}

func TestShouldStartOllamaPull(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	if !shouldStartOllamaPull(nil, now) {
		t.Fatal("first sight of a model must pull")
	}
	if shouldStartOllamaPull(&ollamaPullState{inFlight: true}, now) {
		t.Fatal("must not start a second pull while one is in flight")
	}
	recent := &ollamaPullState{lastFailed: now.Add(-ollamaPullRetryAfter / 2), failures: 1}
	if shouldStartOllamaPull(recent, now) {
		t.Fatal("a failed pull must wait out the backoff")
	}
	old := &ollamaPullState{lastFailed: now.Add(-ollamaPullRetryAfter), failures: 1}
	if !shouldStartOllamaPull(old, now) {
		t.Fatal("after the backoff the pull is retried")
	}
}
