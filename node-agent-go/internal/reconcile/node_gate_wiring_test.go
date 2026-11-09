// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

const gateDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// verifiedSet puts a set on disk the way the store leaves a verified one (the
// signed manifest and its marker, no files), with one GPU profile int8 that
// needs min_compute min.
func verifiedSet(t *testing.T, root string, ref modelsets.Ref, min string) {
	t.Helper()
	weights := sha256.Sum256([]byte("12345"))
	doc := map[string]any{
		"format": "noo-model-set/1", "id": ref.ID, "revision": ref.Revision,
		"kind": "voice", "modality": "stt", "runtime": []string{"rh-stt"},
		"source":  map[string]any{"local": map[string]any{"verified": true}},
		"license": map[string]any{"id": "MIT", "url": "https://example.invalid/mit", "accept": "none"},
		"files":   []map[string]any{{"path": "model.bin", "bytes": 5, "sha256": hex.EncodeToString(weights[:])}},
		"needs": map[string]any{
			"profiles":     []map[string]any{{"name": "int8", "accel": "cuda", "min_compute": min}},
			"cpu_fallback": false, "arch": []string{"amd64"},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ref.ID, ref.Revision)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	for name, content := range map[string][]byte{modelsets.ManifestName: b, modelsets.MarkerName: []byte(hex.EncodeToString(sum[:]) + "\n"), "model.bin": []byte("12345")} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func gateEntry() nodewl.Entry {
	p := "int8"
	return nodewl.Entry{
		Addon: "rhaddon", Name: "worker", State: nodewl.StateRunning,
		Image:   nodewl.ImageRef{Digest: gateDigest},
		Decl:    nodewl.Decl{Accel: nodewl.Accel{GPU: 1}, Models: []nodewl.Slot{{Slot: "main"}}},
		Sets:    map[string][]nodewl.SetRef{"main": {{ID: "rh-stt-small", Revision: "r1"}}},
		Profile: &p,
	}
}

// The gate the agent builds carries every input: a missing wire would skip
// that refusal in production while every nodepolicy test, which builds its own
// Gate, stays green.
func TestTheAgentsGateIsWiredWithEveryInput(t *testing.T) {
	dir := t.TempDir()
	sets := &modelsets.Store{Root: filepath.Join(dir, "sets")}
	verifiedSet(t, sets.Root, modelsets.Ref{ID: "rh-stt-small", Revision: "r1"}, "9.0")
	if st := sets.State(modelsets.Ref{ID: "rh-stt-small", Revision: "r1"}); st.State != modelsets.StateVerified {
		t.Fatalf("the hand-made set is %+v, not verified", st)
	}
	approvals := nodepolicy.NewApprovals(dir)
	caps := []string{"8.0"}
	nvidiaOK := false
	facts := &nodepolicy.Facts{ComputeCaps: func() ([]string, error) { return caps, nil }}
	nvidia := func(context.Context) (bool, error) { return nvidiaOK, nil }
	check := func(cfg *config.Config, mode nodepolicy.Mode, e nodewl.Entry) string {
		g := newGate(cfg, mode, approvals, nil, nvidia, facts, sets)
		return nodewl.CodeOf(g.Check(context.Background(), e))
	}
	e := gateEntry()

	// Mode.
	if got := check(&config.Config{}, nodepolicy.ModeNone, e); got != nodewl.ReasonConsentNone {
		t.Errorf("none: %q", got)
	}
	// Approvals.
	if got := check(&config.Config{}, nodepolicy.ModeApprove, e); got != nodewl.ReasonConsentUnapproved {
		t.Errorf("approve with nothing approved: %q", got)
	}
	approveOnNode(t, dir, "rhaddon", gateDigest)
	if got := check(&config.Config{}, nodepolicy.ModeApprove, e); got != nodewl.ReasonNvidiaRuntimeMissing {
		t.Errorf("approve with the approval, runtime missing: %q (consent passes, the next refusal speaks)", got)
	}
	// ControllerHost (the self-node marker) and its opt-in.
	if got := check(&config.Config{SelfNode: true}, nodepolicy.ModeAuto, e); got != nodewl.ReasonControllerHost {
		t.Errorf("self node, no opt-in: %q", got)
	}
	if got := check(&config.Config{SelfNode: true, AddonWorkloadsOnController: true}, nodepolicy.ModeAuto, e); got != nodewl.ReasonNvidiaRuntimeMissing {
		t.Errorf("self node, opted in: %q (the controller check passes, the next refusal speaks)", got)
	}
	// The nvidia runtime probe.
	if got := check(&config.Config{}, nodepolicy.ModeAuto, e); got != nodewl.ReasonNvidiaRuntimeMissing {
		t.Errorf("no nvidia runtime: %q", got)
	}
	// The set reader and the compute-capability probe, together: the profile's
	// min_compute (from the verified manifest) against the node's GPUs.
	nvidiaOK = true
	if got := check(&config.Config{}, nodepolicy.ModeAuto, e); got != nodewl.ReasonComputeCapLow {
		t.Errorf("GPU 8.0 against a profile needing 9.0: %q", got)
	}
	caps = []string{"9.0"}
	facts = &nodepolicy.Facts{ComputeCaps: func() ([]string, error) { return caps, nil }}
	if got := check(&config.Config{}, nodepolicy.ModeAuto, e); got != "" {
		t.Errorf("GPU 9.0 against a profile needing 9.0: %q", got)
	}
	// A profile the held set does not list is refused by CheckProfile through the same reader.
	bad := "nope"
	e.Profile = &bad
	if got := check(&config.Config{}, nodepolicy.ModeAuto, e); got != nodewl.ReasonProfileInvalid {
		t.Errorf("a profile the set lacks: %q", got)
	}
}
