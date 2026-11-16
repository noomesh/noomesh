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

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
)

const fixtureMainRev = "0123456789abcdef0123456789abcdef01234567"

// plantVerified writes a set the way a sealed fetch leaves it (manifest,
// files of the manifest's sizes, marker = sha256 of the manifest).
func plantVerified(t *testing.T, root string, ref modelsets.Ref) {
	t.Helper()
	body := []byte("weights")
	sum := sha256.Sum256(body)
	doc := map[string]any{
		"format": "noo-model-set/1", "id": ref.ID, "revision": ref.Revision,
		"kind": "voice", "modality": "stt", "runtime": []string{"rh-stt"},
		"source":  map[string]any{"local": map[string]any{"verified": true}},
		"license": map[string]any{"id": "MIT", "url": "https://example.invalid/mit", "accept": "none"},
		"files":   []map[string]any{{"path": "model.bin", "bytes": len(body), "sha256": hex.EncodeToString(sum[:])}},
		"needs": map[string]any{
			"profiles":     []map[string]any{{"name": "cpu", "accel": "cpu"}},
			"cpu_fallback": true, "arch": []string{"amd64"},
		},
	}
	m, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(root, ref.ID, ref.Revision)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	ms := sha256.Sum256(m)
	for name, b := range map[string][]byte{
		"model.bin": body, modelsets.ManifestName: m, modelsets.MarkerName: []byte(hex.EncodeToString(ms[:]) + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(d, name), b, 0o444); err != nil {
			t.Fatal(err)
		}
	}
}

// The same tick that Syncs a new revision Prunes: the verified old revision
// of that set is kept (and reported) while the new one is not verified, and
// pruned on the first tick after it verifies.
func TestConvergeKeepsTheLinkSourceUntilTheNewRevisionVerifies(t *testing.T) {
	r, st, root := setsRig(t)
	old := modelsets.Ref{ID: "rh-s2s-7b", Revision: "r0"}
	plantVerified(t, root, old)
	tk := &tick{desired: &desiredConfig{NodeWorkloads: fixture(t)}}

	r.convergeModelSets(context.Background(), tk)
	st.Wait()
	if st.State(old).State != modelsets.StateVerified {
		t.Fatal("the link source was pruned while the new revision is not verified")
	}
	rows, _ := r.ModelSetsReport().([]modelsets.Row)
	var seen bool
	for _, row := range rows {
		if row.ID == old.ID && row.Revision == old.Revision {
			seen = row.LinkSourceFor == fixtureMainRev
		}
	}
	if !seen {
		t.Fatalf("the held revision is not reported as a link source: %+v", rows)
	}

	plantVerified(t, root, modelsets.Ref{ID: "rh-s2s-7b", Revision: fixtureMainRev})
	r.convergeModelSets(context.Background(), tk)
	st.Wait()
	if _, err := os.Stat(filepath.Join(root, old.ID, old.Revision)); err == nil {
		t.Fatal("the link source outlived the verification of the new revision")
	}
}
