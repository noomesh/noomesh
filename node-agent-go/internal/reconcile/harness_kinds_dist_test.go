// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"regexp"
	"testing"
)

// The platforms the fleet has, in the agent's facts naming (<os>-<arch>).
var fleetPlatforms = []string{"linux-x86_64", "linux-aarch64", "macos-aarch64"}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Every kind that launches a vendor CLI carries the pinned artefact the
// controller stages for it (config/harness-kinds.json `distribution`,
// written by scripts/vendor-pin.py): a version and a sha256 for every
// platform the fleet has, or one `any` digest for a platform-independent
// artefact. `noo` has none. The agent only parses it; the applier installs.
func TestEveryForeignKindHasAPinnedDistribution(t *testing.T) {
	for _, k := range harnessKindTable {
		raw := string(k.Distribution)
		if k.CLI == nil {
			if raw != "" && raw != "null" {
				t.Errorf("%s has no CLI but a distribution: %s", k.Kind, raw)
			}
			continue
		}
		if raw == "" || raw == "null" {
			t.Errorf("%s launches %q but has no distribution", k.Kind, *k.CLI)
			continue
		}
		var d struct {
			Format  string            `json:"format"`
			Source  string            `json:"source"`
			Version string            `json:"version"`
			SHA256  map[string]string `json:"sha256"`
			Entry   string            `json:"entry"`
			Runtime *string           `json:"runtime"`
		}
		if err := json.Unmarshal(k.Distribution, &d); err != nil {
			t.Errorf("%s distribution: %v", k.Kind, err)
			continue
		}
		if d.Version == "" || d.Source == "" || d.Entry == "" || d.Format == "" {
			t.Errorf("%s distribution lacks version/source/entry/format: %+v", k.Kind, d)
		}
		if h, ok := d.SHA256["any"]; ok {
			if len(d.SHA256) != 1 || !hex64.MatchString(h) {
				t.Errorf("%s: an `any` sha256 must be the only key and 64 hex: %v", k.Kind, d.SHA256)
			}
		} else {
			for _, p := range fleetPlatforms {
				if !hex64.MatchString(d.SHA256[p]) {
					t.Errorf("%s: sha256[%s] = %q, want 64 hex", k.Kind, p, d.SHA256[p])
				}
			}
		}
		if d.Runtime != nil {
			var doc struct {
				Runtimes map[string]json.RawMessage `json:"runtimes"`
			}
			_ = json.Unmarshal(harnessKindsJSON, &doc)
			if _, ok := doc.Runtimes[*d.Runtime]; !ok {
				t.Errorf("%s needs runtime %q, which the table does not pin", k.Kind, *d.Runtime)
			}
		}
	}
}
