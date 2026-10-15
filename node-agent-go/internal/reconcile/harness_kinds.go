// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// harnessKindsJSON is config/harness-kinds.json, the ONE declared table of
// harness kinds (the gateway embeds the same file; a go:embed cannot reach
// outside this module, so this is a copy, and
// TestHarnessKindsTableMatchesTheShippedFile holds the two equal).
//
//go:embed harness_kinds.json
var harnessKindsJSON []byte

// harnessKind is one row of the table.
type harnessKind struct {
	Kind  string   `json:"kind"`
	Title string   `json:"title"`
	Wire  string   `json:"wire"`
	Wires []string `json:"wires"`
	// Runner is the executable the applier installs beside the agent; nil
	// means no runner ships for this kind yet and the kind is refused.
	Runner       *string           `json:"runner"`
	TelemetryOff map[string]string `json:"telemetry_off"`
}

var (
	// harnessKindTable is the table in declared order (`noo` first).
	harnessKindTable []harnessKind
	// harnessKinds is kind → the node chat backend types that serve its
	// wire. `noo` speaks every backend's wire; Claude Code speaks
	// Anthropic's Messages API (ollama serves it, vllm/llamacpp do not);
	// Copilot CLI speaks OpenAI's Chat Completions; Codex CLI needs
	// OpenAI's Responses API, which no node backend serves yet.
	harnessKinds map[string][]string
	// harnessTelemetryOff is kind → the vendor telemetry switches its
	// runner must launch the CLI with (docs/security/telemetry.md, "Agent
	// harnesses", names each switch and the vendor documentation behind
	// it). Every kind has an entry, even an empty one, so a new kind cannot
	// ship without deciding; whatever launches a CLI must merge these AFTER
	// any operator or placement value, so a placement cannot switch a
	// vendor's reporting back on.
	harnessTelemetryOff map[string]map[string]string
)

func init() {
	t, err := parseHarnessKinds(harnessKindsJSON)
	if err != nil {
		panic("reconcile: embedded harness_kinds.json: " + err.Error())
	}
	harnessKindTable = t
	harnessKinds = make(map[string][]string, len(t))
	harnessTelemetryOff = make(map[string]map[string]string, len(t))
	for _, k := range t {
		harnessKinds[k.Kind] = k.Wires
		harnessTelemetryOff[k.Kind] = k.TelemetryOff
	}
}

func parseHarnessKinds(raw []byte) ([]harnessKind, error) {
	var doc struct {
		Kinds []harnessKind `json:"kinds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Kinds) == 0 {
		return nil, fmt.Errorf("no kinds")
	}
	seen := map[string]bool{}
	for i := range doc.Kinds {
		k := &doc.Kinds[i]
		if k.Kind == "" || seen[k.Kind] {
			return nil, fmt.Errorf("kind %q is empty or repeated", k.Kind)
		}
		seen[k.Kind] = true
		if k.TelemetryOff == nil {
			return nil, fmt.Errorf("kind %q has no telemetry_off entry", k.Kind)
		}
	}
	return doc.Kinds, nil
}

// harnessKindByName is the table row for kind.
func harnessKindByName(kind string) (harnessKind, bool) {
	for _, k := range harnessKindTable {
		if k.Kind == kind {
			return k, true
		}
	}
	return harnessKind{}, false
}

// knownHarnessKinds is the kinds in declared order, for messages.
func knownHarnessKinds() string {
	names := make([]string, 0, len(harnessKindTable))
	for _, k := range harnessKindTable {
		names = append(names, k.Kind)
	}
	return strings.Join(names, ", ")
}

// HarnessTelemetryEnv returns a copy of the switches a harness kind must be
// launched with (nil for a kind with none). An UNKNOWN kind returns ok=false:
// absent is not "nothing to switch off".
func HarnessTelemetryEnv(kind string) (env map[string]string, ok bool) {
	m, known := harnessTelemetryOff[kind]
	if !known {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out, true
}

// harnessKindCompatible says whether `kind` can talk to `backend`; the
// error names the backends that would do, or says that none would.
func harnessKindCompatible(kind, backend string) error {
	k, known := harnessKindByName(kind)
	if !known {
		return fmt.Errorf("unknown harness kind %q (known: %s)", kind, knownHarnessKinds())
	}
	if len(k.Wires) == 0 {
		return fmt.Errorf("no chat backend on this node can serve harness kind %q (it needs %s): its wire is not served by any backend yet", kind, k.Wire)
	}
	for _, b := range k.Wires {
		if b == backend {
			return nil
		}
	}
	return fmt.Errorf("harness kind %q cannot use a %s backend; it needs one of %s", kind, backend, strings.Join(k.Wires, ", "))
}

// runnerOnDisk says whether a harness runner is installed where the
// applier puts it: /usr/local/bin/<runner> on Linux (scripts/noo-apply.sh,
// the `harness-binary` rail kind), <home>/noomesh/bin/<runner> on macOS
// (noo-cli node_fetch.rs darwin_apply: base = /Users/<user>/noomesh, the
// account this agent runs as). When the home directory cannot be found it
// answers true: not knowing where to look is not evidence of absence (the
// host6 lesson in hostsvc.ErrAbsent), and the service-state check after
// this one still reports a harness that is not installed.
func runnerOnDisk(runner string) bool {
	path := filepath.Join("/usr/local/bin", runner)
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			if u, uerr := user.Current(); uerr == nil {
				home = u.HomeDir
			}
		}
		if home == "" {
			return true
		}
		path = filepath.Join(home, "noomesh", "bin", runner)
	}
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
