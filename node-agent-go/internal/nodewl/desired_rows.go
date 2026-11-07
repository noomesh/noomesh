// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"

	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
)

// DesiredRow is one `node_workloads` row judged on its own: Entry when Err is
// nil, else the refusal (a *Error whose Code is a reason) for the row named
// Addon/Name.
type DesiredRow struct {
	Addon, Name string
	Entry       Entry
	Err         error
}

// ParseDesiredRows is ParseDesired with a per-row verdict: one malformed row
// is that row's refusal and does not stop the others being read (the lifecycle
// reports each row's own reason; ParseDesired's first-refusal-wins is right
// for a caller that needs all-or-nothing, such as the model-set pruner). A
// fragment-level failure (not JSON, the key absent, a JSON null where the
// contract allows none) is an error with no rows. A row whose addon and name
// cannot be read at all cannot be reported against anything; it is skipped.
func ParseDesiredRows(b []byte, ownAgentCN string) ([]DesiredRow, error) {
	var frag struct {
		NodeWorkloads []json.RawMessage `json:"node_workloads"`
	}
	if err := decodeStrict(b, &frag, nullableDesired); err != nil && !mutant.On("dr_strict") {
		return nil, desiredInvalid(err)
	}
	if err := requireKeys(generic(b), "desired-config", "node_workloads"); err != nil && !mutant.On("dr_keys") {
		return nil, desiredInvalid(err)
	}
	out := make([]DesiredRow, 0, len(frag.NodeWorkloads))
	seen := map[string]int{}
	for _, raw := range frag.NodeWorkloads {
		var id struct {
			Addon string `json:"addon"`
			Name  string `json:"name"`
		}
		if (json.Unmarshal(raw, &id) != nil && !mutant.On("dr_id_unmarshal")) || (id.Addon == "" && !mutant.On("dr_id_addon")) || (id.Name == "" && !mutant.On("dr_id_name")) {
			continue
		}
		row := DesiredRow{Addon: id.Addon, Name: id.Name}
		k := id.Addon + "/" + id.Name
		if i, dup := seen[k]; dup && !mutant.On("dr_dup") {
			// Both copies are refused: which one is meant is unknowable.
			dupErr := fail(ReasonDesiredInvalid, "%s is listed twice", k)
			row.Err = dupErr
			if mutant.On("dr_dup_second") {
				row.Entry, row.Err = parseEntry(raw, ownAgentCN)
			}
			if !mutant.On("dr_dup_first") {
				out[i].Err = dupErr
			}
			out = append(out, row)
			continue
		}
		seen[k] = len(out)
		row.Entry, row.Err = parseEntry(raw, ownAgentCN)
		if mutant.On("dr_entry") {
			row.Err = nil
		}
		out = append(out, row)
	}
	return out, nil
}
