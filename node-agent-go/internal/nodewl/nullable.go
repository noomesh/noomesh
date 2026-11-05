// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

// The fields the contract names nullable, as JSON pointers relative to each
// document's root, `*` standing for any one array index. JSON null anywhere
// else is refused with field_type. The table "Nullable fields" in
// docs/reference/node-workloads.md is the one list the agent, the CLI and the
// gateway copy; tests/test_i300_fixture_parity.py holds this file to it.
var (
	// nullableNodeWorkloads: node-workloads.json has no nullable field.
	nullableNodeWorkloads = []string{}
	// nullableModelSet: model-set.json has no nullable field.
	nullableModelSet = []string{}
	// nullableDesired: an entry holds no reservation until one is made.
	nullableDesired = []string{
		"/node_workloads/*/reservation",
	}
)
