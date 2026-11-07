// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import "testing"

// Each way a row's identity can be unreadable skips that row on its own (it
// can be reported against nothing), whatever the other fields say.
func TestParseDesiredRowsSkipsEachKindOfUnidentifiableRow(t *testing.T) {
	for name, row := range map[string]string{
		"no addon":                   `{"name":"worker"}`,
		"an empty addon":             `{"addon":"","name":"worker"}`,
		"no name":                    `{"addon":"rhaddon"}`,
		"an empty name":              `{"addon":"rhaddon","name":""}`,
		"an addon of the wrong type": `{"addon":5,"name":"worker"}`,
		"a name of the wrong type":   `{"addon":"rhaddon","name":5}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDesiredRows([]byte(`{"node_workloads":[`+row+`]}`), "node-a")
			if err != nil || len(got) != 0 {
				t.Fatalf("rows = %+v, %v; want the row skipped", got, err)
			}
		})
	}
}
