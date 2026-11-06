// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
)

// An older gateway sends no node_workloads at all. That is "nothing to do",
// not "desired-config unreadable": the node must not warn about an unreadable
// config on every tick (ParseDesired would refuse empty input, which is why
// the outcome alone cannot tell the two apart).
func TestNoNodeWorkloadsKeyIsNotReportedAsUnreadable(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	r, _, _ := setsRig(t)
	for name, nw := range map[string]json.RawMessage{"nil": nil, "empty": json.RawMessage("")} {
		buf.Reset()
		if !r.convergeModelSets(context.Background(), &tick{desired: &desiredConfig{NodeWorkloads: nw}}) {
			t.Errorf("%s: the pass must go on", name)
		}
		if strings.Contains(buf.String(), "unreadable") {
			t.Errorf("%s: an absent node_workloads was logged as unreadable: %s", name, buf.String())
		}
	}
}

// An entry whose state is absent is being removed from the node: its sets are
// kept (nothing is pruned from under a teardown in progress) but not fetched.
func TestAbsentEntriesSetsAreKeptButNotWanted(t *testing.T) {
	var entries []map[string]any
	if err := json.Unmarshal(fixture(t), &entries); err != nil {
		t.Fatal(err)
	}
	entries[0]["state"] = "absent"
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}

	want, keep, err := desiredSetRefs(raw, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	main := modelsets.Ref{ID: "rh-s2s-7b", Revision: "0123456789abcdef0123456789abcdef01234567"}
	voices := modelsets.Ref{ID: "rh-voices-a", Revision: "v1"}
	for _, w := range want {
		if w == main || w == voices {
			t.Errorf("%s is wanted although its only entry is absent", w)
		}
	}
	for _, k := range []modelsets.Ref{main, voices} {
		if !keep[k] {
			t.Errorf("%s is not kept although an entry still names it", k)
		}
	}
}
