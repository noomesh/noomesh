// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
)

// approveOnNode writes the approvals store as the node owner's
// `sudo noo node workloads approve` does. The agent has no writer (i573).
func approveOnNode(t *testing.T, dir, addon, digest string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"version":   1,
		"approvals": []nodepolicy.Approval{{Addon: addon, Digest: digest}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodepolicy.ApprovalsFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
