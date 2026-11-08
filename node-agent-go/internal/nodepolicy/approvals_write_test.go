// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Add records an approval for this package's tests: atomic (temp file in the
// same directory, then rename) and 0600; adding what is there is a no-op.
// It is TEST code on purpose (i573): the agent only reads the store, and its
// one writer is the node owner's `sudo noo node workloads approve`.
func (a *Approvals) Add(addon, digest string) error {
	x := Approval{Addon: addon, Digest: digest}
	if err := checkApproval(x); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	list, err := a.read()
	if err != nil {
		return err
	}
	for _, y := range list {
		if y == x {
			return nil
		}
	}
	list = append(list, x)
	sortApprovals(list)
	b, err := json.Marshal(approvalsDoc{Version: 1, Approvals: list})
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ApprovalsFile+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, a.path)
}
