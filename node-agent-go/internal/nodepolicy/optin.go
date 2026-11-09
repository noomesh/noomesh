// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// OptInFile is the node owner's opt-in to controller approvals (i596), in the
// agent's state directory: root:root, 0644, created only by local root
// (`noo node workloads controller allow`, or `noo enroll
// --controller-approvals` during the node's one setup run).
//
// The agent only READS it. The agent is what the controller drives, and a
// bundle is signed by the same key that signs approvals, so an opt-in the
// agent (or a bundle, or provision) could write would be no opt-in at all.
// This file holds no call that changes a file;
// tests/test_node_workload_consent_has_one_writer.py fails if one appears
// here or the name is used anywhere else in the agent.
const OptInFile = "controller-approvals-optin"

// OptedIn reports whether the owner of the node whose agent state directory
// is dir opted in to controller approvals. Absent is false. Present, it must
// be a regular file (never a symlink) owned by root and writable by no one
// else; otherwise it is false and an error that says why.
func OptedIn(dir string) (bool, error) { return optedIn(dir, 0) }

func optedIn(dir string, owner uint32) (bool, error) {
	p := filepath.Join(dir, OptInFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Lstat: a symlink is itself not a regular file, so it never counts.
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file (%v)", p, fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return false, fmt.Errorf("%s is writable by its group or by everyone (%v)", p, fi.Mode().Perm())
	}
	uid, ok := fileOwner(fi)
	if !ok {
		return false, fmt.Errorf("%s: its owner cannot be read on this platform", p)
	}
	if uid != owner {
		return false, fmt.Errorf("%s is owned by uid %d, not root", p, uid)
	}
	return true, nil
}
