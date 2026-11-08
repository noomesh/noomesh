// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package nodepolicy is the node's own say over add-on node workloads
// (i300 F5b): the consent policy and its approvals, the placement facts the
// node reports, and the gate that refuses an entry before anything is
// provisioned. The controller places; this node decides whether it agrees,
// and it re-checks every placement-side refusal itself (defence in depth).
package nodepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Mode is the node's consent setting for add-on node workloads
// (`addon_workloads_policy` in the heartbeat).
type Mode string

const (
	// ModeNone refuses every entry, approved or not: the owner's kill
	// switch (NOO_ADDON_WORKLOADS=none).
	ModeNone Mode = "none"
	// ModeApprove runs an entry only when its (add-on, image digest) is
	// approved on this node. It is the default (i573): a node whose owner
	// has approved nothing runs nothing an add-on declared.
	ModeApprove Mode = "approve"
	// ModeAuto runs every entry the controller places and the other checks
	// admit.
	ModeAuto Mode = "auto"
)

// ParseMode reads the setting; unset is ModeApprove. ok is false for a value
// that is not one of the three; the caller treats that as ModeNone (fail
// closed) and says so.
func ParseMode(s string) (Mode, bool) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case ModeNone, ModeApprove, ModeAuto:
		return m, true
	case "":
		return ModeApprove, true
	}
	return ModeNone, false
}

// Approval is one thing the node's owner agreed to run: an add-on at one
// image digest (the registry manifest digest of the lock). A new image
// digest of the same add-on is a new thing to approve.
type Approval struct {
	Addon  string `json:"addon"`
	Digest string `json:"digest"`
}

// ApprovalsFile is the file under the agent's state directory.
const ApprovalsFile = "addon-workload-approvals.json"

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	addonRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Approvals is the persisted list of approvals. A missing file is an empty
// list; a file that cannot be read or parsed is an ERROR, never an empty
// list (an error must not become a fact: a corrupt file would otherwise read
// as "nothing approved" in the heartbeat, or worse).
type Approvals struct {
	path string
	mu   sync.Mutex
}

// NewApprovals keeps approvals in dir (the agent's StateDir).
func NewApprovals(dir string) *Approvals {
	return &Approvals{path: filepath.Join(dir, ApprovalsFile)}
}

type approvalsDoc struct {
	Version   int        `json:"version"`
	Approvals []Approval `json:"approvals"`
}

func (a *Approvals) read() ([]Approval, error) {
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Approval{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc approvalsDoc
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", a.path, err)
	}
	for _, x := range doc.Approvals {
		if err := checkApproval(x); err != nil {
			return nil, fmt.Errorf("corrupt %s: %w", a.path, err)
		}
	}
	if doc.Approvals == nil {
		doc.Approvals = []Approval{}
	}
	return doc.Approvals, nil
}

func checkApproval(x Approval) error {
	if !addonRe.MatchString(x.Addon) {
		return fmt.Errorf("add-on %q is not a valid name", x.Addon)
	}
	if !digestRe.MatchString(x.Digest) {
		return fmt.Errorf("digest %q is not sha256:<64 lower-case hex>", x.Digest)
	}
	return nil
}

// List is every approval, sorted. The error means the file is unreadable.
func (a *Approvals) List() ([]Approval, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out, err := a.read()
	if err != nil {
		return nil, err
	}
	sortApprovals(out)
	return out, nil
}

// Has reports whether (addon, digest) is approved. An unreadable file is an
// error: the caller refuses (it cannot confirm consent).
func (a *Approvals) Has(addon, digest string) (bool, error) {
	list, err := a.List()
	if err != nil {
		return false, err
	}
	for _, x := range list {
		if x.Addon == addon && x.Digest == digest {
			return true, nil
		}
	}
	return false, nil
}

// The agent only READS the approvals (i573). The one writer is the node
// owner's `sudo noo node workloads approve|revoke` (noo-cli
// src/commands/node_workloads.rs). The agent is what the controller drives,
// so a writer here would let the controller grant consent to itself, and
// the default policy (approve, with nothing approved) would no longer be
// closed. tests/test_node_workload_consent_has_one_writer.py fails if a
// write appears here or the store is named anywhere else. The tests' own
// writer is approvals_write_test.go.

func sortApprovals(l []Approval) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].Addon != l[j].Addon {
			return l[i].Addon < l[j].Addon
		}
		return l[i].Digest < l[j].Digest
	})
}
