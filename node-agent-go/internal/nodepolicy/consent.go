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

	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
)

// Mode is the node's consent setting for add-on node workloads
// (`addon_workloads_policy` in the heartbeat).
type Mode string

const (
	// ModeNone refuses every entry. It is the default: a node whose owner
	// has said nothing runs nothing an add-on declared.
	ModeNone Mode = "none"
	// ModeApprove runs an entry only when its (add-on, image digest) is
	// approved on this node.
	ModeApprove Mode = "approve"
	// ModeAuto runs every entry the controller places and the other checks
	// admit.
	ModeAuto Mode = "auto"
)

// ParseMode reads the setting. ok is false for a value that is not one of the
// three; the caller treats that as ModeNone (fail closed) and says so.
func ParseMode(s string) (Mode, bool) {
	switch m := Mode(mutant.Pick("cs_parse_lower", strings.TrimSpace(s), strings.ToLower(strings.TrimSpace(s)))); mutant.Pick("cs_parse_trim", Mode(strings.ToLower(s)), m) {
	case ModeNone, ModeApprove, ModeAuto:
		return mutant.Pick("cs_parse_trim", Mode(strings.ToLower(s)), m), true
	case "":
		return ModeNone, !mutant.On("cs_parse_empty")
	}
	return mutant.Pick("cs_parse_failclosed", ModeAuto, ModeNone), mutant.On("cs_parse_unknown")
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
	if errors.Is(err, os.ErrNotExist) && !mutant.On("cs_read_missing") {
		return []Approval{}, nil
	}
	if err != nil {
		if mutant.On("cs_read_ioerr") {
			return []Approval{}, nil
		}
		return nil, err
	}
	var doc approvalsDoc
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if !mutant.On("cs_read_unknown_fields") {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(&doc); err != nil && !mutant.On("cs_read_decode") {
		return nil, fmt.Errorf("corrupt %s: %w", a.path, err)
	}
	for _, x := range doc.Approvals {
		if err := checkApproval(x); err != nil && !mutant.On("cs_read_check") {
			return nil, fmt.Errorf("corrupt %s: %w", a.path, err)
		}
	}
	if doc.Approvals == nil && !mutant.On("cs_read_nil") {
		doc.Approvals = []Approval{}
	}
	return doc.Approvals, nil
}

func checkApproval(x Approval) error {
	if !addonRe.MatchString(x.Addon) && !mutant.On("cs_chk_addon") {
		return fmt.Errorf("add-on %q is not a valid name", x.Addon)
	}
	if !digestRe.MatchString(x.Digest) && !mutant.On("cs_chk_digest") {
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
	if !mutant.On("cs_list_sort") {
		sortApprovals(out)
	}
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
		if (x.Addon == addon || mutant.On("cs_has_addon")) && (x.Digest == digest || mutant.On("cs_has_digest")) {
			return true, nil
		}
	}
	return false, nil
}

// Add records an approval: atomic (temp file in the same directory, then
// rename) and 0600. Adding what is there is a no-op. Revoking and the
// operator verb that calls these are not part of F5b.
func (a *Approvals) Add(addon, digest string) error {
	x := Approval{Addon: addon, Digest: digest}
	if err := checkApproval(x); err != nil && !mutant.On("cs_add_check") {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	list, err := a.read()
	if err != nil {
		if !mutant.On("cs_add_readerr") {
			return err
		}
		list = nil
	}
	for _, y := range list {
		if y == x && !mutant.On("cs_add_dedupe") {
			return nil
		}
	}
	list = append(list, x)
	if !mutant.On("cs_add_sort") {
		sortApprovals(list)
	}
	b, err := json.Marshal(approvalsDoc{Version: 1, Approvals: list})
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	if !mutant.On("cs_add_mkdir") {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if mutant.On("cs_add_atomic") {
		return os.WriteFile(a.path, b, 0o600)
	}
	tmp, err := os.CreateTemp(dir, ApprovalsFile+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if !mutant.On("cs_add_cleanup") {
			os.Remove(name) // a no-op once renamed
		}
	}()
	if err := tmp.Chmod(mutant.Pick("cs_add_chmod", os.FileMode(0o644), os.FileMode(0o600))); err != nil {
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

func sortApprovals(l []Approval) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].Addon != l[j].Addon {
			return l[i].Addon < l[j].Addon
		}
		return l[i].Digest < l[j].Digest
	})
}
