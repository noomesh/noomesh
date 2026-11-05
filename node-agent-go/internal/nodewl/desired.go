// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
)

// Node workload states in desired-config.
const (
	StateProvisioned = "provisioned"
	StateRunning     = "running"
	StateAbsent      = "absent"
)

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	setIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	setRevRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	intStrRe = regexp.MustCompile(`^-?[0-9]{1,18}$`)
	cnRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Entry is one `node_workloads` row of desired-config.
type Entry struct {
	Addon       string              `json:"addon"`
	Name        string              `json:"name"`
	DeclRaw     json.RawMessage     `json:"decl"`
	Decl        Decl                `json:"-"`
	Image       ImageRef            `json:"image"`
	Sets        map[string][]SetRef `json:"sets"`
	Env         map[string]string   `json:"env"`
	Door        *Door               `json:"door"`
	StartSecs   int64               `json:"start_secs"`
	Drain       Drain               `json:"drain"`
	Reservation *string             `json:"reservation"`
	State       string              `json:"state"`
}

type ImageRef struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type SetRef struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// Door is the sidecar's identity: the per-node service leaf the CLI issued
// (svc-addon-<addon>-<workload>) and the client CNs it admits, which must be
// exactly this node's agent.
type Door struct {
	Leaf  string   `json:"leaf"`
	Admit []string `json:"admit"`
}

func desiredInvalid(err error) error {
	switch CodeOf(err) {
	case CodeBadJSON, CodeUnknownField, CodeFieldType, CodeFieldMissing:
		return &Error{Code: ReasonDesiredInvalid, Detail: err.Error()}
	}
	return err
}

// ParseDesired validates the `node_workloads` fragment of desired-config for
// the node whose agent client certificate has CN ownAgentCN. A refusal's Code
// is one of the reasons in reasons.go; the agent reports it as the entry's
// `reason` and does nothing else with that entry. The first refusal wins.
func ParseDesired(b []byte, ownAgentCN string) ([]Entry, error) {
	var frag struct {
		NodeWorkloads []json.RawMessage `json:"node_workloads"`
	}
	if err := decodeStrict(b, &frag); err != nil {
		return nil, desiredInvalid(err)
	}
	if err := requireKeys(generic(b), "desired-config", "node_workloads"); err != nil {
		return nil, desiredInvalid(err)
	}
	out := make([]Entry, 0, len(frag.NodeWorkloads))
	seen := map[string]bool{}
	for _, raw := range frag.NodeWorkloads {
		e, err := parseEntry(raw, ownAgentCN)
		if err != nil {
			return nil, err
		}
		k := e.Addon + "/" + e.Name
		if seen[k] {
			return nil, fail(ReasonDesiredInvalid, "%s is listed twice", k)
		}
		seen[k] = true
		out = append(out, e)
	}
	return out, nil
}

func parseEntry(raw []byte, ownAgentCN string) (Entry, error) {
	var e Entry
	if err := decodeStrict(raw, &e); err != nil {
		return e, desiredInvalid(err)
	}
	if err := requireKeys(generic(raw), "node_workloads[]", "addon", "name", "decl", "image", "sets", "env", "start_secs", "drain", "reservation", "state"); err != nil {
		return e, desiredInvalid(err)
	}
	switch e.State {
	case StateProvisioned, StateRunning, StateAbsent:
	default:
		return e, fail(ReasonDesiredInvalid, "state %q", e.State)
	}
	if e.Reservation != nil && !uuidRe.MatchString(*e.Reservation) {
		return e, fail(ReasonDesiredInvalid, "reservation is not a canonical lower-case UUID")
	}
	d, err := parseWorkload(e.Addon, e.DeclRaw, nil, false)
	if err != nil {
		var inner *Error
		if errors.As(err, &inner) {
			return e, &Error{Code: ReasonDeclInvalid, Inner: inner.Code, Detail: inner.Detail}
		}
		return e, &Error{Code: ReasonDeclInvalid, Detail: err.Error()}
	}
	e.Decl = d
	if e.Name != d.Name {
		return e, fail(ReasonDesiredInvalid, "name %q differs from decl.name %q", e.Name, d.Name)
	}
	if e.Image.Name != d.Image || !digestRe.MatchString(e.Image.Digest) {
		return e, fail(ReasonImageMissing, "image must be {name: %q, digest: sha256:<64 hex>}", d.Image)
	}
	if e.Door == nil || e.Door.Leaf == "" {
		return e, fail(ReasonDoorLeafMissing, "door.leaf is required")
	}
	if want := "svc-addon-" + e.Addon + "-" + e.Name; e.Door.Leaf != want {
		return e, fail(ReasonDesiredInvalid, "door.leaf %q, want %q", e.Door.Leaf, want)
	}
	if len(e.Door.Admit) != 1 || e.Door.Admit[0] != ownAgentCN || !cnRe.MatchString(ownAgentCN) {
		return e, fail(ReasonAdmitInvalid, "door.admit must be exactly [%q]", ownAgentCN)
	}
	if e.StartSecs != d.Health.StartSecs || e.Drain != d.Drain {
		return e, fail(ReasonDesiredInvalid, "start_secs and drain must equal the decl's")
	}
	if e.State != StateAbsent {
		if err := checkSets(e.Sets, d.Models); err != nil {
			return e, err
		}
	}
	return e, checkEnvValues(e.Env, d.Env)
}

func checkSets(sets map[string][]SetRef, slots []Slot) error {
	known := map[string]Slot{}
	for _, s := range slots {
		known[s.Slot] = s
	}
	names := make([]string, 0, len(sets))
	for k := range sets {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s, ok := known[k]
		if !ok {
			return fail(ReasonSetSlotInvalid, "sets names slot %q, which the decl does not declare", k)
		}
		if len(sets[k]) > 1 && !s.Many {
			return fail(ReasonSetSlotInvalid, "slot %q takes one set (many is false)", k)
		}
		for _, r := range sets[k] {
			if !setIDRe.MatchString(r.ID) || !setRevRe.MatchString(r.Revision) {
				return fail(ReasonSetSlotInvalid, "slot %q: set id or revision is malformed", k)
			}
		}
	}
	for _, s := range slots {
		if !s.Optional && len(sets[s.Slot]) == 0 {
			return fail(ReasonSetMissing, "slot %q has no set", s.Slot)
		}
	}
	return nil
}

// checkEnvValues re-checks what the gateway already checked: every value
// against the decl's bound for its key. A key the decl does not declare is out
// of bounds.
func checkEnvValues(env map[string]string, bounds map[string]EnvBound) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := env[k]
		b, ok := bounds[k]
		if !ok {
			return fail(ReasonEnvOutOfBounds, "env %s is not declared", k)
		}
		if len(v) > 256 {
			return fail(ReasonEnvOutOfBounds, "env %s is over 256 bytes", k)
		}
		if b.OneOf != nil {
			found := false
			for _, m := range b.OneOf {
				found = found || m == v
			}
			if !found {
				return fail(ReasonEnvOutOfBounds, "env %s=%q is not one of the declared values", k, v)
			}
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if !intStrRe.MatchString(v) || err != nil {
			return fail(ReasonEnvOutOfBounds, "env %s=%q is not a base-10 integer", k, v)
		}
		if b.Min != nil && n < *b.Min || b.Max != nil && n > *b.Max {
			return fail(ReasonEnvOutOfBounds, "env %s=%d is outside its bounds", k, n)
		}
	}
	return nil
}
