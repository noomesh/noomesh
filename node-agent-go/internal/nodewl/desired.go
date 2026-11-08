// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Node workload states in desired-config. Only these three are ever desired.
const (
	StateProvisioned = "provisioned"
	StateRunning     = "running"
	StateAbsent      = "absent"
)

// Reported-only row states (heartbeat `node_workloads[].state`). They never
// appear in desired-config: ParseDesired refuses them with desired_invalid.
const (
	// ReportedDraining: from the accepted drain POST until the done poll
	// answers 200 or the drain times out. The gateway proxy answers 409 to a
	// NEW session while the row says draining.
	ReportedDraining = "draining"
	// ReportedNeedsAttention: a drain timeout (reason drain_timeout); the
	// worker is left running and no live session is cut.
	ReportedNeedsAttention = "needs_attention"
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
	Addon     string              `json:"addon"`
	Name      string              `json:"name"`
	DeclRaw   json.RawMessage     `json:"decl"`
	Decl      Decl                `json:"-"`
	Image     ImageRef            `json:"image"`
	Sets      map[string][]SetRef `json:"sets"`
	Env       map[string]string   `json:"env"`
	Door      *Door               `json:"door"`
	StartSecs int64               `json:"start_secs"`
	Drain     Drain               `json:"drain"`
	// Profile names the load profile of the main slot's set (needs.profiles).
	// ParseDesired checks its shape only; CheckProfile judges it against the
	// set's manifest.
	Profile     *string `json:"profile"`
	Reservation *string `json:"reservation"`
	State       string  `json:"state"`
}

// ImageRef names the worker's image. The lock digest is the REGISTRY
// MANIFEST digest; a docker image ID is the CONFIG digest, and a classic
// `docker save` drops RepoDigests, so a node cannot check a loaded tar against
// the lock digest. ID is therefore the image ID the CLI recorded after its
// digest-verified pull (the `.imageid` sidecar, written only by the CLI at
// staging and read by the gateway when it builds the entry, never cached across
// a restage). On the node the worker is created from ID, never from a tag or
// repo name; the tar must load as EXACTLY one image whose ID equals ID (else
// image_digest_mismatch, F5); Digest is record-only there.
type ImageRef struct {
	Name     string `json:"name"`
	Digest   string `json:"digest"`
	ID       string `json:"id"`
	Artifact string `json:"artifact"`
}

// artifactRe is the rail artifact name of a staged image tar for (addon,
// image name, digest): noo-addon-wl_<addon>_<image name>_<64hex of digest>_<arch>.tar.
// Matching <arch> against the node's own is a runtime check (F5,
// arch_mismatch).
func artifactRe(addon, name, digest string) *regexp.Regexp {
	return regexp.MustCompile("^" + regexp.QuoteMeta("noo-addon-wl_"+addon+"_"+name+"_"+strings.TrimPrefix(digest, "sha256:")+"_") + `(amd64|arm64)\.tar$`)
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
	if e, ok := err.(*Error); ok && e.passthrough {
		return err // a JSON null is field_type, as in every validator
	}
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
	if err := decodeStrict(b, &frag, nullableDesired); err != nil {
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
	// raw is a part of the fragment whose tokens ParseDesired already walked.
	if err := decodeTyped(raw, &e); err != nil {
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
	if e.Profile != nil && !setProfileRe.MatchString(*e.Profile) {
		return e, fail(ReasonDesiredInvalid, "profile must be a non-empty lower-case word")
	}
	if e.Reservation != nil && !uuidRe.MatchString(*e.Reservation) {
		return e, fail(ReasonDesiredInvalid, "reservation is not a canonical lower-case UUID")
	}
	// nil routes: the agent has no routes.json, so only the shape of
	// service_drain is re-checked here; the gateway held the route to it.
	d, err := parseWorkload(e.Addon, e.DeclRaw, nil, false, nil)
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
		return e, fail(ReasonImageMissing, "image must be {name: %q, digest: sha256:<64 hex>, id, artifact}", d.Image)
	}
	if !digestRe.MatchString(e.Image.ID) {
		return e, fail(ReasonImageMissing, "image.id must be sha256:<64 lower-case hex>")
	}
	if !artifactRe(e.Addon, e.Image.Name, e.Image.Digest).MatchString(e.Image.Artifact) {
		return e, fail(ReasonImageMissing, "image.artifact must be noo-addon-wl_%s_%s_<hex of digest>_<amd64|arm64>.tar", e.Addon, e.Image.Name)
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

// CheckEnv re-checks an entry's env against its decl's bounds. ParseDesired
// already does; a caller that hands an Entry on (the provisioner) asks again
// rather than trust that the Entry came from ParseDesired. Refusal code:
// env_out_of_bounds.
func CheckEnv(e Entry) error { return checkEnvValues(e.Env, e.Decl.Env) }

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
