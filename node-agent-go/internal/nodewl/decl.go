// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// FormatNodeWorkloads is the `format` of node-workloads.json.
const FormatNodeWorkloads = "noo-addon-node-workloads/1"

// Refusal codes of ParseDecl, beside the shared ones in errors.go.
const (
	CodeWorkloadsInvalid    = "workloads_invalid"
	CodeDoorNameInvalid     = "door_name_invalid"
	CodeDoorNameTooLong     = "door_name_too_long"
	CodeNameDuplicate       = "name_duplicate"
	CodeImageNotInLock      = "image_not_in_lock"
	CodeUIDInvalid          = "uid_invalid"
	CodeCommandInvalid      = "command_invalid"
	CodePortInvalid         = "port_invalid"
	CodeProtocolsInvalid    = "protocols_invalid"
	CodeHealthInvalid       = "health_invalid"
	CodeDrainInvalid        = "drain_invalid"
	CodeAccelInvalid        = "accel_invalid"
	CodeModelSlotInvalid    = "model_slot_invalid"
	CodeEnvKeyOutsidePrefix = "env_key_outside_prefix"
	CodeEnvKeyRefusedPrefix = "env_key_refused_prefix"
	CodeEnvBoundInvalid     = "env_bound_invalid"
	CodeScratchTargetBad    = "scratch_target_refused"
	CodeScratchInvalid      = "scratch_invalid"
	CodeScratchInModelSlot  = "scratch_in_model_slot"
	CodeLimitsInvalid       = "limits_invalid"
)

// maxDoorNames: the door's DNS SAN is noo-stunnel-<addon>-<workload>, one DNS
// label of at most 63 characters; "noo-stunnel-" is 12 and the joining "-" 1,
// so len(addon)+1+len(workload) must be <= 51.
const maxDoorNames = 51

var (
	doorNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	wordRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	httpPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	targetRe   = regexp.MustCompile(`^/[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	runtimeRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	envKeyRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	enumValRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

// refusedEnvPrefixes can never start a declared env key, whatever the add-on
// is called.
var refusedEnvPrefixes = []string{"NOO_", "NVIDIA_", "CUDA_", "LD_", "PYTHON", "HF_", "TRANSFORMERS_"}

// Decl is one validated workload of node-workloads.json. In desired-config it
// travels verbatim as `decl`.
type Decl struct {
	Name      string              `json:"name"`
	Image     string              `json:"image"`
	UID       int64               `json:"uid"`
	Command   []string            `json:"command,omitempty"`
	Port      int64               `json:"port"`
	Protocols []string            `json:"protocols"`
	Health    Health              `json:"health"`
	Drain     Drain               `json:"drain"`
	Accel     Accel               `json:"accel"`
	Models    []Slot              `json:"models,omitempty"`
	Env       map[string]EnvBound `json:"env,omitempty"`
	Scratch   []Scratch           `json:"scratch,omitempty"`
	Limits    Limits              `json:"limits"`
}

type Health struct {
	Ready     string `json:"ready"`
	Live      string `json:"live"`
	StartSecs int64  `json:"start_secs"`
}

type Drain struct {
	Path        string `json:"path"`
	TimeoutSecs int64  `json:"timeout_secs"`
}

type Accel struct {
	GPU      int64 `json:"gpu"`
	Realtime bool  `json:"realtime,omitempty"`
}

// Slot is a model slot: the agent mounts the set the operator chose, read-only,
// at Target.
type Slot struct {
	Slot     string   `json:"slot"`
	Target   string   `json:"target"`
	Accepts  *Accepts `json:"accepts"`
	Many     bool     `json:"many,omitempty"`
	Optional bool     `json:"optional,omitempty"`
}

type Accepts struct {
	Kind    string `json:"kind"`
	Runtime string `json:"runtime,omitempty"`
}

// EnvBound bounds one declared env key: an integer range (Min and/or Max) or
// an enum (OneOf). Values are strings in desired-config.
type EnvBound struct {
	Min   *int64   `json:"min,omitempty"`
	Max   *int64   `json:"max,omitempty"`
	OneOf []string `json:"one_of,omitempty"`
}

// Scratch is writable space: a size-capped named volume (MaxMB) or a tmpfs
// (TmpfsMB), exactly one of the two.
type Scratch struct {
	Target  string `json:"target"`
	MaxMB   *int64 `json:"max_mb,omitempty"`
	TmpfsMB *int64 `json:"tmpfs_mb,omitempty"`
}

type Limits struct {
	RAMMB int64   `json:"ram_mb"`
	CPUs  float64 `json:"cpus"`
	PIDs  int64   `json:"pids"`
}

// EnvPrefix is the prefix every env key of addon must carry: the name
// upper-cased, - as _.
func EnvPrefix(addon string) string {
	return strings.ToUpper(strings.ReplaceAll(addon, "-", "_")) + "_"
}

// ParseDecl validates a node-workloads.json for addon. lockImages is the
// images map of the add-on's verified lock (name -> ref); a workload's image
// must be a key of it. The first refusal wins; fixtures carry one defect each.
func ParseDecl(addon string, b []byte, lockImages map[string]string) ([]Decl, error) {
	var file struct {
		Format    string            `json:"format"`
		Workloads []json.RawMessage `json:"workloads"`
	}
	if err := decodeStrict(b, &file, nullableNodeWorkloads); err != nil {
		return nil, err
	}
	g := generic(b)
	if err := requireKeys(g, "node-workloads.json", "format", "workloads"); err != nil {
		return nil, err
	}
	if file.Format != FormatNodeWorkloads {
		return nil, fail(CodeBadFormat, "format is %q, want %q", file.Format, FormatNodeWorkloads)
	}
	if len(file.Workloads) == 0 || len(file.Workloads) > 16 {
		return nil, fail(CodeWorkloadsInvalid, "%d workloads (1..16)", len(file.Workloads))
	}
	out := make([]Decl, 0, len(file.Workloads))
	seen := map[string]bool{}
	for i, raw := range file.Workloads {
		d, err := parseWorkload(addon, raw, lockImages, true)
		if err != nil {
			return nil, err
		}
		if seen[d.Name] {
			return nil, fail(CodeNameDuplicate, "workloads[%d]: name %q is declared twice", i, d.Name)
		}
		seen[d.Name] = true
		out = append(out, d)
	}
	return out, nil
}

// parseWorkload decodes and validates one workload object. checkLock false
// skips the image-name-in-lock rule: a desired-config entry carries the
// image by name and digest, and the gateway has already held the name to the
// verified lock.
func parseWorkload(addon string, raw []byte, lockImages map[string]string, checkLock bool) (Decl, error) {
	var d Decl
	// raw is a part of a document whose tokens were already walked.
	if err := decodeTyped(raw, &d); err != nil {
		return d, err
	}
	g := generic(raw)
	if err := requireKeys(g, "workload", "name", "image", "uid", "port", "protocols", "health", "drain", "accel", "limits"); err != nil {
		return d, err
	}
	for _, sub := range [][]string{{"health", "ready", "live", "start_secs"}, {"drain", "path", "timeout_secs"}, {"accel", "gpu"}, {"limits", "ram_mb", "cpus", "pids"}} {
		if err := requireKeys(field(g, sub[0]), sub[0], sub[1:]...); err != nil {
			return d, err
		}
	}
	return d, validate(addon, &d, lockImages, checkLock)
}

func validate(addon string, d *Decl, lockImages map[string]string, checkLock bool) error {
	if !doorNameRe.MatchString(addon) {
		return fail(CodeDoorNameInvalid, "add-on name %q must match %s", addon, doorNameRe)
	}
	if !doorNameRe.MatchString(d.Name) {
		return fail(CodeDoorNameInvalid, "workload name %q must match %s", d.Name, doorNameRe)
	}
	if n := len(addon) + 1 + len(d.Name); n > maxDoorNames {
		return fail(CodeDoorNameTooLong, "%s/%s: len(addon)+1+len(workload) is %d, at most %d", addon, d.Name, n, maxDoorNames)
	}
	if checkLock {
		if _, ok := lockImages[d.Image]; !ok || !wordRe.MatchString(d.Image) {
			return fail(CodeImageNotInLock, "image %q is not a name in the lock's images map", d.Image)
		}
	} else if !wordRe.MatchString(d.Image) {
		return fail(CodeImageNotInLock, "image %q is not an image name", d.Image)
	}
	if d.UID < 1 || d.UID > 4294967294 {
		return fail(CodeUIDInvalid, "uid %d (1..4294967294; 0 is refused)", d.UID)
	}
	if d.Command != nil {
		if len(d.Command) == 0 || len(d.Command) > 16 {
			return fail(CodeCommandInvalid, "command has %d elements (1..16)", len(d.Command))
		}
		for _, c := range d.Command {
			if c == "" || len(c) > 256 {
				return fail(CodeCommandInvalid, "a command element is empty or over 256 bytes")
			}
		}
	}
	if d.Port < 1024 || d.Port > 65535 {
		return fail(CodePortInvalid, "port %d (1024..65535)", d.Port)
	}
	if len(d.Protocols) < 1 || len(d.Protocols) > 2 {
		return fail(CodeProtocolsInvalid, "%d protocols", len(d.Protocols))
	}
	for _, p := range d.Protocols {
		if p != "http" && p != "ws" {
			return fail(CodeProtocolsInvalid, "protocol %q (http, ws)", p)
		}
	}
	if !okPath(d.Health.Ready) || !okPath(d.Health.Live) || d.Health.StartSecs < 1 || d.Health.StartSecs > 600 {
		return fail(CodeHealthInvalid, "health needs absolute paths and start_secs 1..600")
	}
	if !okPath(d.Drain.Path) || d.Drain.TimeoutSecs < 1 || d.Drain.TimeoutSecs > 3600 {
		return fail(CodeDrainInvalid, "drain needs an absolute path and timeout_secs 1..3600")
	}
	if d.Accel.GPU < 0 || d.Accel.GPU > 8 {
		return fail(CodeAccelInvalid, "accel.gpu %d (0..8)", d.Accel.GPU)
	}
	if err := validateModels(d.Models); err != nil {
		return err
	}
	if err := validateEnv(addon, d.Env); err != nil {
		return err
	}
	if err := validateScratch(d.Scratch, d.Models); err != nil {
		return err
	}
	l := d.Limits
	if l.RAMMB < 64 || l.RAMMB > 1048576 || l.CPUs < 0.1 || l.CPUs > 128 || l.PIDs < 1 || l.PIDs > 32768 {
		return fail(CodeLimitsInvalid, "limits out of range: ram_mb 64..1048576, cpus 0.1..128, pids 1..32768")
	}
	return nil
}

func okPath(p string) bool { return len(p) <= 128 && httpPathRe.MatchString(p) }

func refusedTarget(t string) bool {
	if t == "/" {
		return true
	}
	for _, r := range []string{"/proc", "/sys", "/dev"} {
		if t == r || strings.HasPrefix(t, r+"/") {
			return true
		}
	}
	return false
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func validateModels(ms []Slot) error {
	if len(ms) > 8 {
		return fail(CodeModelSlotInvalid, "%d model slots (at most 8)", len(ms))
	}
	for i, m := range ms {
		if !wordRe.MatchString(m.Slot) {
			return fail(CodeModelSlotInvalid, "models[%d]: slot name %q", i, m.Slot)
		}
		if m.Accepts == nil {
			return fail(CodeModelSlotInvalid, "models[%d] (%s): `accepts` is required", i, m.Slot)
		}
		if m.Accepts.Kind != "voice" && m.Accepts.Kind != "voice-pack" {
			return fail(CodeModelSlotInvalid, "models[%d] (%s): accepts.kind %q", i, m.Slot, m.Accepts.Kind)
		}
		if m.Accepts.Runtime != "" && !runtimeRe.MatchString(m.Accepts.Runtime) {
			return fail(CodeModelSlotInvalid, "models[%d] (%s): accepts.runtime %q", i, m.Slot, m.Accepts.Runtime)
		}
		if refusedTarget(m.Target) || !targetRe.MatchString(m.Target) || len(m.Target) > 128 {
			return fail(CodeModelSlotInvalid, "models[%d] (%s): target %q", i, m.Slot, m.Target)
		}
		for _, o := range ms[:i] {
			if o.Slot == m.Slot || overlaps(o.Target, m.Target) {
				return fail(CodeModelSlotInvalid, "models[%d] (%s): slot or target repeats or nests with %s", i, m.Slot, o.Slot)
			}
		}
	}
	return nil
}

func validateEnv(addon string, env map[string]EnvBound) error {
	if len(env) > 32 {
		return fail(CodeEnvBoundInvalid, "%d env keys (at most 32)", len(env))
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	prefix := EnvPrefix(addon)
	for _, k := range keys {
		for _, p := range refusedEnvPrefixes {
			if strings.HasPrefix(k, p) {
				return fail(CodeEnvKeyRefusedPrefix, "env key %q starts with refused prefix %s", k, p)
			}
		}
		if !envKeyRe.MatchString(k) || !strings.HasPrefix(k, prefix) {
			return fail(CodeEnvKeyOutsidePrefix, "env key %q must start with %s", k, prefix)
		}
		b := env[k]
		if b.OneOf != nil {
			if b.Min != nil || b.Max != nil || len(b.OneOf) == 0 || len(b.OneOf) > 32 {
				return fail(CodeEnvBoundInvalid, "env %s: one_of takes 1..32 values and no min or max", k)
			}
			for _, v := range b.OneOf {
				if !enumValRe.MatchString(v) {
					return fail(CodeEnvBoundInvalid, "env %s: enum value %q", k, v)
				}
			}
			continue
		}
		if b.Min == nil && b.Max == nil {
			return fail(CodeEnvBoundInvalid, "env %s: needs min and/or max, or one_of", k)
		}
		if b.Min != nil && b.Max != nil && *b.Min > *b.Max {
			return fail(CodeEnvBoundInvalid, "env %s: min %d is above max %d", k, *b.Min, *b.Max)
		}
	}
	return nil
}

func validateScratch(ss []Scratch, ms []Slot) error {
	if len(ss) > 4 {
		return fail(CodeScratchInvalid, "%d scratch entries (at most 4)", len(ss))
	}
	for i, s := range ss {
		if refusedTarget(s.Target) {
			return fail(CodeScratchTargetBad, "scratch[%d]: target %q is not writable space", i, s.Target)
		}
		if !targetRe.MatchString(s.Target) || len(s.Target) > 128 {
			return fail(CodeScratchInvalid, "scratch[%d]: target %q", i, s.Target)
		}
		if (s.MaxMB == nil) == (s.TmpfsMB == nil) {
			return fail(CodeScratchInvalid, "scratch[%d]: exactly one of max_mb and tmpfs_mb", i)
		}
		if s.MaxMB != nil && (*s.MaxMB < 1 || *s.MaxMB > 65536) || s.TmpfsMB != nil && (*s.TmpfsMB < 1 || *s.TmpfsMB > 16384) {
			return fail(CodeScratchInvalid, "scratch[%d]: size out of range", i)
		}
		for _, o := range ss[:i] {
			if o.Target == s.Target {
				return fail(CodeScratchInvalid, "scratch[%d]: target %q repeats", i, s.Target)
			}
		}
		for _, m := range ms {
			if overlaps(m.Target, s.Target) {
				return fail(CodeScratchInModelSlot, "scratch[%d]: target %q overlaps model slot %s (%s)", i, s.Target, m.Slot, m.Target)
			}
		}
	}
	return nil
}
