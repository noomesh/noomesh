// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package dataroots reports the data roots this node actually USES
//
// A provision bundle renders the node's DECLARED data root. The controller
// could not tell when that differed from the root the node's containers
// mount, so
// a bundle silently moved the node off its own data. The agent therefore
// says, on every heartbeat and at registration, what it resolves now:
//
//	"data_roots": {
//	  "noo_data_root": "/data/noo", "noo_data_root_source": "env",
//	  "hf_cache_dir": "/data/noo/hf-cache",
//	  "models_dir": "/data/noo/models",
//	  "ollama_data_dir": "/data/noo/ollama",
//	  "running_mounts": {"vllm": ["/data/noo/hf-cache"]}
//	}
//
// These are the EFFECTIVE values, resolved exactly as the backend specs
// resolve them (backends.go: ${HF_CACHE_DIR:-${NOO_DATA_ROOT:-<DefaultDataRoot>}/hf-cache}),
// not raw env lines. When NOO_DATA_ROOT is unset the hardcoded fallback is
// reported AS a fallback: noo_data_root_source is "default", not "env".
//
// running_mounts_resolved is additive: {source_path: resolved_path} for each
// running mount source whose symlink-resolved path differs from the literal
// one (host3: /opt/noo/hf-cache -> /data/noo/hf-cache, the same data under
// another name). noo_data_root_resolved says the same of the agent's own
// root. A path that cannot be resolved is omitted, never an error.
// running_mounts itself stays literal so older CLIs keep working.
//
// running_mounts is the host side of each MANAGED backend container's data
// bind mounts. It is a map, present and empty when no managed container
// runs; when docker cannot be asked it is OMITTED and running_mounts_error
// says why, so "no mounts" and "could not look" are never the same shape.
package dataroots

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultDataRoot is the fallback every backend spec uses when NOO_DATA_ROOT
// is unset. It is a neutral Linux path, not any one machine's,
// and the Rust CLI and Python copies are held to it by
// tests/test_data_root_default_parity.py. A fallback whose directory does not
// exist is refused at start (docker.requireMountSources), never created.
const DefaultDataRoot = StandardLinuxRoot

// DefaultFor is the fallback for an OS: the Linux standard, or the macOS
// per-user ~/noomesh (the Mac agent runs as the user, and ~/noomesh is where
// its env, keys and binary already live). The path has NO whitespace on
// purpose: the Mac agent's env file is sourced by a shell, and the earlier
// default under "Application Support" was split on its space, dropping the
// node's data roots (a Mac node, 2026-10-06).
func DefaultFor(goos, home string) string {
	if (goos == "darwin" || goos == "macos") && strings.TrimSpace(home) != "" {
		return strings.TrimSuffix(home, "/") + "/noomesh"
	}
	return DefaultDataRoot
}

// DarwinLegacySuffix is the macOS default of the first build that had one
// (#754): under ~/Library/Application Support. It has a space, so it is no
// longer a default — but a Mac that already used it keeps its data there.
const DarwinLegacySuffix = "/Library/Application Support/noo"

// legacyDefaultsFor is LegacyDefaults plus, on macOS, the per-user legacy root.
func legacyDefaultsFor(goos, home string) []string {
	out := append([]string{}, LegacyDefaults...)
	if (goos == "darwin" || goos == "macos") && strings.TrimSpace(home) != "" {
		out = append([]string{strings.TrimSuffix(home, "/") + DarwinLegacySuffix}, out...)
	}
	return out
}

// LegacyDefaults are the roots earlier agents fell back to when NOO_DATA_ROOT
// was unset: /mnt/d/noo until #754, /data/noo after it. A node that ran on
// one of them has its models and data THERE; switching it to today's
// default on upgrade would mount an empty tree (or refuse) — the silent
// move the NOO_DATA_ROOT trap warns about.
var LegacyDefaults = []string{"/mnt/d/noo", "/data/noo"}

// adoptedLegacy is the legacy root AdoptLegacyRoot pinned, for reporting.
var adoptedLegacy string

// adoptedLate: the legacy root was adopted while absent, because the
// filesystem record names it (its mount was late at start).
var adoptedLate bool

// AdoptedLate reports whether AdoptLegacyRoot kept a legacy root that was not
// there at start (its mount was late) because the filesystem record names it.
func AdoptedLate() bool { return adoptedLate }

// legacyRecorded is recorded(); a seam for tests.
var legacyRecorded = recorded

// AdoptLegacyRoot keeps an undeclared node on the root it already uses: with
// NOO_DATA_ROOT unset and a legacy default directory present, it SETS
// NOO_DATA_ROOT to that directory for this process, so every resolver (the
// backend specs' ${NOO_DATA_ROOT:-…} templates included) agrees on it. The
// heartbeat then reports source "legacy_default" and the policy asks for it
// to be declared. Returns the adopted root, or "" when nothing was adopted.
// Called once at startup, before anything resolves a path.
//
// A legacy root on a mount that is LATE at start is not a directory yet.
// It used to fall through to today's default for the whole process: the
// node ran on /var/lib/noo, an empty tree, until a restart. Now a legacy
// root the filesystem record names (data-root-fs.json: it was seen on its
// own disk at an earlier start) is kept even while absent; the policy then
// refuses it (not_on_recorded_fs) until the mount appears, and clears by
// itself when it does. A legacy root never recorded (its first start under
// this check) cannot be told from one that is gone, and keeps the old
// behaviour; main logs which case it was.
func AdoptLegacyRoot(getenv func(string) string, setenv func(string, string) error, isDir func(string) bool) string {
	return adoptLegacyRoot(runtime.GOOS, getenv, setenv, isDir)
}

func adoptLegacyRoot(goos string, getenv func(string) string, setenv func(string, string) error, isDir func(string) bool) string {
	if strings.TrimSpace(getenv("NOO_DATA_ROOT")) != "" {
		return ""
	}
	legacy := legacyDefaultsFor(goos, getenv("HOME"))
	for _, d := range legacy {
		if isDir(d) {
			if err := setenv("NOO_DATA_ROOT", d); err != nil {
				return ""
			}
			adoptedLegacy, adoptedLate = d, false
			return d
		}
	}
	if goos != "linux" {
		return ""
	}
	for _, d := range legacy {
		if legacyRecorded(d) {
			if err := setenv("NOO_DATA_ROOT", d); err != nil {
				return ""
			}
			adoptedLegacy, adoptedLate = d, true
			return d
		}
	}
	return ""
}

// Roots is what this process resolves.
type Roots struct {
	NooDataRoot       string
	NooDataRootSource string // "env" | "default"
	HFCacheDir        string
	ModelsDir         string
	OllamaDataDir     string
}

// Resolve applies the specs' precedence over getenv: an explicit
// HF_CACHE_DIR / MODELS_DIR / OLLAMA_DATA_DIR wins, otherwise a child of the
// resolved NOO_DATA_ROOT.
func Resolve(getenv func(string) string) Roots {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	r := Roots{NooDataRoot: get("NOO_DATA_ROOT"), NooDataRootSource: "env"}
	if adoptedLegacy != "" && r.NooDataRoot == adoptedLegacy {
		r.NooDataRootSource = "legacy_default"
	}
	if r.NooDataRoot == "" {
		r.NooDataRoot, r.NooDataRootSource = DefaultFor(runtime.GOOS, getenv("HOME")), "default"
	}
	child := func(env, name string) string {
		if v := get(env); v != "" {
			return v
		}
		return filepath.Join(r.NooDataRoot, name)
	}
	r.HFCacheDir = child("HF_CACHE_DIR", "hf-cache")
	r.ModelsDir = child("MODELS_DIR", "models")
	r.OllamaDataDir = child("OLLAMA_DATA_DIR", "ollama")
	return r
}

// ResolveFunc resolves a host path through symlinks (filepath.EvalSymlinks).
type ResolveFunc func(string) (string, error)

// resolvedIfDifferent is the resolved form of p, or "" when it cannot be
// resolved or resolves to itself.
func resolvedIfDifferent(p string, eval ResolveFunc) string {
	got, err := eval(p)
	if err != nil || got == "" || filepath.Clean(got) == filepath.Clean(p) {
		return ""
	}
	return got
}

// ResolveMounts maps each mount source whose resolved path differs to that
// path. Sources that fail to resolve (missing, permission) are omitted.
func ResolveMounts(m map[string][]string, eval ResolveFunc) map[string]string {
	out := map[string]string{}
	for _, paths := range m {
		for _, p := range paths {
			if _, done := out[p]; done {
				continue
			}
			if r := resolvedIfDifferent(p, eval); r != "" {
				out[p] = r
			}
		}
	}
	return out
}

// Report is the heartbeat's `data_roots`. mounts returns backend -> host
// paths; an error omits running_mounts and is named in
// running_mounts_error. A nil mounts func (agent without a docker client)
// is the same as an error.
//
// The disk part is bounded (Bounded, ProbeTimeout): a root on a hung mount
// (a hard NFS mount, a dead USB disk) blocks a stat in the kernel, and the
// heartbeat that waited on it went silent. On timeout the beat still goes
// out with the paths it resolves (no disk), the running mounts, and a
// `not_answering` policy problem, which `noo cluster verify` shows as FAIL.
// Docker is asked first, outside the bound: a slow docker is not a slow disk.
func Report(r Roots, mounts func() (map[string][]string, error)) map[string]any {
	if mounts != nil {
		m, err := mounts()
		mounts = func() (map[string][]string, error) { return m, err }
	}
	out, err := Bounded(r.NooDataRoot, func() map[string]any { return reportDisk(r, mounts) })
	if err != nil {
		return notAnsweringReport(r, mounts, err)
	}
	return out
}

// notAnsweringReport is the beat's data_roots when the disk did not answer.
func notAnsweringReport(r Roots, mounts func() (map[string][]string, error), why error) map[string]any {
	out := map[string]any{
		"noo_data_root":        r.NooDataRoot,
		"noo_data_root_source": r.NooDataRootSource,
		"hf_cache_dir":         r.HFCacheDir,
		"models_dir":           r.ModelsDir,
		"ollama_data_dir":      r.OllamaDataDir,
		"probe_error":          why.Error(),
	}
	if mounts == nil {
		out["running_mounts_error"] = "no docker client"
	} else if m, err := mounts(); err != nil {
		out["running_mounts_error"] = err.Error()
	} else {
		if m == nil {
			m = map[string][]string{}
		}
		out["running_mounts"] = m
	}
	out["policy"] = PolicyReport([]Problem{{Code: "not_answering", Detail: why.Error()}})
	return out
}

func reportDisk(r Roots, mounts func() (map[string][]string, error)) map[string]any {
	out := report(r, mounts, filepath.EvalSymlinks)
	out["policy"] = policyReport(r, Check(r, runtime.GOOS, os.Getenv("HOME"), os.Geteuid()))
	out["stores"] = StoresReport(r)
	return out
}

func report(r Roots, mounts func() (map[string][]string, error), eval ResolveFunc) map[string]any {
	out := map[string]any{
		"noo_data_root":        r.NooDataRoot,
		"noo_data_root_source": r.NooDataRootSource,
		"hf_cache_dir":         r.HFCacheDir,
		"models_dir":           r.ModelsDir,
		"ollama_data_dir":      r.OllamaDataDir,
	}
	if rr := resolvedIfDifferent(r.NooDataRoot, eval); rr != "" {
		out["noo_data_root_resolved"] = rr
	}
	if mounts == nil {
		out["running_mounts_error"] = "no docker client"
		return out
	}
	m, err := mounts()
	if err != nil {
		out["running_mounts_error"] = err.Error()
		return out
	}
	if m == nil {
		m = map[string][]string{}
	}
	out["running_mounts"] = m
	if res := ResolveMounts(m, eval); len(res) > 0 {
		out["running_mounts_resolved"] = res
	}
	return out
}
