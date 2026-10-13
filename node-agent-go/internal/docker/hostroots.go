// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
)

// The node declares which parts of its own filesystem the controller may
// name. Desired state PROPOSES a path; this file DISPOSES.
//
// Every host path that reaches Docker from a controller-supplied value —
// `node_config.models_dir` today — must resolve under one of these roots.
// The roots come from THIS process's environment (/etc/noo-node-agent.env),
// which only the node's operator writes; nothing in the controller's
// database can widen them. That is the same trust split the skills bind
// roots use (skills.go: skillBindRoots) and the same one hostDirAllowed was
// written for: "a compromised gateway/DB row must not translate into
// `chown /etc` on every node".
//
// Before this, `models_dir` was taken verbatim: `models_dir:"/"` plus a
// controller-chosen image gave a root container a read of the whole host
// filesystem — /etc/noo-node-agent.env, the fleet secret and the NATS
// password included — on every node in the mesh.

// hostRootEnvs are the env vars whose values are node-declared data roots.
// These are the same variables the backend specs already resolve their
// mount sources from, so declaring them is not new configuration: a node
// that can run a backend at all already sets at least one.
var hostRootEnvs = []string{
	"MODELS_DIR",          // the model store (llamacpp/reranker /models source)
	"NOO_DATA_ROOT",       // the node's data tree (models, caches, ollama)
	"HF_CACHE_DIR",        // the HuggingFace cache (vllm, TEI)
	"OLLAMA_DATA_DIR",     // ollama's blob store
	"NOO_SKILLS_HOST_DIR", // the skills tree (shared with skillBindRoots)
}

// HostRootsEnv is the operator's explicit widening: a PATH-style list of
// absolute directories, read from the agent's own environment. Adding one
// takes a node-local config change and a restart — never a request field
// and never a DB row.
const HostRootsEnv = "NOO_HOST_ROOTS"

// HostRoots returns the canonicalized directories a controller-supplied
// host path may live under. Empty means the node declared nothing, and
// every controller-supplied path is then refused — the safe end state for
// a node whose environment says nothing about where its data lives.
func HostRoots() []string {
	var raw []string
	for _, k := range hostRootEnvs {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			raw = append(raw, v)
		}
	}
	for _, v := range filepath.SplitList(os.Getenv(HostRootsEnv)) {
		if v = strings.TrimSpace(v); v != "" {
			raw = append(raw, v)
		}
	}
	roots := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, r := range raw {
		clean, err := canonicalHostPathAllowMissing(r)
		if err != nil {
			slog.Warn("host roots: ignoring unusable root", "root", r, "error", err)
			continue
		}
		if err := hostDirAllowed(clean); err != nil {
			slog.Warn("host roots: ignoring root that names a system path", "root", r, "error", err)
			continue
		}
		if seen[clean] {
			continue
		}
		seen[clean] = true
		roots = append(roots, clean)
	}
	return roots
}

// canonicalHostPathAllowMissing is canonicalHostPath for a directory that
// may not exist yet — which is the whole point of EnsureHostDir: the node
// creates the models dir on first reconcile.
//
// Resolving symlinks still matters (a symlink planted inside a declared
// root is exactly how a prefix test is defeated), so it resolves the
// DEEPEST EXISTING ancestor and re-appends the missing tail. A tail
// component may not be "." or ".." — filepath.Clean has already removed
// those, and a path that still contains one after Clean is malformed.
func canonicalHostPathAllowMissing(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	clean := filepath.Clean(p)
	if clean == "/" {
		return "", fmt.Errorf("path %q is the filesystem root", p)
	}
	// Walk up to the first component that exists on this host.
	var tail []string
	probe := clean
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			// Nothing on the way down exists — not even "/". Impossible in
			// practice; refuse rather than invent a resolution.
			return "", fmt.Errorf("path %q has no existing ancestor", p)
		}
		tail = append([]string{filepath.Base(probe)}, tail...)
		probe = parent
	}
	resolved, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", fmt.Errorf("path %q does not resolve on this host: %w", p, err)
	}
	out := filepath.Clean(filepath.Join(append([]string{resolved}, tail...)...))
	if out == "/" {
		return "", fmt.Errorf("path %q resolves to the filesystem root", p)
	}
	return out, nil
}

// ValidateHostPathUnderRoots is the admission decision for a
// controller-supplied host path. It returns the canonical path on success
// and an operator-readable refusal otherwise — never a silent drop, and
// never a "warn and continue": a mount the node would not have chosen is a
// placement that must not start.
func ValidateHostPathUnderRoots(p string) (string, error) {
	if err := dataroots.Refusal(dataroots.Current()); err != nil {
		return "", fmt.Errorf("refusing host path %q: %w", p, err)
	}
	clean, err := canonicalHostPathAllowMissing(p)
	if err != nil {
		return "", fmt.Errorf("refusing host path %q: %w", p, err)
	}
	if err := hostDirAllowed(clean); err != nil {
		return "", fmt.Errorf("refusing host path %q: %w", p, err)
	}
	roots := HostRoots()
	if len(roots) == 0 {
		return "", fmt.Errorf(
			"refusing host path %q: this node declares no data roots, so it accepts no "+
				"controller-chosen host path — set MODELS_DIR or NOO_DATA_ROOT (or %s) in "+
				"%s and restart the agent", p, HostRootsEnv, agentEnvFileHint(runtime.GOOS))
	}
	for _, root := range roots {
		if pathWithin(root, clean) {
			return clean, nil
		}
	}
	return "", fmt.Errorf(
		"refusing host path %q (resolves to %s): outside this node's declared data roots %s — "+
			"the controller may choose a path UNDER a declared root, never a new one",
		p, clean, strings.Join(roots, ", "))
}

// hostPathLeafOK bounds the last component of a host path to characters
// that are safe both as a filename and as a shell word. EnsureHostDir
// passes the leaf to a helper container as a positional argument (so the
// shell never re-splits it), and this is the belt to that braces.
func hostPathLeafOK(leaf string) error {
	if leaf == "" {
		return fmt.Errorf("empty path component")
	}
	if leaf == "." || leaf == ".." {
		return fmt.Errorf("path component %q is a relative reference", leaf)
	}
	if len(leaf) > 255 {
		return fmt.Errorf("path component is too long (%d bytes)", len(leaf))
	}
	for _, r := range leaf {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("path component %q contains an invalid character %q "+
				"(allowed: letters, digits, '.', '_', '-')", leaf, r)
		}
	}
	return nil
}

// agentEnvFileHint names the env file an operator edits, per OS: systemd's
// EnvironmentFile on Linux, the file run-agent.sh sources on macOS.
func agentEnvFileHint(goos string) string {
	if goos == "darwin" {
		return "~/noomesh/agent.env (quote values that contain spaces)"
	}
	return "/etc/noo-node-agent.env"
}
