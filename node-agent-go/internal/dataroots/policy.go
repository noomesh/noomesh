// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// The data-root policy: WHERE a node may keep its data, and WHO may own it.
//
// The root is where every model, cache and ollama blob lives, and the node's
// allowed host roots (docker/hostroots.go) are derived from it, so a root of
// /home/someone or /etc would make that tree mountable. Two rules:
//
//   - SHAPE: a dedicated directory named `noo` at a conventional place —
//     /var/lib/noo, or <data mount>/noo on Linux (WSL included, never a
//     Windows drive); ~/noomesh, ~/Library/Application Support/noo or /Volumes/…/noo on
//     macOS. Never a system path, a home directory, or a hidden path.
//   - OWNERSHIP: the directory exists, is owned by the agent's own account
//     (noo-agent on Linux, the user on macOS), and is not writable by group
//     or others.
//
// The shape rule is mirrored in the noo CLI (noo-cli/src/commands/data_root.rs)
// and both are held to config/data-root-shape-vectors.json.
//
// Mode (NOO_DATA_ROOT_POLICY): "warn" (default) reports problems on the
// heartbeat and the controller alerts once per node; "enforce" also refuses
// backend starts and every controller-supplied host path until the root
// passes. The default flips to enforce once the fleet passes.

// Problem is one rule a root fails.
type Problem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// PolicyEnv selects warn or enforce.
const PolicyEnv = "NOO_DATA_ROOT_POLICY"

// Enforcing reports whether the policy refuses, not just reports.
func Enforcing() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(PolicyEnv)), "enforce")
}

// linuxSystemPrefixes may never hold a data root. /var is handled separately:
// /var/lib/noo is the standard location, anything else under /var is not.
var linuxSystemPrefixes = []string{
	"/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run", "/usr",
	"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/tmp", "/opt", "/snap",
}

// StandardLinuxRoot is the conventional location (FHS: persistent service
// state lives under /var/lib, as with /var/lib/docker).
const StandardLinuxRoot = "/var/lib/noo"

// CheckShape applies the shape rule. goos is "linux" or "darwin"/"macos";
// home is the user's home directory (used on macOS only).
func CheckShape(p, goos, home string) []Problem {
	bad := func(code, format string, a ...any) []Problem {
		return []Problem{{Code: code, Detail: fmt.Sprintf(format, a...)}}
	}
	raw := strings.TrimSpace(p)
	if !strings.HasPrefix(raw, "/") {
		return bad("not_absolute", "%q is not an absolute path", p)
	}
	for _, c := range strings.Split(raw, "/") {
		if c == ".." || c == "." {
			return bad("relative_component", "%q contains %q", p, c)
		}
	}
	clean := path.Clean(raw)
	for _, c := range strings.Split(clean, "/") {
		if strings.HasPrefix(c, ".") {
			return bad("hidden", "%q contains the hidden component %q", p, c)
		}
	}
	// A named instance keeps its own tree inside the root:
	// <root>/instances/<name>, where <root> is itself a `noo` directory.
	base := clean
	if parts := strings.Split(clean, "/"); len(parts) >= 4 && parts[len(parts)-2] == "instances" {
		base = strings.Join(parts[:len(parts)-2], "/")
	}
	// The macOS default is ~/noomesh itself (space-free; where the Mac
	// agent's env and keys already live), the one place a root need not be
	// a directory named noo.
	if goos == "darwin" || goos == "macos" {
		if h := strings.TrimSuffix(strings.TrimSpace(home), "/"); h != "" && clean == h+"/noomesh" {
			return nil
		}
	}
	if path.Base(base) != "noo" {
		return bad("not_dedicated", "%q is not a dedicated directory named noo (e.g. %s)", p, StandardLinuxRoot)
	}
	under := func(prefix string) bool { return clean == prefix || strings.HasPrefix(clean, prefix+"/") }
	if goos == "darwin" || goos == "macos" {
		home = strings.TrimSuffix(strings.TrimSpace(home), "/")
		if home != "" && base == home+"/Library/Application Support/noo" {
			return nil
		}
		if under("/Volumes") && strings.Count(clean, "/") >= 3 {
			return nil
		}
		return bad("mac_location", "%q is neither ~/noomesh, ~/Library/Application Support/noo nor /Volumes/<disk>/…/noo", p)
	}
	for _, s := range linuxSystemPrefixes {
		if under(s) {
			return bad("system_path", "%q is under the system path %s", p, s)
		}
	}
	if under("/var") && base != StandardLinuxRoot {
		return bad("system_path", "%q is under /var; the only data root there is %s", p, StandardLinuxRoot)
	}
	if under("/home") {
		return bad("home_dir", "%q is inside a home directory", p)
	}
	if parts := strings.Split(clean, "/"); len(parts) > 2 && parts[1] == "mnt" && len(parts[2]) == 1 {
		return bad("windows_drive", "%q is on a Windows drive (WSL 9P mount, slow and shared); use %s", p, StandardLinuxRoot)
	}
	return nil
}

// OwnerEnv names one more uid that may own the root, declared in the node's
// OWN environment — the controller's self-agent shares the operator's data
// root, which the operator owns. Nothing from the controller can set it.
const OwnerEnv = "NOO_DATA_ROOT_OWNER"

// ownerAllowed: the agent's own account, root (only privileged users can
// write a root-owned 0750 tree), or the node-declared owner.
func ownerAllowed(uid, euid int) bool {
	if uid == euid || uid == 0 {
		return true
	}
	if v := strings.TrimSpace(os.Getenv(OwnerEnv)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n == uid {
			return true
		}
	}
	return false
}

// CheckOwnership applies the ownership rule to the directory on THIS host.
func CheckOwnership(p string, euid int) []Problem {
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []Problem{{Code: "missing", Detail: fmt.Sprintf("%s does not exist", p)}}
		}
		if errors.Is(err, fs.ErrPermission) {
			return []Problem{{Code: "unreadable", Detail: fmt.Sprintf(
				"could not inspect ownership of %s (permission denied for the agent's account, uid %d)", p, euid)}}
		}
		return []Problem{{Code: "unreadable", Detail: fmt.Sprintf("could not inspect ownership of %s (%v)", p, errors.Unwrap(err))}}
	}
	if !fi.IsDir() {
		return []Problem{{Code: "not_a_directory", Detail: fmt.Sprintf("%s is not a directory", p)}}
	}
	var out []Problem
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && !ownerAllowed(int(st.Uid), euid) {
		out = append(out, Problem{Code: "wrong_owner",
			Detail: fmt.Sprintf("%s is owned by uid %d, not the agent's uid %d, root, or %s", p, st.Uid, euid, OwnerEnv)})
	}
	if fi.Mode().Perm()&0o022 != 0 {
		out = append(out, Problem{Code: "writable_by_others",
			Detail: fmt.Sprintf("%s is mode %o; group/others must not write (chmod go-w)", p, fi.Mode().Perm())})
	}
	return out
}

// checkContainment: an explicit child dir must sit inside the root, or it
// widens the node's host roots past the checked directory.
func checkContainment(r Roots) []Problem {
	root := filepath.Clean(r.NooDataRoot)
	var out []Problem
	for _, c := range []struct{ name, dir string }{
		{"HF_CACHE_DIR", r.HFCacheDir}, {"MODELS_DIR", r.ModelsDir}, {"OLLAMA_DATA_DIR", r.OllamaDataDir},
	} {
		d := filepath.Clean(c.dir)
		if d != root && !strings.HasPrefix(d, root+"/") {
			out = append(out, Problem{Code: "outside_root",
				Detail: fmt.Sprintf("%s=%s is outside the data root %s", c.name, c.dir, r.NooDataRoot)})
		}
	}
	return out
}

// Check is every rule, as the heartbeat reports it.
func Check(r Roots, goos, home string, euid int) []Problem {
	var probs []Problem
	if r.NooDataRootSource == "legacy_default" {
		probs = append(probs, Problem{Code: "undeclared_root", Detail: fmt.Sprintf(
			"NOO_DATA_ROOT is unset; the agent kept the earlier default %s, which holds this node's data — declare it", r.NooDataRoot)})
	}
	probs = append(probs, CheckShape(r.NooDataRoot, goos, home)...)
	probs = append(probs, checkContainment(r)...)
	return append(probs, CheckOwnership(r.NooDataRoot, euid)...)
}

// PolicyReport is the heartbeat's data_roots.policy object.
func PolicyReport(probs []Problem) map[string]any {
	mode := "warn"
	if Enforcing() {
		mode = "enforce"
	}
	if probs == nil {
		probs = []Problem{}
	}
	return map[string]any{"mode": mode, "ok": len(probs) == 0, "problems": probs}
}

// Current checks this process's own root, as the gates see it.
func Current() []Problem {
	return Check(Resolve(os.Getenv), runtime.GOOS, os.Getenv("HOME"), os.Geteuid())
}

// Refusal is the error an enforcing node returns for anything that would
// mount under a root that fails the policy; nil when allowed.
func Refusal(probs []Problem) error {
	if !Enforcing() || len(probs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(probs))
	for _, p := range probs {
		parts = append(parts, p.Code+": "+p.Detail)
	}
	return fmt.Errorf("data root policy (%s=enforce) refuses this node's root: %s",
		PolicyEnv, strings.Join(parts, "; "))
}
