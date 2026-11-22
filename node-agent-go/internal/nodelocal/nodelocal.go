// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package nodelocal reads the node's OWN declarations: a small KEY=VALUE file
// the node's operator writes and nothing else ever touches.
//
// Why a second file: the controller renders /etc/noo-node-agent.env and the
// applier replaces it whole on every apply, so a key an operator added there
// by hand (a capability the node allows, an image allow-list, the Mac's
// Ollama registry pulls) was wiped by the next roll. The node's declarations
// bound what the controller may make it do, so they must stay something done
// ON the node: this file is wholly the node's, the rendered env wholly the
// controller's, and nothing is carried between them.
//
//	/etc/noo-node-agent.local.env   (Linux and macOS alike)
//
// It is ROOT's file: owned by root, mode 644 (the agent, which runs as its own
// unprivileged user, reads it; only root writes it), a regular file (never a
// symlink), in a directory that is itself root-owned and not group- or
// world-writable (checked on the resolved path: macOS's /etc is a symlink to
// /private/etc). So the agent can never write its own grant: a declaration
// the agent could write for itself would not bound it. It holds no secrets
// (NOO_MCP_SECRETS_FILE is a path; the secrets stay in their own file).
//
// The agent reads it itself (never sourced by a shell: a declaration is data,
// not code) and takes ONLY the keys named in Keys. Any other key is ignored and
// named, so the file can never set a controller-owned value (the cluster
// secret, the bind address, the PKI). Each value is held to its key's own
// narrow shape:
//
//   - a TRUST declaration (it widens or narrows what the node allows) that
//     fails its rule is NOT applied and is removed from the environment: a
//     refused widening never falls back to allow. A refused narrowing
//     (NOO_IMAGE_REGISTRY_FALLBACK) falls to its narrowest value.
//   - a TUNING key that fails its rule is not applied; the agent's default
//     stands.
//
// A file that is absent declares nothing. A file that is not a regular file,
// is group- or world-writable, or is owned by someone else is refused whole,
// with the reason, and nothing in it is applied.
package nodelocal

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// FilePath is the node's declarations file, on Linux and macOS alike.
const FilePath = "/etc/noo-node-agent.local.env"

type kind int

const (
	trust kind = iota
	tuning
)

type rule struct {
	kind  kind
	check func(string) error
	// onRefuse is the value a refused narrowing falls to ("" = unset).
	onRefuse string
}

// Keys is the node-local key set: the only names this file may set.
var Keys = map[string]rule{
	// Trust declarations.
	"NOO_BACKEND_CAP_ADD":            {kind: trust, check: checkCaps},
	"NOO_CONTAINER_IMAGE_ALLOW":      {kind: trust, check: checkImageAllow},
	"NOO_CONTAINER_RUN_USER":         {kind: trust, check: checkRunUser},
	"NOO_SKILL_RUN_USER":             {kind: trust, check: checkRunUser},
	"NOO_ALLOW_OLLAMA_REGISTRY_PULL": {kind: trust, check: oneOf("0", "1")},
	"NOO_SKILL_BIND_ROOTS":           {kind: trust, check: checkBindRoots},
	"NOO_MCP_SECRETS_FILE":           {kind: trust, check: checkFilePath},
	"NOO_IMAGE_REGISTRY_FALLBACK":    {kind: trust, check: oneOf("public", "off"), onRefuse: "off"},
	// Tuning.
	"NOO_GPU_YIELD":            {kind: tuning, check: oneOf("on", "off")},
	"NOO_GPU_YIELD_FOREIGN_MB": {kind: tuning, check: checkCount},
	"NOO_GPU_YIELD_AFTER_S":    {kind: tuning, check: checkCount},
	"NOO_GPU_RESUME_AFTER_S":   {kind: tuning, check: checkCount},
	"NOO_GPU_TIMEOUT_GRACE_S":  {kind: tuning, check: checkCount},
	"NOO_LOG_SHIP":             {kind: tuning, check: oneOf("0", "1", "on", "off", "true", "false", "yes", "no")},
	"NOO_LOG_SHIP_UNITS":       {kind: tuning, check: checkUnits},
	"NOO_AGENT_TUNNEL":         {kind: tuning, check: oneOf("0", "1", "on", "off", "true", "false", "yes", "no")},
}

// Refusal is one key the file declared and the agent did not apply.
type Refusal struct {
	Key    string `json:"key"`
	Why    string `json:"why"`
	Source string `json:"source"` // local file | environment
	Trust  bool   `json:"trust"`
}

// Declaration is one node-local key in effect and where its value came from:
// "local file", or "environment" (a systemd drop-in, or a line an operator
// put in the rendered env, which the next roll wipes).
type Declaration struct {
	Key    string `json:"key"`
	Source string `json:"source"`
	Trust  bool   `json:"trust"`
}

// Report is what the heartbeat sends as `node_local`.
type Report struct {
	Path     string        `json:"path"`
	State    string        `json:"state"` // absent | read | refused (the FILE's state)
	Why      string        `json:"why,omitempty"`
	Declared []Declaration `json:"declared"`
	Refused  []Refusal     `json:"refused"`
	Ignored  []string      `json:"ignored"`
}

const (
	srcFile = "local file"
	srcEnv  = "environment"
)

var (
	mu   sync.Mutex
	last *Report
)

// Path is where the declarations file lives.
func Path() string { return FilePath }

// wantOwner is the uid the file and its directory must belong to: root, on
// every platform.
func wantOwner() uint32 { return 0 }

// Apply reads Path() and applies its declarations to the process environment
// (call it before anything reads the environment). It records the report the
// heartbeat sends.
func Apply() *Report {
	r := apply(Path(), wantOwner(), wantOwner(), os.Getenv, os.Setenv, os.Unsetenv)
	mu.Lock()
	last = r
	mu.Unlock()
	return r
}

// Current is the last Apply's report, or nil before Apply. Its `state` is
// "absent" when the node declares nothing.
func Current() any {
	mu.Lock()
	defer mu.Unlock()
	if last == nil {
		return nil
	}
	return *last
}

// apply decides the EFFECTIVE value of every node-local key and holds it to
// its rule, whatever its source:
//   - the local file wins when it declares the key;
//   - a key the local file declares and that fails its rule fails closed (a
//     trust key is removed, or set to its narrowest value), even when the
//     environment also sets it;
//   - a key only the environment sets (a systemd drop-in) is kept, but held
//     to the same rule and fails closed the same way: it is no longer taken
//     blindly.
func apply(p string, owner, dirOwner uint32, getenv func(string) string, setenv func(string, string) error, unsetenv func(string) error) *Report {
	r := &Report{Path: p, State: "absent", Declared: []Declaration{}, Refused: []Refusal{}, Ignored: []string{}}
	fileVals, fileBad := readFile(p, owner, dirOwner, r)
	keys := make([]string, 0, len(Keys))
	for k := range Keys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rl := Keys[key]
		if why, bad := fileBad[key]; bad {
			refuse(r, rl, key, why, srcFile, setenv, unsetenv)
			continue
		}
		if val, ok := fileVals[key]; ok {
			if err := setenv(key, val); err != nil {
				refuse(r, rl, key, "could not be applied: "+err.Error(), srcFile, setenv, unsetenv)
				continue
			}
			r.Declared = append(r.Declared, Declaration{Key: key, Source: srcFile, Trust: rl.kind == trust})
			continue
		}
		val := getenv(key)
		if val == "" {
			continue
		}
		if why := valueRefusal(val); why != "" {
			refuse(r, rl, key, why, srcEnv, setenv, unsetenv)
			continue
		}
		if err := rl.check(val); err != nil {
			refuse(r, rl, key, err.Error(), srcEnv, setenv, unsetenv)
			continue
		}
		r.Declared = append(r.Declared, Declaration{Key: key, Source: srcEnv, Trust: rl.kind == trust})
		if rl.kind == trust {
			slog.Warn("node-local trust declaration read from the agent's environment, not the local file: move it there so it is held to one place",
				"key", key, "file", p)
		}
	}
	sort.Strings(r.Ignored)
	if len(r.Ignored) > 0 {
		slog.Warn("node-local declarations: names that are not node-local keys are ignored (only the node's own declarations belong in this file)",
			"path", p, "ignored", r.Ignored)
	}
	slog.Info("node-local declarations applied", "path", p, "file", r.State, "declared", len(r.Declared), "refused", len(r.Refused))
	return r
}

// readFile reads the local file into accepted values and refusals by key. A
// file that is absent, or refused whole, contributes nothing (r.State says
// which).
func readFile(p string, owner, dirOwner uint32, r *Report) (map[string]string, map[string]string) {
	vals, bad := map[string]string{}, map[string]string{}
	fi, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return vals, bad
	}
	if why := fileRefusal(fi, err, owner); why == "" {
		why = dirRefusal(p, dirOwner)
		if why != "" {
			r.State, r.Why = "refused", why
			slog.Error("node-local declarations file refused: nothing in it is applied", "path", p, "why", why)
			return vals, bad
		}
	} else {
		r.State, r.Why = "refused", why
		slog.Error("node-local declarations file refused: nothing in it is applied", "path", p, "why", why)
		return vals, bad
	}
	b, err := os.ReadFile(p)
	if err != nil {
		r.State, r.Why = "refused", "unreadable by the agent ("+err.Error()+"): it must be mode 644 (owner root)"
		slog.Error("node-local declarations file refused: nothing in it is applied", "path", p, "why", r.Why)
		return vals, bad
	}
	r.State = "read"
	seen := map[string]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		key = strings.TrimSpace(key)
		if !ok || !keyName.MatchString(key) {
			r.Ignored = append(r.Ignored, fmt.Sprintf("line %d", n+1))
			continue
		}
		rl, known := Keys[key]
		if !known {
			r.Ignored = append(r.Ignored, key)
			continue
		}
		if seen[key] {
			bad[key] = "declared twice"
			delete(vals, key)
			continue
		}
		seen[key] = true
		if why := valueRefusal(val); why != "" {
			bad[key] = why
			continue
		}
		if err := rl.check(val); err != nil {
			bad[key] = err.Error()
			continue
		}
		vals[key] = val
	}
	return vals, bad
}

// refuse records a refused key and fails closed: a trust declaration is
// removed from the environment (or set to its narrowest value); a tuning key
// is left to the agent's default.
func refuse(r *Report, rl rule, key, why, source string, setenv func(string, string) error, unsetenv func(string) error) {
	r.Refused = append(r.Refused, Refusal{Key: key, Why: why, Source: source, Trust: rl.kind == trust})
	if rl.kind == trust {
		if rl.onRefuse != "" {
			_ = setenv(key, rl.onRefuse)
		} else {
			_ = unsetenv(key)
		}
	}
	slog.Error("node-local declaration refused", "key", key, "why", why, "source", source, "trust", rl.kind == trust)
	if rl.kind != trust {
		// A refused tuning value is not applied: the agent's default stands.
		_ = unsetenv(key)
	}
}

func fileRefusal(fi os.FileInfo, err error, owner uint32) string {
	if err != nil {
		return "unreadable: " + err.Error()
	}
	if !fi.Mode().IsRegular() {
		return "not a regular file (a symlink or a directory is refused)"
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("mode %04o is group- or world-writable (chmod 644)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != owner {
		return fmt.Sprintf("owned by uid %d, not %d", st.Uid, owner)
	}
	return ""
}

// dirRefusal holds the file's directory, resolved (macOS's /etc is a symlink
// to /private/etc), to the same owner and to no group/world write: a weaker
// directory would let someone else swap the file.
func dirRefusal(p string, owner uint32) string {
	dir, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "its directory cannot be resolved: " + err.Error()
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return "its directory is unreadable: " + err.Error()
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("its directory %s is group- or world-writable (mode %04o)", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != owner {
		return fmt.Sprintf("its directory %s is owned by uid %d, not %d", dir, st.Uid, owner)
	}
	return ""
}

// valueRefusal is the charset every value is held to before its own rule:
// no quote, backslash, `$`, backtick, whitespace inside, or `%`.
func valueRefusal(v string) string {
	if v == "" {
		return "empty"
	}
	if strings.ContainsAny(v, "\"'\\$`% \t") {
		return "contains a quote, backslash, $, backtick, % or whitespace"
	}
	return ""
}

func oneOf(vals ...string) func(string) error {
	return func(v string) error {
		for _, ok := range vals {
			if strings.EqualFold(v, ok) {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(vals, ", "))
	}
}

func checkCaps(v string) error {
	if strings.EqualFold(v, "none") {
		return nil
	}
	for _, c := range strings.Split(v, ",") {
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
		if n == "" || !docker.BackendCapGrantable(n) {
			return fmt.Errorf("%q is not grantable (each one outside the allow-list lets a container reach the host)", c)
		}
	}
	return nil
}

var keyName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var (
	imgSeg   = `[a-z0-9]+(?:[._-][a-z0-9]+)*`
	imgEntry = regexp.MustCompile(`^` + imgSeg + `(?::[0-9]+)?(?:/` + imgSeg + `)*/?$`)
)

func checkImageAllow(v string) error {
	for _, e := range strings.Split(v, ",") {
		if !imgEntry.MatchString(e) {
			return fmt.Errorf("%q is not an image repository or a repository prefix", e)
		}
		if strings.HasSuffix(e, "/") && strings.Count(e, "/") < 2 {
			return fmt.Errorf("%q would allow every image on that registry: name a namespace (registry/namespace/)", e)
		}
	}
	return nil
}

var runUser = regexp.MustCompile(`^[0-9]+(?::[0-9]+)?$`)

func checkRunUser(v string) error {
	if !runUser.MatchString(v) {
		return fmt.Errorf("must be uid or uid:gid (numbers)")
	}
	if uid, _ := strconv.Atoi(strings.SplitN(v, ":", 2)[0]); uid == 0 {
		return fmt.Errorf("uid 0 (root) is refused")
	}
	return nil
}

var pathChars = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]+$`)

var denyTrees = []string{"/etc", "/usr", "/boot", "/root", "/var/lib/docker", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/proc", "/sys", "/dev", "/run"}

// cleanAbs holds a path to the shape the protect drop-in uses: absolute,
// normalised, from a narrow charset.
func cleanAbs(p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || p == "/" {
		return fmt.Errorf("%q is not an absolute, normalised path", p)
	}
	if !pathChars.MatchString(p) {
		return fmt.Errorf("%q has a character outside A-Z a-z 0-9 . _ @ + / -", p)
	}
	return nil
}

func checkBindRoots(v string) error {
	for _, p := range strings.Split(v, ":") {
		if err := cleanAbs(p); err != nil {
			return err
		}
		if p == "/home" {
			return fmt.Errorf("%q is every user's home: name the directory", p)
		}
		for _, d := range denyTrees {
			if p == d || strings.HasPrefix(p, d+"/") || strings.HasPrefix(d+"/", p+"/") {
				return fmt.Errorf("%q is, holds or sits under a system tree (%s)", p, d)
			}
		}
	}
	return nil
}

func checkFilePath(v string) error {
	if err := cleanAbs(v); err != nil {
		return err
	}
	for _, d := range []string{"/proc", "/sys", "/dev"} {
		if v == d || strings.HasPrefix(v, d+"/") {
			return fmt.Errorf("%q is under %s", v, d)
		}
	}
	return nil
}

func checkCount(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 10_000_000 {
		return fmt.Errorf("must be a whole number from 0 to 10000000")
	}
	return nil
}

var unitName = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)

func checkUnits(v string) error {
	for _, u := range strings.Split(v, ",") {
		if !unitName.MatchString(u) {
			return fmt.Errorf("%q is not a unit name", u)
		}
	}
	return nil
}
