// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Node-local stdio MCP servers: the ONLY way a process gets started here.
//
// # Why the controller lost this verb entirely
//
// An MCP placement with transport "stdio" carries a `command`, `args`,
// `env` and `cwd` from a controller database row, and the agent used to
// exec it. That made "place an MCP server" a general remote-code-execution
// verb against every node, and no amount of validation on the controller's
// side changes who is trusted: the row is data the controller writes, so a
// compromised controller writes whatever it likes.
//
// A first pass bounded it with an agent-side command allow-list
// (NOO_MCP_STDIO_ALLOW). That was better, but it still left the controller
// choosing the args, the cwd and the environment of a process on the node —
// and an allow-listed interpreter with attacker-chosen args is the same
// hole wearing a hat. `uvx`, `npx`, `python` and `node` are exactly the
// commands an operator would allow-list for MCP, and every one of them runs
// arbitrary code from its arguments.
//
// So the split is now clean, and it is the same split as the rest of this
// package: the controller may say WHICH servers this node should run
// (desired state, by id) but not WHAT runs. Every byte of a stdio server's
// definition — binary, arguments, working directory, environment — comes
// from a root-owned file on the node that the controller cannot write.
//
// # The file
//
// Default /etc/noo/mcp-servers.json, overridable with NOO_MCP_STDIO_FILE
// (read from the agent's own environment, so the override is node-local
// too). Absent is not an error: it means this node runs no stdio MCP
// server, which is every node unless an operator set one up.
//
//	[
//	  {
//	    "id": "git",
//	    "command": "/usr/local/lib/noo-mcp/mcp-server-git",
//	    "args": ["--repository", "/srv/repos/app"],
//	    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
//	    "env": {"GIT_AUTHOR_NAME": "noo", "GITHUB_TOKEN": "$GITHUB_TOKEN"},
//	    "cwd": "/var/lib/noo/mcp/git",
//	    "disabled": false
//	  }
//	]
//
// `$NAME` values resolve against the node-local MCP secrets file (see
// SecretLookup) — never the agent's environment.
//
// # What is checked, and why each check is there
//
// The file and its directory must be owned by uid 0 and not
// group- or world-writable. Without that the wall is decorative: the agent
// runs as noo-agent, so a file noo-agent could write would let anything
// that compromised the AGENT hand itself a new binary to run — and the
// point of this package is that a compromise of the control plane does not
// become code execution.
//
// `command` must be an absolute path. No PATH lookup: PATH is
// environment, and resolving through it means the binary that runs depends
// on state other than this file.
//
// The binary itself must be root-owned and not group/world-writable, for
// the same reason as the file: a writable binary is an allow-list entry
// anyone can redefine.
//
// `sha256`, when the operator records one, is verified on every load. It is
// optional because requiring it would make routine package upgrades fail
// closed in a way operators would work around by deleting the field; the
// ownership checks above are the floor, and the digest is the operator
// saying "and exactly these bytes".

// LocalStdioFileEnv overrides the node-local stdio server file.
const LocalStdioFileEnv = "NOO_MCP_STDIO_FILE"

const localStdioDefaultPath = "/etc/noo/mcp-servers.json"

// LocalEntry is one operator-declared MCP server.
type LocalEntry struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	// Image is REQUIRED. It is the container the server runs in, under the
	// skills sandbox floor — see validateLocalEntry and the design. An
	// entry without it does not start, and there is no un-contained lane to
	// fall back to.
	Image  string            `json:"image"`
	Args   []string          `json:"args"`
	SHA256 string            `json:"sha256"`
	Env    map[string]string `json:"env"`
	// Volumes are extra read-only binds, host path -> container path. Sources
	// must live under this node's declared host roots (NOO_HOST_ROOTS and
	// friends) — the same rule every other mount the agent makes obeys.
	Volumes map[string]string `json:"volumes"`
	// Network is "none" (the default) or a named docker network. A server that
	// needs the network says so here; "host" is refused.
	Network string `json:"network"`
	// Memory is a Docker-style size ("512m"). Empty means unlimited.
	Memory   string `json:"memory"`
	Cwd      string `json:"cwd"`
	Disabled bool   `json:"disabled"`
}

// LocalStdioPath is the file in effect.
func LocalStdioPath() string {
	if v := strings.TrimSpace(os.Getenv(LocalStdioFileEnv)); v != "" {
		return v
	}
	return localStdioDefaultPath
}

// LoadLocalStdio reads the node-local stdio servers.
//
// It returns the entries it accepted AND the per-entry refusals, rather
// than failing the whole file on one bad row: a typo in the fifth server
// must not silently take the other four offline. A problem with the FILE
// (unreadable, not root-owned, not JSON) is a single error — that one is
// not a typo, it is a misconfiguration or an attack, and it should stop
// everything this file would have started.
func LoadLocalStdio() (entries []LocalEntry, refusals map[string]string, err error) {
	return loadLocalStdio(LocalStdioPath(), localOwnerOK)
}

// localOwnerOK is the ownership rule in force. It is requireRootOwned and
// nothing else on a real node: the only writer is a test helper in this
// package, because a test process cannot create a root-owned file to
// exercise the parsing and per-entry validation around the rule. There is
// no env var and no config field behind it, so there is nothing an
// operator — or a controller — can set to relax it.
var localOwnerOK = requireRootOwned

// loadLocalStdio is LoadLocalStdio with the ownership rule injected.
//
// The seam exists because the production rule is "owned by uid 0", and a
// test process cannot create a root-owned file to exercise the parsing and
// per-entry validation around it. It is a package-private FUNCTION
// parameter, never an env var or a config field, so there is no way to
// relax the rule on a real node — and requireRootOwned is itself tested
// directly against real root-owned paths (/etc) and non-root ones.
func loadLocalStdio(
	path string,
	ownerOK func(string, os.FileInfo) error,
) (entries []LocalEntry, refusals map[string]string, err error) {
	refusals = map[string]string{}

	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// This node runs no stdio MCP server. The normal case.
			return nil, refusals, nil
		}
		return nil, refusals, fmt.Errorf("stdio MCP file %s: %w", path, err)
	}
	if err := ownerOK(path, st); err != nil {
		return nil, refusals, err
	}
	// A writable DIRECTORY lets someone replace the file wholesale, which
	// defeats every check on the file itself.
	dir := filepath.Dir(path)
	dst, derr := os.Stat(dir)
	if derr != nil {
		return nil, refusals, fmt.Errorf("stdio MCP file directory %s: %w", dir, derr)
	}
	if err := ownerOK(dir, dst); err != nil {
		return nil, refusals, err
	}

	raw, err := os.ReadFile(path) //nolint:gosec // operator-declared, ownership checked above
	if err != nil {
		return nil, refusals, fmt.Errorf("stdio MCP file %s: %w", path, err)
	}
	var all []LocalEntry
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, refusals, fmt.Errorf(
			"stdio MCP file %s is not a JSON array of server objects: %w", path, err)
	}

	seen := map[string]bool{}
	for i, e := range all {
		name := e.ID
		if name == "" {
			name = fmt.Sprintf("entry #%d", i)
		}
		if e.Disabled {
			continue
		}
		if err := validateLocalEntry(&e); err != nil {
			refusals[name] = err.Error()
			continue
		}
		if seen[e.ID] {
			refusals[e.ID] = "duplicate id in " + path
			continue
		}
		seen[e.ID] = true
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, refusals, nil
}

// requireRootOwned is the whole trust basis of this file: if noo-agent can
// write it, the agent can choose what the agent executes, and a control
// plane compromise becomes code execution after all.
func requireRootOwned(path string, st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine the owner of %s on this platform", path)
	}
	if sys.Uid != 0 {
		return fmt.Errorf(
			"%s must be owned by root (uid 0), not uid %d — this file decides what this node "+
				"executes, so a file the agent's own user can write is not a control at all; "+
				"`sudo chown root:root %s && sudo chmod 644 %s`",
			path, sys.Uid, path, path)
	}
	if mode := st.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf(
			"%s is group- or world-writable (%#o) — `sudo chmod %s %s`",
			path, mode, map[bool]string{true: "755", false: "644"}[st.IsDir()], path)
	}
	return nil
}

func validateLocalEntry(e *LocalEntry) error {
	if !valid_local_id(e.ID) {
		return fmt.Errorf("id %q must match [a-z0-9][a-z0-9_-]{0,63} (it becomes an MCP tool prefix)", e.ID)
	}
	if strings.TrimSpace(e.Image) == "" {
		// THE floor. A node-local MCP server is a third-party program the node
		// runs, exactly like a skill, and it now gets the skill's sandbox:
		// non-root, CapDrop ALL, no-new-privileges, a pid cap, no host network
		// and binds only under declared roots. It used to run as `noo-agent`,
		// which is in the `docker` group — root on the host by another name.
		//
		// This REFUSES rather than falling back to the old exec lane, because
		// a fallback is what the old lane would become: the weaker mode would
		// stay the easy one to write, and every entry that omitted the field
		// would quietly sit beside the docker socket. No node has this file
		// today, so nothing in the fleet is migrated by it.
		return fmt.Errorf(
			"entry has no `image`, and a node-local MCP server runs only in a container "+
				"(the skills sandbox floor: non-root, no capabilities, no-new-privileges, "+
				"a pid cap, no host network). Add \"image\": \"<the image this server runs "+
				"in>\" to this entry in %s — the image must be in this node's "+
				"managed-container allow-list (%s). There is no un-contained lane",
			LocalStdioPath(), "NOO_CONTAINER_IMAGE_ALLOW")
	}
	if !filepath.IsAbs(e.Command) {
		return fmt.Errorf(
			"command %q must be an absolute path — this file names a binary, not a PATH lookup, "+
				"so that what runs does not depend on the agent's environment. It is "+
				"bind-mounted read-only into the container at this same path", e.Command)
	}
	st, err := os.Stat(e.Command)
	if err != nil {
		return fmt.Errorf("command %s: %w", e.Command, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("command %s is not a regular file", e.Command)
	}
	if err := requireRootOwned(e.Command, st); err != nil {
		return fmt.Errorf("command %s: %w", e.Command, err)
	}
	if e.Cwd != "" && !filepath.IsAbs(e.Cwd) {
		return fmt.Errorf("cwd %q must be an absolute path", e.Cwd)
	}
	if e.SHA256 != "" {
		want := strings.ToLower(strings.TrimSpace(e.SHA256))
		if len(want) != 64 {
			return fmt.Errorf("sha256 %q is not 64 hex characters", e.SHA256)
		}
		got, err := fileSHA256(e.Command)
		if err != nil {
			return fmt.Errorf("hashing %s: %w", e.Command, err)
		}
		if got != want {
			return fmt.Errorf(
				"command %s does not match the sha256 recorded for it (have %s, want %s) — "+
					"the binary changed; update the digest deliberately if that was an upgrade",
				e.Command, got[:12]+"…", want[:12]+"…")
		}
	}
	return nil
}

func valid_local_id(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // operator-declared path
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Placement renders a local entry as the same shape the supervisor already
// drives, so there is ONE start path rather than two.
//
// The transport is `container`, never `stdio`: `stdio` now means "an
// uncontained process", and this package no longer has one.
func (e LocalEntry) Placement() Placement {
	spec, _ := json.Marshal(containerSpec{
		Image:   e.Image,
		Command: e.Command,
		Args:    e.Args,
		Env:     e.Env,
		Volumes: e.Volumes,
		Network: e.Network,
		Memory:  e.Memory,
	})
	return Placement{ID: e.ID, Transport: transportContainer, Spec: spec, Kind: "tool", DesiredState: "running"}
}
