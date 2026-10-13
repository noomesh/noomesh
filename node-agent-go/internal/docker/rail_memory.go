// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Which local image each verified rail tar loaded as.
//
// The controller's manifest names the image ID the tar holds AS THE
// CONTROLLER SEES IT. That is the config digest on Docker's classic image
// store and the manifest digest on the containerd image store (the default
// for fresh Docker 29 installs), so a node on the other store type never sees
// a match — and without this record it would re-fetch a multi-GB tar at every
// start. After a verified load the node records "tar sha256 → my image ID";
// a local image is then the staged one if it matches EITHER the manifest's
// image_id or the ID this node itself loaded from that exact tar.
//
// Persisted under <state dir>/rail/images.json (directory 0700, file 0600)
// so an agent restart does not cost a re-fetch, and READ only when this
// agent's uid owns it and nobody else can write it. Losing or distrusting
// the file costs one re-fetch per image, never a wrong answer.

var (
	railMemMu     sync.Mutex
	railMem       map[string]string
	railMemLoaded bool
)

// railMemoryPath is a seam for tests.
var railMemoryPath = func() string {
	dir := os.Getenv("NOO_AGENT_STATE")
	if dir == "" {
		dir = "/var/lib/noo-node-agent"
	}
	return filepath.Join(dir, "rail", "images.json")
}

func loadRailMemoryLocked() {
	if railMemLoaded {
		return
	}
	railMemLoaded = true
	railMem = map[string]string{}
	p := railMemoryPath()
	if err := railMemoryFileTrusted(p); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("rail image memory ignored: the file is not one only this agent can have written",
				"path", p, "reason", err.Error(),
				"effect", "local images are re-verified against the controller (one tar fetch each)")
		}
		return
	}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &railMem)
	}
}

// railMemoryFileTrusted: the record is believed only if it is a regular file
// owned by this process's uid and writable by nobody else. Anyone who could
// write it could otherwise mark an arbitrary local image as "the staged one".
func railMemoryFileTrusted(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (%s)", fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group- or world-writable (%o)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not this agent's %d", st.Uid, os.Getuid())
	}
	return nil
}

// rememberRailImage records that the tar with this sha256 loaded as imageID.
func rememberRailImage(sha, imageID string) {
	sha, imageID = strings.ToLower(strings.TrimSpace(sha)), strings.TrimSpace(imageID)
	if len(sha) != 64 || imageID == "" {
		return
	}
	railMemMu.Lock()
	defer railMemMu.Unlock()
	loadRailMemoryLocked()
	railMem[sha] = imageID
	if b, err := json.MarshalIndent(railMem, "", "  "); err == nil {
		p := railMemoryPath()
		if os.MkdirAll(filepath.Dir(p), 0o700) == nil {
			tmp := p + ".tmp"
			_ = os.Remove(tmp)
			if os.WriteFile(tmp, b, 0o600) == nil {
				_ = os.Rename(tmp, p)
			}
		}
	}
}

// railImageFor is the local image ID this node loaded from the tar with
// this sha256, or "" when it never did.
func railImageFor(sha string) string {
	railMemMu.Lock()
	defer railMemMu.Unlock()
	loadRailMemoryLocked()
	return railMem[strings.ToLower(strings.TrimSpace(sha))]
}

// resetRailMemory forgets the in-process copy. Tests only.
func resetRailMemory() {
	railMemMu.Lock()
	railMem, railMemLoaded = nil, false
	railMemMu.Unlock()
}
