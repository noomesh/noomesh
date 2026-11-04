// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// heldStateFile is the held-model seed, under the agent's state dir.
const heldStateFile = "held-models.json"

// heldState is the file's shape: version, then base URL -> placed models
// (primary first), the exact slice the reconciler handed SetHeldModels.
type heldState struct {
	Version int                 `json:"version"`
	Held    map[string][]string `json:"held"`
}

// heldFileMu serialises read-modify-write of the file inside this process.
var heldFileMu sync.Mutex

func readHeldState(path string) (heldState, error) {
	var st heldState
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return heldState{}, fmt.Errorf("corrupt %s: %w", path, err)
	}
	return st, nil
}

// SaveHeld persists this lane's held set (as SetHeldModels recorded it) in
// dir, so a restarted agent can report the placed model on its first
// heartbeat instead of waiting for the first reconcile pass (followup i418).
// Atomic (temp file + rename), 0600. A rewrite is skipped when nothing
// changed, so the reconcile tick does not touch the disk.
func (n *Native) SaveHeld(dir string) error {
	if n == nil || dir == "" {
		return nil
	}
	path := filepath.Join(dir, heldStateFile)
	held := n.HeldModels()

	heldFileMu.Lock()
	defer heldFileMu.Unlock()
	// A missing or corrupt file is rebuilt from this lane's set alone.
	st, _ := readHeldState(path)
	if st.Held == nil {
		st.Held = map[string][]string{}
	}
	prev, had := st.Held[n.ollamaBase]
	if len(held) == 0 && !had {
		return nil
	}
	if equalStrings(prev, held) && had {
		return nil
	}
	if len(held) == 0 {
		delete(st.Held, n.ollamaBase)
	} else {
		st.Held[n.ollamaBase] = held
	}
	st.Version = 1
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, heldStateFile+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SeedHeld loads the persisted held set for this lane's base into the
// in-memory store and returns it. A missing file is not an error (first run,
// or nothing was ever placed); a corrupt one is returned as an error with
// nothing seeded. Callers log it and carry on empty. The reconciler stays the
// authority: its first pass overwrites the seed.
func (n *Native) SeedHeld(dir string) ([]string, error) {
	if n == nil || dir == "" {
		return nil, nil
	}
	heldFileMu.Lock()
	st, err := readHeldState(filepath.Join(dir, heldStateFile))
	heldFileMu.Unlock()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	models := st.Held[n.ollamaBase]
	n.SetHeldModels(models...)
	return n.HeldModels(), nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
