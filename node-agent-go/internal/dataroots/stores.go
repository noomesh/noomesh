// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// The model stores' modes, for the `model stores` verify row (proposal 61
// §7b). A store anyone on the host can write is a store anyone can plant
// model bytes in. HF weights are verified at each backend start on a placed
// node, GGUF files at start when the controller has a manifest, Ollama models
// against the controller's record about every 10 minutes; a store written by
// hand, or a node without a controller record, is not. Found on awolf
// 2026-11-17: hf-cache, hub, models and ollama 0777.
//
// The heartbeat's `data_roots.stores` is
//
//	{"checked": N, "world_writable": [{"path", "store", "mode", "uid", "gid"}]}
//
// where the checked paths are each declared root (the data root, the HF
// cache, the models dir, the Ollama store) and their first-level
// subdirectories (directories only, at most storeChildCap per root). Only
// the offending entries are listed, so a healthy node sends two numbers.
// World-writable means o+w WITHOUT the sticky bit: a 1777 directory lets
// anyone add a file but not replace someone else's. Read-only: the agent
// stats, it never changes a mode.

const storeChildCap = 64

// storeStat is os.Lstat, a seam for tests.
var storeStat = os.Lstat

// storeReadDir is os.ReadDir, a seam for tests.
var storeReadDir = os.ReadDir

// StoresReport is the `stores` object for r.
func StoresReport(r Roots) map[string]any {
	type root struct{ store, path string }
	roots := []root{
		{"data_root", r.NooDataRoot},
		{"hf_cache", r.HFCacheDir},
		{"models", r.ModelsDir},
		{"ollama", r.OllamaDataDir},
	}
	seen := map[string]bool{}
	checked := 0
	bad := []map[string]any{}
	look := func(store, p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		fi, err := storeStat(p)
		if err != nil || !fi.IsDir() {
			return
		}
		checked++
		m := fi.Mode()
		if m.Perm()&0o002 == 0 || m&fs.ModeSticky != 0 {
			return
		}
		e := map[string]any{"path": p, "store": store, "mode": modeOctal(m)}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			e["uid"], e["gid"] = int(st.Uid), int(st.Gid)
		}
		bad = append(bad, e)
	}
	for _, rt := range roots {
		look(rt.store, filepath.Clean(rt.path))
	}
	for _, rt := range roots {
		if rt.path == "" {
			continue
		}
		ents, err := storeReadDir(rt.path)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range ents {
			if n >= storeChildCap {
				break
			}
			if !e.IsDir() {
				continue
			}
			n++
			look(rt.store, filepath.Join(rt.path, e.Name()))
		}
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i]["path"].(string) < bad[j]["path"].(string) })
	return map[string]any{"checked": checked, "world_writable": bad}
}

// modeOctal is the permission bits plus setuid/setgid/sticky as chmod would
// take them ("0777", "2775", "1777").
func modeOctal(m fs.FileMode) string {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	s := []byte("0000")
	for i := 3; i >= 0; i-- {
		s[i] = byte('0' + v%8)
		v /= 8
	}
	return string(s)
}
