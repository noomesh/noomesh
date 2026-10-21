// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package addonwl holds the add-on workloads this node may start and stop
// (noomesh-internal i163 part B).
//
// An add-on's signed bundle declares its workloads (a container the add-on
// composes itself: a voice worker, an image or video worker). The launcher
// verifies the bundle, the gateway carries the declarations to the node in
// desired-config (`addon_workloads`), and the node agent's ONE generic
// actuator (`POST /api/addon-workloads/{addon}/{workload}/start|stop`) acts
// only on a container that is declared here AND carries the labels
// `noo.addon=<addon>` and `noo.workload=<workload>`. Nothing about the
// container (image, command, mounts) comes from the caller: start means
// start the existing container the add-on's compose created. So the add-on's
// own controller needs no Docker socket, and a future media add-on needs no
// node-agent change.
package addonwl

import (
	"strings"
	"sync"
)

// Decl is one declared workload as desired-config carries it.
type Decl struct {
	Addon     string `json:"addon"`
	Name      string `json:"name"`
	Container string `json:"container"`
	// GPU: the workload takes the GPU; it may start only under a GPU hold.
	GPU bool `json:"gpu"`
	// NeedMB: GPU memory the workload needs (0 = not declared).
	NeedMB int `json:"need_mb"`
}

var (
	mu       sync.RWMutex
	declared = map[string]Decl{}
)

func key(addon, name string) string { return addon + "/" + name }

// SetDeclared replaces the declarations (the reconciler, every tick, from
// desired-config). nil clears them: an undeclared workload cannot be acted on.
func SetDeclared(d []Decl) {
	next := map[string]Decl{}
	for _, w := range d {
		w.Addon, w.Name, w.Container = strings.TrimSpace(w.Addon), strings.TrimSpace(w.Name), strings.TrimSpace(w.Container)
		if w.Addon == "" || w.Name == "" || w.Container == "" {
			continue
		}
		next[key(w.Addon, w.Name)] = w
	}
	mu.Lock()
	declared = next
	mu.Unlock()
}

// Lookup is the declaration for addon/name, if any.
func Lookup(addon, name string) (Decl, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := declared[key(addon, name)]
	return d, ok
}

// DeclaredContainer reports whether addon/name is declared with exactly
// this container name (the node agent's container proxy admits such a
// container beside the ones it started itself).
func DeclaredContainer(addon, name, container string) bool {
	d, ok := Lookup(addon, name)
	return ok && d.Container == container
}

// Declared is every declaration, for a report.
func Declared() []Decl {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Decl, 0, len(declared))
	for _, d := range declared {
		out = append(out, d)
	}
	return out
}

// NameOK is the rule for an add-on or workload name as it is joined into a
// label value and a path: lowercase letters, digits, `-` and `_`, starting
// with a letter, at most 32 characters (the gateway's add-on name rule).
func NameOK(s string) bool {
	if s == "" || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
