// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// Image retention on a node: the keep file hostd's reclaim rung 5 reads
// (internal/hostd/image_retention.go). It names, by image ID and by exact
// repo digest, every image this node's desired state wants:
//
//   - each desired placement's image (BackendImageRef: the controller's
//     override, else the hardened default the start path would use),
//     whatever the placement's state: a backend paused for a GPU
//     reservation, or stopped, is still desired and keeps its image;
//   - every `repo@sha256:` reference anywhere in desired-config (add-on
//     node workloads, add-on workloads, door pins), which are pulled or
//     started by that digest; each claims only its own repository as
//     ours (the namespaces are the managed roots plus those repositories);
//
// resolved to the local image ID where the daemon has it (a rail-loaded
// image may carry no digest at all). The previous generation's entries are
// carried once when the set changes, so a rollback finds its images.
//
// It is rewritten at the end of every completed reconcile pass and carries
// a max age, so a node whose agent stops reconciling soon has a keep file
// hostd no longer believes, and the rung skips.

// imageKeepPath is where hostd's worker spool reads it (a var for tests).
var imageKeepPath = filepath.Join(hostd.WorkerSpoolDir, "image-keep.json")

const imageKeepMaxAge = time.Hour

var keepDigestRe = regexp.MustCompile(`[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}`)

type keepOut struct {
	Ref string `json:"ref,omitempty"`
	ID  string `json:"id,omitempty"`
	Why string `json:"why"`
}

type keepFileOut struct {
	Version       int       `json:"version"`
	WrittenAt     string    `json:"written_at"`
	MaxAgeSeconds int64     `json:"max_age_seconds"`
	Namespaces    []string  `json:"namespaces"`
	Keep          []keepOut `json:"keep"`
	// Current is this pass's set; Keep is Current plus the previous one.
	Current []keepOut `json:"current"`
}

// keepNamespace is the namespace a digest ref claims: its own repository
// and nothing wider. An add-on started from docker.io/library/x@sha256 must
// not make every docker.io/library image on the node look like ours.
func keepNamespace(ref string) string {
	name := strings.SplitN(ref, "@", 2)[0]
	if !strings.Contains(name, "/") {
		return ""
	}
	if !validKeepNamespace(name + "/") {
		return ""
	}
	return name + "/"
}

// validKeepNamespace is hostd's own test (`<registry host>/<path>/`): one
// namespace it refuses would make it disbelieve the whole file.
func validKeepNamespace(ns string) bool {
	host := strings.SplitN(ns, "/", 2)[0]
	return strings.HasSuffix(ns, "/") && strings.Count(ns, "/") >= 2 &&
		(strings.Contains(host, ".") || strings.HasPrefix(host, "localhost"))
}

// buildNodeKeep is the keep file, pure over its inputs.
func buildNodeKeep(d *desiredConfig, rawDesired []byte, imageRef func(backend, override string) string,
	localID func(ref string) string, roots []string, prev *keepFileOut, now time.Time) *keepFileOut {
	seen := map[string]bool{}
	var cur []keepOut
	add := func(e keepOut) {
		k := e.Ref + "|" + e.ID
		if (e.Ref == "" && e.ID == "") || seen[k] {
			return
		}
		seen[k] = true
		cur = append(cur, e)
	}
	ns := map[string]bool{}
	for _, r := range roots {
		if validKeepNamespace(r) {
			ns[r] = true
		}
	}
	for _, p := range d.Placements {
		ref := imageRef(p.Backend, p.Image)
		if ref == "" {
			continue
		}
		why := fmt.Sprintf("desired placement %s (%s)", p.Backend, strings.TrimSpace(p.DesiredState))
		e := keepOut{ID: localID(ref), Why: why}
		if keepDigestRe.MatchString(ref) && keepDigestRe.FindString(ref) == ref {
			e.Ref = ref
		}
		add(e)
	}
	for _, ref := range keepDigestRe.FindAllString(string(rawDesired), -1) {
		if n := keepNamespace(ref); n != "" {
			ns[n] = true
		}
		add(keepOut{Ref: ref, ID: localID(ref), Why: "named by digest in desired-config"})
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Ref+cur[i].ID < cur[j].Ref+cur[j].ID })
	keep := append([]keepOut{}, cur...)
	if prev != nil && !sameKeep(prev.Current, cur) {
		for _, e := range prev.Current {
			k := e.Ref + "|" + e.ID
			if !seen[k] {
				seen[k] = true
				keep = append(keep, keepOut{Ref: e.Ref, ID: e.ID, Why: "previous: " + strings.TrimPrefix(e.Why, "previous: ")})
			}
		}
	} else if prev != nil {
		// Unchanged set: keep carrying what the last change carried.
		for _, e := range prev.Keep {
			k := e.Ref + "|" + e.ID
			if !seen[k] && strings.HasPrefix(e.Why, "previous: ") {
				seen[k] = true
				keep = append(keep, e)
			}
		}
	}
	names := make([]string, 0, len(ns))
	for n := range ns {
		names = append(names, n)
	}
	sort.Strings(names)
	return &keepFileOut{Version: 1, WrittenAt: now.UTC().Format(time.RFC3339),
		MaxAgeSeconds: int64(imageKeepMaxAge / time.Second), Namespaces: names, Keep: keep, Current: cur}
}

func sameKeep(a, b []keepOut) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Ref != b[i].Ref || a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// writeImageKeep is the last reconcile phase. Never stops the pass.
func (r *Reconciler) writeImageKeep(ctx context.Context, t *tick) bool {
	if t.desired == nil || r.docker == nil {
		return true
	}
	raw, _ := json.Marshal(t.desired)
	var prev *keepFileOut
	if b, err := os.ReadFile(imageKeepPath); err == nil {
		var p keepFileOut
		if json.Unmarshal(b, &p) == nil {
			prev = &p
		}
	}
	k := buildNodeKeep(t.desired, raw, dockerpkg.BackendImageRef,
		func(ref string) string { return r.docker.LocalImageID(ctx, ref) },
		dockerpkg.OwnRegistryRoots(), prev, time.Now())
	if len(k.Keep) == 0 {
		return true // nothing desired: no keep file is written, the rung skips
	}
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return true
	}
	if err := os.MkdirAll(filepath.Dir(imageKeepPath), 0o755); err != nil {
		slog.Warn("reconcile.image_keep_unwritable", "error", err)
		return true
	}
	tmp := imageKeepPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		if err := os.Rename(tmp, imageKeepPath); err != nil {
			slog.Warn("reconcile.image_keep_unwritable", "error", err)
		}
	}
	return true
}
