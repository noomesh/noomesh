// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Rung 5 — superseded images (also the post-roll step, `only=superseded-images`).
//
// Every image the stack runs is pulled BY DIGEST from its lock, so an image
// a later release replaced keeps its RepoDigest and is never "dangling":
// rung 1 cannot see it, and every release and rc a host ever pulled stays
// (pop-os, 2026-11-13: ~58 GB of superseded images in the first 60 lines of
// `docker system df -v`). This rung removes an image ONLY when all of:
//
//  1. it is OURS: every one of its tags and repo digests is under a
//     namespace the keep file names (the registries our locks pin from).
//     An image with any foreign name — the operator's ollama/ollama:latest,
//     a trading image, a local build — is never a candidate. An image with
//     no tag and no digest is rung 1's, not this one's.
//  2. no container uses it, running OR stopped;
//  3. the keep file does not name it, by image ID or by exact repo digest.
//     The keep file is written by the caller that knows the locks (the CLI
//     on a controller, the agent on a node): the current and previous stack
//     lock, every enabled add-on's current and previous pin, a disabled
//     add-on's last pin, and on a node the images it vouches for.
//
// Identity is the image ID or an exact `repo@sha256:` digest, never a name
// pattern. Removal is `docker image rm` WITHOUT -f, by each of the image's
// refs and then its ID, so Docker itself still refuses an image in use.
//
// The keep file must be PROVABLY CURRENT or the rung does nothing: either
// every source file it names (stack.lock, addons.lock, ...) still hashes to
// what it was built from, or it is younger than its max_age_seconds. A keep
// file that is missing, unreadable, stale or empty skips the rung, saying
// why — it never falls back to "keep nothing".

const (
	imageKeepBasename   = "image-keep.json"
	imageReportBasename = "image-retention-report.json"
	imageKeepVersion    = 1
)

type keepEntry struct {
	Ref string `json:"ref"` // repo@sha256:<digest>
	ID  string `json:"id"`  // sha256:<image id>
	Why string `json:"why"`
}

type keepSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type keepFile struct {
	Version       int          `json:"version"`
	WrittenAt     string       `json:"written_at"`
	MaxAgeSeconds int64        `json:"max_age_seconds"`
	Sources       []keepSource `json:"sources"`
	Namespaces    []string     `json:"namespaces"`
	Keep          []keepEntry  `json:"keep"`
}

var (
	digestRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)
	imageIDRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// loadKeepFile reads and validates the keep file. Any doubt is an error, and
// an error skips the rung.
// resolveKeepArg turns `keep=spool` into this hostd's own spool's keep file.
// The controller's gateway sees the spool only through its container mount
// (/var/run/noo-spool), so it cannot name the host path; the token lets it
// say "the keep file beside the commands" without one. Anything else is
// passed through for loadKeepFile to judge (absolute path to image-keep.json
// only). With no spool known, the bare token stays and is refused as not
// absolute, so the rung skips with the reason.
func resolveKeepArg(v, spool string) string {
	if v == "spool" && spool != "" {
		return filepath.Join(spool, imageKeepBasename)
	}
	return v
}

func loadKeepFile(path string, now time.Time, readFile func(string) ([]byte, error)) (*keepFile, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) != imageKeepBasename {
		return nil, fmt.Errorf("keep file %q is not an absolute path to %s", path, imageKeepBasename)
	}
	raw, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("keep file %s cannot be read: %v", path, err)
	}
	var k keepFile
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("keep file %s is not valid JSON: %v", path, err)
	}
	if k.Version != imageKeepVersion {
		return nil, fmt.Errorf("keep file %s has version %d, this hostd reads %d", path, k.Version, imageKeepVersion)
	}
	if len(k.Namespaces) == 0 {
		return nil, fmt.Errorf("keep file %s names no namespace, so nothing can be shown to be ours", path)
	}
	for _, ns := range k.Namespaces {
		if !strings.HasSuffix(ns, "/") || !strings.Contains(strings.SplitN(ns, "/", 2)[0], ".") && !strings.HasPrefix(ns, "localhost") {
			return nil, fmt.Errorf("keep file %s names namespace %q, which is not `<registry host>/<path>/`", path, ns)
		}
	}
	if len(k.Keep) == 0 {
		return nil, fmt.Errorf("keep file %s keeps nothing; a keep-set that empty is not believed", path)
	}
	for _, e := range k.Keep {
		if (e.Ref == "" || !digestRefRe.MatchString(e.Ref)) && (e.ID == "" || !imageIDRe.MatchString(e.ID)) {
			return nil, fmt.Errorf("keep file %s has an entry with neither a repo@sha256 digest nor an image id (%q)", path, e.Why)
		}
	}
	// Provably current: every source hashes as recorded, or it is young enough.
	switch {
	case len(k.Sources) > 0:
		for _, s := range k.Sources {
			b, err := readFile(s.Path)
			if err != nil {
				return nil, fmt.Errorf("keep file %s was built from %s, which cannot be read now (%v): stale", path, s.Path, err)
			}
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != s.SHA256 {
				return nil, fmt.Errorf("keep file %s was built from a different %s than the one on disk: stale (the next roll or `noo addons` change rewrites it)", path, s.Path)
			}
		}
	case k.MaxAgeSeconds > 0:
		t, err := time.Parse(time.RFC3339, k.WrittenAt)
		if err != nil {
			return nil, fmt.Errorf("keep file %s has no readable written_at", path)
		}
		if age := now.Sub(t); age > time.Duration(k.MaxAgeSeconds)*time.Second || age < -5*time.Minute {
			return nil, fmt.Errorf("keep file %s was written %s ago, past its %ds limit: stale", path, age.Round(time.Second), k.MaxAgeSeconds)
		}
	default:
		return nil, fmt.Errorf("keep file %s names neither its sources nor a max age, so it cannot be shown to be current", path)
	}
	return &k, nil
}

// imageFacts is one local image as Docker reports it.
type imageFacts struct {
	ID      string   // sha256:<64 hex>
	Tags    []string // repo:tag
	Digests []string // repo@sha256:<64 hex>
	Bytes   int64    // unique bytes when Docker says so, else total size
	Unique  bool
}

// imageVerdict is what the rung decided for one image, with the reason.
type imageVerdict struct {
	ID     string   `json:"id"`
	Refs   []string `json:"refs"`
	Bytes  int64    `json:"bytes"`
	Unique bool     `json:"bytes_unique"`
	Remove bool     `json:"remove"`
	Why    string   `json:"why"`
	Result string   `json:"result,omitempty"` // live run: removed | refused: <docker's words>
}

func refRepo(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i]
	}
	// repo:tag — the tag follows the LAST colon after the last slash.
	slash := strings.LastIndex(ref, "/")
	if c := strings.LastIndex(ref, ":"); c > slash {
		return ref[:c]
	}
	return ref
}

func underNamespace(ref string, namespaces []string) bool {
	repo := refRepo(ref) + "/"
	for _, ns := range namespaces {
		if strings.HasPrefix(repo, ns) {
			return true
		}
	}
	return false
}

// classifyImages is the rung's whole judgement, pure: `used` holds the image
// IDs of every container, running or stopped.
func classifyImages(imgs []imageFacts, used map[string]bool, k *keepFile) []imageVerdict {
	keepID := map[string]string{}
	keepRef := map[string]string{}
	for _, e := range k.Keep {
		if e.ID != "" {
			keepID[e.ID] = e.Why
		}
		if e.Ref != "" {
			keepRef[e.Ref] = e.Why
		}
	}
	out := make([]imageVerdict, 0, len(imgs))
	for _, im := range imgs {
		refs := append(append([]string{}, im.Tags...), im.Digests...)
		v := imageVerdict{ID: im.ID, Refs: refs, Bytes: im.Bytes, Unique: im.Unique}
		idWhy, idKept := keepID[im.ID]
		switch {
		case used[im.ID]:
			v.Why = "kept: used by a container (running or stopped)"
		case idKept:
			// Named by ID (a node's rail-loaded image): kept whatever its names.
			v.Why = "kept: " + idWhy
		case len(refs) == 0:
			v.Why = "skipped: no tag and no digest (dangling: rung 1's)"
		default:
			foreign := ""
			for _, r := range refs {
				if !underNamespace(r, k.Namespaces) {
					foreign = r
					break
				}
			}
			if foreign != "" {
				v.Why = "kept: not ours (" + foreign + ")"
				break
			}
			why, kept := "", false
			for _, d := range im.Digests {
				if w, ok := keepRef[d]; ok {
					why, kept = w, true
					break
				}
			}
			if kept {
				v.Why = "kept: " + why
			} else {
				v.Remove = true
				v.Why = "remove: ours, unused, named by no kept lock or pin"
			}
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Remove != out[j].Remove {
			return out[i].Remove
		}
		return out[i].Bytes > out[j].Bytes
	})
	return out
}

// parseHumanBytes reads Docker's sizes ("2.457GB", "91.42MB", "30.67kB", "2B").
func parseHumanBytes(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	units := []struct {
		suf  string
		mult float64
	}{{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"KB", 1e3}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(s, u.suf) {
			f, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suf), 64)
			if err != nil || f < 0 {
				return 0, false
			}
			return int64(f * u.mult), true
		}
	}
	return 0, false
}

// listImages gathers every local image's ID, tags, digests and size. Unique
// sizes come from `docker system df -v`; when Docker cannot say, the total
// size is used and marked so (shared layers then count more than once).
func (e *Engine) listImages(ctx context.Context) ([]imageFacts, error) {
	rc, ids := e.Runner.Capture(ctx, reclaimDir, "docker", "image", "ls", "-aq", "--no-trunc")
	if rc != 0 {
		return nil, fmt.Errorf("docker image ls failed")
	}
	seen := map[string]bool{}
	var list []string
	for _, l := range strings.Split(ids, "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] {
			seen[l] = true
			list = append(list, l)
		}
	}
	if len(list) == 0 {
		return nil, nil
	}
	args := append([]string{"image", "inspect", "--format",
		`{{.Id}}|{{join .RepoTags ","}}|{{join .RepoDigests ","}}|{{.Size}}`}, list...)
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", args...)
	if rc != 0 {
		return nil, fmt.Errorf("docker image inspect failed")
	}
	unique := e.uniqueSizes(ctx)
	var imgs []imageFacts
	for _, l := range strings.Split(out, "\n") {
		p := strings.Split(strings.TrimSpace(l), "|")
		if len(p) != 4 || !imageIDRe.MatchString(p[0]) {
			continue
		}
		im := imageFacts{ID: p[0], Tags: splitRefs(p[1]), Digests: splitRefs(p[2])}
		if n, err := strconv.ParseInt(p[3], 10, 64); err == nil {
			im.Bytes = n
		}
		if u, ok := unique[strings.TrimPrefix(p[0], "sha256:")[:12]]; ok {
			im.Bytes, im.Unique = u, true
		}
		imgs = append(imgs, im)
	}
	return imgs, nil
}

func splitRefs(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" && r != "<none>:<none>" && r != "<none>@<none>" {
			out = append(out, r)
		}
	}
	return out
}

// uniqueSizes maps a 12-hex image ID prefix to its unique bytes, from
// `docker system df -v --format '{{json .}}'`. Empty when Docker cannot say.
func (e *Engine) uniqueSizes(ctx context.Context) map[string]int64 {
	out := map[string]int64{}
	rc, raw := e.Runner.Capture(ctx, reclaimDir, "docker", "system", "df", "-v", "--format", "{{json .}}")
	if rc != 0 {
		return out
	}
	var df struct {
		Images []struct {
			ID         string `json:"ID"`
			UniqueSize string `json:"UniqueSize"`
		} `json:"Images"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &df) != nil {
		return out
	}
	for _, im := range df.Images {
		id := strings.TrimPrefix(im.ID, "sha256:")
		if len(id) < 12 {
			continue
		}
		if n, ok := parseHumanBytes(im.UniqueSize); ok {
			out[id[:12]] = n
		}
	}
	return out
}

// usedImageIDs is the image ID of every container, running or stopped. An
// error skips the rung: an unknown "in use" set protects nothing.
func (e *Engine) usedImageIDs(ctx context.Context) (map[string]bool, error) {
	rc, ids := e.Runner.Capture(ctx, reclaimDir, "docker", "ps", "-aq", "--no-trunc")
	if rc != 0 {
		return nil, fmt.Errorf("docker ps -a failed")
	}
	var list []string
	for _, l := range strings.Split(ids, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			list = append(list, l)
		}
	}
	used := map[string]bool{}
	if len(list) == 0 {
		return used, nil
	}
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", append([]string{"inspect", "--format", "{{.Image}}"}, list...)...)
	if rc != 0 {
		return nil, fmt.Errorf("docker inspect of the containers failed")
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); imageIDRe.MatchString(l) {
			used[l] = true
			n++
		}
	}
	// One image ID per container, or the "in use" set is not known: a reply
	// that parsed short (a format change, a partial answer) would otherwise
	// leave some container's image looking unused.
	if n != len(list) {
		return nil, fmt.Errorf("docker inspect returned %d image ids for %d containers, so what is in use is not known", n, len(list))
	}
	return used, nil
}

// supersededImages runs rung 5: classify, then (live) remove. It returns the
// compact report line and the bytes it freed (or would free).
func (e *Engine) supersededImages(ctx context.Context, keepPath string, dryRun bool) (string, int64) {
	k, err := loadKeepFile(keepPath, time.Now(), os.ReadFile)
	if err != nil {
		return "rung5 superseded images: SKIPPED — " + err.Error(), 0
	}
	used, err := e.usedImageIDs(ctx)
	if err != nil {
		return "rung5 superseded images: SKIPPED — " + err.Error(), 0
	}
	imgs, err := e.listImages(ctx)
	if err != nil {
		return "rung5 superseded images: SKIPPED — " + err.Error(), 0
	}
	verdicts := classifyImages(imgs, used, k)
	var freed int64
	removed, refused, kept := 0, 0, 0
	for i := range verdicts {
		v := &verdicts[i]
		if !v.Remove {
			kept++
			continue
		}
		if dryRun {
			freed += v.Bytes
			continue
		}
		if msg, ok := e.removeImage(ctx, v); ok {
			v.Result = "removed"
			removed++
			freed += v.Bytes
		} else {
			v.Result = "refused: " + msg
			refused++
		}
	}
	e.writeImageReport(keepPath, dryRun, verdicts, freed)
	if dryRun {
		return fmt.Sprintf("rung5 superseded images: would remove %d (%s), keep %d — per image in %s",
			countRemove(verdicts), humanBytes(freed), kept, filepath.Join(filepath.Dir(keepPath), imageReportBasename)), freed
	}
	line := fmt.Sprintf("rung5 superseded images: removed %d (%s), kept %d", removed, humanBytes(freed), kept)
	if refused > 0 {
		line += fmt.Sprintf(", %d refused by docker", refused)
	}
	return line, freed
}

func countRemove(vs []imageVerdict) int {
	n := 0
	for _, v := range vs {
		if v.Remove {
			n++
		}
	}
	return n
}

// removeImage untags each ref, then removes the ID if it is still there —
// never -f, so Docker refuses an image a container started meanwhile.
func (e *Engine) removeImage(ctx context.Context, v *imageVerdict) (string, bool) {
	for _, r := range v.Refs {
		if rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "image", "rm", "--", r); rc != 0 {
			return firstLine(out), false
		}
	}
	if rc, _ := e.Runner.Capture(ctx, reclaimDir, "docker", "image", "inspect", "--format", "{{.Id}}", v.ID); rc == 0 {
		if rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "image", "rm", "--", v.ID); rc != 0 {
			return firstLine(out), false
		}
	}
	return "", true
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// writeImageReport writes every verdict beside the keep file for the caller
// (the roll summary, verify) to read. Best effort: the result line stands.
func (e *Engine) writeImageReport(keepPath string, dryRun bool, vs []imageVerdict, total int64) {
	rep := struct {
		WrittenAt string         `json:"written_at"`
		DryRun    bool           `json:"dry_run"`
		Bytes     int64          `json:"bytes"`
		Images    []imageVerdict `json:"images"`
	}{time.Now().UTC().Format(time.RFC3339), dryRun, total, vs}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return
	}
	p := filepath.Join(filepath.Dir(keepPath), imageReportBasename)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
