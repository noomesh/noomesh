// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Docker disk reclaim (op: disk-reclaim).
//
// The ladder is deliberately narrow. It may remove ONLY:
//
//  1. dangling images — `docker image prune -f`, never -a. -a deletes tagged
//     images, and a "stale" tag can be a documented rollback target.
//  2. build cache older than 7 days — never --all.
//  3. stopped rename-orphan containers named <12hex>_noo-* (the design's
//     artifact class), via `docker rm` WITHOUT -f, so a running container is
//     structurally impossible to remove even if the listing races.
//
//  4. build-cache volumes — ONLY volumes carrying the `noo.cargo-docker-src`
//     label that scripts/cargo-docker.sh puts on its per-checkout Rust target
//     volumes, ONLY when no container uses them, and ONLY when the checkout
//     they cache is gone or the volume has been idle for a week. Removed one
//     by one with `docker volume rm` (no -f), so a volume in use fails.
//
// It must NEVER touch any OTHER volume, tagged images, or anything running.
// Volumes are the sharp one: a briefly-down container makes its volume
// "unused", so an unattended `docker volume prune` can destroy the pgvector
// store, a trading database or the model cache during a routine restart. That
// is why rung 4 selects by OUR label, never by "dangling" alone, and never
// prunes. On host3 98 such build volumes held ~117 GB while the
// unlabelled dangling set beside them included real databases.

// orphanRe matches ONLY the compose rename-orphan pattern: an anchored 12-hex
// prefix plus a literal "_noo-". Nothing an operator names by hand collides
// with this, which is what makes rung 3 safe to run unattended.
var orphanRe = regexp.MustCompile(`^[0-9a-f]{12}_noo-`)

var reclaimedRe = regexp.MustCompile(`Total(?::| reclaimed space:) .*`)

// diskReclaimTargetPath picks the filesystem whose usage the ladder is trying
// to relieve. Image layers live under the containerd snapshotter on the
// two-disk split deployment, so prefer that; fall back to Docker's root dir,
// then /.
func (e *Engine) diskReclaimTargetPath(ctx context.Context) string {
	if fi, err := os.Stat("/var/lib/containerd"); err == nil && fi.IsDir() {
		return "/var/lib/containerd"
	}
	if rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "info", "--format", "{{.DockerRootDir}}"); rc == 0 && out != "" {
		if fi, err := os.Stat(out); err == nil && fi.IsDir() {
			return out
		}
	}
	return "/"
}

// diskUsagePct returns the integer used-percent of the filesystem at path,
// using df's own rounding so the number matches what an operator sees. Returns
// -1 when it cannot be determined.
func (e *Engine) diskUsagePct(ctx context.Context, path string) int {
	rc, out := e.Runner.Capture(ctx, reclaimDir, "df", "-P", "--", path)
	if rc != 0 {
		return -1
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return -1
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
	if err != nil {
		return -1
	}
	return v
}

// reclaimOrphans lists stopped containers matching the rename-orphan pattern.
// reclaimBuilders returns top-level buildx BUILDER names (never node rows).
//
// `docker buildx ls --format '{{.Name}}'` emits builders AND their child
// nodes ("noo-builder0"); a node name is not addressable via --builder — it
// yields empty output and a failed prune. Node rows are indented in the table
// output, builder rows are not, so parse the table rather than the template.
// Falls back to "default" so the ladder still runs on a docker without buildx.
func (e *Engine) reclaimBuilders(ctx context.Context) []string {
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "buildx", "ls")
	if rc != 0 || strings.TrimSpace(out) == "" {
		return []string{"default"}
	}
	seen := map[string]bool{}
	var names []string
	for i, l := range strings.Split(out, "\n") {
		if i == 0 || l == "" || l[0] == ' ' || l[0] == '\t' {
			continue // header, blank, or an indented node row
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		n := strings.TrimSuffix(f[0], "*") // the current builder is starred
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	if len(names) == 0 {
		return []string{"default"}
	}
	return names
}

// buildxSupportsMaxUsedSpace reports whether this buildx can cap cache size.
// Older buildx has no such flag, and passing it would fail the whole rung.
func (e *Engine) buildxSupportsMaxUsedSpace(ctx context.Context) bool {
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "buildx", "prune", "--help")
	return rc == 0 && strings.Contains(out, "--max-used-space")
}

func (e *Engine) reclaimOrphans(ctx context.Context) []string {
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "ps", "-a",
		"--filter", "status=exited", "--filter", "status=created", "--format", "{{.Names}}")
	if rc != 0 || out == "" {
		return nil
	}
	var names []string
	for _, n := range strings.Split(out, "\n") {
		n = strings.TrimSpace(n)
		if n != "" && orphanRe.MatchString(n) {
			names = append(names, n)
		}
	}
	return names
}

// diskReclaim walks the ladder, stopping as soon as usage drops below the
// watermark. The returned string is the report that rides the result file —
// one compact line per rung, because it is capped at 2000 chars.
func (e *Engine) diskReclaim(ctx context.Context, dryRun bool, watermark int, capBytes int64) (int, string) {
	target := e.diskReclaimTargetPath(ctx)
	before := e.diskUsagePct(ctx, target)
	if before < 0 {
		return 1, fmt.Sprintf("disk-reclaim: cannot measure usage of %s", target)
	}
	report := fmt.Sprintf("target=%s before=%d%% watermark=%d%%", target, before, watermark)

	if dryRun {
		// Preview only. This is the SHIPPED DEFAULT; the operator sets
		// dry_run:false on the autonomy location to act.
		_, dangling := e.Runner.Capture(ctx, reclaimDir, "docker", "images", "-f", "dangling=true", "-q")
		nDangling := 0
		for _, l := range strings.Split(dangling, "\n") {
			if strings.TrimSpace(l) != "" {
				nDangling++
			}
		}
		// Per builder, NOT `docker system df` — that reports only the
		// docker-driver builder and can hide tens of GB (see rung 2).
		var caches []string
		for _, b := range e.reclaimBuilders(ctx) {
			_, du := e.Runner.Capture(ctx, reclaimDir, "docker", "buildx", "du", "--builder", b)
			r := "unknown"
			for _, l := range strings.Split(du, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), "Reclaimable:") {
					if p := strings.SplitN(l, ":", 2); len(p) == 2 {
						r = strings.TrimSpace(p[1])
					}
				}
			}
			caches = append(caches, b+": "+r)
		}
		cache := "unknown"
		if len(caches) > 0 {
			cache = strings.Join(caches, ", ")
		}
		orphans := "none"
		if o := e.reclaimOrphans(ctx); len(o) > 0 {
			orphans = strings.Join(o, " ")
		}
		return 0, fmt.Sprintf(
			"DRY RUN (nothing removed) — %s | rung1: %d dangling image(s) "+
				"| rung2: build cache reclaimable %s (only >7d would be pruned) "+
				"| rung3: rename-orphan container(s): %s "+
				"| rung4: %d stale build-cache volume(s)",
			report, nDangling, cache, orphans, len(e.staleBuildVolumes(ctx, time.Now())))
	}

	// Rung 1 — dangling images.
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "image", "prune", "-f")
	if rc != 0 {
		return 1, fmt.Sprintf("%s | rung1 (dangling images) FAILED", report)
	}
	report += " | rung1 dangling images: " + reclaimedOrNothing(out)
	if after := e.usageOr(ctx, target, before); after < watermark {
		return 0, fmt.Sprintf("%s (now %d%%) | stopped: below watermark", report, after)
	}

	// Rung 2 — build cache older than 7 days, on EVERY builder.
	//
	// `docker builder prune` and `docker system df` only see the docker-driver
	// builder. A buildx container-driver builder keeps its cache in its own
	// volume, invisible to both. A host can sit at 82% disk with system df
	// reporting 1.2 GB while noo-builder holds 96.9 GB — this rung would
	// have run, freed nothing, and reported success.
	builders := e.reclaimBuilders(ctx)
	var freed2 []string
	prunedAny := false
	for _, b := range builders {
		rc, out = e.Runner.Capture(ctx, reclaimDir, "docker", "buildx", "prune", "-f",
			"--builder", b, "--filter", "until=168h")
		if rc != 0 {
			// A stopped container-driver builder is a normal state, not an
			// error — do not abort the remaining builders.
			freed2 = append(freed2, b+": FAILED")
			continue
		}
		prunedAny = true
		freed2 = append(freed2, b+": "+reclaimedOrNothing(out))
	}
	if !prunedAny {
		return 1, fmt.Sprintf("%s | rung2 (build cache >7d) FAILED on every builder", report)
	}
	report += " | rung2 build cache >7d: " + strings.Join(freed2, ", ")
	if after := e.usageOr(ctx, target, before); after < watermark {
		return 0, fmt.Sprintf("%s (now %d%%) | stopped: below watermark", report, after)
	}

	// Rung 2b — cap each builder's cache at CacheCapBytes (0 = off).
	//
	// Rung 2's until=168h filters on LAST USED, not created. A base layer that
	// every build reuses is touched hourly, so it is never 7 days idle and
	// rung 2 can never evict it however large it grows. rung 2 can free
	// 276 MB of 96.9 GB where a size cap frees 82 GB (82% -> 50%). An age policy
	// cannot bound build cache; a size policy can. Cache is regenerable, so
	// the only cost of eviction is a slower next build.
	if capBytes <= 0 {
		capBytes = e.CacheCapBytes
	}
	if capBytes > 0 {
		if !e.buildxSupportsMaxUsedSpace(ctx) {
			report += " | rung2b skipped: buildx too old for --max-used-space"
		} else {
			var freed2b []string
			for _, b := range builders {
				rc, out = e.Runner.Capture(ctx, reclaimDir, "docker", "buildx", "prune", "-f",
					"--builder", b, "--max-used-space", strconv.FormatInt(capBytes, 10))
				if rc != 0 {
					freed2b = append(freed2b, b+": FAILED")
					continue
				}
				freed2b = append(freed2b, b+": "+reclaimedOrNothing(out))
			}
			report += fmt.Sprintf(" | rung2b cache cap %dB: %s",
				capBytes, strings.Join(freed2b, ", "))
			if after := e.usageOr(ctx, target, before); after < watermark {
				return 0, fmt.Sprintf("%s (now %d%%) | stopped: below watermark", report, after)
			}
		}
	}

	// Rung 3 — stopped rename-orphan containers only.
	removed, failed := 0, 0
	for _, n := range e.reclaimOrphans(ctx) {
		if rc, _ := e.Runner.Run(ctx, reclaimDir, nil, "docker", "rm", "--", n); rc == 0 {
			removed++
		} else {
			failed++
		}
	}
	report += fmt.Sprintf(" | rung3 rename-orphans: removed %d", removed)
	if failed > 0 {
		report += fmt.Sprintf(", %d failed", failed)
	}
	if after := e.usageOr(ctx, target, before); after < watermark {
		return 0, fmt.Sprintf("%s (now %d%%) | stopped: below watermark", report, after)
	}

	// Rung 4 — stale build-cache volumes, by our label only (see the header).
	vRemoved, vFailed := 0, 0
	for _, v := range e.staleBuildVolumes(ctx, time.Now()) {
		if rc, _ := e.Runner.Run(ctx, reclaimDir, nil, "docker", "volume", "rm", "--", v); rc == 0 {
			vRemoved++
		} else {
			vFailed++ // in use by a container that started since the listing
		}
	}
	report += fmt.Sprintf(" | rung4 build-cache volumes: removed %d", vRemoved)
	if vFailed > 0 {
		report += fmt.Sprintf(", %d in use", vFailed)
	}

	after := e.usageOr(ctx, target, before)
	if after < watermark {
		return 0, fmt.Sprintf("%s (now %d%%) | below watermark", report, after)
	}
	return 0, fmt.Sprintf("%s | LADDER EXHAUSTED, still at %d%% — remaining space is tagged "+
		"images, data volumes or running containers, which this action will never touch. "+
		"Operator judgement required (docker system df).", report, after)
}

// buildVolumeLabel is the label scripts/cargo-docker.sh puts on its target
// volumes; its value is the checkout directory the volume caches.
// reclaimDir is the working directory of every ladder command. None of them
// reads a relative path, and the ladder also runs on workers, where the
// project root does not exist: a missing cmd.Dir fails exec before df ever
// starts, which is how the v0.2.88 rehearsal reported "cannot measure usage".
const reclaimDir = "/"

const buildVolumeLabel = "noo.cargo-docker-src"

// buildVolumeIdle is how long an unused build-cache volume whose checkout
// still exists is kept. A developer between builds keeps their cache; a
// checkout nobody has built in a week pays one cold rebuild.
const buildVolumeIdle = 7 * 24 * time.Hour

// staleBuildVolumes lists the rung-4 candidates: volumes with OUR label, used
// by no container (`dangling=true`), whose checkout is gone or whose data has
// not changed for buildVolumeIdle. An unreadable label or mountpoint keeps
// the volume — when in doubt, this rung does nothing.
func (e *Engine) staleBuildVolumes(ctx context.Context, now time.Time) []string {
	rc, out := e.Runner.Capture(ctx, reclaimDir, "docker", "volume", "ls", "-q",
		"--filter", "dangling=true", "--filter", "label="+buildVolumeLabel)
	if rc != 0 {
		return nil
	}
	var stale []string
	for _, v := range strings.Split(out, "\n") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		rc, info := e.Runner.Capture(ctx, reclaimDir, "docker", "volume", "inspect", "-f",
			`{{index .Labels "`+buildVolumeLabel+`"}}|{{.Mountpoint}}`, v)
		if rc != 0 {
			continue
		}
		src, mount, ok := strings.Cut(strings.TrimSpace(info), "|")
		if !ok || src == "" {
			continue
		}
		if _, err := os.Stat(src); os.IsNotExist(err) {
			stale = append(stale, v) // the checkout it caches is gone
			continue
		}
		if t, ok := newestMtime(mount); ok && now.Sub(t) > buildVolumeIdle {
			stale = append(stale, v)
		}
	}
	return stale
}

// newestMtime is the latest modification time of dir and its direct entries
// — a build rewrites files at the top of a cargo target dir, so this moves on
// every build without walking the whole tree.
func newestMtime(dir string) (time.Time, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return time.Time{}, false
	}
	newest := fi.ModTime()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return newest, true
	}
	for _, en := range entries {
		if info, err := en.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, true
}

func (e *Engine) usageOr(ctx context.Context, target string, fallback int) int {
	if v := e.diskUsagePct(ctx, target); v >= 0 {
		return v
	}
	return fallback
}

func reclaimedOrNothing(pruneOutput string) string {
	if m := reclaimedRe.FindAllString(pruneOutput, -1); len(m) > 0 {
		return strings.TrimSpace(m[len(m)-1])
	}
	return "nothing to remove"
}
