#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# reclaim-dev-disk.sh — free the build output a development checkout piles up.
#
# Every session that works in a worktree builds there, and each `target/`
# runs to several GB. On a busy dev box, dozens of worktrees whose PRs had
# already merged held well over 100 GB of `target/` while the disk sat nearly
# full and starved a model load. This removes ONLY build output:
#
#   - `target/` directories (top level and one level down) inside
#     `.worktrees/*` whose branch's PR is MERGED on GitHub. Merged is asked of
#     GitHub, not git: this repo rebase-merges, so a merged branch's commits
#     are never ancestors of dev and an ancestry test calls almost every
#     worktree "unmerged". A worktree with an open PR is left alone.
#   - nothing touched in the last 60 minutes (a build may be running).
#
# It never deletes a worktree, a branch, source files or Docker volumes (the
# node's own reclaim ladder handles labelled build volumes — see
# docs/operating/runbooks/autonomy-engine.md). Dry run by default.
#
# Usage: scripts/reclaim-dev-disk.sh [--apply]   (run from any clone)
set -euo pipefail

apply=0
case "${1:-}" in
  --apply) apply=1 ;;
  "") ;;
  -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  *) echo "unknown argument: $1 (use --apply, or nothing for a dry run)" >&2; exit 2 ;;
esac

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git checkout" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh is required to tell which PRs merged" >&2; exit 2; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh pr list -R "$(gh repo view --json nameWithOwner -q .nameWithOwner)" --state merged --limit 2000 \
  --json headRefName -q '.[].headRefName' | sort -u > "$tmp/merged"
gh pr list --state open --limit 500 --json headRefName -q '.[].headRefName' | sort -u > "$tmp/open"
[ -s "$tmp/merged" ] || { echo "GitHub returned no merged PRs — refusing to guess" >&2; exit 1; }

total_kb=0; count=0
while IFS=$'\t' read -r path branch; do
  grep -qxF "$branch" "$tmp/merged" || continue
  grep -qxF "$branch" "$tmp/open" && continue
  for t in "$path"/target "$path"/*/target; do
    [ -d "$t" ] || continue
    if [ -n "$(find "$t" -maxdepth 1 -newermt '-60 minutes' -print -quit 2>/dev/null)" ]; then
      echo "skip (built in the last hour): $t"; continue
    fi
    kb=$(du -sk "$t" 2>/dev/null | cut -f1); total_kb=$((total_kb + ${kb:-0})); count=$((count + 1))
    if [ "$apply" = 1 ]; then
      ionice -c3 nice -n19 rm -rf -- "$t" && echo "removed $t ($((kb / 1024)) MB)"
    else
      echo "would remove $t ($((kb / 1024)) MB)"
    fi
  done
done < <(git -C "$repo" worktree list --porcelain | awk '/^worktree /{p=$2} /^branch /{b=$2; sub("refs/heads/","",b); print p"\t"b}' | grep "/.worktrees/")

verb=$([ "$apply" = 1 ] && echo "freed" || echo "would free")
echo "$count build dir(s), $verb $((total_kb / 1024 / 1024)) GB$([ "$apply" = 1 ] || echo ' — re-run with --apply')"
