#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Prune test-core-local's venv cache: keep the KEEP most recently USED venvs
# under DIR, remove the rest, never one in use, never CURRENT.
#
#   scripts/test-core-venv-prune.sh [--dry-run] DIR KEEP CURRENT
#
# --dry-run lists what it would remove (noomesh-internal's ops/batch/
# cleanup.sh reports with it) and removes nothing.
#
# test-core-local.sh keys a venv on the checkout's path, so every worktree
# gets its own (~2 GB), and nothing removed them: on 2026-11-10 awolf's root
# volume reached 0 MB free with 114 venvs, 192 GB, under
# ~/.cache/noomesh/test-core-venv.
#
# - A venv is a directory under DIR holding `.ci-install-stamp` (written by
#   test-core-local.sh). Nothing else under DIR is touched.
# - "Used" is the mtime of its `.last-used` (touched on every run), else of
#   its `.ci-install-stamp` (venvs from before this script).
# - "In use" is any `.in-use/<pid>` whose pid is alive (test-core-local.sh
#   writes its own before pruning and `exec`s pytest under the same pid, so
#   the marker holds for the whole run; a dead pid's marker is stale), or any
#   live process whose command line names the venv's path (runs that predate
#   the markers).
# - CURRENT (the venv this run uses) counts toward KEEP and is never removed.
# Prints ONE line when it removed something: how many, from where, and how
# much it freed. Exit 0 always unless the arguments are wrong: a cache it
# cannot prune must not stop a test run.
set -uo pipefail

dry=0
if [ "${1:-}" = "--dry-run" ]; then dry=1; shift; fi
dir=${1:-}; keep=${2:-}; current=${3:-}
if [ -z "$dir" ] || [ -z "$current" ] || ! [[ "$keep" =~ ^[1-9][0-9]*$ ]]; then
  echo "test-core-venv-prune: usage: DIR KEEP(>=1) CURRENT" >&2
  exit 2
fi
[ -d "$dir" ] || exit 0

in_use() {   # venv
  local m c
  for m in "$1"/.in-use/*; do
    [ -e "$m" ] || continue
    kill -0 "$(basename "$m")" 2>/dev/null && return 0
  done
  # A run started by a test-core-local.sh from before the markers (or any
  # other user of the venv) has none: a live process whose command line
  # names the venv's path (`$venv/bin/pytest …`) also counts.
  for c in /proc/[0-9]*/cmdline; do
    tr '\0' ' ' < "$c" 2>/dev/null | grep -qF -- "$1/" && return 0
  done
  return 1
}

used_at() {  # venv -> epoch seconds
  stat -c %Y "$1/.last-used" 2>/dev/null || stat -c %Y "$1/.ci-install-stamp" 2>/dev/null || echo 0
}

current=$(realpath -m "$current")
mapfile -t ranked < <(
  for v in "$dir"/*/; do
    v=${v%/}
    [ -f "$v/.ci-install-stamp" ] || continue
    printf '%s\t%s\n' "$(used_at "$v")" "$(realpath -m "$v")"
  done | sort -rn -k1,1 | cut -f2
)

# CURRENT takes the first of the KEEP slots, whatever its age.
slots=$((keep - 1))
removed=() bytes=0
for v in "${ranked[@]}"; do
  [ "$v" = "$current" ] && continue
  if [ "$slots" -gt 0 ]; then
    slots=$((slots - 1))
    continue
  fi
  in_use "$v" && continue
  size=$(du -sb "$v" 2>/dev/null | cut -f1)
  if [ "$dry" = 1 ]; then
    echo "would remove $v ($(numfmt --to=iec "${size:-0}" 2>/dev/null || echo "${size:-0}"))"
    removed+=("$(basename "$v")")
    bytes=$((bytes + ${size:-0}))
  elif rm -rf -- "$v" 2>/dev/null; then
    removed+=("$(basename "$v")")
    bytes=$((bytes + ${size:-0}))
  fi
done

if [ "${#removed[@]}" -gt 0 ]; then
  if [ "$dry" = 1 ]; then
    echo "test-core-local: would prune ${#removed[@]} unused venv(s) under $dir (keeping the $keep most recently used), freeing $(numfmt --to=iec "$bytes" 2>/dev/null || echo "$bytes bytes")"
  else
    echo "test-core-local: pruned ${#removed[@]} unused venv(s) under $dir (kept the $keep most recently used), freed $(numfmt --to=iec "$bytes" 2>/dev/null || echo "$bytes bytes")"
  fi
fi
exit 0
