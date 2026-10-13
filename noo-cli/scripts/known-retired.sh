#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# known-retired.sh — regenerate the KNOWN_RETIRED table in
# noo-cli/src/onboard/standalone.rs.
#
# KNOWN_RETIRED is the fixed cleanup list for files an install's OWN
# manifest cannot cover: an operator upgrading straight into the manifest
# feature has no old manifest at all, so the only way to retire a file
# their earlier noo already shipped is to know its shipped shas up front.
#
# Method: for every path the embed rules in build.rs would include (the
# individual entries in STANDALONE_FILES, plus every file ever recursively
# under a STANDALONE_DIRS directory), find every commit that DELETED such a
# path since the standalone-asset machinery was born (noo-cli/build.rs
# itself, added 2026-08-30 — a file gone before that was never embedded by
# anything and is not a candidate), then hash the file's content at every
# commit that touched it before the deletion.
#
# This script only PRINTS candidates + their shas; a human still decides
# which ones are true retirements (a rename to a new embedded path is not
# one) and edits the Rust table. Run it after any commit that deletes a
# file under a currently- or formerly-embedded path.
#
# Usage: noo-cli/scripts/known-retired.sh [since-date, default 2026-07-01]

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SINCE="${1:-2026-07-01}"
BUILD_RS_BIRTH="71338556e424d456074579d81bbceac51fbe06d2"  # noo-cli/build.rs added

# Directories walked recursively with NO filter (STANDALONE_DIRS).
DIRS=(prompts skills monitoring configs/grafana)

echo "# Deletions under embedded directories since $SINCE" >&2
git log --diff-filter=D --name-only --format='COMMIT %H %ad' --date=short \
    --since="$SINCE" -- "${DIRS[@]}" |
while read -r line; do
    if [[ "$line" == COMMIT* ]]; then
        commit="$line"
        continue
    fi
    [[ -z "$line" ]] && continue
    path="$line"
    # Skip anything deleted at or before build.rs's own birth commit — the
    # embed machinery did not exist yet, so nothing there was ever shipped.
    del_commit="${commit#COMMIT }"; del_commit="${del_commit%% *}"
    if git merge-base --is-ancestor "$del_commit" "$BUILD_RS_BIRTH" 2>/dev/null; then
        continue
    fi
    if [[ "$del_commit" == "$BUILD_RS_BIRTH" ]]; then
        continue
    fi
    echo "### $path  (deleted $commit)"
    shas=""
    for c in $(git log --format=%H -- "$path"); do
        # only commits BEFORE (or at) the deletion, oldest first
        if git merge-base --is-ancestor "$c" "$del_commit" 2>/dev/null || [[ "$c" == "$del_commit" ]]; then
            content_commit="$c"
            # the deletion commit itself has no content for this path
            if [[ "$c" == "$del_commit" ]]; then continue; fi
            sha=$(git show "$c:$path" 2>/dev/null </dev/null | sha256sum | cut -d' ' -f1) || true || continue
            echo "  $c  $sha"
        fi
    done
done

# STANDALONE_FILES entries (named individual paths) — swept from build.rs
# history: every quoted path that EVER appeared in the list (added or removed
# lines) since build.rs was born and that no longer exists in the tree.
# (followup: ones missed by the directory sweep above — the cluster executor,
# the host watcher, restart-watchdog.) Paths the current build.rs still lists
# are skipped. Hashes use every commit that touched the path.
echo "# Named STANDALONE_FILES paths that left the tree" >&2
git log --format= -p "${BUILD_RS_BIRTH}^..HEAD" -- noo-cli/build.rs |
    grep -E '^[-+ ][[:space:]]+"[A-Za-z0-9_./-]+",?[[:space:]]*$' |
    sed -E 's/^.[[:space:]]+"([^"]+)".*/\1/' | sort -u |
while read -r path; do
    [[ -e "$path" ]] && continue
    grep -qF "\"$path\"" noo-cli/build.rs && continue
    echo "### $path  (STANDALONE_FILES entry no longer in the tree)"
    for c in $(git log --format=%h --reverse -- "$path" </dev/null); do
        sha=$(git show "$c:$path" 2>/dev/null </dev/null | sha256sum | cut -d' ' -f1) || true
        # the empty-file sha is the deletion/rename commit itself — skip it
        [[ "$sha" == e3b0c442* ]] && continue
        echo "  $c  $sha"
    done
    true  # a trailing `continue` leaves status 1; under pipefail+set -e that would end the script
done

echo >&2
echo "# NOTE: a candidate may be a RENAME whose old dest is still stale on disk" >&2
echo "# (ansible/templates/noo-node-agent.env.j2 -> node-agent-go/deploy/…) —" >&2
echo "# decide by hand. Dedupe shas; list only versions that actually shipped." >&2
