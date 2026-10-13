#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# merge-when-green.sh — watch a PR's checks and rebase-merge when honestly green.
#
# Usage: scripts/merge-when-green.sh <pr-number> [max-minutes]
#
# Encodes three lessons, each learned by merging red:
#   1. absence of PENDING checks is not green — count FAILURES and
#      refuse on any.
#   2. flake handling: a failure verdict stops the merge; rerunning is a
#      human decision (`gh run rerun <id> --failed`) made on evidence, not
#      automatic.
#   3. #917: checks that haven't REGISTERED yet look exactly like a green
#      board — require the expected CI check names to be present before
#      green counts (the CI workflow can attach a minute after push).
# Plus: GitHub 503 storms — every gh mutation retries.
set -euo pipefail

PR="${1:?usage: merge-when-green.sh <pr-number> [max-minutes]}"
MAX_MIN="${2:-25}"
# Check names that must be PRESENT before a green verdict is trusted.
# Adjust here if the CI workflow renames jobs.
EXPECTED_RE="${MERGE_EXPECTED_CHECKS_RE:-test|sqlx|rust-gateway}"
EXPECTED_MIN="${MERGE_EXPECTED_CHECKS_MIN:-3}"

#   4. (same night, first use) after a push/force-push, `gh pr checks`
#      reports the PREVIOUS head's results for a short window — a stale
#      red board reads exactly like a real one. Settle first.
sleep "${MERGE_INITIAL_WAIT:-60}"

deadline=$(( $(date +%s) + MAX_MIN * 60 ))
while :; do
    out="$(gh pr checks "$PR" 2>/dev/null || true)"
    pend=$(printf '%s\n' "$out" | awk '$2=="pending"' | grep -c . || true)
    fail=$(printf '%s\n' "$out" | awk '$2=="fail"' | grep -c . || true)
    have=$(printf '%s\n' "$out" | grep -cE "$EXPECTED_RE" || true)
    if [ "$fail" -gt 0 ] && [ "$pend" -eq 0 ]; then
        echo "PR #$PR has FAILING checks — refusing to merge:" >&2
        printf '%s\n' "$out" | awk '$2=="fail"' >&2
        exit 1
    fi
    if [ "$have" -ge "$EXPECTED_MIN" ] && [ "$pend" -eq 0 ] && [ "$fail" -eq 0 ]; then
        echo "PR #$PR green ($have expected checks present)."
        break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "PR #$PR: timed out after ${MAX_MIN}m (pending=$pend expected-present=$have)" >&2
        exit 1
    fi
    sleep 30
done

for i in 1 2 3; do
    if gh pr merge "$PR" --rebase; then
        echo "PR #$PR merged."
        exit 0
    fi
    echo "merge attempt $i failed (GitHub blip or dev moved) — retrying in 45s" >&2
    sleep 45
done
echo "PR #$PR: merge failed after retries. If dev moved onto your files:" >&2
echo "  git fetch origin && git rebase origin/dev && git push -f && $0 $PR" >&2
exit 1
