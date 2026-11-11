#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Upload release assets ONE AT A TIME, retrying each on a transient error.
#
#   scripts/release-upload-assets.sh <owner/repo> <tag> <file>...
#
# The CLI release used to hand all 29 files to one `gh release create`, with
# no retry: on noo-cli-v0.6.22-rc.1 one upload answered
# `HTTP 408: Upload body timed out due to inactivity` (run 42862153616) and
# the whole job had to be re-run, 12 minutes later. Here each asset is its
# own `gh release upload --clobber`; a transient failure (408, 429, a 5xx,
# a timeout or a reset connection) is retried, at most RETRY_ATTEMPTS
# (default 3) attempts, RETRY_DELAY (default 20) seconds times the attempt
# number apart. Anything else (a missing file, 401/403/404/422) fails at
# once with gh's own message. --clobber makes a retry, or a re-run of the
# job, replace a half-uploaded asset rather than fail on it.
set -uo pipefail

[ $# -ge 3 ] || { echo "usage: $0 <owner/repo> <tag> <file>..." >&2; exit 2; }
repo=$1 tag=$2
shift 2
attempts="${RETRY_ATTEMPTS:-3}"
delay="${RETRY_DELAY:-20}"
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || attempts=3
[[ "$delay" =~ ^[0-9]+$ ]] || delay=20

transient() {
  grep -qiE 'HTTP (408|429|5[0-9][0-9])|timed out|timeout|connection reset|EOF|i/o timeout|TLS handshake' <<<"$1"
}

for f in "$@"; do
  [ -f "$f" ] || { echo "release-upload-assets: $f does not exist" >&2; exit 1; }
  n=1
  while :; do
    out=$(gh release upload "$tag" --repo "$repo" --clobber "$f" 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "uploaded $(basename "$f")"
      break
    fi
    if [ "$n" -ge "$attempts" ] || ! transient "$out"; then
      echo "release-upload-assets: $(basename "$f") failed (attempt $n of $attempts): $out" >&2
      exit "$rc"
    fi
    echo "release-upload-assets: $(basename "$f"): transient failure (attempt $n of $attempts), retrying in $((delay * n))s: $out" >&2
    sleep $((delay * n))
    n=$((n + 1))
  done
done
