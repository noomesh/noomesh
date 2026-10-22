#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Run a registry-facing command (docker pull, docker buildx build --push,
# imagetools create) and retry it when, and only when, it failed with a
# TRANSIENT registry error.
#
#   scripts/retry-registry.sh docker buildx build --push ...
#
# The 0.6.10 release candidates lost two whole runs to errors a re-run cleared
# with no change: `docker pull moby/buildkit` answering "unauthorized:
# authentication required" (Docker Hub's token service, for a public image)
# and `ERROR: failed to build: unknown blob` (a registry losing a blob between
# the layer upload and the manifest push). Each cost a release a 20-40 minute
# lane re-run.
#
# A REAL build failure is never retried: output that says a build step did not
# complete (`did not complete successfully`, a RUN that exited non-zero) or
# that names no transient class fails at once with the command's own exit code.
# Retries are bounded: RETRY_ATTEMPTS (default 3) attempts in all, waiting
# RETRY_DELAY seconds (default 20) times the attempt number between them.
# Pushing again after a partial push is safe: blobs and manifests are
# content-addressed, so a retry re-sends what is missing and nothing else.
set -uo pipefail

[ $# -gt 0 ] || { echo "usage: $0 <command> [args...]" >&2; exit 2; }
attempts="${RETRY_ATTEMPTS:-3}"
delay="${RETRY_DELAY:-20}"
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || attempts=3
[[ "$delay" =~ ^[0-9]+$ ]] || delay=20

# The transient classes. Each one is a registry or transport answer, never a
# property of the thing being built.
TRANSIENT='unknown blob|blob unknown|unauthorized: authentication required|toomanyrequests|429 Too Many Requests|50[234] (Bad Gateway|Service Unavailable|Gateway Time-?out)|TLS handshake timeout|connection reset by peer|i/o timeout|unexpected EOF'
# A build step that failed: the build is wrong, a retry would only repeat it.
REAL='did not complete successfully'

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
i=1
while :; do
    "$@" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] && exit 0
    if grep -q -- "$REAL" "$log"; then
        echo "retry-registry: a build step failed (exit $rc): not a registry error, not retried" >&2
        exit "$rc"
    fi
    hit="$(grep -m1 -E -- "$TRANSIENT" "$log" | cut -c1-200)"
    if [ -z "$hit" ]; then
        echo "retry-registry: exit $rc with no transient registry error in the output: not retried" >&2
        exit "$rc"
    fi
    if [ "$i" -ge "$attempts" ]; then
        echo "::error::transient registry error persisted after $attempts attempt(s): $hit"
        exit "$rc"
    fi
    echo "::warning::transient registry error (attempt $i/$attempts): $hit; retrying in $((delay * i))s"
    sleep "$((delay * i))"
    i=$((i + 1))
done
