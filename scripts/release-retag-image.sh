#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Re-tag one release-candidate image as the final — no rebuild.
#
#   scripts/release-retag-image.sh <image> <rc image tag> <final image tag> [expected digest]
#   e.g.  release-retag-image.sh whisper v0.2.99-rc.1 v0.2.99 sha256:2ec4…
#
# Env: REGISTRY, OWNER (as images-release.yml sets them), PUSH_LATEST=1 to
# also move :latest (a final always does). IMAGE_OWNER is the registry path the
# image is published under, if not $OWNER: the DHI-derived bases (deps-core,
# deps-base) live under $DHI_OWNER (ghcr.io/noomesh/dhi/<img>). The workflow
# passes it from the same variable its build step pushes to; re-tagging under
# the wrong one is "not found" (stack-v0.6.0).
#
# images-release.yml calls this for every image scripts/release-retag-plan.py
# cleared (the rc's tree and sibling trees equal the final's). Three checks,
# each a hard failure — a release that cannot prove what it publishes must
# stop, not fall back to something it did not plan:
#   1. the rc TAG still resolves to the digest the rc's signed lock recorded
#      (a lock and a registry that disagree mean one of them moved);
#   2. `imagetools create` from that digest;
#   3. the final tag now resolves to the SAME digest. A single-platform
#      manifest would be wrapped in a new index (new digest) — every image this
#      workflow pushes is an index (buildx provenance), and this check is what
#      keeps that an observed fact rather than an assumption.
set -euo pipefail

img="${1:?image}" rc="${2:?rc image tag}" tag="${3:?final image tag}" want="${4:-}"
: "${REGISTRY:?}" "${OWNER:?}"
ref="$REGISTRY/${IMAGE_OWNER:-$OWNER}/$img"

digest_of() {
    docker buildx imagetools inspect "$1" --format '{{json .Manifest.Digest}}' | tr -d '"'
}

got="$(digest_of "$ref:$rc")"
[ -n "$got" ] || { echo "::error::$ref:$rc does not resolve — cannot re-tag from it"; exit 1; }
if [ -n "$want" ] && [ "$got" != "$want" ]; then
    echo "::error::$ref:$rc is $got but the rc lock says $want — the rc tag or its lock moved; refusing to re-tag"
    exit 1
fi

set -x
docker buildx imagetools create \
    --tag "$ref:$tag" \
    ${PUSH_LATEST:+--tag "$ref:latest"} \
    "$ref@$got"
set +x

now="$(digest_of "$ref:$tag")"
if [ "$now" != "$got" ]; then
    echo "::error::$ref:$tag resolves to $now after re-tagging $got — the digest changed (a single-manifest source is re-wrapped); build this image instead"
    exit 1
fi
echo "re-tagged $ref@$got as :$tag${PUSH_LATEST:+ and :latest} (from :$rc)"
