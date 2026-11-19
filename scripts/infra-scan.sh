#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The infra images' vulnerability scan and gate: ONE copy, run by both
# workflows that can ship an infra image (scripts/infra-staged.py DAILY).
#
#   infra-staged.yml   the daily build; :staged moves only past the gate.
#   images-release.yml an infra image the release BUILT itself (no usable
#                      :staged copy) is scanned and gated here, exactly as
#                      strictly as a staged one, before its digest reaches
#                      the signed lock. A re-tagged image is not scanned
#                      again: it already passed this gate (or the rc's).
#
#   infra-scan.sh install-trivy
#       the pinned, sha256-verified Trivy (the version ci.yml's security-scan
#       pins; tests/test_infra_scan.py keeps the two equal) into
#       $RUNNER_TEMP/trivy-bin, added to $GITHUB_PATH.
#   infra-scan.sh scan REF DIGEST PLATFORMS
#       every platform (comma-separated) of REF@DIGEST into scan/new/, and the
#       current REF:staged on the platforms it HAS into scan/old/, against ONE
#       vulnerability database (downloaded once, then --skip-db-update).
#       Fixable HIGH/CRITICAL only. The :staged digest (empty: none) goes to
#       scan/old-digest and, in Actions, OLD_DIGEST in $GITHUB_ENV.
#   infra-scan.sh gate
#       scripts/infra-staged.py new-findings over those reports: exit 1 on a
#       fixable HIGH/CRITICAL (id, package) the current :staged lacks.
#       Inherited and RIDING findings are reported, not gated. No :staged at
#       all: no --old, reported, not gated. Output also in scan/gate.txt and
#       the step summary.
#   infra-scan.sh verdict IMAGE
#       after a passing gate, the release's line for an image it built.
#   infra-scan.sh retag-line IMAGE SOURCE [STAGED_AT]
#       the release's line for an image it re-tagged (SOURCE is the plan's
#       source tag: `@sha256:…` for :staged, else the rc's image tag).
#
# Read-only on the registry: nothing here pushes or moves a tag.
set -euo pipefail

TRIVY_VERSION="0.70.0"
TRIVY_SHA256="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"; }

install_trivy() {
  local dir="$RUNNER_TEMP/trivy-bin"
  mkdir -p "$dir"
  curl -fsSL --retry 3 -o "$dir/trivy.tgz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
  echo "${TRIVY_SHA256}  $dir/trivy.tgz" | sha256sum -c -
  tar -xzf "$dir/trivy.tgz" -C "$dir" trivy
  rm -f "$dir/trivy.tgz"
  [ -z "${GITHUB_PATH:-}" ] || echo "$dir" >> "$GITHUB_PATH"
  "$dir/trivy" --version
}

scan() {
  local ref="${1:?REF}" digest="${2:?DIGEST}" platforms="${3:?PLATFORMS}" old old_platforms p n
  mkdir -p scan/new scan/old
  trivy image --download-db-only
  old="$(docker buildx imagetools inspect "$ref:staged" --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"' || true)"
  printf '%s\n' "$old" > scan/old-digest
  [ -z "${GITHUB_ENV:-}" ] || echo "OLD_DIGEST=$old" >> "$GITHUB_ENV"
  # The platforms the current staged copy HAS. A platform the new build
  # adds (the whisper/piper staged copies were amd64-only, 2026-11-11) has no
  # old copy to scan: Trivy failed the whole job on it, so the staged
  # copy never moved. Now it is simply not scanned on the old side, and the
  # gate counts every finding on it as new.
  old_platforms=""
  if [ -n "$old" ]; then
    old_platforms="$(docker buildx imagetools inspect --raw "$ref@$old" | python3 "$HERE/infra-staged.py" platforms)"
    echo "current staged copy platforms: ${old_platforms:-none}"
  fi
  for p in $(echo "$platforms" | tr ',' ' '); do
    n="$(echo "$p" | tr '/' '-')"
    trivy image --skip-db-update --image-src remote --platform "$p" \
      --severity HIGH,CRITICAL --ignore-unfixed --format json \
      -o "scan/new/$n.json" "$ref@$digest"
    if [ -n "$old" ] && case " $old_platforms " in *" $p "*) true ;; *) false ;; esac; then
      trivy image --skip-db-update --image-src remote --platform "$p" \
        --severity HIGH,CRITICAL --ignore-unfixed --format json \
        -o "scan/old/$n.json" "$ref@$old"
    fi
  done
}

gate() {
  local old
  old="$(cat scan/old-digest)"
  : > scan/gate.txt
  # pipefail (set above): without it `| tee` would turn the gate's exit 1 into 0.
  if [ -n "$old" ]; then
    # Only the platforms the current staged copy has (maybe none of the
    # new ones): a missing one is gated in full, never skipped.
    shopt -s nullglob
    local olds=(scan/old/*.json)
    python3 "$HERE/infra-staged.py" new-findings --new scan/new/*.json --old "${olds[@]}" \
      | tee -a scan/gate.txt "${GITHUB_STEP_SUMMARY:-/dev/null}"
  else
    python3 "$HERE/infra-staged.py" new-findings --new scan/new/*.json \
      | tee -a scan/gate.txt "${GITHUB_STEP_SUMMARY:-/dev/null}"
  fi
}

verdict() {
  local image="${1:?IMAGE}" old n line
  old="$(cat scan/old-digest)"
  n="$(sed -n 's|^fixable HIGH/CRITICAL in the new build: \([0-9][0-9]*\).*|\1|p' scan/gate.txt)"
  if [ -z "$n" ] || grep -q '^  NEW ' scan/gate.txt; then
    echo "::error::$image: no passing gate result in scan/gate.txt; not reporting it as scanned"; exit 1
  fi
  if [ -n "$old" ]; then
    line="built here; scanned: $n fixable HIGH/CRITICAL, 0 new vs :staged $old"
    echo "$image: $line"
  else
    line="built here; first build (no :staged), scanned, not gated: $n fixable HIGH/CRITICAL"
    echo "::warning::$image: $line"
  fi
  summary "- **$image**: $line"
}

retag_line() {
  local image="${1:?IMAGE}" source="${2:?SOURCE}" at="${3:-}" line
  case "$source" in
    @sha256:*)
      [ -n "$at" ] || { echo "::error::$image: re-tagged from :staged but the plan gave no build time"; exit 1; }
      line="re-tagged from :staged ${source#@} (built $at, passed infra-staged's gate)" ;;
    *)
      line="re-tagged from the rc image :$source (its own release run scanned or re-tagged it)" ;;
  esac
  echo "$image: $line"
  summary "- **$image**: $line"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  install-trivy) install_trivy ;;
  scan) scan "$@" ;;
  gate) gate ;;
  verdict) verdict "$@" ;;
  retag-line) retag_line "$@" ;;
  *) echo "usage: infra-scan.sh install-trivy | scan REF DIGEST PLATFORMS | gate | verdict IMAGE | retag-line IMAGE SOURCE [STAGED_AT]" >&2; exit 2 ;;
esac
