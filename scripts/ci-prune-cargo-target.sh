#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Shrink a crate's cargo target/ before CI saves it as a cache.
#
#   scripts/ci-prune-cargo-target.sh <crate-dir> [max-gb]
#
# Why: the noo-cli job on a GitHub-hosted runner filled the disk while
# actions/cache/save tarred ~/.cargo + noo-cli/target ("zstd: No space left on device"; the restored entry alone was
# 2.7 GB compressed). Everything the tests had already proved went red on a
# cache write. What a cache is FOR is the dependency artifacts; this drops the
# rest:
#
#   - target/<profile>/incremental   — only ever reused by the same crate
#                                      source, which the next run changes
#   - target/<profile>/examples
#   - the crate's OWN artifacts in deps/, .fingerprint/ and build/ (lib, bin,
#     unit-test and integration-test binaries): rebuilt every run anyway,
#     since the cache key ends in a source hash
#   - top-level files in target/<profile>/ (the final binaries + .d files)
#
# Dependency build-script outputs (target/<profile>/build/<dep>-*) are KEPT:
# they are what a warm build reuses (ring, openssl-sys, ...).
#
# A restore-keys fallback restores an OLDER target and the build adds to it,
# so the entry can only grow. Past max-gb (default 4) the target is dropped
# whole and only ~/.cargo is cached: the next dev push rebuilds and saves a
# clean one. Never fails: a prune problem must not fail a job whose checks
# passed (the save step is continue-on-error for the same reason).
set -uo pipefail

crate="${1:?usage: ci-prune-cargo-target.sh <crate-dir> [max-gb]}"
max_gb="${2:-4}"
target="$crate/target"

[ -d "$target" ] || { echo "ci-prune-cargo-target: no $target — nothing to prune"; exit 0; }

size() { du -sh "$1" 2>/dev/null | cut -f1; }
echo "ci-prune-cargo-target: $target before: $(size "$target")"

# The crate's own artifact names: [package] name, [[bin]] names, and every
# integration test / bench / example file stem. Cargo writes them dashed in
# .fingerprint/ and build/, underscored in deps/.
names="$(
  {
    awk '
      /^\[/ { sect = $0 }
      (sect == "[package]" || sect == "[[bin]]" || sect == "[lib]") && /^name *=/ {
        gsub(/^name *= *"|".*$/, ""); print
      }' "$crate/Cargo.toml"
    for d in tests benches examples; do
      [ -d "$crate/$d" ] && find "$crate/$d" -maxdepth 1 -name '*.rs' -printf '%f\n' | sed 's/\.rs$//'
    done
  } | sort -u
)"

for prof in "$target"/*/; do
  prof="${prof%/}"
  [ -d "$prof/deps" ] || [ -d "$prof/.fingerprint" ] || continue
  rm -rf "$prof/incremental" "$prof/examples"
  # Top-level files only (the binaries and their .d files), not the dirs.
  find "$prof" -maxdepth 1 -type f -delete 2>/dev/null
  for n in $names; do
    u="${n//-/_}"
    rm -rf "$prof/deps/$u"-* "$prof/deps/lib$u"-* \
           "$prof/.fingerprint/$n"-* "$prof/.fingerprint/$u"-* \
           "$prof/build/$n"-* "$prof/build/$u"-*
  done
done

kb="$(du -sk "$target" 2>/dev/null | cut -f1)"
if [ "${kb:-0}" -gt $((max_gb * 1024 * 1024)) ]; then
  echo "::warning::ci-prune-cargo-target: $target is still $(size "$target") after pruning (cap ${max_gb} GB) — dropping it; only ~/.cargo is cached this time and the next dev push saves a fresh target"
  rm -rf "$target"
else
  echo "ci-prune-cargo-target: $target after: $(size "$target")"
fi
# registry/src is the unpacked copy of registry/cache's .crate files; cargo
# re-extracts it in seconds, so caching both stores every dependency twice.
rm -rf "${CARGO_HOME:-$HOME/.cargo}/registry/src"
for d in "${CARGO_HOME:-$HOME/.cargo}/registry" "${CARGO_HOME:-$HOME/.cargo}/git"; do
  [ -d "$d" ] && echo "ci-prune-cargo-target: $d: $(size "$d")"
done
df -h . 2>/dev/null | tail -1 | awk '{print "ci-prune-cargo-target: disk free: " $4}'
exit 0
