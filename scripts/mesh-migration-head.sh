#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
#
# Print the newest mesh migration revision the gateway at this checkout knows
# (e.g. 094_audit_chain_append_only). images-release.yml writes it into the
# SIGNED stack lock as `# mesh-migration-head <rev>`, so `noo upgrade --stack`
# can refuse a rollback to a release whose gateway would not start on the
# current database stamp (rehearsal 0.6.7-rc.1 F2). A gateway unit test
# (mesh_migrate::tests::the_release_script_reads_the_real_chain_head) pins
# this script's answer to the real chain.
set -eu
src="${1:-gateway-rust/src/mesh_migrate.rs}"
# Everything before the first `#[cfg(test)]`: test fixtures name revisions
# that do not exist (999_from_the_future).
head="$(awk '/#\[cfg\(test\)\]/{exit} {print}' "$src" \
  | grep -o '"[0-9][0-9][0-9]_[a-z0-9_]*"' | tr -d '"' | sort -u | tail -1)"
[ -n "$head" ] || { echo "no migration revision found in $src" >&2; exit 1; }
printf '%s\n' "$head"
