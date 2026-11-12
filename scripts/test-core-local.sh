#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Run CI's test-core Python suite locally, as CI runs it.
#
#   scripts/test-core-local.sh                 # the whole suite, CI's own pytest line
#   scripts/test-core-local.sh tests/test_x.py # just these, same venv and env
#
# Nothing here lists a package or a test to skip. Everything is read from
# .github/workflows/ci.yml at run time (scripts/ci_step.py) and run verbatim:
#   - the TRELLION_PUBLIC switch (workflow-level env), fed through test-core's
#     own `Is trellion declared public?` probe step, as CI does;
#   - the `Install dependencies` step, on the interpreter .python-version names,
#     in a uv venv kept OUTSIDE the checkout (a venv in the tree would be read by
#     the tree-scanning tests); it is rebuilt only when the install step,
#     pyproject.toml, the Dockerfile it reads, the switch or trellion's main moves;
#   - the `Run tests` step (CI's deselect/ignore lists and pytest line).
# ci_step.py refuses any step that could need or print a credential (`${{ }}`,
# sudo, GITHUB_TOKEN, docker login).
#
# Local stand-ins for the step env CI fills in:
#   TRELLION_PUBLIC           the probe step's output, as in CI
#   PAI_TRELLION_CHECKOUT     a path with no sibling checkout, as in CI
#   NOO_KB_AUDIENCE_TEST_DSN  passed through if you set it (a local pgvector);
#                             unset, those tests skip
#   NOO_TEST_CORE_VENV        where the venv lives (default under ~/.cache)
#   NOO_BATCH_MIN_DISK_GB     refuse to start below this much free disk (15) on
#                             the venv's volume: the same knob noo-batch reads
#                             (noomesh-internal ops/batch/lib-disk.sh)
#   NOO_TEST_CORE_VENV_KEEP   how many venvs the default cache keeps (6): each
#                             run prunes the least recently used others
#                             (scripts/test-core-venv-prune.sh), never one in use
# tests/test_test_core_local.py fails if the steps change shape or gain an
# env key this script does not supply.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
command -v uv >/dev/null || { echo "test-core-local: needs uv (https://docs.astral.sh/uv/)" >&2; exit 1; }
py=$(tr -d '[:space:]' < .python-version)
[ -n "$py" ] || { echo "test-core-local: .python-version is empty" >&2; exit 1; }

JOB="test-core"
PROBE_STEP="Is trellion declared public? (TRELLION_PUBLIC)"
INSTALL_STEP="Install dependencies"
RUN_STEP="Run tests"
SWITCH="TRELLION_PUBLIC"
# Every env key of the steps above must be supplied below.
HANDLED_ENV=(TRELLION_PUBLIC PAI_TRELLION_CHECKOUT NOO_KB_AUDIENCE_TEST_DSN)

ci_step() { uv run -q --no-project --python "$py" --with pyyaml python scripts/ci_step.py "$@"; }

switch=$(ci_step --workflow-env "$SWITCH")
probe_body=$(ci_step "$JOB" "$PROBE_STEP")
install_body=$(ci_step "$JOB" "$INSTALL_STEP")
run_body=$(ci_step "$JOB" "$RUN_STEP")
for step in "$PROBE_STEP" "$INSTALL_STEP" "$RUN_STEP"; do
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    [[ " ${HANDLED_ENV[*]} " == *" $key "* ]] || {
      echo "test-core-local: ci.yml $JOB / '$step' sets env $key, which this script does not supply; add it to HANDLED_ENV" >&2
      exit 1
    }
  done < <(ci_step --env "$JOB" "$step")
done

# The probe step, verbatim: it reads the switch and writes public=true|false.
probe_out=$(mktemp)
TRELLION_PUBLIC="$switch" GITHUB_OUTPUT="$probe_out" bash -e -c "$probe_body" || { rm -f "$probe_out"; exit 1; }
public=$(sed -n 's/^public=//p' "$probe_out")
rm -f "$probe_out"
case "$public" in true|false) ;; *) echo "test-core-local: the probe step wrote no public=true|false" >&2; exit 1 ;; esac

export TRELLION_PUBLIC="$public"
export PAI_TRELLION_CHECKOUT="$root/_no_sibling_checkout"
if [ -n "${NOO_KB_AUDIENCE_TEST_DSN:-}" ]; then export NOO_KB_AUDIENCE_TEST_DSN; fi

# CI installs trellion from git @main on every run: a moved main rebuilds here.
trellion_main=""
if [ "$public" = "true" ]; then
  trellion_main=$(GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/personifAI/trellion refs/heads/main | cut -f1)
fi

cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/noomesh/test-core-venv"
venv="${NOO_TEST_CORE_VENV:-$cache_dir/$(printf '%s' "$root" | sha256sum | cut -c1-16)}"
case "$venv" in "$root"|"$root"/*) echo "test-core-local: the venv must live outside the checkout ($venv)" >&2; exit 1 ;; esac
# Refuse to start on a nearly full disk (2026-11-10: the venv cache filled
# awolf's root volume to 0 MB free). Measured at the nearest existing
# directory of the venv's path, with noo-batch's knob and default.
min_gb="${NOO_BATCH_MIN_DISK_GB:-15}"
[[ "$min_gb" =~ ^[0-9]+$ ]] || { echo "test-core-local: NOO_BATCH_MIN_DISK_GB=$min_gb is not a whole number of GB" >&2; exit 1; }
probe="$venv"; while [ ! -d "$probe" ] && [ "$probe" != "/" ]; do probe=$(dirname "$probe"); done
free_kb=$(df -Pk "$probe" 2>/dev/null | awk 'NR==2 {print $4}')
[[ "$free_kb" =~ ^[0-9]+$ ]] || { echo "test-core-local: cannot read the free space on the volume holding $probe" >&2; exit 1; }
if [ "$free_kb" -lt $((min_gb * 1024 * 1024)) ]; then
  echo "test-core-local: only $((free_kb / 1024 / 1024)) GB free on the volume holding $probe; at least $min_gb GB is needed (NOO_BATCH_MIN_DISK_GB)" >&2
  exit 1
fi
# This run's venv is in use (by this pid, which `exec` keeps for pytest) and
# just used; then the default cache is pruned to the most recently used few
# (one venv per checkout path, ~2 GB each: 192 GB on 2026-11-10).
mkdir -p "$venv/.in-use"
: > "$venv/.in-use/$$"
touch "$venv/.last-used"
if [ -z "${NOO_TEST_CORE_VENV:-}" ]; then
  "$root/scripts/test-core-venv-prune.sh" "$cache_dir" "${NOO_TEST_CORE_VENV_KEEP:-6}" "$venv" || true
fi
stamp=$( { printf '%s\n' "$py" "$public" "$trellion_main" "$install_body"; cat pyproject.toml docker/Dockerfile.whisper; } | sha256sum | cut -d' ' -f1)
if [ ! -x "$venv/bin/python" ] || [ "$(cat "$venv/.ci-install-stamp" 2>/dev/null)" != "$stamp" ]; then
  echo "test-core-local: installing CI's test-core set (trellion public: $public) on python $py into $venv"
  mkdir -p "$(dirname "$venv")"
  uv venv -q --seed --allow-existing --python "$py" "$venv"
  rm -f "$venv/.ci-install-stamp"
  (
    export VIRTUAL_ENV="$venv" PATH="$venv/bin:$PATH"
    bash -e -c "$install_body"
  )
  echo "$stamp" > "$venv/.ci-install-stamp"
fi

export VIRTUAL_ENV="$venv" PATH="$venv/bin:$PATH"
if [ "$#" -gt 0 ]; then
  exec pytest "$@"
fi
exec bash -e -c "$run_body"
