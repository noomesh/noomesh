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
#   NOO_TEST_CORE_VENV        where the venv lives (default under ~/.cache); a
#                             path you choose is yours: nothing else is touched
#   NOO_TEST_CORE_VENVS_KEEP  (developer-tool tuning, not a product switch) how many per-checkout venvs the default base keeps
#                             (default 4; ~1.7 GB each)
#
# One venv per checkout path (the install is editable, `pip install -e .`, so it
# points at that checkout and cannot be shared). Before each run, and only with
# the default base (NOO_TEST_CORE_VENV unset), a bounded cleanup runs over
# ${XDG_CACHE_HOME:-~/.cache}/noomesh/test-core-venv: it removes a venv whose
# recorded checkout ($venv/.root) no longer exists; a venv with no .root (made
# by an older script) once its .last-used, else its dir mtime, is over 14 days
# old; then the least recently used (by the .last-used marker, never the dir
# mtime; no marker = oldest) beyond NOO_TEST_CORE_VENVS_KEEP. Never the
# current venv, and never a venv some process has as its exe or cwd (Linux
# /proc; elsewhere the in-use check is unavailable and says so). Only direct, non-symlink children named 16 hex characters that
# hold bin/python or pyvenv.cfg are considered; each removal is printed, and a
# failed removal warns and goes on. `test-core-local.sh --gc-only` runs just
# that cleanup and exits (no uv, no install).
# tests/test_test_core_local.py fails if the steps change shape or gain an
# env key this script does not supply.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

# ---- venv cleanup (default base only) ---------------------------------------
gc_base="${XDG_CACHE_HOME:-$HOME/.cache}/noomesh/test-core-venv"
gc_current="$(printf '%s' "$root" | sha256sum | cut -c1-16)"
gc_stale_days=14

gc_mtime() { stat -c %Y -- "$1" 2>/dev/null || echo 0; }

gc_venvs() {
  [ -z "${NOO_TEST_CORE_VENV:-}" ] || return 0
  [ -d "$gc_base" ] && [ ! -L "$gc_base" ] || return 0
  local keep="${NOO_TEST_CORE_VENVS_KEEP:-4}"
  case "$keep" in ''|*[!0-9]*) echo "test-core-local: NOO_TEST_CORE_VENVS_KEEP='$keep' is not a number; using 4" >&2; keep=4 ;; esac
  local now d name rootfile r stamp ts age_ts reason total_kb=0 removed=0
  now=$(date +%s)
  local -a rest=()
  for d in "$gc_base"/*; do
    name=${d##*/}
    [ -L "$d" ] && continue
    [ -d "$d" ] || continue
    [[ "$name" =~ ^[0-9a-f]{16}$ ]] || continue
    [ -f "$d/bin/python" ] || [ -L "$d/bin/python" ] || [ -f "$d/pyvenv.cfg" ] || continue
    [ "$name" = "$gc_current" ] && continue
    # Recency is the .last-used marker only; no marker (old script) = oldest.
    # The 14-day rule for unrooted venvs falls back to the dir mtime.
    if [ -f "$d/.last-used" ]; then ts=$(gc_mtime "$d/.last-used"); age_ts=$ts; else ts=0; age_ts=$(gc_mtime "$d"); fi
    reason=""
    rootfile="$d/.root"
    r=""
    [ -f "$rootfile" ] && r=$(head -n 1 -- "$rootfile" 2>/dev/null || true)
    if [ -n "$r" ]; then
      [ -e "$r" ] || reason="its checkout $r is gone"
    elif [ $(( now - age_ts )) -gt $(( gc_stale_days * 86400 )) ]; then
      reason="no .root and unused for over $gc_stale_days days"
    fi
    if [ -n "$reason" ]; then
      gc_remove "$d" "$name" "$reason" || true
    else
      rest+=("$ts $name")
    fi
  done
  # The current venv counts toward the cap; drop the least recently used extras.
  local cur=0 line
  [ -d "$gc_base/$gc_current" ] && cur=1
  local over=$(( ${#rest[@]} + cur - keep ))
  if [ "$over" -gt 0 ]; then
    while IFS= read -r line; do
      [ "$over" -gt 0 ] || break
      if gc_remove "$gc_base/${line#* }" "${line#* }" "over the cap of $keep, least recently used"; then
        over=$(( over - 1 ))
      fi
    done < <(printf '%s\n' "${rest[@]}" | sort -n)
  fi
  if [ "$gc_removed" -gt 0 ]; then
    echo "test-core-local: removed $gc_removed venv(s), $(( gc_total_kb / 1024 )) MB freed"
  fi
}

gc_removed=0
gc_total_kb=0
gc_proc_warned=0
# Prints the pid of a process whose exe or cwd is under the venv, if any.
# Linux /proc only; elsewhere says so once and reports nothing.
gc_in_use() { # dir
  if [ ! -d /proc/self ]; then
    if [ "$gc_proc_warned" = 0 ]; then echo "test-core-local: in-use check unavailable (no /proc)" >&2; gc_proc_warned=1; fi
    return 1
  fi
  local d="$1" real p pid l
  real=$(realpath -- "$d" 2>/dev/null || echo "$d")
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    for l in exe cwd; do
      t=$(readlink -- "$p/$l" 2>/dev/null) || continue
      case "$t" in "$d"/*|"$d"|"$real"/*|"$real") echo "$pid"; return 0 ;; esac
    done
  done
  return 1
}

gc_remove() { # dir name reason
  local d="$1" name="$2" reason="$3" kb pid t
  [ ! -L "$d" ] && [ "$(dirname -- "$d")" = "$gc_base" ] || return 1
  if pid=$(gc_in_use "$d"); then
    echo "test-core-local: kept venv $name (in use by pid $pid)"
    return 1
  fi
  kb=$(du -sk -- "$d" 2>/dev/null | cut -f1)
  kb=${kb:-0}
  if rm -rf -- "$d" 2>/dev/null && [ ! -e "$d" ]; then
    echo "test-core-local: removed venv $name ($reason, $(( kb / 1024 )) MB)"
    gc_removed=$(( gc_removed + 1 ))
    gc_total_kb=$(( gc_total_kb + kb ))
  else
    echo "test-core-local: could not remove venv $name; leaving it" >&2
    return 1
  fi
}

if [ "${1:-}" = "--gc-only" ]; then
  gc_venvs
  exit 0
fi

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

venv="${NOO_TEST_CORE_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/noomesh/test-core-venv/$(printf '%s' "$root" | sha256sum | cut -c1-16)}"
case "$venv" in "$root"|"$root"/*) echo "test-core-local: the venv must live outside the checkout ($venv)" >&2; exit 1 ;; esac
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

# Record whose venv this is and that it was used now, then prune the others.
{ printf '%s\n' "$root" > "$venv/.root" && touch "$venv/.last-used"; } 2>/dev/null \
  || echo "test-core-local: could not record $venv/.root" >&2
gc_venvs || echo "test-core-local: venv cleanup failed; continuing" >&2

export VIRTUAL_ENV="$venv" PATH="$venv/bin:$PATH"
if [ "$#" -gt 0 ]; then
  exec pytest "$@"
fi
exec bash -e -c "$run_body"
