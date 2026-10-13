#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Run cargo against gateway-rust in a container — there is no host Rust
# toolchain on the controller (the gateway builds in Docker).
#
# Use this instead of a hand-rolled `docker run … cargo` for one reason:
# WITHOUT --user, cargo writes gateway-rust/target/ as root. That is ~4400
# root-owned files inside the repo, and the first thing it breaks is
# `git worktree remove`, which fails with "Permission denied" and leaves the
# tree behind. There is no passwordless sudo here, so recovery needs another
# container just to delete them. Passing --user costs nothing and avoids the
# whole class of problem.
#
# Usage:
#   scripts/cargo-docker.sh check
#   scripts/cargo-docker.sh check --tests      # also compiles #[cfg(test)]
#   scripts/cargo-docker.sh clippy -- -D warnings
#   scripts/cargo-docker.sh fmt --check
#
# First run pulls deps (~10 min). Later runs are ~35s: the cargo registry is
# mounted from $HOME so it persists across invocations and worktrees.
#
# READING A CLEAN LINT. The target dir persists between runs, so a crate whose
# artifacts are already fresh is not re-linted and the run prints no
# diagnostics at all — indistinguishable from "linted and clean". To tell the
# two apart, force the crate to be re-examined (`touch` a source file in it)
# and look for its own `Checking <crate>` line in the output. A clean report
# with no such line says nothing about the code.
set -euo pipefail

# --- Shared build slots -------------------------------------------------------
# This box (host3) also serves the fleet's vLLM on 19 GB of RAM. On 2026-10-02
# three parallel builds from one session crashed vLLM; on 2026-10-03 five
# builds from four sessions starved it again. A per-session rule cannot bound
# what several sessions do together, so the bound lives here, in the one
# script every session builds through: at most NOO_BUILD_SLOTS builds at once
# across ALL sessions (flock on files every session shares), and none starts
# while MemAvailable is under NOO_BUILD_MIN_FREE_GB. A waiting build says so
# once and polls; the lock is held by this process's fd 9, which the exec'd
# `docker run` inherits, so it is released exactly when the build ends.
# CI runners (CI=true) and NOO_BUILD_SLOTS=0 skip it: they are not this box.
acquire_build_slot() {
    local slots="${NOO_BUILD_SLOTS:-2}" min_gb="${NOO_BUILD_MIN_FREE_GB:-6}"
    local dir="${NOO_BUILD_SLOT_DIR:-/tmp/noo-build-slots}" waited=0 avail i
    if [ -n "${CI:-}" ] || [ "$slots" = 0 ] || ! command -v flock >/dev/null 2>&1; then
        return 0
    fi
    mkdir -p "$dir" 2>/dev/null && chmod 1777 "$dir" 2>/dev/null || true
    while :; do
        avail="$(awk '/^MemAvailable:/ {print int($2 / 1048576)}' /proc/meminfo 2>/dev/null || echo 999)"
        if [ "${avail:-999}" -ge "$min_gb" ]; then
            for i in $(seq 1 "$slots"); do
                exec 9>>"$dir/slot.$i"
                if flock -n 9; then
                    [ "$waited" -gt 0 ] && echo "cargo-docker: build slot $i free after ${waited}s" >&2
                    return 0
                fi
                exec 9>&-
            done
        fi
        if [ "$waited" -eq 0 ]; then
            echo "cargo-docker: waiting for a build slot (${slots} shared by every session on this box; needs >= ${min_gb} GB available, now ${avail} GB)" >&2
        fi
        sleep "${NOO_BUILD_SLOT_POLL:-15}"
        waited=$((waited + ${NOO_BUILD_SLOT_POLL:-15}))
    done
}

# Resolve the repo root from the CALLER'S working directory, not from where
# this script file lives. The difference bites in worktrees: invoking the main
# clone's copy (`../../scripts/cargo-docker.sh`) from inside a worktree used to
# silently check/test the MAIN CLONE's source — a green result for code that
# was never compiled. That is the same trap the pytest `pythonpath` fix closed
# for Python (PR #642), in Rust form; it produced a confident wrong "0 tests
# matched" on 2026-08-13. `git rev-parse` follows $PWD, so whichever copy of
# the script you invoke, the tree you are STANDING IN is the one built.
# Fallback to script-relative resolution only outside any git tree.
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; })"
CRATE_DIR="${CARGO_DOCKER_CRATE:-$REPO_ROOT/gateway-rust}"
# Both paths as the filesystem knows them, not as the caller spelled them.
# `git rev-parse` returns the physical path, but callers pass
# CARGO_DOCKER_CRATE=$PWD/noo-cli, and $PWD keeps a symlink (the workspace
# a workspace reached through a symlink, for one). The crate then looks like it sits OUTSIDE
# the repo mount, build.rs cannot read its inputs, and the shared target
# volume caches an empty generated file (ADDON_DECLS) that later runs from
# the right path keep reusing — four add-on tests failed spuriously twice on
# 2026-10-03 until `touch noo-cli/build.rs`. Resolving here makes every
# spelling of the same tree the same build.
REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
if [ -d "$CRATE_DIR" ]; then
    CRATE_DIR="$(cd "$CRATE_DIR" && pwd -P)"
fi
IMAGE="${CARGO_DOCKER_IMAGE:-rust:1-bookworm}"
REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry"

if [ ! -d "$CRATE_DIR" ]; then
    echo "error: no crate at $CRATE_DIR (set CARGO_DOCKER_CRATE)" >&2
    exit 1
fi
mkdir -p "$REGISTRY"

if [ "$#" -eq 0 ]; then
    set -- check --message-format short
fi

# Components (clippy, rustfmt) are absent from the rust images, which ship the
# `minimal` profile. Installing one writes to /usr/local/rustup, owned by root,
# so it cannot be done as the invoking user — CARGO_DOCKER_COMPONENTS runs the
# container as root for that case and hands ownership back afterwards.
#
# The chown is not tidiness. On a persistent self-hosted runner, root-owned
# files under the workspace survive the job, and the NEXT run's
# actions/checkout cleans the tree as the runner user and fails with
# permission denied. Exactly the failure that made `git worktree remove`
# impossible on the controller.
COMPONENTS="${CARGO_DOCKER_COMPONENTS:-}"

# A subcommand that NEEDS a component derives it, rather than depending on the
# caller to know.
#
# Without this, `cargo-docker.sh clippy` — the invocation this script's own
# usage block advertises — took the plain branch below, which runs an image
# shipping the `minimal` profile and therefore has no clippy at all. What came
# back was not a lint that passed; it was no lint, reported as success. Three
# sessions read that as green in one day (2026-09-12), and CI caught what each
# of them had "verified" locally.
#
# The env var stays as the override for anything else (`miri`, a second
# component, a subcommand this case arm does not know about).
if [ -z "$COMPONENTS" ]; then
    case "${1:-}" in
        clippy) COMPONENTS="clippy" ;;
        fmt)    COMPONENTS="rustfmt" ;;
    esac
fi

# Mount the REPO, work in the CRATE.
#
# This used to be `-v $CRATE_DIR:/w -w /w`, and the narrow mount was never
# about isolation — it was about target-dir ownership, which is now handled
# by CARGO_TARGET_DIR and the volume below. What the narrow mount actually
# did was make every test that reads a file outside its own crate take its
# skip arm, silently. `noo-cli/src/commands/node_fetch.rs::
# neither_poller_has_an_unverified_lane` asserts that scripts/noo-fetch.sh
# and scripts/prep-host.sh carry no unverified-transport lane — a real
# cross-language contract that had NEVER executed in CI, while the green
# tick said it had. build.rs degraded to empty asset consts for the same
# reason (`noo-cli built OUTSIDE the repo tree`).
#
# So: mount the repo root, set the workdir to the crate inside it. `..`
# resolves, the crate path is unchanged from cargo's point of view, and
# nothing about ownership moves. A CARGO_DOCKER_CRATE outside the repo
# (nothing in-tree does this) keeps the old narrow mount.
case "$CRATE_DIR/" in
    "$REPO_ROOT"/*)
        CRATE_REL="${CRATE_DIR#"$REPO_ROOT"/}"
        MOUNT="-v $REPO_ROOT:/repo -w /repo/$CRATE_REL"
        ;;
    *)
        echo "cargo-docker: $CRATE_DIR is outside $REPO_ROOT — mounting the crate alone;" >&2
        echo "cargo-docker: tests that read repo files outside the crate will not find them." >&2
        MOUNT="-v $CRATE_DIR:/w -w /w"
        ;;
esac

# SQLX_OFFLINE only affects the `query!` macros, which read .sqlx/. The
# runtime sqlx::query()/query_as() API is unaffected either way.
#
# NOO_CARGO_DOCKER marks "you are running under this harness". A test that
# needs a repo file uses it to decide whether an unreadable file is a
# legitimate skip (bare `cargo test` from an unpacked crate) or a harness
# regression that must fail loudly.
COMMON="$MOUNT -v $REGISTRY:/usr/local/cargo/registry \
    -e SQLX_OFFLINE=${SQLX_OFFLINE:-true} -e CARGO_TERM_COLOR=always \
    -e NOO_CARGO_DOCKER=1"

# `exec` is load-bearing, not a micro-optimisation: this process BECOMES
# docker, so cargo's exit status is this script's exit status with nothing
# in between to swallow it. Anything added after these lines must preserve
# that — capture "$?" and re-exit with it, never let a cleanup be the last
# command. The guard is
# tests/test_cargo_docker_harness_reaches_the_repo.py::test_cargo_s_exit_status_is_the_script_s_exit_status
# — it asserts over EVERY docker run in this file, so it covers both branches.
# (It used to name `scripts/cargo-docker-exit-code.sh`, which never existed: a
# comment written to stop someone breaking the contract sent them looking for a
# file that is not there.)
if [ -z "$COMPONENTS" ]; then
    # shellcheck disable=SC2086
    acquire_build_slot
    exec docker run --rm --user "$(id -u):$(id -g)" $COMMON "$IMAGE" cargo "$@"
fi

# Opt-in: a component run that SHARES the crate's own target dir, as the
# invoking user — CARGO_DOCKER_SHARED_TARGET=1. CI sets it (ci.yml
# rust-gateway and noo-cli): on a GitHub-hosted runner the named volume below
# is created empty on every run, so clippy re-checked the whole dependency
# tree from cold (3.5 min of rust-gateway's ~9) while `cargo check` had just
# produced exactly those artifacts in target/, restored from the actions
# cache. clippy reuses a dependency's check metadata (only workspace members
# go through clippy-driver), so sharing the dir leaves it one crate to lint.
#
# It runs as --user, like the plain branch, so nothing in the checkout is
# ever written as root — the failure mode the volume exists to prevent. The
# official rust image leaves RUSTUP_HOME world-writable, so `rustup component
# add` works without root inside this throwaway container (verified with
# rust:1-bookworm, 2026-10-09). Interactive use keeps the volume (default).
QUOTED=""
for a in "$@"; do QUOTED="$QUOTED '$(printf %s "$a" | sed "s/'/'\\''/g")'"; done
if [ -n "${CARGO_DOCKER_SHARED_TARGET:-}" ]; then
    # shellcheck disable=SC2086
    acquire_build_slot
    exec docker run --rm --user "$(id -u):$(id -g)" $COMMON "$IMAGE" sh -euc "
    rustup component add $COMPONENTS >/dev/null
    cargo $QUOTED
"
fi

# Component runs write to a VOLUME, never into the checkout.
#
# The earlier design ran as root and chowned /w back afterwards. That is a
# cleanup, and cleanups do not run when a job is cancelled — GitHub cancels
# in-flight jobs on every re-run and on a new push to the same PR. A cancel
# mid-`cargo clippy` left root-owned files inside a PERSISTENT self-hosted
# workspace, and the next job there died in actions/checkout:
#
#   ##[error]File was unable to be removed
#     Error: EACCES: permission denied, rmdir '.../target/...'
#
# Redirecting CARGO_TARGET_DIR out of the bind mount removes the failure mode
# instead of tidying after it: root writes only to the volume, so /w is never
# touched as root and there is nothing to hand back. Reading the sources as
# root is harmless, and `--locked` keeps cargo from rewriting Cargo.lock.
#
# The volume is named per crate so noo-cli and gateway-rust do not share one
# target dir, and it persists between runs, which keeps clippy warm.
#
# Per-crate here means PER PATH — so every worktree mints its own volume,
# and removing the worktree used to leave a 2–7 GB orphan behind (13 of
# them held 14 GB on 2026-08-25). Self-cleanup: label each volume with its
# source path at creation, and sweep labeled volumes whose path no longer
# exists before each run. Volumes created before the labeling are invisible
# to the sweep (cleaned by hand once; cannot recur). A volume still in use
# simply fails the rm, which is the correct outcome.
VOLUME="cargo-docker-target-$(printf %s "$CRATE_DIR" | md5sum | cut -c1-12)"
docker volume ls -q --filter label=noo.cargo-docker-src 2>/dev/null | while read -r v; do
    src="$(docker volume inspect -f '{{index .Labels "noo.cargo-docker-src"}}' "$v" 2>/dev/null || true)"
    if [ -n "$src" ] && [ ! -d "$src" ]; then
        docker volume rm "$v" >/dev/null 2>&1 || true
    fi
done
docker volume create --label "noo.cargo-docker-src=$CRATE_DIR" "$VOLUME" >/dev/null 2>&1 || true

# `set --` args are re-quoted into the inner shell (QUOTED, built above) so
# a component run behaves identically to the plain path.
# shellcheck disable=SC2086
acquire_build_slot
exec docker run --rm $COMMON \
    -v "$VOLUME:/target" \
    -e CARGO_TARGET_DIR=/target \
    "$IMAGE" sh -euc "
    rustup component add $COMPONENTS >/dev/null
    cargo $QUOTED
"
