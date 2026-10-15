#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Regenerate gateway-rust/.sqlx — the offline cache that lets `sqlx::query!`
# type-check without a database at build time.
#
#   scripts/sqlx-prepare.sh            regenerate and rewrite the cache
#   scripts/sqlx-prepare.sh --check    verify the cache still matches the live
#                                      schema; changes nothing, exits non-zero
#                                      on drift (also: scripts/sqlx-check.sh)
#
# Run the regenerate form after adding or changing ANY `sqlx::query!` statement,
# and after any migration that alters a column those queries touch. Commit the
# result.
#
# The two forms catch different failures, and both are needed:
#   source -> cache   `cargo check` with SQLX_OFFLINE, in CI on every PR. Fails
#                     when a query! has no cached entry.
#   cache  -> schema  THIS script with --check. Fails when a migration moved
#                     the schema out from under a cache that is still
#                     internally consistent — `cargo check` cannot see that.
#
# There is no cargo on the host by design, so this runs the toolchain in a
# container attached to the same network as Postgres. The DATABASE_URL is read
# from the running gateway rather than from `.env`: `secrets/env.sops` is the
# authoritative env and `.env` regularly disagrees with what is deployed.
set -euo pipefail

MODE=prepare
if [[ "${1:-}" == "--check" ]]; then MODE=check; fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="${NOO_DB_NETWORK:-pai-assistant_noo-db}"
CLI_IMAGE="${NOO_SQLX_IMAGE:-noo-sqlx-cli:0.9}"
SQLX_VERSION="${NOO_SQLX_VERSION:-^0.9}"

if ! docker image inspect "$CLI_IMAGE" >/dev/null 2>&1; then
  echo "==> building $CLI_IMAGE (one-off, a few minutes)"
  # NOTE: installed on the DEFAULT bridge, not $NETWORK. The compose DB network
  # has no outbound DNS, so `cargo install` there fails to resolve
  # index.crates.io. The prepare step below does need $NETWORK, but by then
  # nothing is downloaded.
  docker rm -f noo-sqlx-cli-build >/dev/null 2>&1 || true
  # pkg-config + libssl-dev mirror docker/Dockerfile.gateway-rust's builder
  # stage. Without them openssl-sys fails to configure and the prepare run dies
  # partway through the crate rather than at startup.
  docker run --name noo-sqlx-cli-build dhi.io/rust:1-debian13-dev sh -c "
    apt-get update -qq &&
    apt-get install -y -qq --no-install-recommends pkg-config libssl-dev &&
    cargo install sqlx-cli --version '$SQLX_VERSION' \
      --no-default-features --features postgres,rustls --root /out"
  docker commit noo-sqlx-cli-build "$CLI_IMAGE" >/dev/null
  docker rm -f noo-sqlx-cli-build >/dev/null
fi

DB_URL="${DATABASE_URL:-$(docker exec noo-gateway printenv DATABASE_URL)}"
if [[ -z "$DB_URL" ]]; then
  echo "could not resolve DATABASE_URL (is noo-gateway running?)" >&2
  exit 1
fi

[[ "$MODE" == check ]] && echo "==> cargo sqlx prepare --check (read-only)" \
                       || echo "==> cargo sqlx prepare"
# Two networks are needed and `docker run` only accepts one: $NETWORK to reach
# Postgres, and the default bridge for the crates.io index (the compose DB
# network has no outbound DNS — cargo fails with "Could not resolve host:
# index.crates.io" there). So: start detached, attach the second network, exec.
docker rm -f noo-sqlx-prepare >/dev/null 2>&1 || true
docker run -d --name noo-sqlx-prepare \
  --network "$NETWORK" \
  -e DATABASE_URL="$DB_URL" \
  -v "$REPO_ROOT/gateway-rust":/w -w /w \
  -v noo-sqlx-cargo:/usr/local/cargo/registry \
  -v noo-sqlx-target:/w/target \
  "$CLI_IMAGE" sleep 7200 >/dev/null
docker network connect bridge noo-sqlx-prepare
trap 'docker rm -f noo-sqlx-prepare >/dev/null 2>&1 || true' EXIT

# `cargo clean -p` forces the macros to re-expand. Cargo's freshness check only
# tracks SOURCE files, so with a warm target/ neither prepare nor --check would
# look at `.sqlx` or the database at all — it would exit 0 in under a second and
# report agreement it never verified.
#
# This MUST NOT be `find src -name '*.rs' -exec touch {} +`: the rust:1-debian13
# image has no `find`, so that form fails silently inside `sh -c` and the check
# becomes a no-op that always passes. Cleaning one package needs no external
# binary and keeps dependency artifacts, so it is both correct and cheap.
CARGO_ARGS=(-- --all-targets)
[[ "$MODE" == check ]] && CARGO_ARGS=(--check "${CARGO_ARGS[@]}")

docker exec noo-sqlx-prepare sh -c "
  export PATH=/out/bin:\$PATH
  set -e
  cargo clean -p noo-gateway
  cargo sqlx prepare ${CARGO_ARGS[*]}"

if [[ "$MODE" == check ]]; then
  echo "==> cache agrees with the live schema"
  exit 0
fi

# The container writes as root; hand the cache back to the invoking user so the
# working tree stays usable (and `git worktree remove` does not hit EPERM).
docker run --rm -v "$REPO_ROOT/gateway-rust":/w alpine \
  chown -R "$(id -u):$(id -g)" /w/.sqlx

echo "==> done. Review and commit gateway-rust/.sqlx/"
git -C "$REPO_ROOT" status --short gateway-rust/.sqlx
