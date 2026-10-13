#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Regenerate the mesh sqlx baselines from the Alembic chain.
#
#   scripts/generate-mesh-baseline.sh            regenerate and rewrite
#   scripts/generate-mesh-baseline.sh --check    verify committed == generated
#
# WHERE THE SCHEMA IS BUILT — read this before "simplifying" it.
#
# By default this script STARTS ITS OWN disposable Postgres and destroys it on
# exit. It used to default to $PGCONTAINER=noo-postgres, the LIVE database,
# on the theory that a throwaway DATABASE inside it was harmless. It is not:
# **Postgres roles are CLUSTER-GLOBAL**, so migrations 033/034/038 rewrote the
# real noo_app / noo_evolve / noo_trellion passwords — to a placeholder that
# ships in this repo — and crash-looped the gateway twice on 2026-08-04.
#
# There is no flag to point it at the live stack. Setting PGCONTAINER borrows
# an EXISTING container (that is how CI reuses its service container), and
# scripts/lib-baseline-db.sh refuses one that looks like a live stack.
#
# Two modes for applying the chain:
#
#   default        `docker run` the gateway image against $PGCONTAINER.
#                  What a developer has locally.
#   BASELINE_DSN   apply the chain in-process with the installed noomesh.
#                  What CI has: a service container and a pip install, no
#                  gateway image. This is the sqlx-drift path.
#
# Both still shell into $PGCONTAINER for psql/pg_dump. In CI that container is
# the service container, discovered by `docker ps` — service containers are
# ordinary containers on the runner, so `docker exec` works.
#
# THE MAJOR VERSION MUST MATCH PRODUCTION (pg18). pg_dump output is
# version-specific: dumping this schema with pg16 differs from pg18 in ways
# that have nothing to do with drift, so a mismatched CI would fail --check
# on the version and teach everyone to ignore it. pg_dump runs INSIDE
# $PGCONTAINER so the client version always tracks the server it dumps, and
# the sqlx-drift service is pinned to pgvector/pgvector:pg18 to match the
# controller image (dhi.io/postgres:18-alpine3.22). Bump both together.
#
# an earlier change's amendment: the sqlx chain does NOT transcribe the 46 Alembic
# revisions. It starts from a dump of the schema they produce. A dump replays
# byte-identically (verified 2026-08-04), so this is both cheaper and safer
# than hand-porting 46 files — there is no transcription step to get wrong.
#
# The baseline is GENERATED, never edited. Editing it by hand guarantees drift
# from the Alembic chain, and drift here means a fresh install gets a
# different schema from an upgraded one. `--check` is the gate for that.
#
# TWO outputs, because the pro/OSS split must survive:
#
#   migrations/0001_baseline.sql      OSS tables
#
# The head dump contains noo_ga_*, noo_rl_* and noo_hofstadter_loop_cycles.
# Shipping one baseline would leak pro DDL into the OSS sync — exactly what
# `002_pro_tables` exists to prevent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Images for the throwaway containers below. `pai-assistant/<x>:latest` was
# the hardcoded default until 2026-09-12; that namespace stopped being built
# on 2026-09-06 (it is `noomesh/` now), so the defaults named nothing. Resolve
# them the way the stack does — one definition, in lib-dist.sh (tracker R42).
# shellcheck source=scripts/lib-dist.sh
source "$REPO_ROOT/scripts/lib-dist.sh"
apply_dist_mode "$REPO_ROOT" >/dev/null 2>&1 || true

OUT_DIR="$REPO_ROOT/gateway-rust/migrations"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

# The PRO_TABLES scan is GONE with the pro baseline.
# 002_pro_tables no longer executes DDL — its upgrade() returns before the
# frozen _DDL record — so the chain-built fixture cannot contain a pro table
# and the licence-leak this guarded against is structurally impossible: the
# OSS dump cannot leak tables the chain never creates.

# shellcheck source=scripts/lib-baseline-db.sh
. "$REPO_ROOT/scripts/lib-baseline-db.sh"

# A borrowed container (CI) still needs its superuser credentials from the
# caller. The disposable path invents its own and needs no secret store at all
# — which is the point: a baseline build should have no reason to decrypt
# production credentials.
if [ -n "${PGCONTAINER:-}" ] && [ -z "${POSTGRES_PASSWORD:-}" ]; then
    # shellcheck source=scripts/lib-secrets.sh
    . "$REPO_ROOT/scripts/lib-secrets.sh" >/dev/null 2>&1 || true
    load_secrets >/dev/null 2>&1 || true
    : "${POSTGRES_PASSWORD:?PGCONTAINER is set but POSTGRES_PASSWORD is not, and secrets could not be loaded}"
fi

baseline_db_start

# Belt and braces. Even against a container that passed the disposability
# check, the role migrations must not rewrite an existing login role — see
# src/noomesh/db/role_provision.py.
export NOO_DB_SCHEMA_ONLY=1

DB="mesh_baseline_gen_$$"
cleanup() {
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" \
        psql -U "$PGSUPERUSER" -d postgres -tAc "DROP DATABASE IF EXISTS $DB;" >/dev/null 2>&1 || true
    baseline_db_stop
}
trap cleanup EXIT

echo "==> building a clean mesh schema via the Alembic chain"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" \
    psql -U "$PGSUPERUSER" -d postgres -tAc "CREATE DATABASE $DB;" >/dev/null
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" \
    psql -U "$PGSUPERUSER" -d "$DB" -tAc "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null

if [ -n "${BASELINE_DSN:-}" ]; then
    # DSN mode (CI). noomesh is pip-installed on the runner, so the chain
    # runs in-process — no gateway image, no docker network. The DSN's dbname
    # is replaced with the throwaway $DB; everything else (host, port, creds)
    # is taken as given so this works against a service container.
    # No NOO_*_DB_PASSWORD is passed. Under NOO_DB_SCHEMA_ONLY the role
    # migrations mint a random per-run password for a role they have to
    # create, and leave an existing role alone. A fixed placeholder here was
    # a PUBLISHED credential — scripts/ syncs to the OSS repo.
    python3 - "$BASELINE_DSN" "$DB" <<'PYEOF' >/dev/null
import sys
from urllib.parse import urlsplit, urlunsplit

from noomesh.db.migration_runner import upgrade

parts = urlsplit(sys.argv[1])
upgrade(urlunsplit(parts._replace(path="/" + sys.argv[2])), "heads", envs="mesh")
PYEOF
else
    NET="$(docker inspect "$PGCONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')"
    docker run --rm --network "$NET" --entrypoint python \
        -e PGPW="$POSTGRES_PASSWORD" \
        -e NOO_DB_SCHEMA_ONLY=1 \
        "${GATEWAY_IMAGE:-$(resolve_release_image gateway)}" -c "
import os, sys; sys.path.insert(0, '/app/src')
from noomesh.db.migration_runner import upgrade
upgrade(f\"postgresql://$PGSUPERUSER:{os.environ['PGPW']}@$PGCONTAINER:5432/$DB\", 'heads', envs='mesh')
" >/dev/null
fi

REV="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" \
    psql -U "$PGSUPERUSER" -d "$DB" -tAc 'SELECT version_num FROM alembic_version_mesh;' | tr -d ' \r')"
echo "==> chain head: $REV"

dump() {
    # --no-owner/--no-privileges: ownership is assigned by the role migrations
    # (033/034/038), not by the baseline. Baking an owner in would pin every
    # install to whatever role this generator happened to run as.
    #
    # Two classes of line are stripped because they vary per run or per host
    # WITHOUT the schema differing — leaving either in means --check can never
    # pass, and a gate that always fails gets ignored:
    #
    #   \restrict / \unrestrict   a per-invocation nonce
    #   -- Dumped from/by ...     the postgres MINOR version. A dev on 18.4
    #                             and a CI runner on 18.5 produce identical
    #                             schemas and a differing comment.
    #
    # The MAJOR version is deliberately NOT normalised away — see the header.
    # It genuinely changes the DDL, so it must be matched, not papered over.
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" \
        pg_dump -U "$PGSUPERUSER" -d "$DB" --schema-only --no-owner --no-privileges "$@" \
        | grep -vE '^\\(restrict|unrestrict)' \
        | grep -vE '^-- Dumped (from database version|by pg_dump version)'
}

# The pro EXCLUDE/INCLUDE machinery is GONE. The
# Alembic chain no longer creates evolve's tables (002 is gutted in place),
# so a chain-built fixture has nothing pro to exclude and no 0002 to emit.
# The `_*` sequence-leak lesson it carried lives on in git history and in
# noo-evolve's own baseline, which owns those tables now.
HEADER="-- GENERATED by scripts/generate-mesh-baseline.sh — DO NOT EDIT.
-- Regenerate with that script and verify with its --check mode.
-- Alembic chain head at generation time: $REV"

mkdir -p "$OUT_DIR"
# Post-process to the LAYOUT-AGNOSTIC form the committed file carries since
# the mesh-schema move: pg_dump's session-wide search_path reset goes (the
# runner owns the path now), `public.` qualification goes (the path decides
# layout), and the definer function's pin gains `mesh` so one definition
# serves both layouts. Same transform, same order, as the one-time conversion
# of the committed file — they must stay byte-identical or --check lies.
dequalify() {
    grep -v "SELECT pg_catalog.set_config('search_path', '', false);" \
        | sed "s/public\.//g; s/SET search_path TO 'pg_catalog', 'public'/SET search_path TO 'mesh', 'public', 'pg_catalog'/"
}
NEW_OSS="$(printf '%s\n-- Scope: OSS tables only. The five evolve tables live in the evolve repo chain.\n-- Layout: UNQUALIFIED — the runner applies this under `SET search_path = mesh, public`,\n-- so a fresh install lands everything in schema `mesh` (symmetry with trellion/evolve)\n-- while the file itself stays layout-agnostic: applied under a bare psql it builds the\n-- legacy public layout, which is exactly what the equivalence gate compares against.\n\n%s\n' "$HEADER" "$(dump | dequalify)")"

if [ "$CHECK_ONLY" = 1 ]; then
    fail=0
    for pair in "0001_baseline.sql:$NEW_OSS"; do
        f="${pair%%:*}"; body="${pair#*:}"
        if [ ! -f "$OUT_DIR/$f" ]; then
            echo "ERROR: $f is missing — run scripts/generate-mesh-baseline.sh" >&2; fail=1; continue
        fi
        # Ignore the recorded head line: it moves whenever Alembic gains a
        # revision, and that alone is not schema drift.
        if ! diff -q <(grep -v '^-- Alembic chain head' "$OUT_DIR/$f") \
                     <(printf '%s\n' "$body" | grep -v '^-- Alembic chain head') >/dev/null; then
            echo "ERROR: $f is out of date with the Alembic chain." >&2
            diff <(grep -v '^-- Alembic chain head' "$OUT_DIR/$f") \
                 <(printf '%s\n' "$body" | grep -v '^-- Alembic chain head') | head -40 >&2
            fail=1
        fi
    done
    [ "$fail" = 0 ] && echo "==> baselines are current" || exit 1
    exit 0
fi

printf '%s\n' "$NEW_OSS" > "$OUT_DIR/0001_baseline.sql"
echo "==> wrote $OUT_DIR/0001_baseline.sql ($(grep -c '^CREATE TABLE' "$OUT_DIR/0001_baseline.sql") tables)"
