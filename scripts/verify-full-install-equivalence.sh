#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Does the sqlx path build the SAME schema as Alembic, for a REALISTIC install?
#
#   scripts/verify-full-install-equivalence.sh          (local, docker)
#   BASELINE_DSN=... scripts/verify-full-install-equivalence.sh   (CI)
#
# WHY THIS EXISTS SEPARATELY FROM generate-mesh-baseline.sh --check.
#
# That check regenerates the baselines from the mesh chain and diffs them. It
# is mesh-only on BOTH sides, so by construction it cannot see anything that
# spans two migration domains — and it duly passed while the baselines were
# missing fk_temporal_edges_source_cycle, a constraint every real install has.
#
# The mesh database has MORE THAN ONE WRITER:
#
#   gateway   -> mesh env   (alembic_version_mesh)
#   trellion  -> memory env  (alembic_version_memory)
#   evolve    -> owns the pro tables' DATA (role noo_evolve); no env of its own
#                today, but that can change
#
# Any of them can introduce an object the others' baselines do not describe.
# Rather than enumerate writers — which is the assumption that just failed —
# this compares end results:
#
#   A:  memory (alembic) -> mesh (alembic)                    reference
#   B:  memory (alembic) -> baselines                          sqlx path
#
# and diffs `pg_dump --schema-only`. A new cross-domain object from ANY writer
# shows up as a diff, without this script knowing anything about it.
#
# Both sides apply the same baselines the gateway embeds, so this cannot drift
# into verifying something the gateway does not do.
#
# WHERE THE DATABASES COME FROM — read this before "simplifying" it.
#
# By default this script STARTS ITS OWN disposable Postgres and destroys it on
# exit. It used to default to $PGCONTAINER=noo-postgres, the LIVE database, on
# the theory that throwaway DATABASES inside it were harmless. They are not:
# **Postgres roles are CLUSTER-GLOBAL**, so the memory/mesh chains replayed
# here run migrations 033/034/038 against the REAL noo_app / noo_evolve /
# noo_trellion roles. That has crash-looped the gateway when run against a
# live cluster.
#
# There is no flag to point it at the live stack. Setting PGCONTAINER borrows
# an EXISTING container (that is how CI reuses its service container), and
# scripts/lib-baseline-db.sh refuses one that looks like a live stack.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Images for the throwaway containers below. `pai-assistant/<x>:latest` was
# the hardcoded default until 2026-09-12; that namespace stopped being built
# on 2026-09-06 (it is `noomesh/` now), so the defaults named nothing. Resolve
# them the way the stack does — one definition, in lib-dist.sh (tracker R42).
# shellcheck source=scripts/lib-dist.sh
source "$REPO_ROOT/scripts/lib-dist.sh"
apply_dist_mode "$REPO_ROOT" >/dev/null 2>&1 || true

MIG="$REPO_ROOT/gateway-rust/migrations"

# shellcheck source=scripts/lib-baseline-db.sh
. "$REPO_ROOT/scripts/lib-baseline-db.sh"

# A borrowed container (CI) still needs its superuser credentials from the
# caller. The disposable path invents its own and needs no secret store at all
# — which is the point: an equivalence run should have no reason to decrypt
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
# src/noomesh/db/role_provision.py. Exported so the in-process DSN leg
# inherits it too.
export NOO_DB_SCHEMA_ONLY=1

A="fi_alembic_$$"
B="fi_sqlx_$$"
PG()  { docker exec    -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" "$@"; }
PGI() { docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$PGCONTAINER" "$@"; }
cleanup() {
    for d in "$A" "$B"; do
        PG psql -U "$PGSUPERUSER" -d postgres -tAc "DROP DATABASE IF EXISTS $d;" >/dev/null 2>&1 || true
    done
    baseline_db_stop
}
trap cleanup EXIT

for d in "$A" "$B"; do
    PG psql -U "$PGSUPERUSER" -d postgres -tAc "CREATE DATABASE $d;" >/dev/null
    # BOTH extensions, since noo-trellion #35: the memory env verifies and
    # refuses to create them (that superuser-only step moved to the broker),
    # so this harness does the broker's job. vector alone worked only while
    # the old env quietly created pg_trgm itself.
    PG psql -U "$PGSUPERUSER" -d "$d" -tAc "CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS pg_trgm;" >/dev/null
done

# Apply an Alembic env to a database. DSN mode runs in-process (CI has the
# packages installed); otherwise via the gateway/trellion images.
apply_env() {  # $1=db  $2=envs  $3=image-if-docker-mode
    if [ -n "${BASELINE_DSN:-}" ]; then
        # No NOO_*_DB_PASSWORD is passed. Under NOO_DB_SCHEMA_ONLY the role
        # migrations mint a random per-run password for a role they have to
        # create, and leave an existing role alone. A fixed placeholder here
        # was a PUBLISHED credential — scripts/ syncs to the OSS repo.
        python3 - "$BASELINE_DSN" "$1" "$2" <<'PYEOF' >/dev/null
import sys
from urllib.parse import urlsplit, urlunsplit
from noomesh.db.migration_runner import upgrade
parts = urlsplit(sys.argv[1])
upgrade(urlunsplit(parts._replace(path="/" + sys.argv[2])), "heads", envs=sys.argv[3])
PYEOF
    else
        local net
        net="$(docker inspect "$PGCONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')"
        docker run --rm --network "$net" --entrypoint python \
            -e PGPW="$POSTGRES_PASSWORD" \
            -e NOO_DB_SCHEMA_ONLY=1 \
            "$3" -c "
import os, sys; sys.path.insert(0, '/app/src')
from noomesh.db.migration_runner import upgrade
upgrade(f\"postgresql://$PGSUPERUSER:{os.environ['PGPW']}@$PGCONTAINER:5432/$1\", 'heads', envs='$2')" >/dev/null
    fi
}

echo "==> memory env into both (every real install migrates it first)"
apply_env "$A" memory "${TRELLION_IMAGE:-$(resolve_release_image trellion)}"
apply_env "$B" memory "${TRELLION_IMAGE:-$(resolve_release_image trellion)}"

echo "==> A: mesh via Alembic"
apply_env "$A" mesh "${GATEWAY_IMAGE:-$(resolve_release_image gateway)}"

echo "==> B: baselines + cross-domain reconciliation"
# 0001 only — 0002_pro.sql is GONE: evolve's five
# tables come from evolve's own chain, into its own schema, so the mesh
# baseline is OSS-only by construction and both sides of this gate agree
# without a pro leg.
PGI psql -U "$PGSUPERUSER" -d "$B" -v ON_ERROR_STOP=1 -q < "$MIG/0001_baseline.sql" >/dev/null
# 0003_cross_domain_pro.sql is GONE. Mesh no longer
# creates an object spanning two other systems' tables, so there is nothing to
# reconcile here — and side A no longer produces one either, which is why this
# gate stays symmetric without it.

dump() {
    # ⚠ THIS GATE IS BLIND TO PRIVILEGES AND OWNERSHIP, BY CONSTRUCTION.
    #
    # --no-owner --no-privileges is applied to BOTH sides, so anything in that
    # plane cancels out and a diff can never see it. That is not hypothetical:
    # the sqlx baseline lost the login roles, all 348 of noo_app's grants, and
    # the ownership of 34 tables, and this gate reported IDENTICAL throughout.
    # A fresh install migrated cleanly and then died in preflight on
    # "only 0/6 core tables" — 0 because information_schema only shows tables
    # you hold a privilege on.
    #
    # Same shape as the cross-domain FK miss: a diff only catches what both
    # sides are ALLOWED to express. The flags cannot simply be dropped —
    # ownership legitimately differs between a chain-built database and a
    # dump-restored one, which is why they were added.
    #
    # The privilege plane is covered instead by gateway-rust/src/role_provision.rs
    # (which reconciles it on every boot) and tests/test_role_ownership_parity.py
    # (which keeps its lists in step with 033/034/038). If you are here because
    # something about grants broke, this script is not where it will show up.
    PG pg_dump -U "$PGSUPERUSER" -d "$1" --schema-only --no-owner --no-privileges \
        | grep -vE '^\\(restrict|unrestrict)' \
        | grep -vE '^-- Dumped (from database version|by pg_dump version)'
}
# ── Third writer: noo-evolve ─────────────────────────────────────────────
# The leg that compared evolve's create_all() against mesh's pro schema is
# GONE with 0002_pro.sql: mesh no longer declares
# evolve's tables, so there are no two copies left to disagree. Chain-vs-
# create_all equivalence for evolve's five tables is proven where the chain
# lives — noo-evolve's own verification (PR #9: identical 117-line dumps).

dump() {
    # ⚠ THIS GATE IS BLIND TO PRIVILEGES AND OWNERSHIP, BY CONSTRUCTION.
    #
    # --no-owner --no-privileges is applied to BOTH sides, so anything in that
    # plane cancels out and a diff can never see it. That is not hypothetical:
    # the sqlx baseline lost the login roles, all 348 of noo_app's grants, and
    # the ownership of 34 tables, and this gate reported IDENTICAL throughout.
    # A fresh install migrated cleanly and then died in preflight on
    # "only 0/6 core tables" — 0 because information_schema only shows tables
    # you hold a privilege on.
    #
    # Same shape as the cross-domain FK miss: a diff only catches what both
    # sides are ALLOWED to express. The flags cannot simply be dropped —
    # ownership legitimately differs between a chain-built database and a
    # dump-restored one, which is why they were added.
    #
    # The privilege plane is covered instead by gateway-rust/src/role_provision.rs
    # (which reconciles it on every boot) and tests/test_role_ownership_parity.py
    # (which keeps its lists in step with 033/034/038). If you are here because
    # something about grants broke, this script is not where it will show up.
    PG pg_dump -U "$PGSUPERUSER" -d "$1" --schema-only --no-owner --no-privileges \
        | grep -vE '^\\(restrict|unrestrict)' \
        | grep -vE '^-- Dumped (from database version|by pg_dump version)'
}
# ── Third writer: noo-evolve ─────────────────────────────────────────────
# evolve has NO migration env. It self-bootstraps its five tables at startup
# (api.py -> db.create_all), by design: "in-cluster they may already exist
# from the Mesh pro migration; standalone this creates them."
#
# So those tables are declared TWICE — by the mesh chain and by evolve's
# SQLAlchemy models — and kept in step by hand. Whoever creates them first
# wins and the other silently accepts what it finds, which makes a drift here
# order-dependent and invisible: an in-cluster install and a standalone one
# would diverge with nothing failing.
#
# Verified identical 2026-08-04. This leg is what keeps it that way.
#
# Local-only: CI has no evolve image and evolve is a separate package, so this
# SKIPS there rather than pretending to cover it. Stated out loud, because a
# skip that reads like a pass is worse than no check.
if [ -n "${BASELINE_DSN:-}" ]; then
    echo "==> evolve leg SKIPPED (DSN/CI mode — no evolve image available)"
elif ! docker image inspect "${EVOLVE_IMAGE:-$(resolve_release_image noo-evolve)}" >/dev/null 2>&1; then
    echo "==> evolve leg SKIPPED (${EVOLVE_IMAGE:-$(resolve_release_image noo-evolve)} not present)"
else
    E="fi_evolve_$$"
    PG psql -U "$PGSUPERUSER" -d postgres -tAc "CREATE DATABASE $E;" >/dev/null
    PG psql -U "$PGSUPERUSER" -d "$E" -tAc "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null
    net="$(docker inspect "$PGCONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')"
    # The add-on's own schema bootstrap, through the console script the image
    # ships for it (a command, not a package import: nothing here names the
    # add-on's modules).
    docker run --rm --network "$net" --entrypoint noo-evolve-schema \
        -e DATABASE_URL="postgresql://$PGSUPERUSER:$POSTGRES_PASSWORD@$PGCONTAINER:5432/$E" \
        "${EVOLVE_IMAGE:-$(resolve_release_image noo-evolve)}" >/dev/null 2>&1

    PRO_TABLES=(noo_ga_generations noo_ga_genomes noo_hofstadter_loop_cycles noo_rl_arms noo_rl_experiences)
    SEL=()
    for t in "${PRO_TABLES[@]}"; do SEL+=(--table="public.$t"); done
    pro_dump() {
        PG pg_dump -U "$PGSUPERUSER" -d "$1" --schema-only --no-owner --no-privileges "${SEL[@]}" \
            | grep -vE '^\\(restrict|unrestrict)' | grep -vE '^-- Dumped (from|by)'
    }
    pro_dump "$E" > /tmp/fi_e.$$ ; pro_dump "$A" > /tmp/fi_ea.$$
    if diff -q /tmp/fi_e.$$ /tmp/fi_ea.$$ >/dev/null; then
        echo "==> evolve self-bootstrap matches the mesh pro schema"
    else
        echo "==> DIVERGED: evolve's create_all() does NOT match the mesh chain." >&2
        echo "    '<' is evolve, '>' is mesh. These two declare the same five" >&2
        echo "    tables independently; whichever runs first wins, so this is a" >&2
        echo "    real order-dependent split between in-cluster and standalone." >&2
        diff /tmp/fi_e.$$ /tmp/fi_ea.$$ | head -30 >&2
        rm -f /tmp/fi_e.$$ /tmp/fi_ea.$$
        PG psql -U "$PGSUPERUSER" -d postgres -tAc "DROP DATABASE IF EXISTS $E;" >/dev/null 2>&1 || true
        exit 1
    fi
    rm -f /tmp/fi_e.$$ /tmp/fi_ea.$$
    PG psql -U "$PGSUPERUSER" -d postgres -tAc "DROP DATABASE IF EXISTS $E;" >/dev/null 2>&1 || true
fi

dump "$A" > /tmp/fi_a.$$ ; dump "$B" > /tmp/fi_b.$$
if diff -q /tmp/fi_a.$$ /tmp/fi_b.$$ >/dev/null; then
    echo "==> IDENTICAL ($(grep -c '^CREATE TABLE' /tmp/fi_a.$$) tables) — sqlx path matches Alembic"
    rm -f /tmp/fi_a.$$ /tmp/fi_b.$$
else
    echo "==> DIVERGED: the sqlx path does NOT reproduce the Alembic schema." >&2
    echo "    '<' is Alembic (correct), '>' is the sqlx path." >&2
    echo "    A cross-domain object from ANY writer (mesh/trellion/evolve)" >&2
    echo "    lands here — it belongs to whichever system owns the table." >&2
    diff /tmp/fi_a.$$ /tmp/fi_b.$$ | head -60 >&2
    rm -f /tmp/fi_a.$$ /tmp/fi_b.$$
    exit 1
fi
