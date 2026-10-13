#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Assert the privilege-plane INVARIANTS of a mesh database.
#
# The schema gates dump `--no-owner --no-privileges` on both sides, so this
# plane is invisible to them — which is exactly how the sqlx cutover shipped
# with no roles, no grants and no ownership while every gate stayed green
# (2026-08-04). `pg-privilege-dump.sh` makes the plane VISIBLE; this script
# makes it ENFORCED.
#
# Invariants, not diffs, on purpose: a diff needs two comparable databases,
# and what "should match" differs by how each side was built. An invariant —
# "no runtime role can CREATE", "noo_app owns nothing" — is true of EVERY
# correctly-provisioned mesh database: CI's, a fresh install, production.
# So this runs against any of them, and failing on any of them means the
# same thing.
#
# Usage:
#   scripts/verify-privilege-plane.sh <database>
#   PGCONTAINER=noo-postgres scripts/verify-privilege-plane.sh noo   # live
#
# Environment:
#   PGCONTAINER   docker container to exec psql in (default: noo-postgres)
#   PGSUPERUSER   role to connect as (default: noo)
set -euo pipefail

DB="${1:-}"
if [ -z "$DB" ]; then
    echo "usage: $0 <database>" >&2
    exit 2
fi
PGCONTAINER="${PGCONTAINER:-noo-postgres}"
PGSUPERUSER="${PGSUPERUSER:-noo}"

q() { docker exec -i "$PGCONTAINER" psql -U "$PGSUPERUSER" -d "$DB" -tAc "$1"; }

fail=0
say_fail() { echo "FAIL: $1" >&2; fail=1; }
say_ok()   { echo "  ok: $1"; }

echo "==> privilege-plane invariants on $DB"

# ── 1. No noo role except the superuser holds ANY escalation attribute. ──
# A scoped role that quietly gained SUPERUSER/CREATEDB/CREATEROLE/BYPASSRLS
# is the whole scoping model silently voided.
BAD_ATTRS=$(q "SELECT string_agg(rolname, ', ')
    FROM pg_roles
    WHERE rolname LIKE 'noo\\_%'
      AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls)")
if [ -n "$BAD_ATTRS" ]; then
    say_fail "scoped role(s) hold escalation attributes: $BAD_ATTRS"
else
    say_ok "no scoped role holds SUPERUSER/CREATEDB/CREATEROLE/BYPASSRLS"
fi

# ── 2. No RUNTIME role holds CREATE on any schema. ──────────────────────
# "New tables arrive by migration" is only a rule if it is checkable; this
# is the check. DDL roles are excluded — CREATE on their OWN schema is their
# entire purpose, and invariant 3 pins the "own" part.
BAD_CREATE=$(q "SELECT string_agg(r.rolname || ' on ' || n.nspname, ', ')
    FROM pg_roles r CROSS JOIN pg_namespace n
    WHERE r.rolname LIKE 'noo\\_%' AND r.rolname NOT LIKE '%\\_ddl'
      AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
      AND has_schema_privilege(r.rolname, n.nspname, 'CREATE')")
if [ -n "$BAD_CREATE" ]; then
    say_fail "runtime role(s) hold CREATE: $BAD_CREATE"
else
    say_ok "no runtime role holds CREATE on any schema"
fi

# ── 3. A DDL role's CREATE reaches exactly its own schema. ──────────────
# noo_trellion_ddl with CREATE on public (or on evolve) is the shared-schema
# arrangement an earlier change replaced, back under a different name.
BAD_DDL=$(q "SELECT string_agg(r.rolname || ' on ' || n.nspname, ', ')
    FROM pg_roles r CROSS JOIN pg_namespace n
    WHERE r.rolname LIKE 'noo\\_%\\_ddl'
      AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
      AND has_schema_privilege(r.rolname, n.nspname, 'CREATE')
      AND n.nspname <> replace(r.rolname, 'noo_', '')
      AND n.nspname <> regexp_replace(r.rolname, '^noo_(.*)_ddl$', '\\1')")
if [ -n "$BAD_DDL" ]; then
    say_fail "DDL role(s) hold CREATE outside their own schema: $BAD_DDL"
else
    say_ok "every DDL role's CREATE is confined to its own schema"
fi

# ── 4. noo_app owns nothing, anywhere. ───────────────────────────────────
# The oldest invariant of the split, and the one that makes "the gateway
# runtime cannot alter schema" a fact instead of a habit.
APP_OWNED=$(q "SELECT count(*) FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r' AND pg_get_userbyid(c.relowner) = 'noo_app'")
if [ "$APP_OWNED" != "0" ]; then
    say_fail "noo_app owns $APP_OWNED table(s); it must own zero"
else
    say_ok "noo_app owns zero tables"
fi

# ── 5. Per-system schemas are owned by their DDL role. ──────────────────
# Only asserted for schemas that EXIST: an OSS install may have neither, a
# pre-broker install has none, and absence is not a violation. Wrong OWNER
# on one that exists always is.
# Keyed on the DDL role's existence — that is the marker that the BROKER
# provisioned this database. A chain replayed by a bare superuser (the CI
# replay harness, a standalone install) legitimately produces noo-owned
# objects and never claimed otherwise; asserting broker-shaped ownership
# there is testing a promise nobody made. Where the DDL role exists, the
# promise was made, and wrong ownership is a real violation.
BAD_SCHEMA=$(q "SELECT string_agg(nspname || ' owned by ' || pg_get_userbyid(nspowner), ', ')
    FROM pg_namespace
    WHERE nspname IN ('trellion', 'evolve')
      AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_' || nspname || '_ddl')
      AND pg_get_userbyid(nspowner) <> 'noo_' || nspname || '_ddl'")
if [ -n "$BAD_SCHEMA" ]; then
    say_fail "per-system schema with wrong owner: $BAD_SCHEMA"
else
    say_ok "existing per-system schemas are owned by their DDL roles"
fi

# ── 6. Every table INSIDE a per-system schema is owned by that DDL role. ─
# Ownership-at-birth is the property that deleted the pinned table lists;
# a table that sneaks in under another owner resurrects the drift problem
# with no list left to catch it.
BAD_OWNER=$(q "SELECT string_agg(n.nspname || '.' || c.relname || ' owned by ' || pg_get_userbyid(c.relowner), ', ')
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r' AND n.nspname IN ('trellion', 'evolve')
      AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_' || n.nspname || '_ddl')
      AND pg_get_userbyid(c.relowner) <> 'noo_' || n.nspname || '_ddl'")
if [ -n "$BAD_OWNER" ]; then
    say_fail "table(s) in a per-system schema with the wrong owner: $BAD_OWNER"
else
    say_ok "every table in a per-system schema is owned by its DDL role"
fi

# ── 7. Runtime roles can REACH their own schema. ─────────────────────────
# The inverse failure: perfectly locked down and unusable. USAGE missing is
# the "works on legacy installs, fails only on fresh ones" shape.
BAD_USAGE=$(q "SELECT string_agg(n.nspname, ', ')
    FROM pg_namespace n
    WHERE n.nspname IN ('trellion', 'evolve')
      AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_' || n.nspname)
      AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noo_' || n.nspname || '_ddl')
      AND NOT has_schema_privilege('noo_' || n.nspname, n.nspname, 'USAGE')")
if [ -n "$BAD_USAGE" ]; then
    say_fail "runtime role lacks USAGE on its own schema: $BAD_USAGE"
else
    say_ok "runtime roles hold USAGE on their own schemas"
fi

if [ "$fail" = 1 ]; then
    echo "==> PRIVILEGE PLANE VIOLATED — see FAIL lines above." >&2
    echo "    Inspect with: scripts/pg-privilege-dump.sh $DB" >&2
    exit 1
fi
echo "==> privilege plane holds"
