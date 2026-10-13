#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Emit a normalised, diffable snapshot of a database's PRIVILEGE PLANE —
# roles, ownership and grants — which `pg_dump` deliberately does not show.
#
# WHY THIS EXISTS
#
# Both equivalence gates dump with `--no-owner --no-privileges`, ON BOTH
# SIDES. That is not an oversight: ownership legitimately differs between a
# chain-built database and a dump-restored one, so the flags were added to stop
# the diff screaming about a difference that does not matter.
#
# The cost showed up on 2026-08-04. The sqlx cutover shipped with NO login
# roles, NONE of noo_app's 348 grants, and the ownership of 34 tables missing —
# and both gates reported IDENTICAL throughout, because a diff only catches
# what both sides are allowed to express. A fresh install migrated cleanly and
# then died in preflight on "only 0/6 core tables"; 0 because
# `information_schema` shows you only the tables you hold a privilege on.
#
# That was papered over by `gateway-rust/src/role_provision.rs` reconciling the
# plane on every boot, with `tests/test_role_ownership_parity.py` keeping its
# pinned lists honest. an earlier change DELETES both — ownership becomes
# correct at birth once each system migrates into its own schema as its own
# role — so the compensating control goes away and this has to replace it.
#
# WHAT IT DOES NOT DO
#
# It does not compare. It prints. Comparison is the caller's job, because what
# SHOULD match differs by context: two databases built the same way must match
# exactly, while a chain-built and a dump-restored one legitimately differ on
# owner until B' lands. A script that hard-coded one answer would be wrong half
# the time.
#
# Usage:
#   scripts/pg-privilege-dump.sh <database>            # to stdout
#   PGCONTAINER=noo-postgres scripts/pg-privilege-dump.sh noo
#
# Environment:
#   PGCONTAINER    docker container to exec psql in (default: noo-postgres)
#   PGSUPERUSER    role to connect as (default: noo)
#
# Output is sorted and free of timestamps, OIDs and anything else that varies
# between two identical databases — so a byte diff means a real difference.
set -euo pipefail

DB="${1:-}"
if [ -z "$DB" ]; then
    echo "usage: $0 <database>" >&2
    exit 2
fi
PGCONTAINER="${PGCONTAINER:-noo-postgres}"
PGSUPERUSER="${PGSUPERUSER:-noo}"

q() {
    docker exec -i "$PGCONTAINER" psql -U "$PGSUPERUSER" -d "$DB" -tAF'|' -c "$1"
}

# ── roles ────────────────────────────────────────────────────────────────
# Cluster-global, so this is a property of the SERVER rather than the
# database — included anyway, because a missing role is the failure that
# started all of this, and the reader is looking at one install either way.
#
# The password is never read: `rolpassword` is not selected here and must not
# be added. What matters is that the role exists with the right attributes.
echo "== roles =="
q "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
    FROM pg_roles
    WHERE rolname LIKE 'noo%'
    ORDER BY rolname"

# ── schemas ──────────────────────────────────────────────────────────────
echo "== schemas =="
q "SELECT nspname, pg_get_userbyid(nspowner)
    FROM pg_namespace
    WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema'
    ORDER BY nspname"

# ── table ownership ──────────────────────────────────────────────────────
# The plane the schema dump cannot see at all. `relkind='r'` only: views and
# sequences follow their tables, and including them adds noise without adding
# a failure mode anyone has hit.
echo "== table owners =="
q "SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner)
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
    ORDER BY 1"

# ── table grants ─────────────────────────────────────────────────────────
# Aggregated per (table, grantee) so the row count tracks the interesting
# thing — who can touch what — rather than exploding by privilege type.
# PUBLIC and the superuser's implicit grants are excluded: they are noise that
# differs by how the database was built, not by what was intended.
echo "== table grants =="
q "SELECT table_schema || '.' || table_name || ' -> ' || grantee || ': ' ||
           string_agg(privilege_type, ',' ORDER BY privilege_type)
    FROM information_schema.role_table_grants
    WHERE grantee LIKE 'noo%' AND grantee <> '$PGSUPERUSER'
      AND table_schema NOT LIKE 'pg_%' AND table_schema <> 'information_schema'
    GROUP BY table_schema, table_name, grantee
    ORDER BY 1"

# ── schema privileges ────────────────────────────────────────────────────
# CREATE is the one that matters: "the runtime role owns nothing and can
# create nothing" is the property schema-per-system rests on, and it is
# checkable only here.
echo "== schema privileges =="
q "SELECT n.nspname || ' -> ' || r.rolname || ': ' ||
           CASE WHEN has_schema_privilege(r.rolname, n.nspname, 'CREATE')
                THEN 'CREATE,' ELSE '' END ||
           CASE WHEN has_schema_privilege(r.rolname, n.nspname, 'USAGE')
                THEN 'USAGE' ELSE '-' END
    FROM pg_namespace n CROSS JOIN pg_roles r
    WHERE r.rolname LIKE 'noo%'
      AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
    ORDER BY 1"

# ── default privileges ───────────────────────────────────────────────────
# Recorded per granting role, and invisible everywhere else. Without these a
# table created by a DDL role is unreachable by its runtime role — a failure
# that surfaces at the first query against a newly migrated table, nowhere
# near the migration that caused it.
echo "== default privileges =="
q "SELECT pg_get_userbyid(defaclrole) || ' in ' ||
           COALESCE(defaclnamespace::regnamespace::text, '(all)') || ': ' ||
           array_to_string(defaclacl, ' ')
    FROM pg_default_acl
    ORDER BY 1"
