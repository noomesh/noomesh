#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Verify the noo_app role is genuinely constrained before pointing the gateway
# at it.
#
# The whole point of the role split is that RLS policies actually apply. A role
# that is superuser, has BYPASSRLS, or owns the tables silently ignores every
# policy — so this script asserts the negative properties, not just that the
# role exists.
#
# Usage:
#   NOO_APP_DB_PASSWORD=... scripts/verify-app-role.sh [container] [db]
set -euo pipefail

CONTAINER="${1:-noo-postgres}"
DB="${2:-noo}"
APP_ROLE="noo_app"
FAILED=0

psql_admin() { docker exec "$CONTAINER" psql -U noo -d "$DB" -tAc "$1"; }

check() {  # check <description> <actual> <expected>
    if [ "$2" = "$3" ]; then
        printf '  PASS  %s\n' "$1"
    else
        printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"
        FAILED=1
    fi
}

echo "Verifying ${APP_ROLE} in ${CONTAINER}/${DB}"
echo

exists=$(psql_admin "SELECT count(*) FROM pg_roles WHERE rolname='${APP_ROLE}'")
if [ "$exists" != "1" ]; then
    echo "  FAIL  role ${APP_ROLE} does not exist — run migration 033 first"
    exit 1
fi

echo "Role attributes (each of these individually defeats RLS):"
check "not superuser"  "$(psql_admin "SELECT rolsuper FROM pg_roles WHERE rolname='${APP_ROLE}'")" "f"
check "not bypassrls" "$(psql_admin "SELECT rolbypassrls FROM pg_roles WHERE rolname='${APP_ROLE}'")" "f"
check "cannot create role" "$(psql_admin "SELECT rolcreaterole FROM pg_roles WHERE rolname='${APP_ROLE}'")" "f"
check "cannot create db"   "$(psql_admin "SELECT rolcreatedb FROM pg_roles WHERE rolname='${APP_ROLE}'")" "f"
check "can log in"         "$(psql_admin "SELECT rolcanlogin FROM pg_roles WHERE rolname='${APP_ROLE}'")" "t"

echo
echo "Ownership (owners are RLS-exempt unless FORCE ROW LEVEL SECURITY):"
owned=$(psql_admin "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tableowner='${APP_ROLE}'")
check "owns zero tables" "$owned" "0"

echo
echo "Grants — the role must be able to do its job:"
total=$(psql_admin "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
granted=$(psql_admin "SELECT count(*) FROM pg_tables t WHERE t.schemaname='public' \
  AND has_table_privilege('${APP_ROLE}', format('%I.%I', t.schemaname, t.tablename), 'SELECT')")
check "SELECT on all ${total} tables" "$granted" "$total"

writable=$(psql_admin "SELECT count(*) FROM pg_tables t WHERE t.schemaname='public' \
  AND has_table_privilege('${APP_ROLE}', format('%I.%I', t.schemaname, t.tablename), 'INSERT')")
check "INSERT on all ${total} tables" "$writable" "$total"

echo
echo "Live connection test (requires NOO_APP_DB_PASSWORD):"
if [ -z "${NOO_APP_DB_PASSWORD:-}" ]; then
    echo "  SKIP  NOO_APP_DB_PASSWORD not set — cannot test an actual login."
    echo "        This is the check that matters most; re-run with it set."
    FAILED=1
else
    as_app() {
        docker exec -e PGPASSWORD="$NOO_APP_DB_PASSWORD" "$CONTAINER" \
            psql -U "$APP_ROLE" -d "$DB" -h 127.0.0.1 -tAc "$1" 2>&1
    }
    who=$(as_app "SELECT current_user")
    check "can connect" "$who" "$APP_ROLE"

    # Must be able to read.
    if as_app "SELECT 1 FROM noo_users LIMIT 1" >/dev/null 2>&1; then
        printf '  PASS  can read noo_users\n'
    else
        printf '  FAIL  cannot read noo_users — grants are incomplete\n'
        FAILED=1
    fi

    # Must NOT be able to perform DDL. A role that can DROP defeats the split.
    if as_app "CREATE TABLE _noo_role_probe (x int)" 2>&1 | grep -qi "permission denied"; then
        printf '  PASS  DDL is denied (cannot CREATE TABLE)\n'
    else
        printf '  FAIL  role was able to run DDL — it is not constrained\n'
        as_app "DROP TABLE IF EXISTS _noo_role_probe" >/dev/null 2>&1 || true
        FAILED=1
    fi
fi

echo
if [ "$FAILED" = 0 ]; then
    echo "OK — ${APP_ROLE} is constrained. Safe to point DATABASE_URL at it."
    echo "Next: RLS policies are still no-ops until tables set FORCE ROW LEVEL SECURITY."
else
    echo "FAILED — do NOT point the gateway at ${APP_ROLE} yet."
    exit 1
fi
