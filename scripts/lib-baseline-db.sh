#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Disposable Postgres for schema-baseline work. SOURCE this, never execute it.
#
# WHY THIS EXISTS — the outage it prevents.
#
# The baseline generator builds a throwaway DATABASE and replays the Alembic
# chain into it. That reads as safe, and it is not: migrations 033/034/038
# create the `noo_app` / `noo_evolve` / `noo_trellion` login roles, and
# **Postgres roles are CLUSTER-GLOBAL, not per-database**. A throwaway database
# inside the LIVE cluster still shares that cluster's role catalogue, so
# replaying the chain there rewrites the real roles' passwords. On 2026-08-04
# this reset all three production roles to a placeholder that ships in the
# repo, and the gateway crash-looped on
#   password authentication failed for user "noo_app"
#
# Two independent defences, because either alone has a bypass:
#
#   here          the schema is built in a container this script CREATES and
#                 DESTROYS, so there are no real roles to clobber
#   migrations    `NOO_DB_SCHEMA_ONLY=1` (see db/role_provision.py) makes the
#                 role migrations leave an EXISTING role untouched, so even a
#                 mis-pointed run cannot rewrite a live credential
#
# Contract for callers:
#
#   baseline_db_start   sets PGCONTAINER / PGSUPERUSER / POSTGRES_PASSWORD and,
#                       when it created the container, BASELINE_DB_NETWORK
#   baseline_db_stop    idempotent; safe in a trap, no-op for a borrowed container
#
# If the caller has ALREADY set PGCONTAINER (CI points at its service
# container), nothing is created — but the container must pass
# `baseline_db_assert_disposable`, which refuses a live stack.

# Same pin as the sqlx-drift CI service and the production major version. See
# the header of generate-mesh-baseline.sh: pg_dump output is major-version
# specific, so this must not drift from the controller image.
BASELINE_PG_IMAGE="${BASELINE_PG_IMAGE:-pgvector/pgvector:pg18}"

BASELINE_DB_OWNED=0
BASELINE_DB_NETWORK=""

baseline_random_secret() {
    # Never a fixed string. A hardcoded placeholder in `scripts/` is a
    # PUBLISHED credential — scripts/ is not in PRO_EXCLUDES, so it syncs to
    # the OSS repo — and the 2026-08-04 incident ended with three production
    # roles authenticating with exactly such a value.
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# Refuse to build a baseline inside a cluster that has real users.
#
# Three independent tells, ANY of which is disqualifying. They are cheap and
# they overlap on purpose: a single heuristic that a future container layout
# happens to dodge would silently restore the old failure.
baseline_db_assert_disposable() {
    local c="$1" reason="" v num img proj

    # `com.docker.compose.container-number`, NOT `...project`. Both appear in
    # `.Config.Labels`, but that view MERGES the image's labels — and an image
    # built by `docker compose build` carries project/service/version, so the
    # obvious check calls every container from such an image compose-managed.
    # (Verified 2026-08-04: a plain `docker run` of the controller's postgres
    # image reports project=pai-assistant.) container-number is written by
    # compose when it CREATES a container and is never baked into an image.
    num="$(docker inspect "$c" --format '{{index .Config.Labels "com.docker.compose.container-number"}}' 2>/dev/null || true)"
    case "$num" in
        ""|"<no value>") ;;
        *)
            proj="$(docker inspect "$c" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)"
            reason="it is managed by docker compose (project '$proj')"
            ;;
    esac

    if [ -z "$reason" ]; then
        # Persistent storage means somebody intends to keep what is in there.
        # A NAMED volume or a bind, not an anonymous volume: postgres images
        # declare `VOLUME /var/lib/postgresql/data`, so every throwaway
        # container gets an anonymous one (64 hex chars) and treating that as
        # persistent would reject the CI service container too.
        v="$(docker inspect "$c" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}:{{.Name}}{{end}}{{end}}' 2>/dev/null || true)"
        case "$v" in
            "") ;;
            bind:*) reason="its data directory is a bind mount" ;;
            volume:*)
                img="${v#volume:}"
                if ! printf '%s' "$img" | grep -qE '^[0-9a-f]{64}$'; then
                    reason="its data directory is the named volume '$img'"
                fi
                ;;
        esac
    fi

    if [ -z "$reason" ]; then
        # Last resort: does the cluster hold application data? Role EXISTENCE
        # is deliberately NOT the test — CI's throwaway service container has
        # the roles by the time this runs, because the replay check made them.
        local rows
        rows="$(docker exec -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$c" \
            psql -U "${PGSUPERUSER:-postgres}" -d postgres -tAc \
            "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1') AND datdba <> 0 AND pg_database_size(datname) > 100000000;" \
            2>/dev/null | tr -d ' \r' || true)"
        [ -n "$rows" ] && [ "$rows" != "0" ] && reason="it holds a database larger than 100 MB (real data)"
    fi

    [ -z "$reason" ] && return 0

    if [ "${NOO_BASELINE_ALLOW_LIVE_CLUSTER:-}" = "1" ]; then
        echo "!! NOO_BASELINE_ALLOW_LIVE_CLUSTER=1: proceeding against '$c' although $reason." >&2
        echo "!! Role passwords are still protected by NOO_DB_SCHEMA_ONLY, but nothing" >&2
        echo "!! else about this cluster is. You are on your own." >&2
        return 0
    fi

    cat >&2 <<EOF
ERROR: refusing to build a schema baseline in container '$c' — $reason.

  Postgres roles are CLUSTER-GLOBAL. Replaying the Alembic chain here would
  run migrations 033/034/038 against the REAL noo_app / noo_evolve /
  noo_trellion roles, even though the schema goes into a throwaway database.
  That is exactly what took the gateway down on 2026-08-04.

  Just unset PGCONTAINER: this script then starts and destroys its own
  Postgres, which is the supported path and needs no secrets at all.
EOF
    return 1
}

baseline_db_start() {
    if [ -n "${PGCONTAINER:-}" ]; then
        # Borrowed container (CI service container). Not ours to destroy — but
        # it must not be a live stack.
        : "${PGSUPERUSER:=noo}"
        baseline_db_assert_disposable "$PGCONTAINER" || return 1
        echo "==> using caller-provided container '$PGCONTAINER' (not disposable by us)"
        return 0
    fi

    PGCONTAINER="noo-baseline-pg-$$"
    PGSUPERUSER="noo"
    POSTGRES_PASSWORD="$(baseline_random_secret)"
    BASELINE_DB_NETWORK="noo-baseline-net-$$"
    export PGCONTAINER PGSUPERUSER POSTGRES_PASSWORD

    # A USER-DEFINED network, not the default bridge: the docker-mode leg runs
    # the gateway image and resolves the database BY CONTAINER NAME, and the
    # default bridge has no DNS.
    docker network create "$BASELINE_DB_NETWORK" >/dev/null
    docker run -d --name "$PGCONTAINER" --network "$BASELINE_DB_NETWORK" \
        -e POSTGRES_USER="$PGSUPERUSER" \
        -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
        -e POSTGRES_DB=postgres \
        "$BASELINE_PG_IMAGE" >/dev/null
    BASELINE_DB_OWNED=1

    echo "==> started disposable postgres '$PGCONTAINER' ($BASELINE_PG_IMAGE)"
    local i
    for i in $(seq 1 60); do
        if docker exec "$PGCONTAINER" pg_isready -U "$PGSUPERUSER" -d postgres >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: disposable postgres did not become ready in 60s" >&2
    docker logs "$PGCONTAINER" 2>&1 | tail -20 >&2
    return 1
}

baseline_db_stop() {
    [ "${BASELINE_DB_OWNED:-0}" = 1 ] || return 0
    docker rm -f "$PGCONTAINER" >/dev/null 2>&1 || true
    [ -n "$BASELINE_DB_NETWORK" ] && docker network rm "$BASELINE_DB_NETWORK" >/dev/null 2>&1
    BASELINE_DB_OWNED=0
    return 0
}
