#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Replay both Alembic chains (memory env, then mesh env) from an EMPTY
# database and prove the result is sane. This is the check that keeps the
# migration history replayable — the property that broke in an earlier change
# (create_all()-based baselines absorbing future columns) and is now held
# by pinned baselines.
#
# Usage: scripts/migration-replay-check.sh [DSN]
#   DSN defaults to $DATABASE_URL. Point it at a THROWAWAY database — the
#   script migrates it to heads. It never drops or writes user data, but a
#   scratch pgvector instance is the intended target (CI service container
#   or `docker run pgvector/pgvector:pg16`).
#
# Checks, in order:
#   1. upgrade(dsn, "heads") from whatever state the DB is in (empty in CI)
#   2. both version tables landed on the actual head of their env
#   3. a second upgrade() is a clean no-op (the from-existing-install path)
#
# Env needed by role-creating migrations (033/034/038): NOO_APP_DB_PASSWORD,
# NOO_EVOLVE_DB_PASSWORD, NOO_TRELLION_DB_PASSWORD. CI sets throwaway
# literals. Roles are CLUSTER-level, not schema-level: on a shared scratch
# Postgres a role can outlive the database, so all three migrations
# CREATE-or-ALTER idempotently (033/034/038 all check pg_roles first).
set -euo pipefail

DSN="${1:-${DATABASE_URL:-}}"
if [ -z "$DSN" ]; then
    echo "usage: $0 <dsn>  (or set DATABASE_URL)" >&2
    exit 2
fi

python3 - "$DSN" <<'PYEOF'
import sys

from sqlalchemy import create_engine, text

from noomesh.db.engine import _sync_dsn
from noomesh.db.migration_runner import all_cfgs, memory_cfg, mesh_cfg, upgrade

dsn = sys.argv[1]

# 0. the broker's job, done by hand here: since noo-trellion #35 the memory
#    env VERIFIES vector/pg_trgm and refuses to create them — shedding that
#    superuser-only step is what lets the chain run as noo_trellion_ddl. A
#    replay database is fresh, so someone privileged must install them
#    first, and in this harness that someone is us (the DSN is a superuser
#    on a throwaway DB by this script's contract).
_boot = create_engine(_sync_dsn(dsn))
with _boot.connect() as conn:
    for ext in ("vector", "pg_trgm"):
        if not conn.execute(
            text("SELECT 1 FROM pg_extension WHERE extname = :e"), {"e": ext}
        ).scalar():
            conn.execute(text(f"CREATE EXTENSION {ext}"))
    conn.commit()
_boot.dispose()

# 1. replay both chains
upgrade(dsn, "heads")

# 2. each env's version table must be at that env's real head(s)
from alembic.script import ScriptDirectory

failures = []
engine = create_engine(_sync_dsn(dsn))
# The memory env's version table lives in the TRELLION schema since the
# squash (100_trellion_squash) — an unqualified lookup would find nothing
# and report a mismatch that is really a wrong address.
for label, cfg, table in (
    ("memory", memory_cfg(dsn), "trellion.alembic_version_memory"),
    ("mesh", mesh_cfg(dsn), "public.alembic_version_mesh"),
):
    heads = set(ScriptDirectory.from_config(cfg).get_heads())
    with engine.connect() as conn:
        stamped = {r[0] for r in conn.execute(text(f"SELECT version_num FROM {table}"))}
    if stamped != heads:
        failures.append(f"{label}: stamped={sorted(stamped)} heads={sorted(heads)}")
    else:
        print(f"REPLAY_HEAD_OK {label} {sorted(heads)}")
engine.dispose()
if failures:
    print("REPLAY_HEAD_MISMATCH: " + "; ".join(failures))
    sys.exit(1)

# 3. re-running against the now-migrated DB must be a clean no-op —
#    this is the path every existing install takes on gateway startup.
upgrade(dsn, "heads")
print("REPLAY_RERUN_NOOP_OK")
print("FRESH_MIGRATE_OK")
PYEOF
