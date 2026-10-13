#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Container entrypoint — MIGRATIONS ONLY.

PKI staging, CA-bundle install, Claude settings merge and git identity now
live in the Rust binary (gateway-rust/src/startup_tasks.rs).
They are NOT duplicated here: two implementations of the same startup
behaviour drift, and the Python copies were already unreachable.

Original docstring follows.

Container entrypoint — PKI setup, CA install, Claude config merge, then exec uvicorn.

Pure Python so it works on both :latest-dev (has shell) and :latest (no shell).
Replaces /opt/entrypoint.sh + the shell CMD.
"""

import os
import re
import shutil
import sys
import time


# Where a mounted client key's 0600 copy lives: the same `/app/pki → /tmp/pki`
# layout gateway-rust/src/startup_tasks.rs::stage_pki produces, so every
# process in a container agrees on the path. Mirrors
# src/noomesh/db/engine.py::_usable_client_key, kept stdlib-only here on
# purpose: this file runs before the package is importable (the sandbox
# image) and must never grow a noomesh import.
def _staged_key_path(path: str) -> str:
    for root in ("/app/pki/", "/tls/"):
        if path.startswith(root):
            return "/tmp/pki/" + path[len(root):]
    return "/tmp/pki" + path


def _libpq_accepts_key(mode: int, st_uid: int) -> bool:
    """libpq's client-key permission rule, exactly (fe-secure-openssl.c,
    REL_16/17/18 and master; the images ship libpq 18.6 in psycopg-binary):

        if (buf.st_uid == 0 ?
            buf.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO) :
            buf.st_mode & (S_IRWXG | S_IRWXO))  -> refuse

    Root-owned: 0640 or less (no g+w, g+x, nor any other bit). Owned by
    anyone else: 0600 or less (no group or other bit at all). 0640 owned
    by a non-root uid (the `noo security pki fix-modes` shape: 0640 + an
    ACL for uid 65532, owned by the operator) is REFUSED. libpq does not
    compare st_uid to the euid: a 0600 key owned by another uid passes
    the mode check (and opens only if the process can read it anyway).
    MUST stay identical to src/noomesh/db/engine.py::_libpq_accepts_key
    (tests/test_pg_client_key_perms.py pins the parity)."""
    if st_uid == 0:
        return mode & 0o037 == 0
    return mode & 0o077 == 0


def _same_bytes(a: str, b: str) -> bool:
    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            return fa.read() == fb.read()
    except OSError:
        return False


def _usable_client_key(path: str) -> str:
    """The key libpq will accept: the mounted one if it passes libpq's rule
    (_libpq_accepts_key), else a private 0600 copy under /tmp/pki owned by
    this process (made here if missing or stale). "" when no copy can be
    made — the connection then fails at the server with a message that
    names the certificate, not with libpq's perms error."""
    if not path or not os.path.isfile(path):
        return path
    try:
        st = os.stat(path)
        if _libpq_accepts_key(st.st_mode, st.st_uid):
            return path
    except OSError:
        return path
    private = _staged_key_path(path)
    try:
        if os.path.isfile(private):
            pst = os.stat(private)
            if _libpq_accepts_key(pst.st_mode, pst.st_uid) and _same_bytes(path, private):
                return private
        os.makedirs(os.path.dirname(private), mode=0o700, exist_ok=True)
        shutil.copyfile(path, private)
        os.chmod(private, 0o600)
        print(f"[entrypoint] staged Postgres client key {path} -> {private} (0600)")
        return private
    except OSError as exc:
        print(f"[entrypoint] WARNING: client key {path} fails libpq's permission rule and could not be staged: {exc}", file=sys.stderr)
        return ""


_SSLKEY = re.compile(r"([?&])sslkey=([^&]+)")


def stage_pg_client_keys(environ=None) -> list[str]:
    """Every DSN in the environment that names `sslkey=<mounted path>` gets
    the staged path substituted, IN PLACE, before anything connects.

    Since 2026-09-28 Postgres requires a client certificate from every TCP
    client (docker/postgres/pg_hba.conf) and every compose DSN names the
    controller leaf on its ro mount — a 0644 key libpq refuses. Rewriting
    the environment (rather than one DSN) is what covers the three readers
    in this container: the Alembic env (reads PAGEINDEX_DSN & co. itself),
    the DSN chosen below, and the process exec'd at the end, whose own DSN
    handling (trellion's engine) passes the URL to libpq verbatim.
    Returns the variable names it rewrote.
    """
    env = os.environ if environ is None else environ
    changed = []
    for name, value in list(env.items()):
        if "postgres" not in value or "sslkey=" not in value:
            continue
        m = _SSLKEY.search(value)
        if not m:
            continue
        usable = _usable_client_key(m.group(2))
        if not usable or usable == m.group(2):
            continue
        env[name] = value[: m.start(2)] + usable + value[m.end(2):]
        changed.append(name)
    return changed






def run_migrations():
    """Apply pending alembic migrations on both envs (memory + mesh).

    Idempotent — `pai db upgrade head` with nothing pending is a no-op
    (~50ms). Runs on every container start so schema and code never
    drift, regardless of which engine (Rust or Python) starts after.

    Skip with NOO_SKIP_MIGRATIONS=1 (debugging only).

    Failure mode: log the error and exit 1. A stuck container is a
    louder signal than silent corruption against an outdated schema.
    """
    if os.environ.get("NOO_SKIP_MIGRATIONS", "").lower() in ("1", "true", "yes"):
        print("[entrypoint] NOO_SKIP_MIGRATIONS set — skipping alembic upgrade")
        return

    # Which Alembic env(s) this container applies (WP-T23 phase 3):
    #   (unset)/all — memory then mesh, single runner. Default; exactly
    #                 today's behavior when the trellion split is off.
    #   mesh       — gateway in trellion-split mode: the memory env moved
    #                 to the noo-trellion container, this one runs mesh
    #                 only, after a bounded wait for the memory head
    #                 (002_pro_tables FKs onto a memory table).
    #   memory      — the noo-trellion container: memory env only.
    # Unknown values fail safe to "all" (same pattern as
    # NOO_WORKER_SUPERVISOR): a typo must not silently skip migrations.
    envs = (os.environ.get("NOO_MIGRATIONS_ENVS") or "all").strip().lower()
    if envs not in ("all", "memory", "mesh"):
        print(
            f"[entrypoint] unknown NOO_MIGRATIONS_ENVS={envs!r} — "
            "falling back to 'all' (valid: all, memory, mesh)",
            file=sys.stderr,
        )
        envs = "all"

    # Migrations need a PRIVILEGED role, not the runtime one: env.py runs
    # CREATE EXTENSION (vector, pg_trgm), 010/036 manage partitions, and
    # 033/034 CREATE the noo_app/noo_evolve login roles. Historically that
    # privilege arrived by ACCIDENT — PAGEINDEX_DSN/PGVECTOR_URL carry the
    # superuser `pai` role and happened to be checked before DATABASE_URL
    # (the least-privileged `noo_app`). NOO_MIGRATIONS_DSN makes the choice
    # explicit; the legacy fallback order is kept so existing installs keep
    # working unchanged.
    # In MEMORY mode (the noo-trellion container) the DDL identity comes
    # first: since noo-trellion #35 the memory env needs no superuser — the
    # broker owns extensions and roles — so the chain runs as
    # noo_trellion_ddl, CREATE on schema trellion and nothing else. The
    # legacy chain falls through to the privileged DSNs unchanged.
    dsn = (
        (os.environ.get("NOO_TRELLION_DDL_DATABASE_URL") if envs == "memory" else None)
        or os.environ.get("NOO_MIGRATIONS_DSN")
        or os.environ.get("PAGEINDEX_DSN")
        or os.environ.get("PGVECTOR_URL")
        or os.environ.get("DATABASE_URL")
    )
    if not dsn:
        print("[entrypoint] No DB DSN found (PAGEINDEX_DSN/PGVECTOR_URL/DATABASE_URL) — skipping migrations")
        return

    # Force the psycopg v3 driver explicitly for everything downstream.
    # pyproject ships psycopg[binary]>=3.1; the legacy `postgresql://`
    # scheme would have SQLAlchemy (and Alembic's env.py) reach for
    # psycopg2 — not installed — and fail with `No module named
    # 'psycopg2'`. Normalize once at the top so connectivity probe AND
    # alembic upgrade both use the right driver.
    dsn = dsn.replace("postgresql+asyncpg://", "postgresql+psycopg://")
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]

    # Wait for the DB to accept connections. Postgres often takes a few
    # seconds longer than the gateway container to come up.
    deadline = time.time() + 60
    last_err = None
    while time.time() < deadline:
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(dsn, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            engine.dispose()
            break
        except Exception as exc:
            last_err = exc
            time.sleep(2)
    else:
        print(f"[entrypoint] DB never became ready within 60s: {last_err}", file=sys.stderr)
        sys.exit(1)

    # EXACTLY ONE ENGINE MAY OWN THE MESH ENV.
    #
    # NOO_MESH_MIGRATOR=sqlx hands mesh to the Rust runner, which applies it
    # after this process exec()s the gateway. Alembic must then not touch
    # mesh, or two engines race to create the same tables on a fresh install
    # and the loser dies on "already exists" — the same one-owner rule the
    # scheduler engine has for tasks.dispatch.*.
    #
    # Parsed the SAME way as Engine::parse in mesh_migrate.rs: the Rust
    # runner is the DEFAULT now, and only an exact "alembic" opts back out.
    # Mirroring one negated literal is what keeps the two parsers in step; a
    # test asserts it. The dangerous disagreement is asymmetric — Python
    # handing mesh over while Rust does not take it leaves a fresh install
    # with no schema at all.
    mesh_owner_is_rust = (
        os.environ.get("NOO_MESH_MIGRATOR", "").strip().lower() != "alembic"
    )
    if mesh_owner_is_rust and envs in ("all", "mesh"):
        new = "memory" if envs == "all" else None
        _raw = os.environ.get("NOO_MESH_MIGRATOR", "").strip() or "<unset, default sqlx>"
        print(
            f"[entrypoint] NOO_MESH_MIGRATOR={_raw} — mesh env is owned by "
            f"the Rust runner; alembic scope {envs!r} -> {new or 'NOTHING'}"
        )
        if new is None:
            # Nothing left for Alembic here, and nothing to wait for either:
            # the wait existed for the cross-domain FK (0003), which phase C
            # deleted — mesh no longer creates anything on a memory-env
            # table, so one system's boot no longer blocks on another's
            # schema. That was the point.
            print("[entrypoint] nothing for alembic — handing off to the Rust runner")
            return
        envs = new

    try:
        from noomesh.db.migration_runner import upgrade
        if envs == "mesh":
            print(
                "[entrypoint] alembic mode: MESH-ONLY (NOO_MIGRATIONS_ENVS="
                "mesh) — memory env is owned by the noo-trellion container"
            )
        elif envs == "memory":
            print(
                "[entrypoint] alembic mode: MEMORY-ONLY (NOO_MIGRATIONS_ENVS="
                "memory) — mesh env is owned by the gateway container"
            )
        else:
            print("[entrypoint] alembic mode: ALL (memory + mesh envs)")
        upgrade(dsn, "heads", envs=envs)
        print(f"[entrypoint] alembic upgrade complete (envs={envs})")
    except Exception as exc:
        print(f"[entrypoint] alembic upgrade FAILED: {exc}", file=sys.stderr)
        sys.exit(1)




def main():
    """Apply pending migrations, then exec the gateway.

    MIGRATIONS ONLY. PKI staging, CA-bundle install, Claude settings merge
    and git identity moved into the Rust binary (gateway-rust
    src/startup_tasks.rs) — they were the last reasons this
    image needed a shell and a `git` binary, and removing them is what lets
    the runtime move to the shell-less hardened base.

    This wrapper survives only because the mesh schema is still an Alembic
    chain. When an earlier change ports it to sqlx, this file goes away and the
    container's ENTRYPOINT becomes the binary itself.

    Ordering note: the Rust tasks run AFTER this process execs, so nothing
    here may depend on them. The one thing the migration connection needs
    from the PKI — a 0600 copy of the client key the DSN names — is staged
    here first (stage_pg_client_keys); the CA it verifies against is the
    DSN's `sslrootcert`, so the system-bundle install is not a prerequisite.
    """
    stage_pg_client_keys()
    run_migrations()

    # Exec the container CMD (Rust gateway binary, or whatever docker
    # exec / compose `command:` passed). There is no default fallback —
    # the Python FastAPI gateway (noomesh.gateway.app) was deleted;
    # the Rust gateway is the only engine.
    if len(sys.argv) > 1:
        os.execvp(sys.argv[1], sys.argv[1:])

    print(
        "[entrypoint] ERROR: no command given. The Python gateway was "
        "removed; supply a CMD (e.g. /usr/local/bin/noo-gateway).",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
