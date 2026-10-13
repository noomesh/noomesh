# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared sync + async SQLAlchemy engine pool.

Replaces 7+ independent ``psycopg.connect()`` calls with a single
connection pool that all store modules share.

Public API:
    init_db(dsn)           -- create engines, ensure extensions, run migrations
    get_engine()           -- sync Engine  (heartbeat, conversation, etc.)
    get_async_engine()     -- AsyncEngine  (node_store, pageindex_store)
    close_engines()        -- dispose pools on shutdown
"""

from __future__ import annotations

import structlog
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

logger = structlog.get_logger(__name__)

_engine: Optional[Engine] = None
_async_engine: Optional[AsyncEngine] = None


def _libpq_accepts_key(mode: int, st_uid: int) -> bool:
    """libpq's client-key permission rule, exactly (fe-secure-openssl.c,
    REL_16/17/18 and master; the images ship libpq 18.6 in psycopg-binary):

        if (buf.st_uid == 0 ?
            buf.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO) :
            buf.st_mode & (S_IRWXG | S_IRWXO))  -> refuse

    Root-owned: 0640 or less. Owned by anyone else: 0600 or less. 0640
    owned by a non-root uid (0640 + an ACL for uid 65532, owned by the
    operator: the fix-modes shape) is REFUSED. libpq does not compare
    st_uid to the euid. MUST stay identical to
    docker/entrypoint.py::_libpq_accepts_key (parity test in
    tests/test_pg_client_key_perms.py)."""
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
    """Return a Postgres client key path libpq will accept, or "".

    libpq refuses a client key that fails its permission rule
    (_libpq_accepts_key): 0600 or less, or 0640 or less when ROOT owns
    it. The cluster's leaf keys are readable by non-root service
    containers through the ro PKI mount (0644, or 0640 + an ACL owned by
    the operator) — both refused. Since 2026-09-28 Postgres requires a
    client certificate from every TCP client (docker/postgres/pg_hba.conf),
    so "drop the cert and fall back to a password" is no longer a
    connection that works — the key has to be usable.

    So: if the resolved key passes libpq's rule, use it. Otherwise STAGE
    it: copy it to a private 0600 file, owned by this process, under
    /tmp/pki at the same relative path (`/app/pki/gateway/gateway.key` →
    `/tmp/pki/gateway/gateway.key`, the layout the gateway's stage_pki and
    docker/entrypoint.py produce, so every process in a container agrees
    on where the copy is), reusing an existing copy only when it still
    passes and holds the same bytes (a rotated key restages). Only when
    even that fails (read-only /tmp, unreadable source) return "" — the
    caller then connects without the cert and Postgres refuses it with a
    message that names the certificate, which beats a cryptic libpq error.
    """
    import os as _os
    import shutil as _shutil
    import stat as _stat

    if not path or not _os.path.isfile(path):
        return path  # nothing to validate; caller handles empty/missing
    try:
        st = _os.stat(path)
    except OSError:
        return path
    mode = _stat.S_IMODE(st.st_mode)
    if _libpq_accepts_key(mode, st.st_uid):
        return path

    private = _staged_key_path(path)
    try:
        if _os.path.isfile(private):
            pst = _os.stat(private)
            if _libpq_accepts_key(pst.st_mode, pst.st_uid) and _same_bytes(path, private):
                logger.info("pg_client_key_using_private_copy", original=path, using=private)
                return private
        _os.makedirs(_os.path.dirname(private), mode=0o700, exist_ok=True)
        _shutil.copyfile(path, private)
        _os.chmod(private, 0o600)
        logger.info("pg_client_key_staged", original=path, using=private,
                    mode=oct(mode), owner_uid=st.st_uid)
        return private
    except OSError as exc:
        logger.warning(
            "pg_client_key_refused_and_unstageable",
            key=path, mode=oct(mode), owner_uid=st.st_uid, error=str(exc),
            detail="libpq refuses this client key (0600 or less, or 0640 or less "
                   "if root-owned) and the 0600 copy could not be written; "
                   "Postgres will refuse this client")
        return ""


def _staged_key_path(path: str) -> str:
    """Where the 0600 copy of a mounted key lives: the mount root
    (`/app/pki/` or `/tls/`) replaced by `/tmp/pki/`; anything else is
    mirrored under `/tmp/pki` by its full path."""
    for root in ("/app/pki/", "/tls/"):
        if path.startswith(root):
            return "/tmp/pki/" + path[len(root):]
    return "/tmp/pki" + path


def _stage_dsn_client_key(url: str) -> str:
    """A DSN that names `sslkey=<mount path>` (every compose DSN does since
    2026-09-28) gets the staged path substituted, by the same rule as the
    env-derived key above. Leaves the DSN alone when the key is fine."""
    import re as _re
    m = _re.search(r"([?&])sslkey=([^&]+)", url)
    if not m:
        return url
    from urllib.parse import unquote as _unquote
    key = _unquote(m.group(2))
    usable = _usable_client_key(key)
    if not usable or usable == key:
        return url
    return url[: m.start(2)] + usable + url[m.end(2):]


def _sync_dsn(dsn: str) -> str:
    """Ensure DSN uses psycopg sync driver, with a client key libpq accepts.

    Every DSN this package hands to libpq passes here (init_db, the audit
    sink, HeartbeatStore's DSN path, the migration runner), so this is
    where `sslkey=` is staged: a process with no entrypoint env rewrite
    (noo-worker) otherwise passes libpq a key it refuses."""
    return _stage_dsn_client_key(_psycopg_scheme(dsn))


def _psycopg_scheme(dsn: str) -> str:
    if dsn.startswith("postgresql+psycopg://"):
        return dsn
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn.replace("postgresql+asyncpg://", "postgresql+psycopg://")
    if dsn.startswith("postgresql://"):
        return dsn.replace("postgresql://", "postgresql+psycopg://", 1)
    if dsn.startswith("postgres://"):
        return dsn.replace("postgres://", "postgresql+psycopg://", 1)
    return dsn


def _async_dsn(dsn: str) -> str:
    """Ensure DSN uses psycopg async driver (psycopg3 is async natively),
    with the client key staged exactly as _sync_dsn does."""
    return _sync_dsn(dsn)


async def init_db(dsn: str, run_migrations: bool = True) -> None:
    """Create engine pool, ensure extensions, optionally run Alembic migrations.

    This is the single entry point called from ``app.py`` lifespan.
    """
    global _engine, _async_engine

    sync_url = _sync_dsn(dsn)
    async_url = _async_dsn(dsn)

    # Append PostgreSQL sslmode if configured via env, config, or TLS setup
    import os as _os
    _pg_sslmode = _os.getenv("NOO_PG_SSLMODE", "")
    if not _pg_sslmode:
        # Fall back to config field if available
        try:
            from ..config import get_config
            _cfg = get_config()
            if hasattr(_cfg, "security") and _cfg.security.postgres_sslmode:
                _pg_sslmode = _cfg.security.postgres_sslmode
        except Exception:
            pass
    if _pg_sslmode and "sslmode=" not in sync_url:
        _sep = "&" if "?" in sync_url else "?"
        sync_url += f"{_sep}sslmode={_pg_sslmode}"
        async_url += f"{_sep}sslmode={_pg_sslmode}"
    _pg_sslrootcert = _os.getenv("NOO_PG_SSLROOTCERT", "")
    if not _pg_sslrootcert:
        # Fall back to config field, then cluster CA
        try:
            from ..config import get_config
            _cfg = get_config()
            if hasattr(_cfg, "security") and _cfg.security.postgres_sslrootcert:
                _pg_sslrootcert = _cfg.security.postgres_sslrootcert
        except Exception:
            pass
    if not _pg_sslrootcert:
        # Use cluster CA as default root cert if available
        _tls_ca = _os.getenv("NOO_TLS_CA", "")
        if _tls_ca and _os.path.exists(_tls_ca):
            _pg_sslrootcert = _tls_ca
    if _pg_sslrootcert and "sslrootcert=" not in sync_url:
        _sep = "&" if "?" in sync_url else "?"
        sync_url += f"{_sep}sslrootcert={_pg_sslrootcert}"
        async_url += f"{_sep}sslrootcert={_pg_sslrootcert}"

    # mTLS: present client cert + key to PostgreSQL. Resolve the KEY first
    # and validate its perms — libpq requires cert AND key together, so if
    # the key is unusable (0644 mount path in a non-entrypoint context) we
    # must drop BOTH and fall back to password auth over verified TLS,
    # rather than send a cert with no (usable) key.
    _pg_sslcert = _os.getenv("NOO_TLS_CERT", "")
    _pg_sslkey = _os.getenv("NOO_TLS_KEY", "")
    if not _pg_sslcert or not _pg_sslkey:
        try:
            from ..config import get_config
            _cfg = get_config()
            if hasattr(_cfg, "tls"):
                _pg_sslcert = _pg_sslcert or _cfg.tls.postgres_sslcert
                _pg_sslkey = _pg_sslkey or _cfg.tls.postgres_sslkey
        except Exception:
            pass
    _pg_sslkey = _usable_client_key(_pg_sslkey)
    if _pg_sslcert and _pg_sslkey and "sslkey=" not in sync_url:
        _sep = "&" if "?" in sync_url else "?"
        _pair = f"sslcert={_pg_sslcert}&sslkey={_pg_sslkey}"
        sync_url += f"{_sep}{_pair}"
        async_url += f"{_sep}{_pair}"
    # A DSN that already carries the pair (compose) still needs the key
    # staged for libpq — same rule, applied to the URL's own path.
    sync_url = _stage_dsn_client_key(sync_url)
    async_url = _stage_dsn_client_key(async_url)

    # H-D2: surface / enforce Postgres TLS. An empty or weak sslmode lets libpq
    # default to "prefer", which silently downgrades to plaintext if the server
    # doesn't offer TLS. Warn when it isn't a verifying/encrypting mode; fail
    # closed when NOO_PG_TLS_REQUIRED is set. Default = warn only (non-breaking);
    # flip to enforcement once the server has hostssl + you've set
    # NOO_PG_SSLMODE=verify-full (with NOO_PG_SSLROOTCERT / NOO_TLS_CA).
    _secure_sslmodes = ("require", "verify-ca", "verify-full")
    if _pg_sslmode not in _secure_sslmodes:
        _tls_msg = (
            f"PostgreSQL TLS not enforced (sslmode={_pg_sslmode or 'unset->prefer'}): "
            "the connection may be unencrypted or downgradeable. Set "
            "NOO_PG_SSLMODE=verify-full (+ NOO_PG_SSLROOTCERT/NOO_TLS_CA) once the "
            "server has TLS; set NOO_PG_TLS_REQUIRED=1 to fail closed."
        )
        if _os.getenv("NOO_PG_TLS_REQUIRED", "").strip().lower() in ("1", "true", "yes"):
            raise RuntimeError("NOO_PG_TLS_REQUIRED is set but " + _tls_msg)
        try:
            import structlog as _structlog
            _structlog.get_logger(__name__).warning("postgres_tls_unenforced", detail=_tls_msg)
        except Exception:
            import warnings as _warnings
            _warnings.warn(_tls_msg)

    _pool_size = max(10, (_os.cpu_count() or 4) * 2)

    _engine = create_engine(
        sync_url,
        pool_size=_pool_size,
        max_overflow=20,
        pool_timeout=30,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    _async_engine = create_async_engine(
        async_url,
        pool_size=_pool_size,
        max_overflow=20,
        pool_timeout=30,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

    # Share engines with trellion so its stores reuse the same connection
    # pool (avoids opening a second pool against the same Postgres).
    try:
        from trellion.db.engine import set_engines as _set_trellion_engines
        _set_trellion_engines(_engine, _async_engine)
    except ImportError:
        # Trellion not installed — memory features unavailable but mesh
        # core can still run. Logged at debug since this is expected in
        # minimal installs.
        logger.debug("trellion_not_installed_memory_features_disabled")

    # Ensure required PostgreSQL extensions — CHECK-THEN-ACT, not
    # `IF NOT EXISTS`. Postgres verifies the privilege BEFORE the guard
    # (noo-evolve#7), and both extensions are untrusted, so the guarded form
    # raises for any non-superuser even when the extensions already exist.
    # That made this line the second blocker to de-privileging the runtime
    # DSNs: every worker start would have failed here for work
    # that was already done. Under a superuser the behavior is unchanged;
    # under anything else, presence is the success condition and creation is
    # only ATTEMPTED when genuinely missing — where a loud failure is
    # correct, because the broker (in-cluster) or the database owner
    # (standalone) was supposed to have installed it.
    with _engine.connect() as conn:
        for ext in ("vector", "pg_trgm"):
            present = conn.execute(
                text("SELECT 1 FROM pg_extension WHERE extname = :e"),
                {"e": ext},
            ).scalar()
            if not present:
                conn.execute(text(f"CREATE EXTENSION {ext}"))
        conn.commit()

    logger.info("db engines created, extensions ensured, shared with trellion")

    if run_migrations:
        _run_migrations(sync_url)


def _run_migrations(dsn: str) -> None:
    """Run Alembic upgrades on both envs (memory first, then mesh).

    The split into two envs landed in Phase 2 of the trellion extraction
    See ``noomesh.db.migration_runner`` for details and
    the legacy single-env upgrade shim that runs first on installs from
    the pre-split world.
    """
    from .migration_runner import upgrade as _upgrade

    _upgrade(dsn, "heads")
    logger.info("alembic migrations applied (memory + mesh envs)")


def get_engine() -> Engine:
    """Return the shared sync Engine.  Raises if ``init_db`` hasn't been called."""
    if _engine is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _engine


def get_async_engine() -> AsyncEngine:
    """Return the shared AsyncEngine.  Raises if ``init_db`` hasn't been called."""
    if _async_engine is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _async_engine


async def close_engines() -> None:
    """Dispose both engine pools.  Call from lifespan shutdown."""
    global _engine, _async_engine

    if _async_engine is not None:
        await _async_engine.dispose()
        _async_engine = None

    if _engine is not None:
        _engine.dispose()
        _engine = None

    logger.info("db engines closed")
