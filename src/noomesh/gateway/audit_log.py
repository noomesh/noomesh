# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Persistent security audit logging.

ℹ️ LIVE PYTHON LIBRARY — Schema owner per RUST_PYTHON_SPLIT.md. Rust
``routes/admin.rs`` exposes ``/api/security/audit-history`` and
``/api/security/audit/stats`` (read-side) by querying the same Postgres
table this module writes to. Python writers (this module) stay live;
Rust handles read-side reporting.

Writes security events to structlog, PostgreSQL ``noo_security_audit`` table,
and an optional rotating log file.  Singleton pattern following the project
convention: ``init_audit_logger()`` / ``get_audit_logger()`` / ``audit()``.

Event types:
    auth_success, auth_failure, cluster_auth_failure, node_agent_blocked,
    exec_approved, exec_denied, admin_action, rate_limit, path_traversal
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

import hashlib
import hmac

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Audit integrity (CRIT-6)
# ---------------------------------------------------------------------------
# Per-row keyed hash for tamper-evidence. BOTH writers (this module and the Rust
# gateway, `routes/core.rs::write_audit_row`) MUST compute it identically.
#
# Version 2 — what both writers sign from v0.2.83 on, stored as
# `v2:<hex>`: HMAC-SHA256 over `canonical_v2`, which covers EVERY column but
# entry_hash itself — id, the time, event_type, severity, actor, resource,
# outcome, request_id, details and prev_hash — each length-prefixed, NULL
# distinct from "". Two values are taken as STORED, not as held in memory:
#   * the time is integer microseconds since the epoch of the datetime this
#     writer binds (timestamptz keeps microseconds; so does datetime), never
#     the float `AuditEvent.timestamp`;
#   * `details` is Postgres's own jsonb text for the value, asked for with
#     `SELECT CAST(:d AS jsonb)::text` before signing — jsonb re-orders keys
#     and re-spaces on store, and the verifier reads `details::text`.
#
# Version 1 — what both writers signed up to v0.2.82, a bare 64-hex hash: the
# six varchar fields below joined by the unit separator. It covered neither
# the time, the id nor details. Kept here only so the shared vector still pins
# it; the gateway verifies every row written before the hash-v2 marker with it.
#
# ⚠️ If you change either form here, change it in
# gateway-rust/src/audit_integrity.rs (`row_hash_with` / `canonical_v2`) too,
# and the shared vectors in tests/fixtures/audit_hash_v2_vectors.json, or
# verification breaks.
#
# The key is NOO_AUDIT_HMAC_KEY and nothing else. It used to fall back to a
# derivation of NOO_JWT_SECRET (and, without that, to a public literal), which
# let anyone holding the login secret re-sign an edited row. That derivation
# now exists only in the gateway, as a VERIFY-ONLY key for rows written before
# the audit-key checkpoint; the verifier is the gateway's
# `GET /api/security/audit/verify` (`noo security audit verify`), because only
# the gateway holds both keys. Without the key a row is REFUSED, loudly.
_AUDIT_HASH_SEP = "\x1f"


class AuditKeyMissing(RuntimeError):
    """NOO_AUDIT_HMAC_KEY is not available to this process: the row is refused."""


def _audit_hmac_key() -> bytes:
    """The dedicated audit HMAC key. Raises AuditKeyMissing when unset — there
    is deliberately no fallback."""
    from ..secret_env import secret_or_empty

    key = secret_or_empty("NOO_AUDIT_HMAC_KEY")
    if not key:
        raise AuditKeyMissing(
            "NOO_AUDIT_HMAC_KEY is not set; security audit rows are refused "
            "(run `noo upgrade --stack`, which mints it when absent and recreates the stack)"
        )
    return key.encode("utf-8")


def audit_row_hash(event_type: str, severity: str, actor: str, resource: str,
                   outcome: str, request_id: str) -> str:
    """The v1 hash (verify-only since v0.2.83; no writer signs it). Mirror of
    the Rust `row_hash_with`. Raises AuditKeyMissing without the key."""
    canonical = _AUDIT_HASH_SEP.join(
        (event_type, severity, actor, resource, outcome, request_id or "")
    )
    return hmac.new(_audit_hmac_key(), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


_V2_PREFIX = "v2:"
_V2_DOMAIN = "noo-audit-row-v2"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def stored_micros(ts: datetime) -> int:
    """Integer microseconds since the epoch of an aware datetime — exact, no
    float. This is the value timestamptz stores for `ts`."""
    return (ts - _EPOCH) // timedelta(microseconds=1)


def canonical_v2(*, id: str, timestamp_us: int, event_type: str, severity: str,
                 actor: str, resource: str, outcome: str, request_id: Optional[str],
                 details: Optional[str], prev_hash: Optional[str]) -> bytes:
    """The v2 canonical form: `noo-audit-row-v2`, then per column, in this
    order, `\\n<name>=` and `-` for NULL or `<utf-8 byte length>:<value>`.
    Mirror of the Rust `audit_integrity::canonical_v2`, byte for byte."""
    out = _V2_DOMAIN.encode("utf-8")
    for name, value in (
        ("id", id),
        ("timestamp_us", str(int(timestamp_us))),
        ("event_type", event_type),
        ("severity", severity),
        ("actor", actor),
        ("resource", resource),
        ("outcome", outcome),
        ("request_id", request_id),
        ("details", details),
        ("prev_hash", prev_hash),
    ):
        out += b"\n" + name.encode("utf-8") + b"="
        if value is None:
            out += b"-"
        else:
            b = value.encode("utf-8")
            out += str(len(b)).encode("ascii") + b":" + b
    return out


def audit_row_hash_v2(*, key: Optional[bytes] = None, **fields: Any) -> str:
    """`v2:` + HMAC-SHA256 over `canonical_v2(**fields)`. The key defaults to
    NOO_AUDIT_HMAC_KEY; raises AuditKeyMissing without it."""
    k = _audit_hmac_key() if key is None else key
    return _V2_PREFIX + hmac.new(k, canonical_v2(**fields), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# The hash chain (deletion evidence)
# ---------------------------------------------------------------------------
# Every row is also LINKED to the one before it: `chain_seq` (gapless) and
# `chain_hash` = HMAC(audit key, domain | seq | previous chain_hash | this
# row's entry_hash). Delete or reorder a middle row and the link breaks,
# which the per-row hash cannot show. All four writers (the gateway and the
# Python containers) take the SAME transaction-scoped advisory lock, read the
# newest chained row, choose a time no earlier than its, sign, insert and
# commit, so concurrent writers cannot fork the chain. The application role is
# INSERT-only (migration 092), so a row cannot be sealed after the fact: the
# link is made at insert or not at all.
#
# A writer that finds NO chained row yet (the gateway has not written the
# genesis row) inserts an unchained row; the genesis' keyed digest covers it.
#
# ⚠️ Mirror of gateway-rust/src/audit_chain.rs (`chain_hash`, `CHAIN_LOCK_KEY`),
# pinned by tests/fixtures/audit_chain_vectors.json.
CHAIN_LOCK_KEY = 0x6E6F6F5F61756474  # ASCII "noo_audt"
_CHAIN_DOMAIN = "noo-audit-chain-v1"
RETENTION_EVENT = "audit_retention_checkpoint"


def chain_hash(*, key: bytes, seq: int, prev: str, entry_hash: str) -> str:
    """Hex HMAC-SHA256 of one link; length-prefixed like the row form."""
    canonical = (
        f"{_CHAIN_DOMAIN}\nseq={int(seq)}\n"
        f"prev={len(prev.encode('utf-8'))}:{prev}\n"
        f"entry={len(entry_hash.encode('utf-8'))}:{entry_hash}"
    )
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _refuse_unsigned(event: "AuditEvent", exc: AuditKeyMissing) -> None:
    # error, every time: an audit row that was not recorded is not a debug line.
    logger.error("audit_write_refused_no_key", error=str(exc),
                 event_type=event.event_type, actor=event.actor)


# ---------------------------------------------------------------------------
# AuditEvent dataclass
# ---------------------------------------------------------------------------

SEVERITIES = ("info", "warning", "error", "critical")


@dataclass
class AuditEvent:
    event_type: str
    severity: str = "info"
    actor: str = ""
    resource: str = ""
    outcome: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


# ---------------------------------------------------------------------------
# The one row both DB sinks write
# ---------------------------------------------------------------------------

_INSERT_SQL = (
    "INSERT INTO noo_security_audit "
    "(id, timestamp, event_type, severity, actor, resource, outcome, details, request_id, "
    "entry_hash, chain_seq, chain_hash) "
    "VALUES (:id, :ts, :et, :sev, :actor, :resource, :outcome, :details, :rid, :eh, :seq, :ch)"
)

# Only for a database that has not run migration 092 yet (a worker that starts
# before the gateway has migrated): the row is recorded unchained, never lost.
_INSERT_UNCHAINED_SQL = (
    "INSERT INTO noo_security_audit "
    "(id, timestamp, event_type, severity, actor, resource, outcome, details, request_id, entry_hash) "
    "VALUES (:id, :ts, :et, :sev, :actor, :resource, :outcome, :details, :rid, :eh)"
)

_LOCK_SQL = "SELECT pg_advisory_xact_lock(:k)"
_TAIL_SQL = (
    "SELECT chain_seq, chain_hash, timestamp FROM noo_security_audit "
    "WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1"
)


def _no_chain_columns(exc: BaseException) -> bool:
    """Is this the error of a database without migration 092's columns?"""
    msg = str(exc)
    return "chain_seq" in msg and "does not exist" in msg


def _canonical_details_sql():
    """Postgres's jsonb text for a value — what `details::text` reads back."""
    from sqlalchemy import text

    return text("SELECT CAST(:d AS jsonb)::text")


def _details_json(event: "AuditEvent") -> str:
    import json

    return json.dumps(event.details)


def _signed_params(event: "AuditEvent", key: bytes, details: str, tail=None) -> dict:
    """The insert's parameters, signed v2 and, given the newest chained row
    `tail` = (chain_seq, chain_hash, timestamp), linked after it. `ts` is the
    datetime bound to the column, so the hashed microseconds are the stored
    ones; `details` is Postgres's own text for the value
    (`_canonical_details_sql`). With a tail the time is never earlier than the
    tail's, which keeps a monthly partition's seq range contiguous."""
    ts = datetime.fromtimestamp(event.timestamp, tz=timezone.utc)
    if tail is not None:
        tail_ts = tail[2]
        if tail_ts.tzinfo is None:
            tail_ts = tail_ts.replace(tzinfo=timezone.utc)
        tail_ts = tail_ts.astimezone(timezone.utc)
        if ts < tail_ts:
            ts = tail_ts
    row_id = str(uuid.uuid4())
    entry_hash = audit_row_hash_v2(
        key=key, id=row_id, timestamp_us=stored_micros(ts), event_type=event.event_type,
        severity=event.severity, actor=event.actor, resource=event.resource,
        outcome=event.outcome, request_id=event.request_id, details=details, prev_hash=None,
    )
    seq = chain = None
    if tail is not None:
        seq = int(tail[0]) + 1
        chain = chain_hash(key=key, seq=seq, prev=tail[1], entry_hash=entry_hash)
    return {
        "id": row_id,
        "ts": ts,
        "et": event.event_type,
        "sev": event.severity,
        "actor": event.actor,
        "resource": event.resource,
        "outcome": event.outcome,
        "details": details,
        "rid": event.request_id,
        "eh": entry_hash,
        "seq": seq,
        "ch": chain,
    }


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Write security audit events to multiple sinks."""

    def __init__(self, db_engine=None, log_file: Optional[str] = None, async_engine=None):
        # `db_engine` is a SYNC SQLAlchemy Engine (app.py lifespan path).
        # `async_engine` is an AsyncEngine (worker_pool path — the live prod
        # process, where only trellion's async engine is available). Exactly
        # one is normally set; if both are, the sync engine wins for _write_db.
        self._db_engine = db_engine
        self._async_engine = async_engine
        # Retain in-flight async write tasks so they aren't GC'd mid-flight
        # ("Task was destroyed but it is pending").
        self._pending: set = set()
        self._log_file = log_file
        self._file_handle = None
        if log_file:
            try:
                self._file_handle = open(log_file, "a", encoding="utf-8")
            except OSError as exc:
                logger.warning("audit_log_file_open_failed", path=log_file, error=str(exc))

    def log(self, event: AuditEvent) -> None:
        """Write event to all configured sinks."""
        # 1. Structlog (always)
        log_fn = getattr(logger, event.severity if event.severity in SEVERITIES else "info")
        log_fn(
            "security_audit",
            event_type=event.event_type,
            actor=event.actor,
            resource=event.resource,
            outcome=event.outcome,
            request_id=event.request_id,
            **event.details,
        )

        # 2. PostgreSQL (best-effort, non-blocking)
        if self._db_engine is not None:
            try:
                self._write_db(event)
            except Exception as exc:
                # WARNING, not debug: this is a security audit row that was
                # NOT recorded. Logged at debug, a total write failure is
                # indistinguishable from a quiet system — which is how the
                # missing-partition bug (tracker R44) went unnoticed on every
                # fresh install. Still best-effort; still never raises.
                logger.warning("audit_db_write_failed", error=str(exc),
                               event_type=event.event_type, actor=event.actor)
        elif self._async_engine is not None:
            # Live prod (worker_pool) only has an AsyncEngine. audit() is a sync
            # fire-and-forget call made from async handler contexts, so schedule
            # the write on the running loop. If there is no loop (audit called
            # from a non-async context), the DB sink is skipped — structlog +
            # file already captured the event above.
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(self._write_db_async(event))
                self._pending.add(task)
                task.add_done_callback(self._pending.discard)
            except RuntimeError:
                logger.debug("audit_db_async_no_loop", event_type=event.event_type)

        # 3. File (best-effort)
        if self._file_handle is not None:
            try:
                import json

                line = json.dumps(asdict(event), default=str)
                self._file_handle.write(line + "\n")
                self._file_handle.flush()
            except Exception:
                pass

    def _write_db(self, event: AuditEvent) -> None:
        """Insert audit row into PostgreSQL, signed with hash v2 and linked into the chain."""
        from sqlalchemy import text

        try:
            key = _audit_hmac_key()
        except AuditKeyMissing as exc:
            _refuse_unsigned(event, exc)
            return
        with self._db_engine.connect() as conn:
            details = conn.execute(_canonical_details_sql(), {"d": _details_json(event)}).scalar_one()
            sql = _INSERT_SQL
            try:
                # Held until commit: the next writer reads the tail only after this row is in.
                conn.execute(text(_LOCK_SQL), {"k": CHAIN_LOCK_KEY})
                tail = conn.execute(text(_TAIL_SQL)).first()
            except Exception as exc:
                if not _no_chain_columns(exc):
                    raise
                conn.rollback()
                tail, sql = None, _INSERT_UNCHAINED_SQL
            params = _signed_params(event, key, details, tail)
            if sql is _INSERT_UNCHAINED_SQL:
                params = {k: v for k, v in params.items() if k not in ("seq", "ch")}
            conn.execute(text(sql), params)
            conn.commit()

    async def _write_db_async(self, event: AuditEvent) -> None:
        """Insert audit row via an AsyncEngine (worker_pool / Rust-primary mode).

        Mirrors ``_write_db`` but uses the async connection API. Best-effort:
        a failed write must never break the caller's request path.
        """
        from sqlalchemy import text

        try:
            key = _audit_hmac_key()
        except AuditKeyMissing as exc:
            _refuse_unsigned(event, exc)
            return
        try:
            async with self._async_engine.connect() as conn:
                details = (await conn.execute(
                    _canonical_details_sql(), {"d": _details_json(event)})).scalar_one()
                sql = _INSERT_SQL
                try:
                    await conn.execute(text(_LOCK_SQL), {"k": CHAIN_LOCK_KEY})
                    tail = (await conn.execute(text(_TAIL_SQL))).first()
                except Exception as exc:
                    if not _no_chain_columns(exc):
                        raise
                    await conn.rollback()
                    tail, sql = None, _INSERT_UNCHAINED_SQL
                params = _signed_params(event, key, details, tail)
                if sql is _INSERT_UNCHAINED_SQL:
                    params = {k: v for k, v in params.items() if k not in ("seq", "ch")}
                await conn.execute(text(sql), params)
                await conn.commit()
        except Exception as exc:
            # See _write_db: a lost audit row is a warning, not a debug line.
            logger.warning("audit_db_async_write_failed", error=str(exc),
                           event_type=event.event_type, actor=event.actor)

    def close(self) -> None:
        if self._file_handle is not None:
            self._file_handle.close()
            self._file_handle = None


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_audit_logger: Optional[AuditLogger] = None


def audit_sink_engine(env: Optional[Mapping[str, str]] = None):
    """The AsyncEngine the DB sink writes ``noo_security_audit`` with, or
    ``(None, reason)``.

    The table lives in the ``mesh`` schema and only the app role
    (``DATABASE_URL``) may insert into it. Until 2026-09-16 the worker
    handed the sink trellion's engine instead — the scoped ``noo_trellion``
    role with ``search_path=trellion,public``, which cannot see the table —
    so every Python-emitted security event failed with
    ``relation "noo_security_audit" does not exist`` and the audit trail
    held no worker rows at all. This engine is the app role's, pinned to
    the mesh schema, and small: the sink writes one row per event.
    """
    env = os.environ if env is None else env
    dsn = env.get("DATABASE_URL", "")
    if not dsn:
        return None, "DATABASE_URL is not set; structlog + file sinks only"
    from sqlalchemy.ext.asyncio import create_async_engine

    from ..db.engine import _async_dsn

    engine = create_async_engine(
        _async_dsn(dsn),
        pool_size=2,
        max_overflow=2,
        pool_pre_ping=True,
        pool_recycle=3600,
        connect_args={"options": "-csearch_path=mesh,public"},
    )
    return engine, "app role, search_path=mesh,public"


def init_audit_logger(
    db_engine=None, log_file: Optional[str] = None, async_engine=None
) -> AuditLogger:
    global _audit_logger
    _audit_logger = AuditLogger(
        db_engine=db_engine, log_file=log_file, async_engine=async_engine
    )
    return _audit_logger


def get_audit_logger() -> Optional[AuditLogger]:
    return _audit_logger


def audit(
    event_type: str,
    *,
    severity: str = "info",
    actor: str = "",
    resource: str = "",
    outcome: str = "",
    **details: Any,
) -> None:
    """Convenience function — fire-and-forget audit event."""
    al = _audit_logger
    if al is None:
        return
    al.log(
        AuditEvent(
            event_type=event_type,
            severity=severity,
            actor=actor,
            resource=resource,
            outcome=outcome,
            details=details,
        )
    )


# The verifier is the gateway's (gateway-rust/src/audit_integrity.rs): it needs
# the retired NOO_JWT_SECRET derivation for rows before the audit-key
# checkpoint, and this process is not meant to hold that secret.
