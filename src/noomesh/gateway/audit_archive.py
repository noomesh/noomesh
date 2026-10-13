# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Audit log partition lifecycle: create, export, drop.

ℹ️ LIVE PYTHON LIBRARY — Postgres partition lifecycle (DDL + cold-tier
export). No Rust counterpart found. Verify whether the partition
ensure/export/drop calls are still triggered in production (the Python
lifespan path is dead, so any startup hook here that relied on it is
silently not running). May need to move triggering to Rust startup or
to a heartbeat scheduler task once that's ported.

``noo_security_audit`` is a Postgres-level partitioned table (RANGE on
``timestamp``, monthly). This module provides the primitives:

  - ``ensure_partition(year, month)`` — create the child partition if
    missing. Called at startup for the current month and the upcoming
    month so inserts always have a target.
  - ``export_partition(year, month, cfg)`` — stream the partition's rows
    to the configured cold-tier backend (local dir / Azure / S3) as
    JSONL or Parquet.
  - ``drop_partition(year, month)`` — DETACH then DROP. Safe only after
    a verified export.
  - ``rotate(retention_months, cfg)`` — the orchestration entry point.
    Finds partitions older than retention, exports + drops each in turn.

The scheduled ``audit_log_rotate`` heartbeat action calls ``rotate``
monthly. Operators can also trigger it manually via
``noo security audit export <YYYY-MM>`` + ``noo security audit rotate``.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = structlog.get_logger(__name__)


# ── Partition helpers ─────────────────────────────────────────────────


def _partition_name(year: int, month: int) -> str:
    return f"noo_security_audit_{year:04d}_{month:02d}"


def _parse_partition_name(name: str) -> Optional[tuple[int, int]]:
    m = re.match(r"^noo_security_audit_(\d{4})_(\d{2})$", name)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


# ── Ensure partition ──────────────────────────────────────────────────


async def ensure_partition(engine: AsyncEngine, year: int, month: int) -> bool:
    """Create the partition for (year, month) if absent. Returns True if
    a partition was created, False if it already existed.

    Delegates to ``public.noo_ensure_audit_partition`` (migration 036) rather
    than issuing DDL directly. The gateway is moving to the non-superuser
    ``noo_app`` role, which has no CREATE on the schema — and ``IF NOT EXISTS``
    does not rescue that, because Postgres checks the privilege before the
    existence shortcut. The function is SECURITY DEFINER with a pinned
    search_path and builds the partition name internally from the integer
    arguments, so the caller cannot name an arbitrary table.

    The existence check lives inside the function too, so this is one round
    trip and there is no check-then-create race between two processes.
    """
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT noo_ensure_audit_partition(:y, :m)"),
            {"y": year, "m": month},
        )
        created = bool(result.scalar())
    if created:
        logger.info("audit_archive.partition_created", year=year, month=month)
    return created


async def ensure_current_and_next(engine: AsyncEngine) -> int:
    """At startup, make sure current and next month partitions exist so
    inserts never fail due to "no partition for this range"."""
    now = datetime.now(timezone.utc)
    next_month = 1 if now.month == 12 else now.month + 1
    next_year = now.year + 1 if now.month == 12 else now.year
    created = 0
    for (y, m) in [(now.year, now.month), (next_year, next_month)]:
        if await ensure_partition(engine, y, m):
            created += 1
    return created


# ── Listing ───────────────────────────────────────────────────────────


async def list_partitions(engine: AsyncEngine) -> list[tuple[int, int]]:
    """Return (year, month) tuples for every existing audit partition, sorted."""
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT relname FROM pg_class WHERE relname LIKE 'noo_security_audit_%' "
                "AND relkind = 'r'"
            )
        )
        parts: list[tuple[int, int]] = []
        for row in rows:
            parsed = _parse_partition_name(row[0])
            if parsed:
                parts.append(parsed)
    parts.sort()
    return parts


# ── Export ────────────────────────────────────────────────────────────


@dataclass
class ArchiveConfig:
    backend: str = "local_dir"
    format: str = "jsonl"
    local_dir: str = "./audit-archive"
    azure_container: str = "noo-audit-cold"
    azure_conn_env: str = "NOO_AUDIT_AZURE_CONN"
    s3_bucket: str = ""
    s3_region: str = "us-east-1"

    @classmethod
    def from_pydantic(cls, cfg: Any) -> "ArchiveConfig":
        return cls(
            backend=cfg.backend,
            format=cfg.format,
            local_dir=os.path.expandvars(os.path.expanduser(cfg.local_dir)),
            azure_container=cfg.azure_container,
            azure_conn_env=cfg.azure_conn_env,
            s3_bucket=cfg.s3_bucket,
            s3_region=cfg.s3_region,
        )


async def export_partition(
    engine: AsyncEngine,
    year: int,
    month: int,
    cfg: ArchiveConfig,
) -> Optional[str]:
    """Stream the partition's rows to cold storage. Returns the object URI
    (local path or blob path) on success, None on failure. Does not drop
    the partition — caller invokes drop_partition after verifying."""
    if cfg.backend == "none":
        logger.warning("audit_archive.export_skipped_backend_none", year=year, month=month)
        return None

    name = _partition_name(year, month)
    rows = await _fetch_partition_rows(engine, name)

    if cfg.backend == "local_dir":
        return _export_to_local(cfg, year, month, rows)
    if cfg.backend == "azure_blob":
        return await _export_to_azure(cfg, year, month, rows)
    if cfg.backend == "s3":
        return await _export_to_s3(cfg, year, month, rows)
    logger.error("audit_archive.export_unknown_backend", backend=cfg.backend)
    return None


async def _fetch_partition_rows(engine: AsyncEngine, partition_name: str) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                f'SELECT id::text, timestamp, event_type, severity, actor, resource, '
                f'outcome, details, request_id FROM "{partition_name}"'
            )
        )
        return [dict(r) for r in result.mappings()]


def _rows_to_jsonl(rows: Iterable[dict[str, Any]]) -> bytes:
    lines = []
    for row in rows:
        norm = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in row.items()
        }
        lines.append(json.dumps(norm, default=str))
    return ("\n".join(lines) + "\n").encode("utf-8") if lines else b""


def _export_to_local(
    cfg: ArchiveConfig, year: int, month: int, rows: list[dict[str, Any]]
) -> str:
    target_dir = Path(cfg.local_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    ext = "jsonl" if cfg.format == "jsonl" else "parquet"
    target = target_dir / f"noo_security_audit_{year:04d}_{month:02d}.{ext}"
    if cfg.format == "jsonl":
        target.write_bytes(_rows_to_jsonl(rows))
    else:
        _write_parquet(target, rows)
    size = target.stat().st_size
    logger.info(
        "audit_archive.exported_local",
        path=str(target),
        rows=len(rows),
        bytes=size,
    )
    return str(target)


def _write_parquet(target: Path, rows: list[dict[str, Any]]) -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as e:
        raise RuntimeError(
            "Parquet export requires 'pyarrow'. Install it or switch "
            "audit_archive.format to 'jsonl'."
        ) from e
    if not rows:
        pq.write_table(pa.table({}), target)
        return
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, target)


async def _export_to_azure(
    cfg: ArchiveConfig, year: int, month: int, rows: list[dict[str, Any]]
) -> Optional[str]:
    conn_str = os.getenv(cfg.azure_conn_env)
    if not conn_str:
        logger.error(
            "audit_archive.azure_conn_missing",
            env_var=cfg.azure_conn_env,
        )
        return None
    try:
        from azure.storage.blob.aio import BlobServiceClient
    except ImportError:
        logger.error("audit_archive.azure_sdk_missing")
        return None
    ext = "jsonl" if cfg.format == "jsonl" else "parquet"
    blob_name = f"noo_security_audit_{year:04d}_{month:02d}.{ext}"
    data = (
        _rows_to_jsonl(rows) if cfg.format == "jsonl"
        else _parquet_bytes(rows)
    )
    async with BlobServiceClient.from_connection_string(conn_str) as svc:
        container = svc.get_container_client(cfg.azure_container)
        try:
            await container.create_container()
        except Exception:
            pass
        await container.upload_blob(name=blob_name, data=data, overwrite=True)
    logger.info(
        "audit_archive.exported_azure",
        container=cfg.azure_container,
        blob=blob_name,
        rows=len(rows),
    )
    return f"azure://{cfg.azure_container}/{blob_name}"


async def _export_to_s3(
    cfg: ArchiveConfig, year: int, month: int, rows: list[dict[str, Any]]
) -> Optional[str]:
    try:
        import aioboto3
    except ImportError:
        logger.error("audit_archive.s3_sdk_missing")
        return None
    if not cfg.s3_bucket:
        logger.error("audit_archive.s3_bucket_missing")
        return None
    ext = "jsonl" if cfg.format == "jsonl" else "parquet"
    key = f"noo_security_audit_{year:04d}_{month:02d}.{ext}"
    data = (
        _rows_to_jsonl(rows) if cfg.format == "jsonl"
        else _parquet_bytes(rows)
    )
    session = aioboto3.Session()
    async with session.client("s3", region_name=cfg.s3_region) as s3:
        await s3.put_object(Bucket=cfg.s3_bucket, Key=key, Body=data)
    logger.info(
        "audit_archive.exported_s3",
        bucket=cfg.s3_bucket,
        key=key,
        rows=len(rows),
    )
    return f"s3://{cfg.s3_bucket}/{key}"


def _parquet_bytes(rows: list[dict[str, Any]]) -> bytes:
    import io
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        raise RuntimeError("Parquet format requires 'pyarrow'.")
    buf = io.BytesIO()
    if rows:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, buf)
    return buf.getvalue()


# ── Drop ──────────────────────────────────────────────────────────────


async def drop_partition(engine: AsyncEngine, year: int, month: int) -> bool:
    """DETACH then DROP the partition. Returns True if dropped, False if
    it didn't exist."""
    # Delegates to ``public.noo_drop_audit_partition`` (revision 047), the
    # DROP twin of the SECURITY DEFINER that ``ensure_partition`` already
    # uses — and for the same reason: partition DDL needs the table's OWNER,
    # and this code is dropping to a non-superuser identity.
    # The function builds the name from integers, refuses current/future
    # months regardless of what our retention arithmetic concluded, and does
    # DETACH+DROP in its own transaction like the direct DDL it replaces.
    # Existence is checked inside it too, so False still means "was not
    # there" to our caller.
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT noo_drop_audit_partition(:y, :m)"),
            {"y": year, "m": month},
        )
        dropped = bool(result.scalar())
    if dropped:
        logger.info(
            "audit_archive.partition_dropped",
            partition=_partition_name(year, month),
        )
    return dropped


# ── Orchestration ─────────────────────────────────────────────────────


async def rotate(
    engine: AsyncEngine,
    cfg: ArchiveConfig,
    retention_months: int,
) -> dict[str, int]:
    """Export-then-drop every partition older than the retention window.
    Returns counts: {"exported": N, "dropped": N, "errors": N}."""
    now = datetime.now(timezone.utc)
    parts = await list_partitions(engine)
    cutoff = _subtract_months(now.year, now.month, retention_months)

    exported = dropped = errors = 0
    retained = 0
    for (y, m) in parts:
        if (y, m) >= cutoff:
            continue  # still within retention
        try:
            # With no archive destination, RETAIN the partition rather than
            # dropping it — silently deleting audit history on the retention
            # boundary is exactly the audit-retention gap. Operators who truly want
            # rotation-drop must configure an archive backend.
            if cfg.backend == "none":
                logger.warning(
                    "audit_archive.retained_no_backend",
                    year=y,
                    month=m,
                    hint="set an archive backend to enable rotation-drop",
                )
                retained += 1
                continue
            uri = await export_partition(engine, y, m, cfg)
            if uri is None:
                # Export failed — do NOT drop. Rotation halts on this partition.
                logger.error(
                    "audit_archive.rotate_export_failed_skipping_drop",
                    year=y,
                    month=m,
                )
                errors += 1
                continue
            exported += 1
            if await drop_partition(engine, y, m):
                dropped += 1
        except Exception as e:
            logger.error(
                "audit_archive.rotate_partition_failed",
                year=y,
                month=m,
                error=str(e),
            )
            errors += 1

    logger.info(
        "audit_archive.rotation_complete",
        exported=exported,
        dropped=dropped,
        retained=retained,
        errors=errors,
        retention_months=retention_months,
    )
    return {
        "exported": exported,
        "dropped": dropped,
        "retained": retained,
        "errors": errors,
    }


def _subtract_months(year: int, month: int, n_months: int) -> tuple[int, int]:
    """Return (year, month) that is n_months before (year, month)."""
    total = (year * 12 + (month - 1)) - n_months
    return (total // 12, (total % 12) + 1)
