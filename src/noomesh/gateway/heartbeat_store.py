# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""PostgreSQL persistence for Heartbeat Scheduler tasks and run history.

ℹ️ LIVE PYTHON LIBRARY — Schema owner per RUST_PYTHON_SPLIT.md. Rust
``routes/intelligence.rs`` reads/writes the same tables via raw SQL.
Stays Python (Postgres + Alembic schema lives here).

Uses the shared SQLAlchemy engine from ``noomesh.db`` with
SQLAlchemy Core expressions via ``Model.__table__``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine

from ..db.models import PaiHeartbeatRun, PaiHeartbeatTask

logger = structlog.get_logger()

task_t = PaiHeartbeatTask.__table__
run_t = PaiHeartbeatRun.__table__


def _serialize_row(row) -> Dict[str, Any]:
    """Convert a SQLAlchemy Row to a JSON-safe dict."""
    d = dict(row._mapping)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


class HeartbeatStore:
    """Sync PostgreSQL store for heartbeat tasks and run records."""

    def __init__(self, engine: Optional[Engine] = None, dsn: Optional[str] = None):
        if engine is not None:
            self._engine = engine
        elif dsn is not None:
            # Legacy path: caller passed a DSN directly
            from noomesh.db.engine import _sync_dsn
            from sqlalchemy import create_engine
            self._engine = create_engine(_sync_dsn(dsn), pool_pre_ping=True)
        else:
            from noomesh.db import get_engine
            self._engine = get_engine()

    # -- Tasks -----------------------------------------------------------

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(
                    task_t.c.id, task_t.c.name, task_t.c.schedule, task_t.c.action,
                    task_t.c.config, task_t.c.channels, task_t.c.recipients,
                    task_t.c.enabled, task_t.c.last_run, task_t.c.next_run,
                    task_t.c.created_by,
                )
                .order_by(task_t.c.name)
            ).fetchall()
        results = []
        for row in rows:
            d = _serialize_row(row)
            d["config"] = d.get("config") or {}
            d["channels"] = d.get("channels") or []
            d["recipients"] = d.get("recipients") or []
            d["created_by"] = d.get("created_by") or "user"
            results.append(d)
        return results

    def save_task(self, task_data: Dict[str, Any]) -> None:
        stmt = pg_insert(task_t).values(
            id=task_data["id"],
            name=task_data["name"],
            schedule=task_data["schedule"],
            action=task_data.get("action", "custom_prompt"),
            config=task_data.get("config", {}),
            channels=task_data.get("channels", []),
            recipients=task_data.get("recipients", []),
            enabled=task_data.get("enabled", True),
            last_run=task_data.get("last_run"),
            next_run=task_data.get("next_run"),
            created_by=task_data.get("created_by", "user"),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "name": stmt.excluded.name,
                "schedule": stmt.excluded.schedule,
                "action": stmt.excluded.action,
                "config": stmt.excluded.config,
                "channels": stmt.excluded.channels,
                "recipients": stmt.excluded.recipients,
                "enabled": stmt.excluded.enabled,
                "last_run": stmt.excluded.last_run,
                "next_run": stmt.excluded.next_run,
                "updated_at": func.now(),
                # NOTE: created_by is NOT updated on conflict — preserve original creator
            },
        )
        with self._engine.connect() as conn:
            conn.execute(stmt)
            conn.commit()

    def insert_task_if_new(self, task_data: Dict[str, Any]) -> None:
        """Insert a task only if it doesn't already exist in the DB.

        Used for default/system tasks on startup — preserves user edits
        (enabled state, config, schedule) by skipping rows that already exist.
        """
        stmt = pg_insert(task_t).values(
            id=task_data["id"],
            name=task_data["name"],
            schedule=task_data["schedule"],
            action=task_data.get("action", "custom_prompt"),
            config=task_data.get("config", {}),
            channels=task_data.get("channels", []),
            recipients=task_data.get("recipients", []),
            enabled=task_data.get("enabled", True),
            last_run=task_data.get("last_run"),
            next_run=task_data.get("next_run"),
            created_by=task_data.get("created_by", "user"),
        )
        stmt = stmt.on_conflict_do_nothing(index_elements=["id"])
        with self._engine.connect() as conn:
            conn.execute(stmt)
            conn.commit()

    def update_task(self, task_data: Dict[str, Any]) -> None:
        """Alias for save_task (upsert)."""
        self.save_task(task_data)

    def delete_task(self, task_id: str) -> None:
        with self._engine.connect() as conn:
            conn.execute(delete(task_t).where(task_t.c.id == task_id))
            conn.commit()

    _MAX_RESULT_LEN = 2000

    @staticmethod
    def _truncate_result(text: str) -> str:
        if len(text) > HeartbeatStore._MAX_RESULT_LEN:
            logger.debug("heartbeat_result_truncated",
                         original_len=len(text), max_len=HeartbeatStore._MAX_RESULT_LEN)
            return text[:HeartbeatStore._MAX_RESULT_LEN]
        return text

    # -- Runs ------------------------------------------------------------

    def save_run(self, run_data: Dict[str, Any]) -> None:
        # UPSERT on run_id (the PK): when the Rust gateway dispatched this
        # run it already inserted the row with status "running" under the
        # same id — this write completes it.
        # A run with no start row inserts exactly as before.
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        values = dict(
            run_id=run_data["run_id"],
            task_id=run_data["task_id"],
            task_name=run_data["task_name"],
            action=run_data["action"],
            started_at=run_data["started_at"],
            completed_at=run_data.get("completed_at"),
            status=run_data.get("status", "running"),
            result_text=self._truncate_result(run_data.get("result_text", "")),
            error=run_data.get("error", ""),
            duration_ms=run_data.get("duration_ms", 0),
            notified_channels=run_data.get("notified_channels", []),
            artifacts=run_data.get("artifacts", []),
        )
        stmt = pg_insert(run_t).values(**values)
        update_cols = {
            k: getattr(stmt.excluded, k) for k in values if k != "run_id"
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=[run_t.c.run_id], set_=update_cols
        )
        with self._engine.connect() as conn:
            conn.execute(stmt)
            conn.commit()

    def _history_filters(self, stmt, task_id=None, status=None):
        """Apply common WHERE clauses for history queries."""
        if task_id:
            stmt = stmt.where(run_t.c.task_id == task_id)
        if status:
            stmt = stmt.where(run_t.c.status == status)
        return stmt

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
        task_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        stmt = select(
            run_t.c.run_id, run_t.c.task_id, run_t.c.task_name, run_t.c.action,
            run_t.c.started_at, run_t.c.completed_at, run_t.c.status,
            run_t.c.result_text, run_t.c.error, run_t.c.duration_ms,
            run_t.c.notified_channels, run_t.c.artifacts,
        )
        stmt = self._history_filters(stmt, task_id, status)
        stmt = stmt.order_by(run_t.c.started_at.desc()).offset(offset).limit(limit)

        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()

        results = []
        for row in rows:
            d = _serialize_row(row)
            d["notified_channels"] = d.get("notified_channels") or []
            d["artifacts"] = d.get("artifacts") or []
            results.append(d)
        return results

    def count_history(
        self,
        task_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        stmt = select(func.count()).select_from(run_t)
        stmt = self._history_filters(stmt, task_id, status)
        with self._engine.connect() as conn:
            return conn.execute(stmt).scalar() or 0
