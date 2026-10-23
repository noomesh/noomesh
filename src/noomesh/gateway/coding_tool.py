# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Claude Code integration — async coding task execution with progress streaming.

Allows the coordinator agent to delegate coding tasks to Claude Code running
in the SANDBOX container: this manager submits over HTTP
(``NOO_SANDBOX_URL`` → POST /coding/exec) and polls /coding/status/{id} for
the stream-json lines, which feed the same ``_parse_stream_event`` progress
loop as before. The subprocess itself — `claude
--dangerously-skip-permissions` on a model-controlled description — never
runs in this container; the sandbox (no docker socket, no host mounts,
isolated network) is the only acceptable home for it. Tasks run
asynchronously; progress updates and final results are sent back to the
originating channel (Google Chat, Telegram, etc.) so the user doesn't need
to sit at a terminal.
"""

from __future__ import annotations

import asyncio
from .. import json_fast as json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class CodingTask:
    """A single Claude Code execution request.

    The ``engine`` field selects which LLM runs the Claude Code agentic
    loop. Only ``"claude"`` remains: it uses the real Anthropic API and
    bills your account. The ``"local"`` engine pointed the same CLI at
    the gateway's ``/v1/messages`` anthropic-compat endpoint, which PR
    #316 deleted on 2026-07-31 — the CLI speaks the Anthropic Messages
    wire format and the gateway now serves only the OpenAI-compatible
    surface (``/v1/chat/completions``), so there is nothing for it to
    talk to."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    description: str = ""
    channel: str = ""
    conversation_id: str = ""
    engine: str = "claude"
    status: TaskStatus = TaskStatus.PENDING
    result: str = ""
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    files_edited: list[str] = field(default_factory=list)
    # Changed-file set reported by the sandbox (git status of the task
    # workdir, computed sandbox-side). None = enumeration failed there,
    # which the tier gate treats as Tier 3 (refuse auto-apply).
    sandbox_changed_files: Optional[list[str]] = None
    # Self-develop audit linkage. Populated in submit() when logging is
    # enabled; consumed in _run_claude_code()'s finally block to finalize
    # the iteration row. None when self-develop logging is opted out.
    cycle_id: Optional[str] = None
    iteration_id: Optional[str] = None

    def elapsed_seconds(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at if self.started_at else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.id,
            "description": self.description[:200],
            "status": self.status.value,
            "result": self.result[:4000],
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds(), 1),
            "files_edited": self.files_edited,
        }


_VALID_ENGINES = ("claude",)

# Maximum concurrent Claude Code tasks (prevent API cost explosion)
MAX_CONCURRENT_TASKS = 2

# Opt-in gate for spawning the Claude Code subprocess. The ``claude`` CLI
# runs with ``--dangerously-skip-permissions`` inside /app, driven by a
# model-controlled ``task.description``. Default OFF so production must
# explicitly enable code execution. Parsed truthy the same way as
# _auto_restart_enabled() in verify/apply.py.
_CODING_TASK_ENABLED_ENV = "NOO_CODING_TASK_ENABLED"


class CodingTaskManager:
    """Manages async Claude Code subprocess execution with channel notifications."""

    def __init__(self) -> None:
        self._tasks: dict[str, CodingTask] = {}
        self._channel_manager: Any = None
        self._running_count = 0
        self._lock = asyncio.Lock()
        # Dashboard progress queues: conversation_id -> asyncio.Queue
        # The /ws/coordinator handler registers a queue to receive live progress
        self._dashboard_queues: dict[str, asyncio.Queue] = {}

    def register_dashboard_queue(self, conversation_id: str, queue: asyncio.Queue) -> None:
        """Register a queue for receiving coding task progress on the dashboard."""
        self._dashboard_queues[conversation_id] = queue

    def unregister_dashboard_queue(self, conversation_id: str) -> None:
        """Remove a dashboard progress queue."""
        self._dashboard_queues.pop(conversation_id, None)

    def set_channel_manager(self, cm: Any) -> None:
        self._channel_manager = cm

    async def submit(
        self,
        description: str,
        *,
        channel: str = "",
        conversation_id: str = "",
        timeout_minutes: int = 5,
        engine: str = "claude",
        trigger_source: str = "user_message",
        trigger_actor: Optional[str] = None,
        goal: Optional[str] = None,
        cycle_id: Optional[str] = None,
        log_self_develop: bool = True,
    ) -> dict[str, Any]:
        """Refuse the task with a pointer to the external-coding flow.

        In-cluster execution is retired (2026-08-11 design flip); this
        method exists so callers get a clear refusal instead of an
        AttributeError. The signature keeps the historical kwargs
        (``trigger_source``, ``cycle_id``, ``log_self_develop``, …) so
        existing dispatch sites don't break on unexpected-keyword — they
        are accepted and ignored."""
        if engine not in _VALID_ENGINES:
            return {
                "success": False,
                "error": (
                    f"Unknown engine '{engine}'. Valid: "
                    f"{', '.join(_VALID_ENGINES)}."
                ),
            }

        # RETIRED by the 2026-08-11 design flip : Mesh
        # never spawns Claude Code. Coding runs as EXTERNAL Claude Code on
        # the operator's machine, connected to Mesh through the MCP door
        # (~/.claude/settings.json -> https://<gateway>:8080/mcp/operator) — Claude
        # calls Mesh, not the other way round. The sandbox is Mesh's
        # AIRGAPPED executor for untrusted code (network internal: true),
        # so an in-cluster claude subprocess could not reach Anthropic
        # even if we still shipped one. The execution machinery that used
        # to sit below this return was removed the earlier sweep.
        return {
            "success": False,
            "error": (
                "noo_coding_task no longer executes in-cluster: coding is "
                "done by external Claude Code connected via the Mesh MCP "
                "door (/mcp/operator on the gateway). Ask the operator to run "
                "the task from Claude Code; this tool records/serves task "
                "history only."
            ),
        }

        # (The in-cluster execution path that used to follow this return —
        # sandbox submit, `claude` subprocess, stream parsing, progress
        # relay, self-develop audit open/close, tier classification +
        # post-edit apply — was removed the earlier sweep. It had been
        # unreachable since the 2026-08-11 design flip. The verify/ gate it
        # called is archived at git history (before 2026-08-08).)

    def get_status(self, task_id: str) -> dict[str, Any]:
        """Get status of a coding task. Checks in-memory first (fast,
        live-progress fields), falls back to DB lookup if the manager
        was restarted after the task was submitted."""
        task = self._tasks.get(task_id)
        if task is None:
            return {"success": False, "error": f"Unknown task_id: {task_id}"}
        return {"success": True, **task.to_dict()}

    async def get_task(self, task_id: str) -> Optional[dict[str, Any]]:
        """Return a task dict (for the worker_pool GET handler).
        Prefers in-memory; falls back to DB on miss (post-restart)."""
        task = self._tasks.get(task_id)
        if task is not None:
            return task.to_dict()
        return await _load_task_from_db(task_id)

    async def list_tasks(self) -> list[dict[str, Any]]:
        """Return all known tasks (in-memory + DB-only). DB rows for
        task_ids that aren't in memory get appended so the dashboard
        sees historical tasks across restarts."""
        out: dict[str, dict[str, Any]] = {
            tid: t.to_dict() for tid, t in self._tasks.items()
        }
        for row in await _list_tasks_from_db():
            tid = row.get("task_id") or row.get("id")
            if tid and tid not in out:
                out[tid] = row
        return list(out.values())

    # -- Background execution --------------------------------------------------

# ---------------------------------------------------------------------------
# Postgres persistence (the design_coding_tasks)
#
# Pre-persistence, CodingTaskManager kept _tasks in-memory only — a gateway
# restart wiped all state and any pre-restart task_id became unresolvable.
# These helpers UPSERT/SELECT against `noo_coding_tasks` so task state
# survives restarts. The Rust GET routes at /api/coding/tasks already
# read from this table directly (graceful-degrades to [] if missing).
# ---------------------------------------------------------------------------

async def _persist_task(task: CodingTask) -> None:
    """UPSERT a task row. Best-effort: failures log but don't propagate
    (subprocess execution is the source of truth; persistence is for
    cross-restart recovery)."""
    try:
        from sqlalchemy import text
        from ..db import get_async_engine
        eng = get_async_engine()
        if eng is None:
            return
        async with eng.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO noo_coding_tasks "
                    "(id, description, channel, conversation_id, status, "
                    " result, error, elapsed_seconds, files_edited, "
                    " started_at, completed_at) VALUES "
                    "(:id, :description, :channel, :conversation_id, :status, "
                    " :result, :error, :elapsed_seconds, :files_edited, "
                    " :started_at, :completed_at) "
                    "ON CONFLICT (id) DO UPDATE SET "
                    " status = EXCLUDED.status, "
                    " result = EXCLUDED.result, "
                    " error = EXCLUDED.error, "
                    " elapsed_seconds = EXCLUDED.elapsed_seconds, "
                    " files_edited = EXCLUDED.files_edited, "
                    " completed_at = EXCLUDED.completed_at"
                ),
                _task_to_row(task),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("coding_task_persist_failed", task_id=task.id, error=str(exc))


def _task_to_row(task: CodingTask) -> dict[str, Any]:
    from datetime import datetime, timezone
    return {
        "id": task.id,
        "description": task.description,
        "channel": task.channel,
        "conversation_id": task.conversation_id,
        "status": task.status.value,
        "result": task.result or None,
        "error": task.error or None,
        "elapsed_seconds": round(task.elapsed_seconds(), 2) if task.started_at else None,
        "files_edited": json.dumps(task.files_edited),
        "started_at": (
            datetime.fromtimestamp(task.started_at, tz=timezone.utc)
            if task.started_at else None
        ),
        "completed_at": (
            datetime.fromtimestamp(task.completed_at, tz=timezone.utc)
            if task.completed_at else None
        ),
    }


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "task_id": row[0],
        "description": (row[1] or "")[:200],
        "channel": row[2] or "",
        "conversation_id": row[3] or "",
        "status": row[4] or "pending",
        "result": (row[5] or "")[:4000],
        "error": row[6] or "",
        "elapsed_seconds": round(row[7], 1) if row[7] is not None else 0.0,
        "files_edited": row[8] if isinstance(row[8], list) else json.loads(row[8] or "[]"),
        "started_at": row[9].isoformat() if row[9] else None,
        "completed_at": row[10].isoformat() if row[10] else None,
    }


async def _load_task_from_db(task_id: str) -> Optional[dict[str, Any]]:
    try:
        from sqlalchemy import text
        from ..db import get_async_engine
        eng = get_async_engine()
        if eng is None:
            return None
        async with eng.connect() as conn:
            r = await conn.execute(
                text(
                    "SELECT id, description, channel, conversation_id, status, "
                    "       result, error, elapsed_seconds, files_edited, "
                    "       started_at, completed_at "
                    "FROM noo_coding_tasks WHERE id = :id"
                ),
                {"id": task_id},
            )
            row = r.fetchone()
            return _row_to_dict(row) if row else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("coding_task_db_load_failed", task_id=task_id, error=str(exc))
        return None


async def _list_tasks_from_db(limit: int = 200) -> list[dict[str, Any]]:
    try:
        from sqlalchemy import text
        from ..db import get_async_engine
        eng = get_async_engine()
        if eng is None:
            return []
        async with eng.connect() as conn:
            r = await conn.execute(
                text(
                    "SELECT id, description, channel, conversation_id, status, "
                    "       result, error, elapsed_seconds, files_edited, "
                    "       started_at, completed_at "
                    "FROM noo_coding_tasks "
                    "ORDER BY started_at DESC NULLS LAST LIMIT :limit"
                ),
                {"limit": limit},
            )
            return [_row_to_dict(row) for row in r.fetchall()]
    except Exception as exc:  # noqa: BLE001
        logger.warning("coding_task_db_list_failed", error=str(exc))
        return []


# ---------------------------------------------------------------------------
# Backward-compat getter — used by MCP tools and the worker pool which
# cannot receive Depends(get_state).  Reads the service registry (the
# FastAPI gateway.app that used to own the singleton was deleted; under
# the Rust gateway nothing constructed it there anyway).
# ---------------------------------------------------------------------------

def get_coding_manager() -> Optional[CodingTaskManager]:
    """Return the CodingTaskManager from the service registry, if set."""
    try:
        from .deps import services
        return getattr(services, "coding_manager", None)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTTP API router for debugging coding tasks
# ---------------------------------------------------------------------------

try:
    from fastapi import APIRouter, Depends, HTTPException
    from .gateway_state import GatewayState, get_state

    coding_router = APIRouter(prefix="/api/coding", tags=["coding"])

    @coding_router.get("/tasks")
    async def list_coding_tasks(gw: GatewayState = Depends(get_state)) -> dict:
        """List all coding tasks (in-memory) with status."""
        mgr = gw.coding_manager
        if mgr is None:
            raise HTTPException(503, "Coding task manager not initialized")
        tasks = sorted(
            mgr._tasks.values(),
            key=lambda t: t.started_at or 0,
            reverse=True,
        )
        return {"tasks": [t.to_dict() for t in tasks]}

    @coding_router.get("/tasks/{task_id}")
    async def get_coding_task(task_id: str, gw: GatewayState = Depends(get_state)) -> dict:
        """Detailed info for a specific coding task."""
        mgr = gw.coding_manager
        if mgr is None:
            raise HTTPException(503, "Coding task manager not initialized")
        task = mgr._tasks.get(task_id)
        if task is None:
            raise HTTPException(404, f"Task {task_id} not found")
        # Return full result (not truncated to 4000 like to_dict)
        return {
            "task_id": task.id,
            "description": task.description,
            "channel": task.channel,
            "conversation_id": task.conversation_id,
            "status": task.status.value,
            "result": task.result,
            "error": task.error,
            "elapsed_seconds": round(task.elapsed_seconds(), 1),
            "files_edited": task.files_edited,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
        }

    CODING_ROUTER_AVAILABLE = True
except ImportError:
    CODING_ROUTER_AVAILABLE = False
