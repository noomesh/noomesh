# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Heartbeat run handler (worker.api.heartbeat.run).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were moved to
the 2026-08-08 sweep (history in git log before that) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.
"""

from __future__ import annotations

from typing import Any

import structlog


from .registry import worker_handler

log = structlog.get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════════
# Heartbeat handlers
# ═══════════════════════════════════════════════════════════════════════


# POST /api/heartbeat/run was *claimed* ported to Rust but actually wasn't.
# The Rust catchall translates the URL → `worker.api.heartbeat.run`, which
# had no subscriber, so manual triggers from the dashboard / CLI hung until
# the 60s NATS deadline. This Python handler restores the trigger; a real
# Rust port (HTTP route + DB read + dispatch) is filed.
# status/tasks/artifacts are native Rust in routes/intelligence.rs.
@worker_handler("worker.api.heartbeat.run")
async def _heartbeat_run_task(request: dict) -> Any:
    """POST /api/heartbeat/tasks/{task_id}/run"""
    try:
        from ..gateway.heartbeat import get_heartbeat_scheduler
        hs = get_heartbeat_scheduler()
        if not hs:
            from ..gateway.deps import services
            hs = services.heartbeat_scheduler
        if not hs:
            return {"error": "Heartbeat scheduler not initialized"}
        task_id = request.get("task_id", request.get("params", {}).get("task_id", ""))
        if not task_id:
            return {"error": "Missing task_id"}
        # The gateway inserts the run row at dispatch (status "running") and
        # sends its run_id along; recording under the same id turns that row
        # into the outcome instead of leaving it dangling. Absent (older
        # gateway) → _execute_task generates one, as before.
        run_id = request.get("run_id") or None
        record = await hs.run_task_now(task_id, run_id=run_id)
        if record is None:
            return {"error": f"Task '{task_id}' not found"}
        return record.to_dict()
    except Exception as e:
        return {"error": str(e)}


# `worker.api.heartbeat.webhook` was REMOVED with the Rust route it served.
#
# /api/heartbeat/webhook/{task_id} was documented in auth.rs as carrying a
# "per-task webhook secret, verified inside the handler". No such check
# existed in either language: the Rust handler delegated straight to
# heartbeat_run_task, and the path sat in PUBLIC_PATH_PREFIXES, so any caller
# who could reach the gateway could run any heartbeat task by id — and the ids
# are guessable (daily_log, graph_prune, cluster_health, daily_digest_gchat).
# ngrok's allowlist published it to the internet.
#
# Nothing is lost: /api/heartbeat/tasks/{task_id}/run is the same operation
# behind auth.
