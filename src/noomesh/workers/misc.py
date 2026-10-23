# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Coding-submit handler (worker.api.coding.task).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were removed in the
2026-08-08 sweep (history in git log before that) — only live
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
# Coding handlers
# ═══════════════════════════════════════════════════════════════════════


# POST /api/coding/task — actual submission. The MCP `noo_coding_task` tool
# POSTs here; the Rust catchall translates the URL to this NATS subject.
# Without a subscriber the call silently no-op'd and the tool's
# format_response defaulted task_id="?" / status="submitted", making the
# failure look like success. tasks/get_task reads are native Rust (SQL).
@worker_handler("worker.api.coding.task")
async def _coding_submit(request: dict) -> Any:
    """POST /api/coding/task — submit a Claude Code task asynchronously.

    Wired here because the MCP `noo_coding_task` tool POSTs to this path
    expecting a JSON body with `task` (preferred), `command`, or
    `description`. Returns `{"success": bool, "task_id": str, ...}` —
    if `success` is missing or `task_id` is empty, the tool's
    `format_response` should treat it as failure so the model doesn't
    keep reporting fake "submitted" successes.
    """
    try:
        from ..gateway.coding_tool import get_coding_manager
        mgr = get_coding_manager()
        if not mgr:
            return {"success": False, "error": "Coding manager not initialized"}
        # Body comes through under different keys depending on caller path
        # (Rust catchall passes `body`, direct routers pass top-level).
        body = request.get("body") or request
        if isinstance(body, str):
            try:
                from .. import json_fast as _json
                body = _json.loads(body)
            except Exception:
                body = {}
        description = (
            body.get("task")
            or body.get("command")
            or body.get("description")
            or ""
        )
        if not description:
            return {
                "success": False,
                "error": "Missing 'task' (or 'command'/'description') in request body",
            }
        channel = body.get("channel", "")
        conversation_id = body.get("conversation_id", "")
        timeout_minutes = int(body.get("timeout_minutes", 5))
        engine = body.get("engine", "claude")
        return await mgr.submit(
            description=description,
            channel=channel,
            conversation_id=conversation_id,
            timeout_minutes=timeout_minutes,
            engine=engine,
        )
    except Exception as e:
        return {"success": False, "error": f"coding_submit_failed: {e}"}


# worker.browser.action was retired 2026-08-11 (port-lane item 6): the
# Rust gateway serves POST /api/tools/browser/action natively — the
# handler here only proxied HTTP to the noo-browser container and kept
# its sessions in THIS process's memory, invisible to the Rust-started
# ones. Nothing publishes the subject any more.
