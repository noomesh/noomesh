# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Follow an asynchronous-operation handle to its result (gateway ``ops.rs``).

The long routes (recluster, extract-relations, consolidate, ingest, and the
slower graph walks) start an operation and wait a few seconds for it. A run
that finished in time is answered 200 with its result, as it always was; one
that did not is answered **202** with a handle ``{op_id, status, poll, ...}``.
A caller that needs the outcome calls :func:`settle` on the response it got:
a non-202 passes through untouched, and a 202 is followed with long-polls
(``GET /api/v1/ops/{id}?wait=``, a handful of requests, not a busy loop) until
the operation finishes or ``timeout`` is spent.

The result of a followed operation is a :class:`Settled`, which has the
``status_code`` / ``json()`` / ``text`` an ``httpx.Response`` has, carrying the
status the synchronous route would have answered (a failed ingest is 400, not
200). If time runs out the caller gets the 202 handle back, still unfinished,
so "submitted" is never reported as "done".
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

#: The longest single long-poll the gateway honours (ops.rs MAX_WAIT_SECS).
POLL_WAIT_SECS = 20


class Settled:
    """The end of a followed operation, shaped like the response it replaces."""

    def __init__(self, status_code: int, body: Any, op: Optional[Dict[str, Any]] = None) -> None:
        self.status_code = status_code
        self._body = body
        self.op = op or {}

    def json(self) -> Any:
        return self._body

    @property
    def text(self) -> str:
        return json.dumps(self._body)


def is_handle(response: Any) -> bool:
    """Whether ``response`` is an operation handle (202 with an ``op_id``)."""
    if getattr(response, "status_code", None) != 202:
        return False
    try:
        body = response.json()
    except Exception:
        return False
    return isinstance(body, dict) and bool(body.get("op_id"))


async def settle(client: Any, response: Any, base_url: str, *, timeout: float = 300.0) -> Any:
    """``response`` if it is not a handle; else the finished operation as a :class:`Settled`.

    ``client`` is the ``httpx.AsyncClient`` that made the request (so its auth
    headers carry over); ``base_url`` is the gateway's. On timeout the original
    202 ``response`` is returned unchanged.
    """
    if not is_handle(response):
        return response
    handle = response.json()
    url = f"{base_url.rstrip('/')}/api/v1/ops/{handle['op_id']}"
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return response
        wait = max(1, min(POLL_WAIT_SECS, int(remaining)))
        r = await client.get(url, params={"wait": wait})
        if r.status_code >= 400:
            return Settled(r.status_code, _safe_json(r), None)
        op = r.json()
        status = op.get("status")
        if status == "succeeded":
            return Settled(int(op.get("result_status") or 200), op.get("result"), op)
        if status == "failed":
            body = op.get("result")
            if body is None:
                body = {"error": op.get("error") or "the operation failed"}
            return Settled(int(op.get("result_status") or 500), body, op)
        if status in ("cancelled", "expired"):
            return Settled(409 if status == "cancelled" else 410, {"error": f"the operation was {status}"}, op)


def _safe_json(r: Any) -> Any:
    try:
        return r.json()
    except Exception:
        return {"error": getattr(r, "text", "")[:500]}
