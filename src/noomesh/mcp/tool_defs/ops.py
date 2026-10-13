# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Asynchronous operations: start a long run, poll for its status and result.

A run that takes minutes (a recluster, a relation extraction, a consolidation,
an ingest, a slow graph walk) must not be a request an MCP client or a proxy
has to hold open: they give up first and the user is told the gateway is
unreachable while it is working. The gateway runs such work as an OPERATION --
a stored row with an id -- and these tools are the poll side of it.

The long tools (`noo_graph_run_clustering`, `noo_graph_extract_relations`,
`noo_consolidate_now`, `noo_graph_navigate`, `noo_graph_traverse_with_intent`,
`noo_rag_ingest`) already start an operation and wait a few seconds for it:
the result comes back if it finished, an operation handle if it did not. Pass
that handle's `op_id` to `noo_op_status`. `noo_op_start` is the explicit form
for a client that wants the handle first and never a result.

The gateway's own routes are `POST /api/v1/ops`, `GET|DELETE /api/v1/ops/{id}`
and `GET /api/v1/ops`; see docs/reference/api.md ("Asynchronous operations").
Operations are visible to the account that started them (and admins): another
account's id is simply "not found".
"""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import AuthLevel, HttpMethod, RiskLevel, ToolDef, register

#: Appended to the description of every tool whose route is operation-backed,
#: so a model that is handed a handle knows what to do with it.
ASYNC_NOTE = (
    "\n\nLong-running: this starts an operation and waits a few seconds. If it finished you get the "
    "result; if not you get a handle {op_id, status, poll} -- call noo_op_status with that op_id "
    "(wait up to 25 seconds per call) until status is succeeded or failed. noo_op_cancel stops the "
    "gateway-side wait (the worker run itself may continue)."
)

OP_TYPES = (
    "graph.recluster | graph.extract_relations | snapshots.consolidate | "
    "graph.navigate | graph.traverse | rag.ingest | docs.ingest"
)


@register
class PaiOpStart(ToolDef):
    """Start a long-running operation and get its id immediately; poll it with noo_op_status.

    `type` is one of: graph.recluster, graph.extract_relations, snapshots.consolidate,
    graph.navigate, graph.traverse, rag.ingest, docs.ingest. `params` is exactly the body the
    type's own tool takes (e.g. {"query": "..."} for graph.navigate). You are held to the same
    permissions as that tool. Answers at once with {op_id, status, poll, poll_interval_ms}; it
    never waits for the result."""

    name: ClassVar[str] = "noo_op_start"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/ops"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    tags: ClassVar[List[str]] = ["ops", "external"]

    type: str = Field(description=f"Operation type: {OP_TYPES}")
    params: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="The operation's parameters, as the matching tool takes them",
    )


@register
class PaiOpStatus(ToolDef):
    """Status, progress and (once finished) the result or error of an operation.

    `wait` (seconds, at most 25) holds the call until the operation finishes or the time is up, so
    you can wait without polling in a loop. status is queued, running, succeeded, failed, cancelled
    or expired; a finished operation carries `result` (or `error`). Only the account that started an
    operation can read it: any other id is "not found"."""

    name: ClassVar[str] = "noo_op_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/ops/{op_id}"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    # The route holds the request up to `wait` (<= 25s); outlast it.
    timeout_secs: ClassVar[int] = 40
    tags: ClassVar[List[str]] = ["ops", "status", "external"]

    op_id: str = Field(description="The operation id from the handle a long tool or noo_op_start returned")
    wait: Optional[int] = Field(
        default=None, ge=0, le=25,
        description="Seconds to wait for it to finish before answering (0-25)",
    )


@register
class PaiOpCancel(ToolDef):
    """Cancel an operation you started.

    Stops the gateway-side wait and marks it cancelled. It does NOT stop a worker run that has
    already begun: the answer says what the worker will do (`cancel.worker_stopped` is false)."""

    name: ClassVar[str] = "noo_op_cancel"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.DELETE
    path: ClassVar[str] = "/api/v1/ops/{op_id}"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    tags: ClassVar[List[str]] = ["ops", "external"]

    op_id: str = Field(description="The operation id to cancel")


@register
class PaiOpList(ToolDef):
    """List your operations, newest first (no results; fetch one with noo_op_status)."""

    name: ClassVar[str] = "noo_op_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/ops"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    tags: ClassVar[List[str]] = ["ops", "status", "external"]

    status: Optional[str] = Field(
        default=None,
        description="Filter: queued, running, succeeded, failed, cancelled or expired",
    )
    mine: Optional[bool] = Field(default=None, description="Only operations you started (admins otherwise see all)")
    limit: Optional[int] = Field(default=None, ge=1, le=100, description="Most to return (default 50)")
