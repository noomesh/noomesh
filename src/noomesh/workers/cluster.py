# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster discovery/enrollment/proposal handlers (worker.api.cluster.*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were moved to
``legacy/python-workers-reference/`` (2026-08-08 sweep) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.

2 handlers removed 2026-07-18 — ported to native Rust routes
(gateway-rust routes/cluster.rs); see PR #206. proposals.decide is
unregistered but its body remains: channels/approvals.py calls it
in-process. DELIBERATELY LEFT by the 2026-08-08 reference sweep — the
adapters' handle_interaction methods (approvals.py's only entry points)
moved to legacy/python-channels-reference/, so this chain is now
Python-caller-less; the live decide path is Rust
(channels/approvals.rs → routes/cluster.rs). Retiring
approvals.py + this decide body together is a follow-up decision, not
part of the sweep. The _notify_proposal/_notify_proposal_auto senders
(zero callers) are archived in legacy/python-workers-reference/cluster.py.
"""

from __future__ import annotations

from typing import Any

import structlog

from .. import json_fast as json

from .common import _get_conversation_store, _unwrap_body

log = structlog.get_logger(__name__)

# ── Agentic mesh ops + observability (gap-analysis items 3+4) ─────

# ═══════════════════════════════════════════════════════════════════════

# ── Tier 2: proposal queue (agent proposes, human approves) ──────────

def _conversation_store_engine() -> Any | None:
    """Reuse the conversation store's AsyncEngine for proposal SQL."""
    store = _get_conversation_store()
    if store is None:
        return None
    return getattr(store, "_engine", None)


async def _emit_cluster_event(kind: str, payload: dict) -> None:
    """Publish a proposal-lifecycle observability event to NATS.
    Best-effort, never fails the caller. Subject: ``events.cluster.<kind>``.

    NOTE (2026-08 zombie sweep): there is NO in-tree subscriber — the
    once-planned dashboard WebSocket relay was never built. Events land in
    the JetStream EVENTS stream (``events.>``, 24h retention) for external
    observation only. The Rust twin is routes/cluster.rs::emit_cluster_event
    (proposal.created / proposal.auto_enrolled); this one emits the decision
    kinds (proposal.approved / proposal.rejected)."""
    try:
        from ..cluster.messaging import get_messaging
        msg = get_messaging()
        if msg is None or not getattr(msg, "nc", None):
            return
        body = {"kind": kind, **payload, "ts": __import__("time").time()}
        await msg.nc.publish(
            f"events.cluster.{kind}",
            json.dumps(body, default=str).encode("utf-8"),
        )
    except Exception as e:
        log.debug("emit_cluster_event_failed", kind=kind, error=str(e))


# NOT NATS-registered (subject ported to Rust routes/cluster.rs) — kept
# because channels/approvals.py calls _cluster_proposals_decide in-process.
async def _cluster_proposals_decide(request: dict) -> Any:
    """POST /api/cluster/proposals/{id}/decide
       Body: {decision: "approve" | "reject", decided_by, decided_via}
    """
    from sqlalchemy import text as _sql_text

    body = _unwrap_body(request)
    proposal_id = body.get("id") or body.get("proposal_id")
    decision = (body.get("decision") or "").lower().strip()
    decided_by = body.get("decided_by") or "unknown"
    decided_via = body.get("decided_via") or "dashboard"

    if not proposal_id:
        return {"error": "id required"}
    if decision not in ("approve", "reject"):
        return {"error": "decision must be 'approve' or 'reject'"}

    engine = _conversation_store_engine()
    if engine is None:
        return {"error": "DB engine not initialised"}

    new_status = "approved" if decision == "approve" else "rejected"
    try:
        async with engine.begin() as conn:
            result = await conn.execute(
                _sql_text(
                    "UPDATE noo_cluster_proposals "
                    "SET status = :s, decided_at = NOW(), decided_by = :by, decided_via = :via "
                    "WHERE id = CAST(:id AS uuid) AND status = 'pending' "
                    "RETURNING host, user_name, role"
                ),
                {"s": new_status, "by": str(decided_by), "via": str(decided_via),
                 "id": str(proposal_id)},
            )
            row = result.first()
    except Exception as e:
        return {"error": f"decision failed: {e}"}

    if row is None:
        return {"error": "proposal not found or not pending"}

    out = {
        "proposal_id": proposal_id,
        "status": new_status,
        "host": row[0], "user": row[1], "role": row[2],
    }
    if new_status == "approved":
        # The host-side executor that used to "pick this up on its next
        # poll" was deleted with the controller->node SSH lane on
        # 2026-09-11. The one useful thing it did for an enrolment row —
        # write out the bootstrap procedure — the Rust gateway now does
        # inline at approval time (routes/cluster.rs::
        # resolve_enrolment_proposal). This Python twin is a legacy NATS
        # handler; it states the procedure and does NOT claim an executor
        # will act.
        out["status"] = "needs_bootstrap"
        out["next_step"] = (
            "Approved. Nothing will act on this row unattended — enrolment is "
            "a pull-rail one-liner run ON the node. On the controller:\n\n"
            "  noo cluster bootstrap-token create --node {host}\n\n"
            "then run the printed one-liner ON {host}."
            .format(host=row[0])
        )

    # Phase 5: dashboard live-feed event
    await _emit_cluster_event(f"proposal.{new_status}", {
        "id": proposal_id, "host": row[0], "user": row[1], "role": row[2],
        "status": new_status, "decided_by": str(decided_by), "decided_via": str(decided_via),
    })
    return out
