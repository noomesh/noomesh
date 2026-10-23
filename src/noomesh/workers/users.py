# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""User administration + proposal-flow handlers (worker.api.users*) and legacy auth handlers.

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were removed in the
2026-08-08 sweep (history in git log before that) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.

7 handlers removed 2026-07-18 — ported to native Rust routes
(gateway-rust routes/users.rs); see PR #206.
"""

from __future__ import annotations


import structlog



log = structlog.get_logger(__name__)


async def _notify_exec_approval(req) -> None:
    """Approval-callback for the exec-approval gate: ping the approval
    channels when an autonomous HIGH-risk tool call opens a window.
    Best-effort — a failed notification never blocks the gate."""
    import os as _os

    tool = req.tool_call.qualified_name if req.tool_call else "?"
    text = (f"Exec approval requested: {tool} (id {req.id})\n"
            f"Mode window is open — decide with the dashboard Admin view "
            f"or: noo approval approve {req.id} / noo approval deny {req.id}")
    # Every channel send goes through the gateway's /api/channels/send
    # (``ChannelManager.dispatch`` → ``GatewayChannelClient``), which lands
    # on the Rust transports and their egress floor (gateway-rust
    # src/egress.rs). This used to POST to the Telegram API directly — the
    # one Python path that bypassed the boundary
    # (tests/test_channel_egress_guard.py).
    targets = [
        ("google_chat", _os.environ.get("NOO_APPROVAL_GCHAT_SPACE", "").strip()),
        ("telegram", _os.environ.get("NOO_APPROVAL_TELEGRAM_CHAT", "").strip()),
    ]
    for channel, recipient in targets:
        if not recipient:
            continue
        try:
            from ..gateway.deps import services
            cm = getattr(services, "channel_manager", None) if services else None
            if cm and cm.get_adapter(channel):
                await cm.dispatch(channel, recipient, text)
        except Exception as e:
            log.debug("notify_exec_approval_send_failed", channel=channel, error=str(e))
