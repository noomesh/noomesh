# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tool execution/recording handlers (worker.tool.*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were moved to
``git history (before 2026-08-08)`` (2026-08-08 sweep) — only live
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

#: Envelope key of the gateway-minted per-dispatch user token — the wire
#: contract with `gateway-rust/src/worker_delegation.rs::ENVELOPE_KEY`.
DELEGATED_TOKEN_KEY = "delegated_token"

# Conversations handlers
# ═══════════════════════════════════════════════════════════════════════

# ── Conversation NATS handlers removed 2026-03-31 ──
# All 6 conversation endpoints are now native Rust SQL in gateway-rust/src/routes/memory.rs:
#   - conv_stats_overview    (GET /api/conversations/stats/overview)
#   - conv_stats_tools       (GET /api/conversations/stats/tools)
#   - conv_feedback_stats    (GET /api/conversations/feedback/stats)
#   - conv_feedback_export_dpo (GET /api/conversations/feedback/export/dpo)
#   - conv_detail            (GET /api/conversations/{conversation_id})
#   - conv_feedback          (POST /api/conversations/{conversation_id}/feedback)


# ═══════════════════════════════════════════════════════════════════════
# Tool handlers
# ═══════════════════════════════════════════════════════════════════════


# worker.tool.web_search ported to native Rust 2026-08-08:
# gateway-rust/src/web_search.rs talks to the DuckDuckGo HTML endpoint the
# ddgs library scrapes. worker.tool.python was retired 2026-08-09
# (port-lane item 3): "executes Python" never meant "runs in trellion" —
# the executor was already sandbox-first, so the gateway now POSTs to the
# sandbox /exec directly (tools.rs native_python_exec) and the in-process
# local-subprocess fallback is gone with it. worker.tool.generic stays as
# the extensibility escape hatch for tools_executor tools and any tool
# name the Rust native set doesn't know. The tools/custom/ dispatch rung
# was removed 2026-08-08: drop-in plugins ran in-process in
# trellion, bypassing the sandbox — extension code belongs in skills
# (`noo skills scaffold`).
@worker_handler("worker.tool.generic")
async def _tool_generic(request: dict) -> Any:
    """Execute a generic tool (web_search, python_tool, local_files, browser, skill, etc.).

    Dispatch order:
    1. Pydantic ToolDef registry (FastMCP models) — unfiltered fast path
    2. Gateway tool registry (tools_executor.py — legacy)
    3. handle_tool_call — same registry as step 1, but NOO_MCP_TOOLS-enforcing
       (the mcp/tools.py shim it used to call was retired 2026-08-17)
    """
    # The gateway's per-dispatch user token. POPPED first,
    # before anything else reads the request, so nothing downstream — the
    # tool's arguments, an approval row, a log line, an exception message —
    # can carry a bearer that outlives this call. It is held only in the
    # ContextVar below, for this handler's task.
    delegated = request.pop(DELEGATED_TOKEN_KEY, None)
    name = request.get("name", "")
    args = request.get("arguments", {})
    if isinstance(args, str):
        import json as _json
        args = _json.loads(args)

    # ── The tool runs AS THE PERSON WHO ASKED ────
    #
    # `dispatch()` proxies most tools back to the gateway over HTTP. It used
    # to present a controller-HMAC bearer minted as `mcp-server` — an
    # internal service with full access — so a tool call arrived at the
    # gateway with more authority than the user who triggered it, and with
    # no subject for RBAC or the exec-approval gate to bind to.
    #
    # `set_caller_identity` makes `_auth_headers` present a user token
    # instead. The NAME is the verified bus principal; the TOKEN is the one
    # the gateway minted for this dispatch — this worker
    # holds no signing secret and never mints one.
    #
    # ContextVar, so it covers the whole dispatch tree without threading an
    # argument through every tool; set inside this handler's own task, which
    # `worker_pool` gives each request.
    from ..gateway import bus_principal

    principal = bus_principal.of(request)
    if principal is not None and principal.is_user:
        if not delegated:
            # A gateway older than this worker (it mints nothing), or a
            # mint that failed on the gateway. Loud, and the call does not
            # run: the alternative is running it as somebody else.
            log.error("tool.delegated_token_missing", tool=name, sub=principal.sub)
            return {
                "success": False,
                "error": (
                    f"refused: the gateway sent no delegated token for {principal.sub!r}, and this "
                    "worker does not mint one. Roll the gateway and worker together."
                ),
            }
        from ..mcp.tool_models import set_caller_identity

        set_caller_identity(principal.sub, principal.scopes, delegated)
        log.debug(
            "tool.caller_bound", tool=name, sub=principal.sub, scopes=principal.scopes
        )

    # ── And the approval row it may raise is bound to that turn (R41) ──
    #
    # `exec_approval` keys the chat shorthand on conversation_id, so an
    # unbound row is decidable by a bare `y` typed anywhere — or, once bound
    # to the WRONG conversation, by somebody who never saw the call. The
    # gateway attaches `conversation_id`/`channel` beside `arguments`
    # (tools.rs) and the verified principal supplies `_requester`; this binds
    # all three for the duration of the dispatch.
    #
    # Unguarded, now that #126 has landed. It was wrapped in an ImportError
    # guard while the consumer half was in flight; the guard is gone rather
    # than kept "just in case", because a binding that can silently not
    # happen is the failure R41 describes, and an import that fails loudly at
    # module load is the better outcome by a wide margin.
    from ..gateway.exec_approval import (
        TurnPrincipal,
        bind_turn_principal,
        reset_turn_principal,
    )

    token = bind_turn_principal(TurnPrincipal.from_envelope(request))
    try:
        return await _tool_generic_inner(name, args)
    finally:
        reset_turn_principal(token)


async def _tool_generic_inner(name: str, args: Any) -> Any:
    """The dispatch ladder itself. Split out so the principal binding above
    has a single, unmissable `finally`."""
    # 1. Try new Pydantic ToolDef registry (FastMCP models)
    try:
        from ..mcp.tool_models import call_tool, get_tool_class
        if get_tool_class(name):
            output = await call_tool(name, args)
            return {"success": True, "output": str(output)[:4000]}
    except Exception:
        pass

    # 2. Try the gateway tool registry (ToolRegistry with executors)
    try:
        from ..gateway.tools_executor import get_tool_registry
        registry = get_tool_registry()
        if registry:
            executor = registry.get_executor(name)
            if executor:
                result = await registry.execute_tool(name, **args)
                output = result.output if hasattr(result, 'output') else str(result)
                success = result.success if hasattr(result, 'success') else True
                error = getattr(result, 'error', None)
                return {"success": success, "output": str(output)[:4000], **({"error": error} if error else {})}
    except Exception:
        pass

    # 3. Fallback: filter-enforcing dispatch (ex-shim entry point)
    try:
        from ..mcp.tool_models import handle_tool_call
        output = await handle_tool_call(name, args)
        return {"success": True, "output": str(output)[:4000]}
    except Exception as e:
        return {"success": False, "error": str(e)}
