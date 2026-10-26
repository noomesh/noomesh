# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Exec Approval Manager -- risk-based tool execution gating.

ℹ️ LIVE PYTHON LIBRARY — NOT a router. The ``/api/exec-approval/status``
HTTP endpoint is Rust-native (``gateway-rust/src/routes/admin.rs``), but
this module's ``ExecApprovalManager`` class is the actual gating logic
called by Python tools (``tools/local_files.py``). Stays Python until
 turns it into an ``ExecApprovalGate`` provider
injected into the harness.

Classifies tool calls by risk level and applies approval policies:
- LOW: auto-approve silently (web_search, rag_query, etc.)
- MEDIUM: log + auto-approve (python_tool, browser)
- HIGH: depends on mode (auto/approval/strict)

Modes:
- auto: log HIGH calls, execute after configurable timeout
- approval: send approval request to user channel, wait for confirmation
- strict: deny HIGH calls unless explicitly pre-approved
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"


# Default risk classification map
DEFAULT_RISK_MAP: Dict[str, RiskLevel] = {
    # LOW risk -- read-only, no side effects
    "web_search": RiskLevel.LOW,
    "rag_query": RiskLevel.LOW,
    "rag_status": RiskLevel.LOW,
    "memory_search": RiskLevel.LOW,
    "graph_search": RiskLevel.LOW,
    "graph_neighbors": RiskLevel.LOW,
    "graph_entity_detail": RiskLevel.LOW,
    "cluster_status": RiskLevel.LOW,
    "local_files_read": RiskLevel.LOW,
    "recall_memory_search": RiskLevel.LOW,
    "video_memory_search": RiskLevel.LOW,  # deprecated name
    "conversation_context": RiskLevel.LOW,
    # MEDIUM risk -- side effects but contained
    "python_tool": RiskLevel.MEDIUM,
    "browser": RiskLevel.MEDIUM,
    "rag_ingest": RiskLevel.MEDIUM,
    "channel_send": RiskLevel.MEDIUM,
    "inference": RiskLevel.MEDIUM,
    "agentic_inference": RiskLevel.MEDIUM,
    "job_submit": RiskLevel.MEDIUM,
    # HIGH risk -- writes, deletes, system-level
    "local_files_write": RiskLevel.HIGH,
    "local_files_delete": RiskLevel.HIGH,
    "skill_execute": RiskLevel.HIGH,
    "shell": RiskLevel.HIGH,
    "noo_coding_task": RiskLevel.HIGH,
}


# ---------------------------------------------------------------------------
# Tool call representation
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """Represents a tool call to be approved."""
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    action: str = ""  # e.g. "read", "write", "delete" for local_files

    @property
    def qualified_name(self) -> str:
        """Return name_action if action is set, else just name."""
        if self.action:
            return f"{self.name}_{self.action}"
        return self.name


# ---------------------------------------------------------------------------
# Turn principal — who raised this, and where (migration 070)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TurnPrincipal:
    """Who a worker-side tool call belongs to, and where it was raised.

    The Python twin of the Rust gateway's ``TURN_PRINCIPAL`` task-local
    (``routes/communication.rs::turn_principal``), whose four values migration
    070 added to ``noo_approval_requests``. Every field is optional and every
    missing field is written as SQL ``NULL``.

    **NULL is a real answer, not a gap to fill.** An unattended turn
    (heartbeat, autonomy) genuinely has no requester and no conversation, and
    ``channels::approvals`` scopes the chat shorthand to ``conversation_id``
    — so an unbound row is decidable only by naming its id, which is correct:
    nobody is sitting in its conversation to type ``y``. Inventing a value
    here would do the opposite of what the binding exists for. It would let a
    bare ``y`` in somebody's chat decide a request that chat never saw.

    **Where the values may come from.** Only from context the gateway
    attached server-side. Never from a tool call's ``arguments``: those are
    written by the MODEL, so a binding taken from them is a principal the
    model chose for itself — an approval request that claims to be somebody
    else's, decidable in somebody else's chat. :meth:`from_envelope` reads
    only the envelope keys that sit BESIDE ``arguments``, and there is a test
    that feeds it a hostile ``arguments`` payload and asserts nothing binds.
    """

    requester: Optional[str] = None
    conversation_id: Optional[str] = None
    channel: Optional[str] = None
    chat_id: Optional[str] = None

    @staticmethod
    def _clean(value: Any) -> Optional[str]:
        """A non-empty string, or None. Anything else is not a principal."""
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value or None

    @classmethod
    def from_envelope(cls, envelope: Optional[Dict[str, Any]]) -> "TurnPrincipal":
        """Read the principal from a worker RPC envelope.

        The envelope is the dict a ``worker.*`` handler receives over NATS.
        Its ``arguments`` member is model-authored and is NOT consulted; the
        siblings of ``arguments`` are gateway-authored and are.

        Returns an all-NULL principal when the envelope carries nothing,
        which is the honest state of ``worker.tool.generic`` today: the Rust
        side sends ``{"name", "arguments"}`` and no identity at all. Track M
        (bus-principal) is what puts a verified principal on that envelope;
        until it lands this binds nothing on that path, and says so rather
        than guessing.
        """
        if not isinstance(envelope, dict):
            return cls()
        requester = envelope.get("_requester")
        sub = cls._clean(requester.get("sub")) if isinstance(requester, dict) else None
        return cls(
            requester=sub,
            conversation_id=cls._clean(envelope.get("conversation_id")),
            channel=cls._clean(envelope.get("channel")),
            chat_id=cls._clean(envelope.get("chat_id")),
        )

    @property
    def bound(self) -> bool:
        """True when at least one column will be non-NULL."""
        return any((self.requester, self.conversation_id, self.channel,
                    self.chat_id))


_TURN_PRINCIPAL: "contextvars.ContextVar[TurnPrincipal]" = contextvars.ContextVar(
    "noo_exec_approval_turn_principal", default=TurnPrincipal()
)


def bind_turn_principal(principal: TurnPrincipal) -> "contextvars.Token":
    """Bind the principal for every approval raised in this context.

    Call it once per worker turn, from the handler that OWNS the envelope —
    the same place the Rust coordinator scopes its task-local. Returns the
    token so a caller that shares its context can reset it.
    """
    return _TURN_PRINCIPAL.set(principal)


def reset_turn_principal(token: "contextvars.Token") -> None:
    """Undo a :func:`bind_turn_principal`."""
    _TURN_PRINCIPAL.reset(token)


def turn_principal() -> TurnPrincipal:
    """The principal bound for this context, or the all-NULL one."""
    return _TURN_PRINCIPAL.get()


@dataclass
class ApprovalRequest:
    """A pending approval request."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    tool_call: Optional[ToolCall] = None
    risk_level: RiskLevel = RiskLevel.LOW
    status: ApprovalStatus = ApprovalStatus.PENDING
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    resolved_by: str = ""
    # Captured at CONSTRUCTION, not at insert: the DB write happens after an
    # await, and the context that awaits is not guaranteed to be the context
    # that raised the request.
    principal: TurnPrincipal = field(default_factory=turn_principal)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool_call.qualified_name if self.tool_call else "",
            "arguments": self.tool_call.arguments if self.tool_call else {},
            "risk_level": self.risk_level.value,
            "status": self.status.value,
            "reason": self.reason,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "requester": self.principal.requester,
            "conversation_id": self.principal.conversation_id,
            "channel": self.principal.channel,
            "chat_id": self.principal.chat_id,
        }


@dataclass
class ApprovalResult:
    """Result of an approval check."""
    status: ApprovalStatus
    request_id: str = ""
    reason: str = ""

    @property
    def approved(self) -> bool:
        return self.status == ApprovalStatus.APPROVED


# ---------------------------------------------------------------------------
# ExecApprovalManager
# ---------------------------------------------------------------------------

class ExecApprovalManager:
    """Risk-based tool execution approval gate.

    Usage:
        manager = ExecApprovalManager(mode="approval", timeout=300)
        result = await manager.check(tool_call)
        if result.approved:
            execute_tool(tool_call)
        else:
            log.warning("tool_denied", reason=result.reason)
    """

    # Default mode mirrors gateway-rust `middleware::DEFAULT_EXEC_APPROVAL_MODE`
    # (`strict`). This is the value used when the caller passes nothing — a
    # worker that failed to read config, or a docstring-following test. It used
    # to be "auto", so the fallback manager the worker builds on a config error
    # ran every HIGH-risk tool ungated, which is the opposite of what a config
    # error should produce.
    DEFAULT_MODE = "strict"

    def __init__(
        self,
        mode: str = DEFAULT_MODE,
        timeout: int = 300,
        risk_map: Optional[Dict[str, RiskLevel]] = None,
        high_risk_tools: Optional[List[str]] = None,
        medium_risk_tools: Optional[List[str]] = None,
        approval_callback: Optional[Callable[..., Coroutine]] = None,
    ):
        self.mode = mode  # "auto", "approval", "strict"
        self.timeout = timeout
        self._risk_map = dict(DEFAULT_RISK_MAP)
        if risk_map:
            self._risk_map.update(risk_map)

        # Override from config lists
        if high_risk_tools:
            for tool in high_risk_tools:
                self._risk_map[tool] = RiskLevel.HIGH
        if medium_risk_tools:
            for tool in medium_risk_tools:
                self._risk_map[tool] = RiskLevel.MEDIUM

        self._approval_callback = approval_callback
        self._pending: Dict[str, ApprovalRequest] = {}
        self._events: Dict[str, asyncio.Event] = {}
        self._resolved_engine = None  # cached after a one-time probe

    # ------------------------------------------------------------------
    # DB bridge (noo_approval_requests)
    #
    # The Rust gateway serves /api/approval/* straight from SQL, and the
    # CLI/dashboard decide there — but the blocked caller waits HERE, in
    # this process. Mirroring the queue into the table and polling it is
    # what connects the two: a row flipped to approved/denied by any
    # process releases the in-memory wait. Every DB step is best-effort;
    # with no engine the manager degrades to the old in-memory-only
    # behaviour (same-process approve/deny still works).
    # ------------------------------------------------------------------

    async def _db_engine(self):
        """Resolve a WORKING async engine for the mirror, cached after a
        one-time probe.

        Two engines exist depending on process: the coordinator gate runs
        in the worker, where the conversation store's engine is the one
        that actually connects; the HTTP lifespan has noomesh's
        get_async_engine(). We can't assume either is initialized, and —
        found via a fire drill 2026-07-12 — noomesh's engine can be
        initialized-but-BROKEN: it presents the 0644 leaf TLS key (the
        container-read cert contract), which psycopg refuses as
        world-readable. So don't trust an engine by mere existence; probe
        it with SELECT 1 and cache the first that answers."""
        from sqlalchemy import text as _sql_text

        if getattr(self, "_resolved_engine", None) is not None:
            return self._resolved_engine

        candidates = []
        try:  # worker process — the proven-working engine in practice
            from .worker_pool import _get_conversation_store
            store = _get_conversation_store()
            if store is not None and getattr(store, "_engine", None) is not None:
                candidates.append(store._engine)
        except Exception as e:
            logger.debug("exec_approval_worker_engine_unavailable", error=str(e))
        try:  # HTTP lifespan process
            from ..db.engine import get_async_engine
            eng = get_async_engine()
            if eng is not None and eng not in candidates:
                candidates.append(eng)
        except Exception as e:
            logger.debug("exec_approval_lifespan_engine_unavailable", error=str(e))

        for eng in candidates:
            try:
                async with eng.connect() as conn:
                    await conn.execute(_sql_text("SELECT 1"))
                self._resolved_engine = eng
                return eng
            except Exception as exc:
                logger.debug("exec_approval_engine_probe_failed", error=str(exc))
        return None

    async def _db_insert(self, req: ApprovalRequest) -> None:
        eng = await self._db_engine()
        if eng is None:
            return
        try:
            from sqlalchemy import text as _sql_text
            args_summary = ""
            if req.tool_call and req.tool_call.arguments:
                args_summary = json.dumps(req.tool_call.arguments, default=str)[:300]
            async with eng.connect() as conn:
                await conn.execute(_sql_text(
                    # Migration 070's binding, written by the worker-side
                    # gate too — the Rust gate is not the only producer of
                    # these rows, and an unbound row is invisible to every
                    # scoped surface that reads them (`noo approval
                    # pending`, the Admin view, and the chat shorthand).
                    #
                    # What binds on each path, exactly:
                    #   * a turn with a principal bound by its handler
                    #     (`bind_turn_principal`) → all four columns it
                    #     carries, each one NULL if that field is absent;
                    #   * `worker.tool.generic` today → all four NULL: the
                    #     NATS envelope carries {name, arguments} and no
                    #     identity, so there is nothing to bind and nothing
                    #     is invented. Track M (bus-principal) is what puts
                    #     a verified principal on that envelope;
                    #   * an unattended turn (heartbeat, autonomy) → all
                    #     four NULL by nature, same as the Rust gate.
                    #
                    # A row with a NULL conversation is decidable only by
                    # naming its id: `channels::approvals` scopes a bare `y`
                    # to the conversation it was typed in, so an unbound row
                    # can never be swept up by somebody else's `y`. That is
                    # the #118 shorthand rule, applying unchanged to
                    # worker-raised requests.
                    "INSERT INTO noo_approval_requests "
                    "(request_id, tool_name, risk_level, reason, status, "
                    " requester, conversation_id, channel, chat_id) "
                    "VALUES (:id, :tool, :risk, :reason, 'pending', "
                    "        :requester, :conversation_id, :channel, :chat_id) "
                    "ON CONFLICT (request_id) DO NOTHING"),
                    {"id": req.id,
                     "tool": req.tool_call.qualified_name if req.tool_call else "?",
                     "risk": req.risk_level.value, "reason": args_summary or None,
                     "requester": req.principal.requester,
                     "conversation_id": req.principal.conversation_id,
                     "channel": req.principal.channel,
                     "chat_id": req.principal.chat_id})
                await conn.commit()
            logger.info("exec_approval_db_insert",
                        request_id=req.id, bound=req.principal.bound,
                        requester=req.principal.requester,
                        conversation_id=req.principal.conversation_id)
        except Exception as exc:
            logger.debug("exec_approval_db_insert_failed", error=str(exc))

    async def _db_finalise(self, req: ApprovalRequest) -> None:
        eng = await self._db_engine()
        if eng is None:
            return
        try:
            from sqlalchemy import text as _sql_text
            async with eng.connect() as conn:
                await conn.execute(_sql_text(
                    "UPDATE noo_approval_requests SET status = :s, "
                    "resolved_by = :by, resolved_at = now() "
                    "WHERE request_id = :id AND status = 'pending'"),
                    {"s": req.status.value, "by": req.resolved_by or None,
                     "id": req.id})
                await conn.commit()
        except Exception as exc:
            logger.debug("exec_approval_db_finalise_failed", error=str(exc))

    async def _db_poll(self, request_id: str):
        """Return (status, resolved_by, reason) from the table, or None."""
        eng = await self._db_engine()
        if eng is None:
            return None
        try:
            from sqlalchemy import text as _sql_text
            async with eng.connect() as conn:
                row = (await conn.execute(_sql_text(
                    "SELECT status, resolved_by, reason "
                    "FROM noo_approval_requests WHERE request_id = :id"),
                    {"id": request_id})).fetchone()
            return (row[0], row[1] or "", row[2] or "") if row else None
        except Exception as exc:
            logger.debug("exec_approval_db_poll_failed", error=str(exc))
            return None

    async def _wait_resolved(self, req: ApprovalRequest,
                             event: asyncio.Event) -> None:
        """Wait until the request resolves (same-process event or a DB
        row flipped by the dashboard/CLI) or the timeout passes."""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            slice_s = min(2.0, max(deadline - time.time(), 0.05))
            try:
                await asyncio.wait_for(event.wait(), timeout=slice_s)
            except asyncio.TimeoutError:
                pass
            if req.status != ApprovalStatus.PENDING:
                return
            external = await self._db_poll(req.id)
            if external and external[0] in ("approved", "denied"):
                status, by, reason = external
                req.status = (ApprovalStatus.APPROVED if status == "approved"
                              else ApprovalStatus.DENIED)
                req.resolved_by = by
                if status == "denied" and reason:
                    req.reason = reason
                req.resolved_at = time.time()
                logger.info("exec_approval_resolved_externally",
                            request_id=req.id, status=status, by=by)
                return

    def classify(self, tool_call: ToolCall) -> RiskLevel:
        """Classify the risk level of a tool call.

        For ``python_tool``, the base risk is MEDIUM but auto-escalates to
        HIGH when :func:`check_python_code_safety` detects dangerous patterns
        (subprocess, eval, file deletion, etc.).
        """
        qualified = tool_call.qualified_name
        if qualified in self._risk_map:
            base = self._risk_map[qualified]
        elif tool_call.name in self._risk_map:
            base = self._risk_map[tool_call.name]
        else:
            base = RiskLevel.MEDIUM  # default for unknown tools

        # Auto-escalate python_tool when dangerous code patterns are detected
        if base == RiskLevel.MEDIUM and tool_call.name == "python_tool":
            code = tool_call.arguments.get("code", "")
            if code:
                try:
                    from .security import check_python_code_safety
                    warnings = check_python_code_safety(code)
                    if warnings:
                        logger.warning(
                            "exec_approval_python_escalated",
                            tool=qualified,
                            warnings=warnings,
                        )
                        return RiskLevel.HIGH
                except ImportError:
                    pass

        return base

    async def check(self, tool_call: ToolCall) -> ApprovalResult:
        """Check whether a tool call should be allowed.

        Returns an ApprovalResult immediately for LOW/MEDIUM risk.
        For HIGH risk, behaviour depends on the mode.
        """
        risk = self.classify(tool_call)

        if risk == RiskLevel.LOW:
            return ApprovalResult(status=ApprovalStatus.APPROVED)

        if risk == RiskLevel.MEDIUM:
            logger.info(
                "exec_approval_medium_risk",
                tool=tool_call.qualified_name,
                args_keys=list(tool_call.arguments.keys()),
            )
            return ApprovalResult(status=ApprovalStatus.APPROVED)

        # HIGH risk
        logger.warning(
            "exec_approval_high_risk",
            tool=tool_call.qualified_name,
            mode=self.mode,
            args_keys=list(tool_call.arguments.keys()),
        )

        if self.mode == "auto":
            return await self._auto_approve(tool_call)
        elif self.mode == "approval":
            return await self._request_approval(tool_call)
        else:  # strict
            return ApprovalResult(
                status=ApprovalStatus.DENIED,
                reason=f"Strict mode: HIGH-risk tool '{tool_call.qualified_name}' blocked",
            )

    async def approve(self, request_id: str, approved_by: str = "user") -> None:
        """Approve a pending request."""
        req = self._pending.get(request_id)
        if not req:
            logger.warning("exec_approval_approve_unknown", request_id=request_id)
            return

        req.status = ApprovalStatus.APPROVED
        req.resolved_at = time.time()
        req.resolved_by = approved_by
        tool_name = req.tool_call.qualified_name if req.tool_call else "unknown"
        logger.info(
            "exec_approval_approved",
            request_id=request_id,
            tool=tool_name,
            approved_by=approved_by,
        )
        try:
            from .audit_log import audit
            audit("exec_approved", actor=approved_by, resource=tool_name, outcome="approved")
        except Exception as e:
            logger.warning("exec_approval_audit_failed", event="exec_approved", error=str(e))

        await self._db_finalise(req)
        event = self._events.get(request_id)
        if event:
            event.set()

    async def deny(self, request_id: str, reason: str = "", denied_by: str = "user") -> None:
        """Deny a pending request."""
        req = self._pending.get(request_id)
        if not req:
            logger.warning("exec_approval_deny_unknown", request_id=request_id)
            return

        req.status = ApprovalStatus.DENIED
        req.reason = reason
        req.resolved_at = time.time()
        req.resolved_by = denied_by
        tool_name = req.tool_call.qualified_name if req.tool_call else "unknown"
        logger.info(
            "exec_approval_denied",
            request_id=request_id,
            tool=tool_name,
            reason=reason,
            denied_by=denied_by,
        )
        try:
            from .audit_log import audit
            audit("exec_denied", actor=denied_by, resource=tool_name, outcome="denied", reason=reason)
        except Exception as e:
            logger.warning("exec_approval_audit_failed", event="exec_denied", error=str(e))

        await self._db_finalise(req)
        event = self._events.get(request_id)
        if event:
            event.set()

    def get_pending(self) -> list[ApprovalRequest]:
        """List all currently pending requests."""
        return [
            r for r in self._pending.values()
            if r.status == ApprovalStatus.PENDING
        ]

    def get_stats(self) -> Dict[str, int]:
        """Return counts of requests by status (for heartbeat security audit)."""
        counts: Dict[str, int] = {
            "approved": 0,
            "denied": 0,
            "timed_out": 0,
            "pending": 0,
            "total": 0,
        }
        for req in self._pending.values():
            counts["total"] += 1
            if req.status == ApprovalStatus.APPROVED:
                counts["approved"] += 1
            elif req.status == ApprovalStatus.DENIED:
                counts["denied"] += 1
            elif req.status == ApprovalStatus.TIMED_OUT:
                counts["timed_out"] += 1
            elif req.status == ApprovalStatus.PENDING:
                counts["pending"] += 1
        return counts

    # ------------------------------------------------------------------
    # Internal strategies
    # ------------------------------------------------------------------

    async def _auto_approve(self, tool_call: ToolCall) -> ApprovalResult:
        """Log the HIGH-risk call and execute after timeout. The window is
        mirrored to the DB so an operator can DENY from the dashboard/CLI
        before the timer runs out."""
        req = ApprovalRequest(tool_call=tool_call, risk_level=RiskLevel.HIGH)
        self._pending[req.id] = req
        event = asyncio.Event()
        self._events[req.id] = event
        await self._db_insert(req)

        logger.info(
            "exec_approval_auto_timer_start",
            request_id=req.id,
            tool=tool_call.qualified_name,
            timeout=self.timeout,
        )

        await self._wait_resolved(req, event)
        if req.status == ApprovalStatus.PENDING:
            req.status = ApprovalStatus.TIMED_OUT
            req.resolved_at = time.time()
            logger.info(
                "exec_approval_auto_timeout",
                request_id=req.id,
                tool=tool_call.qualified_name,
            )
        await self._db_finalise(req)

        self._events.pop(req.id, None)

        if req.status in (ApprovalStatus.APPROVED, ApprovalStatus.TIMED_OUT):
            return ApprovalResult(
                status=ApprovalStatus.APPROVED,
                request_id=req.id,
            )
        return ApprovalResult(
            status=ApprovalStatus.DENIED,
            request_id=req.id,
            reason=req.reason or "Denied during auto-approval window",
        )

    async def _request_approval(self, tool_call: ToolCall) -> ApprovalResult:
        """Send approval request and block until resolved or timed out.

        The request is mirrored to noo_approval_requests so the dashboard
        Admin view, ``noo approval``, and the Rust /api/approval/* routes
        can resolve it from outside this process."""
        req = ApprovalRequest(tool_call=tool_call, risk_level=RiskLevel.HIGH)
        self._pending[req.id] = req
        event = asyncio.Event()
        self._events[req.id] = event
        await self._db_insert(req)

        if self._approval_callback:
            try:
                await self._approval_callback(req)
            except Exception as exc:
                logger.error(
                    "exec_approval_callback_error",
                    request_id=req.id,
                    error=str(exc),
                )

        logger.info(
            "exec_approval_waiting",
            request_id=req.id,
            tool=tool_call.qualified_name,
            timeout=self.timeout,
        )

        await self._wait_resolved(req, event)
        if req.status == ApprovalStatus.PENDING:
            # TIMED_OUT is not APPROVED, so the caller gets a denial; the
            # table records the accurate status.
            req.status = ApprovalStatus.TIMED_OUT
            req.reason = "Approval timed out"
            req.resolved_at = time.time()
            logger.warning(
                "exec_approval_timeout_denied",
                request_id=req.id,
                tool=tool_call.qualified_name,
            )
        await self._db_finalise(req)

        self._events.pop(req.id, None)

        if req.status == ApprovalStatus.APPROVED:
            return ApprovalResult(
                status=ApprovalStatus.APPROVED,
                request_id=req.id,
            )
        return ApprovalResult(
            status=ApprovalStatus.DENIED,
            request_id=req.id,
            reason=req.reason or "Denied or timed out",
        )


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_approval_manager: Optional[ExecApprovalManager] = None


def get_approval_manager() -> ExecApprovalManager:
    """Get or create the global ExecApprovalManager."""
    global _approval_manager
    if _approval_manager is None:
        _approval_manager = ExecApprovalManager()
    return _approval_manager


def init_approval_manager(**kwargs) -> ExecApprovalManager:
    """Create and store the global ExecApprovalManager."""
    global _approval_manager
    _approval_manager = ExecApprovalManager(**kwargs)
    return _approval_manager


# Back-compat alias: some callers historically imported ``get_approval_gate``.
get_approval_gate = get_approval_manager  # back-compat alias
