# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The worker-side approval gate must bind its rows the way migration 070
says, and must never bind a value the model chose.

`ExecApprovalManager._db_insert` is the Python twin of the Rust gate in
`middleware.rs::wait_for_exec_approval`. Since migration 070 an approval row
carries requester / conversation_id / channel / chat_id, and every surface
that lists or decides those rows is scoped by them. A worker-raised row that
leaves all four NULL is not wrong — an unattended turn genuinely has no
requester — but a row that binds a value the MODEL supplied is: it would
claim to be somebody else's request, and a bare `y` typed in that person's
chat would decide it.

These tests capture the SQL parameters `_db_insert` actually sends, so they
fail if the columns are dropped from the statement, if the values stop being
read from the principal, or if `arguments` ever becomes a binding source.
"""
from contextlib import asynccontextmanager

import pytest

from noomesh.gateway.exec_approval import (
    ApprovalRequest,
    ExecApprovalManager,
    RiskLevel,
    ToolCall,
    TurnPrincipal,
    bind_turn_principal,
    reset_turn_principal,
)


class _CapturingConn:
    def __init__(self, sink):
        self._sink = sink

    async def execute(self, statement, params=None):
        self._sink.append((str(statement), params))
        return None

    async def commit(self):
        pass


class _CapturingEngine:
    """Records every (sql, params) pair the manager sends."""

    def __init__(self):
        self.calls = []

    def connect(self):
        sink = self.calls

        @asynccontextmanager
        async def _cm():
            yield _CapturingConn(sink)

        return _cm()


async def _insert(monkeypatch, req):
    mgr = ExecApprovalManager(mode="approval")
    engine = _CapturingEngine()
    # Pin the engine past the SELECT 1 probe so the capture below is the
    # INSERT and nothing else.
    mgr._resolved_engine = engine
    await mgr._db_insert(req)
    assert engine.calls, (
        "the gate must have written something — an empty capture means the "
        "insert was skipped, not that it bound correctly"
    )
    sql, params = engine.calls[-1]
    assert "INSERT INTO noo_approval_requests" in sql
    return sql, params


# ── 1. The four columns are in the statement at all ──────────────────────


async def test_insert_names_the_070_columns(monkeypatch):
    sql, params = await _insert(
        monkeypatch,
        ApprovalRequest(tool_call=ToolCall(name="shell"), risk_level=RiskLevel.HIGH),
    )
    for column in ("requester", "conversation_id", "channel", "chat_id"):
        assert column in sql, f"migration 070's {column} dropped out of the insert"
        assert column in params, f"{column} is named but never bound"


# ── 2. A bound principal reaches the row ─────────────────────────────────


async def test_a_bound_principal_is_written(monkeypatch):
    token = bind_turn_principal(
        TurnPrincipal(
            requester="ada",
            conversation_id="conv-1",
            channel="telegram",
            chat_id="55",
        )
    )
    try:
        req = ApprovalRequest(
            tool_call=ToolCall(name="shell"), risk_level=RiskLevel.HIGH
        )
    finally:
        reset_turn_principal(token)

    # Captured at construction, so resetting the context above cannot unbind
    # it — the DB write happens after an await.
    _, params = await _insert(monkeypatch, req)
    assert params["requester"] == "ada"
    assert params["conversation_id"] == "conv-1"
    assert params["channel"] == "telegram"
    assert params["chat_id"] == "55"


# ── 3. Nothing bound means NULL, never a placeholder ──────────────────────


async def test_an_unattended_turn_writes_nulls(monkeypatch):
    req = ApprovalRequest(tool_call=ToolCall(name="shell"), risk_level=RiskLevel.HIGH)
    _, params = await _insert(monkeypatch, req)
    for column in ("requester", "conversation_id", "channel", "chat_id"):
        assert params[column] is None, (
            f"{column} must be SQL NULL for an unattended turn, not "
            f"{params[column]!r} — an invented value is decidable by "
            "somebody else's chat shorthand"
        )


async def test_partial_binding_keeps_the_rest_null(monkeypatch):
    token = bind_turn_principal(TurnPrincipal(requester="ada"))
    try:
        req = ApprovalRequest(
            tool_call=ToolCall(name="shell"), risk_level=RiskLevel.HIGH
        )
    finally:
        reset_turn_principal(token)
    _, params = await _insert(monkeypatch, req)
    assert params["requester"] == "ada"
    assert params["conversation_id"] is None
    assert params["channel"] is None
    assert params["chat_id"] is None


# ── 4. The envelope reader: gateway keys yes, model arguments no ──────────


def test_envelope_binds_gateway_authored_siblings():
    p = TurnPrincipal.from_envelope(
        {
            "name": "shell",
            "arguments": {"cmd": "ls"},
            "_requester": {"sub": "ada", "scopes": ["read"]},
            "conversation_id": "conv-1",
            "channel": "telegram",
            "chat_id": "55",
        }
    )
    assert p == TurnPrincipal("ada", "conv-1", "telegram", "55")
    assert p.bound


def test_envelope_never_reads_model_authored_arguments():
    """The hostile case. `arguments` is written by the model, so a principal
    taken from there is one the model chose for itself."""
    p = TurnPrincipal.from_envelope(
        {
            "name": "shell",
            "arguments": {
                "_requester": {"sub": "root"},
                "conversation_id": "somebody-elses-conversation",
                "channel": "telegram",
                "chat_id": "55",
                "requester": "root",
            },
        }
    )
    assert p == TurnPrincipal(), (
        "a model-supplied identity must not bind: it would make the request "
        "decidable from a conversation that never raised it"
    )
    assert not p.bound


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {},
        {"name": "shell", "arguments": {}},          # today's worker.tool.generic
        {"_requester": "ada"},                       # not a dict
        {"_requester": {"sub": ""}},                 # empty
        {"_requester": {"sub": "   "}},              # whitespace
        {"conversation_id": 12345},                  # not a string
    ],
)
def test_envelope_without_a_usable_principal_binds_nothing(envelope):
    assert TurnPrincipal.from_envelope(envelope) == TurnPrincipal()


def test_values_are_trimmed_not_mangled():
    p = TurnPrincipal.from_envelope(
        {"_requester": {"sub": "  ada  "}, "conversation_id": " conv-1 "}
    )
    assert p.requester == "ada"
    assert p.conversation_id == "conv-1"


# ── 5. The dict the CLI/heartbeat render must carry the binding ───────────


def test_to_dict_exposes_the_binding():
    token = bind_turn_principal(TurnPrincipal(requester="ada", conversation_id="c1"))
    try:
        d = ApprovalRequest(tool_call=ToolCall(name="shell")).to_dict()
    finally:
        reset_turn_principal(token)
    assert d["requester"] == "ada"
    assert d["conversation_id"] == "c1"
    assert d["channel"] is None
    assert d["chat_id"] is None
