# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`worker.tool.generic` acts as the user with the GATEWAY's token.

End to end through the worker's real entry point — `worker_pool._handle_request`
with a signed `Noo-Principal` header, the real `_tool_generic` handler, the
real `ToolDef` dispatcher — with only the HTTP transport faked, and with NO
`NOO_JWT_SECRET` anywhere in the process.

Two properties:

* the outbound call to the gateway carries exactly the token the gateway put
  in the envelope, and a user dispatch without one is refused before any
  HTTP happens (a new worker behind an old gateway fails loud);
* the token is a bearer, so it never lands anywhere that outlives the call:
  not in the handler's reply, not in a log line, not in an audit row, not in
  the request dict the handler leaves behind.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time

import httpx
import pytest
import structlog

from noomesh.gateway import bus_principal as bp
from noomesh.gateway import worker_pool
from noomesh.mcp import tool_models
from noomesh.workers.tools import DELEGATED_TOKEN_KEY

KEYS = {"worker": "worker-bus-key"}  # the worker's OWN bus key
SUBJECT = "worker.tool.generic"
TOKEN = "eyJhbGciOiJFUzI1NiIsImtpZCI6Imt0In0.eyJzdWIiOiJhbGljZSJ9.DELEGATED-BEARER-SIG"  # leak-ok: fabricated JWT (unsigned "DELEGATED-BEARER-SIG" tail) for the redaction test
TOOL = "noo_graph_stats"


def _sign(sub: str = "alice", kind: str = "user", scopes=("read",)) -> str:
    now = int(time.time())
    claims = {
        "sub": sub, "kind": kind, "role": "user", "scopes": list(scopes),
        "subj": SUBJECT, "iat": now, "exp": now + 60, "nonce": f"n{time.time_ns()}",
    }
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    mac = hmac.new(KEYS["worker"].encode(), f"worker.{body}".encode(), hashlib.sha256).hexdigest()
    return f"{body}.worker={mac}"


class FakeMsg:
    def __init__(self, data: dict, headers: dict):
        self.subject = SUBJECT
        self.data = json.dumps(data).encode()
        self.headers = headers
        self.reply = "_INBOX.test"
        self.responses: list[dict] = []

    async def respond(self, payload: bytes) -> None:
        self.responses.append(json.loads(payload.decode()))


@pytest.fixture
def world(monkeypatch):
    """A worker with no login signing secret, a fake gateway transport, and
    every sink the envelope could reach recorded."""
    monkeypatch.setenv("NOO_BUS_KEY", KEYS["worker"])
    monkeypatch.setenv("NOO_BUS_AUDIENCE", "worker")
    monkeypatch.delenv("NOO_BUS_PRINCIPAL", raising=False)
    monkeypatch.delenv("NOO_JWT_SECRET", raising=False)
    monkeypatch.delenv("NOO_JWT_SECRET_FILE", raising=False)
    bp.reset_nonce_cache()
    import noomesh.workers.tools  # noqa: F401 — registers the handler

    assert tool_models.get_tool_class(TOOL), f"{TOOL} is not a ToolDef any more — pick another"

    seen: list[httpx.Request] = []

    def _gateway(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"entities": 3})

    monkeypatch.setattr(
        tool_models, "_http_client", httpx.AsyncClient(transport=httpx.MockTransport(_gateway))
    )

    audits: list[str] = []

    def _audit(*a, **kw):
        audits.append(repr((a, kw)))

    monkeypatch.setattr("noomesh.gateway.audit_log.audit", _audit)
    yield {"seen": seen, "audits": audits}
    bp.reset_nonce_cache()


def _run(msg: FakeMsg, caplog) -> tuple[list[dict], str]:
    caplog.set_level(logging.DEBUG)
    with structlog.testing.capture_logs() as captured:
        asyncio.run(worker_pool._handle_request(msg))
    return captured, caplog.text


def test_the_tool_calls_the_gateway_with_the_envelope_token(world, caplog):
    msg = FakeMsg(
        {"name": TOOL, "arguments": {}, "conversation_id": "c1", DELEGATED_TOKEN_KEY: TOKEN},
        {bp.HEADER: _sign()},
    )
    captured, text = _run(msg, caplog)
    assert msg.responses and msg.responses[0].get("success") is True, msg.responses
    assert msg.responses[0]["data"].get("success") is True, msg.responses
    assert len(world["seen"]) == 1, "the tool should have made exactly one gateway call"
    assert world["seen"][0].headers["authorization"] == f"Bearer {TOKEN}"

    # …and nothing that outlives the call carries it.
    assert TOKEN not in json.dumps(msg.responses), "reply"
    assert TOKEN not in repr(captured), "structlog lines"
    assert "DELEGATED-BEARER-SIG" not in text, "stdlib log lines"
    assert not any("DELEGATED-BEARER-SIG" in a for a in world["audits"]), "audit rows"


def test_the_handler_pops_the_token_before_anything_reads_the_request(world):
    """The request dict the handler is given is the one every later reader
    (approval rows, error paths) sees; the token must be gone from it."""
    from noomesh.workers import tools

    request = {"name": TOOL, "arguments": {}, DELEGATED_TOKEN_KEY: TOKEN}
    request = bp.apply_to_request(request, bp.verify_message({bp.HEADER: _sign()}, SUBJECT))
    asyncio.run(tools._tool_generic(request))
    assert DELEGATED_TOKEN_KEY not in request
    assert TOKEN not in repr(request)


def test_a_user_dispatch_without_a_token_is_refused_before_any_http(world, caplog):
    """A new worker behind an old gateway: loud, and nothing runs."""
    msg = FakeMsg({"name": TOOL, "arguments": {}}, {bp.HEADER: _sign()})
    captured, _ = _run(msg, caplog)
    inner = msg.responses[0]["data"]
    assert inner["success"] is False
    assert "no delegated token" in inner["error"], inner
    assert world["seen"] == [], "refused means NO call — not a call with some other credential"
    assert any(e.get("event") == "tool.delegated_token_missing" for e in captured), captured


def test_an_internal_principal_never_presents_a_user_token(world, monkeypatch, caplog):
    """A loop acting on its own account dispatches with the container's
    service credential; a stray token in its envelope is dropped, not used."""
    monkeypatch.setattr(
        "noomesh.cluster.cluster_auth.internal_gateway_headers",
        lambda actor: {"Authorization": f"Bearer svc-{actor}"},
    )
    msg = FakeMsg(
        {"name": TOOL, "arguments": {}, DELEGATED_TOKEN_KEY: TOKEN},
        {bp.HEADER: _sign(sub="internal:heartbeat", kind="internal")},
    )
    _run(msg, caplog)
    assert len(world["seen"]) == 1
    assert world["seen"][0].headers["authorization"] == "Bearer svc-mcp-server"
