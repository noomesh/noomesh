# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A worker error is never blank.

0.6.13-rc.2/rc.3 rehearsal: a bare ``assert`` in trellion's embedder failed
every rag.query, and the operator saw ``Worker error on worker.rag.query: ``
with nothing after it, because the reply carried ``str(e)``.
"""
from __future__ import annotations

import asyncio
import json
from noomesh.gateway import worker_pool
from noomesh.gateway.worker_pool import error_reply, error_text


def test_an_empty_message_names_the_type():
    assert error_text(AssertionError()) == "AssertionError"
    assert error_text(RuntimeError("  ")) == "RuntimeError"
    assert error_reply(AssertionError())["error"] == "AssertionError"


def test_a_message_is_kept_exactly():
    assert error_text(ValueError("question required")) == "question required"
    assert error_reply(KeyError("doc"))["error"] == str(KeyError("doc"))


class _Msg:
    subject = "worker.rag.query"
    reply = "_INBOX.t"
    headers = None

    def __init__(self):
        self.data = json.dumps({"question": "q"}).encode()
        self.sent = None

    async def respond(self, data):
        self.sent = json.loads(data)


def test_a_bare_assert_in_a_handler_replies_with_its_type_and_logs_the_traceback(monkeypatch):
    async def handler(_request):
        raise AssertionError()  # what a bare `assert` raises outside pytest

    monkeypatch.setattr(worker_pool, "get_handler", lambda subject: handler)
    # The principal check runs before dispatch; this test is about what follows it.
    monkeypatch.setattr(worker_pool.bus_principal, "verify_message", lambda headers, subject: None)
    monkeypatch.setattr(worker_pool.bus_principal, "apply_to_request", lambda request, principal: request)
    events = []
    monkeypatch.setattr(worker_pool.log, "warning", lambda event, **kw: events.append((event, kw)))
    msg = _Msg()
    asyncio.run(worker_pool._handle_request(msg))
    assert msg.sent["success"] is False
    assert msg.sent["error"] == "AssertionError"
    (event, kw), = [e for e in events if e[0] == "worker.handler_error"]
    assert kw["error"] == "AssertionError" and kw["exc_info"] is True
