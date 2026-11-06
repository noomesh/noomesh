# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""worker.temporal.extract hands the requester's org to the extractor (i435).

The gateway resolves the org and sends it as ``org_id``. The extractor stamps it
on the entities it writes, because project state is read back with a strict org
match. An extractor from before i435 has no ``org_id`` parameter, so the worker
leaves it out rather than make every call raise and drop every triple.
"""
from __future__ import annotations

import asyncio

from noomesh.workers import graph


class _NewExtractor:
    def __init__(self):
        self.calls = []

    async def extract_and_store(self, message_text, author, conversation_id,
                                entry_id=None, user_id=None, channel=None, org_id=None):
        self.calls.append({"user_id": user_id, "org_id": org_id})
        return 3


class _OldExtractor:
    def __init__(self):
        self.calls = []

    async def extract_and_store(self, message_text, author, conversation_id,
                                entry_id=None, user_id=None, channel=None):
        self.calls.append({"user_id": user_id})
        return 2


REQUEST = {
    "conversation_id": "c1",
    "author": "user",
    "message_text": "we decided to ship rustls only",
    "user_id": "ada",
    "org_id": "acme",
}


def _run(monkeypatch, extractor):
    monkeypatch.setattr(graph, "_get_temporal_extractor", lambda: extractor)
    return asyncio.run(graph._temporal_extract(dict(REQUEST)))


def test_the_requesters_org_reaches_the_extractor(monkeypatch):
    ex = _NewExtractor()
    out = _run(monkeypatch, ex)
    assert out == {"success": True, "data": {"inserted": 3}}
    assert ex.calls == [{"user_id": "ada", "org_id": "acme"}]


def test_no_org_in_the_request_is_passed_as_none(monkeypatch):
    ex = _NewExtractor()
    monkeypatch.setattr(graph, "_get_temporal_extractor", lambda: ex)
    req = {k: v for k, v in REQUEST.items() if k != "org_id"}
    asyncio.run(graph._temporal_extract(req))
    assert ex.calls == [{"user_id": "ada", "org_id": None}]


def test_an_extractor_from_before_i435_still_extracts(monkeypatch):
    ex = _OldExtractor()
    out = _run(monkeypatch, ex)
    assert out == {"success": True, "data": {"inserted": 2}}, out
    assert ex.calls == [{"user_id": "ada"}]
