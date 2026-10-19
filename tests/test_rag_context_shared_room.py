# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A group chat / space turn retrieves from shared tiers only.

The gateway marks a channel turn in a non-private chat with
``shared_room: true`` on ``worker.rag.context``. The reply is posted to every
member, so the linked sender's own ``user:<name>`` tier (and granted team
tiers) must not feed it. A private chat is unchanged.
"""
from __future__ import annotations

import pytest

from noomesh.workers import rag as wrag


class _Retriever:
    def __init__(self):
        self.roles = "unset"

    async def retrieve(self, q, top_k=5, roles=None):
        self.roles = roles

        class _P:
            text = "chunk"
            title = "Doc"

        return [_P()]


class _RAG:
    _started = True

    def __init__(self):
        self.retriever = _Retriever()
        self.navigator = None


@pytest.fixture
def rag(monkeypatch):
    from noomesh.identity import scope

    scope.reset_scope_cache()

    async def _sole():
        return "solo", "sole_account"

    async def _grants():
        return {"solo": ["team:red"]}

    monkeypatch.setattr(scope, "_sole_account", _sole)
    monkeypatch.setattr(wrag, "_kb_grants_map", _grants)
    r = _RAG()
    monkeypatch.setattr(wrag, "_get_rag", lambda: r)
    return r


async def test_private_chat_keeps_own_and_granted_tiers(rag):
    await wrag._rag_context({"question": "q"})
    assert "user:solo" in rag.retriever.roles
    assert "team:red" in rag.retriever.roles


async def test_shared_room_retrieves_company_and_system_only(rag):
    out = await wrag._rag_context({"question": "q", "shared_room": True})
    assert out["answer"]
    assert sorted(rag.retriever.roles) == ["company", "system"]


async def test_a_non_true_flag_does_not_narrow_or_widen(rag):
    await wrag._rag_context({"question": "q", "shared_room": "yes"})
    assert "user:solo" in rag.retriever.roles
