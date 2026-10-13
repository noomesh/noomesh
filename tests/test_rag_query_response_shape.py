# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`worker.rag.query` reports what it retrieved.

`noo rag query` prints `strategy <s> · intent <i> · <n> evidence pages` from
the response. The handler returned only answer/citations/strategy_used, so the
CLI printed `intent ?` and `0 evidence pages` for every query — a hit and a
retrieval miss were indistinguishable, and the "unclassified intent" it
appeared to report was never real (the intent is a regex classifier).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from noomesh.workers import kb as kb_worker
from noomesh.workers import rag as rag_worker


class _FakeRag:
    _started = True

    def __init__(self, evidence):
        self._evidence = evidence

    async def query(self, question, strategy="hybrid", roles=None):
        return SimpleNamespace(
            answer="",
            citations=[],
            strategy_used="lookup",
            intent="lookup",
            evidence=self._evidence,
        )


def _run(evidence, monkeypatch):
    async def _grants():
        return {}

    monkeypatch.setattr(rag_worker, "_get_rag", lambda: _FakeRag(evidence))
    # The role set now comes from the one resolver entry point both retrieval
    # and the gateway's listing use, so that is what is stubbed.
    monkeypatch.setattr(kb_worker, "_kb_grants_map", _grants)
    monkeypatch.setattr(kb_worker, "_resolve_kb_roles", lambda params, grants=None: None)
    return asyncio.run(rag_worker._rag_query({"question": "what is the codeword"}))


def test_response_carries_intent_and_evidence_count(monkeypatch):
    out = _run([object(), object()], monkeypatch)
    assert out["intent"] == "lookup"
    assert out["evidence_count"] == 2


def test_a_miss_reports_zero_evidence_but_still_the_intent(monkeypatch):
    out = _run([], monkeypatch)
    assert out["intent"] == "lookup"
    assert out["evidence_count"] == 0
