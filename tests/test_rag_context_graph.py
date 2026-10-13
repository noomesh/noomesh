# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The graph layer of the auto-injected KB context (worker.rag.context).

gateway-rust/src/coordinator/context.rs::fetch_rag_context reads
``graph_context.hypotheses[].{description,confidence}`` and
``graph_context.seed_entities[].canonical_name`` off the reply. The handler
returned neither, so "the coordinator's context carries the top graph
relationships" was false on every install (docs audit 2026-10-08).
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from noomesh.workers import rag as wrag

CONTEXT_RS = Path(__file__).resolve().parents[1] / "gateway-rust/src/coordinator/context.rs"


@dataclass
class _Pack:
    text: str
    title: str


@dataclass
class _Hyp:
    description: str
    confidence: float
    path: list = field(default_factory=list)
    edges: list = field(default_factory=list)


@dataclass
class _GraphResult:
    seed_entities: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)


class _Retriever:
    def __init__(self):
        self.roles = "unset"

    async def retrieve(self, q, top_k=5, roles=None):
        self.roles = roles
        return [_Pack("page text", "Doc A")]


class _Nav:
    """Navigator over an in-memory graph whose edges carry the audience of the
    document they came from, honouring ``roles`` the way the add-on's
    audience-scoped store does (an edge from an unreadable doc is not walked)."""

    EDGES = [
        ("Alpha", "USES", "Beta", 0.5, "team"),
        ("Alpha", "CAUSES", "SecretCo", 0.9, "admin"),
        ("Beta", "PART_OF", "Gamma", 0.7, "team"),
        ("Alpha", "SIMILAR_TO", "Delta", 0.2, "team"),
        ("Alpha", "DEPENDS_ON", "Eps", 0.6, "team"),
    ]
    #: document id each audience's edges came from
    DOC = {"team": "d_team", "admin": "d_admin"}

    def __init__(self):
        self.calls = []

    async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, roles=None):
        self.calls.append({"roles": roles, "max_hops": max_hops})
        edges = [e for e in self.EDGES if roles is None or e[4] in roles]
        names = {n for e in edges for n in (e[0], e[2])}
        seeds = [{"canonical_name": n, "entity_id": f"id-{n}"} for n in sorted(names)]
        hyps = [
            _Hyp(f"{a} --[{r}]--> {b}", c, edges=[{"evidence": {"doc_id": self.DOC[aud]}}])
            for a, r, b, c, aud in edges
        ]
        return _GraphResult(seeds, hyps)


class _RAG:
    _started = True

    def __init__(self, navigator=None):
        self.retriever = _Retriever()
        self.navigator = navigator


def _sole_account(monkeypatch):
    from noomesh.identity import scope

    scope.reset_scope_cache()

    async def _fake():
        return "solo", "sole_account"

    monkeypatch.setattr(scope, "_sole_account", _fake)


def _confirm_audience(monkeypatch, ok=True):
    from noomesh.workers import graph as wgraph

    monkeypatch.setattr(
        wgraph, "_intel_audience",
        lambda op: (object(), None) if ok else (None, {"error": "not audience-aware"}),
    )


READABLE_DOCS = {"d_team"}  # what the "team" audience may read in the fake world


@pytest.fixture
def setup(monkeypatch):
    _sole_account(monkeypatch)
    _confirm_audience(monkeypatch)

    async def _operator(user_id):
        return True

    async def _readable(rag, mod, roles, *, docs, entities):
        return (docs & READABLE_DOCS, {e for e in entities if e != "id-SecretCo"})

    monkeypatch.setattr(wrag, "_account_may_read_graph", _operator)
    monkeypatch.setattr(wrag, "_readable_ids", _readable)

    def _install(rag, roles="keep"):
        monkeypatch.setattr(wrag, "_get_rag", lambda: rag)
        if roles != "keep":
            monkeypatch.setattr(wrag, "_resolve_kb_roles", lambda *a, **k: roles)
        return rag

    return _install


async def test_intelligent_tier_returns_bounded_confidence_ordered_graph(setup):
    rag = setup(_RAG(_Nav()), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    g = out["graph_context"]
    hyps = g["hypotheses"]
    assert 0 < len(hyps) <= wrag.GRAPH_MAX_HYPOTHESES
    confs = [h["confidence"] for h in hyps]
    assert confs == sorted(confs, reverse=True)
    assert 0 < len(g["seed_entities"]) <= wrag.GRAPH_MAX_SEEDS
    assert all("canonical_name" in e for e in g["seed_entities"])
    assert "graph_error" not in out and out["answer"]
    assert rag.navigator.calls[0]["roles"] == ["team"]


async def test_base_tier_omits_graph_without_error(setup):
    setup(_RAG(navigator=None), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    assert out["answer"]
    assert "graph_context" not in out and "graph_error" not in out and "error" not in out


async def test_unreadable_document_entity_never_appears(setup):
    setup(_RAG(_Nav()), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    blob = repr(out)
    assert "SecretCo" not in blob
    # the unrestricted caller does see it: the fake really is audience-sensitive
    setup(_RAG(_Nav()), roles=None)
    assert "SecretCo" in repr(await wrag._rag_context({"question": "alpha?"}))


async def test_unconfirmed_audience_support_refuses_graph_but_keeps_pages(setup, monkeypatch):
    rag = setup(_RAG(_Nav()), roles=["team"])
    _confirm_audience(monkeypatch, ok=False)
    out = await wrag._rag_context({"question": "alpha?"})
    assert out["answer"] and "graph_context" not in out
    assert out["graph_error"] == "graph_audience_unconfirmed"
    assert rag.navigator.calls == []  # never walked unfiltered


async def test_graph_timeout_keeps_pages_and_marks_graph_missing(setup, monkeypatch):
    class _Slow(_Nav):
        async def navigate(self, *a, **k):
            await asyncio.sleep(60)

    monkeypatch.setattr(wrag, "GRAPH_BUDGET_S", 0.05)
    setup(_RAG(_Slow()), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    assert out["answer"] == "page text"
    assert "graph_context" not in out
    assert out["graph_error"] == "graph_timeout"


async def test_graph_exception_keeps_pages_and_marks_graph_missing(setup):
    class _Boom(_Nav):
        async def navigate(self, *a, **k):
            raise RuntimeError("db gone")

    setup(_RAG(_Boom()), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    assert out["answer"] == "page text" and "graph_context" not in out
    assert out["graph_error"].startswith("graph_failed")


async def test_a_hypothesis_with_an_unreadable_or_unrecorded_source_is_dropped(setup):
    """Defence in depth over the scoped walk: even if the navigator hands back a
    relationship, it is returned only when EVERY source document it records is
    readable. An edge with no recorded source cannot be proven, so it is out."""

    class _Leaky(_Nav):  # a navigator that does NOT scope: returns everything
        async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, roles=None):
            res = await super().navigate(query, roles=None)
            res.hypotheses.append(_Hyp("Zed --[R]--> Y", 0.99, edges=[{"evidence": {}}]))      # no source
            res.hypotheses.append(_Hyp("Q --[R]--> W", 0.98, edges=[{"evidence": {
                "doc_id": "d_team", "last_evidence": {"doc_id": "d_admin"}}}]))                  # reinforced by a private doc
            return res

    setup(_RAG(_Leaky()), roles=["team"])
    out = await wrag._rag_context({"question": "alpha?"})
    blob = repr(out)
    for leaked in ("SecretCo", "Zed", "Q --[R]--> W"):
        assert leaked not in blob
    assert out["graph_context"]["hypotheses"]  # the provable ones remain


async def test_a_reinforced_edge_is_dropped_even_when_first_and_last_source_are_readable(setup):
    """readable -> private -> readable leaves first and last readable; the middle one is gone."""

    class _Reinforced(_Nav):
        async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, roles=None):
            res = await super().navigate(query, roles=["team"])
            res.hypotheses.append(_Hyp("R --[X]--> S", 0.99, edges=[{"evidence": {
                "doc_id": "d_team", "reinforced_at": "t", "last_evidence": {"doc_id": "d_team"}}}]))
            return res

    setup(_RAG(_Reinforced()), roles=["team"])
    out = await wrag._rag_context({"question": "q"})
    assert "R --[X]--> S" not in repr(out) and out["graph_context"]["hypotheses"]


async def test_a_seed_with_no_readable_mention_is_dropped_even_if_the_navigator_returns_it(setup):
    class _Leaky(_Nav):
        async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, roles=None):
            return await super().navigate(query, roles=None)

    setup(_RAG(_Leaky()), roles=["team"])
    names = [e["canonical_name"] for e in (await wrag._rag_context({"question": "q"}))["graph_context"]["seed_entities"]]
    assert "SecretCo" not in names and names


async def test_a_failed_provenance_check_serves_no_graph_but_keeps_pages(setup, monkeypatch):
    async def _boom(*a, **k):
        raise RuntimeError("db down")

    setup(_RAG(_Nav()), roles=["team"])
    monkeypatch.setattr(wrag, "_readable_ids", _boom)
    out = await wrag._rag_context({"question": "q"})
    assert out["answer"] and "graph_context" not in out and out["graph_error"].startswith("graph_failed")


async def test_a_read_only_account_gets_no_graph_but_the_same_pages(setup, monkeypatch):
    rag = setup(_RAG(_Nav()), roles=["team"])
    allowed = await wrag._rag_context({"question": "q"})

    async def _read_only(user_id):
        return False

    monkeypatch.setattr(wrag, "_account_may_read_graph", _read_only)
    out = await wrag._rag_context({"question": "q"})
    assert "graph_context" not in out and out["graph_error"] == "graph_role_refused"
    assert out["answer"] == allowed["answer"] and out["citations"] == allowed["citations"]
    assert len(rag.navigator.calls) == 1  # only the operator's call walked the graph


class _Store:
    def __init__(self, row=None, boom=False):
        self._engine = self
        self.row, self.boom = row, boom

    def connect(self):
        return self

    async def __aenter__(self):
        if self.boom:
            raise RuntimeError("db down")
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, *_a, **_k):
        row = self.row

        class _R:
            def first(self_inner):
                return row

        return _R()


@pytest.mark.parametrize(
    "row,boom,expect",
    [
        (None, False, False),                       # no such / disabled account
        ((["read"],), False, False),                # User tier
        (([],), False, False),
        ((["read", "ingest"],), False, False),
        ((["read", "write"],), False, True),      # Operator
        ((["read", "write", "admin"],), False, True),
        (None, True, False),                        # cannot establish the role: refused
    ],
)
async def test_the_role_comes_from_the_account_scopes_like_the_gateway_derives_it(monkeypatch, row, boom, expect):
    monkeypatch.setattr(wrag, "_get_conversation_store", lambda: _Store(row, boom))
    assert await wrag._account_may_read_graph("u") is expect


async def test_graph_error_stays_out_of_the_prompt(setup, monkeypatch):
    """The reason lives in logs and the reply; the gateway never prints it."""
    src = CONTEXT_RS.read_text()
    body = src[src.index("pub(super) async fn fetch_rag_context"):]
    body = body[: body.index("/// Fetch conversation memory")]
    assert "graph_error" not in body  # context.rs does not read it, so it cannot reach the prompt


def test_reply_keys_match_what_the_gateway_reads():
    """One contract: every graph key context.rs reads is one the worker writes."""
    src = CONTEXT_RS.read_text()
    body = src[src.index("pub(super) async fn fetch_rag_context"):]
    body = body[: body.index("/// Fetch conversation memory")]
    assert f'data.get("{wrag.GRAPH_CONTEXT_KEY}")' in body
    gateway_reads = set(re.findall(r'graph\.get\("(\w+)"\)', body))
    assert gateway_reads == {"hypotheses", "seed_entities"}
    for k in ("description", "confidence", "canonical_name"):
        assert f'get("{k}")' in body
    # the take() bounds the worker honours
    assert re.search(r"hypotheses\.iter\(\)\.take\(%d\)" % wrag.GRAPH_MAX_HYPOTHESES, body)
    assert re.search(r"\.take\(%d\)" % wrag.GRAPH_MAX_SEEDS, body)
