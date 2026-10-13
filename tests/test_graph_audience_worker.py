# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The graph worker's audience contract.

A restricted caller is served the Intelligent-tier graph routes only when the
build that answers them filters by audience AND says so: every reply produced
under a verified restricted call carries ``audience_filtered: true``, and the
gateway refuses to forward one that does not. These pin the worker half:

* unrestricted: the original code path, nothing new passed, nothing stamped;
* restricted + an intel build that declares the op: ``roles`` reaches the
  handler, the reply is stamped;
* restricted + an intel build that does not (older trellion-intel): the
  navigator is never called and the reply carries no flag, so the gateway
  fails closed;
* a non-privileged user principal with no audience, or a malformed one, is
  refused;
* every graph handler except the query-only classifier is wrapped.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from noomesh.gateway import bus_principal as bp
from noomesh.workers import graph as g
from noomesh.workers.audience import AUDIENCE_KEY

SRC = pathlib.Path(g.__file__)
ROLES = ["company", "system", "user:a"]


class FakeNav:
    """Records what the handler passed. Accepts `roles` like the new navigator."""

    def __init__(self):
        self.calls = []

    async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, **kw):
        self.calls.append(("navigate", kw))
        return {"query": query}

    async def traverse_with_intent(self, entity_id, query_intent, hops=2, **kw):
        self.calls.append(("traverse", kw))
        return [{"entity_id": "e"}]

    async def explain_path(self, src_entity_id, dst_entity_id, **kw):
        self.calls.append(("explain_path", kw))
        return []


class OldNav:
    """An older trellion-intel navigator: no `roles` parameter at all."""

    def __init__(self):
        self.calls = 0

    async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None):
        self.calls += 1
        return {"query": query, "hidden": "EVERYTHING"}


class FakeAudience:
    def __init__(self, ops=("navigate", "traverse", "explain_path", "semantic_search",
                            "search_clusters", "recall_traversals", "extract_relations")):
        self.ops = set(ops)

    def supports(self, op):
        return op in self.ops


class FakeRag:
    def __init__(self, nav):
        self.navigator = nav
        self.store = object()


@pytest.fixture
def rig(monkeypatch):
    import noomesh.addon_roles as roles_mod

    held: dict = {}

    def provide(obj):
        held["audience"] = obj

    def _provider(role):
        # The add-on's audience scope is a provider role; absent = the tier is not installed.
        if role != roles_mod.AUDIENCE_SCOPE or held.get("audience") is None:
            raise ImportError(f"{role}: requires the Intelligent tier")
        return held["audience"]

    monkeypatch.setattr(roles_mod, "provider", _provider)

    def make(nav, intel=FakeAudience()):
        rag = FakeRag(nav)
        monkeypatch.setattr(g, "_get_rag", lambda: rag)

        provide(intel)
        return rag

    make.provide = provide
    return make


def user(scopes=("read",)):
    return {bp.PRINCIPAL_KEY: bp.Principal(sub="a", kind="user", role="user", scopes=list(scopes))}


async def test_unrestricted_runs_the_original_path_and_is_not_stamped(rig):
    nav = FakeNav()
    rig(nav)
    out = await g._graph_navigate({"query": "q"})
    assert out == {"query": "q"} and AUDIENCE_KEY not in out
    assert nav.calls == [("navigate", {})], "an unrestricted call must not pass `roles`"


async def test_restricted_passes_roles_and_confirms(rig):
    nav = FakeNav()
    rig(nav)
    out = await g._graph_navigate({"query": "q", "roles": ROLES})
    assert out[AUDIENCE_KEY] is True
    assert nav.calls == [("navigate", {"roles": ROLES})]
    rows = await g._graph_traverse({"entity_id": "e", "intent": "causal", "roles": ROLES})
    assert rows[AUDIENCE_KEY] is True and nav.calls[-1] == ("traverse", {"roles": ROLES})
    path = await g._graph_explain_path({"src_entity_id": "s", "dst_entity_id": "d", "roles": ROLES})
    assert path[AUDIENCE_KEY] is True and nav.calls[-1] == ("explain_path", {"roles": ROLES})
    # an empty role list is a real (match-nothing) audience, not "unrestricted"
    out = await g._graph_navigate({"query": "q", "roles": []})
    assert out[AUDIENCE_KEY] is True and nav.calls[-1] == ("navigate", {"roles": []})


async def test_an_intel_build_that_cannot_confirm_is_never_called_and_never_stamps(rig):
    for intel in (None, FakeAudience(ops=())):
        nav = OldNav()
        rig(nav, intel=intel)
        out = await g._graph_navigate({"query": "q", "roles": ROLES})
        assert "error" in out and AUDIENCE_KEY not in out
        assert "hidden" not in out
        assert nav.calls == 0, "an older navigator must not be asked to walk the graph for a restricted caller"
        # ...while an unrestricted caller still gets the old navigator's answer
        out = await g._graph_navigate({"query": "q"})
        assert out["hidden"] == "EVERYTHING" and nav.calls == 1


async def test_a_user_with_no_audience_is_refused_not_served_unrestricted(rig):
    nav = FakeNav()
    rig(nav)
    out = await g._graph_navigate({"query": "q", **user()})
    assert "error" in out and AUDIENCE_KEY not in out and nav.calls == []
    # An admin / kb:unrestricted user principal legitimately has none.
    out = await g._graph_navigate({"query": "q", **user(("admin",))})
    assert out == {"query": "q"}
    out = await g._graph_navigate({"query": "q", **user(("read", "kb:unrestricted"))})
    assert out == {"query": "q"}


@pytest.mark.parametrize("bad", ["admin", [1], {"a": 1}, ["ok", None]])
async def test_a_malformed_audience_is_refused(rig, bad):
    nav = FakeNav()
    rig(nav)
    out = await g._graph_navigate({"query": "q", "roles": bad})
    assert "error" in out and AUDIENCE_KEY not in out and nav.calls == []


def _handlers():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    for n in tree.body:
        if isinstance(n, ast.AsyncFunctionDef):
            subjects = [
                d.args[0].value for d in n.decorator_list
                if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "worker_handler"
                and d.args and isinstance(d.args[0], ast.Constant)
                and str(d.args[0].value).startswith("worker.graph.")
            ]
            if subjects:
                wrapped = [d for d in n.decorator_list
                           if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "_audience_op"]
                yield subjects[0], n.name, wrapped


def test_every_graph_handler_but_the_query_only_ones_is_audience_wrapped():
    """A new graph handler is audience-blind by default; this makes that a
    decision somebody has to write down here."""
    open_by_design = {
        "worker.graph.classify_intent",  # reads only the query string
        "worker.graph.recluster",        # a write over the whole graph; operator-gated, no audience
    }
    seen = {}
    for subject, name, wrapped in _handlers():
        seen[subject] = bool(wrapped)
        if subject in open_by_design:
            assert not wrapped, f"{subject} is open by design and should not need an audience"
        else:
            assert wrapped, f"{subject} ({name}) is not wrapped in _audience_op"
    assert {"worker.graph.navigate", "worker.graph.traverse", "worker.graph.explain_path",
            "worker.graph.semantic_search", "worker.graph.search_clusters",
            "worker.graph.recall_traversals", "worker.graph.extract_relations"} <= set(seen)
    # the op each wrapper names is the op in its subject
    for subject, name, wrapped in _handlers():
        if wrapped:
            assert wrapped[0].args[0].value == subject.removeprefix("worker.graph.")


async def test_extract_relations_refuses_a_page_the_caller_cannot_read(rig):
    class Ext:
        store = object()

        def __init__(self):
            self.ran = False

        async def extract_relations_for_page(self, page_id):
            self.ran = True
            return 3

    class Aud(FakeAudience):
        async def page_is_readable(self, store, page_id, roles):
            return page_id == "mine"

    ext = Ext()
    rag = rig(FakeNav(), intel=Aud())
    rag.relation_extractor = ext
    out = await g._graph_extract_relations({"page_id": "theirs", "roles": ROLES})
    assert out["error"] == "page not found" and not ext.ran and out[AUDIENCE_KEY] is True
    out = await g._graph_extract_relations({"page_id": "mine", "roles": ROLES})
    assert out["edges_created"] == 3 and ext.ran
    # unrestricted: no page check at all
    ext.ran = False
    out = await g._graph_extract_relations({"page_id": "theirs"})
    assert out["edges_created"] == 3 and ext.ran and AUDIENCE_KEY not in out


async def test_search_handlers_use_the_scoped_search_for_a_restricted_caller(rig):
    class Emb:
        async def embed_text(self, q):
            return [1.0, 0.0]

    class Store:
        async def search_entity_embeddings(self, embedding, top_k):
            return [{"canonical_name": "UNFILTERED"}]

        async def search_clusters(self, embedding, top_k):
            return [{"name": "UNFILTERED"}]

    class Aud(FakeAudience):
        async def search_entity_embeddings(self, store, vec, top_k, roles):
            return [{"canonical_name": f"scoped:{top_k}:{roles}"}]

        async def search_clusters(self, store, vec, top_k, roles):
            return [{"name": f"scoped:{top_k}"}]

    rag = rig(FakeNav(), intel=Aud())
    rag.embedder, rag.store = Emb(), Store()
    got = await g._graph_semantic_search({"query": "q", "top_k": 4, "roles": ROLES})
    assert got["entities"] == [{"canonical_name": f"scoped:4:{ROLES}"}] and got[AUDIENCE_KEY] is True
    got = await g._graph_search_clusters({"query": "q", "top_k": 2, "roles": ROLES})
    assert got["clusters"] == [{"name": "scoped:2"}]
    got = await g._graph_semantic_search({"query": "q"})
    assert got["entities"] == [{"canonical_name": "UNFILTERED"}] and AUDIENCE_KEY not in got


def test_the_marker_spelling_matches_the_gateways():
    """gateway-rust/src/memory/scope.rs::AUDIENCE_KEY is the other half of the echo."""
    rust = (pathlib.Path(__file__).resolve().parent.parent
            / "gateway-rust/src/memory/scope.rs").read_text(encoding="utf-8")
    assert f'pub const AUDIENCE_KEY: &str = "{AUDIENCE_KEY}";' in rust


# ── Edge evidence for a restricted caller ──────────────

from noomesh.workers import rag as wrag  # noqa: E402

READABLE = "doc-readable"
PRIVATE = "doc-private-of-b"
SNIPPET = "PRIVATE SNIPPET from b's notebook"


def _edge(eid, src, dst, ev):
    return {"edge_id": eid, "src_entity_id": src, "rel_type": "RELATED_TO", "dst_entity_id": dst,
            "confidence": 1.0, "evidence": ev}


def _full_ev(doc=READABLE):
    return {"source_type": "chunk", "doc_id": doc, "page_id": "pg-1", "page_no": 3,
            "snippet": SNIPPET, "span": [0, 9], "confidence": 0.9}


CLEAN = _edge("e1", "a", "b", _full_ev())
REINFORCED = _edge("e2", "b", "c", {**_full_ev(), "reinforced_at": "2026-10-01",
                                     "last_evidence": _full_ev(PRIVATE)})
NO_DOC = _edge("e3", "c", "d", {"source_type": "chunk", "snippet": SNIPPET})
UNREADABLE_DOC = _edge("e4", "d", "e", _full_ev(PRIVATE))
STR_EV = _edge("e5", "e", "f", __import__("json").dumps(_full_ev()))


class EdgeNav(FakeNav):
    """Returns edge-bearing results shaped like trellion-intel's GraphResult."""

    def __init__(self, edges):
        super().__init__()
        self.edges = edges

    async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, **kw):
        self.calls.append(("navigate", kw))
        e = self.edges
        return {
            "query": query,
            "seed_entities": [{"entity_id": "a", "canonical_name": "A"}],
            "expanded_entities": list(e),
            "candidate_page_ids": ["pg-ok"],
            "reasoning_paths": [[x] for x in e] + [list(e)],
            "hypotheses": [{"path": ["A"], "description": f"h{i}", "confidence": 0.5, "edges": [x]}
                           for i, x in enumerate(e)] + [{"path": ["A"], "description": "all", "confidence": 0.1, "edges": list(e)}],
        }

    async def explain_path(self, src_entity_id, dst_entity_id, **kw):
        self.calls.append(("explain_path", kw))
        return list(self.edges)


@pytest.fixture
def edge_rig(rig, monkeypatch):
    seen = []

    async def _fake_readable(rag, mod, roles, *, docs, entities):
        seen.append((set(docs), list(roles)))
        return {d for d in docs if d == READABLE}, set()

    monkeypatch.setattr(wrag, "_readable_ids", _fake_readable)

    def make(edges):
        nav = EdgeNav(edges)
        rig(nav)
        return nav, seen

    return make


def _all_text(x):
    return repr(x)


async def test_navigate_for_a_restricted_caller_has_no_snippet_page_ids_or_unprovable_edges(edge_rig):
    _, seen = edge_rig([CLEAN, REINFORCED, NO_DOC, UNREADABLE_DOC, STR_EV])
    out = await g._graph_navigate({"query": "q", "roles": ROLES})
    assert out[AUDIENCE_KEY] is True
    ids = [e["edge_id"] for e in out["expanded_entities"]]
    assert ids == ["e1", "e5"], "reinforced, no-doc_id and unreadable-document edges are dropped"
    text = _all_text(out)
    for banned in (SNIPPET, "pg-1", "'page_id'", "'page_no'", "last_evidence", "'snippet'", "'span'", PRIVATE, "reinforced_at"):
        assert banned not in text, f"{banned!r} leaked to a restricted caller"
    # kept edges keep their (readable) doc_id
    assert out["expanded_entities"][0]["evidence"]["doc_id"] == READABLE
    # a path / hypothesis holding a dropped edge goes whole; the clean single-edge ones stay
    assert [[e["edge_id"] for e in p] for p in out["reasoning_paths"]] == [["e1"], ["e5"]]
    assert [h["description"] for h in out["hypotheses"]] == ["h0", "h4"]
    assert seen and seen[0][1] == ROLES
    assert out["candidate_page_ids"] == ["pg-ok"] and out["seed_entities"][0]["entity_id"] == "a"


async def test_explain_path_for_a_restricted_caller_is_cut_to_a_provable_route(edge_rig):
    edge_rig([CLEAN, STR_EV])
    ok = await g._graph_explain_path({"src_entity_id": "a", "dst_entity_id": "f", "roles": ROLES})
    assert ok[AUDIENCE_KEY] is True and ok["found"] is True and ok["hops"] == 2
    assert SNIPPET not in _all_text(ok) and "page_id" not in _all_text(ok)
    edge_rig([CLEAN, REINFORCED])
    cut = await g._graph_explain_path({"src_entity_id": "a", "dst_entity_id": "c", "roles": ROLES})
    assert cut[AUDIENCE_KEY] is True
    assert cut["path"] == [] and cut["found"] is False and cut["hops"] == 0
    assert cut["reason"] == "route_not_provable_for_audience"
    assert SNIPPET not in _all_text(cut) and PRIVATE not in _all_text(cut)


async def test_unrestricted_output_is_unchanged_and_unchecked(edge_rig):
    _, seen = edge_rig([CLEAN, REINFORCED, NO_DOC])
    out = await g._graph_navigate({"query": "q"})
    assert AUDIENCE_KEY not in out
    assert [e["edge_id"] for e in out["expanded_entities"]] == ["e1", "e2", "e3"]
    assert out["expanded_entities"][1]["evidence"]["last_evidence"]["snippet"] == SNIPPET
    assert out["expanded_entities"][0]["evidence"]["page_id"] == "pg-1"
    path = await g._graph_explain_path({"src_entity_id": "a", "dst_entity_id": "d"})
    assert path["hops"] == 3 and path["path"][1]["evidence"]["last_evidence"]
    assert seen == [], "an unrestricted caller never pays for the readability re-check"


async def test_a_reinforced_edge_is_not_provable_for_any_restricted_caller_but_is_for_an_unrestricted_one(edge_rig):
    """Mirrors tests/test_rag_context_graph_db.py: the reinforced triple's first
    document is readable, but its sighting count is not stored (the middle
    sighting may be a private document), so no restricted caller is shown it;
    an unrestricted caller has no scoping and sees it."""
    edge_rig([REINFORCED])
    for roles in (["user:a"], ["user:b"], ["company"], []):
        out = await g._graph_navigate({"query": "q", "roles": roles})
        assert out["expanded_entities"] == [] and out["hypotheses"] == [] and out["reasoning_paths"] == []
        assert PRIVATE not in _all_text(out) and SNIPPET not in _all_text(out)
    admin = await g._graph_navigate({"query": "q"})
    assert [e["edge_id"] for e in admin["expanded_entities"]] == ["e2"]


async def test_a_failed_readability_recheck_serves_no_edges(rig, monkeypatch):
    rig(EdgeNav([CLEAN]))

    async def _boom(*a, **kw):
        raise RuntimeError("db down")

    monkeypatch.setattr(wrag, "_readable_ids", _boom)
    out = await g._graph_navigate({"query": "q", "roles": ROLES})
    assert "error" in out and "expanded_entities" not in out and SNIPPET not in _all_text(out)
    out = await g._graph_explain_path({"src_entity_id": "a", "dst_entity_id": "b", "roles": ROLES})
    assert "error" in out and "path" not in out


class ClusterRag(FakeRag):
    def __init__(self):
        super().__init__(FakeNav())

        class _Emb:
            async def embed_text(self, q):
                return [0.0]

        self.embedder = _Emb()


async def test_search_clusters_drops_the_hierarchy_fields_for_a_restricted_caller_only(rig, monkeypatch):
    rig(FakeNav())
    rag = ClusterRag()
    monkeypatch.setattr(g, "_get_rag", lambda: rag)
    row = {"cluster_id": "c1", "name": "n", "level": 2, "parent_cluster_id": "p", "generation": 4, "size": 3}

    async def _scoped(store, vec, k, roles):
        return [dict(row)]

    async def _plain(embedding, top_k):
        return [dict(row)]

    rag.store = type("S", (), {"search_clusters": staticmethod(_plain)})()
    rig.provide(type(
        "A", (), {"supports": staticmethod(lambda op: True), "search_clusters": staticmethod(_scoped)})())
    out = await g._graph_search_clusters({"query": "q", "roles": ROLES})
    assert out["clusters"] == [{"cluster_id": "c1", "name": "n", "size": 3}] and out[AUDIENCE_KEY] is True
    plain = await g._graph_search_clusters({"query": "q"})
    assert plain["clusters"] == [row]
