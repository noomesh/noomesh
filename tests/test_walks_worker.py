# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Saving and recalling a user's own walks (phase 1b): the worker half.

``workers/walks.py`` keeps a signed-in user's ``navigate`` / ``traverse`` /
``rag.query`` walk as a ``kind='thread'`` row; ``worker.graph.recall_walks``
reads their own back through trellion-intel. The DB-backed tests use the REAL
trellion archiver against a private schema and SKIP, loudly, without Postgres
(same switch as the other audience tests):

    NOO_KB_AUDIENCE_TEST_DSN=postgresql://postgres:x@127.0.0.1:55437/postgres \\
        pytest tests/test_walks_worker.py

The two-user recall rule itself (only the caller's own, every gate, the
audience filter) is trellion-intel's and is tested there against a real graph;
what is pinned HERE is that this side hands it the VERIFIED account and nothing
else, stamps the reply, saves only what it should and never lets a save touch
the reply.
"""
from __future__ import annotations

import ast
import asyncio
import json
import os
import pathlib
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from noomesh.config import WalksConfig
from noomesh.gateway import bus_principal as bp
from noomesh.workers import graph as g
from noomesh.workers import walks as w
from noomesh.workers.audience import AUDIENCE_KEY

DSN = os.environ.get("NOO_KB_AUDIENCE_TEST_DSN") or os.environ.get("NOO_BROKER_TEST_DSN")
needs_db = pytest.mark.skipif(
    not DSN, reason="NOO_KB_AUDIENCE_TEST_DSN not set (needs Postgres); see module docstring"
)

DIM = 4
VEC = [0.5, 0.25, 0.125, 0.0625]
DDL = [
    "CREATE EXTENSION IF NOT EXISTS vector",
    "CREATE TABLE docs (doc_id uuid PRIMARY KEY, source_uri text, title text, hash text, "
    "created_at timestamptz NOT NULL DEFAULT now(), metadata jsonb)",
    "CREATE TABLE entities (entity_id uuid PRIMARY KEY, canonical_name text NOT NULL, type text NOT NULL)",
    "CREATE TABLE edges (edge_id uuid PRIMARY KEY, src_entity_id uuid NOT NULL, rel_type text NOT NULL, "
    "dst_entity_id uuid NOT NULL, evidence_json jsonb, created_at timestamptz NOT NULL DEFAULT now())",
    "CREATE TABLE trellion_traversal_records (id uuid PRIMARY KEY, persona_id text NOT NULL DEFAULT '', "
    f"query_text text NOT NULL, query_embedding vector({DIM}), intent text, "
    "traversal_path jsonb NOT NULL DEFAULT '[]', outcome_score double precision NOT NULL, "
    "created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), "
    "user_id text, exploration_rate double precision, "
    "uncertainty_fingerprint jsonb NOT NULL DEFAULT '{}', archived_to_video boolean NOT NULL DEFAULT false, "
    "video_frame_id uuid, kind text NOT NULL DEFAULT 'simulated', thread_id uuid, turn_index integer, "
    "run_id text, provenance jsonb NOT NULL DEFAULT '{}', evidence jsonb NOT NULL DEFAULT '{}', "
    "usefulness double precision, status text NOT NULL DEFAULT 'active', last_validated_at timestamptz, "
    "last_recalled_at timestamptz, recall_count integer NOT NULL DEFAULT 0, expires_at timestamptz, "
    "embedding_model text, embedding_dim integer)",
    "CREATE TABLE trellion_episodes (id uuid PRIMARY KEY, persona_id text NOT NULL, record_type text, "
    f"index_name text, content_summary text, prominence_score double precision, metadata jsonb, "
    f"embedding vector({DIM}), user_id text)",
    "CREATE TABLE noo_user_settings (username text NOT NULL, key text NOT NULL, value jsonb NOT NULL, "
    "updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (username, key))",
]


def user(sub="alice", scopes=("admin",), kind="user"):
    return {bp.PRINCIPAL_KEY: bp.Principal(sub=sub, kind=kind, role="admin", scopes=list(scopes))}


class Rig:
    """A private schema, a fake rag over it, and the ids a navigate result refers to."""

    def __init__(self):
        self.engine = None
        self.schema = None
        self.ent = {}
        self.doc = None
        self.embedded = []
        self.embed_error = None

    async def rows(self, where="TRUE"):
        from sqlalchemy import text

        async with self.engine.connect() as c:
            return [dict(r) for r in (await c.execute(
                text(f"SELECT * FROM trellion_traversal_records WHERE {where} ORDER BY created_at"))).mappings().all()]

    async def set_setting(self, account, value):
        from sqlalchemy import text

        async with self.engine.begin() as c:
            await c.execute(text("INSERT INTO noo_user_settings (username, key, value) "
                                 "VALUES (:u, 'walks.save_threads', CAST(:v AS jsonb))"),
                            {"u": account, "v": json.dumps(value)})

    def navigate_result(self, *, paths=2):
        e = self.ent
        edge1 = {"edge_id": str(uuid.uuid4()), "src_entity_id": e["a"], "rel_type": "CAUSES",
                 "dst_entity_id": e["b"], "evidence": {"doc_id": self.doc}, "depth": 1}
        edge2 = {"edge_id": str(uuid.uuid4()), "src_entity_id": e["c"], "rel_type": "PART_OF",
                 "dst_entity_id": e["b"], "evidence": None, "depth": 2}
        return {
            "seed_entities": [{"entity_id": e["a"], "canonical_name": "Alpha", "type": "concept"}],
            "expanded_entities": [edge1, edge2],
            "candidate_page_ids": ["p1", "p2", "p3"],
            "reasoning_paths": [[edge1], [edge1, edge2]][:paths],
            "entity_name_map": {e["a"]: "Alpha", e["b"]: "Beta", e["c"]: "Gamma"},
            "hypotheses": [],
        }


@pytest.fixture
async def rig(monkeypatch):
    if not DSN:
        pytest.skip("NOO_KB_AUDIENCE_TEST_DSN not set (needs Postgres); see module docstring")
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    r = Rig()
    r.schema = f"walks1b_{uuid.uuid4().hex}"
    base = DSN.replace("+asyncpg", "+psycopg")
    if "+" not in base.split("://")[0]:
        base = base.replace("postgresql://", "postgresql+psycopg://", 1)
    admin = create_async_engine(base)
    async with admin.begin() as c:
        await c.execute(text(f"CREATE SCHEMA {r.schema}"))
    await admin.dispose()
    r.engine = create_async_engine(base, connect_args={"options": f"-csearch_path={r.schema},public"})
    async with r.engine.begin() as c:
        for ddl in DDL:
            await c.execute(text(ddl))
        r.doc = str(uuid.uuid4())
        await c.execute(text("INSERT INTO docs (doc_id, source_uri, title, hash) VALUES "
                             "(CAST(:d AS uuid), 'file:///d', 'd', 'h')"), {"d": r.doc})
        for k, name in (("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")):
            r.ent[k] = str(uuid.uuid4())
            await c.execute(text("INSERT INTO entities VALUES (CAST(:i AS uuid), :n, 'concept')"),
                            {"i": r.ent[k], "n": name})
        for src, rel, dst, ev in (("a", "CAUSES", "b", {"doc_id": r.doc}), ("c", "PART_OF", "b", None)):
            await c.execute(text("INSERT INTO edges VALUES (gen_random_uuid(), CAST(:s AS uuid), :r, "
                                 "CAST(:d AS uuid), CAST(:e AS jsonb))"),
                            {"s": r.ent[src], "r": rel, "d": r.ent[dst], "e": json.dumps(ev) if ev else None})

    class Store:
        _engine = r.engine

        async def get_entities_by_ids(self, ids):
            async with r.engine.connect() as c:
                res = await c.execute(text("SELECT entity_id::text, canonical_name, type FROM entities "
                                           "WHERE entity_id::text = ANY(CAST(:i AS text[]))"), {"i": list(ids)})
                return {i: {"canonical_name": n, "type": t} for i, n, t in res.all()}

    class Embedder:
        model = "test-embed"

        async def embed_text(self, t):
            r.embedded.append(t)
            if r.embed_error:
                raise r.embed_error
            return VEC

    rag = types.SimpleNamespace(store=Store(), embedder=Embedder(), navigator=None, _started=True)
    conv = types.SimpleNamespace(_engine=r.engine)
    import noomesh.config as cfgmod
    import noomesh.workers.common as common

    monkeypatch.setattr(common, "_get_rag", lambda: rag)
    monkeypatch.setattr(common, "_get_conversation_store", lambda: conv)
    monkeypatch.setattr(g, "_get_rag", lambda: rag)
    monkeypatch.setattr(cfgmod, "get_config", lambda: types.SimpleNamespace(walks=WalksConfig()))
    r.rag, r.cfgmod = rag, cfgmod
    try:
        yield r
    finally:
        await w.drain()
        async with r.engine.begin() as c:
            await c.execute(text(f"DROP SCHEMA {r.schema} CASCADE"))
        await r.engine.dispose()


class Nav:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def navigate(self, query, seed_entities=None, max_hops=2, rel_types=None, **kw):
        self.calls.append(query)
        return self.result

    async def traverse_with_intent(self, entity_id, query_intent, hops=2, **kw):
        return self.result


# ----------------------------------------------------------------------
# No database: building a walk from a reply
# ----------------------------------------------------------------------


def _edges():
    return [
        {"src_entity_id": "A", "rel_type": "R1", "dst_entity_id": "B", "evidence": {"doc_id": "d1"}},
        {"src_entity_id": "C", "rel_type": "R2", "dst_entity_id": "B", "evidence": None},
    ]


def test_the_longest_reasoning_path_becomes_a_connected_chain_from_the_seed():
    e = _edges()
    walk = w.walk_from_graph_result({
        "seed_entities": [{"entity_id": "A", "canonical_name": "Alpha", "type": "concept"}],
        "reasoning_paths": [[e[0]], [e[0], e[1]]],
        "entity_name_map": {"A": "Alpha", "B": "Beta", "C": "Gamma"},
        "candidate_page_ids": ["p1"],
    })
    assert [s["entity_id"] for s in walk.path] == ["A", "B", "C"]
    assert [s["direction"] for s in walk.path] == ["seed", "outgoing", "incoming"]
    assert walk.triples == [["A", "R1", "B"], ["B", "R2", "C"]]
    assert walk.doc_ids == ["d1"]
    assert walk.path[0]["entity_name"] == "Alpha" and walk.path[0]["entity_type"] == "concept"
    assert walk.outcome == pytest.approx(1 / 3)


def test_no_path_or_a_broken_chain_is_not_a_walk():
    assert w.walk_from_graph_result({"reasoning_paths": []}) is None
    assert w.walk_from_graph_result("nonsense") is None
    broken = [{"src_entity_id": "A", "rel_type": "R", "dst_entity_id": "B"},
              {"src_entity_id": "X", "rel_type": "R", "dst_entity_id": "Y"}]
    assert w.walk_from_graph_result({"reasoning_paths": [broken]}) is None


def test_a_traverse_walk_comes_from_the_best_scored_structured_path():
    rows = [
        {"entity_id": "B", "name": "Beta", "type": "t", "score": 0.2,
         "path_steps": [{"entity_id": "A", "rel_type": ""}, {"entity_id": "B", "rel_type": "R1"}]},
        {"entity_id": "C", "name": "Gamma", "type": "t", "score": 0.9,
         "path_steps": [{"entity_id": "A", "rel_type": ""}, {"entity_id": "B", "rel_type": "R1"},
                        {"entity_id": "C", "rel_type": "R2"}]},
        {"entity_id": "Z", "score": 1.0},  # an older intel: no path_steps
    ]
    walk = w.walk_from_traverse("A", rows, "causal")
    assert [s["entity_id"] for s in walk.path] == ["A", "B", "C"]
    assert walk.triples == [["A", "R1", "B"], ["B", "R2", "C"]]
    assert walk.outcome == pytest.approx(0.9) and walk.intent == "causal"
    assert w.walk_from_traverse("A", [{"entity_id": "Z", "score": 1.0}]) is None


def test_a_rag_walk_carries_its_verification_and_a_rejected_one_is_not_kept():
    def result(status):
        ver = types.SimpleNamespace(status=status, confidence=0.8) if status else None
        return types.SimpleNamespace(
            graph_context={"seed_entities": [{"entity_id": "A"}], "reasoning_paths": [_edges()[:1]],
                           "entity_name_map": {}},
            verification=ver, intent="lookup", strategy_used="hybrid",
            citations=[types.SimpleNamespace(doc_id="d9"), types.SimpleNamespace(doc_id="d1")],
        )

    ok = w.walk_from_rag_result(result("approved"))
    assert ok.provenance["verification"] == {"status": "approved", "confidence": 0.8}
    assert ok.provenance["n_citations"] == 2 and ok.intent == "lookup"
    assert ok.doc_ids == ["d1", "d9"]  # edge evidence first, then the cited, deduplicated
    assert w.walk_from_rag_result(result("rejected")) is None
    assert w.walk_from_rag_result(types.SimpleNamespace(graph_context=None)) is None


def test_the_save_is_scheduled_by_the_verified_account_only(monkeypatch):
    seen = []

    async def fake(account, query, walk, via, prov, thread_id):
        seen.append((account, query, thread_id))

    monkeypatch.setattr(w, "_save_guarded", fake)

    async def go():
        walk = w.Walk([{"entity_id": "A"}, {"entity_id": "B"}], [["A", "R", "B"]])
        # the body CLAIMS another user and a thread; only the principal's account counts
        body = {"user_id": "someone-else", "conversation_id": str(uuid.UUID(int=7))}
        assert w.schedule_save(body, via="navigate", query="q", walk=walk) is None  # unsigned
        assert w.schedule_save({**user(kind="internal"), **body}, via="navigate", query="q", walk=walk) is None
        t = w.schedule_save({**user("alice/laptop"), **body}, via="navigate", query=" q ", walk=walk)
        await w.drain()
        assert t is not None
        # a thread id that is not a UUID is dropped, not guessed at
        w.schedule_save({**user(), "thread_id": "nope"}, via="navigate", query="q", walk=walk)
        await w.drain()

    asyncio.run(go())
    assert seen == [("alice", "q", str(uuid.UUID(int=7))), ("alice", "q", None)]


# ----------------------------------------------------------------------
# Saving, DB-backed
# ----------------------------------------------------------------------


async def _navigate(rig, request, roles=None, nav=None):
    nav = nav or Nav(rig.navigate_result())
    rig.rag.navigator = nav
    req = {"query": "how does Alpha cause Beta", **request}
    if roles is not None:
        req["roles"] = roles
    return await g._graph_navigate(req)


@needs_db
async def test_a_signed_in_navigate_saves_exactly_one_thread_after_the_reply(rig):
    reply = await _navigate(rig, user("alice/laptop", ("admin",)))
    # The reply is in hand and NOTHING has been written: the save is off its path.
    assert reply["candidate_page_ids"] == ["p1", "p2", "p3"] and "error" not in reply
    assert await rig.rows() == []
    await w.drain()
    (row,) = await rig.rows()
    e = rig.ent
    assert row["user_id"] == "alice"  # the account, not the connection
    assert row["kind"] == "thread" and row["status"] == "active"
    assert row["query_text"] == "how does Alpha cause Beta"
    assert [s["entity_id"] for s in row["traversal_path"]] == [e["a"], e["b"], e["c"]]
    assert [s["entity_name"] for s in row["traversal_path"]] == ["Alpha", "Beta", "Gamma"]
    ev = row["evidence"]
    assert ev["triples"] == [[e["a"], "CAUSES", e["b"]], [e["b"], "PART_OF", e["c"]]]
    assert ev["doc_ids"] == [rig.doc]
    assert datetime.fromisoformat(ev["newest_evidence_at"]) > datetime.now(timezone.utc) - timedelta(minutes=5)
    assert row["provenance"]["via"] == "navigate"
    assert row["embedding_model"] == "test-embed" and row["embedding_dim"] == DIM
    assert rig.embedded == ["how does Alpha cause Beta"]  # the question, embedded once
    assert row["expires_at"] - row["created_at"] == pytest.approx(timedelta(days=180), abs=timedelta(minutes=1))
    assert row["usefulness"] is None  # U is computed at recall, from the live graph
    from sqlalchemy import text
    async with rig.engine.connect() as c:
        emb = (await c.execute(text("SELECT query_embedding::text FROM trellion_traversal_records"))).scalar()
        ep = (await c.execute(text("SELECT user_id, content_summary FROM trellion_episodes"))).one()
    assert [round(float(x), 4) for x in emb.strip("[]").split(",")] == VEC
    assert ep.user_id == "alice" and "how does Alpha" not in ep.content_summary  # the question stays off the frame


@needs_db
async def test_a_restricted_callers_reply_is_stamped_and_their_walk_saved(rig, monkeypatch):
    from trellion.live.pageindex_store import PageIndexStore

    class Aud:
        # The evidence re-check for a restricted caller (graph._restrict_edge_evidence)
        # asks the audience module for trellion's own document predicate, as
        # the add-on's audience scope provides it; without it the reply fails closed.
        ROLES_WHERE = PageIndexStore._ROLES_WHERE

        def supports(self, op):
            return True

    monkeypatch.setattr(g, "_intel_audience", lambda op: (Aud(), None))
    # The document behind the edge is readable by this caller's audience (an
    # untagged document is readable only with the generic `user` role, which a
    # restricted caller never has): the walk they are shown is built from edges
    # that survive the evidence re-check.
    from sqlalchemy import text
    async with rig.engine.begin() as c:
        await c.execute(text("UPDATE docs SET metadata = CAST(:m AS jsonb) WHERE doc_id = CAST(:d AS uuid)"),
                        {"m": json.dumps({"roles": ["company"]}), "d": rig.doc})
    nav = Nav(rig.navigate_result())
    rig.rag.navigator = nav
    reply = await g._graph_navigate({**user("a", ("read",)), "query": "q", "roles": ["company", "user:a"]})
    assert reply[AUDIENCE_KEY] is True
    await w.drain()
    assert [r["user_id"] for r in await rig.rows()] == ["a"]


@needs_db
async def test_an_opted_out_account_saves_nothing(rig):
    await rig.set_setting("alice", False)
    reply = await _navigate(rig, user("alice"))
    assert "error" not in reply
    await w.drain()
    assert await rig.rows() == [] and rig.embedded == []  # not even embedded
    # and turning it back on resumes saving (off does not delete, on does not backfill)
    from sqlalchemy import text
    async with rig.engine.begin() as c:
        await c.execute(text("UPDATE noo_user_settings SET value = 'true'::jsonb"))
    await _navigate(rig, user("alice"))
    await w.drain()
    assert len(await rig.rows()) == 1


@needs_db
async def test_turning_saving_off_leaves_existing_threads_alone(rig):
    await _navigate(rig, user("alice"))
    await w.drain()
    await rig.set_setting("alice", False)
    await _navigate(rig, user("alice"))
    await w.drain()
    rows = await rig.rows()
    assert len(rows) == 1 and rows[0]["status"] == "active"


@needs_db
async def test_an_unreadable_setting_fails_closed(rig, monkeypatch):
    from sqlalchemy import text

    async with rig.engine.begin() as c:
        await c.execute(text("DROP TABLE noo_user_settings"))
    await _navigate(rig, user("alice"))
    await w.drain()
    assert await rig.rows() == []


@needs_db
async def test_unsigned_and_internal_walks_are_not_threads(rig):
    # unsigned: no principal at all (the unrestricted original path)
    reply = await _navigate(rig, {})
    assert "error" not in reply
    # internal: a loop acting for a user may NAME them in the body; that is its say-so, not an asker
    await _navigate(rig, {**user("heartbeat", ("read",), kind="internal"), "user_id": "alice"})
    await w.drain()
    assert await rig.rows() == [] and rig.embedded == []


@needs_db
async def test_a_failing_save_never_fails_the_request(rig, caplog):
    rig.embed_error = RuntimeError("embedder down")
    reply = await _navigate(rig, user("alice"))
    assert reply["candidate_page_ids"] == ["p1", "p2", "p3"] and "error" not in reply
    await w.drain()  # the background task failed; draining does not raise
    assert await rig.rows() == []
    # ...and a reply the walk builder cannot make sense of cannot break it either
    rig.embed_error = None
    rig.rag.navigator = Nav({"reasoning_paths": "not-a-list", "seed_entities": 5})
    reply = await g._graph_navigate({**user("alice"), "query": "q"})
    assert "error" not in reply


@needs_db
async def test_a_navigate_with_no_walk_saves_nothing(rig):
    reply = await _navigate(rig, user("alice"), nav=Nav({"seed_entities": [], "reasoning_paths": [],
                                                      "candidate_page_ids": []}))
    assert "error" not in reply
    await w.drain()
    assert await rig.rows() == []


@needs_db
async def test_a_traverse_is_saved_with_a_query_made_from_intent_and_seed(rig):
    e = rig.ent
    rows = [{"entity_id": e["b"], "name": "Beta", "type": "concept", "score": 0.8, "depth": 1,
             "path_steps": [{"entity_id": e["a"], "rel_type": ""}, {"entity_id": e["b"], "rel_type": "CAUSES"}]}]
    rig.rag.navigator = Nav(rows)
    out = await g._graph_traverse({**user("alice"), "entity_id": e["a"], "intent": "causal"})
    assert out["count"] == 1
    await w.drain()
    (row,) = await rig.rows()
    assert row["query_text"] == "causal traversal from Alpha"  # seed named from the graph
    assert row["provenance"]["via"] == "traverse" and row["intent"] == "causal"
    assert row["evidence"]["triples"] == [[e["a"], "CAUSES", e["b"]]]
    assert row["evidence"]["doc_ids"] == [rig.doc]  # found by looking the edge up


@needs_db
async def test_a_rag_answer_is_saved_with_its_verification_and_citations(rig, monkeypatch):
    from noomesh.workers import rag as rag_worker

    e = rig.ent
    result = types.SimpleNamespace(
        answer="Alpha causes Beta", strategy_used="hybrid", intent="causal", evidence=[1, 2],
        citations=[types.SimpleNamespace(doc_id=rig.doc, __dict__={"doc_id": rig.doc})],
        verification=types.SimpleNamespace(status="partial", confidence=0.6),
        graph_context=rig.navigate_result(),
    )

    async def query(question, strategy="hybrid", roles=None):
        return result

    rig.rag.query = query
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: rig.rag)

    async def no_roles(params):
        return None

    monkeypatch.setattr(rag_worker, "_kb_roles_for", no_roles)
    reply = await rag_worker._rag_query({**user("alice"), "question": "why Beta?"})
    assert reply["answer"] == "Alpha causes Beta"
    assert await rig.rows() == []
    await w.drain()
    (row,) = await rig.rows()
    assert row["provenance"]["via"] == "rag" and row["provenance"]["n_citations"] == 1
    assert row["provenance"]["verification"]["status"] == "partial"
    assert row["intent"] == "causal" and row["outcome_score"] == 0.5
    assert [e["a"], e["b"], e["c"]] == [s["entity_id"] for s in row["traversal_path"]]


@needs_db
async def test_over_the_cap_the_least_recalled_oldest_threads_are_staged_not_skipped(rig, monkeypatch):
    monkeypatch.setattr(rig.cfgmod, "get_config",
                        lambda: types.SimpleNamespace(walks=WalksConfig(max_threads_per_user=3)))
    from sqlalchemy import text

    for i in range(3):
        await _navigate(rig, user("alice"), nav=Nav(rig.navigate_result()))
        await w.drain()
    rows = await rig.rows()
    # the oldest is the most recalled: it must survive a newer, never-recalled one
    async with rig.engine.begin() as c:
        await c.execute(text("UPDATE trellion_traversal_records SET recall_count = 5 WHERE id = CAST(:i AS uuid)"),
                        {"i": str(rows[0]["id"])})
    await _navigate(rig, user("alice"))
    await w.drain()
    after = {str(r["id"]): r for r in await rig.rows()}
    assert len(after) == 4  # the new thread WAS saved
    active = [r for r in after.values() if r["status"] == "active"]
    staged = [r for r in after.values() if r["status"] == "staged"]
    assert len(active) == 3 and len(staged) == 1
    assert after[str(rows[0]["id"])]["status"] == "active"  # recalled: kept
    assert staged[0]["id"] == rows[1]["id"]  # never recalled, then oldest: staged


# ----------------------------------------------------------------------
# Recall: the worker hands the walk store the VERIFIED account
# ----------------------------------------------------------------------


class FakeWalks:
    """Stands in for the add-on's walk store: records exactly what it was asked."""

    class WalkPolicy:
        def __init__(self, **kw):
            self.kw = kw

    def __init__(self):
        self.calls = []

    async def recall_walks(self, store, user_id, roles, query_embedding, top_k=5, *, policy=None):
        self.calls.append(("recall", user_id, roles, list(query_embedding), top_k, policy.kw))
        return [{"id": "w1", "query": "mine", "kind": "thread"}]

    async def list_walks(self, store, user_id, roles, limit=20, *, policy=None):
        self.calls.append(("list", user_id, roles, limit))
        return []

    async def get_walk(self, store, user_id, roles, walk_id, *, policy=None):
        self.calls.append(("get", user_id, roles, walk_id))
        return None if walk_id == "nope" else {"id": walk_id, "available": True}


@pytest.fixture
def recall_rig(monkeypatch):
    fake = FakeWalks()
    rag = types.SimpleNamespace(store=object(), embedder=types.SimpleNamespace(embed_text=_embed))
    monkeypatch.setattr(g, "_get_rag", lambda: rag)

    class Aud:
        def supports(self, op):
            return op == "recall_walks"

    monkeypatch.setattr(g, "_intel_audience", lambda op: (Aud(), None))
    import noomesh.addon_roles as roles_mod

    monkeypatch.setattr(roles_mod, "provider", lambda role: fake if role == roles_mod.WALK_STORE else None)
    import noomesh.config as cfgmod

    monkeypatch.setattr(cfgmod, "get_config", lambda: types.SimpleNamespace(
        walks=WalksConfig(soft_gating=True, min_relevance=0.6, freshness_half_life_days=30)))
    return fake


async def _embed(text):
    return [1.0, 0.0]


async def test_recall_asks_for_the_verified_accounts_threads_and_nobody_elses(recall_rig):
    out = await g._graph_recall_walks({
        **user("alice/laptop", ("admin",)), "query": "x", "top_k": 3,
        "user_id": "victim", "account": "victim", "username": "victim",  # a body can claim anything
    })
    assert out["count"] == 1 and out["walks"][0]["query"] == "mine"
    kind, account, roles, vec, top_k, policy = recall_rig.calls[0]
    assert (kind, account, roles, vec, top_k) == ("recall", "alice", None, [1.0, 0.0], 3)
    # the soft-gating flag and its thresholds come from config, not from the request
    assert policy["soft_gating"] is True and policy["min_relevance"] == 0.6
    assert policy["half_life_days"] == 30


async def test_recall_without_a_query_lists_and_with_an_id_shows(recall_rig):
    lst = await g._graph_recall_walks({**user("alice")})
    assert lst["strategy"] == "recent" and recall_rig.calls[0][:2] == ("list", "alice")
    one = await g._graph_recall_walks({**user("alice"), "id": "w9"})
    assert one["walk"] == {"id": "w9", "available": True}
    assert (await g._graph_recall_walks({**user("alice"), "id": "nope"})) == {"error": "walk not found"}


async def test_a_caller_with_no_signed_in_account_has_no_threads(recall_rig):
    for req in ({"query": "x"}, {**user("heartbeat", ("read",), "internal"), "query": "x", "user_id": "alice"}):
        out = await g._graph_recall_walks(req)
        assert "error" in out and "walks" not in out
    assert recall_rig.calls == []


async def test_a_restricted_recall_is_stamped_and_an_older_intel_is_refused_unstamped(recall_rig, monkeypatch):
    out = await g._graph_recall_walks({**user("a", ("read",)), "query": "x", "roles": ["company", "user:a"]})
    assert out[AUDIENCE_KEY] is True
    assert recall_rig.calls[0][2] == ["company", "user:a"]  # the gateway's audience reaches intel
    monkeypatch.setattr(g, "_intel_audience", lambda op: (None, {"error": "older intel"}))
    out = await g._graph_recall_walks({**user("a", ("read",)), "query": "x", "roles": ["company", "user:a"]})
    assert out == {"error": "older intel"} and AUDIENCE_KEY not in out


def test_the_unrestricted_legacy_recall_no_longer_serves_threads():
    src = pathlib.Path(g.__file__).read_text()
    assert "AND kind <> 'thread' AND status = 'active'" in src


def test_every_hook_is_after_the_reply_and_never_awaited():
    """Structural: the save is scheduled, not awaited, in every hooked handler."""
    for path, handlers in ((g.__file__, {"_graph_navigate", "_graph_traverse"}),
                           (pathlib.Path(g.__file__).with_name("rag.py"), {"_rag_query"})):
        tree = ast.parse(pathlib.Path(path).read_text())
        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name in handlers:
                calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Attribute) and n.func.attr == "keep"]
                assert calls, f"{node.name} does not keep the walk"
                for c in ast.walk(node):
                    if isinstance(c, ast.Await) and isinstance(c.value, ast.Call):
                        f = c.value.func
                        assert not (isinstance(f, ast.Attribute) and f.attr in ("keep", "save_thread", "schedule_save")), \
                            f"{node.name} awaits the save"
                seen.add(node.name)
        assert seen == handlers


def test_the_worker_reads_the_key_the_gateway_route_writes():
    rs = (pathlib.Path(__file__).resolve().parents[1] / "gateway-rust" / "src" / "routes" / "walks.rs").read_text()
    assert f'pub const SAVE_KEY: &str = "{w.SETTING_KEY}";' in rs
