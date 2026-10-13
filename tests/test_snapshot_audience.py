# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Audience-scoped curriculum.

``GET /api/snapshots/{id}/curriculum`` answers from a concept graph built out of
a snapshot. A snapshot is built from the TEMPORAL graph (see
``noomesh/workers/snapshot_audience.py``), so ownership there is ``user_id`` on
entities/edges plus ``source_page_id`` for document-derived facts, and the
document predicate (trellion's ``_ROLES_WHERE``) applies to those pages.

DB-backed: needs Postgres, SKIPS loudly without one (same switch as the Rust
audience tests):

    docker run -d --rm --name fu1306-pg -e POSTGRES_PASSWORD=x -p 55437:5432 postgres:16-alpine
    NOO_KB_AUDIENCE_TEST_DSN=postgresql://postgres:x@127.0.0.1:55437/postgres pytest tests/test_snapshot_audience.py

The corpus reuses ``tests/fixtures/kb_audience_isolation.json`` for who may read
which document; the temporal graph on top of it is built here.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

FX = json.loads((Path(__file__).parent / "fixtures" / "kb_audience_isolation.json").read_text())
DSN = os.environ.get("NOO_KB_AUDIENCE_TEST_DSN") or os.environ.get("NOO_BROKER_TEST_DSN")
needs_db = pytest.mark.skipif(
    not DSN, reason="NOO_KB_AUDIENCE_TEST_DSN not set (needs Postgres); see module docstring"
)


def roles_of(who):
    return FX["callers"][who]["roles"]


DDL = [
    "CREATE TABLE docs (doc_id uuid PRIMARY KEY, source_uri text, title text, hash text, "
    "created_at timestamptz NOT NULL DEFAULT now(), metadata jsonb)",
    "CREATE TABLE pages (page_id uuid PRIMARY KEY, doc_id uuid NOT NULL, page_no int, text text)",
    "CREATE TABLE noo_entities_typed (id uuid PRIMARY KEY, type text NOT NULL, canonical_name text NOT NULL, "
    "metadata jsonb DEFAULT '{}', user_id text, org_id text)",
    "CREATE TABLE noo_temporal_edges (id uuid PRIMARY KEY, subject_id uuid NOT NULL, predicate text NOT NULL, "
    "object_entity_id uuid, user_id text, source_page_id uuid, org_id text)",
    "CREATE TABLE trellion_concepts (id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, canonical_name text NOT NULL, "
    "type text NOT NULL)",
    "CREATE TABLE trellion_dag_edges (id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, src_concept_id uuid NOT NULL, "
    "dst_concept_id uuid NOT NULL, rel_type text NOT NULL, weight double precision DEFAULT 1.0)",
    "CREATE TABLE trellion_communities (id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, level int NOT NULL, "
    "name text NOT NULL, member_concept_ids jsonb NOT NULL DEFAULT '[]')",
    "CREATE TABLE trellion_provenance (id uuid PRIMARY KEY, snapshot_id uuid NOT NULL, concept_id uuid NOT NULL, "
    "source_kind text NOT NULL, source_id uuid NOT NULL)",
]

# name -> (type, owner user_id)
ENTITIES = {
    "ua-person": ("user", "a"),
    "ub-person": ("user", "b"),
    "tpc-aonly": ("topic", None),
    "tpc-bonly": ("topic", None),
    "tpc-shared": ("topic", None),
    "tpc-company": ("topic", None),
    "tpc-adm": ("topic", None),
    "tpc-agent": ("agent_self", None),
    "tpc-orphan": ("topic", None),
}
# (edge name, subject, object, user_id, source page doc key)
EDGES = [
    ("e_a1", "ua-person", "tpc-aonly", "a", None),
    ("e_a2", "ua-person", "tpc-shared", "a", None),
    ("e_b1", "ub-person", "tpc-bonly", "b", None),
    ("e_b2", "ub-person", "tpc-shared", "b", None),
    ("e_co", "tpc-company", "tpc-shared", None, "co"),       # document-derived, company doc
    ("e_adm", "tpc-adm", "tpc-shared", None, "adm"),         # document-derived, admin-only doc
    ("e_agent", "tpc-agent", "tpc-shared", None, None),      # the agent's own state
    ("e_cross", "tpc-aonly", "tpc-bonly", "b", None),        # B's private link to B's topic
    ("e_priv_between_readable", "tpc-aonly", "tpc-company", "b", None),  # B's edge between two A-readable concepts
]


class World:
    pass


async def _build() -> World:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    w = World()
    w.schema = f"fu1306c_{uuid.uuid4().hex}"
    base = DSN
    if base.startswith("postgres://"):
        base = base.replace("postgres://", "postgresql://", 1)
    if "+" not in base.split("://")[0]:
        base = base.replace("postgresql://", "postgresql+psycopg://", 1)
    admin = create_async_engine(base)
    async with admin.begin() as c:
        await c.execute(text(f"CREATE SCHEMA {w.schema}"))
    await admin.dispose()
    w.engine = create_async_engine(base, connect_args={"options": f"-csearch_path={w.schema},public"})
    w.sid = str(uuid.uuid4())
    w.ent, w.concept, w.doc, w.page = {}, {}, {}, {}
    async with w.engine.begin() as c:
        async def ins(sql, **p):
            await c.execute(text(sql), p)

        for ddl in DDL:
            await c.execute(text(ddl))
        for d in FX["docs"]:
            doc, page = str(uuid.uuid4()), str(uuid.uuid4())
            meta = {} if d["roles"] is None else {"roles": d["roles"]}
            await ins("INSERT INTO docs (doc_id, source_uri, title, hash, metadata) "
                      "VALUES (CAST(:i AS uuid), :u, :t, :h, CAST(:m AS jsonb))",
                      i=doc, u=f"file:///{d['key']}", t=d["key"], h=d["key"], m=json.dumps(meta))
            await ins("INSERT INTO pages (page_id, doc_id, page_no) VALUES (CAST(:p AS uuid), CAST(:d AS uuid), 1)",
                      p=page, d=doc)
            w.doc[d["key"]], w.page[d["key"]] = doc, page
        for name, (etype, owner) in ENTITIES.items():
            eid, cid = str(uuid.uuid4()), str(uuid.uuid4())
            await ins("INSERT INTO noo_entities_typed (id, type, canonical_name, user_id) "
                      "VALUES (CAST(:i AS uuid), :t, :n, :u)", i=eid, t=etype, n=name, u=owner)
            await ins("INSERT INTO trellion_concepts (id, snapshot_id, canonical_name, type) "
                      "VALUES (CAST(:i AS uuid), CAST(:s AS uuid), :n, :t)", i=cid, s=w.sid, n=name, t=etype)
            await ins("INSERT INTO trellion_provenance (id, snapshot_id, concept_id, source_kind, source_id) "
                      "VALUES (gen_random_uuid(), CAST(:s AS uuid), CAST(:c AS uuid), 'temporal_edge', CAST(:e AS uuid))",
                      s=w.sid, c=cid, e=eid)
            w.ent[name], w.concept[name] = eid, cid
        for name, subj, obj, owner, page_key in EDGES:
            await ins("INSERT INTO noo_temporal_edges (id, subject_id, predicate, object_entity_id, user_id, source_page_id) "
                      "VALUES (gen_random_uuid(), CAST(:s AS uuid), 'REL', CAST(:o AS uuid), :u, CAST(:p AS uuid))",
                      s=w.ent[subj], o=w.ent[obj], u=owner, p=w.page[page_key] if page_key else None)
            # the build step projects the same relation as a DAG edge between the two concepts
            await ins("INSERT INTO trellion_dag_edges (id, snapshot_id, src_concept_id, dst_concept_id, rel_type) "
                      "VALUES (gen_random_uuid(), CAST(:s AS uuid), CAST(:a AS uuid), CAST(:b AS uuid), 'PREREQ')",
                      s=w.sid, a=w.concept[subj], b=w.concept[obj])
        await ins("INSERT INTO trellion_communities (id, snapshot_id, level, name, member_concept_ids) "
                  "VALUES (gen_random_uuid(), CAST(:s AS uuid), 0, 'L0.C0', CAST(:m AS jsonb))",
                  s=w.sid, m=json.dumps(list(w.concept.values())))
    return w


@pytest.fixture
async def world(monkeypatch):
    w = await _build()
    from noomesh.workers import snapshots as snap

    monkeypatch.setattr(snap, "_trellion_engine", lambda: w.engine)
    try:
        yield w
    finally:
        from sqlalchemy import text

        async with w.engine.begin() as c:
            await c.execute(text(f"DROP SCHEMA {w.schema} CASCADE"))
        await w.engine.dispose()


def _labels(ckg):
    return {c.label for c in ckg.concepts.values()}


def _edges(ckg):
    return {(ckg.concepts[s].label, ckg.concepts[d].label) for s, ds in ckg.forward.items() for d in ds}


@needs_db
async def test_a_restricted_concept_graph_holds_only_what_the_caller_can_read(world):
    from noomesh.workers.snapshot_audience import load_ckg_for_audience

    a = await load_ckg_for_audience(world.engine, world.sid, roles_of("a"))
    # A's own person + topic, the topic B also touched, the company-document topic.
    assert _labels(a) == {"ua-person", "tpc-aonly", "tpc-shared", "tpc-company"}
    # B's, the admin document's, the agent's own state and an entity with no provenance: absent.
    for hidden in ("ub-person", "tpc-bonly", "tpc-adm", "tpc-agent", "tpc-orphan"):
        assert hidden not in _labels(a)
    # Edges: only those with a readable source. B's private edge BETWEEN two concepts A can read is not A's.
    assert _edges(a) == {("ua-person", "tpc-aonly"), ("ua-person", "tpc-shared"), ("tpc-company", "tpc-shared")}
    assert ("tpc-aonly", "tpc-company") not in _edges(a)

    b = await load_ckg_for_audience(world.engine, world.sid, roles_of("b"))
    assert _labels(b) == {"ub-person", "tpc-bonly", "tpc-shared", "tpc-company", "tpc-aonly"}
    # B owns e_cross / e_priv_between_readable, so aonly is B-readable through them.
    assert ("tpc-aonly", "tpc-bonly") in _edges(b) and ("tpc-aonly", "tpc-company") in _edges(b)
    assert ("ua-person", "tpc-aonly") not in _edges(b)


@needs_db
async def test_with_every_concept_readable_the_scoped_loader_equals_trellions(world):
    """Pins the line-for-line re-assembly in snapshot_audience against trellion's
    own loader, so a change to how trellion builds a CKG shows up here."""
    from trellion.snapshots.ckg_adapter import load_ckg_from_snapshot
    from noomesh.workers.snapshot_audience import load_ckg_for_audience

    # A caller who owns both people, and the company/admin documents: reads everything with provenance.
    everyone = ["user:a", "user:b", "company", "system", "admin", "team:x", "user"]
    full = await load_ckg_from_snapshot(world.engine, world.sid)
    scoped = await load_ckg_for_audience(world.engine, world.sid, everyone)
    # tpc-agent (the agent's own state) and tpc-orphan have no owner and no page-derived edge,
    # so not even this caller reads them; every other concept is identical to trellion's.
    assert _labels(scoped) == _labels(full) - {"tpc-agent", "tpc-orphan"}

    def attrs(ckg, keep):
        return {c.label: (c.taxonomy, c.relation_type) for c in ckg.concepts.values() if c.label in keep}

    assert attrs(scoped, _labels(scoped)) == attrs(full, _labels(scoped))
    assert _edges(scoped) == {(s, d) for s, d in _edges(full) if "tpc-agent" not in (s, d)}


@needs_db
async def test_the_curriculum_handler_answers_from_the_readable_graph_and_confirms(world):
    from noomesh.workers import snapshots as snap
    from noomesh.workers.audience import AUDIENCE_KEY

    async def ask(q, roles=None):
        body = {"snapshot_id": world.sid, "q": q}
        if roles is not None:
            body["roles"] = roles
        return await snap._snapshots_curriculum(body)

    # Prerequisites of tpc-aonly: B's topic and B's private edge are both invisible to A.
    a = await ask("what are the prerequisites of tpc-aonly", roles_of("a"))
    assert a["content"] == "none" and a[AUDIENCE_KEY] is True
    assert "tpc-bonly" not in json.dumps(a) and "tpc-company" not in a["content"]
    # Unrestricted is unchanged and unstamped.
    full = await ask("what are the prerequisites of tpc-aonly")
    assert "tpc-bonly" in full["content"] and "tpc-company" in full["content"] and AUDIENCE_KEY not in full
    # A concept the caller cannot read does not exist for them.
    gone = await ask("tell me about tpc-adm", roles_of("a"))
    assert gone["content"] == "No matching concept found." and gone[AUDIENCE_KEY] is True
    assert "tpc-adm" in (await ask("tell me about tpc-adm"))["content"]
    # A path that would need a hidden node is not found, rather than routed through it.
    p = await ask("path from ua-person to tpc-bonly", roles_of("a"))
    assert "tpc-bonly" not in p["content"] and "tpc-aonly" not in p["content"]
    assert "ua-person -> tpc-aonly -> tpc-bonly" in (await ask("path from ua-person to tpc-bonly"))["content"]
    # Listing a taxonomy shows readable members only.
    t = await ask("list all L0.C0", roles_of("a"))
    assert set(t["content"].split(", ")) == {"ua-person", "tpc-aonly", "tpc-shared", "tpc-company"}
    # A snapshot with nothing the caller can read looks like an empty one, and says it was filtered.
    nothing = await ask("tell me about tpc-aonly", ["user:nobody"])
    assert nothing["query_type"] == "EMPTY" and nothing[AUDIENCE_KEY] is True
    # Errors raised after the audience is known are stamped too (so the gateway can show them as 400s).
    err = await snap._snapshots_curriculum({"snapshot_id": world.sid, "roles": roles_of("a")})
    assert err["error"] and err[AUDIENCE_KEY] is True


async def test_a_malformed_audience_is_refused_without_reading_anything(monkeypatch):
    from noomesh.workers import snapshots as snap
    from noomesh.workers.audience import AUDIENCE_KEY

    def boom():
        raise AssertionError("must not touch the database")

    monkeypatch.setattr(snap, "_trellion_engine", boom)
    out = await snap._snapshots_curriculum({"snapshot_id": "s", "q": "x", "roles": "admin"})
    assert "error" in out and AUDIENCE_KEY not in out


# ── list / get / diff for a restricted caller ────────────────

HIDDEN = ("ub-person", "tpc-bonly", "tpc-adm", "tpc-agent", "tpc-orphan", "tpc-bnew")


async def _second_snapshot(world):
    """A later snapshot: everything the first holds, plus a concept B added privately."""
    from sqlalchemy import text

    sid2 = str(uuid.uuid4())
    eid, cid = str(uuid.uuid4()), str(uuid.uuid4())
    async with world.engine.begin() as c:
        await c.execute(text(
            "INSERT INTO trellion_concepts (id, snapshot_id, canonical_name, type) "
            "SELECT gen_random_uuid(), CAST(:n AS uuid), canonical_name, type FROM trellion_concepts "
            "WHERE snapshot_id = CAST(:o AS uuid)"), {"n": sid2, "o": world.sid})
        await c.execute(text(
            "INSERT INTO trellion_provenance (id, snapshot_id, concept_id, source_kind, source_id) "
            "SELECT gen_random_uuid(), CAST(:n AS uuid), c2.id, 'temporal_edge', pr.source_id "
            "FROM trellion_concepts c1 JOIN trellion_provenance pr ON pr.concept_id = c1.id "
            "JOIN trellion_concepts c2 ON c2.snapshot_id = CAST(:n AS uuid) AND c2.canonical_name = c1.canonical_name "
            "WHERE c1.snapshot_id = CAST(:o AS uuid)"), {"n": sid2, "o": world.sid})
        await c.execute(text(
            "INSERT INTO noo_entities_typed (id, type, canonical_name, user_id) "
            "VALUES (CAST(:e AS uuid), 'topic', 'tpc-bnew', 'b')"), {"e": eid})
        await c.execute(text(
            "INSERT INTO trellion_concepts (id, snapshot_id, canonical_name, type) "
            "VALUES (CAST(:c AS uuid), CAST(:n AS uuid), 'tpc-bnew', 'topic')"), {"c": cid, "n": sid2})
        await c.execute(text(
            "INSERT INTO trellion_provenance (id, snapshot_id, concept_id, source_kind, source_id) "
            "VALUES (gen_random_uuid(), CAST(:n AS uuid), CAST(:c AS uuid), 'temporal_edge', CAST(:e AS uuid))"),
            {"n": sid2, "c": cid, "e": eid})
        await c.execute(text(
            "INSERT INTO noo_temporal_edges (id, subject_id, predicate, object_entity_id, user_id) "
            "VALUES (gen_random_uuid(), CAST(:e AS uuid), 'REL', CAST(:p AS uuid), 'b')"),
            {"e": eid, "p": world.ent["ub-person"]})
    return sid2


async def _scoped(snap, body, who):
    from noomesh.workers.audience import AUDIENCE_KEY

    out = await snap._snapshots_scoped({**body, "roles": roles_of(who)})
    assert out.get(AUDIENCE_KEY) is True, out
    return out


@needs_db
async def test_a_restricted_diff_never_shows_a_concept_the_caller_cannot_read(world):
    from noomesh.workers import snapshots as snap

    sid2 = await _second_snapshot(world)
    a1 = (await _scoped(snap, {"op": "concepts", "snapshot_id": world.sid}, "a"))["concepts"]
    a2 = (await _scoped(snap, {"op": "concepts", "snapshot_id": sid2}, "a"))["concepts"]
    names = {n for n, _ in a1} | {n for n, _ in a2}
    assert names == {"ua-person", "tpc-aonly", "tpc-shared", "tpc-company"}
    for hidden in HIDDEN:
        assert hidden not in json.dumps([a1, a2])
    # B added a private concept between the two snapshots: for A the diff is empty.
    assert {tuple(r) for r in a1} == {tuple(r) for r in a2}
    # For B it is the one thing that changed.
    b1 = {tuple(r) for r in (await _scoped(snap, {"op": "concepts", "snapshot_id": world.sid}, "b"))["concepts"]}
    b2 = {tuple(r) for r in (await _scoped(snap, {"op": "concepts", "snapshot_id": sid2}, "b"))["concepts"]}
    assert b2 - b1 == {("tpc-bnew", "topic")} and not b1 - b2


@needs_db
async def test_restricted_list_and_get_counts_are_the_callers_own(world):
    from noomesh.workers import snapshots as snap

    sid2 = await _second_snapshot(world)
    out = await _scoped(snap, {"op": "counts", "snapshot_ids": [world.sid, sid2]}, "a")
    # A reads 4 concepts and 3 DAG edges in the first (see the loader test); the second (built
    # with no DAG edges) holds the same 4 for A: B's extra concept is not A's.
    assert out["counts"][world.sid] == {"concepts": 4, "dag_edges": 3}
    assert out["counts"][sid2] == {"concepts": 4, "dag_edges": 0}
    # The global figure (10 concepts in snapshot 2) never appears for A, and B sees its own.
    # Compare the VALUES: the ids are random UUIDs and may contain "10" as text.
    assert all(v != 10 for c in out["counts"].values() for v in c.values())
    b = await _scoped(snap, {"op": "counts", "snapshot_ids": [sid2]}, "b")
    assert b["counts"][sid2]["concepts"] == 6
    # The counts agree with what the curriculum loader builds for the same caller.
    from noomesh.workers.snapshot_audience import load_ckg_for_audience

    ckg = await load_ckg_for_audience(world.engine, world.sid, roles_of("a"))
    assert len(ckg.concepts) == out["counts"][world.sid]["concepts"]
    assert len(_edges(ckg)) == out["counts"][world.sid]["dag_edges"]
    # A snapshot with nothing readable counts zero.
    nobody = await snap._snapshots_scoped({"op": "counts", "snapshot_ids": [world.sid], "roles": ["user:nobody"]})
    assert nobody["counts"][world.sid] == {"concepts": 0, "dag_edges": 0}


@needs_db
async def test_the_scoped_subject_answers_restricted_callers_only_and_validates(world):
    from noomesh.workers import snapshots as snap
    from noomesh.workers.audience import AUDIENCE_KEY

    refused = await snap._snapshots_scoped({"op": "concepts", "snapshot_id": world.sid})
    assert "error" in refused and "concepts" not in refused and AUDIENCE_KEY not in refused
    bad = await snap._snapshots_scoped({"op": "concepts", "snapshot_id": "not-a-uuid", "roles": roles_of("a")})
    assert bad["error"] and bad[AUDIENCE_KEY] is True
    unk = await snap._snapshots_scoped({"op": "drop", "roles": roles_of("a")})
    assert unk["error"] and unk[AUDIENCE_KEY] is True
