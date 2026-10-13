# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`worker.rag.entity_cleanup`: the junk-entity cleanup behind the front door.

The cleanup itself is trellion's (``trellion.live.junk_entity_cleanup``, tested
in trellion). What is pinned HERE is what this worker adds: a dry run unless
told otherwise, the worker's own store engine and nothing the caller names, a
clear answer on an older trellion, a busy answer rather than a queue, and a
reply that never carries a database error (whose text includes entity names).

Two layers. The unit tests stand in a FAITHFUL FAKE of
``junk_entity_cleanup.run`` (same signature and report shape as the real one:
see ``FakeCleanup``). The DB-backed tests at the bottom run the REAL module
against a real schema; they need ``NOO_ENTITY_CLEANUP_TEST_DSN`` (a pgvector
Postgres) and a trellion that has the module, and skip loudly otherwise.
"""

from __future__ import annotations

import os
import re
import sys
import types
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

os.environ.setdefault("NOO_WORKER_SURFACES", "ml")

from noomesh.workers import rag as rag_mod  # noqa: E402
from noomesh.workers import registry  # noqa: E402

MODULE = "trellion.live.junk_entity_cleanup"


@dataclass
class Cand:
    entity_id: str
    name: str
    etype: str
    reason: str = "math_symbol"
    edges: int = 0
    mentions: int = 0
    clusters: int = 0


@dataclass
class Report:
    dry_run: bool
    scanned: int = 0
    candidates: list = field(default_factory=list)
    staged: int = 0
    skipped_over_cap: int = 0
    run_id: Any = None
    lock_busy: bool = False

    def by_reason(self):
        from collections import Counter
        return Counter(c.reason for c in self.candidates)

    def by_type(self):
        from collections import Counter
        return Counter(c.etype for c in self.candidates)


class FakeCleanup(types.ModuleType):
    """Same call shape as trellion's ``run(engine, *, apply, max_delete, batch,
    restrict_to)`` and the same ``CleanupReport`` fields."""

    def __init__(self, cands=None, lock_busy=False, boom=None):
        super().__init__(MODULE)
        self.calls: list[dict] = []
        self.cands, self.lock_busy, self.boom = cands or [], lock_busy, boom

    async def run(self, engine, *, apply=False, max_delete=5000, batch=200, restrict_to=None,
                  staging_schema=None):
        self.calls.append({"engine": engine, "apply": apply, "max_delete": max_delete,
                           "batch": batch, "restrict_to": restrict_to, "staging_schema": staging_schema})
        if self.boom:
            raise self.boom
        rep = Report(dry_run=not apply, scanned=100, candidates=list(self.cands))
        if apply:
            rep.run_id = "entq-deadbeef"
            if self.lock_busy:
                rep.lock_busy = True
            else:
                rep.staged = min(len(self.cands), max_delete)
        return rep


ENGINE = object()


class _Store:
    _engine = ENGINE


class _Rag:
    store = _Store()


@pytest.fixture
def rig(monkeypatch):
    async def _where(engine):
        return "mesh"

    def _install(fake: FakeCleanup | None):
        monkeypatch.setattr(rag_mod, "_get_rag", lambda: _Rag())
        monkeypatch.setattr(rag_mod, "_staging_schema", _where)
        monkeypatch.setitem(sys.modules, MODULE, fake)
        return fake
    return _install


JUNK = [
    Cand("1", "theta", "parameter", edges=7, mentions=8, clusters=1),
    Cand("2", "0.003", "parameter", "bare_number", edges=2, mentions=4),
    Cand("3", "a", "variable", edges=0, mentions=1),
]


ADMIN = {"sub": "root", "role": "admin"}


async def call(req: dict):
    """As the gateway sends it: an admin caller attached (a test that wants none says `_requester: None`)."""
    req = {"_requester": ADMIN, **req}
    if req["_requester"] is None:
        del req["_requester"]
    return await rag_mod._rag_entity_cleanup(req)


def test_the_subject_is_registered_on_the_ml_surface_not_the_intelligent_tier():
    assert "worker.rag.entity_cleanup" in registry.all_handlers()
    import subprocess
    out = subprocess.run(
        [sys.executable, "-c",
         "import json; from noomesh.workers import all_handlers; print(json.dumps(sorted(all_handlers())))"],
        env={**os.environ, "NOO_WORKER_SURFACES": "ml-intel",
             "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")},
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr[-400:]
    assert "worker.rag.entity_cleanup" not in out.stdout


async def test_it_is_a_dry_run_unless_apply_is_true(rig):
    fake = rig(FakeCleanup(JUNK))
    out = await call({})
    assert fake.calls[-1]["apply"] is False
    assert out["status"] == "dry-run" and out["dry_run"] is True
    assert out["junk"] == 3 and out["staged"] == 0 and out["run_id"] is None
    # the examples are most-connected first, with the footprint
    assert [e["name"] for e in out["examples"]] == ["theta", "0.003", "a"]
    assert out["examples"][0] == {"name": "theta", "type": "parameter", "reason": "math_symbol",
                                  "edges": 7, "mentions": 8, "clusters": 1}
    assert out["edge_rows"] == 9 and out["with_edges"] == 2 and out["mention_rows"] == 13
    assert out["by_reason"] == {"math_symbol": 2, "bare_number": 1}
    await call({"apply": False})
    assert fake.calls[-1]["apply"] is False


@pytest.mark.parametrize("bad", ["true", "false", 1, 0, "yes", [True]])
async def test_apply_must_be_the_boolean_true(rig, bad):
    fake = rig(FakeCleanup(JUNK))
    out = await call({"apply": bad})
    assert "error" in out and fake.calls == []


async def test_apply_stages_and_reports_the_run(rig):
    fake = rig(FakeCleanup(JUNK))
    out = await call({"apply": True, "max_delete": 2})
    assert fake.calls[-1]["apply"] is True and fake.calls[-1]["max_delete"] == 2
    assert out["status"] == "applied" and out["staged"] == 2 and out["run_id"] == "entq-deadbeef"


async def test_apply_names_the_schema_the_staging_table_is_in_and_a_dry_run_does_not(rig):
    fake = rig(FakeCleanup(JUNK))
    await call({"apply": True})
    assert fake.calls[-1]["staging_schema"] == "mesh"
    await call({})
    assert fake.calls[-1]["staging_schema"] is None


async def test_the_staging_schema_is_never_taken_from_the_request(rig):
    fake = rig(FakeCleanup(JUNK))
    await call({"apply": True, "staging_schema": "evil", "staging_table": "x"})
    assert fake.calls[-1]["staging_schema"] == "mesh"


async def test_a_trellion_that_cannot_be_told_the_schema_is_an_upgrade_not_a_half_apply(rig):
    class Old(FakeCleanup):
        async def run(self, engine, *, apply=False, max_delete=5000, batch=200, restrict_to=None):
            assert not apply, "an apply must not run on a trellion that cannot be told the schema"
            return Report(dry_run=True, scanned=1)

    rig(Old(JUNK))
    out = await call({"apply": True})
    assert "upgrade" in out["error"]
    assert (await call({}))["status"] == "dry-run"  # a preview never needed the schema


async def test_no_staging_table_anywhere_refuses_before_changing_anything(rig, monkeypatch):
    fake = rig(FakeCleanup(JUNK))

    async def nowhere(engine):
        return ""
    monkeypatch.setattr(rag_mod, "_staging_schema", nowhere)
    out = await call({"apply": True})
    assert "does not exist" in out["error"] and fake.calls == []


async def test_the_workers_own_engine_is_used_and_nothing_the_caller_names(rig):
    fake = rig(FakeCleanup(JUNK))
    await call({"apply": True, "engine": object(), "dsn": "postgresql://evil/x", "database_url": "x",
                "restrict_to": ["1"], "batch": 1, "examples": 1})
    c = fake.calls[-1]
    assert c["engine"] is ENGINE
    assert c["restrict_to"] is None and c["batch"] == 200


@pytest.mark.parametrize("req", [{"examples": -1}, {"examples": 201}, {"examples": "5"}, {"examples": True},
                                 {"max_delete": 0}, {"max_delete": 5001}, {"max_delete": "9"}, {"max_delete": 1.5}])
async def test_out_of_range_counts_are_refused_before_anything_runs(rig, req):
    fake = rig(FakeCleanup(JUNK))
    out = await call(req)
    assert "error" in out and fake.calls == []


async def test_examples_are_capped_to_what_was_asked(rig):
    rig(FakeCleanup(JUNK))
    assert len((await call({"examples": 1}))["examples"]) == 1
    assert (await call({"examples": 0}))["examples"] == []


async def test_a_held_prune_lock_is_busy_not_a_silent_success(rig):
    rig(FakeCleanup(JUNK, lock_busy=True))
    out = await call({"apply": True})
    assert out["status"] == "busy" and "busy" in out["error"] and "run_id" not in out


async def test_an_older_trellion_without_the_module_gets_a_clear_upgrade_error(rig):
    rig(None)  # sys.modules[MODULE] = None: `import` raises ModuleNotFoundError(name=MODULE)
    out = await call({"apply": True})
    assert "no entity cleanup" in out["error"] and "upgrade" in out["error"]


async def test_a_broken_dependency_inside_the_module_is_not_reported_as_upgrade(rig, monkeypatch):
    rig(FakeCleanup(JUNK))
    import importlib

    def broken(name):
        raise ModuleNotFoundError("No module named 'something_else'", name="something_else")
    monkeypatch.setattr(importlib, "import_module", broken)
    out = await call({})
    assert "upgrade" not in out["error"] and "could not be loaded" in out["error"]


async def test_a_database_error_never_reaches_the_reply(rig):
    rig(FakeCleanup(JUNK, boom=RuntimeError("DETAIL: Key (canonical_name)=(patient zero) [parameters: {'n': 'patient zero'}]")))
    out = await call({"apply": True})
    assert "patient zero" not in str(out) and "RuntimeError" in out["error"]
    assert "restorable" in out["error"]


async def test_a_request_with_no_caller_is_refused(rig):
    fake = rig(FakeCleanup(JUNK))
    for req in ({"apply": True, "_requester": None}, {"apply": True, "_requester": "root"}, {"apply": True, "_requester": []}):
        out = await call(req)
        assert "admin" in out["error"] and fake.calls == [], req


async def test_a_database_error_never_reaches_the_log(rig):
    from structlog.testing import capture_logs

    class DbError(Exception):
        sqlstate = "23505"

    secret = "patient zero said the quote text"
    boom = RuntimeError(f"DETAIL: Key (canonical_name)=(patient zero) [parameters: {{'p': '{secret}'}}]")
    boom.orig = DbError(f"[parameters: {{'p': '{secret}'}}]")
    rig(FakeCleanup(JUNK, boom=boom))
    with capture_logs() as logs:
        out = await call({"apply": True})
    assert "error" in out
    blob = repr(logs)
    assert "patient zero" not in blob and secret not in blob, blob
    failed = [l for l in logs if l["event"] == "entity_cleanup.failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError" and failed[0]["sqlstate"] == "23505"
    assert not any("exc_info" in l or "error" in l for l in failed), failed
    # the import-failure line carries a class and a module name, not the message
    import importlib
    with capture_logs() as logs2:
        rig(FakeCleanup(JUNK))
        orig = importlib.import_module
        importlib.import_module = lambda n: (_ for _ in ()).throw(ModuleNotFoundError(f"No module named 'x' secret={secret}", name="x"))
        try:
            await call({})
        finally:
            importlib.import_module = orig
    assert secret not in repr(logs2)


@pytest.mark.parametrize("role", ["operator", "user", "", None])
async def test_a_non_admin_requester_is_refused_here_too(rig, role):
    fake = rig(FakeCleanup(JUNK))
    out = await call({"apply": True, "_requester": {"sub": "x", "role": role}})
    assert "admin" in out["error"] and fake.calls == []
    out = await call({"apply": True, "_requester": {"sub": "root", "role": "admin"}})
    assert out["status"] == "applied"


async def test_without_a_rag_store_it_says_so(rig, monkeypatch):
    rig(FakeCleanup(JUNK))
    monkeypatch.setattr(rag_mod, "_get_rag", lambda: None)
    assert (await call({}))["error"] == "RAG not initialized"


# ---------------------------------------------------------------- DB-backed (real trellion, production layout)
#
# The layout the cluster runs, not a one-schema stand-in (the stand-in is why
# the first real `noo graph entity-cleanup --apply` failed 42P01 with CI green):
#
#   * trellion's tables in schema ``trellion``, built by trellion's own alembic chain;
#   * ``mesh.graph_prune_staging`` in schema ``mesh``, from the gateway baseline's
#     own DDL (read out of gateway-rust/migrations/0001_baseline.sql, so a change
#     there is a change here);
#   * the worker's engine is what ``PageIndexRAG(dsn=PAGEINDEX_DSN)`` builds: a
#     ``PageIndexStore(dsn=...)`` engine as ``noo_app``, whose DSN carries
#     ``search_path=mesh,public,trellion,evolve`` and which trellion then pins to
#     ``trellion,public``;
#   * a second role shaped like ``noo_trellion``: DML on trellion, no USAGE on mesh.
#
# CI's python `test` job has the pgvector service (NOO_KB_AUDIENCE_TEST_DSN, a
# superuser) and trellion installed; these tests must run there, not skip.

DSN = os.environ.get("NOO_ENTITY_CLEANUP_TEST_DSN") or os.environ.get("NOO_KB_AUDIENCE_TEST_DSN")
BASELINE = os.path.join(os.path.dirname(__file__), "..", "gateway-rust", "migrations", "0001_baseline.sql")


def _real_module():
    try:
        import importlib
        return importlib.import_module(MODULE)
    except ImportError:
        return None


needs_db = pytest.mark.skipif(
    not DSN or _real_module() is None,
    reason="needs NOO_KB_AUDIENCE_TEST_DSN (or NOO_ENTITY_CLEANUP_TEST_DSN) and a trellion with "
           "junk_entity_cleanup (PYTHONPATH=<trellion>/src)",
)


def _staging_ddl() -> list[str]:
    """Every statement in the gateway baseline that creates ``graph_prune_staging``
    (table, primary key, indexes), unqualified exactly as the baseline has them."""
    import re

    sql = open(BASELINE).read()
    out = []
    for stmt in sql.split(";\n"):
        body = "\n".join(l for l in stmt.splitlines() if not l.startswith("--")).strip()
        if re.match(r"(CREATE TABLE|ALTER TABLE ONLY) graph_prune_staging\b", body) or re.match(
            r"CREATE INDEX \S+ ON graph_prune_staging\b", body
        ):
            out.append(body)
    assert out and out[0].startswith("CREATE TABLE") and any("PRIMARY KEY" in o for o in out), \
        f"the baseline no longer defines graph_prune_staging the way this reads it: {out}"
    return out


class Prod:
    pass


@pytest.fixture(scope="module")
def prod():
    """A scratch database laid out like production, with its two roles."""
    import subprocess

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    import trellion

    tag = uuid.uuid4().hex[:8]
    base = make_url(DSN.replace("postgres://", "postgresql://", 1)).set(drivername="postgresql+psycopg")
    dbname, app, tre = f"entstg_{tag}", f"entstg_{tag}_app", f"entstg_{tag}_tre"
    pw = "entstg-pw"

    def admin_engine(db):
        return create_engine(base.set(database=db), isolation_level="AUTOCOMMIT")

    root = admin_engine(base.database)
    with root.connect() as c:
        c.execute(text(f'CREATE DATABASE "{dbname}"'))
        for r in (app, tre):
            c.execute(text(f"CREATE ROLE {r} LOGIN PASSWORD '{pw}' NOSUPERUSER NOCREATEDB NOCREATEROLE"))
    scratch = admin_engine(dbname)
    try:
        with scratch.connect() as c:
            c.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            c.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            c.execute(text("CREATE SCHEMA mesh"))
        # trellion's own chain, as the DDL role (here: the superuser), into schema `trellion`
        ini = os.path.join(os.path.dirname(trellion.__file__), "db", "alembic.ini")
        env = {k: v for k, v in os.environ.items()
               if k not in ("NOO_TRELLION_DDL_DATABASE_URL", "NOO_MIGRATIONS_DSN", "PAGEINDEX_DSN", "PGVECTOR_URL")}
        env["DATABASE_URL"] = base.set(database=dbname).render_as_string(hide_password=False)
        res = subprocess.run([sys.executable, "-m", "alembic", "-c", ini, "upgrade", "head"],
                             env=env, capture_output=True, text=True, timeout=600)
        assert res.returncode == 0, res.stderr[-1500:]
        with scratch.connect() as c:
            c.execute(text("SET search_path = mesh"))
            for ddl in _staging_ddl():
                c.execute(text(ddl))
            assert c.execute(text("SELECT to_regclass('mesh.graph_prune_staging') IS NOT NULL")).scalar()
            assert not c.execute(text("SELECT to_regclass('trellion.graph_prune_staging') IS NOT NULL")).scalar()
            # noo_app: what role_provision::grant_runtime_access gives it on mesh/public, plus
            # trellion's DML (live: noo_app holds DELETE,INSERT,SELECT,UPDATE on trellion.*).
            for sch in ("mesh", "public", "trellion"):
                c.execute(text(f"GRANT USAGE ON SCHEMA {sch} TO {app}"))
                c.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {sch} TO {app}"))
                c.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {sch} TO {app}"))
            # noo_trellion: DML on trellion, and NO usage on mesh (live: that is the fact).
            for sch in ("public", "trellion"):
                c.execute(text(f"GRANT USAGE ON SCHEMA {sch} TO {tre}"))
            c.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA trellion TO {tre}"))
            c.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA trellion TO {tre}"))
        p = Prod()
        p.admin = scratch

        def dsn_of(role, options=""):
            u = base.set(database=dbname, username=role, password=pw).render_as_string(hide_password=False)
            return u.replace("postgresql+psycopg://", "postgresql://", 1) + options

        # the container's PAGEINDEX_DSN, search_path and all
        p.app_dsn = dsn_of(app, "?options=-c%20search_path%3Dmesh,public,trellion,evolve")
        p.tre_dsn = dsn_of(tre)
        p.app_role = app
        yield p
    finally:
        scratch.dispose()
        with root.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)'))
            for r in (app, tre):
                c.execute(text(f"DROP ROLE IF EXISTS {r}"))
        root.dispose()


class Graph:
    pass


async def _seed(store, tag):
    g = Graph()
    g.store, g.tag = store, tag
    doc_id, _ = await store.insert_doc(f"entcli://{tag}", "t", tag)
    page_id = await store.insert_page(doc_id, 1, "JEPA, world models, a, x_t.")
    g.real = {n: await store.upsert_entity(n, "concept") for n in (f"jepa-{tag}", f"world model {tag}")}
    g.junk = {"a": await store.upsert_entity("a", "variable"), "x_t": await store.upsert_entity("x_t", "variable")}
    for eid in [*g.real.values(), *g.junk.values()]:
        await store.insert_mention(eid, page_id, quote="q")
    r = list(g.real.values())
    await store.insert_edge(r[0], "RELATED_TO", g.junk["a"], {})
    await store.insert_edge(r[0], "RELATED_TO", r[1], {})
    return g


async def _graph_for(dsn, monkeypatch):
    from trellion.live.pageindex_store import PageIndexStore

    store = PageIndexStore(dsn=dsn)  # what PageIndexRAG(dsn=...) builds: the worker's engine
    g = await _seed(store, uuid.uuid4().hex[:8])

    class Rag:
        pass
    rag = Rag()
    rag.store = store
    monkeypatch.setattr(rag_mod, "_get_rag", lambda: rag)
    return g


@pytest.fixture
async def graph(prod, monkeypatch):
    from sqlalchemy import text

    g = await _graph_for(prod.app_dsn, monkeypatch)
    g.prod = prod
    # the premise that made this bug: the worker's engine cannot see mesh by bare name
    async with g.store._engine.connect() as conn:
        assert (await conn.execute(text("SELECT to_regclass('graph_prune_staging') IS NULL"))).scalar(), \
            "the worker's engine can resolve graph_prune_staging by bare name: this test no longer reproduces production"
    yield g
    ids = [*g.real.values(), *g.junk.values()]
    async with g.store._engine.connect() as conn:
        await conn.execute(text("DELETE FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))"), {"i": ids})
        await conn.execute(text("DELETE FROM mesh.graph_prune_staging WHERE entity_id = ANY(CAST(:i AS uuid[]))"), {"i": ids})
        await conn.execute(text("DELETE FROM docs WHERE source_uri LIKE :u"), {"u": f"entcli://{g.tag}%"})
        await conn.commit()
    await g.store._engine.dispose()


async def _count(store, sql, **p):
    from sqlalchemy import text
    async with store._engine.connect() as conn:
        return (await conn.execute(text(sql), p)).scalar()


@needs_db
async def test_real_dry_run_reports_the_junk_and_changes_nothing(graph):
    tables = ("entities", "edges", "mentions", "mesh.graph_prune_staging")
    before = {t: await _count(graph.store, f"SELECT count(*) FROM {t}") for t in tables}
    out = await call({})
    assert out["status"] == "dry-run" and out["run_id"] is None
    assert sorted(e["name"] for e in out["examples"]) == ["a", "x_t"]
    by = {e["name"]: e for e in out["examples"]}
    assert by["a"]["edges"] == 1 and by["a"]["mentions"] == 1 and by["x_t"]["edges"] == 0
    assert {t: await _count(graph.store, f"SELECT count(*) FROM {t}") for t in tables} == before


@needs_db
async def test_real_apply_stages_then_deletes_only_the_junk(graph):
    from sqlalchemy import text

    # `a` is private to an account (entities.user_id = the account NAME), `x_t` is shared
    async with graph.store._engine.begin() as conn:
        await conn.execute(text("UPDATE entities SET user_id = :u WHERE entity_id = CAST(:e AS uuid)"),
                           {"u": f"own-{graph.tag}", "e": graph.junk["a"]})
    out = await call({"apply": True})
    assert out["status"] == "applied" and out["staged"] == 2 and out["run_id"].startswith("entq-")
    junk, real = list(graph.junk.values()), list(graph.real.values())
    q = "SELECT count(*) FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))"
    assert await _count(graph.store, q, i=junk) == 0
    assert await _count(graph.store, q, i=real) == 2
    assert await _count(graph.store,
        "SELECT count(*) FROM edges WHERE src_entity_id = CAST(:a AS uuid) AND dst_entity_id = CAST(:b AS uuid)",
        a=real[0], b=real[1]) == 1
    # staged with reason junk_entity under the run id the reply names, restorable by the prune restore
    assert await _count(graph.store,
        "SELECT count(*) FROM mesh.graph_prune_staging WHERE run_id = :r AND reason = 'junk_entity' AND restored_at IS NULL",
        r=out["run_id"]) == 2
    # the owner rides in the payload's top-level `user_id`, the key the gateway's restore and an
    # account erase read: ALWAYS present, null for a shared entity (a missing key is refused on restore)
    async with graph.store._engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT canonical_name, payload ? 'user_id', payload->>'user_id' FROM mesh.graph_prune_staging "
            "WHERE run_id = :r"), {"r": out["run_id"]})).all()
    owners = {n: (has, o) for n, has, o in rows}
    assert owners == {"a": (True, f"own-{graph.tag}"), "x_t": (True, None)}, owners
    # the worker's report, run again, finds nothing left
    assert (await call({}))["junk"] == 0


GRAPH_PRUNE_RS = os.path.join(os.path.dirname(__file__), "..", "gateway-rust", "src", "graph_prune.rs")


def _json_keys(block: str) -> set[str]:
    return set(re.findall(r'"(\w+)":', block))


def _gateway_payload_shape() -> dict[str, set[str]]:
    """The keys the gateway's graph prune writes into a staged entity payload, read from
    graph_prune.rs: the restore and the erase are written against exactly this shape."""
    src = open(GRAPH_PRUNE_RS).read()
    as_json = re.search(r"fn as_json\(&self\) -> Value \{\s*json!\(\{(.*?)\}\)", src, re.S)
    snap = re.search(r"async fn snapshot_entity\(.*?\n\}\n", src, re.S)
    assert as_json and snap, "graph_prune.rs no longer has as_json/snapshot_entity: re-point this parity test"
    blocks = re.findall(r"json!\(\{(.*?)\}\)", snap.group(0), re.S)
    assert len(blocks) == 3, f"expected the edge, mention and top-level json! blocks, found {len(blocks)}"
    shape = {"entity": _json_keys(as_json.group(1)), "edges": _json_keys(blocks[0]),
             "mentions": _json_keys(blocks[1]), "top": _json_keys(blocks[2])}
    # the parse found the real thing, not an empty set that every payload satisfies
    assert {"entity_id", "canonical_name"} <= shape["entity"] and "edge_id" in shape["edges"] \
        and "mention_id" in shape["mentions"] and {"entity", "user_id"} <= shape["top"], shape
    return shape


@needs_db
async def test_the_cleanup_payload_has_the_gateway_prune_payload_shape(graph):
    """trellion's cleanup and the gateway's prune stage into the same table, read back by the
    same restore and the same account erase. They drifted once (the cleanup left out `user_id`
    and a restore made private entities shared): every key the gateway writes, the cleanup
    writes too (it may add its own, e.g. `cluster_members`)."""
    from sqlalchemy import text

    gw = _gateway_payload_shape()
    out = await call({"apply": True})
    async with graph.store._engine.connect() as conn:
        payload = (await conn.execute(text(
            "SELECT payload FROM mesh.graph_prune_staging WHERE run_id = :r AND canonical_name = 'a'"),
            {"r": out["run_id"]})).scalar_one()
    assert payload["edges"] and payload["mentions"], "seed `a` with an edge and a mention, or the row shapes go unchecked"
    assert gw["top"] <= set(payload), gw["top"] - set(payload)
    assert set(payload["entity"]) == gw["entity"]
    assert set(payload["edges"][0]) == gw["edges"]
    assert set(payload["mentions"][0]) == gw["mentions"]


@needs_db
async def test_an_apply_through_an_engine_that_cannot_see_mesh_refuses_and_changes_nothing(prod, monkeypatch):
    """noo_trellion has DML on trellion and no USAGE on mesh. The apply must say so
    BEFORE touching a row: never a delete without its staging row."""
    from sqlalchemy import text

    g = await _graph_for(prod.tre_dsn, monkeypatch)
    try:
        out = await call({"apply": True})
        assert "error" in out and "run_id" not in out, out
        assert await _count(g.store, "SELECT count(*) FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))",
                            i=[*g.junk.values()]) == 2
        with prod.admin.connect() as c:
            assert c.execute(text("SELECT count(*) FROM mesh.graph_prune_staging")).scalar() == 0
    finally:
        async with g.store._engine.connect() as conn:
            await conn.execute(text("DELETE FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))"),
                               {"i": [*g.real.values(), *g.junk.values()]})
            await conn.execute(text("DELETE FROM docs WHERE source_uri LIKE :u"), {"u": f"entcli://{g.tag}%"})
            await conn.commit()
        await g.store._engine.dispose()


@needs_db
async def test_a_decoy_staging_table_the_gateway_does_not_read_is_refused_and_nothing_is_deleted(graph):
    """Staging must land where the gateway's restore reads it (mesh, else public).
    With mesh's table gone and a stray trellion.graph_prune_staging that the
    engine's own search_path WOULD resolve, an apply must refuse: a delete whose
    undo nothing can find is a silent loss."""
    from sqlalchemy import text

    admin = graph.prod.admin
    with admin.connect() as c:
        c.execute(text("ALTER TABLE mesh.graph_prune_staging RENAME TO graph_prune_staging_aside"))
        c.execute(text("CREATE TABLE trellion.graph_prune_staging "
                       "(LIKE mesh.graph_prune_staging_aside INCLUDING DEFAULTS)"))
        c.execute(text(f"GRANT INSERT, SELECT ON trellion.graph_prune_staging TO {graph.prod.app_role}"))
    try:
        # the premise: the worker's own engine now resolves the bare name to the decoy
        async with graph.store._engine.connect() as conn:
            assert (await conn.execute(text("SELECT to_regclass('graph_prune_staging') IS NOT NULL"))).scalar(), \
                "the decoy is not on the engine's path: the test proves nothing"
        out = await call({"apply": True})
        assert "error" in out and "run_id" not in out, out
        assert "mesh.graph_prune_staging" in out["error"]
        q = "SELECT count(*) FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))"
        assert await _count(graph.store, q, i=[*graph.junk.values()]) == len(graph.junk)
        with admin.connect() as c:
            assert c.execute(text("SELECT count(*) FROM trellion.graph_prune_staging")).scalar() == 0
    finally:
        with admin.connect() as c:
            c.execute(text("DROP TABLE IF EXISTS trellion.graph_prune_staging"))
            c.execute(text("ALTER TABLE mesh.graph_prune_staging_aside RENAME TO graph_prune_staging"))


@needs_db
async def test_a_delete_that_is_refused_takes_its_staging_row_with_it(graph):
    """Staging and delete commit together: when the delete cannot happen, the staging
    insert does not survive either, so a re-run is not double-staged and nothing is lost."""
    from sqlalchemy import text

    with graph.prod.admin.connect() as c:
        c.execute(text(f"REVOKE DELETE ON trellion.entities FROM {graph.prod.app_role}"))
    try:
        out = await call({"apply": True})
        assert "error" in out and "run_id" not in out, out
    finally:
        with graph.prod.admin.connect() as c:
            c.execute(text(f"GRANT DELETE ON trellion.entities TO {graph.prod.app_role}"))
    ids = [*graph.junk.values()]
    assert await _count(graph.store, "SELECT count(*) FROM entities WHERE entity_id = ANY(CAST(:i AS uuid[]))", i=ids) == 2
    assert await _count(graph.store, "SELECT count(*) FROM mesh.graph_prune_staging WHERE entity_id = ANY(CAST(:i AS uuid[]))",
                        i=ids) == 0


# ---------------------------------------------------------------- the glue's contract with trellion

#: What trellion's `junk_entity_cleanup` promises (trellion #83) and this worker leans on.
RUN_PARAMS = {"engine", "apply", "max_delete", "batch", "restrict_to", "staging_schema"}
REPORT_FIELDS = {"dry_run", "scanned", "candidates", "staged", "skipped_over_cap", "run_id", "lock_busy"}
CANDIDATE_FIELDS = {"name", "etype", "reason", "edges", "mentions", "clusters"}


def test_the_worker_only_passes_what_run_accepts_and_only_reads_what_the_report_has_structural():
    """Always runs: parses THIS worker's source, so a rename on either side of the
    glue fails here even where trellion is not installed."""
    import ast
    import inspect

    src = inspect.getsource(rag_mod)
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "run" and getattr(n.func.value, "id", "") == "cleanup"]
    assert len(calls) == 1, "the worker calls cleanup.run exactly once"
    passed = {k.arg for k in calls[0].keywords} - {None}  # None = the **kwargs spread
    assert passed <= RUN_PARAMS and {"apply", "max_delete"} <= passed, passed
    # (staging_schema reaches run() through **kwargs from _rag_entity_cleanup; pinned in the
    # fake tests above and, against the real run, in the two-schema test below)
    assert len(calls[0].args) == 1, "the engine is the one positional argument"
    assert "restrict_to" not in passed, "a caller-named restriction never reaches trellion"
    # every report / candidate attribute the payload builder reads is in the contract
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_entity_cleanup_payload")
    def attrs_of(var):
        return {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute) and getattr(n.value, "id", "") == var}

    report_attrs, cand_attrs = attrs_of("report"), attrs_of("c")
    assert report_attrs and cand_attrs, "the walk found nothing: the payload builder was renamed"
    assert report_attrs <= REPORT_FIELDS | {"by_reason", "by_type"}, report_attrs
    assert cand_attrs <= CANDIDATE_FIELDS, cand_attrs


def test_the_worker_matches_the_installed_trellions_real_run_signature():
    """With a trellion that ships the module (CI's), the contract above is checked
    against the real `run`, `CleanupReport` and `Candidate`; without one the
    structural test above is what guards the glue."""
    import dataclasses
    import inspect

    mod = _real_module()
    if mod is None:
        return
    params = set(inspect.signature(mod.run).parameters)
    assert {"engine", "apply", "max_delete"} <= params, params
    assert RUN_PARAMS >= {"apply", "max_delete"} and {"apply", "max_delete"} <= params
    rep = {f.name for f in dataclasses.fields(mod.CleanupReport)}
    cand = {f.name for f in dataclasses.fields(mod.Candidate)}
    assert REPORT_FIELDS <= rep, REPORT_FIELDS - rep
    assert CANDIDATE_FIELDS <= cand, CANDIDATE_FIELDS - cand
    for m in ("by_reason", "by_type"):
        assert callable(getattr(mod.CleanupReport, m))
    # the worker's payload builder runs against a REAL report object
    report = mod.CleanupReport(dry_run=True, scanned=3, candidates=[mod.Candidate("1", "a", "variable", "single_letter", edges=2)])
    out = rag_mod._entity_cleanup_payload(report, 5)
    assert out["junk"] == 1 and out["examples"][0]["name"] == "a" and out["by_reason"] == {"single_letter": 1}


# ---------------------------------------------------------------- recluster takes the same lock

class _Res:
    def __init__(self, v):
        self.v = v

    def scalar(self):
        return self.v


class LockConn:
    def __init__(self, log, got):
        self.log, self.got = log, got

    async def execute(self, sql):
        text_ = str(sql)
        self.log.append("lock" if "pg_try_advisory_lock" in text_ else "unlock")
        return _Res(self.got)

    async def commit(self):
        pass

    async def close(self):
        self.log.append("close")


class LockEngine:
    def __init__(self, log, got=True):
        self.log, self.got = log, got

    async def connect(self):
        return LockConn(self.log, self.got)


class Clusterer:
    def __init__(self, log, gate=None):
        self.log, self.gate = log, gate

    async def run_clustering(self, **kw):
        self.log.append("cluster")
        if self.gate is not None:
            await self.gate.wait()
        return {"clusters": 1}


def _recluster_rag(log, got=True, gate=None):
    class Store:
        _engine = LockEngine(log, got)

    class Rag:
        store = Store()
        clusterer = Clusterer(log, gate)

    return Rag()


async def test_recluster_runs_under_the_prune_lock_and_releases_it(monkeypatch):
    from noomesh.workers import graph as graph_mod

    log: list = []
    monkeypatch.setattr(graph_mod, "_get_rag", lambda: _recluster_rag(log))
    out = await graph_mod._graph_recluster({})
    assert out["status"] == "ok"
    assert log == ["lock", "cluster", "unlock", "close"], log


async def test_recluster_refuses_while_prune_or_a_cleanup_holds_the_lock(monkeypatch):
    from noomesh.workers import graph as graph_mod

    log: list = []
    monkeypatch.setattr(graph_mod, "_get_rag", lambda: _recluster_rag(log, got=False))
    out = await graph_mod._graph_recluster({})
    assert out["status"] == "already_running" and "lock" in out["message"]
    assert "cluster" not in log and log[-1] == "close"
    # and the in-flight flag was not left set by the refusal
    log.clear()
    monkeypatch.setattr(graph_mod, "_get_rag", lambda: _recluster_rag(log))
    assert (await graph_mod._graph_recluster({}))["status"] == "ok"


@needs_db
async def test_a_running_recluster_makes_a_real_cleanup_apply_busy_and_vice_versa(graph, monkeypatch):
    import asyncio

    from noomesh.workers import graph as graph_mod

    gate = asyncio.Event()
    started = asyncio.Event()

    class Rag:
        pass

    rag = Rag()
    rag.store = graph.store

    class Cl:
        async def run_clustering(self, **kw):
            started.set()
            await gate.wait()
            return {"clusters": 0}

    rag.clusterer = Cl()
    monkeypatch.setattr(graph_mod, "_get_rag", lambda: rag)
    monkeypatch.setattr(rag_mod, "_get_rag", lambda: rag)
    task = asyncio.create_task(graph_mod._graph_recluster({}))
    await asyncio.wait_for(started.wait(), 10)
    before = await _count(graph.store, "SELECT count(*) FROM entities")
    busy = await call({"apply": True})
    assert busy["status"] == "busy", busy
    assert await _count(graph.store, "SELECT count(*) FROM entities") == before, "a busy cleanup deleted nothing"
    gate.set()
    assert (await task)["status"] == "ok"
    done = await call({"apply": True})
    assert done["status"] == "applied" and done["staged"] == 2, done
