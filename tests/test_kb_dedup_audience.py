# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An ingest never changes an existing document's audience.

The fake `rag.ingest` reproduces trellion's `insert_doc` on a content-hash
hit: the existing row's metadata is merged with the NEW call's, new keys
winning. Since #622 every ingest carries roles, so before the fix Bob
re-uploading Alice's private content turned `user:alice` into `user:bob`.
The assertions are on what ends up in the row.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from noomesh.gateway import kb_roles
from noomesh.workers import rag as rag_worker

ALICE = {"sub": "alice", "scopes": ["read", "write"]}
BOB = {"sub": "bob", "scopes": ["read", "write"]}
ADMIN = {"sub": "root", "scopes": ["admin", "write", "read"], "role": "admin"}
EPOCH = datetime(2026, 10, 1, tzinfo=timezone.utc)


class _Result:
    def __init__(self, rows, rowcount=0):
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Conn:
    def __init__(self, eng):
        self.eng = eng

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def commit(self):
        pass

    async def execute(self, stmt, params=None):
        sql = " ".join(str(stmt).split())
        params = params or {}
        if "clock_timestamp" in sql:
            return _Result([(self.eng.clock,)])
        if sql.startswith("SELECT 1 FROM docs"):
            return _Result([(1,)] if params["id"] in self.eng.docs else [])
        if sql.startswith("UPDATE docs SET metadata"):
            # The real statement is conditional: no roles yet AND created by
            # this ingest. Mirror that, so a test can race two callers.
            assert "NOT (COALESCE(metadata, '{}'::jsonb) ? 'roles')" in sql, sql
            assert "created_at >= :started" in sql, sql
            d = self.eng.docs.get(params["id"])
            if d is None or "roles" in d["metadata"] or d["created_at"] < params["started"]:
                return _Result([], rowcount=0)
            d["metadata"]["roles"] = json.loads(params["roles"])
            self.eng.writes.append(params["id"])
            return _Result([], rowcount=1)
        raise AssertionError(f"unexpected SQL: {sql}")


class FakeEngine:
    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.clock = EPOCH
        self.writes: list[str] = []

    def connect(self):
        return _Conn(self)


class FakeRag:
    def __init__(self):
        self.store = type("S", (), {})()
        self.engine = self.store._engine = FakeEngine()
        self.calls: list[dict] = []

    async def ingest(self, content, title=None, source_uri=None, metadata=None):
        self.calls.append({"metadata": metadata})
        h = hashlib.sha1(content.encode()).hexdigest()
        hit = next((i for i, d in self.engine.docs.items() if d["hash"] == h), None)
        if hit:  # trellion insert_doc on a hash hit: new keys win
            self.engine.docs[hit]["metadata"].update(metadata or {})
            return hit
        self.engine.clock += timedelta(seconds=5)
        doc_id = f"00000000-0000-0000-0000-{len(self.engine.docs) + 1:012d}"
        self.engine.docs[doc_id] = {"hash": h, "created_at": self.engine.clock,
                                    "metadata": dict(metadata or {})}
        return doc_id


@pytest.fixture
def rag(monkeypatch):
    r = FakeRag()

    async def _none():
        return {}

    async def _rules():
        return []

    monkeypatch.setattr(rag_worker, "_get_rag", lambda: r)
    monkeypatch.setattr(rag_worker, "_kb_grants_map", _none)
    monkeypatch.setattr(rag_worker, "_kb_source_rules", _rules)
    monkeypatch.setattr(kb_roles, "_load_kb_config", lambda: None)
    monkeypatch.setitem(kb_roles._cache, "rules", [])
    monkeypatch.setitem(kb_roles._cache, "default_roles", [])
    return r


async def _ingest(text, requester, **kw):
    req = {"text": text, "title": "t", **kw}
    if requester is not None:
        req["_requester"] = requester
    return await rag_worker._rag_ingest(req)


def _roles(rag, doc_id):
    return rag.engine.docs[doc_id]["metadata"].get("roles")


async def test_a_new_document_gets_its_audience(rag):
    out = await _ingest("fresh", ALICE)
    assert _roles(rag, out["doc_id"]) == ["user:alice"]
    assert "roles" not in rag.calls[-1]["metadata"], "roles must not ride the merge"


async def test_bob_uploading_alices_identical_content_does_not_take_it_over(rag):
    first = await _ingest("the plan", ALICE)
    second = await _ingest("the plan", BOB)
    assert second["doc_id"] == first["doc_id"]
    assert _roles(rag, first["doc_id"]) == ["user:alice"]
    assert rag.engine.writes == [first["doc_id"]], "only the creating ingest wrote the row"
    assert "audience_history" not in rag.engine.docs[first["doc_id"]]["metadata"]
    # a restricted caller gets the plain success shape: no existence oracle
    assert set(second) == {"doc_id", "message", "title"}


async def test_an_admin_reingest_leaves_roles_alone_and_says_so(rag):
    first = await _ingest("shared", BOB)
    again = await _ingest("shared", ADMIN, roles=["company"])
    assert _roles(rag, first["doc_id"]) == ["user:bob"], "an explicit roles= is not a retag"
    assert again["existing"] is True and again["audience_unchanged"] is True
    assert "already in the knowledge base" in again["message"]
    assert (await _ingest("shared", None))["existing"] is True  # internal caller


async def test_the_flag_is_for_operators_and_admins_only(rag):
    await _ingest("doc", ALICE)
    op = {"sub": "olga", "scopes": ["read", "write"], "role": "operator"}
    assert (await _ingest("doc", op)).get("existing") is True
    assert "existing" not in await _ingest("doc", BOB)
    assert "existing" not in await _ingest("never seen", ADMIN)


async def test_a_legacy_untagged_document_stays_untagged_on_reingest(rag):
    rag.engine.docs["00000000-0000-0000-0000-0000000000aa"] = {
        "hash": hashlib.sha1(b"legacy").hexdigest(),
        "created_at": EPOCH - timedelta(days=90), "metadata": {}}
    await _ingest("legacy", BOB)
    assert _roles(rag, "00000000-0000-0000-0000-0000000000aa") is None


async def test_a_failed_audience_write_fails_the_ingest(rag, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(rag_worker.kb_ingest_roles, "settle_roles", boom)
    with pytest.raises(RuntimeError):
        await _ingest("x", ALICE)


async def test_two_racing_identical_uploads_settle_on_exactly_one_audience():
    # Both callers took the clock BEFORE the row was inserted, so both look
    # like its creator. Only one conditional UPDATE may land; the other is
    # told the document already existed and changes nothing.
    from noomesh.workers import kb_ingest_roles
    eng = FakeEngine()
    store = type("S", (), {"_engine": eng})()
    eng.docs["d1"] = {"created_at": EPOCH, "metadata": {}}
    first = await kb_ingest_roles.settle_roles(store, "d1", ["user:alice"], EPOCH)
    second = await kb_ingest_roles.settle_roles(store, "d1", ["user:bob"], EPOCH)
    assert (first, second) == ("created", "existing")
    assert eng.docs["d1"]["metadata"]["roles"] == ["user:alice"]
    assert eng.writes == ["d1"]
