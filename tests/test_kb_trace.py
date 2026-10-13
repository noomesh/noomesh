# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Provenance on ingest and history on retag.

An operator reviewing the corpus asks two things of any document: where did
it come from, and who changed who may read it. These drive the real
`_rag_ingest` / `_rag_retag` and assert what reaches the storage boundary:
`rag.ingest` and `rag.store.set_doc_roles` for the pre-existing calls, and a
fake of the SQL engine behind `docs` for the metadata the worker writes
itself (`metadata.ingest`, `metadata.audience_history`).

The fake `ingest` below reproduces trellion's `insert_doc` dedup semantics,
including the awkward one: on a content-hash hit the NEW metadata is merged
over the existing row ("new keys win"). The "first provenance is kept" test
is only meaningful because of that.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from noomesh.gateway import kb_roles
from noomesh.workers import kb_trace
from noomesh.workers import rag as rag_worker

ADMIN = {"sub": "alice", "scopes": ["admin", "write", "read"]}
PERSON = {"sub": "bob", "scopes": ["read", "write"]}
EPOCH = datetime(2026, 10, 1, tzinfo=timezone.utc)


class _Result:
    def __init__(self, rows, rowcount=0):
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _Conn:
    def __init__(self, eng):
        self.eng = eng

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def commit(self):
        self.eng.commits += 1

    async def execute(self, stmt, params=None):
        sql = " ".join(str(stmt).split())
        params = params or {}
        if "clock_timestamp" in sql:
            return _Result([(self.eng.clock,)])
        if sql.startswith("SELECT doc_id::text"):
            out = []
            for i in params["ids"]:
                d = self.eng.docs.get(i)
                if d is not None:
                    m = d["metadata"]
                    out.append((i, d["created_at"], m.get("ingest"), m.get("audience_history")))
            return _Result(out)
        if sql.startswith("SELECT 1 FROM docs"):
            return _Result([(1,)] if params["id"] in self.eng.docs else [])
        if sql.startswith("UPDATE docs SET metadata") and "roles" in params:
            # one conditional statement (no roles yet AND
            # created by this ingest).
            d = self.eng.docs.get(params["id"])
            if d is None or "roles" in d["metadata"] or d["created_at"] < params["started"]:
                return _Result([], rowcount=0)
            d["metadata"]["roles"] = json.loads(params["roles"])
            return _Result([], rowcount=1)
        if sql.startswith("UPDATE docs SET metadata"):
            self.eng.docs[params["id"]]["metadata"].update(json.loads(params["patch"]))
            self.eng.writes.append((params["id"], json.loads(params["patch"])))
            return _Result([])
        raise AssertionError(f"unexpected SQL: {sql}")


class FakeEngine:
    """The `docs` table, as far as kb_trace touches it."""

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.clock = EPOCH
        self.writes: list[tuple[str, dict]] = []
        self.commits = 0

    def connect(self):
        return _Conn(self)


class FakeStore:
    def __init__(self, eng):
        self._engine = eng
        self.set_calls: list[tuple[list[str], list[str]]] = []
        self.candidates: list[dict] = []

    async def select_docs_for_retag(self, **kw):
        self.select_kw = kw
        return list(self.candidates)

    async def set_doc_roles(self, doc_ids, roles):
        self.set_calls.append((list(doc_ids), list(roles)))
        return len(doc_ids)


class FakeRag:
    """`rag.ingest` with trellion's dedup: same content -> same row, new
    metadata merged over the old (new keys win)."""

    def __init__(self):
        self.engine = FakeEngine()
        self.store = FakeStore(self.engine)
        self.calls: list[dict] = []

    async def ingest(self, content, title=None, source_uri=None, metadata=None):
        self.calls.append({"content": content, "source_uri": source_uri, "metadata": metadata})
        h = hashlib.sha1(content.encode()).hexdigest()
        existing = next((i for i, d in self.engine.docs.items() if d["hash"] == h), None)
        if existing:
            self.engine.docs[existing]["metadata"].update(metadata or {})
            return existing
        # the row is created "now" on the database clock
        self.engine.clock += timedelta(seconds=5)
        doc_id = f"00000000-0000-0000-0000-{len(self.engine.docs) + 1:012d}"
        self.engine.docs[doc_id] = {
            "hash": h, "created_at": self.engine.clock, "metadata": dict(metadata or {}),
        }
        return doc_id


@pytest.fixture
def rag(monkeypatch):
    r = FakeRag()
    grants: dict = {}
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: r)

    async def _rules():
        return []

    async def _grants():
        return grants

    monkeypatch.setattr(rag_worker, "_kb_source_rules", _rules)
    monkeypatch.setattr(rag_worker, "_kb_grants_map", _grants)
    monkeypatch.setattr(kb_roles, "_load_kb_config", lambda: None)
    monkeypatch.setitem(kb_roles._cache, "rules", [])
    monkeypatch.setitem(kb_roles._cache, "default_roles", [])
    return r


async def _ingest(rag, text="hello", requester=None, **params):
    req = {"text": text, "title": "t", **params}
    if requester is not None:
        req["_requester"] = requester
    out = await rag_worker._rag_ingest(req)
    return rag.engine.docs[out["doc_id"]]["metadata"].get("ingest"), out["doc_id"]


# ── provenance on ingest ──────────────────────────────────────────────


async def test_a_person_upload_records_who_and_that_it_was_an_upload(rag):
    prov, _ = await _ingest(rag, requester=PERSON, source_uri="upload://notes.md")
    assert prov["by"] == "bob" and prov["via"] == "upload"
    assert datetime.fromisoformat(prov["at"]).tzinfo is not None


async def test_the_cli_is_recognised_by_its_file_scheme(rag):
    prov, _ = await _ingest(rag, requester=PERSON, source_uri="file:///home/bob/a.md")
    assert (prov["by"], prov["via"]) == ("bob", "cli")


async def test_a_plain_api_call_with_a_user_is_api(rag):
    prov, _ = await _ingest(rag, requester=PERSON)
    assert (prov["by"], prov["via"]) == ("bob", "api")


async def test_the_mcp_door_is_read_from_the_signed_harness_claim(rag):
    req = {**PERSON, "harness": "mcp-external:laptop"}
    prov, _ = await _ingest(rag, requester=req, source_uri="file:///x.md")
    assert (prov["by"], prov["via"]) == ("bob", "mcp"), "harness beats the scheme"


async def test_an_operator_hmac_call_has_no_by_and_is_internal(rag):
    prov, _ = await _ingest(rag, requester=None)
    assert prov["by"] is None and prov["via"] == "internal"
    assert prov["by"] is None  # never a token, never a header value
    assert set(prov) == {"by", "via", "at"}


async def test_the_ingest_loop_says_folder_or_drive_in_its_metadata(rag):
    folder, _ = await _ingest(rag, text="a", source_uri="/mnt/nas/a.pdf",
                              metadata={"source_kind": "watched_folder", "mount": "/mnt/nas"})
    drive, _ = await _ingest(rag, text="b", source_uri="gdrive://F1",
                             metadata={"source_kind": "watched_drive"})
    assert (folder["by"], folder["via"]) == (None, "folder")
    assert (drive["by"], drive["via"]) == (None, "drive")
    # a Drive URI with no loop metadata is still Drive
    bare, _ = await _ingest(rag, text="c", source_uri="gdrive://F2")
    assert bare["via"] == "drive"


async def test_a_heartbeat_report_is_a_heartbeat(rag):
    prov, _ = await _ingest(rag, source_uri="heartbeat://task-1/run-9", roles=["generated"])
    assert (prov["by"], prov["via"]) == (None, "heartbeat")
    research, _ = await _ingest(rag, text="r", source_uri="research://topic/2026-10-01")
    assert research["via"] == "research"


async def test_a_person_cannot_label_their_upload_as_a_folder_scan(rag):
    prov, _ = await _ingest(rag, requester=PERSON, metadata={"source_kind": "watched_folder"},
                            source_uri="heartbeat://x/y")
    assert prov["via"] == "api" and prov["by"] == "bob"


async def test_a_caller_cannot_write_the_trail_through_metadata(rag):
    forged = {"by": "root", "via": "cli", "at": "1999-01-01T00:00:00+00:00"}
    prov, doc_id = await _ingest(rag, requester=PERSON,
                                 metadata={"ingest": forged, "audience_history": [{"by": "root"}], "k": 1})
    assert prov["by"] == "bob"
    sent = rag.calls[-1]["metadata"]
    assert "ingest" not in sent and "audience_history" not in sent and sent["k"] == 1
    assert "audience_history" not in rag.engine.docs[doc_id]["metadata"]


async def test_a_dedup_hit_keeps_the_first_ingests_provenance(rag):
    first, doc_id = await _ingest(rag, text="same", requester=PERSON, source_uri="file:///a.md")
    again, doc_id2 = await _ingest(rag, text="same", requester=ADMIN, source_uri="upload://b.md")
    assert doc_id2 == doc_id
    assert again == first and again["by"] == "bob" and again["via"] == "cli"
    # ...and the second ingest never rewrote it
    assert [w for w in rag.engine.writes if w[0] == doc_id and "ingest" in w[1]] == [
        (doc_id, {"ingest": first})
    ]


async def test_a_dedup_hit_on_a_document_from_before_provenance_stays_unknown(rag):
    old = "00000000-0000-0000-0000-0000000000aa"
    rag.engine.docs[old] = {
        "hash": hashlib.sha1(b"legacy").hexdigest(),
        "created_at": EPOCH - timedelta(days=90),
        "metadata": {"roles": ["admin"]},
    }
    prov, doc_id = await _ingest(rag, text="legacy", requester=PERSON)
    assert doc_id == old and prov is None, "a re-ingest must not claim an old document"


async def test_provenance_failing_never_fails_the_ingest(rag, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(kb_trace, "_patch", boom)
    out = await rag_worker._rag_ingest({"text": "x", "title": "t", "_requester": PERSON})
    assert out["doc_id"]


# ── retag: refuse an empty audience ───────────────────────────────────


@pytest.mark.parametrize("roles", [[], [" ", ""], None, ""])
async def test_retag_refuses_an_empty_audience(rag, roles):
    rag.store.candidates = [{"doc_id": "d1", "title": "t", "source_uri": "u", "roles": ["admin"]}]
    req = {"match": "*", "apply": True, "only_untagged": False}
    if roles is not None:
        req["roles"] = roles
    out = await rag_worker._rag_retag({**req, "_requester": ADMIN})
    assert "always has an audience" in out["error"] and "--role admin" in out["error"]
    assert rag.store.set_calls == [], "nothing may reach the store"


# ── retag: history ────────────────────────────────────────────────────


def _seed(rag, *specs):
    rag.store.candidates = []
    for i, (frm, history) in enumerate(specs):
        doc_id = f"11111111-1111-1111-1111-{i + 1:012d}"
        rag.engine.docs[doc_id] = {"hash": str(i), "created_at": EPOCH,
                                   "metadata": {"roles": frm, "audience_history": history} if history is not None
                                   else {"roles": frm}}
        rag.store.candidates.append({"doc_id": doc_id, "title": f"t{i}", "source_uri": f"u{i}", "roles": frm})
    return [c["doc_id"] for c in rag.store.candidates]


async def test_an_applied_retag_appends_at_by_from_to_per_document(rag):
    ids = _seed(rag, (["admin"], None), ([], None), (["user:amy"], None))
    out = await rag_worker._rag_retag({
        "match": "*", "roles": ["user:alice", "team:ops"], "apply": True,
        "only_untagged": False, "_requester": ADMIN})
    assert out["status"] == "ok" and "warning" not in out
    # what reached the store
    assert rag.store.set_calls == [(ids, ["user:alice", "team:ops"])]
    for doc_id, frm in zip(ids, (["admin"], [], ["user:amy"])):
        (entry,) = rag.engine.docs[doc_id]["metadata"]["audience_history"]
        assert set(entry) == {"at", "by", "from", "to"}
        assert entry["by"] == "alice"
        assert entry["from"] == frm and entry["to"] == ["user:alice", "team:ops"]
        assert datetime.fromisoformat(entry["at"]).tzinfo is not None
    # a second retag appends rather than replaces
    rag.store.candidates = [{"doc_id": ids[0], "title": "t", "source_uri": "u", "roles": ["user:alice", "team:ops"]}]
    await rag_worker._rag_retag({"doc_ids": [ids[0]], "roles": ["company"], "apply": True,
                                 "only_untagged": False, "_requester": ADMIN})
    hist = rag.engine.docs[ids[0]]["metadata"]["audience_history"]
    assert [h["to"] for h in hist] == [["user:alice", "team:ops"], ["company"]]


async def test_a_dry_run_writes_nothing_anywhere(rag):
    _seed(rag, (["admin"], None))
    out = await rag_worker._rag_retag({"match": "*", "roles": ["company"], "only_untagged": False,
                                       "_requester": ADMIN})
    assert out["status"] == "dry-run"
    assert out["documents"][0]["from"] == ["admin"] and out["documents"][0]["to"] == ["company"]
    assert rag.store.set_calls == [] and rag.engine.writes == []


async def test_a_retag_that_changes_nothing_records_nothing(rag):
    _seed(rag, (["company"], None))
    await rag_worker._rag_retag({"match": "*", "roles": ["company"], "apply": True,
                                 "only_untagged": False, "_requester": ADMIN})
    assert rag.engine.writes == []


async def test_the_history_is_capped_at_the_newest_twenty(rag):
    old = [{"at": f"t{i}", "by": "x", "from": [], "to": ["admin"]} for i in range(20)]
    (doc_id,) = _seed(rag, (["admin"], old))
    await rag_worker._rag_retag({"doc_ids": [doc_id], "roles": ["company"], "apply": True,
                                 "only_untagged": False, "_requester": ADMIN})
    hist = rag.engine.docs[doc_id]["metadata"]["audience_history"]
    assert len(hist) == kb_trace.HISTORY_CAP == 20
    assert hist[0]["at"] == "t1", "the oldest entry fell off"
    assert hist[-1]["to"] == ["company"] and hist[-1]["by"] == "alice"


async def test_a_history_write_failure_is_reported_not_raised(rag, monkeypatch):
    ids = _seed(rag, (["admin"], None))

    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(kb_trace, "_patch", boom)
    out = await rag_worker._rag_retag({"doc_ids": ids, "roles": ["company"], "apply": True,
                                       "only_untagged": False, "_requester": ADMIN})
    assert out["status"] == "ok" and out["applied"] == 1
    assert "audience_history not written" in out["warning"]


async def test_the_cluster_caller_is_named_cluster(rag):
    ids = _seed(rag, (["admin"], None))
    await rag_worker._rag_retag({"doc_ids": ids, "roles": ["company"], "apply": True, "only_untagged": False})
    assert rag.engine.docs[ids[0]]["metadata"]["audience_history"][0]["by"] == "cluster"


# ── retag: the clamp is still enforced ────────────────────────────────


async def test_a_non_admin_cannot_tag_into_an_audience_they_could_not_write(rag):
    ids = _seed(rag, (["user:bob"], None))
    out = await rag_worker._rag_retag({"doc_ids": ids, "roles": ["admin"], "apply": True,
                                       "only_untagged": False, "_requester": PERSON})
    assert "not yours to tag into" in out["error"] and "admin" in out["error"]
    assert rag.store.set_calls == [] and rag.engine.writes == []
    other = await rag_worker._rag_retag({"doc_ids": ids, "roles": ["user:amy"], "apply": True,
                                         "only_untagged": False, "_requester": PERSON})
    assert "not yours" in other["error"] and rag.store.set_calls == []
    # their own tier is theirs to set, and is recorded under their name
    ok = await rag_worker._rag_retag({"doc_ids": ids, "roles": ["user:bob"], "apply": True,
                                      "only_untagged": False, "_requester": PERSON})
    assert ok["status"] == "ok"


def test_the_empty_audience_message_is_the_one_the_cli_prints():
    cli = (rag_worker.__file__ and __import__("pathlib").Path(rag_worker.__file__)
           .resolve().parents[3] / "noo-cli/src/commands/rag.rs").read_text()
    m = re.search(r'const EMPTY_AUDIENCE: &str = "([^"]+)"', cli)
    assert m and m.group(1) == rag_worker.EMPTY_AUDIENCE_MSG
