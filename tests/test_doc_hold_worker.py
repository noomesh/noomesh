# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The document-hold worker handlers: dry run by default, one selector, a
reason where one is needed, and a clean error against a trellion that does
not know about holds yet.

The store is trellion's (`PageIndexStore.hold_docs` and friends); these pin
what the HANDLERS do with a request before and after it.
"""

from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("NOO_WORKER_SURFACES", "ml")

from noomesh.workers import rag as rag_worker  # noqa: E402


class FakeStore:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def hold_docs(self, title_prefix=None, doc_ids=None, reason="", apply=False):
        self.calls.append(("hold", dict(title_prefix=title_prefix, doc_ids=doc_ids, reason=reason, apply=apply)))
        ids = [f"id{i}" for i in range(80)]
        return {"count": len(ids), "doc_ids": ids, "applied": apply}

    async def unhold_docs(self, title_prefix=None, doc_ids=None, apply=False):
        self.calls.append(("unhold", dict(title_prefix=title_prefix, doc_ids=doc_ids, apply=apply)))
        return {"count": 2, "doc_ids": ["a", "b"], "applied": apply}

    async def list_held(self, reason=None, limit=1000, offset=0):
        self.calls.append(("held", dict(reason=reason, limit=limit, offset=offset)))
        return {"total": 1, "docs": [], "limit": limit, "offset": offset}

    async def purge_held(self, reason, apply=False, batch=500):
        self.calls.append(("purge", dict(reason=reason, apply=apply)))
        return {"count": 3, "doc_ids": ["a", "b", "c"], "deleted": 3 if apply else 0}


class Rag:
    def __init__(self, store):
        self.store = store


@pytest.fixture
def store(monkeypatch):
    s = FakeStore()
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: Rag(s))
    return s


def run(coro):
    return asyncio.run(coro)


def test_subjects_are_registered():
    import noomesh.workers  # noqa: F401
    from noomesh.workers import registry

    handlers = registry.all_handlers()
    for subject in ("hold", "unhold", "held", "purge"):
        assert f"worker.rag.{subject}" in handlers


def test_hold_is_a_dry_run_unless_asked(store):
    out = run(rag_worker._rag_hold({"title_prefix": "p", "reason": "r"}))
    assert store.calls == [("hold", dict(title_prefix="p", doc_ids=None, reason="r", apply=False))]
    assert out["status"] == "dry-run" and out["applied"] == 0 and out["count"] == 80
    assert "Nothing changed" in out["message"]
    # the reply is size-capped, the count is not
    assert len(out["doc_ids"]) == 50


def test_hold_applies_only_when_apply_is_true(store):
    out = run(rag_worker._rag_hold({"doc_ids": ["x"], "reason": "r", "apply": True}))
    assert store.calls[-1][1]["apply"] is True
    assert out["status"] == "ok" and out["applied"] == 80
    # a truthy string is not apply=true
    run(rag_worker._rag_hold({"doc_ids": ["x"], "reason": "r", "apply": ""}))
    assert store.calls[-1][1]["apply"] is False


@pytest.mark.parametrize(
    "req",
    [
        {"reason": "r"},  # no selector
        {"title_prefix": "p", "doc_ids": ["a"], "reason": "r"},  # two selectors
        {"doc_ids": "not-a-list", "reason": "r"},
    ],
)
def test_the_selector_must_be_exactly_one(store, req):
    out = run(rag_worker._rag_hold(req))
    assert "error" in out and store.calls == []


@pytest.mark.parametrize("reason", [None, "", "   "])
def test_hold_needs_a_reason(store, reason):
    out = run(rag_worker._rag_hold({"title_prefix": "p", "reason": reason, "apply": True}))
    assert "reason" in out["error"] and store.calls == []


def test_unhold_needs_no_reason_and_is_a_dry_run_by_default(store):
    out = run(rag_worker._rag_unhold({"title_prefix": "p"}))
    assert store.calls == [("unhold", dict(title_prefix="p", doc_ids=None, apply=False))]
    assert out["status"] == "dry-run" and out["applied"] == 0


def test_held_passes_paging_through(store):
    run(rag_worker._rag_held({"reason": "r", "limit": 7, "offset": 14}))
    assert store.calls == [("held", dict(reason="r", limit=7, offset=14))]


@pytest.mark.parametrize("reason", [None, "", "  "])
def test_purge_without_a_reason_is_refused(store, reason):
    out = run(rag_worker._rag_purge({"reason": reason, "apply": True}))
    assert "reason" in out["error"] and store.calls == []


def test_purge_is_a_dry_run_unless_asked(store):
    out = run(rag_worker._rag_purge({"reason": "r"}))
    assert store.calls == [("purge", dict(reason="r", apply=False))]
    assert out["status"] == "dry-run" and out["deleted"] == 0 and out["count"] == 3
    out = run(rag_worker._rag_purge({"reason": "r", "apply": True}))
    assert out["status"] == "ok" and out["deleted"] == 3


def test_an_older_trellion_gets_a_roll_trellion_message(monkeypatch):
    class Old:  # no hold methods at all
        pass

    monkeypatch.setattr(rag_worker, "_get_rag", lambda: Rag(Old()))
    for call, req in (
        (rag_worker._rag_hold, {"title_prefix": "p", "reason": "r"}),
        (rag_worker._rag_unhold, {"title_prefix": "p"}),
        (rag_worker._rag_held, {}),
        (rag_worker._rag_purge, {"reason": "r"}),
    ):
        assert "roll trellion" in run(call(req))["error"]


def _check_rag_sql(monkeypatch, column_present: bool) -> list[str]:
    from noomesh.workers import autonomy

    seen: list[str] = []

    class Res:
        def __init__(self, v):
            self.v = v

        def scalar(self):
            return self.v

    class Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, stmt):
            q = str(stmt)
            if "information_schema" in q:
                return Res(column_present)
            seen.append(q)
            # a database without the column rejects any query that names it
            if not column_present and "held_at" in q:
                raise AssertionError(f"names a column that does not exist: {q}")
            return Res(0)

    class Eng:
        def connect(self):
            return Conn()

    monkeypatch.setattr(autonomy, "_trellion_engine", lambda: Eng())
    out = run(autonomy._autonomy_check_rag({}))
    assert out["success"] is True, out
    return seen


def test_the_self_heal_counts_leave_held_documents_out(monkeypatch):
    """check_rag reports unembedded pages and the entity gap to the Rust
    self-heal loop; a held document is kept out of both on purpose."""
    seen = _check_rag_sql(monkeypatch, True)
    page_sql = [q for q in seen if "FROM pages" in q]
    assert len(page_sql) == 2, seen
    assert all("held_at IS NULL" in q and "JOIN docs" in q for q in page_sql), page_sql


def test_the_self_heal_still_answers_before_trellion_migrates(monkeypatch):
    """No docs.held_at yet (the stack can ship beside an older trellion): the
    plain form, and no error."""
    seen = _check_rag_sql(monkeypatch, False)
    page_sql = [q for q in seen if "FROM pages" in q]
    assert len(page_sql) == 2, seen
    assert all("held_at" not in q for q in page_sql)


def test_a_missing_column_error_becomes_the_roll_trellion_message(monkeypatch):
    class Unmigrated:
        async def hold_docs(self, **kw):
            raise RuntimeError('column "held_at" of relation "docs" does not exist')

        async def list_held(self, **kw):
            raise RuntimeError('column "held_at" does not exist')

        async def purge_held(self, **kw):
            raise RuntimeError('column "hold_reason" does not exist')

    monkeypatch.setattr(rag_worker, "_get_rag", lambda: Rag(Unmigrated()))
    for call, req in (
        (rag_worker._rag_hold, {"title_prefix": "p", "reason": "r"}),
        (rag_worker._rag_held, {}),
        (rag_worker._rag_purge, {"reason": "r"}),
    ):
        assert "roll trellion" in run(call(req))["error"]
