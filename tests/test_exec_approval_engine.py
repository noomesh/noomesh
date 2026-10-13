# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The mirror's engine resolver must skip a broken engine and cache the
working one — regression test for the mTLS-key fire-drill finding."""
from contextlib import asynccontextmanager


from noomesh.gateway.exec_approval import ExecApprovalManager


class _FakeConn:
    def __init__(self, fail):
        self._fail = fail

    async def execute(self, *a, **k):
        if self._fail:
            raise RuntimeError("private key file has group or world access")
        return None

    async def commit(self):
        pass


class _FakeEngine:
    """Minimal stand-in exposing the async `connect()` context manager the
    resolver probes with SELECT 1."""

    def __init__(self, works: bool):
        self.works = works
        self.probes = 0

    def connect(self):
        engine = self

        @asynccontextmanager
        async def _cm():
            engine.probes += 1
            yield _FakeConn(fail=not engine.works)

        return _cm()


async def _resolve_with(monkeypatch, store_engine, noo_engine):
    mgr = ExecApprovalManager(mode="approval")

    class _Store:
        _engine = store_engine

    monkeypatch.setattr(
        "noomesh.gateway.worker_pool._get_conversation_store",
        lambda: (_Store() if store_engine is not None else None),
        raising=False,
    )
    monkeypatch.setattr(
        "noomesh.db.engine.get_async_engine",
        lambda: noo_engine,
        raising=False,
    )
    return mgr, await mgr._db_engine()


async def test_skips_broken_prefers_working(monkeypatch):
    broken = _FakeEngine(works=False)   # e.g. the mTLS-key engine
    working = _FakeEngine(works=True)
    # store engine broken, noomesh engine working -> must pick noomesh
    mgr, resolved = await _resolve_with(monkeypatch, broken, working)
    assert resolved is working


async def test_prefers_store_engine_when_it_works(monkeypatch):
    working = _FakeEngine(works=True)
    other = _FakeEngine(works=True)
    mgr, resolved = await _resolve_with(monkeypatch, working, other)
    assert resolved is working  # store tried first


async def test_returns_none_when_all_broken(monkeypatch):
    mgr, resolved = await _resolve_with(
        monkeypatch, _FakeEngine(works=False), _FakeEngine(works=False))
    assert resolved is None


async def test_result_is_cached(monkeypatch):
    working = _FakeEngine(works=True)
    mgr, resolved = await _resolve_with(monkeypatch, working, None)
    assert resolved is working
    probes_after_first = working.probes
    again = await mgr._db_engine()
    assert again is working
    assert working.probes == probes_after_first  # no re-probe
