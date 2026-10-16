# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for the security audit logger sinks (CRIT-5 regression).

Covers the no-op-before-init guard, the file sink, the sync DB sink, and the
new AsyncEngine DB sink used by worker_pool in Rust-primary mode — the path
that was previously never wired, silently dropping every Python-emitted
security event.

Runnable two ways:
  - `pytest tests/test_audit_log.py`
  - `PYTHONPATH=src python3 tests/test_audit_log.py`   (no pytest needed)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import noomesh.gateway.audit_log as m
from noomesh.gateway.audit_log import AuditEvent, AuditLogger


# ── Fakes: record the bound params instead of touching a real DB ────────────
class _FakeSyncConn:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, _stmt, params=None):
        return _record(self.sink, _stmt, params)

    def commit(self):
        pass


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value

    def first(self):
        return None  # no chained row yet


def _record(sink, stmt, params):
    """Record the INSERT's params; answer the writer's jsonb-text question
    (`CAST(:d AS jsonb)::text`) with the text unchanged."""
    if "AS jsonb)::text" in str(stmt):
        return _Result(params["d"])
    if str(stmt).lstrip().upper().startswith("SELECT"):
        return _Result(None)  # the chain lock and the tail read
    sink.append(params)
    return _Result(None)


class _FakeSyncEngine:
    def __init__(self):
        self.rows = []

    def connect(self):
        return _FakeSyncConn(self.rows)


class _FakeAsyncConn:
    def __init__(self, sink):
        self.sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, _stmt, params=None):
        return _record(self.sink, _stmt, params)

    async def commit(self):
        pass


class _FakeAsyncEngine:
    def __init__(self):
        self.rows = []

    def connect(self):
        return _FakeAsyncConn(self.rows)


def test_audit_noop_before_init():
    # audit() must never raise when the singleton is uninitialised.
    m._audit_logger = None
    m.audit("exec_denied", actor="x", outcome="denied")  # no exception


def test_init_sets_singleton_and_file_sink_writes():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        m.init_audit_logger(log_file=path)
        m.audit("admin_action", severity="warning", actor="u", outcome="ok", extra="v")
        m.get_audit_logger().close()
        lines = [l for l in open(path).read().splitlines() if l.strip()]
        assert len(lines) == 1
        row = json.loads(lines[0])
        assert row["event_type"] == "admin_action"
        assert row["severity"] == "warning"
        assert row["details"]["extra"] == "v"


def test_sync_db_sink_writes_row():
    eng = _FakeSyncEngine()
    lg = AuditLogger(db_engine=eng)
    lg.log(AuditEvent(event_type="exec_denied", actor="u", resource="tool", outcome="denied"))
    assert len(eng.rows) == 1
    assert eng.rows[0]["et"] == "exec_denied"
    assert eng.rows[0]["actor"] == "u"
    assert eng.rows[0]["outcome"] == "denied"


def test_async_db_sink_writes_row():
    eng = _FakeAsyncEngine()
    lg = AuditLogger(async_engine=eng)

    async def _inner():
        # audit() is sync fire-and-forget; from within a running loop the write
        # is scheduled as a task. Drain it before asserting.
        lg.log(AuditEvent(event_type="cluster_auth_failure", actor="node-1", outcome="blocked"))
        assert lg._pending, "async write should have been scheduled"
        await asyncio.gather(*list(lg._pending))

    asyncio.run(_inner())
    assert len(eng.rows) == 1
    assert eng.rows[0]["et"] == "cluster_auth_failure"
    assert eng.rows[0]["actor"] == "node-1"


def test_async_sink_without_running_loop_is_safe():
    # Called outside any event loop: DB sink is skipped, no crash, no rows.
    eng = _FakeAsyncEngine()
    lg = AuditLogger(async_engine=eng)
    lg.log(AuditEvent(event_type="path_traversal", actor="a", outcome="blocked"))
    assert eng.rows == []


def test_sync_engine_wins_when_both_set():
    sync_eng = _FakeSyncEngine()
    async_eng = _FakeAsyncEngine()
    lg = AuditLogger(db_engine=sync_eng, async_engine=async_eng)
    lg.log(AuditEvent(event_type="rate_limit", actor="ip", outcome="throttled"))
    assert len(sync_eng.rows) == 1
    assert async_eng.rows == []


if __name__ == "__main__":
    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)


# ---------------------------------------------------------------------------
# 2026-09-16: the DB sink writes as the app role, pinned to the mesh schema.
# The worker used to hand it trellion's engine (noo_trellion, search_path
# trellion,public), which cannot see mesh.noo_security_audit — every
# Python-emitted event failed and the trail held no worker rows.
# ---------------------------------------------------------------------------

def test_audit_sink_engine_is_off_without_the_app_dsn():
    engine, reason = m.audit_sink_engine(env={})
    assert engine is None
    assert "DATABASE_URL" in reason


def test_audit_sink_engine_is_the_app_role_pinned_to_mesh(monkeypatch):
    captured = {}

    def fake_create_async_engine(url, **kw):
        captured["url"] = url
        captured.update(kw)
        return object()

    import sqlalchemy.ext.asyncio as sa_async
    monkeypatch.setattr(sa_async, "create_async_engine", fake_create_async_engine)
    engine, reason = m.audit_sink_engine(
        env={"DATABASE_URL": "postgresql://noo_app:pw@postgres:5432/noomesh",
             "NOO_TRELLION_DATABASE_URL": "postgresql://noo_trellion:pw@postgres:5432/noomesh"}
    )
    assert engine is not None
    assert captured["url"].startswith("postgresql+psycopg://noo_app:")
    assert "search_path=mesh" in captured["connect_args"]["options"]
    assert "mesh" in reason


def test_worker_audit_file_lookup_survives_a_broken_config(monkeypatch):
    import noomesh.gateway.worker_pool as wp

    def broken():
        raise ValueError("Configuration has cross-section errors")

    import noomesh.config as cfg
    monkeypatch.setattr(cfg, "get_config", broken)
    assert wp._configured_audit_log_file() is None
