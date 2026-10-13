# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for audit-archive rotation retention semantics (H-L2 regression).

The key hardening: with `backend="none"` a partition past the retention window
must be RETAINED (never dropped) — silently deleting audit history on the
rotation boundary is an audit-retention gap. The normal path (a real backend)
still exports-then-drops.

Runnable via pytest or `PYTHONPATH=src python3 tests/test_audit_archive_rotate.py`.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import noomesh.gateway.audit_archive as aa
from noomesh.gateway.audit_archive import ArchiveConfig


class _DummyEngine:
    pass


def _run(coro):
    return asyncio.run(coro)


def _patch(monkey):
    """Install fakes; return a dict recording drop/export calls."""
    calls = {"dropped": [], "exported": []}

    async def fake_list(_engine):
        # Two partitions, both far older than any retention window.
        return [(2000, 1), (2000, 2)]

    async def fake_export(_engine, y, m, _cfg):
        calls["exported"].append((y, m))
        return f"file:///archive/{y}-{m}.jsonl"

    async def fake_drop(_engine, y, m):
        calls["dropped"].append((y, m))
        return True

    monkey["list_partitions"] = aa.list_partitions
    monkey["export_partition"] = aa.export_partition
    monkey["drop_partition"] = aa.drop_partition
    aa.list_partitions = fake_list
    aa.export_partition = fake_export
    aa.drop_partition = fake_drop
    return calls


def _restore(monkey):
    aa.list_partitions = monkey["list_partitions"]
    aa.export_partition = monkey["export_partition"]
    aa.drop_partition = monkey["drop_partition"]


def test_backend_none_retains_and_never_drops():
    saved = {}
    calls = _patch(saved)
    try:
        res = _run(aa.rotate(_DummyEngine(), ArchiveConfig(backend="none"), retention_months=12))
    finally:
        _restore(saved)
    assert res["retained"] == 2, res
    assert res["dropped"] == 0, res
    assert calls["dropped"] == [], "backend=none must not drop any partition"
    assert calls["exported"] == [], "backend=none must not attempt export"


def test_real_backend_exports_then_drops():
    saved = {}
    calls = _patch(saved)
    try:
        res = _run(aa.rotate(_DummyEngine(), ArchiveConfig(backend="local_dir"), retention_months=12))
    finally:
        _restore(saved)
    assert res["exported"] == 2, res
    assert res["dropped"] == 2, res
    assert res["retained"] == 0, res
    assert calls["dropped"] == [(2000, 1), (2000, 2)]


def test_failed_export_halts_drop():
    saved = {}
    calls = _patch(saved)

    async def failing_export(_engine, y, m, _cfg):
        return None  # export failed

    aa.export_partition = failing_export
    try:
        res = _run(aa.rotate(_DummyEngine(), ArchiveConfig(backend="s3"), retention_months=12))
    finally:
        _restore(saved)
    assert res["errors"] == 2, res
    assert res["dropped"] == 0, res
    assert calls["dropped"] == [], "a failed export must never drop the partition"


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
