# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Live worker-path surfaces must not report failure as a clean zero.

"The system must not lie" audit. Each test below pins one site where an
error or an unavailable dependency used to be returned as ``success: True``
with zeroed/empty data — which the Rust autonomy self-heal loop and the
dashboard both read as "measured, nothing to do".

The rule these encode:
  * an error / unreachable dependency is NOT ``success: True`` + zeros,
  * a value that cannot be measured is ``None`` with a stated reason, and
  * the response envelope callers already parse stays the same shape.
"""
from __future__ import annotations

import asyncio


from noomesh.workers import autonomy as wautonomy
from noomesh.workers import rag as wrag
from noomesh.workers import recall as wrecall


# ── worker.autonomy.check_rag ──────────────────────────────────────


class TestCheckRagEngineUnavailable:
    """A KB we cannot reach is not a KB with nothing left to embed."""

    async def test_engine_unavailable_is_failure_not_zeros(self, monkeypatch):
        monkeypatch.setattr(wautonomy, "_trellion_engine", lambda: None)
        result = await wautonomy._autonomy_check_rag({})
        assert result["success"] is False
        assert "error" in result
        # The old reply — success:True with unembedded_pages:0 — told the
        # self-heal loop the corpus was fully embedded.
        assert "data" not in result

    async def test_engine_raises_is_failure(self, monkeypatch):
        def _boom():
            raise RuntimeError("connection refused")

        monkeypatch.setattr(wautonomy, "_trellion_engine", _boom)
        result = await wautonomy._autonomy_check_rag({})
        assert result["success"] is False


# ── worker.autonomy.evaluate_custom: tests removed with the 2026-08-08
# reference sweep. The subject was ported in #573 and the Python body is
# archived in git history (before 2026-08-08); the live
# implementation is gateway-rust autonomy_evaluators.rs::eval_custom_location,
# which carries the same non-200→error branch explicitly and pins the
# condition-evaluation semantics (dotted lookup, all-must-hold, empty-never-
# fires, missing-metric-fails) with inline Rust tests. ──


# ── worker.recall.archive_status ───────────────────────────────────


class _Archiver:
    def __init__(self, exc=None, count=0):
        self._exc = exc
        self._count = count

    async def get_unarchived_count(self):
        if self._exc:
            raise self._exc
        return self._count


class _VM:
    _started = True

    def __init__(self, archiver=None):
        self.archiver = archiver


class TestRecallArchiveStatus:
    """An archive backlog that cannot be measured must not read as 0 —
    otherwise the backlog alarm built on this number can never fire."""

    async def test_no_manager_is_failure(self, monkeypatch):
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: None)
        result = await wrecall._recall_archive_status({})
        assert result["success"] is False
        assert "error" in result
        assert "data" not in result

    async def test_no_archiver_is_failure(self, monkeypatch):
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: _VM(archiver=None))
        result = await wrecall._recall_archive_status({})
        assert result["success"] is False

    async def test_query_error_is_failure(self, monkeypatch):
        vm = _VM(archiver=_Archiver(exc=RuntimeError("relation does not exist")))
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: vm)
        result = await wrecall._recall_archive_status({})
        assert result["success"] is False
        assert "relation does not exist" in result["error"]

    async def test_real_zero_is_still_a_success(self, monkeypatch):
        vm = _VM(archiver=_Archiver(count=0))
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: vm)
        result = await wrecall._recall_archive_status({})
        assert result["success"] is True
        assert result["data"]["unarchived_count"] == 0


# ── worker.recall.status ───────────────────────────────────────────


class TestRecallStatusDerivedFields:
    async def test_uncountable_tables_report_none_with_a_reason(self, monkeypatch):
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: None)
        result = await wrecall._recall_status({})
        data = result["data"]
        # Was: 0 frames / 0 traversals — "recall memory is empty".
        assert data["video_count"] is None
        assert data["total_records"] is None
        assert data["traversals"]["count"] is None
        assert data["count_errors"]

    async def test_no_config_means_no_invented_constants(self, monkeypatch):
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: None)
        data = (await wrecall._recall_status({}))["data"]
        # Were hardcoded True / 768 / 0.6 / 10 regardless of configuration.
        assert data["enabled"] is None
        assert data["embedding_dim"] is None
        assert data["promotion_threshold"] is None
        assert data["lifecycle"]["archive_interval_min"] is None
        assert data["traversals"]["buffered"] is None
        # `videos: []` used to sit next to a non-zero video_count.
        assert "videos" not in data

    async def test_config_backed_fields_are_derived(self, monkeypatch):
        class _Cfg:
            enabled = True
            embedding_dim = 1024
            promotion_confidence_threshold = 0.42
            archive_interval_minutes = 7

        class _ConfiguredVM:
            _started = True
            config = _Cfg()

            def status(self):
                return {"started": True, "version": 2, "backend": "postgres+faiss"}

        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: _ConfiguredVM())
        data = (await wrecall._recall_status({}))["data"]
        assert data["enabled"] is True
        assert data["embedding_dim"] == 1024
        assert data["promotion_threshold"] == 0.42
        assert data["lifecycle"]["archive_interval_min"] == 7

    async def test_live_tombstoned_and_by_type_come_from_the_episodes_table(self, monkeypatch):
        import sys
        import types

        rows = [("conversation", False, 5), ("traversal", False, 3), ("conversation", True, 2)]

        class _Result:
            def all(self):
                return rows

            def scalar(self):
                return 3

        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def execute(self, stmt):
                return _Result()

        class _Engine:
            def connect(self):
                return _Conn()

        mod = types.ModuleType("trellion.db.engine")
        mod.get_async_engine = lambda: _Engine()
        monkeypatch.setitem(sys.modules, "trellion.db.engine", mod)
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: None)
        data = (await wrecall._recall_status({}))["data"]
        assert data["total_records"] == 10
        assert data["lifecycle"]["live_records"] == 8
        assert data["lifecycle"]["tombstoned_records"] == 2
        assert data["episodes_by_type"] == {"conversation": 5, "traversal": 3}

    async def test_uncounted_episodes_are_none_not_zero(self, monkeypatch):
        monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: None)
        data = (await wrecall._recall_status({}))["data"]
        assert data["lifecycle"]["live_records"] is None
        assert data["episodes_by_type"] is None


# ── worker.rag.context ─────────────────────────────────────────────


class _Retriever:
    def __init__(self, behaviour):
        self._behaviour = behaviour

    async def retrieve(self, *_a, **_k):
        if self._behaviour == "timeout":
            await asyncio.sleep(60)
        if self._behaviour == "boom":
            raise RuntimeError("embedder 503")
        return []


class _RAG:
    _started = True

    def __init__(self, retriever):
        self.retriever = retriever


def _sole_account(monkeypatch, username="solo"):
    """Pretend the install has exactly one enabled account, so the
    auto-injected KB path resolves a scope instead of failing closed."""
    from noomesh.identity import scope

    scope.reset_scope_cache()

    async def _fake():
        return username, "sole_account"

    monkeypatch.setattr(scope, "_sole_account", _fake)


class TestRagContextErrorsAreVisible:
    """This is the auto-injected RAG path — it runs on every prompt, so a
    broken KB silently degrading every answer must leave a signal."""

    @staticmethod
    def _assert_envelope(result):
        # The Rust coordinator reads data.answer / data.citations; the
        # envelope must not change shape, only gain an `error`.
        assert "answer" in result and "citations" in result

    async def test_rag_not_started_is_flagged(self, monkeypatch):
        monkeypatch.setattr(wrag, "_get_rag", lambda: None)
        result = await wrag._rag_context({"question": "q"})
        self._assert_envelope(result)
        assert result["error"] == "rag_not_started"

    async def test_missing_retriever_is_flagged(self, monkeypatch):
        rag = _RAG(retriever=None)
        rag.orchestrator = type("O", (), {"retriever": None})()
        monkeypatch.setattr(wrag, "_get_rag", lambda: rag)
        _sole_account(monkeypatch)
        result = await wrag._rag_context({"question": "q"})
        self._assert_envelope(result)
        assert result["error"] == "rag_retriever_unavailable"

    async def test_timeout_is_distinguishable_from_empty(self, monkeypatch):
        monkeypatch.setattr(wrag, "_get_rag", lambda: _RAG(_Retriever("timeout")))
        _sole_account(monkeypatch)

        real_wait_for = asyncio.wait_for

        async def _fast_wait_for(aw, timeout=None):
            return await real_wait_for(aw, timeout=0.05)

        monkeypatch.setattr(wrag.asyncio, "wait_for", _fast_wait_for)
        result = await wrag._rag_context({"question": "q"})
        self._assert_envelope(result)
        assert result["error"] == "rag_retrieval_timeout"

    async def test_exception_is_distinguishable_from_empty(self, monkeypatch):
        monkeypatch.setattr(wrag, "_get_rag", lambda: _RAG(_Retriever("boom")))
        _sole_account(monkeypatch)
        result = await wrag._rag_context({"question": "q"})
        self._assert_envelope(result)
        assert result["error"].startswith("rag_retrieval_failed")

    async def test_genuinely_empty_carries_no_error(self, monkeypatch):
        monkeypatch.setattr(wrag, "_get_rag", lambda: _RAG(_Retriever("empty")))
        _sole_account(monkeypatch)
        result = await wrag._rag_context({"question": "q"})
        self._assert_envelope(result)
        assert "error" not in result

# TestNodeStatsOneLivenessDefinition moved to
# git history (before 2026-08-08) with cluster/node.py (fu 58
# round 2): it tested NodeRegistry.get_stats, not the workers.


class TestRecallMemoryEnabledFollowsConfig:
    def test_reads_the_operators_setting(self, monkeypatch):
        from noomesh import config as cfgmod

        class _C:
            class recall_memory:
                enabled = True

        monkeypatch.setattr(cfgmod, "get_config", lambda: _C())
        assert cfgmod.recall_memory_enabled() is True
        _C.recall_memory.enabled = False
        assert cfgmod.recall_memory_enabled() is False

    def test_a_broken_config_reads_as_off(self, monkeypatch):
        from noomesh import config as cfgmod

        def boom():
            raise RuntimeError("bad yaml")

        monkeypatch.setattr(cfgmod, "get_config", boom)
        assert cfgmod.recall_memory_enabled() is False
