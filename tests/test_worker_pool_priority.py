# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Priority-tier dispatch for NATS worker subjects.

Priority subjects run in their own asyncio.Task so they never queue behind
long-running background jobs (entity extraction, embeddings, recall memory).
`_PRIORITY_PREFIXES` is module-level precisely so this can be asserted.

These tests exist because the failure is silent and asymmetric: a request
that queues too long doesn't error at the handler, it times out at the
CALLER, so the symptom surfaces on the Rust side ("could not be dispatched
… the task did not run") with nothing wrong in Python's logs.
"""
from __future__ import annotations

from noomesh.gateway.worker_pool import (
    _PER_SUBJECT_LIMITS,
    _PRIORITY_PREFIXES,
    _is_priority_subject,
)


class TestHeartbeatDelegation:
    """Rust owns cron firing but delegates every action not in
    RUST_NATIVE_ACTIONS / RUST_LLM_ACTIONS — so Python is the DEFAULT
    heartbeat path, not an exception.
    """

    def test_heartbeat_run_is_priority(self):
        # The exact subject gateway-rust/src/heartbeat_loop.rs requests.
        assert _is_priority_subject("worker.api.heartbeat.run")

    def test_heartbeat_webhook_is_priority(self):
        assert _is_priority_subject("worker.api.heartbeat.webhook")

    def test_prefix_is_not_over_broad(self):
        """A different worker.api.* family must not become priority just
        because heartbeat did. cluster.* is deliberately still sequential
        (see the TODO next to the commented-out entry).
        """
        assert not _is_priority_subject("worker.api.cluster.discover")


class TestFloodSubjectsStaySequential:
    """The whole point of the priority tier is that it is NOT universal —
    the slow floods must stay bounded, or promoting heartbeat achieves
    nothing.
    """

    def test_slow_ml_subjects_are_not_priority(self):
        for subject in (
            "worker.temporal.extract",
            "worker.embedding.encode",
            "worker.rag.ingest",
            "worker.recall.archive",
        ):
            assert not _is_priority_subject(subject), (
                f"{subject} is a known flood source and must stay bounded"
            )

    def test_flood_subjects_have_concurrency_caps(self):
        """A subject that can starve others should also be capped."""
        for subject in _PER_SUBJECT_LIMITS:
            assert not _is_priority_subject(subject), (
                f"{subject} is both capped and priority — contradictory"
            )


class TestPriorityPrefixHygiene:
    def test_no_empty_or_whitespace_prefix(self):
        """An empty prefix would make EVERY subject priority via
        startswith(''), silently removing all back-pressure.
        """
        for prefix in _PRIORITY_PREFIXES:
            assert prefix.strip(), "empty prefix makes every subject priority"
            assert prefix == prefix.strip()

    def test_all_prefixes_are_worker_scoped(self):
        for prefix in _PRIORITY_PREFIXES:
            assert prefix.startswith("worker."), prefix

    def test_no_duplicate_prefixes(self):
        assert len(_PRIORITY_PREFIXES) == len(set(_PRIORITY_PREFIXES))
