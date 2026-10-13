# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The RSS watchdog must not exit while work is in flight.

2026-08-08: v0.1.13 trellion's steady-state working set crossed the
NOO_WORKER_RSS_LIMIT_MB=7000 ceiling, and the watchdog's unconditional
os._exit(0) put the container in a permanent ~8-minute restart loop —
82 restarts, every structured_research heartbeat task killed mid-flight
("dispatched to the Python worker and never reported an outcome").

These tests pin the pure decision core and the in-flight accounting.
"""

from noomesh.gateway import inflight
from noomesh.gateway.worker_pool import _watchdog_decision


class TestWatchdogDecision:
    def test_under_limit_is_ok(self):
        assert _watchdog_decision(5000, 7000, busy=3, deferred_secs=0) == "ok"

    def test_unreadable_rss_is_ok(self):
        assert _watchdog_decision(None, 7000, busy=0, deferred_secs=0) == "ok"

    def test_over_limit_idle_exits(self):
        assert _watchdog_decision(7100, 7000, busy=0, deferred_secs=0) == "exit"

    def test_over_limit_busy_defers(self):
        assert _watchdog_decision(7100, 7000, busy=1, deferred_secs=0) == "defer"

    def test_hard_factor_overrides_busy(self):
        # 1.25 * 7000 = 8750 — past that, exit even mid-task: the host's
        # memory outranks any single task.
        assert _watchdog_decision(8800, 7000, busy=5, deferred_secs=0) == "exit"

    def test_max_deferral_overrides_busy(self):
        # An ever-busy queue must not ride deferral forever.
        assert _watchdog_decision(7100, 7000, busy=5, deferred_secs=900) == "exit"
        assert _watchdog_decision(7100, 7000, busy=5, deferred_secs=899) == "defer"

    def test_exactly_at_limit_is_ok(self):
        assert _watchdog_decision(7000, 7000, busy=0, deferred_secs=0) == "ok"


class TestInflightCounter:
    def test_tracked_counts_and_releases(self):
        assert inflight.count() == 0
        with inflight.tracked():
            assert inflight.count() == 1
            with inflight.tracked():
                assert inflight.count() == 2
            assert inflight.count() == 1
        assert inflight.count() == 0

    def test_tracked_releases_on_exception(self):
        try:
            with inflight.tracked():
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert inflight.count() == 0
