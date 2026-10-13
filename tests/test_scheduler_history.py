# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Job history reads + honest status reporting for the Python scheduler.

`noo:jobs:history` has exactly one writer, and it is not here:
`scheduler_engine::terminalize()` in gateway-rust writes it inside the same
atomic step that flips a job terminal. Python only reads the list. These
tests pin that read, and pin `get_status()` to not claim a dispatch role it
no longer has.

Companion to tests/test_scheduler_python_no_dispatch.py, which pins the
absence of the dispatch surface itself.
"""
from __future__ import annotations

from noomesh.cluster.scheduler import (
    HISTORY_KEY,
    JobScheduler,
    JobStatus,
)


class _FakeRedis:
    """Just enough Redis for the history/status paths."""

    def __init__(self, hashes=None):
        self.hashes = hashes or {}
        self.lists: dict[str, list] = {}
        self.sets: dict[str, set] = {}

    # hashes
    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    # lists
    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def ltrim(self, key, start, end):
        self.lists[key] = self.lists.get(key, [])[start:end + 1]

    def llen(self, key):
        return len(self.lists.get(key, []))

    def lrange(self, key, start, end):
        return self.lists.get(key, [])[start:end + 1]

    # sets
    def scard(self, key):
        return len(self.sets.get(key, set()))

    def smembers(self, key):
        return set(self.sets.get(key, set()))

    def sismember(self, key, member):
        return member in self.sets.get(key, set())

    def zrangebyscore(self, *_a, **_k):
        return []

    def zcard(self, *_a, **_k):
        return 0

    # pipeline — executes eagerly, order preserved
    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, r):
        self._r = r
        self._ops = []

    def lpush(self, *a):
        self._ops.append(("lpush", a))
        return self

    def ltrim(self, *a):
        self._ops.append(("ltrim", a))
        return self

    def execute(self):
        for name, args in self._ops:
            getattr(self._r, name)(*args)
        self._ops = []


def _scheduler(redis) -> JobScheduler:
    sched = JobScheduler.__new__(JobScheduler)
    sched.redis = redis
    sched._paused = False
    sched._messaging = None
    return sched


def _job(job_id="j1", status=JobStatus.COMPLETED.value):
    return {
        "id": job_id,
        "type": "inference",
        "status": status,
        "node_id": "n1",
        "created_at": "2026-08-01T00:00:00+00:00",
        "completed_at": "2026-08-01T00:01:00+00:00",
        "error": "",
        "retries": "0",
    }


# ── the reader ─────────────────────────────────────────────────────


def test_get_job_history_reads_what_rust_wrote():
    """The Rust terminal script LPUSHes a compact summary; Python decodes
    it as-is. A shape change on either side is a silently empty
    `noo jobs history`."""
    import json

    r = _FakeRedis()
    r.lists[HISTORY_KEY] = [json.dumps(_job()), json.dumps(_job("j0"))]
    sched = _scheduler(r)

    hist = sched.get_job_history()
    assert [h["id"] for h in hist] == ["j1", "j0"]
    assert hist[0]["status"] == JobStatus.COMPLETED.value


def test_get_job_history_respects_the_limit():
    import json

    r = _FakeRedis()
    r.lists[HISTORY_KEY] = [json.dumps(_job(f"j{i}")) for i in range(5)]
    assert len(_scheduler(r).get_job_history(limit=2)) == 2


# ── get_status honesty ─────────────────────────────────────────────


def test_status_never_claims_this_process_dispatches():
    """`running` means "THIS process dispatches", and after phase 7 it never
    does. The gateway's own /api/scheduler/status answers the real question
    from loop_health; this one must not guess on its behalf."""
    sched = _scheduler(_FakeRedis())

    status = sched.get_status()
    assert status["engine"] == "rust"
    assert status["running"] is False
    assert "rust" in status["running_detail"].lower()


def test_status_loop_alive_is_always_false():
    """The producer poll — the last loop in this process — was deleted in
    the 2026-08-09 sweep. The key survives for status consumers, pinned
    to False; real loop health is the Rust /api/scheduler/status."""
    sched = _scheduler(_FakeRedis())
    assert sched.get_status()["loop_alive"] is False


def test_delegated_completions_are_not_reported_as_unhealthy():
    """`completions_healthy=False` used to mean both "listener broken" and
    "handed to Rust". Only the second is true now, and `None` says
    "not mine" rather than publishing a health verdict on a listener this
    process deliberately never starts."""
    status = _scheduler(_FakeRedis()).get_status()
    assert status["completions_owner"] == "rust"
    assert status["completions_healthy"] is None


def test_status_drops_the_janitor_fields():
    """The janitor is a Rust loop; its stats are not observable from here.
    Reporting a frozen `{}` would read as "janitor ran and found nothing"."""
    status = _scheduler(_FakeRedis()).get_status()
    assert "janitor_stats" not in status
    assert "last_janitor_run" not in status
