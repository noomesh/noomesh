# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for the Heartbeat Scheduler (cron-based task execution)."""
import pytest
from datetime import datetime

from noomesh.gateway.heartbeat import (
    CRONITER_AVAILABLE,
    HeartbeatConfig,
    HeartbeatTask,
    TaskRunRecord,
    HeartbeatScheduler,
)


# -- HeartbeatConfig -----------------------------------------------------------


class TestHeartbeatConfig:
    def test_defaults(self):
        cfg = HeartbeatConfig()
        assert cfg.enabled is False
        assert cfg.check_interval_seconds == 60
        assert cfg.startup_delay_seconds == 30
        assert cfg.tasks == []

    def test_custom_values(self):
        cfg = HeartbeatConfig(
            enabled=True,
            check_interval_seconds=120,
            startup_delay_seconds=10,
        )
        assert cfg.enabled is True
        assert cfg.check_interval_seconds == 120

    def test_interval_validation(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HeartbeatConfig(check_interval_seconds=5)  # below min of 10

        with pytest.raises(ValidationError):
            HeartbeatConfig(check_interval_seconds=7200)  # above max of 3600


# -- HeartbeatTask -------------------------------------------------------------


class TestHeartbeatTask:
    def test_create_task(self):
        task = HeartbeatTask(
            id="t1",
            name="Daily Briefing",
            schedule="0 8 * * *",
            action="daily_briefing",
        )
        assert task.id == "t1"
        assert task.name == "Daily Briefing"
        assert task.schedule == "0 8 * * *"
        assert task.action == "daily_briefing"
        assert task.enabled is True
        assert task.last_run is None
        assert task.next_run is None

    def test_to_dict(self):
        task = HeartbeatTask(
            id="t2",
            name="Health Check",
            schedule="*/15 * * * *",
            action="cluster_health",
            channels=["telegram"],
            recipients=["42"],
        )
        d = task.to_dict()
        assert d["id"] == "t2"
        assert d["name"] == "Health Check"
        assert d["schedule"] == "*/15 * * * *"
        assert d["action"] == "cluster_health"
        assert d["channels"] == ["telegram"]
        assert d["recipients"] == ["42"]
        assert d["enabled"] is True

    def test_task_with_config(self):
        task = HeartbeatTask(
            id="t3",
            name="Custom Prompt",
            schedule="0 9 * * 1",
            action="custom_prompt",
            config={"prompt": "Summarize this week's activity."},
        )
        assert task.config["prompt"] == "Summarize this week's activity."


# -- TaskRunRecord -------------------------------------------------------------


class TestTaskRunRecord:
    def test_create_record(self):
        now = datetime.now()
        record = TaskRunRecord(
            run_id="r1",
            task_id="t1",
            task_name="Test",
            action="custom_prompt",
            started_at=now,
            status="success",
            result_text="Done",
            duration_ms=150,
        )
        assert record.run_id == "r1"
        assert record.task_id == "t1"
        assert record.status == "success"
        assert record.duration_ms == 150
        assert record.started_at == now

    def test_record_to_dict(self):
        now = datetime.now()
        record = TaskRunRecord(
            run_id="r2",
            task_id="t2",
            task_name="Health",
            action="cluster_health",
            started_at=now,
            status="error",
            result_text="Gateway unreachable",
            duration_ms=5000,
        )
        d = record.to_dict()
        assert d["run_id"] == "r2"
        assert d["status"] == "error"
        assert d["result_text"] == "Gateway unreachable"
        assert d["started_at"] == now.isoformat()


# -- HeartbeatScheduler --------------------------------------------------------


class TestHeartbeatScheduler:
    def _make_scheduler(self, **kwargs) -> HeartbeatScheduler:
        config = HeartbeatConfig(enabled=True, **kwargs)
        return HeartbeatScheduler(
            config=config,
            gateway_url="http://localhost:8080",
            store=None,
        )

    def test_create_scheduler(self):
        sched = self._make_scheduler()
        assert sched.config.enabled is True
        # No firing loop in Python: the Rust heartbeat_loop owns cron, and
        # a second loop here was the 2026-06-12 dual-fire bug.
        for gone in ("start", "stop", "_run", "_tick"):
            assert not hasattr(sched, gone), f"HeartbeatScheduler.{gone} is back"
        assert sched.get_status()["running"] is False

    def test_add_task(self):
        sched = self._make_scheduler()
        # Scheduler auto-loads DEFAULT_TASKS; clear so the test measures add only
        sched._tasks.clear()
        task = HeartbeatTask(
            id="t1",
            name="Test Task",
            schedule="0 8 * * *",
            action="cluster_health",
        )
        sched.add_task(task)
        assert len(sched._tasks) == 1
        assert "t1" in sched._tasks

    def test_remove_task(self):
        sched = self._make_scheduler()
        task = HeartbeatTask(
            id="t1",
            name="Test Task",
            schedule="0 8 * * *",
        )
        sched.add_task(task)
        sched.remove_task("t1")
        assert "t1" not in sched._tasks

    def test_remove_nonexistent(self):
        sched = self._make_scheduler()
        sched.remove_task("nonexistent")  # should not raise

    def test_list_tasks(self):
        sched = self._make_scheduler()
        sched._tasks.clear()  # ignore auto-loaded DEFAULT_TASKS
        sched.add_task(HeartbeatTask(id="t1", name="Task 1", schedule="0 8 * * *"))
        sched.add_task(HeartbeatTask(id="t2", name="Task 2", schedule="0 9 * * *"))
        tasks = sched.list_tasks()
        assert len(tasks) == 2

    def test_get_task(self):
        sched = self._make_scheduler()
        sched.add_task(HeartbeatTask(id="t1", name="Task 1", schedule="0 8 * * *"))
        task = sched.get_task("t1")
        assert task is not None
        assert task.name == "Task 1"

    def test_get_nonexistent_task(self):
        sched = self._make_scheduler()
        assert sched.get_task("nope") is None

    def test_get_status(self):
        sched = self._make_scheduler()
        sched._tasks.clear()  # ignore auto-loaded DEFAULT_TASKS
        sched.add_task(HeartbeatTask(id="t1", name="Task 1", schedule="0 8 * * *"))
        status = sched.get_status()
        assert status["enabled"] is True
        assert status["running"] is False
        assert status["task_count"] == 1
        assert "croniter_available" in status

    @pytest.mark.skipif(not CRONITER_AVAILABLE, reason="croniter not installed")
    def test_compute_next_run(self):
        sched = self._make_scheduler()
        task = HeartbeatTask(id="t1", name="Every minute", schedule="* * * * *")
        sched.add_task(task)
        # After adding, next_run should be set if croniter is available
        stored = sched.get_task("t1")
        assert stored is not None
        assert stored.next_run is not None

    def test_history(self):
        sched = self._make_scheduler()
        result = sched.get_history()
        assert result == {"runs": [], "total": 0}


# -- Failure signalling --------------------------------------------------------
#
# _execute_task marks a run "success" on ANY normal return, so an action that
# reports failure by RETURNING a string is recorded as a successful run. That is
# not hypothetical: the 6-hourly database_backup did exactly this and reported
# success on every run for weeks while never writing a backup (PR #247). These
# tests pin the contract: actions signal failure by RAISING.


class _RaisingExecutor:
    """Stand-in executor whose action fails the way a real one should."""

    def __init__(self):
        self._current_artifacts = []

    async def execute(self, task):
        raise RuntimeError("boom")


class _ReturningExecutor:
    """Executor that returns normally — must be recorded as success."""

    def __init__(self):
        self._current_artifacts = []

    async def execute(self, task):
        return "all good"


def _scheduler_with(executor):
    sched = HeartbeatScheduler(config=HeartbeatConfig(), gateway_url="http://x")
    sched._executor = executor
    return sched


class TestFailureSignalling:
    @pytest.mark.asyncio
    async def test_raising_action_is_recorded_as_error(self):
        sched = _scheduler_with(_RaisingExecutor())
        task = HeartbeatTask(id="t1", name="T", schedule="0 * * * *", action="noop")

        await sched._execute_task(task, datetime.now())

        rec = sched._run_history[-1]
        assert rec.status == "error", "a raising action must be recorded as error"
        assert "boom" in (rec.error or "")

    @pytest.mark.asyncio
    async def test_returning_action_is_recorded_as_success(self):
        sched = _scheduler_with(_ReturningExecutor())
        task = HeartbeatTask(id="t2", name="T", schedule="0 * * * *", action="noop")

        await sched._execute_task(task, datetime.now())

        rec = sched._run_history[-1]
        assert rec.status == "success"
        assert rec.result_text == "all good"

    # test_database_backup_raises_when_spool_unavailable was REMOVED here.
    #
    # `database_backup` moved to Rust, so `_database_backup` no longer exists
    # on the Python executor and the test could only ever AttributeError —
    # which is how it left dev red. It is not deleted as dead weight: it
    # pinned the #247 contract (a failed spool write must RAISE, never record
    # status=success), and that contract still matters.
    #
    # The assertion now lives with the implementation, in
    # `heartbeat_actions.rs::database_backup_tests`. Deleting it here without
    # moving it would have dropped coverage of the exact regression that hid
    # a broken backup for 17 days.

    @pytest.mark.asyncio
    async def test_unknown_action_raises(self):
        """A task whose action has no handler is doing nothing — that is a
        failure, not a success.

        This regressed for real during the Rust port: actions ported to Rust
        were still routed to Python, which answered "Unknown action: ..." and
        recorded a SUCCESSFUL run, so the mis-routing stayed invisible.
        """
        from noomesh.gateway import heartbeat as hb

        executor = hb.HeartbeatActionExecutor(gateway_url="http://x")
        task = HeartbeatTask(
            id="bogus", name="B", schedule="0 * * * *",
            action="definitely_not_a_real_action",
        )

        with pytest.raises(RuntimeError, match="Unknown heartbeat action"):
            await executor.execute(task)
