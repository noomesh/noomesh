# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A task name that states a cadence must agree with its cron.

`database_backup` was named "(6-hourly)" while it ran `30 3 * * *`: the schedule
moved to daily and the name stayed. Install rows keep the name they were seeded
with, so the old name is also migrated (exact match only).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from noomesh.gateway.heartbeat import DEFAULT_TASKS, LEGACY_DEFAULT_NAMES, HeartbeatScheduler  # noqa: E402


def _fires_per_day(cron: str) -> int | None:
    """Fires per day (on the days it fires) for a plain `m h dom mon dow` cron.

    A weekday-only task called "Daily ..." still fires once per day it runs, so
    day-of-week is ignored; day-of-month and month restrictions are not daily.
    """
    m, h, dom, mon, _dow = cron.split()
    if (dom, mon) != ("*", "*") or not m.isdigit():
        return None
    if h == "*":
        return 24
    if h.startswith("*/") and h[2:].isdigit():
        return 24 // int(h[2:])
    return len(h.split(","))


def _stated_per_day(name: str) -> int | None:
    low = name.lower()
    if m := re.search(r"(\d+)-hourly", low):
        return 24 // int(m.group(1))
    if "hourly" in low:
        return 24
    if "daily" in low:
        return 1
    return None


def test_cadence_in_a_default_task_name_matches_its_cron() -> None:
    checked = 0
    for t in DEFAULT_TASKS:
        stated = _stated_per_day(t["name"])
        if stated is None:
            continue
        checked += 1
        assert _fires_per_day(t["schedule"]) == stated, (
            f"{t['id']}: name {t['name']!r} disagrees with schedule {t['schedule']!r}"
        )
    assert checked >= 1, "no task name carries a cadence — the check found nothing"


def test_the_cadence_check_catches_the_original_mismatch() -> None:
    assert _stated_per_day("Database Backup (6-hourly)") != _fires_per_day("30 3 * * *")


def test_legacy_names_point_at_names_that_agree_with_the_cron() -> None:
    by_id = {t["id"]: t for t in DEFAULT_TASKS}
    for (tid, old), new in LEGACY_DEFAULT_NAMES.items():
        assert old != new
        assert by_id[tid]["name"] == new
        assert _stated_per_day(new) == _fires_per_day(by_id[tid]["schedule"])


def test_a_stored_legacy_name_is_renamed_and_a_custom_one_is_not() -> None:
    saved: list = []

    class Store:
        def __init__(self, name):
            self.name = name

        def list_tasks(self):
            return [{"id": "database_backup", "name": self.name, "schedule": "30 3 * * *",
                     "action": "database_backup"}]

        def save_task(self, d):
            saved.append(d["name"])

    for stored, expect in (("Database Backup (6-hourly)", "Database Backup (daily, 03:30)"),
                           ("Nightly dump (mine)", "Nightly dump (mine)")):
        saved.clear()
        sched = HeartbeatScheduler.__new__(HeartbeatScheduler)
        sched._tasks = {}
        sched.store = Store(stored)
        sched._load_store_tasks()
        assert sched._tasks["database_backup"].name == expect
        assert saved == ([expect] if stored != expect else [])
