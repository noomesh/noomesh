# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One declaration of the job-type table, three languages that must agree.

The authoritative table — every job type and *who executes it* — lives in
`gateway-rust/src/job_types.rs`. Two other sources restate the node-side
half of it and cannot see the Rust crate at build time:

  * `node-agent-go/internal/jobs/types.go` — what a node-agent will run,
  * `src/noomesh/cluster/scheduler.py::JobType` — the Python enum.

Nothing forced those three to agree, and they didn't: `test_run` is a
gateway-local type (the gateway runs pytest in-process and writes the job
hash with `node_id="gateway"`), but the submit route dispatched it to a
node whose executor has no case for it, so it sat `dispatched` until the
reaper. This module is the guard that keeps them in sync, since no
compiler spans all three.

It parses the sources textually on purpose: importing the Rust/Go
declarations is not possible, and a parse is enough to catch the drift
that matters (a type added to one list and not the others).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUST_TABLE = REPO / "gateway-rust" / "src" / "job_types.rs"
GO_TABLE = REPO / "node-agent-go" / "internal" / "jobs" / "types.go"
GO_EXECUTOR = REPO / "node-agent-go" / "internal" / "jobs" / "executor.go"


def _rust_table() -> dict[str, str]:
    """{job_type: "Node" | "Gateway" | "Pull"} parsed from JOB_TYPES."""
    src = RUST_TABLE.read_text()
    body = src.split("pub const JOB_TYPES", 1)[1].split("];", 1)[0]
    pairs = re.findall(r'\("([a-z_]+)",\s*Executor::(Node|Gateway|Pull)\)', body)
    assert pairs, "could not parse JOB_TYPES out of job_types.rs"
    return dict(pairs)


def _go_executable() -> set[str]:
    src = GO_TABLE.read_text()
    body = src.split("var Executable = map[string]bool{", 1)[1].split("}", 1)[0]
    return set(re.findall(r'"([a-z_]+)":\s*true', body))


def _go_switch_cases() -> set[str]:
    """Job types with a real `case` in Executor.runJob."""
    src = GO_EXECUTOR.read_text()
    body = src.split("switch job.Type {", 1)[1].split("\n\tdefault:", 1)[0]
    return set(re.findall(r'case "([a-z_]+)":', body))


@pytest.fixture(scope="module")
def rust() -> dict[str, str]:
    return _rust_table()


def test_rust_table_declares_test_run_as_gateway_local(rust):
    assert rust["test_run"] == "Gateway"


def test_pull_types_are_never_node_executable(rust):
    # `embed_batch` (i179) is claimed from a JetStream work queue by the
    # node-agent's pull worker, or run by the gateway. It has no case in the
    # Go `switch job.Type` and must not gain one: a dispatched copy would
    # race the queue. The Rust table is the only place it is declared.
    pull_types = {t for t, ex in rust.items() if ex == "Pull"}
    assert pull_types == {"embed_batch"}
    assert not (pull_types & _go_executable())
    assert not (pull_types & _go_switch_cases())


def test_rust_node_types_match_go_executable_map(rust):
    node_types = {t for t, ex in rust.items() if ex == "Node"}
    assert node_types == _go_executable()


def test_go_executable_map_matches_its_own_switch():
    # The map is what handleDispatch gates on; the switch is what actually
    # runs. A type in one and not the other is either a silent
    # "unknown job type" failure or an unreachable executor.
    assert _go_executable() == _go_switch_cases()


def test_gateway_local_types_are_never_node_executable(rust):
    gateway_types = {t for t, ex in rust.items() if ex == "Gateway"}
    assert gateway_types, "expected at least test_run"
    assert not (gateway_types & _go_executable())


def test_python_jobtype_enum_matches_the_node_types(rust):
    from noomesh.cluster.scheduler import JobType

    node_types = {t for t, ex in rust.items() if ex == "Node"}
    assert {t.value for t in JobType} == node_types


# ── The Python submit gate ─────────────────────────────────────


class _StubRedis:
    """Just enough Redis to notice whether the queue was written."""

    def __init__(self):
        self.writes = []

    def pipeline(self):
        return self

    def hset(self, *a, **kw):
        self.writes.append("hset")

    def zadd(self, *a, **kw):
        self.writes.append("zadd")

    def sadd(self, *a, **kw):
        self.writes.append("sadd")

    def execute(self):
        return []


def _scheduler():
    from noomesh.cluster.scheduler import JobScheduler

    sched = JobScheduler.__new__(JobScheduler)
    sched.redis = _StubRedis()
    return sched


def test_submit_job_rejects_a_type_no_node_can_execute():
    sched = _scheduler()
    with pytest.raises(ValueError) as exc:
        sched.submit_job("smoke", {})
    # The message must name the alternatives — a bare "invalid" sends the
    # caller back to the source to find out what is valid.
    assert "smoke" in str(exc.value)
    assert "inference" in str(exc.value)
    assert sched.redis.writes == [], "rejected job must not touch the queue"


def test_submit_job_rejects_gateway_local_test_run():
    # The actual bug: accepted here, dispatched to a node, abandoned.
    sched = _scheduler()
    with pytest.raises(ValueError):
        sched.submit_job("test_run", {"suite": "smoke"})
    assert sched.redis.writes == []


def test_submit_job_accepts_node_types():
    sched = _scheduler()
    job_id = sched.submit_job("inference", {"prompt": "hi"})
    assert job_id
    assert sched.redis.writes == ["hset", "zadd", "sadd"]
