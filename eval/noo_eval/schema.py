# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared data model for the eval harness.

One schema, two producers: the live :mod:`driver`/:mod:`collector` build a
``RunResult`` from real traffic, and :mod:`demo` builds the same shape from
canned numbers. :mod:`report` consumes ``RunResult`` and never cares which.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class NodeInfo(BaseModel):
    """A cluster node as seen at eval time (from /api/cluster/nodes)."""
    node_id: str
    role: str = "worker"            # controller | worker
    location: str = "unknown"       # logical site label (e.g. "us-east", "home-lab")
    online: bool = True
    gpu_model: Optional[str] = None
    vram_gb: float = 0.0
    backends: list[str] = Field(default_factory=list)  # vllm, llamacpp, embedding, rerank
    cached_models: list[str] = Field(default_factory=list)  # models this node has locally
    tier: int = 3


class ReqRecord(BaseModel):
    """One request the driver issued."""
    t_offset_s: float               # seconds since run start
    user: str                       # synthetic persona id
    location: str                   # where the request originated
    endpoint: str                   # /v1/chat/completions, /api/external/embeddings, ...
    model: str = ""
    node: str = ""                  # node that served it (from response header / routing)
    latency_ms: float = 0.0
    ok: bool = True
    status: int = 200


class FaultEvent(BaseModel):
    """An injected fault and how fast the cluster recovered (Availability / A1)."""
    t_offset_s: float
    kind: str                       # node_kill | controller_kill | backend_stall | net_partition
    target: str                     # node_id / controller id
    detected_s: Optional[float] = None   # time-to-detect after injection
    recovered_s: Optional[float] = None  # time-to-recover (MTTR)
    note: str = ""


class IsolationTest(BaseModel):
    """A cross-user memory-isolation probe (the H-D1 control test as an eval)."""
    user_a: str                     # owner of the secret
    user_b: str                     # attacker persona
    probe: str                      # what user_b asked for
    leaked: bool                    # True == user_b saw user_a's data (FAIL)
    detail: str = ""


class ReplEvent(BaseModel):
    """Federated replication sample (multi-controller / future federated push)."""
    t_offset_s: float
    controller: str
    lag_s: float = 0.0              # replication lag to primary
    ok: bool = True


class SecurityPosture(BaseModel):
    """Security counters over the run window (from Prometheus / audit metrics)."""
    auth_failures: int = 0
    exec_denials: int = 0
    rate_limited: int = 0
    audit_rows_written: int = 0


class TaskRun(BaseModel):
    """One task of a harness-compare run, under one harness kind."""
    kind: str
    task_set: str = "default"
    task: str
    task_id: str = ""
    state: str = ""                  # the task's last state (done|failed|stopped|... or timeout)
    loops: int = 0
    wall_s: Optional[float] = None
    result: str = ""                 # the task's result, or its error (truncated)
    node: str = ""                   # where the gateway sent it
    dispatched: bool = False         # a node harness took it (False = ran in process)
    why: str = ""                    # the gateway's reason when it was not dispatched
    children: int = 0                # delegated / fanned-out child tasks
    tools: Optional[int] = None      # tool calls, when the gateway could tell
    prompt_tokens: Optional[int] = None      # None = not reported, never 0-by-default
    completion_tokens: Optional[int] = None
    tokens_source: str = ""          # how the tokens were obtained (see harness_compare)
    check: str = ""
    passed: bool = False
    skipped: bool = False            # the task does not apply to this kind
    note: str = ""                   # why it failed (first line goes in the report)


class KindRun(BaseModel):
    """Placing one kind on the node and waiting for its harness."""
    kind: str
    placed: bool = False
    ready: bool = False
    ready_s: Optional[float] = None
    error: str = ""


class HarnessCompare(BaseModel):
    """A harness-compare run: one task set per kind, on one node."""
    node: str
    kinds: list[str] = Field(default_factory=list)
    original_kind: Optional[str] = None      # None = the node had no harness placement
    restored: bool = False
    restore_note: str = ""
    kind_runs: list[KindRun] = Field(default_factory=list)
    runs: list[TaskRun] = Field(default_factory=list)
    token_method: str = ""


class RunResult(BaseModel):
    """The full artifact of one evaluation run."""
    scenario: str
    axes: list[str] = Field(default_factory=list)      # node|user|location|controller
    started_at: str = ""                               # ISO ts, injected (no wall-clock in-harness)
    duration_s: float = 0.0
    gateway: str = ""
    topology: list[NodeInfo] = Field(default_factory=list)
    requests: list[ReqRecord] = Field(default_factory=list)
    faults: list[FaultEvent] = Field(default_factory=list)
    isolation_tests: list[IsolationTest] = Field(default_factory=list)
    replication: list[ReplEvent] = Field(default_factory=list)
    security: SecurityPosture = Field(default_factory=SecurityPosture)
    harness_compare: Optional[HarnessCompare] = None
    notes: list[str] = Field(default_factory=list)
