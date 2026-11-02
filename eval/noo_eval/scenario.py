# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scenario definitions — the declarative workload spec loaded from YAML."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Persona(BaseModel):
    """A synthetic user."""
    id: str
    location: str = "unknown"
    weight: float = 1.0              # share of traffic
    secret: Optional[str] = None     # planted fact, used by isolation probes


class Workload(BaseModel):
    """A traffic class to drive."""
    endpoint: str                    # /v1/chat/completions | /api/external/embeddings | ...
    model: str = ""
    weight: float = 1.0
    prompt: str = "Summarize the theory of relativity in one sentence."
    payload: dict = Field(default_factory=dict)   # extra body fields (overrides defaults)


class FaultSpec(BaseModel):
    at_s: float
    kind: str                        # node_kill | controller_kill | backend_stall
    target: str


class IdentitySpec(BaseModel):
    """Windows under one account, and a foreign party.

    No credentials here: the ``identity``-scoped service key comes from the
    environment variable named by ``key_env``. ``owner`` is the account that
    key is bound to (its windows are minted as connection subjects); ``foreign``
    is an account the key may mint but does not own, or null to skip."""
    owner: str
    windows: list[str] = Field(default_factory=lambda: ["eval-a", "eval-b", "eval-c"])
    foreign: Optional[str] = None
    key_env: str = "NOO_EVAL_IDENTITY_KEY"


CHECK_KINDS = ("contains", "regex", "nonempty", "state")


def parse_check(check: str) -> tuple[str, str]:
    """Split a task check into ``(kind, argument)``, or raise ``ValueError``.

    ``contains:<text>`` (case-insensitive substring of the result),
    ``regex:<re>`` (``re.search`` over the result), ``nonempty`` (the result
    has non-blank text) and ``state:<state>`` (the task's final state, e.g.
    ``state:done``). A new kind is one more arm here and in
    :func:`noo_eval.harness_compare.evaluate_check`.
    """
    kind, sep, arg = check.partition(":")
    kind = kind.strip()
    if kind not in CHECK_KINDS:
        raise ValueError(f"unknown check {check!r}: expected one of "
                         "contains:<text>, regex:<re>, nonempty, state:<state>")
    if kind == "nonempty":
        if sep and arg.strip():
            raise ValueError("nonempty takes no argument")
        return kind, ""
    if not arg:
        raise ValueError(f"check {kind} needs an argument: {kind}:<...>")
    if kind == "regex":
        try:
            re.compile(arg)      # a bad pattern fails at load, not mid-run
        except re.error as e:
            raise ValueError(f"check {check!r}: bad regex: {e}") from None
    return kind, arg


class CompareTask(BaseModel):
    """One task in a harness-compare task set."""
    name: str
    objective: str
    loop_budget: Optional[int] = None
    model: Optional[str] = None
    check: str = "state:done"
    timeout_s: Optional[float] = None          # falls back to the spec's default
    kinds: Optional[list[str]] = None          # run only under these kinds (None = all)

    @field_validator("check")
    @classmethod
    def _check_parses(cls, v: str) -> str:
        parse_check(v)
        return v


class TaskSet(BaseModel):
    name: str = "default"
    tasks: list[CompareTask]


class HarnessCompareSpec(BaseModel):
    """Run one task set under each harness KIND on one node, in turn.

    The only writes are the node's ``harness`` placement (its
    ``NOO_HARNESS_KIND``) and the tasks themselves; the original placement is
    put back at the end, and on error. Credentials come from the run's
    ``--token`` / ``NOO_EVAL_TOKEN`` (an operator: placements are an
    operator write); ``task_token_env`` optionally names an env var holding
    a USER token to create the tasks and read usage as.
    """
    node: str
    kinds: list[str]
    task_sets: list[TaskSet] = Field(default_factory=list)
    tasks: list[CompareTask] = Field(default_factory=list)   # shorthand: one set
    task_timeout_s: float = 600.0
    poll_s: float = 5.0
    settle_s: float = 20.0           # minimum wait after a kind change
    ready_timeout_s: float = 300.0   # give up on a kind whose harness never runs
    usage_settle_s: float = 3.0      # usage rows are written fire-and-forget
    require_dispatch: bool = True    # a task the controller ran in process fails
    sweep_leftovers: bool = True     # stop live tasks of an earlier run with these objectives first
    task_token_env: Optional[str] = None

    @model_validator(mode="after")
    def _one_task_set(self) -> "HarnessCompareSpec":
        if self.tasks:
            self.task_sets = [TaskSet(name="default", tasks=self.tasks), *self.task_sets]
            self.tasks = []
        if not self.task_sets or not any(ts.tasks for ts in self.task_sets):
            raise ValueError("harness_compare needs at least one task")
        if not self.kinds:
            raise ValueError("harness_compare needs at least one kind")
        return self


class ModelVariant(BaseModel):
    """Run a cell's tasks with ``backend`` serving ``model`` (placed for the
    run, the original placement restored after). The model must already be
    on the node (its ``available_models``): a benchmark never downloads."""
    backend: str
    model: str


class MatrixCell(BaseModel):
    """One node of a harness matrix. No ``variants`` = as the node is placed
    now. ``skip`` records the cell as skipped with that reason, never run
    (a node known to be unable to serve, e.g. a broken backend)."""
    node: str
    variants: list[ModelVariant] = Field(default_factory=list)
    skip: Optional[str] = None


class HarnessMatrixSpec(BaseModel):
    """harness × node × model: the harness-compare task sets on every cell.

    Each (node, variant) runs exactly as :class:`HarnessCompareSpec` does on
    one node, and adds what that node IS (hardware, backend, model) to every
    row, so the report can slice by any of them. Writes, all restored: each
    node's harness placement, and for a variant its backend placement.
    ``busy_locks`` are files whose ``flock`` must be FREE to start (e.g. a
    Rust build lock on a measured box: a build skews every number).
    """
    cells: list[MatrixCell]
    kinds: list[str]
    task_sets: list[TaskSet] = Field(default_factory=list)
    tasks: list[CompareTask] = Field(default_factory=list)
    task_timeout_s: float = 600.0
    poll_s: float = 5.0
    settle_s: float = 20.0
    ready_timeout_s: float = 300.0
    usage_settle_s: float = 3.0
    require_dispatch: bool = True
    sweep_leftovers: bool = True
    task_token_env: Optional[str] = None
    model_ready_timeout_s: float = 600.0   # a variant whose model never serves is recorded, not waited on
    busy_locks: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _shape(self) -> "HarnessMatrixSpec":
        if self.tasks:
            self.task_sets = [TaskSet(name="default", tasks=self.tasks), *self.task_sets]
            self.tasks = []
        if not self.cells:
            raise ValueError("harness_matrix needs at least one cell")
        if not self.kinds:
            raise ValueError("harness_matrix needs at least one kind")
        if not any(ts.tasks for ts in self.task_sets):
            raise ValueError("harness_matrix needs at least one task")
        return self

    def has_variants(self) -> bool:
        return any(c.variants for c in self.cells if not c.skip)

    def compare_spec(self, node: str) -> HarnessCompareSpec:
        """The one-node compare this matrix runs on ``node``."""
        return HarnessCompareSpec(
            node=node, kinds=list(self.kinds), task_sets=list(self.task_sets),
            task_timeout_s=self.task_timeout_s, poll_s=self.poll_s, settle_s=self.settle_s,
            ready_timeout_s=self.ready_timeout_s, usage_settle_s=self.usage_settle_s,
            require_dispatch=self.require_dispatch, sweep_leftovers=self.sweep_leftovers,
            task_token_env=self.task_token_env,
        )


class Scenario(BaseModel):
    name: str
    description: str = ""
    axes: list[str] = Field(default_factory=list)   # node|user|location|controller
    duration_s: float = 60.0
    concurrency: int = 8
    rps: float = 0.0                 # 0 == as fast as concurrency allows
    personas: list[Persona] = Field(default_factory=lambda: [Persona(id="u1")])
    workloads: list[Workload] = Field(default_factory=list)
    faults: list[FaultSpec] = Field(default_factory=list)
    isolation_probes: bool = False   # run cross-user leak tests after the load phase
    identity: Optional[IdentitySpec] = None   # window / foreign-account probes
    harness_compare: Optional[HarnessCompareSpec] = None   # which harness kind is better here
    harness_matrix: Optional[HarnessMatrixSpec] = None     # ... across nodes, backends and models

    @classmethod
    def load(cls, path: str | Path) -> "Scenario":
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)
