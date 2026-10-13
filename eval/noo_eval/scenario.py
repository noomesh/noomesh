# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scenario definitions — the declarative workload spec loaded from YAML."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


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

    @classmethod
    def load(cls, path: str | Path) -> "Scenario":
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)
