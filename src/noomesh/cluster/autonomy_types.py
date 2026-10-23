# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Autonomy location data model — types only, no engine.

These four types are what ``default_locations.py`` is written in, and that
file is preserved as the CANONICAL reference for the Rust autonomy loop
(``gateway-rust/src/autonomy_evaluators.rs`` says so at its top). The engine
that used to share this module — LocationChecker / ActionDispatcher /
AutonomyEngine — was never started in the live stack (the sole instantiation
was a commented-out block in ``gateway/worker_pool.py``; the live loop is
``gateway-rust/src/autonomy_loop.rs``) and was removed in the
cleanup sweep (history in git log before 2026-08-08).

Moved verbatim from ``cluster/autonomy.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LocationType(str, Enum):
    ENDPOINT = "endpoint"
    RAG_STORE = "rag_store"
    CLUSTER = "cluster"
    FILESYSTEM = "filesystem"
    SCHEDULER = "scheduler"
    CUSTOM = "custom"


@dataclass
class Condition:
    metric: str
    operator: str       # gt, lt, eq, ne, gte, lte, contains
    threshold: Any


@dataclass
class Action:
    type: str           # start_backend, submit_job, api_call, log, alert
    config: dict = field(default_factory=dict)


@dataclass
class MonitorLocation:
    name: str
    type: LocationType
    config: dict
    check_interval_seconds: int = 60
    conditions: list[Condition] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    enabled: bool = True
    cooldown_seconds: int = 300
    # "any" = fire when any condition matches (default, historical behaviour).
    # "all" = fire only when every condition matches — useful for backpressure
    # locations that need both a lower bound (work exists) and an upper bound
    # (not overloaded).
    conditions_mode: str = "any"
