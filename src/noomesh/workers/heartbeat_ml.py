# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""ML heartbeat run handler (``worker.api.heartbeat.run_ml``).

The Rust heartbeat_loop routes the ML actions
(``heartbeat_actions::TRELLION_ACTIONS``: graph_signals,
thought_experiment, graph_prune, knowledge_refresh, graph_clustering)
to this subject so they land on the trellion container — the core
dispatch shell (``workers.heartbeat``) has no ML tree and would answer
them with a success-shaped "not available" no-op.

This module lives in ``_ML_MODULES`` so only ``surfaces=ml`` / ``all``
registers it. The import of the core handler happens INSIDE the handler
body on purpose: a module-level ``from .heartbeat import …`` would run
that module's ``@worker_handler("worker.api.heartbeat.run")`` decorator
as a side effect, making trellion a second subscriber of the core
subject — and worker_pool subscriptions carry no NATS queue group, so
two subscribers means every core delegate would execute twice.
"""
from __future__ import annotations

from typing import Any

from .registry import worker_handler


@worker_handler("worker.api.heartbeat.run_ml")
async def _heartbeat_run_ml(request: dict) -> Any:
    from .heartbeat import _heartbeat_run_task

    return await _heartbeat_run_task(request)
