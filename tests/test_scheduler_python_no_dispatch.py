# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Phase 7 — Python does not dispatch, and cannot be made to.

The scheduler port (phase 7) deleted the Python dispatch loop.
The invariant it leaves behind is the same one phases 1-6 protected with a
flag ("exactly one engine may publish `tasks.dispatch.*`"), now enforced by
there being exactly one implementation.

Two dispatchers is not an error condition — it is the same job running
twice on two nodes — and a reintroduction would look entirely innocent in
review ("the scheduler should place its own jobs"). So these tests assert
the *absence* of the dispatch surface, not just the presence of the
producer loop.

The Rust half lives in `gateway-rust/src/scheduler_engine.rs` (claim /
terminal atomicity, slot policy) and `scheduler_completions.rs` (durable
naming).
"""
from __future__ import annotations

import inspect

import pytest

from noomesh.cluster import scheduler as sched_mod
from noomesh.cluster.scheduler import JobScheduler


# ── The dispatch surface is gone ───────────────────────────────

@pytest.mark.parametrize("name", [
    "_dispatch_next",
    "_try_dispatch_job",
    "_requeue_job",
    "_reap_timeouts",
    "_janitor",
    "_record_history",
    "_record_history_for",
    "listen_completions",
    "_check_completion_listener",
    "recover_from_restart",
    "_max_slots",
    "_current_slots",
    "_has_slots",
])
def test_dispatch_methods_are_not_reintroduced(name):
    """Each of these moved to gateway-rust. A Python copy would be a second
    writer of the same Redis keys and, for the dispatch pair, a second
    publisher of `tasks.dispatch.<node>`."""
    assert not hasattr(JobScheduler, name), (
        f"JobScheduler.{name} is back. "
        f"gateway-rust/src/scheduler_engine.rs owns this."
    )


@pytest.mark.parametrize("name", ["DEFAULT_SLOTS", "normalize_tier"])
def test_slot_policy_is_not_duplicated(name):
    """The per-tier slot policy lives only in
    `gateway-rust/src/scheduler_slots.rs` now. It was duplicated during the
    port on purpose; a second copy that can drift is a placement bug that
    shows up as jobs landing on a companion or a monitor node."""
    assert not hasattr(sched_mod, name)


@pytest.mark.parametrize("name", ["scheduler_engine", "rust_owns_dispatch"])
def test_engine_flag_helpers_are_gone(name):
    """`NOO_SCHEDULER_ENGINE` selected between two dispatchers. With one
    left, the only thing the flag could still do is strand the queue."""
    assert not hasattr(sched_mod, name)


def test_module_does_not_read_the_engine_flag():
    src = inspect.getsource(sched_mod)
    # The name may appear in a comment explaining the removal; what must not
    # exist is a read of it.
    assert 'getenv("NOO_SCHEDULER_ENGINE"' not in src
    assert 'environ["NOO_SCHEDULER_ENGINE"' not in src


def test_module_does_not_publish_dispatch_subjects():
    """Nothing left in this module may reach `tasks.dispatch.<node>`."""
    assert "tasks.dispatch" not in inspect.getsource(sched_mod)


# ── No loop at all ─────────────────────────────────────────────


@pytest.mark.parametrize("name", [
    "run",
    "stop",
    "register_background_provider",
    "_maybe_enqueue_background_tasks_async",
])
def test_producer_loop_is_not_reintroduced(name):
    """The background-producer loop was deleted in the 2026-08-09 sweep:
    `setup_background_providers` had no production caller, so the loop
    polled an empty registry forever. The real producers of
    background_embed / background_graph jobs are the Rust autonomy
    evaluators. A reintroduced Python loop would be a second producer
    racing them."""
    assert not hasattr(JobScheduler, name), (
        f"JobScheduler.{name} is back — the producer loop was removed "
        f"2026-08-09; background jobs are submitted by "
        f"gateway-rust/src/autonomy_evaluators.rs."
    )
