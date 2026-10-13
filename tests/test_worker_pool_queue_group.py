# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every worker subscribe carries the queue group.

Static scan, same idiom as the bus-contract parity tests: the failure this
guards is silent at runtime. Without a queue group NATS fans a request out
to every subscriber, so a second replica executes every tool call a second
time and nothing errors — two side effects, one racing reply.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noomesh" / "gateway" / "worker_pool.py"


def _subscribe_calls() -> list[str]:
    text = SRC.read_text()
    return re.findall(r"\bnc\.subscribe\(([^)]*)\)", text, re.S)


def test_worker_pool_has_subscribe_calls():
    # Guard the guard: an empty scan would pass vacuously.
    assert _subscribe_calls(), "no nc.subscribe( found in worker_pool.py — did the call site move?"


def test_every_worker_subscribe_is_in_the_queue_group():
    bad = [c for c in _subscribe_calls() if "queue=WORKER_QUEUE_GROUP" not in c]
    assert not bad, f"subscribe without the queue group (a second replica would double-execute): {bad}"


def test_queue_group_name_is_stable():
    text = SRC.read_text()
    assert 'WORKER_QUEUE_GROUP = "workers"' in text, "the group name is a bus contract shared by every replica"
