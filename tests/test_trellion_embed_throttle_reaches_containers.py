# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""trellion's embed throttle can be set from config: both trellion processes
receive TRELLION_EMBED_MAX_INFLIGHT and TRELLION_EMBED_BATCH_MAX.

The throttle (trellion/live/embed_throttle.py) defaults to ONE request in
flight per process. With three embed targets live and batches taking 10-60 s,
that left most of the embedders idle and the backlog drained at ~30 chunks a
minute (2026-10-09). Nothing passed the variables into the containers, so the
documented knob could not be turned. Read over the composed projection
(base + every add-on overlay), where trellion-intel's `extends` is resolved.
"""

from __future__ import annotations

import pytest

from tests._compose_projection import env_of, full_projection

KNOBS = ("TRELLION_EMBED_MAX_INFLIGHT", "TRELLION_EMBED_BATCH_MAX")


@pytest.fixture(scope="module")
def services() -> dict:
    return full_projection()["services"]


@pytest.mark.parametrize("service", ["trellion", "trellion-intel"])
@pytest.mark.parametrize("knob", KNOBS)
def test_each_trellion_process_receives_the_throttle_knob(services, service, knob):
    env = env_of(services[service])
    assert knob in env, f"{service} does not receive {knob}"
    # Same-named host variable, empty default: unset means trellion's own default.
    assert env[knob] == "${" + knob + ":-}", f"{service} {knob}={env[knob]!r}"
