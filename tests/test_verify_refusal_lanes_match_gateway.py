# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The `legacy lanes` verify row reads the gateway's refusal counters by
their label value; a renamed lane on either side would read as a silent 0."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GW = (REPO / "gateway-rust/src/controller_hmac_refusal.rs").read_text()
VERIFY = (REPO / "noo-cli/src/commands/cluster_verify.rs").read_text()


def const(src: str, name: str) -> str:
    m = re.search(rf'const {name}: &str = "([^"]+)";', src)
    assert m, name
    return m.group(1)


def test_the_refusal_lane_names_are_the_gateways():
    assert const(VERIFY, "GATEWAY_REFUSED_CONTROLLER_LANE") == const(GW, "LANE_CONTROLLER_HMAC_REFUSED")
    assert const(VERIFY, "GATEWAY_REFUSED_FLEET_OFF_NODE_LANE") == const(GW, "LANE_FLEET_OFF_NODE_REFUSED")
