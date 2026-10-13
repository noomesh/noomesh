# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The client package's constants are the gateway's (C.7).

`noo_gateway` encodes four facts about the gateway: where the exchange door
is, how long a token lives, which route prefixes take a raw key, and where
the metrics doors are. Each is a constant in `gateway-rust/src/auth.rs`, read
here with a regex the way tests/_scope_vocabulary.py reads the scope table,
so a change on either side fails this test rather than a container.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "gateway-rust/src/auth.rs"
sys.path.insert(0, str(ROOT / "packages" / "noo-gateway-client" / "src"))

import noo_gateway  # noqa: E402
from noo_gateway.auth import REFRESH_MARGIN_SECS  # noqa: E402
from tests._scope_vocabulary import control_rows  # noqa: E402


def _const(name: str) -> str:
    m = re.search(rf'pub const {name}: &str = "([^"]+)";', AUTH.read_text())
    assert m, f"{name} not found in auth.rs — the parse broke"
    return m.group(1)


def test_the_door_path_is_the_gateways() -> None:
    assert noo_gateway.ADDON_TOKEN_PATH == _const("ADDON_TOKEN_PATH")


def test_the_refresh_margin_fits_inside_the_ttl() -> None:
    m = re.search(r"pub const ADDON_TOKEN_TTL_SECS: u64 = (\d+);", AUTH.read_text())
    assert m, "ADDON_TOKEN_TTL_SECS not found — the parse broke"
    ttl = int(m.group(1))
    assert 0 < REFRESH_MARGIN_SECS < ttl / 2, f"margin {REFRESH_MARGIN_SECS} vs ttl {ttl}"


def test_the_inference_surface_prefixes_are_the_gateways() -> None:
    src = AUTH.read_text()
    m = re.search(r"let is_inference_surface = (.+?);", src)
    assert m, "is_inference_surface not found — the parse broke"
    prefixes = set(re.findall(r'starts_with\("([^"]+)"\)', m.group(1)))
    assert len(prefixes) >= 2, m.group(1)
    assert set(noo_gateway.INFERENCE_SURFACE_PREFIXES) == prefixes
    assert noo_gateway.is_inference_surface("/v1/chat/completions")
    assert noo_gateway.is_inference_surface("/api/external/embeddings")
    assert not noo_gateway.is_inference_surface("/api/temporal/adaptations")
    assert not noo_gateway.is_inference_surface("/api/metrics/increment")


def test_the_metrics_doors_are_the_metrics_scopes_rows() -> None:
    rows = {(m, p) for s, m, p in control_rows() if s == "metrics"}
    assert rows == {("POST", noo_gateway.METRICS_INCREMENT_PATH), ("POST", noo_gateway.METRICS_GAUGE_PATH)}
