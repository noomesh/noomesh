# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every exchange door is in the OpenAPI spec, and its constant matches.

An exchange door trades a long-lived service key for a short-lived token
(`auth::exchange_scope_for`). Each is declared twice on purpose: a constant,
which the middleware matches to decide which scope opens it, and a literal in
`.route(...)`, which is what the OpenAPI generator and the drift checker can
actually see.

Two homes for one path, so they are pinned here. Registering the route with
the constant instead of the literal produces a working door that no generated
artefact knows about: `gen-openapi.py` says "nothing to add" and
`check-openapi-drift.py` says "no new drift", both truthfully, because neither
can see it. That happened while adding the add-on door on 2026-09-20 — the
spec is the contract noo-mesh-ui builds against, so a missing entry surfaces
there as what looks like a gateway bug.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTH_RS = ROOT / "gateway-rust" / "src" / "auth.rs"
SPEC = ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json"


@pytest.fixture(scope="module")
def door_paths() -> dict[str, str]:
    src = AUTH_RS.read_text()
    doors = dict(re.findall(r'pub const (\w*TOKEN_PATH):\s*&str\s*=\s*"([^"]+)"', src))
    # Two since 2026-09-30 (identity, add-on): the kiosk KEY lane's door,
    # KIOSK_TOKEN_PATH, was retired, not missed.
    assert len(doors) >= 2, f"parsed {len(doors)} door constants from auth.rs — the regex missed some"
    assert "IDENTITY_TOKEN_PATH" in doors and "ADDON_TOKEN_PATH" in doors, doors
    return doors


def test_every_exchange_door_constant_is_reachable_in_the_spec(door_paths: dict[str, str]) -> None:
    spec = json.loads(SPEC.read_text())
    paths = spec.get("paths") or {}
    assert paths, "the spec parsed to zero paths — the assertion below would be vacuous"
    missing = {name: p for name, p in door_paths.items() if p not in paths}
    assert not missing, (
        "these exchange doors are not in the OpenAPI spec:\n"
        + "\n".join(f"  {n} = {p}" for n, p in missing.items())
        + "\n\nThe generator reads route LITERALS. A `.route(auth::SOME_TOKEN_PATH, ...)` is "
        "invisible to it, so `gen-openapi.py` reports nothing to add and the drift checker "
        "reports no drift — both truthfully. Register with the literal and re-run "
        "scripts/gen-openapi.py."
    )


def test_each_door_is_registered_with_its_literal_not_its_constant(
    door_paths: dict[str, str],
) -> None:
    """The constant and the literal must name the same path. If they drift,
    the middleware opens one path and the router serves another — the door
    then accepts no credential at all, or worse, accepts any."""
    routes = ""
    for f in (ROOT / "gateway-rust" / "src" / "routes").rglob("*.rs"):
        routes += f.read_text(encoding="utf-8")
    for name, path in door_paths.items():
        assert f'"{path}"' in routes, (
            f"{name} = {path} is never registered as a literal in any router; the middleware "
            f"would treat {path} as an exchange door that nothing serves"
        )
