# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every route a control scope opens is a route the gateway serves.

`CONTROL_SCOPE_ROUTES` in `gateway-rust/src/auth.rs` is the vocabulary an
add-on's key is granted from (`temporal`, `heartbeat`, …). A row naming a
path or method the router does not serve reads as a live permission and
grants nothing — the add-on is provisioned, its call is refused, and the
table says it should not be. The OpenAPI spec is the router's declared
surface (`scripts/check-openapi-drift.py` holds the two together), so the
table is checked against it.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests._scope_vocabulary import control_rows as _rows
from tests._scope_vocabulary import issuable as _issuable

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "src/noomesh/gateway/static/openapi.json"


def _spec_matches(pattern: str, spec_path: str) -> bool:
    a, b = pattern.split("/"), spec_path.split("/")
    return len(a) == len(b) and all(
        x == y or (x == "*" and y.startswith("{") and y.endswith("}")) for x, y in zip(a, b)
    )


def test_every_control_scope_route_is_served() -> None:
    paths = json.loads(SPEC.read_text())["paths"]
    for scope, method, pattern in _rows():
        served = [p for p in paths if _spec_matches(pattern, p) and method.lower() in paths[p]]
        assert served, f"{scope} opens {method} {pattern}, which the gateway does not serve"


def test_config_sections_are_served_by_one_templated_route() -> None:
    # `config:<section>` is not a table row; it opens PUT /api/config/<section>.
    assert "put" in json.loads(SPEC.read_text())["paths"].get("/api/config/{section}", {})


def test_every_declared_addon_scope_is_one_the_gateway_issues() -> None:
    # A declared scope the issuer refuses is a `provision` that fails on its
    # first live run — the shape PR 343 shipped for `addon` itself. The
    # declarations live in each overlay's `x-noo-addon` the earlier change
    # phase B (they were ADDON_DEFAULT_SCOPES in secrets.rs).
    from tests._addon_decls import decls
    for d in decls():
        for scope in d.scopes:
            assert _issuable(scope), (
                f"{d.overlay} asks for {scope!r} for {d.consumer}, which the gateway does not issue"
            )
