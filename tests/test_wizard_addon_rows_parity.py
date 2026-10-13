# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The wizard's add-on rows and the gateway's add-on table must agree on
which add-ons are licensed and by which feature: a row the wizard offers
freely but the gateway gates (or vice versa) is a wrong-tier promise."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _table(path: str, anchor: str) -> str:
    """The text between `anchor` and the end of the array literal.

    A missing anchor means the table moved or was renamed — say so, rather
    than raising IndexError from a split that found nothing.
    """
    text = (REPO / path).read_text()
    _, sep, rest = text.partition(anchor)
    assert sep, f"{path}: {anchor!r} not found — did the table move?"
    return rest.split("];", 1)[0]


def _gateway_licensed() -> dict[str, str | None]:
    table = _table("gateway-rust/src/addons.rs", "pub const ADDONS")
    out: dict[str, str | None] = {}
    for m in re.finditer(r'name:\s*"([a-z_]+)".*?requires_feature:\s*(None|Some\("([a-z_]+)"\))', table, re.S):
        out[m.group(1)] = m.group(3)
    return out


def _wizard_licensed() -> dict[str, str | None]:
    table = _table("noo-cli/src/commands/addons.rs", "const ADDON_ROWS")
    out: dict[str, str | None] = {}
    for m in re.finditer(r'key:\s*"([a-z_]+)".*?licensed:\s*(None|Some\("([a-z_]+)"\))', table, re.S):
        out[m.group(1)] = m.group(3)
    return out


def test_wizard_rows_match_gateway_addon_table():
    gw = _gateway_licensed()
    wz = _wizard_licensed()
    assert gw, "gateway ADDONS table not parsed"
    assert wz, "wizard ADDON_ROWS table not parsed"
    for name, feature in gw.items():
        assert name in wz, f"gateway add-on {name!r} has no wizard row"
        assert wz[name] == feature, f"{name}: wizard says licensed={wz[name]!r}, gateway says {feature!r}"
