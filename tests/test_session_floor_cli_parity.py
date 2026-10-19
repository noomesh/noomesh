# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CLI's admin-password reset and the gateway write the same floor row.

`noo security admin-password reset` writes the session floor straight into
Postgres (it must work with the gateway down), so its INSERT and the
gateway's (`session_floor.rs` UPSERT_SQL) must name the same table and
columns. This lives here rather than as an include_str in the gateway,
because the gateway image's build context does not carry noo-cli sources.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSERT = re.compile(r"INSERT INTO noo_session_floors \(([^)]*)\)")


def _columns(path: str) -> list[list[str]]:
    text = (ROOT / path).read_text()
    found = [[c.strip() for c in m.group(1).split(",")] for m in INSERT.finditer(text)]
    assert found, f"{path} writes no noo_session_floors row"
    return found


def test_cli_reset_and_gateway_write_the_same_columns() -> None:
    gateway = _columns("gateway-rust/src/session_floor.rs")
    cli = _columns("noo-cli/src/host_access.rs")
    assert all(cols == gateway[0] for cols in gateway + cli), (gateway, cli)
