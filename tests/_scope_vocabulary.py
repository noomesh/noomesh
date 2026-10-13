# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway's key-scope vocabulary, read from gateway-rust source.

One reader for three guards: which words a service key may be issued with
(`routes/users.rs::validate_key_scopes`), which routes a control scope opens
(`auth::CONTROL_SCOPE_ROUTES`), and which `config:<section>` words the issuer
refuses (`routes/settings.rs::GATED_CONFIG_SECTIONS`). Hoisted out of
tests/test_control_scope_routes_exist.py so the
add-on declaration guard asks the SAME question the route guard does, instead
of a second copy of the parse deciding "issuable" slightly differently.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "gateway-rust/src/auth.rs"
USERS = ROOT / "gateway-rust/src/routes/users.rs"
SETTINGS = ROOT / "gateway-rust/src/routes/settings.rs"

# Words an add-on may not ASK for: `addon` is always added by the CLI
# (`provisioned_scopes`), `kiosk` is retired (the key lane, 2026-09-30), and the operator-only pair
# mint tokens for accounts or open the operator MCP door.
NOT_ASKABLE = frozenset({"addon", "kiosk", "mcp:operator", "identity"})


def scope_consts() -> dict[str, str]:
    return dict(re.findall(r'pub const (\w+_SCOPE): &str = "([^"]+)";', AUTH.read_text()))


def control_rows() -> list[tuple[str, str, str]]:
    """`CONTROL_SCOPE_ROUTES` (writes) then `CONTROL_READ_SCOPE_ROUTES` (reads)
    as (scope word, METHOD, path pattern): one vocabulary, two tables."""
    src = AUTH.read_text()
    consts = scope_consts()
    rows = []
    for table, floor in (("CONTROL_SCOPE_ROUTES", 5), ("CONTROL_READ_SCOPE_ROUTES", 1)):
        m = re.search(rf"pub const {table}: &\[\(&str, &str, &str\)\] = &\[(.*?)\n\];", src, re.S)
        assert m, f"{table} not found in auth.rs — the parse broke"
        found = []
        for const, method, path in re.findall(r'\((\w+), "([A-Z]+)", "([^"]+)"\)', m.group(1)):
            assert const in consts, f"{const} is not a declared scope constant"
            found.append((consts[const], method, path))
        assert len(found) >= floor, f"parsed only {len(found)} {table} rows — the parse broke"
        rows += found
    return rows


def plain_scopes() -> set[str]:
    """`SERVICE_KEY_SCOPES`: the non-control words a key may carry."""
    plain = re.search(r"const SERVICE_KEY_SCOPES: &\[&str\] = &\[(.*?)\];", USERS.read_text(), re.S)
    assert plain, "SERVICE_KEY_SCOPES not found in users.rs — the parse broke"
    consts = scope_consts()
    words = set(re.findall(r'"([^"]+)"', plain.group(1)))
    words |= {consts[c] for c in re.findall(r"crate::auth::(\w+_SCOPE)", plain.group(1))}
    assert {"chat", "embeddings", "addon"} <= words, f"parsed {words!r} — the parse broke"
    return words


def gated_sections() -> list[str]:
    gated = re.search(r"GATED_CONFIG_SECTIONS: &\[&str\] =\s*&\[(.*?)\];", SETTINGS.read_text(), re.S)
    assert gated, "GATED_CONFIG_SECTIONS not found — the parse broke"
    out = re.findall(r'"([^"]+)"', gated.group(1))
    assert out, "GATED_CONFIG_SECTIONS parsed empty — the parse broke"
    return out


def issuable(scope: str) -> bool:
    """Would `POST /api/security/service-keys` accept this word (ignoring the
    operator-only pair, which no add-on may ask for)?"""
    if scope in plain_scopes() or scope in {s for s, _, _ in control_rows()}:
        return True
    section = scope.removeprefix("config:")
    return (
        scope.startswith("config:")
        and bool(re.fullmatch(r"[a-z0-9_]+", section))
        and section not in gated_sections()
    )
