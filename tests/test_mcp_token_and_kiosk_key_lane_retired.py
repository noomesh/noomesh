# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Two retired credentials stay retired (2026-09-30).

(a) The shared operator MCP token, ``NOO_MCP_TOKEN`` (and its rotation grace
    value ``NOO_MCP_TOKEN_PREVIOUS``). ``/mcp/operator`` takes only a
    per-admin ``mcp:operator`` service key. Nothing may deliver the token to a
    container again, mint it, register it for rotation, or read its value in
    the gateway — a delivered secret nothing is supposed to read is how a
    reader quietly comes back.

(b) The kiosk KEY lane, ``POST /api/kiosk/token``: a ``kiosk``-scoped service
    key that never expired, buying display tokens. Displays mint at
    ``/api/kiosk/token/tailnet`` by tailnet proof. The key lane must not be
    routed, must not be public, and must not be an exchange door.

Each check asserts that its parse found what it expects to find first, so a
moved file or a changed layout fails loudly instead of passing on nothing.

Plants (2026-09-30, restored from .bak): re-adding
``- NOO_MCP_TOKEN_FILE=...`` to the gateway's environment fails
``test_no_container_is_handed_the_mcp_token``; re-adding
``.route("/api/kiosk/token", post(token))`` fails
``test_the_kiosk_key_lane_is_not_routed``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "gateway-rust" / "src"

RETIRED_TOKEN = re.compile(r"\bNOO_MCP_TOKEN(?:_PREVIOUS|_FILE)?\b|\bnoo_mcp_token\b")


def _uncommented(text: str, comment: str) -> list[tuple[int, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(comment):
            continue
        out.append((n, line.split(f" {comment}", 1)[0] if comment == "#" else line))
    return out


def test_no_container_is_handed_the_mcp_token() -> None:
    files = sorted(ROOT.glob("docker-compose*.yml"))
    assert len(files) >= 3, f"compose files not found under {ROOT}: {files}"
    assert any("noo-gateway" in f.read_text() for f in files), "no gateway service found — the scan is vacuous"
    hits = [
        f"{f.name}:{n}: {line.strip()}"
        for f in files
        for n, line in _uncommented(f.read_text(), "#")
        if RETIRED_TOKEN.search(line)
    ]
    assert not hits, (
        "NOO_MCP_TOKEN is retired — the operator door takes only per-admin mcp:operator keys; "
        f"do not deliver it again: {hits}"
    )


def _block(path: Path, pattern: str) -> str:
    text = path.read_text()
    m = re.search(pattern, text, re.S)
    assert m, f"{path.relative_to(ROOT)}: the manifest this guard reads is gone ({pattern!r})"
    return m.group(1)


def test_no_manifest_mints_delivers_or_rotates_the_mcp_token() -> None:
    manifests = {
        "gateway secret_env FILE_BACKED_SECRETS": _block(
            RUST / "secret_env.rs", r"pub const FILE_BACKED_SECRETS: &\[&str\] = &\[(.*?)\n\];"
        ),
        "python secret_env FILE_BACKED_SECRETS": _block(
            ROOT / "src/noomesh/secret_env.py", r"FILE_BACKED_SECRETS: tuple\[str, \.\.\.\] = \((.*?)\n\)"
        ),
        "CLI secrets_delivery TIER1": _block(
            ROOT / "noo-cli/src/commands/secrets_delivery.rs", r"pub\(crate\) const TIER1: &\[&str\] = &\[(.*?)\n\];"
        ),
        "wizard SECRETS": _block(
            ROOT / "noo-cli/src/onboard/mod.rs", r"pub\(crate\) const SECRETS: &\[\(&str, &str\)\] = &\[(.*?)\n\];"
        ),
        "docker-secrets map": _block(ROOT / "src/noomesh/secrets.py", r"_SECRET_FILE_TO_ENV = \{(.*?)\n\}"),
    }
    for name, body in manifests.items():
        # Non-vacuous: every one of these carries the JWT secret.
        assert "NOO_JWT_SECRET" in body, f"{name}: parsed block does not look like the manifest"
        live = "\n".join(line for line in body.splitlines() if not line.strip().startswith(("//", "#")))
        assert not RETIRED_TOKEN.search(live), f"{name} carries the retired NOO_MCP_TOKEN again"
    registry = (ROOT / "noo-cli/src/commands/secrets.rs").read_text()
    assert 'key: "NOO_JWT_SECRET"' in registry, "rotation registry layout changed — this guard is stale"
    assert 'key: "NOO_MCP_TOKEN"' not in registry, "the retired NOO_MCP_TOKEN has a rotation plan again"


def test_the_gateway_never_reads_the_retired_token_value() -> None:
    src = (RUST / "mcp_local.rs").read_text()
    assert "fn authenticate_over_tls" in src, "the operator door moved — this guard is stale"
    code = "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))
    for reader in (r'secret(?:_or_empty|_opt|_required)?\(\s*"NOO_MCP_TOKEN', r'env::var\(\s*"NOO_MCP_TOKEN'):
        assert not re.search(reader, code), f"mcp_local.rs reads the retired token again ({reader})"
    assert "OperatorCaller::Token" not in code, "the anonymous shared-token caller is back"


def test_every_mint_hint_is_a_real_cli_verb() -> None:
    """The refusals name `noo security service-key issue … --scopes mcp:operator
    --user …`. Pinned against the CLI's own usage table, so a renamed verb or
    flag fails here rather than in front of an operator holding a 401."""
    usage = (ROOT / "noo-cli/src/usage.rs").read_text()
    row = re.search(r'\(&\["security", "service-key", "issue"\], "([^"]*)"', usage)
    assert row, "the CLI has no `security service-key issue` row"
    hints = {
        "gateway": (RUST / "mcp_local.rs").read_text(),
        "cli": (ROOT / "noo-cli/src/commands/mcp.rs").read_text(),
    }
    for where, src in hints.items():
        m = re.search(r'const MINT_HINT: &str =\s*"([^"]+)"', src)
        assert m, f"{where}: MINT_HINT not found"
        hint = m.group(1)
        assert hint.startswith("noo security service-key issue "), (where, hint)
        for flag in re.findall(r"(--[a-z-]+)", hint):
            assert flag in row.group(1), f"{where}: {flag} is not a flag of `service-key issue` ({row.group(1)})"
    assert len({re.search(r'const MINT_HINT: &str =\s*"([^"]+)"', s).group(1) for s in hints.values()}) == 1, (
        "the gateway's refusal and the CLI's hint name different commands"
    )


ROUTE = re.compile(r'\.route\(\s*"([^"]+)"')


def test_the_kiosk_key_lane_is_not_routed() -> None:
    paths = [
        (f.relative_to(ROOT), p)
        for f in sorted(RUST.rglob("*.rs"))
        for p in ROUTE.findall(f.read_text())
    ]
    assert len(paths) > 200, f"only {len(paths)} routes parsed — the router scan is vacuous"
    kiosk = [(f, p) for f, p in paths if p.startswith("/api/kiosk/token")]
    assert any(p == "/api/kiosk/token/tailnet" for _, p in kiosk), "the tailnet mint is not routed — the kiosk has no mint"
    stray = [f"{f}: {p}" for f, p in kiosk if p != "/api/kiosk/token/tailnet"]
    assert not stray, f"the retired kiosk KEY lane (or a sibling) is routed again: {stray}"


def test_the_kiosk_key_lane_is_neither_public_nor_an_exchange_door() -> None:
    auth = (RUST / "auth.rs").read_text()
    m = re.search(r"pub const PUBLIC_PATHS_EXACT: &\[&str\] = &\[(.*?)\n\];", auth, re.S)
    assert m, "auth.rs: PUBLIC_PATHS_EXACT not found — this guard is stale"
    public = re.findall(r'^\s*"([^"]+)"', m.group(1), re.M)
    assert "/api/kiosk/token/tailnet" in public, public
    assert "/api/kiosk/token" not in public, "the retired kiosk key lane is PUBLIC"
    door = re.search(r"pub fn exchange_scope_for\(.*?\n}\n", auth, re.S)
    assert door and "IDENTITY_TOKEN_PATH" in door.group(0), "exchange_scope_for moved — this guard is stale"
    assert "KIOSK" not in door.group(0).split("match path", 1)[1], "a kiosk exchange door is back"
    users = (RUST / "routes" / "users.rs").read_text()
    scopes = re.search(r"const SERVICE_KEY_SCOPES: &\[&str\] = &\[(.*?)\];", users, re.S)
    assert scopes and '"chat"' in scopes.group(1), "SERVICE_KEY_SCOPES moved — this guard is stale"
    assert "KIOSK" not in scopes.group(1) and '"kiosk"' not in scopes.group(1), "the kiosk scope is issuable again"
