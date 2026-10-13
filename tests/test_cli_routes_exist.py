# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every gateway path the CLI calls is a route the gateway serves.

The console has had this check since the monorepo import
(`ui/contracts/audit/audit_ui_contract.py`, `npm run audit:contract`); the
CLI, which reaches more of the router than the console does (163 routes to
75, 2026-09-25), had none. A route renamed or deleted in `gateway-rust`
broke `noo` with a 404 at run time and nothing before it.

The gateway spec is the router's declared surface —
`scripts/check-openapi-drift.py` and `gen-openapi.py --check` hold the two
equal — so the CLI's path literals are matched against it, segment by
segment, a `{…}` on either side matching any one segment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "noo-cli/src"
SPEC = ROOT / "src/noomesh/gateway/static/openapi.json"

# A gateway-shaped path the CLI does NOT send to the gateway. Each entry
# names who serves it instead; nothing else belongs here.
NOT_THE_GATEWAY = {
    # onboard's own local web server (onboard/web.rs serves the wizard's
    # folder picker; the gateway may not even exist yet when it runs).
    "/api/browse": "onboard/web.rs",
}

LITERAL = re.compile(r'"(/(?:api|v1|ws|mcp|health|metrics|tools|upload|bootstrap|\.well-known)[^"\s\\]*)"')


def _segments(path: str) -> list[str]:
    return path.split("?", 1)[0].rstrip("/").split("/")


def _served(path: str, routes: list[list[str]]) -> bool:
    want = _segments(path)
    return any(
        len(r) == len(want) and all(a == b or a.startswith("{") or b.startswith("{") for a, b in zip(want, r))
        for r in routes
    )


def _cli_paths() -> dict[str, str]:
    found: dict[str, str] = {}
    for f in sorted(CLI.rglob("*.rs")):
        # Only shipped code calls the gateway: a `#[cfg(test)]` module's
        # fixture paths (addon_cli.rs tests its dispatcher against made-up
        # routes) are not calls, so the scan stops at the first one.
        text = f.read_text().split("#[cfg(test)]", 1)[0]
        for m in LITERAL.finditer(text):
            # A literal ending in "/" is a namespace PREFIX the code checks
            # against ("/api/" in addon_cli.rs), never a path it requests.
            if m.group(1).endswith("/"):
                continue
            found.setdefault(m.group(1), str(f.relative_to(CLI)))
    return found


def test_every_cli_path_is_a_served_route() -> None:
    routes = [_segments(p) for p in json.loads(SPEC.read_text())["paths"]]
    paths = _cli_paths()
    assert len(paths) >= 150, f"found only {len(paths)} path literals in noo-cli — the scan broke"
    unserved = sorted(
        f"{p}  ({where})"
        for p, where in paths.items()
        if _segments(p)[:3] and "/".join(_segments(p)) not in NOT_THE_GATEWAY and not _served(p, routes)
    )
    assert not unserved, "the CLI calls paths the gateway does not serve:\n  " + "\n  ".join(unserved)


def test_the_exceptions_are_still_needed() -> None:
    # An exception whose literal left the CLI is a hole waiting for a real
    # path of the same name.
    paths = {"/".join(_segments(p)) for p in _cli_paths()}
    for path, where in NOT_THE_GATEWAY.items():
        assert path in paths, f"{path} ({where}) no longer appears in the CLI — drop the exception"
