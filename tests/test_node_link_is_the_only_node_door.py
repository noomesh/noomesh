# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`gateway-rust/src/node_link.rs` is the only door from the controller to a
node agent.

Every controller -> node-agent call (an agent URL, the agent port, the shared
client and the credential `node_agent_auth` decides) is built in one module so
that a later phase (i131: NATS RPC for control, a node-held tunnel for
streaming) swaps the transport in one place. A call site that builds its own
`https://{ip}:8081`, resolves an agent URL itself, or asks `node_agent_auth`
for a header directly has stepped around that seam and will keep dialling
inbound after the seam moves.

This guard reads the gateway source and fails on, outside `node_link.rs` and
`node_agent_auth.rs` (the auth policy `NodeLink` calls):

- the agent port literal (`8081`, `:8081`, `8081u16`);
- `get_node_agent_url(` (the old resolver, now `NodeLink::for_node`);
- `build_node_agent_client(` (the old client accessor, now inside `NodeLink`);
- a direct `node_agent_auth::header_for(` / `header_for_self(` call.

Comments and everything from the first `#[cfg(test)]` of a file on are not
scanned: fixtures and test addresses may spell the port. A genuine exception
goes on ALLOWED with the reason; a stale entry fails the guard too.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "gateway-rust" / "src"

# The two files that ARE the door.
DOOR = {"node_link.rs", "node_agent_auth.rs"}

# file (relative to gateway-rust/src) -> {pattern name: why it is not a
# controller -> node-agent call}. Keep this short.
ALLOWED: dict[str, dict[str, str]] = {}

PATTERNS: dict[str, re.Pattern[str]] = {
    "agent port literal": re.compile(r"8081"),
    "get_node_agent_url(": re.compile(r"\bget_node_agent_url\s*\("),
    "build_node_agent_client(": re.compile(r"\bbuild_node_agent_client\s*\("),
    "direct node_agent_auth::header_for": re.compile(r"\bnode_agent_auth::header_for(_self)?\s*\("),
}


def _code_lines(path: Path) -> list[tuple[int, str]]:
    """Non-comment lines of the file's production code (before any test mod)."""
    out: list[tuple[int, str]] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw.lstrip().startswith("#[cfg(test)]"):
            break
        if raw.lstrip().startswith("//"):
            continue
        idx = raw.find(" //")
        out.append((n, raw if idx < 0 else raw[:idx]))
    return out


def violations(src: Path = SRC) -> dict[str, dict[str, list[int]]]:
    found: dict[str, dict[str, list[int]]] = {}
    for path in sorted(src.rglob("*.rs")):
        if path.name in DOOR and path.parent == src:
            continue
        rel = path.relative_to(src).as_posix()
        for n, line in _code_lines(path):
            for name, pat in PATTERNS.items():
                if pat.search(line):
                    found.setdefault(rel, {}).setdefault(name, []).append(n)
    return found


def test_the_scan_sees_the_door_it_guards() -> None:
    """A scan that finds nothing passes for the wrong reason."""
    link = (SRC / "node_link.rs").read_text(encoding="utf-8")
    assert "pub const AGENT_PORT: u16 = 8081;" in link
    auth = (SRC / "node_agent_auth.rs").read_text(encoding="utf-8")
    assert "pub(crate) fn header_for(" in auth
    # The patterns match what they are written for.
    assert PATTERNS["agent port literal"].search('format!("https://{ip}:8081")')
    assert PATTERNS["agent port literal"].search("let p = 8081u16;")
    assert PATTERNS["get_node_agent_url("].search("get_node_agent_url(state, id)")
    assert PATTERNS["direct node_agent_auth::header_for"].search("crate::node_agent_auth::header_for(&url)")
    assert PATTERNS["direct node_agent_auth::header_for"].search("node_agent_auth::header_for_self(&u)")
    assert not PATTERNS["direct node_agent_auth::header_for"].search("`node_agent_auth::header_for`")


def test_only_node_link_dials_a_node_agent() -> None:
    found = violations()
    unexpected: list[str] = []
    for rel, names in found.items():
        for name, lines in names.items():
            if name in ALLOWED.get(rel, {}):
                continue
            unexpected.append(f"{rel}:{','.join(map(str, lines))}: {name}")
    assert not unexpected, (
        "controller -> node-agent calls must go through gateway-rust/src/node_link.rs "
        "(NodeLink::for_node / for_ip / for_base / self_agent, request / stream):\n  "
        + "\n  ".join(unexpected)
    )


def test_every_allow_list_entry_is_still_needed() -> None:
    found = violations()
    stale = [
        f"{rel}: {name}"
        for rel, names in ALLOWED.items()
        for name in names
        if name not in found.get(rel, {})
    ]
    assert not stale, "stale ALLOWED entries (remove them):\n  " + "\n  ".join(stale)
