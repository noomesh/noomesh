# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every MCP tool's path must be a route the gateway actually serves.

A tool definition is a Python class. The router is Rust. Nothing has ever
compared the two, so a tool could name a path that does not exist and the
only symptom was a 404 through the MCP door — which reads to an agent as
"the gateway is broken", not "this tool was never wired". Three evolve tools
sat like that for weeks until the add-on's route surface was written down as
data, and `noo_graph_run_clustering` sat like that for as long as it has
existed, pointing at `/api/v1/graph/run-clustering`.

The check is textual for the same reason the other parity tests are: the
crates share no library and `cargo-docker.sh` mounts only the crate being
built.

`UNROUTED` is an allow-list, not a suppression. Every entry is a tool that
is reachable in a manifest and answers 404, with the reason it is still
declared. It must only ever get shorter.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
GATEWAY = REPO / "gateway-rust/src"
TOOL_DEFS = REPO / "src/noomesh/mcp/tool_defs"

# Dispatched inside the gateway by name, never over HTTP: `NATIVE_TOOLS` in
# gateway-rust/src/tools.rs. Their `path` is documentation.
NATIVE = {
    "noo_rag_query", "noo_memory_search", "noo_inference",
    "noo_channel_send", "noo_tool_search", "web_search", "python_tool",
    "noo_agent_message", "noo_agent_inbox", "noo_agent_ack", "noo_task_done",
    "noo_task_delegate", "noo_task_status", "noo_task_wait",
}

# Declared, reachable, and 404 — The list only shrinks, and the
# test below fails if a fixed entry is left in it.
UNROUTED: dict[str, str] = {
    # Empty. The eight Intelligent-tier graph tools left this list when the
    # routes landed; `noo_coding_status` left it
    # 2026-09-27 when the tool was deleted — nothing spawns a coding task,
    # so nothing had a status to poll.
}


def _router_paths() -> set[str]:
    paths: set[str] = set()
    for f in GATEWAY.rglob("*.rs"):
        paths |= set(re.findall(r'\.route\(\s*"([^"]+)"',
                                f.read_text(encoding="utf-8", errors="ignore")))
    # Add-on routes are not here: an HTTP add-on ships its own manifest and
    # its MCP tools ship in its own fragment, so a core tool may only name a
    # core route (`/api/prompt-skills/evolve` is one: the gateway owns it and
    # the add-on serves it through an internal row).
    return paths


def _matcher(route: str) -> re.Pattern:
    """A route's `{param}` matches any one path segment."""
    return re.compile("^" + "/".join(
        "[^/]+" if seg.startswith("{") else re.escape(seg)
        for seg in route.split("/")) + "$")


def _tools() -> list[tuple[str, str, str]]:
    out = []
    for f in sorted(TOOL_DEFS.glob("*.py")):
        txt = f.read_text(encoding="utf-8")
        for m in re.finditer(
            r'name: ClassVar\[str\] = "([^"]+)"(.*?)path: ClassVar\[str\] = "([^"]+)"',
            txt, re.S,
        ):
            out.append((m.group(1), m.group(3), f.name))
    return out


def _served(path: str, matchers: list[re.Pattern]) -> bool:
    probe = "/".join("X" if s.startswith("{") else s for s in path.split("/"))
    return any(m.match(probe) for m in matchers)


def test_the_tool_registry_is_not_empty():
    """A regex that silently matched nothing would make every other
    assertion here vacuous."""
    assert len(_tools()) > 50


def test_every_tool_path_is_a_route_the_gateway_serves():
    matchers = [_matcher(r) for r in _router_paths()]
    broken = {
        name: path
        for name, path, _ in _tools()
        if name not in NATIVE and not _served(path, matchers)
    }
    new = {k: v for k, v in broken.items() if k not in UNROUTED}
    assert not new, (
        "these MCP tools name a path the gateway does not serve, so they "
        f"404 through both doors: {new}"
    )


def test_the_unrouted_list_only_shrinks():
    """An entry that starts working must leave the list, or the list stops
    meaning anything and the next dead tool hides inside it."""
    matchers = [_matcher(r) for r in _router_paths()]
    by_name = {n: p for n, p, _ in _tools()}
    fixed, gone = [], []
    for name, path in UNROUTED.items():
        if name not in by_name:
            gone.append(name)
        elif _served(by_name[name], matchers):
            fixed.append(name)
    assert not fixed, f"now served — drop from UNROUTED: {fixed}"
    assert not gone, f"no longer declared — drop from UNROUTED: {gone}"
