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

# Dispatched inside the MODEL'S OWN LOOP by name, never over HTTP:
# `NATIVE_TOOLS` in gateway-rust/src/tools.rs. That is NOT true of the MCP
# doors, which build every call from their manifest and proxy it by path
# (`execute_spec`), natives included: `noo_tool_search` sat in this set while
# the operator door 404'd on its path (`GET /api/tools/search`, 2026-11-15).
# So this exemption covers the ToolDef registry only; a tool in a DOOR
# manifest is held by `test_every_door_tool_is_a_route_or_answered_by_the_door`.
NATIVE = {
    "noo_rag_query", "noo_memory_search", "noo_inference",
    "noo_channel_send", "noo_tool_search", "web_search", "python_tool",
    "noo_agent_message", "noo_agent_inbox", "noo_agent_ack", "noo_task_done",
    "noo_task_ask",
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


GATEWAY_ROOT = REPO / "gateway-rust"
# Each door: its manifest, the source whose `native_answer` answers its
# native tools in process.
DOORS = {
    "operator": (GATEWAY_ROOT / "mcp-tools-local.json", GATEWAY / "mcp_local.rs"),
    "user": (GATEWAY_ROOT / "mcp-tools.json", GATEWAY / "mcp_external.rs"),
}


def _native_answer_arms(src: pathlib.Path) -> set[str]:
    """The tool names `async fn native_answer(` matches, from the door's
    source (empty when the door has no such function)."""
    txt = src.read_text(encoding="utf-8")
    i = txt.find("async fn native_answer(")
    if i < 0:
        return set()
    j = txt.find("\n}\n", i)
    return set(re.findall(r'"([a-z0-9_]+)" =>', txt[i:j]))


def test_every_door_tool_is_a_route_or_answered_by_the_door():
    """The doors proxy every manifest tool to its `path`, so each one must be
    a route the gateway serves, or marked `native` AND answered by that
    door's `native_answer` (which the door runs before any self-call). No
    allow-list: a door tool that 404s is a defect, whatever the loop does."""
    import json

    matchers = [_matcher(r) for r in _router_paths()]
    bad = []
    for door, (manifest, src) in DOORS.items():
        arms = _native_answer_arms(src)
        for t in json.loads(manifest.read_text())["tools"]:
            if t.get("native"):
                if t["name"] not in arms:
                    bad.append(f"{door}: {t['name']} is native but {src.name} does not answer it")
            elif not _served(t["path"], matchers):
                bad.append(f"{door}: {t['name']} -> {t['method']} {t['path']} (no such route)")
    assert not bad, "door tools that 404 through their door:\n  " + "\n  ".join(bad)


def test_the_door_check_sees_both_doors_and_the_native_tool():
    """Not vacuous: both manifests read, and the one native tool is found as
    native and answered by the operator door."""
    import json

    local = json.loads(DOORS["operator"][0].read_text())["tools"]
    assert len(local) > 100 and len(json.loads(DOORS["user"][0].read_text())["tools"]) > 20
    assert [t["name"] for t in local if t.get("native")] == ["noo_tool_search"]
    assert "noo_tool_search" in _native_answer_arms(DOORS["operator"][1])


def test_every_native_tooldef_answers_in_process():
    """A `native` ToolDef is never proxied by `dispatch`, so it must override
    `run_local` (the standalone MCP server's in-process answer)."""
    from noomesh.mcp.tool_models import ToolDef, _ensure_tool_defs_registered, _TOOL_REGISTRY

    _ensure_tool_defs_registered()
    natives = [c for c in _TOOL_REGISTRY.values() if getattr(c, "native", False)]
    assert natives, "no native ToolDef found: the check would be vacuous"
    for c in natives:
        assert c.run_local is not ToolDef.run_local, f"{c.name} is native but has no run_local"
