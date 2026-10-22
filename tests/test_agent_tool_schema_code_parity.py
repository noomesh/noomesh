# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Schema <-> code parity for the agent-messaging tools.

The loop is handed the manifest schema (`mcp-tools-local.json`, generated
from `tool_defs/skills.py`) and its native reader is Rust. They were
written apart: the schema named the inbox filter `thread`, the reader read
`thread_id`, and a model passing `thread=` got an unfiltered, unread-only
inbox that looked empty. A grep-based pin, like test_mcp_tool_route_parity:
every property a schema declares must appear as a key the native reader
asks for.
"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOLS_RS = (REPO / "gateway-rust/src/tools.rs").read_text(encoding="utf-8")
MANIFEST = json.loads((REPO / "gateway-rust/mcp-tools-local.json").read_text(encoding="utf-8"))

# manifest tool -> the native function that serves it
READERS = {
    "noo_agent_send": "native_agent_message",
    "noo_agent_inbox": "native_agent_inbox",
    "noo_agent_ack": "native_agent_ack",
    "noo_agent_thread": "native_agent_thread",
}

# Properties the native reader reads under another spelling, or does not
# read because the credential decides (named, so adding one is a decision).
ACCEPTED_ELSEWHERE = {
    # identity is derived from the credential, never claimed
    ("noo_agent_send", "agent"): "identity comes from the credential",
    ("noo_agent_send", "harness"): "harness class comes from the credential",
    # the loop's native inbox is ALWAYS scoped to its own names; `all` widens
    # the HTTP route for operators only and has no meaning in the loop
    ("noo_agent_inbox", "all"): "native inbox is always owner-scoped",
    # the ack route's path parameter; the native reader takes it as `id`/`message_id`
}


def _body(fn: str) -> str:
    m = re.search(rf"async fn {fn}\b.*?(?=\n    (?:pub\(crate\) )?(?:async )?fn |\n    #\[cfg\(test\)\])", TOOLS_RS, re.S)
    assert m, f"{fn} not found in tools.rs"
    return m.group(0)


def _keys_read(body: str) -> set:
    keys = set(re.findall(r'\.get\("(\w+)"\)', body))
    for arr in re.findall(r"arg_str\(args, (&\[[^\]]*\]|[A-Z_]+)\)", body):
        if arr.isupper():
            arr = re.search(rf"const {arr}: &\[&str\] = &\[([^\]]*)\]", TOOLS_RS).group(1)
        keys |= set(re.findall(r'"(\w+)"', arr))
    return keys


def _schema_props(tool: str) -> set:
    for t in MANIFEST["tools"]:
        if t["name"] == tool:
            return set(t["input_schema"].get("properties", {}))
    raise AssertionError(f"{tool} is not in the manifest")


def test_every_schema_property_is_read_by_the_native_reader():
    for tool, fn in READERS.items():
        read = _keys_read(_body(fn))
        assert read, f"{fn}: parsed no argument keys - the pin is blind"
        for prop in _schema_props(tool):
            if (tool, prop) in ACCEPTED_ELSEWHERE:
                continue
            assert prop in read, f"{tool}.{prop} is in the schema but {fn} never reads it (reads {sorted(read)})"


def test_the_inbox_accepts_thread_under_both_names():
    read = _keys_read(_body("native_agent_inbox"))
    assert {"thread", "thread_id"} <= read


def test_every_messaging_tool_is_native():
    m = re.search(r"NATIVE_TOOLS: &\[&str\] = &\[(.*?)\];", TOOLS_RS, re.S)
    native = set(re.findall(r'"(\w+)"', m.group(1)))
    assert set(READERS) <= native
