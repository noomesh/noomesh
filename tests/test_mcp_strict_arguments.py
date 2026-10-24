# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""i217: a tool call with an argument the tool does not declare is refused.

`noo_agent_thread(thread_id=...)` (the parameter is `thread`) used to drop the
unknown name, run with no thread filter, and answer a broader question than the
one asked. The Python registry refuses it (ToolDef extra=forbid); the schemas
the doors advertise, and the Rust door's own check, follow from that.
"""
import json
from pathlib import Path

import pydantic
import pytest

from noomesh.mcp import tool_defs  # noqa: F401  (registers every tool)
from noomesh.mcp.tool_models import call_tool, get_all_tools, get_tool_class

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "gateway-rust"


def test_the_followup_case_is_refused_naming_the_parameter():
    cls = get_tool_class("noo_agent_thread")
    with pytest.raises(pydantic.ValidationError) as e:
        cls.model_validate({"thread_id": "thr_bcbbcd6acb084cf29763"})
    assert "thread_id" in str(e.value)


@pytest.mark.asyncio
async def test_the_dispatch_choke_point_refuses_before_any_request():
    # call_tool is what the NATS worker and the MCP server both use; it must
    # raise on validation, not reach the gateway.
    with pytest.raises(pydantic.ValidationError):
        await call_tool("noo_agent_thread", {"thread_id": "thr_x"})


def test_every_tool_refuses_an_undeclared_argument():
    for name, cls in get_all_tools().items():
        required = {
            k: "x" for k, f in cls.model_fields.items() if f.is_required()
        }
        with pytest.raises(pydantic.ValidationError):
            cls.model_validate({**required, "definitely_not_a_parameter": 1})


def test_declared_arguments_are_unchanged():
    cls = get_tool_class("noo_agent_thread")
    tool = cls.model_validate({"thread": "thr_x"})
    assert tool.thread == "thr_x"
    # a no-argument tool still takes nothing and still validates
    assert get_tool_class("noo_scheduler_status").model_validate({}) is not None


@pytest.mark.parametrize("manifest", ["mcp-tools.json", "mcp-tools-local.json"])
def test_advertised_schemas_say_additional_properties_false(manifest):
    tools = json.loads((GATEWAY / manifest).read_text())["tools"]
    assert tools
    open_ones = [
        t["name"] for t in tools if t["input_schema"].get("additionalProperties") is not False
    ]
    assert not open_ones, f"schemas that do not forbid extras: {open_ones}"


def test_rust_doors_enforce_the_same_rule_everywhere():
    ext = (GATEWAY / "src/mcp_external.rs").read_text()
    # the shared executor checks first, and a no-argument tool accepts nothing
    assert "if let Some(e) = unknown_args(spec, args)" in ext
    assert "this tool takes no arguments" in ext
    assert "missing required argument" in ext
    tasks = (GATEWAY / "src/mcp_user_tasks.rs").read_text()
    assert "if let Some(e) = undeclared(name, args)" in tasks
