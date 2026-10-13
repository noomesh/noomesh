# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A tool's wire shape must survive export to the Rust door.

The door serves `gateway-rust/mcp-tools*.json` and builds each request from
that entry. A hand-written `get_params`/`get_body` is Python and is invisible
to it, so the door sends the DERIVED request instead.

`noo_graph_search_entities` renamed `query` -> `q` in `get_params`. Through
the door it sent `query=`, the route reads `q`, got nothing, and returned an
empty list with HTTP 200 — so every entity search came back empty and
nothing anywhere errored. Verified against the live controller: the row
existed, the ILIKE matched it, and the tool still returned [].
"""

from __future__ import annotations

import json
import pathlib

import pytest

from noomesh.mcp.tool_defs.graph import PaiGraphSearchEntities

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _builder():
    """The generator, loaded as a module so its guard can be called directly."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_mcp_manifest", ROOT / "scripts" / "build-mcp-manifest.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _manifest(name: str) -> dict:
    data = json.loads((ROOT / "gateway-rust" / name).read_text())
    tools = data if isinstance(data, list) else data["tools"]
    return {t["name"]: t for t in tools}


def test_the_search_sends_q_on_the_wire():
    assert PaiGraphSearchEntities(query="mistral").get_params()["q"] == "mistral"


def test_the_client_still_passes_query():
    """A plain `alias` would rename the parameter MCP clients send, because
    `model_json_schema()` renders in validation mode. `serialization_alias`
    changes only what goes to the gateway."""
    props = PaiGraphSearchEntities.model_json_schema()["properties"]
    assert "query" in props
    assert "q" not in props


@pytest.mark.parametrize("manifest", ["mcp-tools.json", "mcp-tools-local.json"])
def test_the_manifest_carries_the_rename(manifest):
    """What the door actually reads. Without this entry it sends `query=`."""
    tool = _manifest(manifest).get("noo_graph_search_entities")
    assert tool is not None
    assert tool["aliases"].get("query") == "q", (
        "the door will send the Python field name and the route will see no "
        "query at all — an empty result with HTTP 200"
    )


def test_no_exported_tool_builds_its_request_in_python():
    """The guard that makes the above impossible to reintroduce."""
    from noomesh.mcp.tool_models import get_all_tools

    builder = _builder()
    registry = {
        n: c
        for n, c in get_all_tools().items()
        if c.__module__.startswith("noomesh.")
    }
    offenders = builder._request_side_is_declarative(registry)
    assert not offenders, (
        "these build their request in Python and the door cannot see it: "
        f"{offenders}"
    )


def test_the_known_exception_is_documented_not_just_listed():
    builder = _builder()
    assert "noo_inference" in builder.UNREPRESENTABLE
    # Each entry says what the door gets WRONG, so the list cannot decay into
    # a suppression list nobody reads.
    for name, why in builder.UNREPRESENTABLE.items():
        assert len(why) > 60, f"{name} is listed with no account of the defect"
