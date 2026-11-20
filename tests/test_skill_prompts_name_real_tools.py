# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Skill prompts name only tools that exist, and send no agent over SSH.

Agents act on `prompts/skills/**/*.md` as instructions. A skill told them to
read `noo_channel_recipients` (the tool is `noo_channel_list_recipients`) and
to look at node logs "via SSH" (the controller's SSH lane is retired; nodes
are pull-only). Neither failed anything: the agent just called a tool that is
not there, or advised a path that does not exist.

Two checks:

* every `noo_*` name a skill writes as a tool (in backticks, or followed by
  `(`) is a tool some catalog serves: the operator door
  (`gateway-rust/mcp-tools-local.json`), the user door
  (`gateway-rust/mcp-tools.json`) or the coordinator's own catalog
  (`config/tools.json`). A bare word such as the `noo_entries` table is not
  a tool reference and is not checked;
* no skill says SSH at all.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "prompts" / "skills"

# `noo_x`, `noo_x(...)` inside backticks, or noo_x( anywhere.
_TOOL_REF = re.compile(r"`(noo_[a-z0-9_]+)[`(]|\b(noo_[a-z0-9_]+)\(")


def _catalog() -> set[str]:
    names: set[str] = set()
    for f in ("mcp-tools-local.json", "mcp-tools.json"):
        data = json.loads((ROOT / "gateway-rust" / f).read_text(encoding="utf-8"))
        names |= {t["name"] for t in data["tools"]}
    cfg = json.loads((ROOT / "config" / "tools.json").read_text(encoding="utf-8"))
    names |= {t["function"]["name"] for t in cfg["core_tools"]}
    for group in cfg["extended_tool_groups"].values():
        names |= set(group["tools"])
    return names


def _skills() -> list[Path]:
    files = sorted(SKILLS.rglob("*.md"))
    assert files, f"no skill prompts under {SKILLS}"
    return files


def tool_refs(text: str) -> set[str]:
    return {a or b for a, b in _TOOL_REF.findall(text)}


def test_the_reference_pattern_reads_tool_calls_not_table_names():
    assert tool_refs("use `noo_rag_query` then noo_rag_ingest(source=x)") == {"noo_rag_query", "noo_rag_ingest"}
    assert tool_refs("`noo_graph_neighbors(id, hops=2)`") == {"noo_graph_neighbors"}
    assert tool_refs("the conversation is already in noo_entries and") == set()


def test_every_tool_a_skill_names_exists_in_a_catalog():
    catalog = _catalog()
    assert "noo_channel_list_recipients" in catalog and "noo_cluster_status" in catalog
    missing = {}
    for p in _skills():
        unknown = sorted(tool_refs(p.read_text(encoding="utf-8")) - catalog)
        if unknown:
            missing[str(p.relative_to(ROOT))] = unknown
    assert not missing, f"skill prompts name tools no catalog serves: {missing}"


def test_no_skill_sends_an_agent_over_ssh():
    hits = [
        f"{p.relative_to(ROOT)}:{i}: {line.strip()}"
        for p in _skills()
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\bssh", line, re.IGNORECASE)
    ]
    assert not hits, "nodes are pull-only and no lane logs into them:\n" + "\n".join(hits)


def _personas() -> list[Path]:
    files = sorted((ROOT / "prompts").glob("coordinator*.md"))
    assert files, "no coordinator persona under prompts/"
    return files


def test_the_persona_routes_no_cli_or_ssh_through_noo_coding_task():
    """`noo_coding_task` refuses every task (coding_tool.py: in-cluster
    Claude Code is retired), so a persona line that sends a `noo ...` command
    or SSH through it tells the coordinator to do something that cannot
    happen. The CLI runs on the controller, by the operator."""
    hits = [
        f"{p.relative_to(ROOT)}:{i}: {line.strip()}"
        for p in _personas()
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\bssh", line, re.IGNORECASE)
        or ("noo_coding_task" in line and re.search(r"`noo [a-z]", line))
    ]
    assert not hits, "\n".join(hits)
