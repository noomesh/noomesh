# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Each graph tool's formatter must render what its worker actually returns.

An MCP tool is two halves in two languages that never meet: the worker builds
a dict (`src/noomesh/workers/graph.py`), the tool's `format_response` reads it
(`src/noomesh/mcp/tool_defs/graph.py`). Nothing compared them, and when the
nine routes landed **five of the eight formatters were wrong** — every one of
them shipping green:

- `explain_path` did `step['src']` on rows keyed `src_entity_id`, so it raised
  KeyError on every path it FOUND and only "worked" when there was none;
- `semantic_search` and `search_clusters` type-checked for a bare list while
  the worker returns `{"entities": [...]}` / `{"clusters": [...]}`, so both
  fell through to the base class and printed raw JSON;
- `extract_relations` read `edges_created` while the worker emitted
  `relations_extracted`, so it always said "Extracted 0 semantic edge(s)";
- `classify_intent` defaulted a missing confidence to 0 and printed
  "confidence: 0.000" for a classifier that has none — a fabricated number,
  which is worse than a blank.

The fixtures below are the worker's real shapes. The assertions are about
what an operator sees, because that is what broke: no exception, no raw JSON
fall-through, and no number that was not measured.
"""

from __future__ import annotations

import json

import pytest

from noomesh.mcp.tool_defs import graph as g


def _tool(name: str):
    cls = next(
        (c for c in vars(g).values()
         if isinstance(c, type) and getattr(c, "name", None) == name),
        None,
    )
    assert cls is not None, f"{name} is not registered in tool_defs/graph.py"
    return cls


def _looks_like_raw_json(out: str) -> bool:
    """The base class dumps JSON. That is the fall-through we are hunting."""
    stripped = out.strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(stripped)
        return True
    except ValueError:
        return False


# name -> (constructor kwargs, the worker's actual response)
CASES = {
    "noo_graph_navigate": (
        {"query": "q"},
        {"seed_entities": [{"canonical_name": "python", "type": "language"}],
         "hypotheses": [{"confidence": 0.9, "description": "h"}],
         "candidate_page_ids": ["p1", "p2"]},
    ),
    "noo_graph_explain_path": (
        {"src_entity_id": "a", "dst_entity_id": "b"},
        # Raw edge rows, as `explain_path` returns them.
        {"path": [{"edge_id": "e1", "src_entity_id": "a", "rel_type": "CAUSES",
                   "dst_entity_id": "b"}],
         "hops": 1, "found": True},
    ),
    "noo_graph_semantic_search": (
        {"query": "q"},
        {"entities": [{"entity_id": "e1", "canonical_name": "python",
                       "type": "language", "score": 0.87}],
         "count": 1},
    ),
    "noo_graph_search_clusters": (
        {"query": "q"},
        {"clusters": [{"cluster_id": "c1", "name": "languages",
                       "member_count": 12, "score": 0.77, "summary": "s"}],
         "count": 1},
    ),
    "noo_graph_classify_intent": ({"query": "q"}, {"intent": "factual", "query": "q"}),
    "noo_graph_extract_relations": ({"page_id": "p1"}, {"page_id": "p1", "edges_created": 7}),
    "noo_graph_run_clustering": (
        {},
        {"status": "ok", "generation": 3, "clusters": 12, "meta_clusters": 2,
         "nodes": 400, "edges": 900, "stale_removed": 1, "elapsed_secs": 61.2},
    ),
}


@pytest.mark.parametrize("name", sorted(CASES), ids=sorted(CASES))
def test_the_formatter_renders_the_workers_real_shape(name):
    kwargs, payload = CASES[name]
    out = _tool(name)(**kwargs).format_response(payload)
    assert isinstance(out, str) and out.strip(), f"{name} rendered nothing"
    assert not _looks_like_raw_json(out), (
        f"{name} fell through to the base class and printed raw JSON — its "
        "type check does not match the shape the worker sends"
    )


def test_explain_path_renders_a_found_path_without_raising():
    """The regression that only appeared on success."""
    payload = CASES["noo_graph_explain_path"][1]
    out = _tool("noo_graph_explain_path")(src_entity_id="a", dst_entity_id="b") \
        .format_response(payload)
    assert "CAUSES" in out and "a" in out and "b" in out
    assert "?" not in out, "an endpoint rendered as '?' — the keys still do not match"


def test_extract_relations_reports_the_real_count():
    out = _tool("noo_graph_extract_relations")(page_id="p1") \
        .format_response({"page_id": "p1", "edges_created": 7})
    assert "7" in out, "the count is not being read; it renders as 0"


def test_classify_intent_does_not_invent_a_confidence():
    out = _tool("noo_graph_classify_intent")(query="q") \
        .format_response({"intent": "factual", "query": "q"})
    assert "factual" in out
    assert "0.000" not in out and "confidence" not in out.lower(), (
        "a keyword classifier reports no confidence; printing one — especially "
        "0.000 — states a measurement that was never taken"
    )
    # ...but it still shows one when the payload genuinely has it.
    with_conf = _tool("noo_graph_classify_intent")(query="q") \
        .format_response({"intent": "factual", "confidence": 0.82})
    assert "0.820" in with_conf


def test_search_clusters_explains_an_empty_result_rather_than_blaming_the_query():
    """An unclustered graph has no centroids. "No matching clusters found"
    would blame the query for a graph that was never clustered."""
    out = _tool("noo_graph_search_clusters")(query="q").format_response(
        {"clusters": [], "count": 0, "reason": "no_clusters_with_centroids",
         "hint": "run `noo graph recluster` first"}
    )
    assert "no_clusters_with_centroids" in out and "recluster" in out


def test_the_worker_and_the_fixtures_agree_on_extract_relations():
    """The one case where the fix was in the worker, not the formatter.

    Parsed, not grepped. The handler's comment names the old key to explain
    why it is gone, so a substring check fails on its own documentation —
    which is the second time that has happened in this session, hence the
    AST.
    """
    import ast
    import pathlib as _p

    src = (_p.Path(__file__).resolve().parent.parent
           / "src/noomesh/workers/graph.py").read_text(encoding="utf-8")
    fn = next(
        n for n in ast.walk(ast.parse(src))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == "_graph_extract_relations"
    )
    returned = {
        k.value
        for node in ast.walk(fn) if isinstance(node, ast.Return)
        for d in ([node.value] if isinstance(node.value, ast.Dict) else [])
        for k in d.keys if isinstance(k, ast.Constant)
    }
    assert "edges_created" in returned, f"handler returns {sorted(returned)}"
    assert "relations_extracted" not in returned, "the old key is back"
