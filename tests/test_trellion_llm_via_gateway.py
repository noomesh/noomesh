# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Trellion never dials an LLM backend directly (2026-09-09).

Its graph extraction and answer synthesis go through the gateway's
`/v1/chat/completions`, which resolves the backend over the mesh like every
chat channel and carries the node credential trellion lacks. Two things pin
that: the worker pool hands trellion the gateway address and the `knowledge`
purpose (i145: no PAGEINDEX_LLM_* in compose), and the gateway proxy passes
the body's `model` to the class resolver, where the purpose is a DB
preference (the mesh when undeclared).
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _trellion_env() -> dict[str, str]:
    from tests._compose_projection import raw_services_union
    svc = raw_services_union()["trellion"]  # its overlay since an earlier change
    env = svc["environment"]
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return env


def test_no_service_picks_its_llm_from_env() -> None:
    """i145: the purpose names the model, the DB says which; compose restates neither."""
    from tests._compose_projection import raw_services_union
    env = _trellion_env()
    assert env["PAGEINDEX_EMBEDDING_URL"] == "${NOO_TRELLION_EMBEDDING_URL:-https://gateway:8080}"
    for name, svc in raw_services_union().items():
        e = svc.get("environment") or {}
        keys = [item.split("=", 1)[0] for item in e] if isinstance(e, list) else list(e)
        for var in ("PAGEINDEX_LLM_URL", "PAGEINDEX_LLM_MODEL"):
            assert var not in keys, f"{name} sets {var}: an LLM choice belongs in the DB as a purpose preference"


def test_worker_llm_callers_send_a_purpose_to_the_gateway() -> None:
    pool = (ROOT / "src/noomesh/gateway/worker_pool.py").read_text()
    assert "llm_model = llm_purposes.KNOWLEDGE" in pool and "llm_url = llm_purposes.gateway_url()" in pool
    graph = (ROOT / "src/noomesh/workers/graph.py").read_text()
    assert '"model": llm_purposes.GRAPH' in graph and '"llm_url": llm_purposes.gateway_url()' in graph
    orch = (ROOT / "src/noomesh/agents/orchestrator.py").read_text()
    assert "base_url=llm_purposes.gateway_url()" in orch
    for src, name in ((pool, "worker_pool"), (graph, "graph"), (orch, "orchestrator")):
        assert 'getenv("PAGEINDEX_LLM' not in src and 'environ.get("PAGEINDEX_LLM' not in src, name
        assert "noo-vllm:8000" not in src and 'os.getenv("VLLM_MODEL"' not in src, name
    rs = (ROOT / "gateway-rust/src/coordinator/classes.rs").read_text()
    m = re.search(r"pub const PURPOSE_ALIASES: \[&str; \d+\] = \[([^\]]*)\]", rs)
    assert m, "PURPOSE_ALIASES not found in classes.rs"
    from noomesh import llm_purposes
    assert {llm_purposes.KNOWLEDGE, llm_purposes.GRAPH} == set(re.findall(r'"([^"]+)"', m.group(1)))


def test_v1_chat_completions_routes_on_the_requested_model() -> None:
    src = (ROOT / "gateway-rust/src/routes/inference.rs").read_text()
    handler = src[src.index("async fn openai_chat_completions(") :]
    handler = handler[: handler.index("\n}\n")]
    # the earlier change the handler runs the shared raw-chat path
    # (`routes/raw_chat.rs::chat_completions`) on the caller's body; that
    # path reads the body's `model` as the class/alias/exact-model hint and
    # hands it to the class resolver. The body must reach it unmodified —
    # no `body["model"] = ...` before the call.
    assert re.search(r"raw_chat::chat_completions\(&state,\s*&mut body", handler), (
        "the /v1 proxy must hand the caller's body to raw_chat::chat_completions"
    )
    assert 'body["model"] =' not in handler, "the handler must not overwrite the caller's model before resolution"
    raw = (ROOT / "gateway-rust/src/routes/raw_chat.rs").read_text()
    helper = raw[raw.index("pub async fn chat_completions(") :]
    helper = helper[: helper.index("\n}\n")]
    assert re.search(r'model_hint\(body\.get\("model"\)', helper), "the shared path reads the body's model as the hint"
    assert re.search(r"resolve_candidates\(state,\s*hint\.as_deref\(\),", helper), (
        "the shared path must hand its hint to the class resolver unchanged"
    )
    assert "coordinator::resolve_backend(&state)" not in handler
    assert "coordinator::resolve_backend(state)" not in helper
