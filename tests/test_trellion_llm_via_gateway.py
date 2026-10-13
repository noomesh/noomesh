# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Trellion never dials an LLM backend directly (2026-09-09).

Its graph extraction and answer synthesis go through the gateway's
`/v1/chat/completions`, which resolves the backend over the mesh like every
chat channel and carries the node credential trellion lacks. Two things pin
that: compose points trellion's `PAGEINDEX_LLM_URL` at the gateway (the same
shape as its embedder URL), and the gateway proxy passes the body's `model`
to the resolver as the exact-match hint, so `PAGEINDEX_LLM_MODEL` placed on
a node steers extraction to it while chat keeps its own model elsewhere.
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


def test_trellion_llm_url_is_the_gateway_not_the_worker_pointer() -> None:
    env = _trellion_env()
    assert env["PAGEINDEX_LLM_URL"] == "${NOO_TRELLION_LLM_URL:-https://gateway:8080}"
    assert env["PAGEINDEX_EMBEDDING_URL"] == "${NOO_TRELLION_EMBEDDING_URL:-https://gateway:8080}"
    assert "${PAGEINDEX_LLM_URL" not in env["PAGEINDEX_LLM_URL"], (
        "a worker-side backend URL must never leak into trellion's env — it is container-relative"
    )


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
    assert re.search(r"resolve_candidates\(state,\s*hint\.as_deref\(\)\)", helper), (
        "the shared path must hand its hint to the class resolver unchanged"
    )
    assert "coordinator::resolve_backend(&state)" not in handler
    assert "coordinator::resolve_backend(state)" not in helper
