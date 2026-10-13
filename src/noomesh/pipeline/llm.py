# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Narrow single-shot LLM calls for pipeline capabilities.

Deliberately NOT the agentic loop: this is one prompt in, one (optionally
JSON-schema-constrained) answer out, routed to a chosen backend/model. Small
local models are reliable at this shape; they are not reliable at multi-step
tool orchestration. Guided/structured decoding + a parse-repair fallback make
the output dependable enough to build pipelines on.

Intentionally NOT a third backend abstraction: it always POSTs the gateway's
``/v1/chat/completions`` and lets the gateway/mesh pick the node+backend.
Per-backend metadata lives in ``noomesh.backends``; direct in-process
clients live in ``noomesh.llm``.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx
import structlog

log = structlog.get_logger("pipeline.llm")


def _gateway_url() -> str:
    # NOO_GATEWAY_URL is how the worker container already addresses the
    # gateway (compose sets https://gateway:8080). The 127.0.0.1 fallback was
    # only ever correct while the worker pool ran inside the gateway process;
    # moved it to its own container, that address pointed at
    # nothing and every pipeline llm_call failed with a connect error.
    url = os.getenv("PIPELINE_GATEWAY_URL") or os.getenv("NOO_GATEWAY_URL")
    if url:
        return url.rstrip("/")
    # https always: the gateway has no plaintext listener.
    return f"https://127.0.0.1:{os.getenv('GATEWAY_PORT', '8080')}"


def _extract_json(text: str) -> Any:
    """Best-effort JSON recovery from a model response (repair fallback)."""
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    # Strip code fences.
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except Exception:
            pass
    # First balanced {...} or [...] block.
    for opener, closer in (("{", "}"), ("[", "]")):
        i = text.find(opener)
        j = text.rfind(closer)
        if 0 <= i < j:
            try:
                return json.loads(text[i:j + 1])
            except Exception:
                continue
    raise ValueError("no parseable JSON in model output")


async def llm_call(
    prompt: str,
    *,
    model: Optional[str] = None,
    system: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    json_mode: bool = False,
    timeout: float = 120.0,
) -> Any:
    """One narrow completion. Returns str, or parsed JSON when json_mode.

    ``model`` picks the backend (e.g. the 26B on host8 for synthesis, the 12B
    on the controller for extraction); None uses the cluster default.
    ``json_mode`` requests structured output and returns the parsed object,
    repairing loosely-formatted responses.
    """
    from ..cluster.cluster_auth import internal_gateway_headers

    messages: List[Dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body: Dict[str, Any] = {
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        # Single-shot: the compat endpoint does one completion, no agentic loop.
        "channel": "pipeline",
    }
    if model:
        body["model"] = model
    if json_mode:
        # vLLM + recent llama.cpp honor this; the repair fallback covers the rest.
        body["response_format"] = {"type": "json_object"}
        if "json" not in prompt.lower():
            body["messages"][-1]["content"] += "\n\nRespond with a single JSON object only."

    from .._providers import default_http_context
    hc = default_http_context()
    async with httpx.AsyncClient(timeout=timeout, verify=hc.verify, cert=hc.cert) as client:
        r = await client.post(
            f"{_gateway_url()}/v1/chat/completions",
            json=body,
            headers=internal_gateway_headers("pipeline"),
        )
        r.raise_for_status()
        data = r.json()

    # OpenAI-compat shape; tolerate the gateway's wrapped variants.
    content = ""
    if isinstance(data, dict):
        if data.get("choices"):
            content = (data["choices"][0].get("message") or {}).get("content", "") or ""
        else:
            d = data.get("data", data)
            content = d.get("response") or d.get("text") or d.get("answer") or ""
    content = content or ""

    if json_mode:
        return _extract_json(content)
    return content
