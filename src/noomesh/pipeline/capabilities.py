# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Core reusable capabilities — the harness's composable building blocks.

Deterministic capabilities (kb_query, web_search, fetch_url, kb_ingest) are
plain code — they *happen*, they don't depend on a model choosing to call
them. Model capabilities (model_map, model_reduce) invoke the LLM only for
narrow single-shot work, with routing (cheap model for map, strong model for
reduce) and optional guided JSON. Registering here makes each a named unit any
pipeline can compose.
"""
from __future__ import annotations

from typing import Any, Dict, List

import structlog

from .core import capability, validator
from .llm import llm_call

log = structlog.get_logger("pipeline.cap")


# ── Deterministic capabilities ──────────────────────────────────────────

@capability("kb_query")
async def kb_query(ctx: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Query the PageIndex KB for grounding. config: {question, strategy?}."""
    from ..mcp.tool_models import handle_tool_call
    question = config.get("question") or ""
    if not question:
        return ""
    try:
        return await handle_tool_call("noo_rag_query", {
            "question": question,
            "strategy": config.get("strategy", "hybrid"),
        })
    except Exception as e:  # noqa: BLE001
        log.info("kb_query.failed", error=str(e)[:200])
        return ""


@capability("web_search")
async def web_search(ctx: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, str]]:
    """Deterministic web search → structured results [{title,url,snippet}].

    config: {query | queries, max_results}. Runs the queries itself; the model
    never decides whether to search.
    """
    from noomesh._providers import default_content_moderator
    queries = config.get("queries") or ([config["query"]] if config.get("query") else [])
    max_results = int(config.get("max_results", 5))
    if not queries:
        return []
    try:
        from ddgs import DDGS
    except ImportError:
        log.warning("web_search.no_ddgs")
        return []

    mod = default_content_moderator()
    seen: set = set()
    out: List[Dict[str, str]] = []
    for q in queries:
        try:
            import asyncio
            rows = await asyncio.to_thread(lambda: list(DDGS().text(q, max_results=max_results)))
        except Exception as e:  # noqa: BLE001
            log.info("web_search.query_failed", query=q, error=str(e)[:150])
            continue
        for r in rows:
            url = r.get("href", "")
            if not url or url in seen:
                continue
            seen.add(url)
            title = mod.moderate(r.get("title", ""), source="web_search") or ""
            snippet = (mod.moderate(r.get("body", ""), source="web_search") or "")[:400]
            out.append({"title": str(title).strip(), "url": url, "snippet": str(snippet).strip()})
    return out


@capability("kb_ingest")
async def kb_ingest(ctx: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Ingest a note into the KB (accumulation).

    config: {title, text, source_uri?, roles?}.

    `source_uri` is not decoration. It is the dedup key (`docs.source_uri`)
    AND what `kb_roles` glob-matches to decide a document's audience. This
    capability used to forward only title+text, so every note it wrote landed
    with an empty source_uri — no dedup key, and no provenance for the role
    rules to match, so each one fell through to `kb.default_roles`.

    Measured on the controller 2026-08-16: 211 research notes across THREE
    distinct titles — roughly 70 copies of each, indistinguishable from
    human-authored documents at retrieval time.
    """
    from ..mcp.tool_models import handle_tool_call
    title = config.get("title") or "Note"
    text = config.get("text") or ""
    if not text.strip():
        return "skipped: empty"
    args: Dict[str, Any] = {"title": title, "text": text}
    if config.get("source_uri"):
        args["source_uri"] = config["source_uri"]
    if config.get("roles"):
        args["roles"] = config["roles"]
    return await handle_tool_call("noo_rag_ingest", args)


# ── Model capabilities (narrow, single-shot, routed) ────────────────────

@capability("model_map")
async def model_map(ctx: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """Run a per-item narrow model call over a list (the MAP).

    config: {items (list), prompt_template ('{item}' placeholder), model?,
    temperature?, max_items?}. Each call is single-shot — reliable on small
    local models. Failed items are dropped, not fatal.
    """
    items = config.get("items") or []
    template = config.get("prompt_template") or "{item}"
    model = config.get("model")
    max_items = int(config.get("max_items", 8))
    results: List[str] = []
    for item in items[:max_items]:
        if isinstance(item, dict):
            rendered = template.format(
                item=item.get("snippet") or item.get("text") or str(item),
                title=item.get("title", ""),
                url=item.get("url", ""),
            )
        else:
            rendered = template.format(item=str(item), title="", url="")
        try:
            r = await llm_call(rendered, model=model,
                               temperature=float(config.get("temperature", 0.2)),
                               max_tokens=int(config.get("max_tokens", 300)))
            if r and r.strip():
                results.append(r.strip())
        except Exception as e:  # noqa: BLE001
            log.info("model_map.item_failed", error=str(e)[:150])
    return results


@capability("model_reduce")
async def model_reduce(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synthesize a collection into structured output (the REDUCE).

    config: {inputs (list|str), prior (str grounding), prompt, model?,
    json_mode? (default True), schema_hint?}. Routes to a strong model
    (e.g. the 26B) and returns parsed JSON with a repair fallback.
    """
    inputs = config.get("inputs") or []
    if isinstance(inputs, list):
        joined = "\n".join(f"- {x}" for x in inputs)
    else:
        joined = str(inputs)
    prior = config.get("prior") or ""
    base = config.get("prompt") or (
        "Synthesize the findings below into 4-6 crisp, non-obvious takeaways. "
        "Ground them against what is already known; include only what is NEW or "
        "materially updates prior knowledge."
    )
    schema_hint = config.get("schema_hint") or (
        'Return JSON: {"takeaways": ["...", ...]}'
    )
    prompt = (
        f"{base}\n\n"
        f"## Already known (prior knowledge)\n{prior or '(none)'}\n\n"
        f"## New findings\n{joined or '(none)'}\n\n"
        f"{schema_hint}"
    )
    json_mode = config.get("json_mode", True)
    return await llm_call(
        prompt,
        model=config.get("model"),
        temperature=float(config.get("temperature", 0.3)),
        max_tokens=int(config.get("max_tokens", 1024)),
        json_mode=bool(json_mode),
    )


# ── Reusable validators (quality floors) ────────────────────────────────

@validator("nonempty_list")
def _nonempty_list(value: Any, ctx: Dict[str, Any]):
    ok = isinstance(value, list) and len(value) > 0
    return ok, "" if ok else "empty list"


@validator("has_takeaways")
def _has_takeaways(value: Any, ctx: Dict[str, Any]):
    if not isinstance(value, dict):
        return False, "not a dict"
    tk = value.get("takeaways")
    if not isinstance(tk, list) or len(tk) < 3:
        return False, f"need >=3 takeaways, got {len(tk) if isinstance(tk, list) else 0}"
    if any(not str(t).strip() for t in tk):
        return False, "blank takeaway"
    return True, ""
