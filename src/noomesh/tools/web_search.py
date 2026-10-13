# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

from typing import Dict

from .base import ToolSpec


def build_web_search_tool(provider: str = "duckduckgo", max_results: int = 5) -> ToolSpec:
    return ToolSpec(
        name="web_search",
        description="Search the web for recent, factual information.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query."},
                "max_results": {
                    "type": "integer",
                    "description": "Max results to return.",
                },
            },
            "required": ["query"],
        },
        handler=lambda args: _search_web(args, provider, max_results),
    )


def _sanitize(text: str) -> str:
    """Moderate search snippet through the injected ContentModerator
    provider."""
    if not text:
        return ""
    from noomesh._providers import default_content_moderator
    cleaned = default_content_moderator().moderate(text, source="web_search")
    return cleaned.strip() if isinstance(cleaned, str) else ""


def _search_web(args: Dict, provider: str, max_results: int) -> str:
    query = args.get("query")
    if not query:
        return "Error: 'query' is required."
    limit = int(args.get("max_results") or max_results)

    if provider != "duckduckgo":
        return f"Error: Unsupported provider '{provider}'."

    try:
        from ddgs import DDGS
    except ImportError:
        return "Error: ddgs not installed. Install with 'pip install ddgs'."

    try:
        ddgs = DDGS()
        results = list(ddgs.text(query, max_results=limit))
    except Exception as e:
        return f"Search error: {e}"

    if not results:
        return "No results found."

    lines = []
    for r in results:
        title = _sanitize(r.get("title", ""))
        url = r.get("href", "")
        snippet = _sanitize(r.get("body", ""))[:300]
        lines.append(f"- {title}\n  {url}\n  {snippet}")
    return "\n".join(lines)
