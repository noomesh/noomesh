# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Research pipeline — the first composition of the capability toolbox.

Flow (code-driven; the model never orchestrates):

    kb_query      ground against prior KB notes on the theme
    web_search    deterministic search over generated queries
    model_map     per-source fact extraction        (cheap model, e.g. 12B)
    model_reduce  synthesize facts+prior → takeaways (strong model, e.g. 26B; guided JSON)
    research_note format markdown + save to file
    kb_ingest     accumulate the note into the KB

Robustness comes from the shape, not the model: search happens in code, each
model call is single-shot, the reduce is quality-floored + retried, and no
step depends on the model deciding to act. No cloud dependency.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from .core import Pipeline, Step, capability, run_pipeline

log = structlog.get_logger("pipeline.research")

# Defaults — swappable via config. map = cheap extraction, reduce = strong synth.
DEFAULT_MAP_MODEL = os.getenv("RESEARCH_MAP_MODEL", "google/gemma-4-12B-it-qat-w4a16-ct")
DEFAULT_REDUCE_MODEL = os.getenv("RESEARCH_REDUCE_MODEL", "gemma-4-26B_q4_0-it.gguf")

_EXTRACT_TEMPLATE = (
    "From the web search result below about the research topic, extract 1-3 "
    "specific, factual points (numbers, names, releases, claims). Ignore fluff "
    "and ads. If nothing substantive, reply 'NONE'.\n\n"
    "Title: {title}\nURL: {url}\nContent: {item}\n\nFacts:"
)


def _slug(topic: str) -> str:
    """Topic -> a stable, filesystem/URI-safe fragment for source_uri.

    Lowercased, non-alphanumerics collapsed to `-`, trimmed. Stability is the
    whole point: the same topic must produce the same slug on every run or
    the dedup key changes and duplicates come back.
    """
    import re
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", topic.lower())).strip("-")[:80] or "topic"


@capability("research_note")
async def research_note(ctx: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Format the synthesis into a dated markdown note and save it to file.

    config: {topic, synthesis (dict with 'takeaways'), sources (list),
    workspace_dir}. Returns the note text (for the ingest step).
    """
    topic = config.get("topic") or "topic"
    synthesis = config.get("synthesis") or {}
    sources = config.get("sources") or []
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    takeaways = synthesis.get("takeaways") if isinstance(synthesis, dict) else None
    takeaways = takeaways or []

    lines = [f"# Research note: {topic}", f"_{date_str} (structured_research)_", ""]
    lines.append("## Takeaways")
    for t in takeaways:
        lines.append(f"- {t}")
    if sources:
        lines.append("\n## Sources")
        for s in sources[:8]:
            if isinstance(s, dict):
                lines.append(f"- [{s.get('title','')}]({s.get('url','')})")
    note = "\n".join(lines)

    workspace = config.get("workspace_dir") or _default_research_dir()
    try:
        os.makedirs(workspace, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in topic)[:40]
        path = os.path.join(workspace, f"research-{safe}-{date_str}.md")
        with open(path, "w") as f:
            f.write(note)
        ctx["note_path"] = path
        log.info("research_note.saved", path=path, takeaways=len(takeaways))
    except Exception as e:  # noqa: BLE001
        log.info("research_note.save_failed", error=str(e)[:150])
    return note


def _default_research_dir() -> str:
    root = os.getenv("NOO_DATA_DIR", "/data")
    return os.path.join(root, "research")


def _queries_for(topic: str) -> List[str]:
    """Deterministic query generation — no model needed for this."""
    year = datetime.now(timezone.utc).year
    return [
        f"{topic} latest developments",
        f"{topic} {year} news",
        f"{topic} recent research",
    ]


def build_research_pipeline(
    topic: str,
    *,
    map_model: Optional[str] = None,
    reduce_model: Optional[str] = None,
    max_results: int = 4,
    workspace_dir: Optional[str] = None,
) -> Pipeline:
    """Compose the research pipeline for a topic."""
    map_model = map_model or DEFAULT_MAP_MODEL
    reduce_model = reduce_model or DEFAULT_REDUCE_MODEL
    return Pipeline(
        name=f"research:{topic[:40]}",
        steps=[
            Step(
                name="ground",
                capability="kb_query",
                config={"question": f"What do we already know about {topic}?"},
                output="prior",
                on_error="continue",
            ),
            Step(
                name="search",
                capability="web_search",
                config={"queries": _queries_for(topic), "max_results": max_results},
                output="sources",
                validate="nonempty_list",
                retries=1,
                on_error="continue",
            ),
            Step(
                name="extract",
                capability="model_map",
                config={"prompt_template": _EXTRACT_TEMPLATE, "model": map_model, "max_items": 8},
                inputs={"items": "sources"},
                output="facts",
                on_error="continue",
            ),
            Step(
                name="synthesize",
                capability="model_reduce",
                config={
                    "model": reduce_model,
                    "prompt": (
                        f"You are producing a research note on: {topic}. Synthesize "
                        "the extracted findings into 4-6 crisp, non-obvious takeaways. "
                        "Prefer concrete facts (names, numbers, releases). Include only "
                        "what is NEW relative to prior knowledge."
                    ),
                },
                inputs={"inputs": "facts", "prior": "prior"},
                output="synthesis",
                validate="has_takeaways",
                retries=2,
                on_error="stop",
            ),
            Step(
                name="note",
                capability="research_note",
                config={"topic": topic, "workspace_dir": workspace_dir},
                inputs={"synthesis": "synthesis", "sources": "sources"},
                output="note_text",
            ),
            Step(
                name="ingest",
                capability="kb_ingest",
                config={
                    "title": f"Research note: {topic}",
                    # Provenance, and therefore BOTH the dedup key and the
                    # role rule that matches. Scoped per topic per DAY: a
                    # stable `research://<slug>` would collapse the whole
                    # history into one row, and no key at all is what
                    # produced 211 notes across three titles. A day is the
                    # granularity the scheduled runs actually differ at.
                    "source_uri": f"research://{_slug(topic)}/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
                    # `generated` ALONE, deliberately. It is not in any
                    # reader's default audience, so these notes drop out of
                    # ordinary retrieval and come back only when asked for by
                    # name (`roles: ["generated"]`, permitted in
                    # kb._resolve_kb_roles). That is the point: an agent doing
                    # new research should not rediscover its own summary of
                    # yesterday.
                    "roles": ["generated"],
                },
                inputs={"text": "note_text"},
                output="ingest_result",
                on_error="continue",
            ),
        ],
    )


async def run_research(
    topic: str,
    *,
    map_model: Optional[str] = None,
    reduce_model: Optional[str] = None,
    workspace_dir: Optional[str] = None,
    max_results: int = 4,
) -> str:
    """Run one research cycle. Returns a short human summary."""
    # Ensure capabilities are registered.
    from . import capabilities  # noqa: F401

    pipeline = build_research_pipeline(
        topic, map_model=map_model, reduce_model=reduce_model,
        max_results=max_results, workspace_dir=workspace_dir,
    )
    result = await run_pipeline(pipeline)
    ctx = result.ctx
    synthesis = ctx.get("synthesis") or {}
    takeaways = synthesis.get("takeaways") if isinstance(synthesis, dict) else []
    takeaways = takeaways or []
    n_sources = len(ctx.get("sources") or [])
    note_path = ctx.get("note_path", "")

    log.info("run_research.done", topic=topic, ok=result.ok,
             takeaways=len(takeaways), sources=n_sources, summary=result.summary())

    # A stop-step failure (synthesize) means nothing was produced: no note, no
    # ingest. Raise so the heartbeat records the run as an error instead of
    # returning the failure text as a "success" summary — that mislabeling hid
    # a month of dead feeds (every llm_call failing) behind green run rows.
    if not result.ok:
        raise RuntimeError(f"structured_research [{topic}] produced nothing — {result.summary()}")

    head = (
        f"structured_research [{topic}]: OK — "
        f"{len(takeaways)} takeaways from {n_sources} sources"
        + (f", saved {note_path}" if note_path else "")
    )
    if takeaways:
        head += "\nTop takeaway: " + str(takeaways[0])[:200]
    return head
