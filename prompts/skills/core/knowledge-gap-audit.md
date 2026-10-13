---
name: knowledge-gap-audit
version: "1.0"
description: "Evaluate whether the knowledge base covers a topic and set up tracking if gaps exist"
author: noo-builtin
tags: [audit, evaluate, track, gap, coverage, knowledge, rag]
trigger_keywords: [do we have, what do we know about, evaluate if we have, can we track, start tracking, any documents on, knowledge gap, coverage check, do we cover, knowledge check]
priority: 7
max_context_chars: 3000
composable: true
requires_tools: [noo_rag_query, noo_rag_status, web_search, noo_rag_ingest, local_files]
fitness: 0.0
generation: 0
parent_skill: null
---

# Knowledge Gap Audit

You are evaluating whether the knowledge base has useful coverage of a
topic, and if not, setting up tracking. This runs when the user asks
"do we have X?", "can we track Y?", or "what do we know about Z?"

## The audit workflow

### 1. Probe the knowledge base

```
noo_rag_query(question="<topic phrased as a question>", strategy="hybrid")
```

Assess the result honestly:
- **Strong coverage**: multiple citations, directly answers the query
- **Tangential coverage**: related but not exact (e.g. foundational docs,
  older terminology)
- **No coverage**: no citations or irrelevant matches

### 2. Report the finding clearly

State explicitly what was found and what's missing. Don't pad weak
results. Example:
> Found 2 foundational documents on model-based planning (from a 2018
> RL textbook), but nothing covering modern LLM-based agentic systems
> or the 2024-2026 literature.

### 3. Propose a tracking plan (if gaps exist)

When coverage is weak or missing, propose concrete tracking:

**Web discovery**: find current sources via web_search
```
web_search(query="<topic> research papers 2026")
```

**Source selection**: identify 3-5 high-quality sources. Prefer:
- arXiv/academic papers over blog posts
- Official project docs over third-party summaries
- Well-cited review articles for breadth

**Ingestion options**:
- Has a PDF/URL? `noo_rag_ingest(source=<url_or_path>)`
- Only web articles? Use the `save-to-knowledge` skill pattern:
  write synthesized markdown to `/workspace/<slug>.md` then ingest
- User wants to review before ingest? List the sources and ask

### 4. Confirm and set up periodic refresh (optional)

If the topic is evolving (AI, security, news), suggest a heartbeat task
to re-search periodically. For stable topics (math, history), one-time
ingestion is enough.

## What this skill does NOT do

- Generate a research report (use `research-synthesis` for that)
- Edit existing documents (use `file-operations`)
- Summarize what's already in the KB (just answer with `noo_rag_query`)

The knowledge gap audit is specifically the **meta-check**: "is our
knowledge base covering this?" followed by closing the gap if needed.
