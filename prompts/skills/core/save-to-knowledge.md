---
name: save-to-knowledge
version: "1.0"
description: "Persist generated content (research, notes, reports) as durable, searchable knowledge via the workspace + RAG pipeline"
author: noo-builtin
tags: [save, store, persist, workspace, knowledge, research, report, notes]
trigger_keywords: [save, store, persist, remember long-term, archive, track long-term, save for later, ingest this, keep this, save the report, add to knowledge, save to workspace, save for future]
priority: 8
max_context_chars: 3000
composable: true
requires_tools: [noo_rag_ingest, local_files, noo_coding_task]
fitness: 0.0
generation: 0
parent_skill: null
---

# Save to Knowledge

You are persisting generated content as durable, searchable knowledge. The
workspace and RAG system play distinct roles:

| Layer | Path / Tool | Purpose |
|-------|-------------|---------|
| Workspace | `/workspace` (mounted at `/mnt/d/AgentWorkspace`) | File-system persistence. Editable, inspectable, NOT auto-indexed. |
| RAG knowledge base | `noo_rag_ingest` | Vector-indexed + graph-extracted. Recalled by `noo_rag_query` on future turns. |

To make content truly retrievable, you MUST do both: write to the workspace AND ingest into RAG.

## The canonical save workflow

When the user asks to "save", "store", "persist", "add to knowledge", or
similar — follow these steps in order:

### 1. Decide the filename and location

- Use `/workspace/<descriptive-slug>.md` for research/notes/reports
- Slug = kebab-case topic (e.g. `agentic-ai-world-models.md`)
- If the user specifies a folder or name, honor it

### 2. Write the content to the workspace file

Use `local_files` with `write` action:
```
local_files(action="write", path="/workspace/<slug>.md", content=<full markdown>)
```

Include a small frontmatter block so the file is self-describing:
```markdown
---
title: <descriptive title>
saved_at: <ISO timestamp if known, else leave blank>
source: <"user-synthesized" | "web_search" | "conversation">
topic: <topic string>
---

# <title>

<content>
```

### 3. Ingest into the RAG knowledge base

```
noo_rag_ingest(source="/workspace/<slug>.md", title="<same title>")
```

Always pass `source` as the file path (not raw `text`) so dedup and
source-URI tracking work correctly. If ingestion returns a doc_id,
include it in your confirmation message.

### 4. Confirm to the user

Report back with:
- The filename written
- Whether RAG ingestion succeeded
- How to retrieve: "search with `noo_rag_query` using keywords like ..."

Example confirmation:
> Saved `agentic-ai-world-models.md` to workspace and ingested into
> knowledge base. You can now retrieve this with queries like
> "what do we know about agentic AI world models?".

## When to use `text=` instead of `source=`

If the content is small (< 1000 chars) and you don't need a file on disk,
use `noo_rag_ingest(text=..., title=...)` directly. But for anything
substantial — reports, research synthesis, multi-paragraph notes —
always write to workspace first. A file on disk is inspectable, editable,
and can be re-ingested later if the content is updated.

## Naming and deduplication

- RAG deduplicates on `source_uri` and SHA-256 content hash
- If you re-save the same content to the same path, it will be detected
  as a duplicate — that's fine; confirm the existing doc_id is used
- If updating content, write to the same path to maintain dedup identity

## Related patterns

- **Ingest existing files** (not generated now): use the `rag-expert` skill
- **Just reference something later in THIS conversation**: don't save to
  knowledge base; the conversation is already in noo_entries and will
  be recalled semantically
- **Save a web article**: scrape with web_search / browser, synthesize
  markdown, then use this skill
