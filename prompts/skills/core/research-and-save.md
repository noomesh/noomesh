---
name: research-and-save
version: "1.0"
description: "Multi-source research that persists the output as durable, searchable knowledge"
author: noo-builtin
tags: [research, synthesis, save, persist, workspace, rag, report]
trigger_keywords: [research and save, research report, produce a report, comprehensive report, detailed report, save the report, write a report and, research this and save, synthesize and store]
priority: 9
max_context_chars: 3000
composable: true
requires_tools: [web_search, noo_rag_query, local_files, noo_rag_ingest]
fitness: 0.0
generation: 0
parent_skill: null
---

# Research and Save

You are conducting research AND persisting the output for future
retrieval. This combines two patterns — research-synthesis (gather)
and save-to-knowledge (persist) — into one end-to-end workflow.

Use this when the user asks for a "report", "research and save",
"comprehensive analysis", or anything that implies the output should
live beyond the current turn.

## End-to-end workflow

### Phase 1: Gather

1. **Check internal knowledge first**:
   ```
   noo_rag_query(question="<topic>", strategy="hybrid")
   ```
   This is fast (~5s) and often provides foundational context.

2. **Supplement with web** if the topic requires current information:
   ```
   web_search(query="<focused search term>")
   ```
   Run 2-4 targeted searches, not one broad one. Cover: definitions,
   mechanisms, recent developments, implications.

3. **Stop gathering** when you have enough for the requested depth.
   Don't accumulate indefinitely — 5-8 good sources beat 20 mediocre ones.

### Phase 2: Synthesize

Produce the report in markdown with:
- Clear title (H1)
- Structured sections the user requested (or default: Summary /
  Background / Analysis / Implications / References)
- Inline citations: `[Source: <name or URL>]`
- A "References" section at the bottom listing every source used

Quality over length — if the user said "1500+ words", aim for ~1800 to
comfortably clear the floor without padding.

### Phase 3: Persist (this is what makes this skill different)

1. **Write to workspace**:
   ```
   local_files(action="write",
               path="/workspace/<topic-slug>.md",
               content=<full markdown with frontmatter>)
   ```

   Include frontmatter:
   ```markdown
   ---
   title: <Report Title>
   topic: <topic string>
   saved_at: <date if known>
   sources_count: <N>
   ---

   # <Report Title>
   ...
   ```

2. **Ingest into RAG**:
   ```
   noo_rag_ingest(source="/workspace/<topic-slug>.md",
                  title="<Report Title>")
   ```

3. **Report back**:
   - Include the full synthesized report in the response (not just a
     link) so the user sees it inline
   - Mention where it was saved and that it's now searchable:
     > Saved to `/workspace/<slug>.md` and indexed. Retrieve later
     > with queries about "<key terms>".

## Important

- **Do not skip persistence** for a research task, even if the user
  didn't explicitly say "save it". The whole point of a report is
  future reference.
- **Do the synthesis once, persist once**. Don't ingest the same content
  twice — content-hash dedup will reject duplicates anyway, but it's
  wasted work.
- **Cite, don't fabricate**. If web_search returned a source, cite the
  URL. If RAG returned a doc, cite the title. If you can't verify a
  claim, say so rather than inventing a reference.
