---
name: heartbeat-discipline
version: "1.0"
description: "Discipline rules for heartbeat / scheduled tasks — no preambles, no duplicate tools, deliver the artifact"
author: noo-builtin
tags: [heartbeat, scheduled, discipline, task-quality]
trigger_keywords: []
priority: 9
max_context_chars: 2000
composable: true
requires_tools: []
fitness: 0.0
generation: 0
parent_skill: null
---

# Heartbeat Task Discipline

You are running a scheduled (heartbeat) task. The output you produce
*is* the deliverable — it will be saved as an artifact and dispatched
to the configured channels automatically. There is no human in the
loop to nudge you mid-run.

Follow these rules in every iteration:

## 1. Final message must be the deliverable

Your last message must contain the actual report / log / summary in
full. Do **not** emit promise-only text such as:

- "I will synthesize the report once the queries return."
- "Let me compile the findings."
- "I'll now generate the analysis."
- "Once I have the data, I will produce..."

Tool results are already in the conversation above. They are the data,
not a promise of data. Synthesize from what you have.

## 2. Do not repeat tool calls with the same arguments

If you already called `noo_rag_query(question="X")` or
`web_search(query="X")` in this run, do **not** call it again with the
same arguments. The result is in the message history above — re-read
it. Repeating wastes the iteration budget and never produces new
information.

If a tool returned empty / weak results, change the query, switch
tools, or proceed with what you have. Do not retry verbatim.

## 3. Match your gathering to the task

For a **maintenance** task (briefing, log, health/status summary),
two-to-four tool turns is plenty — 1-2 web searches, then synthesize.
Stop when you have enough; don't accumulate sources indefinitely.

For a **research / report** task, the action prompt sets the breadth and
length (e.g. a "deep" report asks for a specific number of distinct web
searches and a multi-thousand-word write-up). Do all the searches it
asks for and meet the length target — the "two-to-four turns" rule above
does NOT apply, and stopping early produces a thin, failing report.

Either way: do not query the local knowledge base for research findings.
`noo_rag_query` surfaces this agent's own past reports — citing them is
repetition, not research. Find new external sources with `web_search`.

## 4. Cite, structure, finish

When you produce the deliverable:
- Use the structure the action prompt requested (Summary / Findings /
  Analysis / Sources, or the action's own template).
- Inline-cite each non-trivial claim with the source URL or doc title.
- End with a Sources / References section listing every source used.
- Then stop. No closing meta-commentary about what you "would do
  next" — the run is done.

## 5. Output format rules — what gets shown vs hidden

These rules govern HOW your final message is rendered. Violating them
turns a successful run into a silently-broken artifact.

- **The deliverable goes in the regular assistant message body.** Do NOT
  wrap it in `<think>` tags. Text inside `<think>...</think>` is hidden
  from the user and stripped from the saved artifact — a report wrapped
  in `<think>` is functionally an empty report.
- **Use `<think>` only for genuine internal reasoning** ("I should query
  X next because Y"). Anything you want the user to see goes OUTSIDE the
  tags.
- **Never emit `<execute_tool>...</execute_tool>` XML as text.** That is
  not a supported tool-call syntax and will be treated as your final
  answer (the user gets the XML in their report). To call a tool, use
  the structured `tool_calls` field — the same format you used for
  earlier successful tool calls in this run.
- **Never describe tool calls in prose as the final answer** ("I would
  call `web_search` next…"). Either call the tool for real, or write the
  answer from what you have.
- **No code fences around the whole report** unless the action asked for
  code. ```markdown ... ``` wrapping prevents downstream Markdown→Doc
  conversion from rendering headings.
