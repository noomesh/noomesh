# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Core tool declarations (``core_tools`` in config/tools.json).

These are the tools the LLM always sees. Execution routing: the Rust
coordinator executes the natively ported core tools in-process first
(``gateway-rust/src/tools.rs execute_native``); for the
rest, ``nats_subject`` sends the call to the matching ``@worker_handler``
in ``noomesh/workers/tools.py``, and declarations without a subject
fall back to ``worker.tool.generic``
(see ``get_tool_nats_subject`` in gateway-rust/src/coordinator/backend.rs).

Transcribed verbatim from the hand-maintained config/tools.json —
``noo tools export`` regenerates that file from these declarations.
"""

from __future__ import annotations

from ..decl import tool

tool(
    name="noo_tool_search",
    description=(
        "Search for additional tools by capability. Returns tool names and "
        "descriptions. Use this first when you need a tool not in your current set."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What capability you're looking for"},
        },
        "required": ["query"],
    },
    tags=["core", "discovery"],
    speed="fast",
)

tool(
    name="noo_rag_query",
    description=(
        "Search your internal knowledge base for information. ALWAYS try this "
        "BEFORE web_search — it contains ingested documents, research papers, "
        "and notes. Returns relevant text with source citations."
    ),
    parameters={
        "type": "object",
        "properties": {
            "question": {"type": "string", "description": "The question to search for"},
            "strategy": {
                "type": "string",
                "enum": ["hybrid", "vector", "graph_first", "lookup"],
                "description": "Search strategy (default: hybrid)",
            },
        },
        "required": ["question"],
    },
    tags=["core", "rag", "knowledge"],
    speed="fast",
    # No nats_subject: executed natively by the Rust coordinator
    # (gateway-rust/src/tools.rs execute_native).
)

tool(
    name="noo_inference",
    description="Run a prompt through the local LLM for reasoning, analysis, or generation.",
    parameters={
        "type": "object",
        "properties": {
            "prompt": {"type": "string", "description": "The prompt to run"},
            "model": {"type": "string", "description": "Model name (optional, uses default)"},
            "max_tokens": {"type": "integer", "description": "Max tokens to generate"},
        },
        "required": ["prompt"],
    },
    tags=["core", "inference"],
    speed="slow",
    # No nats_subject: executed natively by the Rust coordinator.
)

tool(
    name="noo_memory_search",
    description=(
        "Search conversation memory for relevant past interactions. Check this "
        "alongside noo_rag_query for context before using external tools."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "top_k": {"type": "integer", "description": "Max results (default 5)"},
        },
        "required": ["query"],
    },
    tags=["core", "memory"],
    speed="fast",
    # No nats_subject: executed natively by the Rust coordinator.
)

tool(
    name="web_search",
    description=(
        "Search the public internet. Use ONLY when noo_rag_query returns no "
        "results or when you need real-time/current information not in the "
        "knowledge base."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "max_results": {"type": "integer", "description": "Max results (default 5)"},
        },
        "required": ["query"],
    },
    tags=["core", "web"],
    speed="fast",
    # No nats_subject: executed natively by the Rust coordinator
    # (gateway-rust/src/web_search.rs).
)

tool(
    name="noo_channel_send",
    description="Send a message to an external channel (Google Chat, Telegram, etc.).",
    parameters={
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "description": "Channel name (google_chat, telegram, etc.)",
            },
            "recipient": {"type": "string", "description": "Recipient ID or name"},
            "message": {"type": "string", "description": "Message text"},
        },
        "required": ["channel", "message"],
    },
    tags=["core", "channels"],
    speed="fast",
    # No nats_subject: executed natively by the Rust coordinator.
)

tool(
    name="python_tool",
    description=(
        "Execute Python code for calculations, data processing, or analysis. "
        "Runs in a sandboxed environment."
    ),
    parameters={
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code to execute"},
        },
        "required": ["code"],
    },
    tags=["core", "compute"],
    speed="fast",
    nats_subject="worker.tool.python",
)
