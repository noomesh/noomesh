# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Extended tool group declarations (``extended_tool_groups`` in config/tools.json).

Groups list tool *names* plus the query keywords that surface them; full
schemas are resolved at runtime via ``noo_tool_search`` / the MCP catalog.

Transcribed verbatim from the hand-maintained config/tools.json —
``noo tools export`` regenerates that file from these declarations.
"""

from __future__ import annotations

from ..decl import tool_group

tool_group(
    "rag",
    tools=[
        "noo_rag_ingest", "noo_rag_status", "noo_docs_list", "noo_doc_detail",
        "noo_rag_retag", "noo_memory_health",
    ],
    keywords=["ingest", "document", "upload", "rag", "knowledge base", "pageindex", "embed", "index"],
)

tool_group(
    "graph",
    tools=[
        "noo_graph_search_entities",
        "noo_graph_entity_detail",
        "noo_graph_neighbors",
        "noo_graph_stats",
        "noo_graph_navigate",
        "noo_graph_traverse_with_intent",
        "noo_graph_explain_path",
        "noo_graph_semantic_search",
        "noo_graph_classify_intent",
        "noo_graph_search_clusters",
        "noo_graph_extract_relations",
        "noo_graph_run_clustering",
        "noo_graph_clusters_audit",
    ],
    keywords=[
        "graph",
        "entity",
        "entities",
        "relationship",
        "knowledge graph",
        "connected",
        "neighbor",
        "traverse",
        "navigate",
        "cluster",
        "causal",
        "hypothesis",
        "path between",
        "semantic search",
    ],
)

tool_group(
    "agents",
    tools=["noo_agents_collaborate", "noo_workflow_run", "noo_workflow_list", "noo_agentic_inference"],
    keywords=["agent", "collaborate", "workflow", "pipeline", "multi-agent", "team", "orchestrate"],
)

tool_group(
    "cluster",
    tools=["noo_cluster_status", "noo_models_cached", "noo_models_pull", "noo_models_switch"],
    keywords=[
        "cluster",
        "node",
        "gpu",
        "vram",
        "backend",
        "model",
        "pull",
        "switch",
        "swap",
        "change model",
        "status",
        "health",
        "infrastructure",
    ],
)

tool_group(
    "files",
    tools=["local_files"],
    keywords=[
        "file",
        "read",
        "write",
        "directory",
        "folder",
        "path",
        "filesystem",
        "save",
        "store",
        "persist",
        "workspace",
        "markdown file",
        "create file",
    ],
)

tool_group(
    "recall_memory",
    tools=[
        "noo_recall_search",
        "noo_recall_status",
        "noo_recall_archive",
        "noo_recall_traversals",
        "noo_walks_recall",
        "noo_walks_stats",
    ],
    keywords=["recall memory", "video memory", "recall", "past conversation", "remember", "archive", "system 1"],
)

tool_group(
    "coding",
    tools=["noo_coding_task"],
    keywords=["code", "implement", "fix bug", "refactor", "coding task", "claude code"],
)

tool_group(
    "heartbeat",
    tools=[
        "noo_heartbeat_list_tasks",
        "noo_heartbeat_create_task",
        "noo_heartbeat_run_task",
        "noo_heartbeat_status",
    ],
    keywords=["heartbeat", "cron", "scheduled", "briefing", "periodic"],
)

tool_group(
    "channels",
    tools=["noo_channel_list", "noo_channel_list_recipients", "noo_channel_read_messages"],
    keywords=["channel", "telegram", "whatsapp", "google chat", "messaging", "recipient"],
)
