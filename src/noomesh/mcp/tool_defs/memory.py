# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Conversation memory and recall memory (System 1) tools."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


# ═══════════════════════════════════════════════════════════════
# Conversation Memory
# ═══════════════════════════════════════════════════════════════


@register
class ConversationPublish(ToolDef):
    """Publish a source conversation entry, session ending or deletion to your
    own conversation memory. Infrastructure import: preserves original words,
    roles and source IDs; assistant dialogue is not verified action evidence.
    Version 1 publications are idempotent and deletion prevents late replays."""

    name: ClassVar[str] = "noo_conversation_publish"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/conversations/import"
    tags: ClassVar[List[str]] = ["memory", "conversation", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    publication: dict = Field(description="Conversation publication v1 with publisher_id, event_id, conversation_id and operation (entry, session_end, delete).")


@register
class PaiMemorySearch(ToolDef):
    """Search conversation memory for past interactions. Returns semantically
    similar conversations ranked by relevance. Use this for recalling previous
    chats, decisions, and context — NOT for document/knowledge base queries."""

    name: ClassVar[str] = "noo_memory_search"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/memory/search"
    tags: ClassVar[List[str]] = ["memory", "conversation", "external"]

    query: str = Field(description="Search query for conversation memory")
    top_k: int = Field(default=5, description="Number of results to return")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            context = data.get("context")
            if context is not None:
                return str(context)
        return super().format_response(data)


@register
class PaiConversationContext(ToolDef):
    """Retrieve recent conversation context from the coordinator. Returns a
    summary of recent interactions, useful for maintaining continuity across
    sessions and channels."""

    name: ClassVar[str] = "noo_conversation_context"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/coordinator/context"
    tags: ClassVar[List[str]] = ["memory", "conversation", "context", "external"]

    limit: Optional[int] = Field(default=None, description="Maximum number of recent messages to include")
    channel: Optional[str] = Field(default=None, description="Filter context by channel (e.g. 'telegram', 'whatsapp')")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            summary = data.get("summary")
            if summary is not None:
                return str(summary)
        return super().format_response(data)


# ═══════════════════════════════════════════════════════════════
# Recall Memory (System 1)
# ═══════════════════════════════════════════════════════════════


@register
class PaiRecallSearch(ToolDef):
    """Search recall memory (System 1 compressed semantic recall). Returns
    records stored as QR-encoded MP4 frames, ranked by prominence and
    relevance. Use for fast associative recall of past knowledge."""

    name: ClassVar[str] = "noo_recall_search"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/recall/search"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]

    query: str = Field(description="Search query for recall memory")
    top_k: int = Field(default=5, description="Number of results to return")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        records = data.get("records") or data.get("results") or []
        if not records:
            return "No recall memory records found."
        lines = [f"Found {len(records)} record(s):"]
        for r in records:
            text = r.get("text") or r.get("content", "")
            score = r.get("score") or r.get("prominence", "")
            preview = text[:120] + ("..." if len(text) > 120 else "")
            bullet = f"  - {preview}"
            if score:
                bullet += f"  (score: {score})"
            lines.append(bullet)
        return "\n".join(lines)


@register
class PaiRecallTraversals(ToolDef):
    """Perform recall traversals across recall memory indices. Walks the
    knowledge graph to find related memories using semantic proximity and
    entity co-occurrence. Returns traversal paths and the strategy used."""

    name: ClassVar[str] = "noo_recall_traversals"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/recall-traversals"
    tags: ClassVar[List[str]] = ["memory", "recall_memory", "graph"]

    query: str = Field(description="Query to drive recall traversal")
    intent: Optional[str] = Field(default=None, description="Optional intent hint to guide traversal strategy")
    top_k: int = Field(default=3, description="Number of traversal results to return")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        strategy = data.get("strategy", "unknown")
        traversals = data.get("traversals") or data.get("results") or []
        lines = [f"Strategy: {strategy}", f"Traversals ({len(traversals)}):"]
        for t in traversals:
            text = t.get("text") or t.get("content", "")
            score = t.get("score", "")
            path = t.get("path", "")
            preview = text[:120] + ("..." if len(text) > 120 else "")
            bullet = f"  - {preview}"
            if score:
                bullet += f"  (score: {score})"
            if path:
                bullet += f"  [path: {path}]"
            lines.append(bullet)
        return "\n".join(lines)


@register
class PaiWalksRecall(ToolDef):
    """Recall YOUR OWN saved graph threads: the knowledge-graph walks your past
    questions followed, saved automatically when you are signed in (turn saving
    off per account with `noo walks settings --save off`). With a query, returns
    the threads nearest it, re-checked against the graph today: a walk through
    something you can no longer read, an edge that was removed, a deleted
    document or a superseded fact is dropped, never served stale. Without a
    query, your most recent threads. Only ever your own, verbatim; never
    another user's."""

    name: ClassVar[str] = "noo_walks_recall"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/walks"
    tags: ClassVar[List[str]] = ["memory", "graph", "external"]

    # `serialization_alias`: the route reads `q`; the client passes `query`.
    query: Optional[str] = Field(
        default=None,
        serialization_alias="q",
        description="What to recall against; omit to list your most recent threads",
    )
    top_k: int = Field(default=5, description="Number of threads to return")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        walks = data.get("walks") or []
        if not walks:
            return "No saved threads."
        lines = [f"Your threads ({len(walks)}):"]
        for w in walks:
            u = w.get("usefulness")
            score = f"  (usefulness {u:.2f})" if isinstance(u, (int, float)) else ""
            path = " -> ".join(str(s.get("entity_name") or "?") for s in (w.get("path") or []))
            lines.append(f"  - {w.get('query', '')}{score}  [{path}]  id={w.get('id', '')}")
        return "\n".join(lines)


@register
class PaiWalksStats(ToolDef):
    """COUNTS of users' saved graph threads (by kind and status, per account, and
    how many accounts turned saving off). Operator door only. Counts never
    include a question, a path or an entity name: reading what a user asked is
    the Admin-only, audited view."""

    name: ClassVar[str] = "noo_walks_stats"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/walks/stats"
    tags: ClassVar[List[str]] = ["memory", "graph", "status"]

    user: Optional[str] = Field(default=None, description="Narrow the counts to one account")


@register
class PaiRecallStatus(ToolDef):
    """Check recall memory subsystem health: index count, total records,
    storage size, and lifecycle state."""

    name: ClassVar[str] = "noo_recall_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/recall/status"
    tags: ClassVar[List[str]] = ["memory", "recall_memory", "status"]


@register
class PaiRecallArchive(ToolDef):
    """Trigger recall memory archival. Compresses active memory records into
    MP4-encoded video frames for long-term storage."""

    name: ClassVar[str] = "noo_recall_archive"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/recall/archive"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            message = data.get("message")
            if message is not None:
                return str(message)
        return super().format_response(data)


@register
class PaiRecallVideos(ToolDef):
    """List all recall memory index files with sizes and metadata."""

    name: ClassVar[str] = "noo_recall_videos"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/recall/videos"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        videos = data.get("videos") or data.get("files") or []
        if not videos:
            return "No recall memory files found."
        lines = [f"Recall memory files ({len(videos)}):"]
        for v in videos:
            name = v.get("name") or v.get("filename", "?")
            size = v.get("size") or v.get("size_bytes", 0)
            if isinstance(size, (int, float)) and size > 0:
                if size >= 1_048_576:
                    size_str = f"{size / 1_048_576:.1f} MB"
                elif size >= 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} B"
            else:
                size_str = str(size)
            records = v.get("records") or v.get("record_count", "")
            bullet = f"  - {name} ({size_str})"
            if records:
                bullet += f" — {records} records"
            lines.append(bullet)
        return "\n".join(lines)


@register
class PaiRecallLifecycle(ToolDef):
    """Run recall memory lifecycle management. Evaluates prominence scores,
    demotes low-prominence records, and consolidates storage."""

    name: ClassVar[str] = "noo_recall_lifecycle"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/recall/lifecycle"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        lines = ["Lifecycle results:"]
        for key, value in data.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)


@register
class PaiRecallLifecycleStats(ToolDef):
    """Get recall memory lifecycle statistics: prominence distribution,
    demotion counts, storage metrics, last run timestamps."""

    name: ClassVar[str] = "noo_recall_lifecycle_stats"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/recall/lifecycle-stats"
    tags: ClassVar[List[str]] = ["memory", "recall_memory", "status"]


@register
class PaiRecallRefresh(ToolDef):
    """Refresh recall memory FAISS indices. Rebuilds search indices from the
    underlying MP4 video files to ensure search consistency."""

    name: ClassVar[str] = "noo_recall_refresh"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/recall/refresh"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            message = data.get("message")
            if message is not None:
                return str(message)
        return super().format_response(data)


@register
class PaiRecallLifecyclePreview(ToolDef):
    """Preview recall memory lifecycle actions without executing them. Shows
    which records would be demoted, consolidated, or archived in a dry run."""

    name: ClassVar[str] = "noo_recall_lifecycle_preview"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/recall/lifecycle-preview"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        actions = data.get("actions") or data.get("preview") or []
        if isinstance(actions, list):
            if not actions:
                return "Lifecycle preview: no actions pending."
            lines = [f"Lifecycle preview ({len(actions)} action(s)):"]
            for a in actions:
                action_type = a.get("action") or a.get("type", "?")
                target = a.get("record_id") or a.get("target", "?")
                reason = a.get("reason", "")
                bullet = f"  - {action_type}: {target}"
                if reason:
                    bullet += f" ({reason})"
                lines.append(bullet)
            return "\n".join(lines)
        # Fallback: format as key-value pairs if not a list
        lines = ["Lifecycle preview:"]
        for key, value in data.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)


@register
class PaiRecallProminent(ToolDef):
    """Retrieve the most prominent recall memory records. Prominence is a
    composite score based on recency, quality, access frequency, and
    durability. Useful for understanding what the system considers most
    salient."""

    name: ClassVar[str] = "noo_recall_prominent"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/recall/prominent"
    tags: ClassVar[List[str]] = ["memory", "recall_memory"]

    top_k: int = Field(default=5, description="Number of prominent records to return")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        records = data.get("records") or data.get("results") or []
        if not records:
            return "No prominent records found."
        lines = [f"Top {len(records)} prominent record(s):"]
        for r in records:
            text = r.get("text") or r.get("content", "")
            prominence = r.get("prominence") or r.get("score", "")
            preview = text[:120] + ("..." if len(text) > 120 else "")
            bullet = f"  - {preview}"
            if prominence:
                bullet += f"  (prominence: {prominence})"
            lines.append(bullet)
        return "\n".join(lines)
