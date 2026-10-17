# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""RAG / PageIndex knowledge base tools."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import (
    AuthLevel, HttpMethod, RiskLevel, ToolDef, register,
)
from .ops import ASYNC_NOTE


@register
class PaiRagQuery(ToolDef):
    """Answer a question using the PageIndex knowledge base (ingested documents).
    Uses vector search + knowledge graph to find relevant pages, then synthesizes
    an answer with [Source N] citations. Strategies: 'hybrid' (default, best quality),
    'lookup' (fast vector-only), 'graph_first' (entity-centric).
    Use this for factual questions about ingested content — NOT for conversation history."""

    name: ClassVar[str] = "noo_rag_query"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/rag/query"
    tags: ClassVar[List[str]] = ["core", "rag", "knowledge", "external"]
    nats_subject: ClassVar[str] = "worker.tool.noo"

    question: str = Field(description="The question to answer from the knowledge base")
    strategy: str = Field(default="hybrid", description="Search strategy: hybrid, lookup, graph_first")
    roles: Optional[List[str]] = Field(
        default=None,
        description="KB role scope, e.g. ['system'] for ops runbooks, "
                    "['user:alice'] for a user's docs, ['company'] org-wide. "
                    "Omit for the caller's default scope.",
    )

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        parts = [data.get("answer", "")]
        citations = data.get("citations")
        if citations:
            parts.append("\nSources:")
            for c in citations:
                title = c.get("title", "?")
                page = c.get("page_no", "?")
                parts.append(f"  - [{title}] page {page}")
        strategy = data.get("strategy_used")
        if strategy:
            parts.append(f"\n(strategy: {strategy})")
        return "\n".join(parts)


@register
class PaiRagIngest(ToolDef):
    """Ingest documents (PDF/MD/HTML/TXT/JSON/CSV/XML/code) into PageIndex.
    Splits into pages, embeds, and indexes for RAG search."""

    name: ClassVar[str] = "noo_rag_ingest"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/docs/ingest"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    tags: ClassVar[List[str]] = ["rag", "ingest", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    parallelizable: ClassVar[bool] = False
    # Operation-backed route (docs.ingest): a few seconds' wait, then an op handle.
    timeout_secs: ClassVar[int] = 60

    source: Optional[str] = Field(default=None, description="ONE file already on the server, inside a directory an operator "
                    "allowed (tools.allowed_paths or a watched folder); symlinks are "
                    "followed and the service's own secrets/config are never allowed. "
                    "URLs, directories and globs are refused: to ingest a web page or "
                    "pasted content, send it as `text`.")
    text: Optional[str] = Field(default=None, description="Raw text to ingest directly (stored as text, never read as a path)")
    title: Optional[str] = Field(default=None, description="Document title")
    roles: Optional[List[str]] = Field(
        default=None,
        description="Audience tags stored in metadata.roles, e.g. ['system'] "
                    "(ops knowledge), ['company'] (all users), ['user:<name>'].",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            msg = data.get("message", "")
            doc_id = data.get("doc_id", "unknown")
            return msg or f"Document ingested: doc_id={doc_id}"
        return str(data)


@register
class PaiRagStatus(ToolDef):
    """Check PageIndex health: embedder state, doc/page/entity counts, unembedded items."""

    name: ClassVar[str] = "noo_rag_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/rag/status"
    tags: ClassVar[List[str]] = ["rag", "status"]


@register
class PaiMemoryHealth(ToolDef):
    """Unified health check across conversation memory, PageIndex, knowledge graph,
    recall memory. Returns A-F grade per subsystem."""

    name: ClassVar[str] = "noo_memory_health"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/memory/health"
    tags: ClassVar[List[str]] = ["rag", "memory", "health"]


@register
class PaiDocsList(ToolDef):
    """List ingested documents, newest first: titles, doc IDs, source URIs, ingestion
    timestamps. Paged with limit (default 200, max 2000) and offset. For an operator/admin
    each item also carries `roles` (its audience tags; null = untagged, readable by
    admins only), and summary=true returns {docs, summary} where summary is
    {total, untagged, by_audience} counted over ALL documents, not just the page.
    Operator/admin items also carry `provenance` ({by, via, at} of the first ingest; null =
    unknown) and `audience_history_len`. Review filters (applied to the listing AND the
    summary): untagged, audience (a tag; `user:*` = any personal tier), match (a glob on
    source_uri, as noo_rag_retag takes) and q (title substring, case-insensitive)."""

    name: ClassVar[str] = "noo_docs_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/docs"
    tags: ClassVar[List[str]] = ["rag", "documents"]

    limit: Optional[int] = Field(default=None, description="Page size (default 200, max 2000)")
    offset: Optional[int] = Field(default=None, description="Documents to skip, newest first")
    summary: Optional[bool] = Field(
        default=None,
        description="Operator/admin only: also return the audience summary over all documents "
                    "({docs, summary}).",
    )
    untagged: Optional[bool] = Field(
        default=None, description="Operator/admin: only documents with no audience tag.")
    audience: Optional[str] = Field(
        default=None,
        description="Only documents whose audience contains this tag, e.g. 'company' or "
                    "'team:ops'; a trailing * is a prefix ('user:*' = every personal tier).")
    match: Optional[str] = Field(
        default=None, description="Only documents whose source_uri matches this glob, e.g. 'gdrive://*'.")
    q: Optional[str] = Field(
        default=None, description="Only documents whose title contains this text (case-insensitive).")


@register
class PaiDocDetail(ToolDef):
    """Show one document so an operator can judge what it is and who may read it: title,
    source_uri, created_at, page_count, the first ~1000 characters of text (`text_preview`),
    its audience (`roles`), where it came from (`provenance`: {by, via, at}, null = ingested
    before provenance was recorded) and `audience_history` (the last 20 retags: at, by, from,
    to). Operator/admin only; the doc_id comes from noo_docs_list."""

    name: ClassVar[str] = "noo_doc_detail"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/docs/{doc_id}"
    tags: ClassVar[List[str]] = ["rag", "documents"]

    doc_id: str = Field(description="The document id (a UUID from noo_docs_list)")


@register
class PaiRagRetag(ToolDef):
    """Change which audience documents belong to (an access-control change). DRY-RUN unless
    apply=true: the dry-run lists each matched document with its current audience (`from`)
    and the new one (`to`), writes nothing. Select with `match` (a glob on source_uri) and/or
    `doc_ids`. Documents that already have an audience are only changed with relabel=true.
    A document always has an audience: roles must be non-empty (use ['admin'] to make one
    admin-only). Every applied retag is recorded on each document (audience_history) and in
    the security audit log. Operator/admin only."""

    name: ClassVar[str] = "noo_rag_retag"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/rag/retag"
    tags: ClassVar[List[str]] = ["rag", "documents"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    parallelizable: ClassVar[bool] = False
    timeout_secs: ClassVar[int] = 120

    roles: List[str] = Field(
        min_length=1,
        description="The new audience, e.g. ['user:alice'], ['user:alice', 'team:ops'], ['company'] "
                    "or ['admin']. Never empty.",
    )
    match: Optional[str] = Field(default=None, description="Glob on source_uri, e.g. 'gdrive://*'")
    doc_ids: Optional[List[str]] = Field(default=None, description="Document ids to retag")
    only_untagged: Optional[bool] = Field(
        default=None,
        description="Default true: touch only untagged documents. Pass false (relabel) to "
                    "change documents that already have an audience.",
    )
    apply: Optional[bool] = Field(
        default=None, description="true writes the change; omitted or false is a dry-run.")
    limit: Optional[int] = Field(default=None, description="Max documents to touch (default 1000)")
