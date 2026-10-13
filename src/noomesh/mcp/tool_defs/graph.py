# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Knowledge graph exploration and reasoning tools."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import (
    AuthLevel, HttpMethod, RiskLevel, ToolDef, register,
)
from .ops import ASYNC_NOTE


@register
class PaiGraphSearchEntities(ToolDef):
    """Search the knowledge graph for named entities (people, organizations, concepts,
    technologies, locations, events, products, standards, regulations).
    Uses text matching with automatic semantic embedding fallback for broader coverage.
    Returns entity IDs, names, and types. Use the IDs with noo_graph_entity_detail,
    noo_graph_neighbors, or noo_graph_traverse_with_intent for deeper exploration."""

    name: ClassVar[str] = "noo_graph_search_entities"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/graph/entities"
    tags: ClassVar[List[str]] = ["graph", "knowledge", "external"]

    # `serialization_alias`, not a hand-written `get_params`: the wire key is
    # `q`, the client still passes `query`, and — unlike an override — the
    # manifest the Rust door serves can represent it. The override version
    # made every search through that door return an empty list.
    query: str = Field(
        serialization_alias="q",
        description="Entity name or partial name to search for (e.g. 'Python', 'NVIDIA')",
    )
    semantic: Optional[bool] = Field(
        default=True,
        description="Enable semantic embedding fallback if text match is sparse (default: true)",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, list):
            if not data:
                return "No entities found."
            lines = []
            for e in data:
                name = e.get("canonical_name", e.get("name", "?"))
                etype = e.get("type", e.get("entity_type", "?"))
                eid = e.get("entity_id", e.get("id", "?"))
                lines.append(f"- {name} ({etype})  id={eid}")
            return "\n".join(lines)
        return super().format_response(data)


@register
class PaiGraphEntityDetail(ToolDef):
    """Get full details of a knowledge graph entity by its UUID: name, type,
    all connected entities (edges), and which document pages mention it.
    Requires an entity_id from noo_graph_search_entities."""

    name: ClassVar[str] = "noo_graph_entity_detail"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/graph/entities/{entity_id}"
    tags: ClassVar[List[str]] = ["graph", "knowledge", "external"]

    entity_id: str = Field(description="Entity UUID from noo_graph_search_entities")


@register
class PaiGraphNeighbors(ToolDef):
    """Traverse the knowledge graph outward from an entity: find related entities
    within 1-3 hops. Returns connected entities and their relationship types
    (CAUSES, DEPENDS_ON, LIMITED_BY, RELATED_TO, etc.).
    Optionally filter by edge type to follow only specific relationships.
    For intent-aware traversal, use noo_graph_traverse_with_intent instead."""

    name: ClassVar[str] = "noo_graph_neighbors"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/graph/entities/{entity_id}/neighbors"
    tags: ClassVar[List[str]] = ["graph", "knowledge", "external"]

    entity_id: str = Field(description="Starting entity UUID")
    hops: Optional[int] = Field(
        default=None,
        description="Traversal depth: 1 (direct neighbors), 2, or 3 (default: 1)",
    )
    rel_types: Optional[str] = Field(
        default=None,
        description="Comma-separated edge types to filter (e.g. 'CAUSES,DEPENDS_ON'). Omit for all types.",
    )


@register
class PaiGraphStats(ToolDef):
    """Get knowledge graph statistics: total entities, edges,
    entity types, and document coverage."""

    name: ClassVar[str] = "noo_graph_stats"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/graph/stats"
    tags: ClassVar[List[str]] = ["graph", "status", "external"]


@register
class PaiGraphNavigate(ToolDef):
    """Find seed entities and reasoning paths for a question.
    This is the primary tool for graph-guided reasoning about a question.
    Returns seed entities, hypotheses (chains of relationships), and candidate pages."""

    name: ClassVar[str] = "noo_graph_navigate"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/navigate"
    # The route is operation-backed (gateway-rust/src/ops.rs): it holds the request at most
    # MAX_WAIT_SECS (25) and then answers with an op handle. tests/test_mcp_door_timeouts.py pins
    # door >= that hold.
    timeout_secs: ClassVar[int] = 60
    tags: ClassVar[List[str]] = ["graph", "reasoning", "external"]

    query: str = Field(description="Natural language question to navigate the graph for")
    seed_entities: Optional[List[str]] = Field(
        default=None,
        description="Pre-selected entity IDs to start from (auto-detected if omitted)",
    )
    max_hops: Optional[int] = Field(
        default=None,
        description="Traversal depth (default: 2)",
    )
    rel_types: Optional[List[str]] = Field(
        default=None,
        description="Filter to specific edge types (e.g. ['CAUSES', 'DEPENDS_ON'])",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            seeds = data.get("seed_entities", [])
            hypotheses = data.get("hypotheses", [])
            pages = data.get("candidate_page_ids", [])
            lines = []
            if seeds:
                lines.append(f"Seed entities ({len(seeds)}):")
                for s in seeds[:5]:
                    lines.append(f"  - {s.get('canonical_name', '?')} ({s.get('type', '?')})")
            if hypotheses:
                lines.append(f"\nHypotheses ({len(hypotheses)}):")
                for h in hypotheses[:10]:
                    lines.append(f"  - [{h.get('confidence', 0):.2f}] {h.get('description', '')}")
            lines.append(f"\nCandidate pages: {len(pages)}")
            return "\n".join(lines) if lines else "No graph results."
        return super().format_response(data)


@register
class PaiGraphTraverseWithIntent(ToolDef):
    """Walk the graph from a single entity, preferring edges relevant to the stated
    intent (for example 'causal' or 'definitional'). Unlike noo_graph_neighbors,
    which treats every edge alike, this favours the edges that matter for the
    intent. Returns scored entities with traversal paths."""

    name: ClassVar[str] = "noo_graph_traverse_with_intent"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/traverse"
    # Operation-backed route: holds the request at most 25s, then answers with a handle.
    timeout_secs: ClassVar[int] = 60
    tags: ClassVar[List[str]] = ["graph", "reasoning", "external"]

    entity_id: str = Field(description="Starting entity UUID")
    intent: str = Field(
        default="exploratory",
        description="Query intent that controls edge weighting: causal, definitional, procedural, comparative, exploratory (default: exploratory)",
    )
    max_hops: Optional[int] = Field(
        default=None,
        description="Traversal depth (default: 2)",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, list):
            if not data:
                return "No entities reached."
            lines = [f"Found {len(data)} entities via {self.intent} traversal:\n"]
            for e in data[:20]:
                lines.append(
                    f"  [{e.get('score', 0):.3f}] {e.get('name', '?')} ({e.get('type', '?')}) "
                    f"depth={e.get('depth', '?')}  path: {e.get('path', '')}"
                )
            return "\n".join(lines)
        return super().format_response(data)


@register
class PaiGraphExplainPath(ToolDef):
    """Find the shortest reasoning path between two entities in the knowledge graph.
    Uses BFS to find the chain of relationships connecting them (max 5 hops).
    Returns human-readable steps like: Python --[USED_IN]--> Data Science --[CAUSES]--> Job Growth.
    Use this to explain how two concepts are related."""

    name: ClassVar[str] = "noo_graph_explain_path"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/explain-path"
    tags: ClassVar[List[str]] = ["graph", "reasoning", "external"]

    src_entity_id: str = Field(description="Source entity UUID")
    dst_entity_id: str = Field(description="Destination entity UUID")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            path = data.get("path", [])
            if not path:
                return data.get("message", "No path found between these entities (max 5 hops).")
            # The steps are edge ROWS — `src_entity_id` / `dst_entity_id`, the
            # column names — not `{src, dst}`. Subscripting the short names
            # raised KeyError on every path that was actually found, so the
            # tool crashed on success and only "worked" when there was no
            # path. `.get` throughout: a formatter must never be the thing
            # that fails.
            def _end(step: dict, which: str) -> str:
                return step.get(f"{which}_entity_id") or step.get(which) or "?"

            lines = [f"Path ({data.get('hops', len(path))} hops):\n"]
            for i, step in enumerate(path):
                if i == 0:
                    lines.append(f"  {_end(step, 'src')}")
                rel = step.get("rel_type", "?")
                lines.append(f"    --[{rel}]--> {_end(step, 'dst')}")
            return "\n".join(lines)
        return super().format_response(data)


@register
class PaiGraphSemanticSearch(ToolDef):
    """Search entities by meaning using graph-aware vector embeddings.
    Unlike noo_graph_search_entities (text matching), this finds conceptually
    similar entities even when names don't match -- e.g. searching 'parallel computing'
    can find 'MPI', 'OpenMP', 'threading'. Requires entity embeddings to be computed."""

    name: ClassVar[str] = "noo_graph_semantic_search"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/semantic-search"
    tags: ClassVar[List[str]] = ["graph", "knowledge", "external"]

    query: str = Field(description="Natural language query for semantic entity search")
    top_k: Optional[int] = Field(
        default=None,
        description="Max results (default: 10)",
    )

    def format_response(self, data: Any) -> str:
        # The worker returns `{"entities": [...], "count": n}` — a list-only
        # check fell straight through to the base class and printed raw JSON.
        if isinstance(data, dict):
            data = data.get("entities", data.get("results", []))
        if isinstance(data, list):
            if not data:
                return "No entities found via semantic search."
            lines = []
            for e in data:
                name = e.get("canonical_name", e.get("name", "?"))
                etype = e.get("type", "?")
                score = e.get("score", 0)
                eid = e.get("entity_id", "?")
                lines.append(f"- [{score:.3f}] {name} ({etype})  id={eid}")
            return "\n".join(lines)
        return super().format_response(data)


@register
class PaiGraphClassifyIntent(ToolDef):
    """Classify a query's intent type and confidence. Returns one of:
    causal (why/cause/effect), definitional (what is/define),
    procedural (how to/steps), comparative (vs/difference),
    exploratory (general). Confidence 0.0-1.0 indicates classification ambiguity.
    Use this to understand how the graph system would approach a query."""

    name: ClassVar[str] = "noo_graph_classify_intent"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/classify-intent"
    tags: ClassVar[List[str]] = ["graph", "reasoning", "external"]

    query: str = Field(description="Query to classify")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            intent = data.get("intent", "?")
            # Only when there IS one. `classify_query` is a keyword scan and
            # reports no confidence, so the old default printed
            # "confidence: 0.000" — which reads as a computed zero rather
            # than as an absent measure.
            confidence = data.get("confidence")
            if isinstance(confidence, (int, float)):
                return f"Intent: {intent} (confidence: {confidence:.3f})"
            return f"Intent: {intent}"
        return super().format_response(data)


@register
class PaiGraphSearchClusters(ToolDef):
    """Find knowledge clusters relevant to a query using vector search over cluster centroids.
    Each cluster is a labelled group of closely-related entities. Use this to discover which areas of the
    knowledge base are most relevant to a topic."""

    name: ClassVar[str] = "noo_graph_search_clusters"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/search-clusters"
    tags: ClassVar[List[str]] = ["graph", "reasoning", "external"]

    query: str = Field(description="Query to find relevant clusters for")
    top_k: Optional[int] = Field(
        default=None,
        description="Max clusters to return (default: 5)",
    )

    def format_response(self, data: Any) -> str:
        # Same wrapper as semantic search — and the `reason` matters here:
        # an unclustered graph has no centroids, and "no matching clusters"
        # would blame the query for a graph that was never clustered.
        reason = hint = None
        if isinstance(data, dict):
            reason, hint = data.get("reason"), data.get("hint")
            data = data.get("clusters", data.get("results", []))
        if isinstance(data, list):
            if not data:
                if reason:
                    return f"No clusters ({reason})." + (f" {hint}" if hint else "")
                return "No matching clusters found."
            lines = []
            for c in data:
                name = c.get("name", "?")
                members = c.get("member_count", "?")
                score = c.get("score", 0)
                lines.append(f"- [{score:.3f}] {name} ({members} members)")
                if c.get("summary"):
                    lines.append(f"  {c['summary']}")
            return "\n".join(lines)
        return super().format_response(data)


@register
class PaiGraphExtractRelations(ToolDef):
    """Trigger LLM-based semantic relation extraction for a specific page.
    Reads the page text and extracts typed relationships (CAUSES, DEPENDS_ON,
    LIMITED_BY, MEASURED_BY, etc.) between entities, creating new graph edges
    that go beyond co-occurrence. Use after ingesting new documents to enrich
    the graph with causal and dependency relationships."""

    name: ClassVar[str] = "noo_graph_extract_relations"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/extract-relations"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    # One LLM extraction per page. The route is operation-backed: it waits a few seconds and then
    # answers with an op handle, so the door need only outlast MAX_WAIT_SECS (25).
    timeout_secs: ClassVar[int] = 60
    tags: ClassVar[List[str]] = ["graph", "ingest"]

    page_id: str = Field(description="Page UUID to extract relations from")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            count = data.get("edges_created", 0)
            return f"Extracted {count} semantic edge(s) for page {self.page_id}"
        return super().format_response(data)


@register
class PaiGraphRunClustering(ToolDef):
    """Trigger on-demand graph clustering: groups related entities into
    labelled clusters. Replaces previous clustering results."""

    name: ClassVar[str] = "noo_graph_run_clustering"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    # Was /api/v1/graph/run-clustering, which the Rust gateway has never
    # served — the tool 404'd through both MCP doors for as long as it has
    # existed, the same way three evolve tools did until the route surface
    # was written down as data. Nothing noticed because the tool definition
    # and the router live in different languages and nothing compared them.
    path: ClassVar[str] = "/api/v1/graph/recluster"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    # A recluster runs for minutes, so its route NEVER holds the request for the run: it answers
    # 202 with an op handle at once (default_wait 0) and the caller polls noo_op_status. The door
    # only has to outlast the route's bounded wait; tests/test_mcp_door_timeouts.py pins it.
    timeout_secs: ClassVar[int] = 60
    tags: ClassVar[List[str]] = ["graph", "admin"]

    min_cluster_size: Optional[int] = Field(
        default=None,
        description="Minimum entities per cluster (default: 3)",
    )
    resolution: Optional[float] = Field(
        default=None,
        description="Clustering resolution -- higher = more, smaller clusters (default: 1.0)",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            clusters = data.get("clusters", 0)
            meta = data.get("meta_clusters", 0)
            nodes = data.get("nodes", 0)
            return (
                f"Clustering complete: {clusters} clusters, {meta} meta-clusters, "
                f"{nodes} entities in graph"
            )
        return super().format_response(data)


@register
class PaiGraphEntityCleanup(ToolDef):
    """Preview the junk entities already in the knowledge graph (single letters, math
    symbols, bare numbers): counts, and the most-connected examples. This tool ONLY
    PREVIEWS. It changes nothing, and apply=true is refused (403) over MCP: removing the
    entities (they are staged first and restorable for 30 days) is done by a person
    running `noo graph entity-cleanup --apply` at a terminal. Admin only."""

    name: ClassVar[str] = "noo_graph_entity_cleanup"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/graph/entity-cleanup"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    risk_level: ClassVar[RiskLevel] = RiskLevel.HIGH
    # The route is op-backed (default wait 3 s, never more than MAX_WAIT_SECS = 25), so the door
    # only has to outlast that bound, not the run; tests/test_mcp_door_timeouts.py pins it.
    timeout_secs: ClassVar[int] = 60
    # NOT tagged "external": the USER door serves only the external subset, so this is on the
    # operator door alone. "admin" keeps it out of any non-admin surface that filters on the tag.
    tags: ClassVar[List[str]] = ["graph", "admin"]

    apply: bool = Field(
        default=False,
        description="Leave false (the default). true is refused over MCP: the delete is CLI-only, run by a person",
    )
    examples: Optional[int] = Field(
        default=None,
        description="How many of the most-connected junk entities to list (default 20, at most 200)",
    )
    max_delete: Optional[int] = Field(
        default=None,
        description="Most entities one applied run removes (default and ceiling 5000)",
    )

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            if data.get("dry_run"):
                return f"Dry run: {data.get('junk', 0)} junk entities of {data.get('scanned', 0)}; nothing changed"
            return f"Staged and removed {data.get('staged', 0)} junk entities (run {data.get('run_id')})"
        return super().format_response(data)


@register
class PaiGraphClustersAudit(ToolDef):
    """Audit how knowledge-graph clusters mix audiences (read-only, admin only).
    For every cluster: its members per audience tier (company, system, generated,
    admin, each team:*, user:* as a count, untagged), whether it is single-tier
    ("pure:<tier>") or "mixed", and how much of it a {company, system} reader would
    see. The summary counts clusters by mix, the clusters that reader sees whole,
    partly or not at all, and how many clustered entities come only from untagged
    documents; a caveat says when that makes the measurement premature. This is the
    measure-first step before deciding on per-audience clustering."""

    name: ClassVar[str] = "noo_graph_clusters_audit"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/v1/graph/clusters/audit"
    # Deliberately not tagged `external`: the audit counts every tier's
    # documents, so it belongs on the operator door only (and the route itself
    # refuses a non-admin with 403).
    tags: ClassVar[List[str]] = ["graph", "admin"]

    limit: Optional[int] = Field(
        default=None,
        description="Max clusters listed, largest first (default 1000, max 5000); the summary always covers all",
    )

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
            return super().format_response(data)
        s = data["summary"]
        reader = s.get("reader", {})
        lines = [
            f"{s.get('total_clusters', '?')} clusters; mix: {s.get('by_mix', {})}",
            f"reader {reader.get('roles', [])} sees {reader.get('whole', '?')} whole, "
            f"{reader.get('partial', '?')} partial, {reader.get('none', '?')} none",
            f"distinct tiers per cluster: {s.get('distinct_tiers_per_cluster', {})}",
        ]
        cov = s.get("coverage", {})
        lines.append(
            f"untagged-only members: {cov.get('untagged_only_members', '?')} "
            f"({cov.get('untagged_only_fraction', '?')} of clustered)"
        )
        lines += [f"CAVEAT: {c}" for c in data.get("caveats", [])]
        return "\n".join(lines)
