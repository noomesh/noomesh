// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `MemoryProvider` — the augmentation-plane facade.
//!
//! Enum dispatch, per the accepted design: the enum IS the trait surface.
//! An async trait object buys nothing here — providers are known at
//! compile time, arrive one per release phase, and enum dispatch keeps
//! every method's signature greppable. Third-party providers do NOT add
//! variants to this enum; they implement the `/v1/memory/*` HTTP contract
//! and are reached through the `Http` variant (phase 2), discovered via
//! the design's `role=memory` resolver.
//!
//! ## Operations — implemented now vs contract TODO
//!
//! Phase 1 defines exactly the operations today's augmentation call sites
//! use (KB query/ingest, graph tools, prune restore, snapshots, semantic
//! relationships). The remaining contract operations are deliberately NOT
//! speculatively implemented — they arrive with the phase that makes them
//! real:
//!
//! * `recall` (`POST /v1/memory/recall`) — phase 3, when the hot-path
//!   context injection reroutes from `worker.memory.search`.
//! * `turns_batch` (`POST /v1/memory/turns:batch`) — phase 3, replacing
//!   the `worker.memory.batch_index` fire-and-forget.
//! * `search` (`POST /v1/memory/search`) — phase 3 (`noo_memory_search`,
//!   `worker.memory.cross_channel`).
//! * `forget` (`POST /v1/memory/forget`) — phase 4, with the
//!   `erase_targets()` RTBF split and two-phase audit record.
//! * `health` / `capabilities` — phase 2, when there is an HTTP provider
//!   to probe.
//!
//! ## Per-operation transport (NatsTrellion, today)
//!
//! | op | transport |
//! | --- | --- |
//! | `kb.query`, `kb.ingest`, `kb.deduplicate` | NATS (`worker.rag.*`) |
//! | `snapshots.consolidate`, `snapshots.curriculum` | NATS (`worker.api.snapshots.*`) |
//! | everything else (`graph.*`, `kb.docs_*`, `snapshots.list/get/concepts`, `memory.semantic_relationships`) | SQL-internal |
//!
//! "SQL-internal" means the impl keeps the direct query against trellion's
//! tables FOR NOW — the point of phase 1 is that the CALL SITES no longer
//! know that, so phase 3 can swap the implementation without touching
//! them. Zero behavior change is the phase-1 invariant: every query
//! string, subject and payload below is byte-identical to the call site
//! it was lifted from (guarded by the tests at the bottom).
//!
//! ## Granularity: call-per-tool, never call-per-hop
//!
//! Graph traversal is the hottest path in the database (`edges` 288M
//! index scans) and must not cross a network boundary per hop. The facade
//! therefore exposes ONE operation per tool invocation — `graph_neighbors`
//! is a single recursive-CTE call (via `repo::graph`), never an
//! edge-at-a-time walk. Keep it that way when adding operations.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::metrics::MetricsState;
use super::scope::{self, Audience};

// ── NATS subjects (trellion's wire today) ────────────────────────────
// Constants so the zero-behavior-change tests below can assert the exact
// strings the pre-facade call sites used.
const SUBJECT_KB_QUERY: &str = "worker.rag.query";
const SUBJECT_KB_INGEST: &str = "worker.rag.ingest";
const SUBJECT_KB_DEDUPLICATE: &str = "worker.rag.deduplicate";
const SUBJECT_KB_RETAG: &str = "worker.rag.retag";
/// Document hold: keep a document, out of embedding and search.
const SUBJECT_KB_HOLD: &str = "worker.rag.hold";
const SUBJECT_KB_UNHOLD: &str = "worker.rag.unhold";
const SUBJECT_KB_HELD: &str = "worker.rag.held";
/// Deletes the documents held under one reason. Batched in trellion, so a
/// large purge is minutes, not seconds.
const SUBJECT_KB_PURGE: &str = "worker.rag.purge";
pub(crate) const KB_PURGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);
/// The caller's KB role set — the ONE resolver (`workers/kb.py`), asked rather
/// than re-implemented.
const SUBJECT_KB_AUDIENCE: &str = "worker.rag.audience";
const SUBJECT_GRAPH_RECLUSTER: &str = "worker.graph.recluster";
/// The junk-entity cleanup. `worker.rag.*` and not `worker.graph.*` on purpose:
/// the validator and the cleanup are in trellion's OPEN tree, so the subject
/// belongs on the base `ml` surface every install has, not the Intelligent
/// tier's `worker.graph.*` family (`addons::is_trellion_intel_subject`).
const SUBJECT_ENTITY_CLEANUP: &str = "worker.rag.entity_cleanup";
/// A scan of every entity (three correlated counts each) and then up to 5,000
/// staged deletes in batches: minutes on a real graph, so not the 120 s default.
pub(crate) const ENTITY_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// The Intelligent tier's graph surface. One subject per
/// capability, matching `worker.rag.*` and `worker.recall.*` rather than a
/// single dispatcher with an `op` field — a subject that means one thing can
/// be granted, revoked and traced on its own.
const SUBJECT_GRAPH_INTEL: &[(&str, &str)] = &[
    ("navigate", "worker.graph.navigate"),
    ("traverse", "worker.graph.traverse"),
    ("explain_path", "worker.graph.explain_path"),
    ("semantic_search", "worker.graph.semantic_search"),
    ("search_clusters", "worker.graph.search_clusters"),
    ("classify_intent", "worker.graph.classify_intent"),
    ("extract_relations", "worker.graph.extract_relations"),
    ("recall_traversals", "worker.graph.recall_traversals"),
    // a user's own saved threads (recall, list, show).
    ("recall_walks", "worker.graph.recall_walks"),
];
/// Community detection clusters the whole graph and labels each cluster.
/// Minutes, not seconds, and the default
/// 120s worker timeout would abandon the caller mid-run every time. The
/// worker refuses to start a second run while one is in flight, so a
/// caller that times out anyway and retries learns that rather than
/// starting a competing generation.
pub(crate) const RECLUSTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);
const SUBJECT_SNAPSHOTS_CONSOLIDATE: &str = "worker.api.snapshots.consolidate";
const SUBJECT_SNAPSHOTS_CURRICULUM: &str = "worker.api.snapshots.curriculum";
const SUBJECT_SNAPSHOTS_SCOPED: &str = "worker.api.snapshots.scoped";

// ── SQL lifted verbatim from the pre-facade call sites ───────────────
// Named consts so the tests below can assert byte-identity with the
// statements the routes used to issue directly ("routing decisions
// unchanged"). Do not edit one without the other.
const SQL_INGESTED_URI_META: &str =
    "WITH all_uris AS (
        SELECT source_uri AS uri,
               (metadata IS NOT NULL AND metadata != '{}'::jsonb) AS has_meta
        FROM docs
        WHERE source_uri IS NOT NULL AND source_uri != ''
        UNION ALL
        SELECT jsonb_array_elements_text(metadata->'aliased_uris') AS uri,
               true AS has_meta
        FROM docs
        WHERE jsonb_typeof(metadata->'aliased_uris') = 'array'
     )
     SELECT uri, bool_or(has_meta) AS has_meta
     FROM all_uris
     GROUP BY uri";
const SQL_DOC_BACKFILL_METADATA: &str =
    "UPDATE docs
     SET metadata = $1::jsonb
     WHERE source_uri = $2
       AND (metadata IS NULL OR metadata = '{}'::jsonb)";
const SQL_GDRIVE_TITLES: &str =
    "SELECT source_uri, title \
     FROM docs \
     WHERE source_uri LIKE 'gdrive://%'";
const SQL_DOC_REPAIR_TITLE: &str =
    "UPDATE docs
     SET title = $1
     WHERE source_uri = $2
       AND title IS DISTINCT FROM $1";
const SQL_ENTITY_SEARCH: &str =
    "SELECT entity_id::text, canonical_name, type, aliases_json, created_at \
     FROM entities \
     WHERE canonical_name ILIKE $1 \
     ORDER BY canonical_name \
     LIMIT 50";
const SQL_ENTITY_GET: &str =
    "SELECT entity_id::text, canonical_name, type, aliases_json, created_at \
     FROM entities WHERE entity_id = $1::uuid";
const SQL_ENTITY_EDGES_1HOP: &str =
    "SELECT edge_id::text, src_entity_id::text, rel_type, dst_entity_id::text, evidence_json \
     FROM edges \
     WHERE src_entity_id = $1::uuid OR dst_entity_id = $1::uuid";
const SQL_ENTITY_NAMES: &str =
    "SELECT entity_id::text, canonical_name, type FROM entities \
     WHERE entity_id = ANY($1::uuid[])";
/// `{HELD}` is the not-held predicate (`TRUE` before trellion migration 105).
const SQL_ENTITY_PAGES: &str =
    "SELECT p.page_id::text, p.page_no, d.title \
     FROM pages p \
     JOIN docs d ON d.doc_id = p.doc_id \
     WHERE {HELD} \
       AND p.page_id IN (SELECT DISTINCT page_id FROM mentions WHERE entity_id = $1::uuid)";
const SQL_ENTITIES_RESOLVE: &str =
    "SELECT entity_id::text, canonical_name, type \
     FROM entities WHERE entity_id = ANY($1::uuid[])";
const SQL_OVERVIEW_EDGES: &str =
    "SELECT src_entity_id::text, dst_entity_id::text, rel_type, confidence, created_at \
     FROM edges \
     WHERE src_entity_id::text = ANY($1::text[]) \
       AND dst_entity_id::text = ANY($1::text[]) \
     LIMIT 5000";
const SQL_CLUSTERS: &str =
    "SELECT cluster_id::text, name, level, member_count \
     FROM entity_clusters \
     WHERE level = $1 AND member_count >= $2 \
     ORDER BY member_count DESC \
     LIMIT $3";
const SQL_CLUSTER_EDGES: &str =
    "SELECT m1.cluster_id::text AS src_cluster, \
            m2.cluster_id::text AS dst_cluster, \
            COUNT(*) AS weight \
     FROM edges e \
     JOIN entity_cluster_members m1 ON m1.entity_id = e.src_entity_id \
     JOIN entity_cluster_members m2 ON m2.entity_id = e.dst_entity_id \
     JOIN entity_clusters c1 ON c1.cluster_id = m1.cluster_id AND c1.level = $1 \
     JOIN entity_clusters c2 ON c2.cluster_id = m2.cluster_id AND c2.level = $1 \
     WHERE m1.cluster_id::text = ANY($2::text[]) \
       AND m2.cluster_id::text = ANY($2::text[]) \
       AND m1.cluster_id <> m2.cluster_id \
     GROUP BY m1.cluster_id, m2.cluster_id \
     HAVING COUNT(*) >= 2 \
     ORDER BY weight DESC \
     LIMIT 2000";
const SQL_SEMANTIC_RELATIONSHIPS: &str =
    "SELECT target_id::text, similarity \
     FROM noo_semantic_relationships \
     WHERE source_id = $1::uuid \
     ORDER BY similarity DESC \
     LIMIT $2";
const SQL_SNAPSHOTS_LIST_BASE: &str =
    "SELECT id::text, generation, slice_kind, slice_spec, status, \
            created_at, completed_at, stats, label \
     FROM trellion_snapshots WHERE 1=1 ";
const SQL_SNAPSHOT_GET: &str =
    "SELECT id::text, generation, slice_kind, slice_spec, status, \
            created_at, completed_at, stats, label \
     FROM trellion_snapshots WHERE id = $1::uuid";
const SQL_SNAPSHOT_CONCEPTS: &str =
    "SELECT canonical_name, type FROM trellion_concepts \
     WHERE snapshot_id = $1::uuid";

/// The registered memory provider. One variant per implementation:
/// `NatsTrellion` today; `Http` (contract client, `mesh::targets(Memory)`
/// discovery) lands in phase 2 behind a flag; selection via
/// `memory: provider:` config is phase 4.
pub enum MemoryProvider<'a> {
    NatsTrellion(NatsTrellion<'a>),
}

/// Row types mirror the exact tuples the pre-facade call sites decoded,
/// so the routes' JSON assembly is untouched.
pub type EntityRow = (String, String, String, Option<Value>, Option<chrono::DateTime<chrono::Utc>>);
pub type EntityNameRow = (String, String, String);
pub type OverviewEdgeRow = (String, String, String, Option<f64>, Option<chrono::DateTime<chrono::Utc>>);
pub type ClusterRow = (String, String, i32, i32);
pub type ClusterEdgeRow = (String, String, i64);
/// `(doc_id, source_uri, title, hash, created_at, metadata.roles,
/// metadata.ingest, audience_history length)`.
pub type DocRow = (String, Option<String>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<Value>, Option<Value>, i64);

impl<'a> MemoryProvider<'a> {
    /// Phase-1 constructor: the only implementation is trellion over its
    /// existing NATS subjects + internal SQL. `AppState::memory()` is the
    /// canonical way to obtain one.
    pub fn nats_trellion(
        nats: &'a async_nats::Client,
        db: &'a sqlx::PgPool,
        metrics: &'a MetricsState,
    ) -> Self {
        Self::NatsTrellion(NatsTrellion { nats, db, metrics })
    }

    // ── kb group: query / ingest (NATS) ──────────────────────────────

    /// `POST /v1/memory/kb/query` — `noo_rag_query` surface.
    /// NatsTrellion: NATS `worker.rag.query`.
    pub async fn kb_query(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_QUERY, "kb.query", body).await,
        }
    }

    /// `POST /v1/memory/kb/ingest` — async document ingest.
    /// NatsTrellion: NATS `worker.rag.ingest`.
    pub async fn kb_ingest(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_INGEST, "kb.ingest", body).await,
        }
    }

    /// `POST /api/v1/rag/retag` — change which audience documents belong to.
    /// NatsTrellion: NATS `worker.rag.retag`.
    pub async fn kb_retag(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_RETAG, "kb.retag", body).await,
        }
    }

    /// `POST /api/v1/docs/hold` — keep documents, out of embedding and search.
    /// NatsTrellion: NATS `worker.rag.hold`.
    pub async fn kb_hold(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_HOLD, "kb.hold", body).await,
        }
    }

    /// `POST /api/v1/docs/unhold`. NatsTrellion: NATS `worker.rag.unhold`.
    pub async fn kb_unhold(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_UNHOLD, "kb.unhold", body).await,
        }
    }

    /// `GET /api/v1/docs/held`. NatsTrellion: NATS `worker.rag.held`.
    pub async fn kb_held(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_HELD, "kb.held", body).await,
        }
    }

    /// `POST /api/v1/docs/purge` — DELETE the documents held under one
    /// reason. NatsTrellion: NATS `worker.rag.purge`, on a 900s timeout.
    pub async fn kb_purge(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => {
                p.request_slow(SUBJECT_KB_PURGE, "kb.purge", body, KB_PURGE_TIMEOUT).await
            }
        }
    }

    /// Page-level dedupe maintenance (kb group).
    /// NatsTrellion: NATS `worker.rag.deduplicate`.
    pub async fn kb_deduplicate(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_DEDUPLICATE, "kb.deduplicate", body).await,
        }
    }

    /// `worker.rag.audience` — the caller's role set (`{"roles": null | [..]}`),
    /// from the same resolver retrieval uses. See [`scope::resolve`].
    pub async fn kb_audience(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_KB_AUDIENCE, "kb.audience", body).await,
        }
    }

    /// One Intelligent-tier graph capability, by name.
    ///
    /// `op` is the key in `SUBJECT_GRAPH_INTEL`; an unknown one is a
    /// programming error in the route table and says so rather than
    /// publishing to a subject nobody serves.
    pub async fn graph_intel(&self, op: &str, body: &Value) -> anyhow::Result<Value> {
        let subject = SUBJECT_GRAPH_INTEL
            .iter()
            .find(|(k, _)| *k == op)
            .map(|(_, s)| *s)
            .ok_or_else(|| anyhow::anyhow!("no graph capability named `{op}`"))?;
        match self {
            Self::NatsTrellion(p) => p.request(subject, "graph.intel", body).await,
        }
    }

    /// Rebuild the entity communities (graph group).
    /// NatsTrellion: NATS `worker.graph.recluster`, on a 900s timeout.
    ///
    /// The only writer of `entity_clusters` / `entity_cluster_members` in
    /// the system. Until this existed those tables had no writer at all and
    /// `/api/v1/graph/clusters/overview` answered with an empty graph on
    /// every install created after the Rust port.
    pub async fn graph_recluster(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => {
                p.request_slow(SUBJECT_GRAPH_RECLUSTER, "graph.recluster", body, RECLUSTER_TIMEOUT)
                    .await
            }
        }
    }

    /// Stage and remove the junk entities (graph group).
    /// NatsTrellion: NATS `worker.rag.entity_cleanup`, on a 600s timeout.
    pub async fn junk_entity_cleanup(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => {
                p.request_slow(SUBJECT_ENTITY_CLEANUP, "graph.entity_cleanup", body, ENTITY_CLEANUP_TIMEOUT)
                    .await
            }
        }
    }

    // ── kb group: docs metadata (SQL-internal) ───────────────────────

    /// Recent documents for `GET /api/v1/docs`. SQL-internal today.
    pub async fn kb_docs_list(
        &self,
        aud: &Audience,
        filter: &scope::DocFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DocRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_docs_list(aud, filter, limit, offset).await,
        }
    }

    /// One document, if `aud` may read it (`GET /api/v1/docs/{doc_id}`).
    pub async fn kb_doc_detail(
        &self,
        aud: &Audience,
        doc_id: &str,
    ) -> Result<Option<scope::DocDetailRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_doc_detail(aud, doc_id).await,
        }
    }

    /// `metadata.roles` of EVERY document (null where untagged), for the
    /// audience summary on `GET /api/v1/docs?summary=1`.
    pub async fn kb_docs_roles_all(
        &self,
        aud: &Audience,
        filter: &scope::DocFilter,
    ) -> Result<Vec<Option<Value>>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_docs_roles_all(aud, filter).await,
        }
    }

    /// `source_uri` → has-meaningful-metadata map for the ingest loops'
    /// dedup + self-healing backfill. SQL-internal today.
    pub async fn kb_ingested_uri_meta(&self) -> Result<HashMap<String, bool>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_ingested_uri_meta().await,
        }
    }

    /// Backfill an existing doc's empty metadata column — the one gateway
    /// WRITE into a provider table that phase 0 flagged must go behind the
    /// contract rather than reclassify. SQL-internal today; folds into
    /// `kb/ingest` semantics in phase 2. Returns whether a row changed.
    pub async fn kb_doc_backfill_metadata(
        &self,
        source_uri: &str,
        metadata: &Value,
    ) -> Result<bool, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_doc_backfill_metadata(source_uri, metadata).await,
        }
    }

    /// `source_uri` → stored title for gdrive:// docs. Feeds the drive
    /// scan's title-repair pass (slash-truncation self-heal). SQL-internal.
    pub async fn kb_gdrive_titles(&self) -> Result<HashMap<String, String>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_gdrive_titles().await,
        }
    }

    /// Correct a stored doc title in place (no-op when already equal).
    /// Same provider-table write class as the metadata backfill above.
    /// Returns whether a row changed.
    pub async fn kb_doc_repair_title(
        &self,
        source_uri: &str,
        title: &str,
    ) -> Result<bool, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.kb_doc_repair_title(source_uri, title).await,
        }
    }

    // ── kb group: knowledge-graph tools (SQL-internal) ───────────────

    /// Entity name search (ILIKE), `noo_graph_search_entities` surface.
    pub async fn graph_search_entities(
        &self,
        aud: &Audience,
        q: &str,
    ) -> Result<Vec<EntityRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_search_entities(aud, q).await,
        }
    }

    /// Full entity detail — entity row, 1-hop connections with resolved
    /// peer names, mentioning pages — assembled provider-side because it
    /// is ONE tool invocation (`noo_graph_entity_detail`), not four.
    /// `Ok(None)` = no such entity.
    pub async fn graph_entity_detail(
        &self,
        aud: &Audience,
        entity_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_entity_detail(aud, entity_id).await,
        }
    }

    /// Batch-resolve entity ids to `(id, canonical_name, type)`.
    pub async fn graph_entities_resolve(
        &self,
        aud: &Audience,
        ids: &[String],
    ) -> Result<Vec<EntityNameRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_entities_resolve(aud, ids).await,
        }
    }

    /// Multi-hop neighbourhood traversal, `noo_graph_neighbors` surface.
    /// ONE call per tool invocation — the recursive CTE runs inside the
    /// provider (see module docs on call-per-tool granularity).
    pub async fn graph_neighbors(
        &self,
        aud: &Audience,
        entity_id: uuid::Uuid,
        hops: i32,
        rel_types: Option<&[String]>,
    ) -> Result<Vec<crate::repo::graph::NeighborEdge>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_neighbors(aud, entity_id, hops, rel_types).await,
        }
    }

    /// Top entities by degree centrality (graph overview).
    pub async fn graph_top_entities(
        &self,
        aud: &Audience,
        min_degree: i32,
        entity_type: Option<&str>,
        limit: i32,
    ) -> Result<Vec<crate::repo::graph::EntityDegree>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_top_entities(aud, min_degree, entity_type, limit).await,
        }
    }

    /// Intra-set edges between overview nodes (with timestamps, cap 5000).
    pub async fn graph_overview_edges(
        &self,
        aud: &Audience,
        node_ids: &[String],
    ) -> Result<Vec<OverviewEdgeRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_overview_edges(aud, node_ids).await,
        }
    }

    /// Clusters at one hierarchy level (super-node overview).
    pub async fn graph_clusters(
        &self,
        aud: &Audience,
        level: i32,
        min_members: i32,
        limit: i32,
    ) -> Result<Vec<ClusterRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_clusters(aud, level, min_members, limit).await,
        }
    }

    /// Weighted inter-cluster edges between the given clusters.
    pub async fn graph_cluster_edges(
        &self,
        aud: &Audience,
        level: i32,
        cluster_ids: &[String],
    ) -> Result<Vec<ClusterEdgeRow>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_cluster_edges(aud, level, cluster_ids).await,
        }
    }

    /// Entity count the caller may see (the "N of M" the overview reports).
    pub async fn graph_entity_count(&self, aud: &Audience) -> Result<i64, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.graph_entity_count(aud).await,
        }
    }

    // ── kb group: prune staging (SQL-internal) ───────────────────────
    //
    // The staging tables themselves (`graph_prune_staging`,
    // `graph_edge_prune_staging`) live in schema MESH (phase-0 finding),
    // but listing joins provider-owned `entities` for display names and
    // restore WRITES provider tables (`entities`, `edges`, `mentions`,
    // `entity_embeddings`) — which is exactly why these are augmentation
    // ops, not mesh-plane SQL. Phase 3 decides how the mesh-owned
    // staging half is threaded through the HTTP contract.

    /// List soft-deleted entities + edges awaiting restore. Returns the
    /// full response body (including the "staging table not created yet"
    /// note) exactly as the route always shaped it.
    pub async fn graph_prune_staged(
        &self,
        limit: i64,
        reason: Option<&str>,
        include_restored: bool,
    ) -> Value {
        match self {
            Self::NatsTrellion(p) => p.graph_prune_staged(limit, reason, include_restored).await,
        }
    }

    /// Restore one staged ENTITY (re-insert or graft, re-create edges and
    /// mentions from the snapshot). Per-id result object, never fatal.
    pub async fn graph_prune_restore_entity(&self, staging_id: &str) -> Value {
        match self {
            Self::NatsTrellion(p) => p.graph_prune_restore_entity(staging_id).await,
        }
    }

    /// Restore up to `limit` still-staged ENTITIES of one run (`run_id`), all of
    /// them if they fit: the cleanup stages up to 5,000 per run, and a restore
    /// by staging id takes 100 per call. `remaining` in the answer says whether
    /// to call again.
    pub async fn graph_prune_restore_run(&self, run_id: &str, limit: i64) -> Value {
        match self {
            Self::NatsTrellion(p) => p.graph_prune_restore_run(run_id, limit).await,
        }
    }

    /// Restore one staged EDGE (edge-metabolism tier).
    pub async fn graph_prune_restore_edge(&self, staging_id: &str) -> Value {
        match self {
            Self::NatsTrellion(p) => p.graph_prune_restore_edge(staging_id).await,
        }
    }

    // ── core group: provider-derived relationships (SQL-internal) ────

    /// Semantic relationships for a memory record
    /// (`noo_semantic_relationships` — provider-derived, the one
    /// augmentation read in the otherwise transcript-plane
    /// `routes/memory.rs`).
    pub async fn semantic_relationships(
        &self,
        record_id: &str,
        limit: i64,
    ) -> Result<Vec<(String, f64)>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.semantic_relationships(record_id, limit).await,
        }
    }

    // ── snapshots group ───────────────────────────────────────────────

    /// List snapshots (summaries, newest first). SQL-internal today.
    pub async fn snapshots_list(
        &self,
        kind: Option<&str>,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Value>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.snapshots_list(kind, status, limit).await,
        }
    }

    /// One snapshot summary by id. `Ok(None)` = not found. SQL-internal.
    pub async fn snapshots_get(&self, snapshot_id: &str) -> Result<Option<Value>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.snapshots_get(snapshot_id).await,
        }
    }

    /// `(canonical_name, type)` concept set of one snapshot — the diff
    /// endpoint loads two of these and diffs gateway-side. SQL-internal.
    pub async fn snapshot_concepts(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        match self {
            Self::NatsTrellion(p) => p.snapshot_concepts(snapshot_id).await,
        }
    }

    /// Snapshot consolidation (temporal-graph extraction — LLM work).
    /// NatsTrellion: NATS `worker.api.snapshots.consolidate`.
    pub async fn snapshots_consolidate(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => {
                p.request(SUBJECT_SNAPSHOTS_CONSOLIDATE, "snapshots.consolidate", body).await
            }
        }
    }

    /// Curriculum materialization over a snapshot's CKG.
    /// NatsTrellion: NATS `worker.api.snapshots.curriculum`.
    pub async fn snapshots_curriculum(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => {
                p.request(SUBJECT_SNAPSHOTS_CURRICULUM, "snapshots.curriculum", body).await
            }
        }
    }

    /// What a restricted caller may see of a snapshot's contents (readable
    /// concept names and counts; the design). NatsTrellion: NATS
    /// `worker.api.snapshots.scoped`.
    pub async fn snapshots_scoped(&self, body: &Value) -> anyhow::Result<Value> {
        match self {
            Self::NatsTrellion(p) => p.request(SUBJECT_SNAPSHOTS_SCOPED, "snapshots.scoped", body).await,
        }
    }
}

/// The restore routes' answer for a staged row that belongs to an erased user
/// (right to be forgotten): refused, nothing written, and the row is left as
/// it is for the erase's own purge. The message names no content.
fn erased_user_refusal(sid: &str) -> Value {
    json!({
        "staging_id": sid,
        "status": "refused",
        "error": "this row was set aside for a user who has been erased; it is not restored",
    })
}

/// The restore routes' answer for a staged row whose payload never recorded an
/// owner (no top-level `user_id` key at all; an explicit `null` is a shared
/// row and restores). Without the key the restore cannot tell a shared entity
/// from a private one, and guessing shared would widen who sees it: refused.
fn ownerless_refusal(sid: &str) -> Value {
    json!({
        "staging_id": sid,
        "status": "refused",
        "error": "this row does not record its owner; it is not restored",
    })
}

/// The restore routes' answer when the database refused a step. The caller sees
/// a fixed message: a database error can quote row values (a duplicate key, a
/// constraint's columns) from somebody's staged data. The detail goes to the
/// gateway log as the step and the SQLSTATE only, never the message.
fn restore_db_error(sid: &str, step: &'static str, e: &sqlx::Error) -> Value {
    let sqlstate = e.as_database_error().and_then(|d| d.code()).map(|c| c.into_owned());
    tracing::warn!(staging_id = sid, step, sqlstate = sqlstate.as_deref().unwrap_or("-"), "graph_prune_restore_failed");
    if sqlstate.as_deref() == Some("23503") && step == "insert_edge" {
        // FK failure: an endpoint entity is gone (possibly itself staged;
        // restore the entity first, then retry the edge).
        return json!({"staging_id": sid, "status": "error",
                      "error": "an endpoint of this edge is not present; restore that entity first"});
    }
    json!({"staging_id": sid, "status": "error", "error": "the restore could not complete; see the gateway log"})
}

/// The restore itself, over the pool alone so a test can drive it.
pub(crate) async fn prune_restore_entity(db: &sqlx::PgPool, sid: &str) -> Value {

    let row = sqlx::query_as::<_, (Value, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT payload, restored_at::text, staged_at FROM graph_prune_staging \
         WHERE staging_id = $1::uuid",
    ).bind(sid).fetch_optional(db).await;

    let (payload, restored_at, staged_at) = match row {
        Ok(Some(r)) => r,
        Ok(None) => return json!({"staging_id": sid, "status": "not_found"}),
        Err(e) => return restore_db_error(sid, "read_row", &e),
    };
    if restored_at.is_some() {
        return json!({"staging_id": sid, "status": "already_restored"});
    }
    if payload.get("user_id").is_none() {
        return ownerless_refusal(sid);
    }
    // Right to be forgotten: a row set aside for an erased user is theirs,
    // and it does not come back.
    let owner = payload["user_id"].as_str().map(str::to_string);
    match crate::erasure_archive::user_is_erased(db, owner.as_deref(), staged_at).await {
        Ok(false) => {}
        Ok(true) => return erased_user_refusal(sid),
        Err(e) => return restore_db_error(sid, "erased_check", &e),
    }

    let entity = &payload["entity"];
    let orig_id = entity["entity_id"].as_str().unwrap_or_default().to_string();
    let name = entity["canonical_name"].as_str().unwrap_or_default().to_string();
    let etype = entity["type"].as_str().unwrap_or_default().to_string();
    if orig_id.is_empty() || name.is_empty() {
        return json!({"staging_id": sid, "status": "error", "error": "malformed payload"});
    }

    // Same (name, type) re-extracted since deletion? Graft onto it instead
    // of violating the entities_name_type_idx unique index.
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT entity_id::text FROM entities WHERE canonical_name = $1 AND type = $2",
    ).bind(&name).bind(&etype)
     .fetch_optional(db).await.ok().flatten();

    let target_id = existing.clone().unwrap_or_else(|| orig_id.clone());
    if existing.is_none() {
        let aliases = entity.get("aliases_json").cloned().unwrap_or(Value::Null);
        if let Err(e) = sqlx::query(
            "INSERT INTO entities (entity_id, canonical_name, type, aliases_json, created_at, user_id) \
             VALUES ($1::uuid, $2, $3, $4, COALESCE($5::timestamptz, now()), $6) \
             ON CONFLICT (entity_id) DO NOTHING",
        ).bind(&orig_id).bind(&name).bind(&etype).bind(&aliases)
         .bind(entity.get("created_at").and_then(|v| v.as_str()))
         .bind(owner.as_deref())
         .execute(db).await
        {
            return restore_db_error(sid, "insert_entity", &e);
        }
    }

    let empty: Vec<Value> = vec![];
    let edges = payload["edges"].as_array().unwrap_or(&empty);
    let (mut e_ok, mut e_skip) = (0u32, 0u32);
    for e in edges {
        let src = prune_remap(e["src_entity_id"].as_str(), &orig_id, &target_id);
        let dst = prune_remap(e["dst_entity_id"].as_str(), &orig_id, &target_id);
        // ON CONFLICT DO UPDATE re-points rows that still exist (merge case:
        // the edge survived, reassigned to the merge target); plain INSERT
        // covers the cascade-deleted case.
        let res = sqlx::query(
            "INSERT INTO edges (edge_id, src_entity_id, rel_type, dst_entity_id, \
                                evidence_json, created_at, confidence, \
                                classified_at, classifier_model) \
             VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, \
                     COALESCE($6::timestamptz, now()), $7, $8::timestamptz, $9) \
             ON CONFLICT (edge_id) DO UPDATE \
                SET src_entity_id = EXCLUDED.src_entity_id, \
                    dst_entity_id = EXCLUDED.dst_entity_id",
        )
        .bind(e["edge_id"].as_str())
        .bind(&src)
        .bind(e["rel_type"].as_str().unwrap_or("RELATED_TO"))
        .bind(&dst)
        .bind(e.get("evidence_json").cloned().unwrap_or(Value::Null))
        .bind(e["created_at"].as_str())
        .bind(e["confidence"].as_f64())
        .bind(e["classified_at"].as_str())
        .bind(e["classifier_model"].as_str())
        .execute(db).await;
        match res { Ok(_) => e_ok += 1, Err(_) => e_skip += 1 }
    }

    let mentions = payload["mentions"].as_array().unwrap_or(&empty);
    let (mut m_ok, mut m_skip) = (0u32, 0u32);
    for m in mentions {
        let res = sqlx::query(
            "INSERT INTO mentions (mention_id, entity_id, page_id, span_json, quote) \
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5) \
             ON CONFLICT (mention_id) DO UPDATE SET entity_id = EXCLUDED.entity_id",
        )
        .bind(m["mention_id"].as_str())
        .bind(&target_id)
        .bind(m["page_id"].as_str())
        .bind(m.get("span_json").cloned().unwrap_or(Value::Null))
        .bind(m["quote"].as_str())
        .execute(db).await;
        match res { Ok(_) => m_ok += 1, Err(_) => m_skip += 1 }
    }

    let _ = sqlx::query(
        "UPDATE graph_prune_staging SET restored_at = now() WHERE staging_id = $1::uuid",
    ).bind(sid).execute(db).await;

    json!({
        "staging_id": sid,
        "status": "restored",
        "entity_id": target_id,
        "grafted_onto_existing": existing.is_some(),
        "edges_restored": e_ok, "edges_skipped": e_skip,
        "mentions_restored": m_ok, "mentions_skipped": m_skip,
    })
}

/// The restore itself, over the pool alone so a test can drive it.
pub(crate) async fn prune_restore_edge(db: &sqlx::PgPool, sid: &str) -> Value {

    let row = sqlx::query_as::<_, (String, String, String, String, Option<f64>, Option<Value>, Option<String>,
        Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT edge_id::text, src_entity_id::text, rel_type, dst_entity_id::text, \
                confidence, evidence_json, restored_at::text, user_id, staged_at \
         FROM graph_edge_prune_staging WHERE staging_id = $1::uuid",
    ).bind(sid).fetch_optional(db).await;

    let (edge_id, src, rel, dst, confidence, evidence, restored_at, owner, staged_at) = match row {
        Ok(Some(r)) => r,
        Ok(None) => return json!({"staging_id": sid, "status": "not_found"}),
        Err(e) => return restore_db_error(sid, "read_edge_row", &e),
    };
    if restored_at.is_some() {
        return json!({"staging_id": sid, "status": "already_restored"});
    }
    match crate::erasure_archive::user_is_erased(db, owner.as_deref(), staged_at).await {
        Ok(false) => {}
        Ok(true) => return erased_user_refusal(sid),
        Err(e) => return restore_db_error(sid, "edge_erased_check", &e),
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO edges (edge_id, src_entity_id, rel_type, dst_entity_id, \
                            evidence_json, confidence, created_at, user_id) \
         VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, now(), $7) \
         ON CONFLICT (edge_id) DO NOTHING",
    )
    .bind(&edge_id).bind(&src).bind(&rel).bind(&dst)
    .bind(evidence.unwrap_or(Value::Null))
    .bind(confidence)
    .bind(owner.as_deref())
    .execute(db).await
    {
        return restore_db_error(sid, "insert_edge", &e);
    }

    let _ = sqlx::query(
        "UPDATE graph_edge_prune_staging SET restored_at = now() WHERE staging_id = $1::uuid",
    ).bind(sid).execute(db).await;

    // Symmetric with the prune's 4c: restoring an edge re-widens the
    // neighbourhood of both endpoints, so drop their embeddings to force a
    // re-embed on the next graph-signals pass (GRAPH_EDGE_METABOLISM.md).
    let _ = sqlx::query(
        "DELETE FROM entity_embeddings WHERE entity_id = ANY($1::uuid[])",
    )
    .bind(&[src.clone(), dst.clone()][..])
    .execute(db).await;

    json!({"staging_id": sid, "status": "restored", "edge_id": edge_id, "rel_type": rel})
}

/// Trellion over its existing wire: NATS `worker.*` subjects for what was
/// already delegated, direct SQL (against trellion's tables, via the
/// pool's `search_path`) for the augmentation reads/writes phase 1 lifted
/// out of the routes. Behavior-identical to the pre-facade call sites.
pub struct NatsTrellion<'a> {
    nats: &'a async_nats::Client,
    db: &'a sqlx::PgPool,
    metrics: &'a MetricsState,
}

impl NatsTrellion<'_> {
    /// Count one facade operation. This counter is the per-op frequency
    /// signal phase 0 found missing (no per-subject NATS counters exist)
    /// and the soak baseline for phase 3's transport flip.
    async fn count(&self, op: &str) {
        let mut labels = HashMap::new();
        labels.insert("op".to_string(), op.to_string());
        self.metrics
            .inc_counter("memory_provider_calls_total", Some(&labels), 1)
            .await;
    }

    /// NATS request/reply with the standard worker envelope handling.
    async fn request(&self, subject: &str, op: &str, body: &Value) -> anyhow::Result<Value> {
        self.count(op).await;
        crate::worker_client::request(self.nats, subject, body).await
    }

    /// `request` with an explicit timeout, for the handful of subjects whose
    /// work is genuinely minutes long. Separate rather than a parameter on
    /// `request` so that the default stays the default: a subject gets a
    /// long timeout because someone decided it should, not by inheriting one.
    async fn request_slow(
        &self,
        subject: &str,
        op: &str,
        body: &Value,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Value> {
        self.count(op).await;
        crate::worker_client::request_with_timeout(self.nats, subject, body, timeout).await
    }

    async fn kb_docs_list(
        &self,
        aud: &Audience,
        filter: &scope::DocFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DocRow>, sqlx::Error> {
        self.count("kb.docs_list").await;
        scope::docs_list(self.db, aud.roles(), filter, limit, offset).await
    }

    async fn kb_docs_roles_all(
        &self,
        aud: &Audience,
        filter: &scope::DocFilter,
    ) -> Result<Vec<Option<Value>>, sqlx::Error> {
        self.count("kb.docs_roles_all").await;
        scope::docs_roles_all(self.db, aud.roles(), filter).await
    }

    async fn kb_doc_detail(
        &self,
        aud: &Audience,
        doc_id: &str,
    ) -> Result<Option<scope::DocDetailRow>, sqlx::Error> {
        self.count("kb.doc_detail").await;
        scope::doc_detail(self.db, aud.roles(), doc_id).await
    }

    async fn kb_ingested_uri_meta(&self) -> Result<HashMap<String, bool>, sqlx::Error> {
        self.count("kb.docs_uri_meta").await;
        let rows: Vec<(String, bool)> = sqlx::query_as(SQL_INGESTED_URI_META)
            .fetch_all(self.db)
            .await?;
        Ok(rows.into_iter().collect())
    }

    async fn kb_doc_backfill_metadata(
        &self,
        source_uri: &str,
        metadata: &Value,
    ) -> Result<bool, sqlx::Error> {
        self.count("kb.docs_backfill_metadata").await;
        let result = sqlx::query(SQL_DOC_BACKFILL_METADATA)
            .bind(metadata.to_string())
        .bind(source_uri)
        .execute(self.db)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn kb_gdrive_titles(&self) -> Result<HashMap<String, String>, sqlx::Error> {
        self.count("kb.docs_gdrive_titles").await;
        let rows: Vec<(String, String)> = sqlx::query_as(SQL_GDRIVE_TITLES)
            .fetch_all(self.db)
            .await?;
        Ok(rows.into_iter().collect())
    }

    async fn kb_doc_repair_title(
        &self,
        source_uri: &str,
        title: &str,
    ) -> Result<bool, sqlx::Error> {
        self.count("kb.docs_repair_title").await;
        let result = sqlx::query(SQL_DOC_REPAIR_TITLE)
            .bind(title)
            .bind(source_uri)
            .execute(self.db)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn graph_search_entities(
        &self,
        aud: &Audience,
        q: &str,
    ) -> Result<Vec<EntityRow>, sqlx::Error> {
        self.count("graph.search_entities").await;
        let pattern = format!("%{q}%");
        if let Audience::Roles(roles) = aud {
            return scope::entity_search(self.db, roles, &pattern).await;
        }
        sqlx::query_as::<_, EntityRow>(SQL_ENTITY_SEARCH)
            .bind(&pattern)
        .fetch_all(self.db)
        .await
    }

    async fn graph_entity_detail(
        &self,
        aud: &Audience,
        entity_id: &str,
    ) -> Result<Option<Value>, sqlx::Error> {
        self.count("graph.entity_detail").await;
        let roles = aud.roles();

        // 1. Fetch the entity itself. A restricted caller asking for an
        // entity they cannot read gets "no such entity", not a refusal: the
        // id is addressable, and a 403 would confirm it exists.
        let entity = match roles {
            Some(r) => scope::entity_get(self.db, r, entity_id).await?,
            None => {
                sqlx::query_as::<_, EntityRow>(SQL_ENTITY_GET)
                    .bind(entity_id)
                    .fetch_optional(self.db)
                    .await?
            }
        };

        let (eid, name, etype, aliases, created) = match entity {
            Some(e) => e,
            None => return Ok(None),
        };

        // 2. Fetch 1-hop edges (same query the neighbors handler uses for hops=1)
        let edges = match roles {
            Some(r) => scope::entity_edges_1hop(self.db, r, entity_id).await,
            None => {
                sqlx::query_as::<_, (String, String, String, String, Option<Value>)>(
                    SQL_ENTITY_EDGES_1HOP,
                )
                .bind(entity_id)
                .fetch_all(self.db)
                .await
            }
        }
        .unwrap_or_default();

        // 3. Collect neighbor IDs and batch-resolve names
        let neighbor_ids: Vec<String> = edges
            .iter()
            .flat_map(|(_, src, _, dst, _)| vec![src.clone(), dst.clone()])
            .filter(|id| id != entity_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut name_map: HashMap<String, (String, String)> = HashMap::new();
        if !neighbor_ids.is_empty() {
            let neighbor_rows = match roles {
                Some(r) => scope::entity_names(self.db, r, &neighbor_ids).await,
                None => {
                    sqlx::query_as::<_, EntityNameRow>(SQL_ENTITY_NAMES)
                        .bind(&neighbor_ids)
                        .fetch_all(self.db)
                        .await
                }
            }
            .unwrap_or_default();

            for (nid, nname, ntype) in neighbor_rows {
                name_map.insert(nid, (nname, ntype));
            }
        }

        // 4. Build connections list
        let connections: Vec<Value> = edges
            .iter()
            .map(|(_, src, rel_type, dst, _)| {
                let (peer_id, direction) = if src == entity_id {
                    (dst.clone(), "outgoing")
                } else {
                    (src.clone(), "incoming")
                };
                let (peer_name, peer_type) = name_map
                    .get(&peer_id)
                    .map(|(n, t)| (n.clone(), t.clone()))
                    .unwrap_or_else(|| {
                        (peer_id[..8.min(peer_id.len())].to_string(), "unknown".to_string())
                    });

                json!({
                    "entity_id": peer_id,
                    "name": peer_name,
                    "type": peer_type,
                    "rel_type": rel_type,
                    "confidence": 1.0,
                    "direction": direction,
                })
            })
            .collect();

        // 5. Fetch pages where entity is mentioned
        let pages = match roles {
            Some(r) => scope::entity_pages(self.db, r, entity_id).await,
            None => {
                let sql = SQL_ENTITY_PAGES.replace(
                    "{HELD}",
                    &crate::held_column::not_held("d", crate::held_column::present(self.db).await),
                );
                sqlx::query_as::<_, (String, Option<i32>, Option<String>)>(sqlx::AssertSqlSafe(&*sql))
                    .bind(entity_id)
                    .fetch_all(self.db)
                    .await
            }
        }
        .unwrap_or_default();

        let pages: Vec<Value> = pages
            .iter()
            .map(|(pid, pno, title)| {
                json!({
                    "page_id": pid,
                    "page_no": pno,
                    "doc_title": title,
                })
            })
            .collect();

        Ok(Some(json!({
            "entity_id": eid,
            "canonical_name": name,
            "type": etype,
            "aliases": aliases.unwrap_or(json!([])),
            "created_at": created,
            "connections": connections,
            "pages": pages,
        })))
    }

    async fn graph_entities_resolve(
        &self,
        aud: &Audience,
        ids: &[String],
    ) -> Result<Vec<EntityNameRow>, sqlx::Error> {
        self.count("graph.entities_resolve").await;
        if let Audience::Roles(roles) = aud {
            return scope::entity_names(self.db, roles, ids).await;
        }
        sqlx::query_as::<_, EntityNameRow>(SQL_ENTITIES_RESOLVE)
            .bind(ids)
        .fetch_all(self.db)
        .await
    }

    async fn graph_neighbors(
        &self,
        aud: &Audience,
        entity_id: uuid::Uuid,
        hops: i32,
        rel_types: Option<&[String]>,
    ) -> Result<Vec<crate::repo::graph::NeighborEdge>, sqlx::Error> {
        self.count("graph.neighbors").await;
        let Some(roles) = aud.roles() else {
            return crate::repo::graph::neighbors(self.db, entity_id, hops, rel_types).await;
        };
        // The traversal itself stays the one recursive CTE in `repo::graph`
        // (hottest query in the database); a restricted caller gets its rows
        // filtered after the fact. The START entity must be readable, or a
        // hidden entity's neighbourhood would be walkable by id.
        if scope::entity_get(self.db, roles, &entity_id.to_string()).await?.is_none() {
            return Ok(Vec::new());
        }
        let rows = crate::repo::graph::neighbors(self.db, entity_id, hops, rel_types).await?;
        let ids: Vec<String> = rows.iter().map(|r| r.0.clone()).collect();
        let ok = scope::readable_edge_ids(self.db, roles, &ids).await?;
        Ok(rows.into_iter().filter(|r| ok.contains(&r.0)).collect())
    }

    async fn graph_top_entities(
        &self,
        aud: &Audience,
        min_degree: i32,
        entity_type: Option<&str>,
        limit: i32,
    ) -> Result<Vec<crate::repo::graph::EntityDegree>, sqlx::Error> {
        self.count("graph.top_entities").await;
        if let Audience::Roles(roles) = aud {
            return scope::top_entities(self.db, roles, min_degree, entity_type, limit).await;
        }
        crate::repo::graph::top_entities_by_degree(self.db, min_degree, entity_type, limit).await
    }

    async fn graph_overview_edges(
        &self,
        aud: &Audience,
        node_ids: &[String],
    ) -> Result<Vec<OverviewEdgeRow>, sqlx::Error> {
        self.count("graph.overview_edges").await;
        if let Audience::Roles(roles) = aud {
            return scope::overview_edges(self.db, roles, node_ids).await;
        }
        sqlx::query_as::<_, OverviewEdgeRow>(SQL_OVERVIEW_EDGES)
            .bind(node_ids)
        .fetch_all(self.db)
        .await
    }

    async fn graph_clusters(
        &self,
        aud: &Audience,
        level: i32,
        min_members: i32,
        limit: i32,
    ) -> Result<Vec<ClusterRow>, sqlx::Error> {
        self.count("graph.clusters").await;
        if let Audience::Roles(roles) = aud {
            return scope::clusters(self.db, roles, level, min_members, limit).await;
        }
        sqlx::query_as::<_, ClusterRow>(SQL_CLUSTERS)
            .bind(level)
        .bind(min_members)
        .bind(limit)
        .fetch_all(self.db)
        .await
    }

    async fn graph_cluster_edges(
        &self,
        aud: &Audience,
        level: i32,
        cluster_ids: &[String],
    ) -> Result<Vec<ClusterEdgeRow>, sqlx::Error> {
        self.count("graph.cluster_edges").await;
        if let Audience::Roles(roles) = aud {
            return scope::cluster_edges(self.db, roles, level, cluster_ids).await;
        }
        sqlx::query_as::<_, ClusterEdgeRow>(SQL_CLUSTER_EDGES)
            .bind(level)
        .bind(cluster_ids)
        .fetch_all(self.db)
        .await
    }

    async fn graph_entity_count(&self, aud: &Audience) -> Result<i64, sqlx::Error> {
        self.count("graph.entity_count").await;
        match aud {
            Audience::Roles(roles) => scope::entity_count(self.db, roles).await,
            Audience::Unrestricted => {
                sqlx::query_scalar("SELECT COUNT(*) FROM entities").fetch_one(self.db).await
            }
        }
    }

    async fn graph_prune_staged(
        &self,
        limit: i64,
        reason: Option<&str>,
        include_restored: bool,
    ) -> Value {
        self.count("graph.prune_staged").await;

        let mut sql = String::from(
            "SELECT staging_id::text, entity_id::text, canonical_name, entity_type, \
                    reason, staged_at::text, restored_at::text, run_id, \
                    jsonb_array_length(COALESCE(payload->'edges', '[]'::jsonb)), \
                    jsonb_array_length(COALESCE(payload->'mentions', '[]'::jsonb)) \
             FROM graph_prune_staging WHERE 1=1",
        );
        if !include_restored {
            sql.push_str(" AND restored_at IS NULL");
        }
        if reason.is_some() {
            sql.push_str(" AND reason = $2");
        }
        sql.push_str(" ORDER BY staged_at DESC LIMIT $1");

        let q = sqlx::query_as::<_, (String, String, String, String, String,
            String, Option<String>, Option<String>, i32, i32)>(sqlx::AssertSqlSafe(&*sql))
            .bind(limit);
        let q = if let Some(r) = reason { q.bind(r) } else { q };

        let rows = match q.fetch_all(self.db).await {
            Ok(rows) => rows,
            // Table missing → prune never ran; report empty rather than 500
            Err(_) => {
                return json!({
                    "staged": [], "counts": {},
                    "note": "staging table not created yet — graph_prune has not run",
                });
            }
        };

        let staged: Vec<Value> = rows.iter().map(|r| json!({
            "staging_id": r.0, "entity_id": r.1, "canonical_name": r.2,
            "entity_type": r.3, "reason": r.4, "staged_at": r.5,
            "restored_at": r.6, "run_id": r.7,
            "edge_count": r.8, "mention_count": r.9,
        })).collect();

        let counts_rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT reason, COUNT(*) FROM graph_prune_staging \
             WHERE restored_at IS NULL GROUP BY reason",
        ).fetch_all(self.db).await.unwrap_or_default();
        let mut counts = serde_json::Map::new();
        for (reason, n) in counts_rows {
            counts.insert(reason, json!(n));
        }

        // Staged EDGES (edge-metabolism tier writes graph_edge_prune_staging).
        // Endpoint names resolved for display; entity may itself be staged, in
        // which case the name comes back NULL and the UI shows the id prefix.
        let mut edge_sql = String::from(
            "SELECT s.staging_id::text, s.edge_id::text, s.rel_type, s.reason, \
                    s.staged_at::text, s.restored_at::text, s.confidence, \
                    se.canonical_name, de.canonical_name, \
                    s.src_entity_id::text, s.dst_entity_id::text \
             FROM graph_edge_prune_staging s \
             LEFT JOIN entities se ON se.entity_id = s.src_entity_id \
             LEFT JOIN entities de ON de.entity_id = s.dst_entity_id \
             WHERE 1=1",
        );
        if !include_restored {
            edge_sql.push_str(" AND s.restored_at IS NULL");
        }
        edge_sql.push_str(" ORDER BY s.staged_at DESC LIMIT $1");
        let edge_rows = sqlx::query_as::<_, (String, String, String, String, String,
            Option<String>, Option<f64>, Option<String>, Option<String>, String, String)>(sqlx::AssertSqlSafe(&*edge_sql))
            .bind(limit)
            .fetch_all(self.db).await.unwrap_or_default();
        let staged_edges: Vec<Value> = edge_rows.iter().map(|r| json!({
            "staging_id": r.0, "edge_id": r.1, "rel_type": r.2, "reason": r.3,
            "staged_at": r.4, "restored_at": r.5, "confidence": r.6,
            "src_name": r.7.clone().unwrap_or_else(|| r.9[..8.min(r.9.len())].to_string()),
            "dst_name": r.8.clone().unwrap_or_else(|| r.10[..8.min(r.10.len())].to_string()),
        })).collect();
        let edge_counts_rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT reason, COUNT(*) FROM graph_edge_prune_staging \
             WHERE restored_at IS NULL GROUP BY reason",
        ).fetch_all(self.db).await.unwrap_or_default();
        let mut edge_counts = serde_json::Map::new();
        for (reason, n) in edge_counts_rows {
            edge_counts.insert(reason, json!(n));
        }

        json!({
            "staged": staged, "counts": counts,
            "staged_edges": staged_edges, "edge_counts": edge_counts,
        })
    }

    async fn graph_prune_restore_entity(&self, sid: &str) -> Value {
        self.count("graph.prune_restore_entity").await;
        prune_restore_entity(self.db, sid).await
    }

    async fn graph_prune_restore_run(&self, run_id: &str, limit: i64) -> Value {
        self.count("graph.prune_restore_run").await;
        prune_restore_run(self.db, run_id, limit).await
    }

    /// Restore one staged EDGE (edge-metabolism tier). The snapshot lives in
    /// columns rather than JSONB. `created_at` resets to now() and the edge
    /// returns unclassified — the classifier re-scores it, which is the right
    /// outcome for a low-confidence snip the operator decided to keep.
    async fn graph_prune_restore_edge(&self, sid: &str) -> Value {
        self.count("graph.prune_restore_edge").await;
        prune_restore_edge(self.db, sid).await
    }

    async fn semantic_relationships(
        &self,
        record_id: &str,
        limit: i64,
    ) -> Result<Vec<(String, f64)>, sqlx::Error> {
        self.count("memory.semantic_relationships").await;
        sqlx::query_as::<_, (String, f64)>(SQL_SEMANTIC_RELATIONSHIPS)
            .bind(record_id)
        .bind(limit)
        .fetch_all(self.db)
        .await
    }

    async fn snapshots_list(
        &self,
        kind: Option<&str>,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Value>, sqlx::Error> {
        self.count("snapshots.list").await;
        let mut sql = String::from(SQL_SNAPSHOTS_LIST_BASE);
        if kind.is_some() {
            sql.push_str("AND slice_kind = $1 ");
        }
        if status.is_some() {
            let n = if kind.is_some() { 2 } else { 1 };
            sql.push_str(&format!("AND status = ${n} "));
        }
        let limit_idx = match (kind.is_some(), status.is_some()) {
            (true, true) => 3,
            (true, false) | (false, true) => 2,
            (false, false) => 1,
        };
        sql.push_str(&format!("ORDER BY created_at DESC LIMIT ${limit_idx}"));

        let mut q = sqlx::query(sqlx::AssertSqlSafe(&*sql));
        if let Some(k) = kind {
            q = q.bind(k);
        }
        if let Some(s) = status {
            q = q.bind(s);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(self.db).await?;
        Ok(rows.into_iter().map(|r| snapshot_row_to_summary(&r)).collect())
    }

    async fn snapshots_get(&self, snapshot_id: &str) -> Result<Option<Value>, sqlx::Error> {
        self.count("snapshots.get").await;
        let row = sqlx::query(SQL_SNAPSHOT_GET)
            .bind(snapshot_id)
            .fetch_optional(self.db)
        .await?;
        Ok(row.map(|r| snapshot_row_to_summary(&r)))
    }

    async fn snapshot_concepts(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        self.count("snapshots.concepts").await;
        use sqlx::Row as _;
        let rows = sqlx::query(SQL_SNAPSHOT_CONCEPTS)
            .bind(snapshot_id)
            .fetch_all(self.db)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                let n: String = r.get(0);
                let t: String = r.get(1);
                (n, t)
            })
            .collect())
    }
}

fn prune_remap(v: Option<&str>, from: &str, to: &str) -> String {
    match v {
        Some(s) if s == from => to.to_string(),
        Some(s) => s.to_string(),
        None => String::new(),
    }
}

fn snapshot_row_to_summary(r: &sqlx::postgres::PgRow) -> Value {
    use sqlx::Row as _;
    let id: String = r.get(0);
    let generation: i32 = r.try_get(1).unwrap_or(0);
    let slice_kind: String = r.try_get(2).unwrap_or_default();
    let slice_spec: Option<Value> = r.try_get(3).ok();
    let status: String = r.try_get(4).unwrap_or_default();
    let created_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get(5).ok();
    let completed_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get(6).ok();
    let stats: Option<Value> = r.try_get(7).ok();
    let label: Option<String> = r.try_get(8).ok();
    json!({
        "id": id,
        "generation": generation,
        "kind": slice_kind,
        "spec": slice_spec.unwrap_or(json!({})),
        "status": status,
        "created_at": created_at.map(|d| d.to_rfc3339()),
        "completed_at": completed_at.map(|d| d.to_rfc3339()),
        "stats": stats.unwrap_or(json!({})),
        "label": label,
    })
}

// ── restore of one cleanup run, over the pool alone so a test can drive it ──

pub(crate) async fn prune_restore_run(db: &sqlx::PgPool, run_id: &str, limit: i64) -> Value {
    let ids: Vec<String> = match sqlx::query_scalar::<_, String>(
        "SELECT staging_id::text FROM graph_prune_staging \
         WHERE run_id = $1 AND restored_at IS NULL AND payload ? 'entity' \
         ORDER BY staging_id LIMIT $2",
    )
    .bind(run_id)
    .bind(limit)
    .fetch_all(db)
    .await
    {
        Ok(v) => v,
        Err(_) => return json!({"run_id": run_id, "status": "error", "error": "the staging table could not be read"}),
    };
    // Put every entity row of the batch back FIRST. A cleanup snapshots an edge
    // between two junk entities with whichever endpoint it staged first, so
    // restoring entities one at a time would skip that edge (its other
    // endpoint is still gone). With all the rows present the per-entity restore
    // below re-creates every edge; it reports each as "grafted onto existing"
    // because the row is already there.
    // A row of an ERASED owner is neither pre-inserted nor restored (the per-row
    // restore refuses it below): filter with the one erased check, unowned rows
    // count as not erased. The owner rides along so a restored row keeps it.
    // A row with no `user_id` key is left out too (the per-row restore refuses it).
    let mut keep: Vec<String> = Vec::with_capacity(ids.len());
    if let Ok(rows) = sqlx::query_as::<_, (String, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT staging_id::text, payload->>'user_id', staged_at FROM graph_prune_staging \
         WHERE staging_id = ANY($1::uuid[]) AND payload ? 'user_id'",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    {
        for (sid, owner, staged_at) in rows {
            // On error, leave the row out of the pre-insert; the per-row restore reports it.
            if let Ok(false) = crate::erasure_archive::user_is_erased(db, owner.as_deref(), staged_at).await {
                keep.push(sid);
            }
        }
    }
    let _ = sqlx::query(
        "INSERT INTO entities (entity_id, canonical_name, type, aliases_json, created_at, user_id) \
         SELECT (payload->'entity'->>'entity_id')::uuid, payload->'entity'->>'canonical_name', \
                payload->'entity'->>'type', payload->'entity'->'aliases_json', \
                COALESCE((payload->'entity'->>'created_at')::timestamptz, now()), payload->>'user_id' \
         FROM graph_prune_staging WHERE staging_id = ANY($1::uuid[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&keep)
    .execute(db)
    .await;
    let (mut restored, mut other) = (0i64, 0i64);
    let (mut edges, mut mentions) = (0i64, 0i64);
    for sid in &ids {
        let r = prune_restore_entity(db, sid).await;
        if r["status"] == "restored" {
            restored += 1;
            edges += r["edges_restored"].as_i64().unwrap_or(0);
            mentions += r["mentions_restored"].as_i64().unwrap_or(0);
        } else {
            other += 1;
        }
    }
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM graph_prune_staging WHERE run_id = $1 AND restored_at IS NULL AND payload ? 'entity'",
    )
    .bind(run_id)
    .fetch_one(db)
    .await
    .unwrap_or(-1);
    json!({
        "run_id": run_id, "status": "ok", "restored": restored, "not_restored": other,
        "edges_restored": edges, "mentions_restored": mentions, "remaining": remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase-1 invariant: routing decisions unchanged. The NatsTrellion
    /// impl must publish to exactly the subjects the pre-facade call
    /// sites used — a renamed subject would strand requests on a wire
    /// nothing answers, silently.
    #[test]
    fn nats_subjects_match_pre_facade_call_sites() {
        // routes/knowledge.rs used delegate_post("worker.rag.query") /
        // ("worker.rag.ingest") / ("worker.rag.deduplicate"); docs_ingest
        // and ingest_loop.rs::submit_ingest called worker.rag.ingest.
        assert_eq!(SUBJECT_KB_QUERY, "worker.rag.query");
        assert_eq!(SUBJECT_KB_INGEST, "worker.rag.ingest");
        assert_eq!(SUBJECT_KB_DEDUPLICATE, "worker.rag.deduplicate");
        assert_eq!(SUBJECT_KB_RETAG, "worker.rag.retag");
        assert_eq!(SUBJECT_KB_HOLD, "worker.rag.hold");
        assert_eq!(SUBJECT_KB_UNHOLD, "worker.rag.unhold");
        assert_eq!(SUBJECT_KB_HELD, "worker.rag.held");
        assert_eq!(SUBJECT_KB_PURGE, "worker.rag.purge");
        assert_eq!(SUBJECT_GRAPH_RECLUSTER, "worker.graph.recluster");
        assert_eq!(SUBJECT_ENTITY_CLEANUP, "worker.rag.entity_cleanup");
        // Every capability the route table names must resolve to a subject.
        for (op, subject) in SUBJECT_GRAPH_INTEL {
            assert!(subject.starts_with("worker.graph."), "{subject}");
            assert!(!op.is_empty());
        }
        assert_eq!(SUBJECT_GRAPH_INTEL.len(), 9); // + recall_walks
        // routes/snapshots.rs used delegate_post + a custom curriculum
        // handler on these two subjects.
        assert_eq!(SUBJECT_SNAPSHOTS_CONSOLIDATE, "worker.api.snapshots.consolidate");
        assert_eq!(SUBJECT_SNAPSHOTS_CURRICULUM, "worker.api.snapshots.curriculum");
        assert_eq!(SUBJECT_SNAPSHOTS_SCOPED, "worker.api.snapshots.scoped");
    }

    /// Phase-1 invariant, SQL half: the statements the facade issues are
    /// byte-identical to the ones the routes issued before the move.
    /// Each expected literal below is copied from the pre-facade file
    /// named in the comment — if a query needs to change, phase 1 is
    /// over and this test changes WITH it, knowingly.
    #[test]
    fn sql_matches_pre_facade_call_sites() {
        // routes/knowledge.rs::graph_entities
        assert_eq!(
            SQL_ENTITY_SEARCH,
            "SELECT entity_id::text, canonical_name, type, aliases_json, created_at \
             FROM entities \
             WHERE canonical_name ILIKE $1 \
             ORDER BY canonical_name \
             LIMIT 50"
        );
        // routes/knowledge.rs::graph_entity_detail (steps 1, 2, 3, 5)
        assert_eq!(
            SQL_ENTITY_GET,
            "SELECT entity_id::text, canonical_name, type, aliases_json, created_at \
             FROM entities WHERE entity_id = $1::uuid"
        );
        assert_eq!(
            SQL_ENTITY_EDGES_1HOP,
            "SELECT edge_id::text, src_entity_id::text, rel_type, dst_entity_id::text, evidence_json \
             FROM edges \
             WHERE src_entity_id = $1::uuid OR dst_entity_id = $1::uuid"
        );
        assert_eq!(
            SQL_ENTITY_NAMES,
            "SELECT entity_id::text, canonical_name, type FROM entities \
             WHERE entity_id = ANY($1::uuid[])"
        );
        assert_eq!(
            SQL_ENTITY_PAGES,
            "SELECT p.page_id::text, p.page_no, d.title \
             FROM pages p \
             JOIN docs d ON d.doc_id = p.doc_id \
             WHERE {HELD} \
               AND p.page_id IN (SELECT DISTINCT page_id FROM mentions WHERE entity_id = $1::uuid)"
        );
        // routes/knowledge.rs::graph_entities_resolve
        assert_eq!(
            SQL_ENTITIES_RESOLVE,
            "SELECT entity_id::text, canonical_name, type \
             FROM entities WHERE entity_id = ANY($1::uuid[])"
        );
        // routes/knowledge.rs::graph_overview edge query
        assert_eq!(
            SQL_OVERVIEW_EDGES,
            "SELECT src_entity_id::text, dst_entity_id::text, rel_type, confidence, created_at \
             FROM edges \
             WHERE src_entity_id::text = ANY($1::text[]) \
               AND dst_entity_id::text = ANY($1::text[]) \
             LIMIT 5000"
        );
        // routes/knowledge.rs::graph_clusters_overview
        assert_eq!(
            SQL_CLUSTERS,
            "SELECT cluster_id::text, name, level, member_count \
             FROM entity_clusters \
             WHERE level = $1 AND member_count >= $2 \
             ORDER BY member_count DESC \
             LIMIT $3"
        );
        assert_eq!(
            SQL_CLUSTER_EDGES,
            "SELECT m1.cluster_id::text AS src_cluster, \
                    m2.cluster_id::text AS dst_cluster, \
                    COUNT(*) AS weight \
             FROM edges e \
             JOIN entity_cluster_members m1 ON m1.entity_id = e.src_entity_id \
             JOIN entity_cluster_members m2 ON m2.entity_id = e.dst_entity_id \
             JOIN entity_clusters c1 ON c1.cluster_id = m1.cluster_id AND c1.level = $1 \
             JOIN entity_clusters c2 ON c2.cluster_id = m2.cluster_id AND c2.level = $1 \
             WHERE m1.cluster_id::text = ANY($2::text[]) \
               AND m2.cluster_id::text = ANY($2::text[]) \
               AND m1.cluster_id <> m2.cluster_id \
             GROUP BY m1.cluster_id, m2.cluster_id \
             HAVING COUNT(*) >= 2 \
             ORDER BY weight DESC \
             LIMIT 2000"
        );
        // routes/memory.rs::relationships (the L529 augmentation read)
        assert_eq!(
            SQL_SEMANTIC_RELATIONSHIPS,
            "SELECT target_id::text, similarity \
             FROM noo_semantic_relationships \
             WHERE source_id = $1::uuid \
             ORDER BY similarity DESC \
             LIMIT $2"
        );
        // routes/snapshots.rs::snapshots_list / snapshots_get / diff loads
        assert_eq!(
            SQL_SNAPSHOTS_LIST_BASE,
            "SELECT id::text, generation, slice_kind, slice_spec, status, \
                    created_at, completed_at, stats, label \
             FROM trellion_snapshots WHERE 1=1 "
        );
        assert_eq!(
            SQL_SNAPSHOT_GET,
            "SELECT id::text, generation, slice_kind, slice_spec, status, \
                    created_at, completed_at, stats, label \
             FROM trellion_snapshots WHERE id = $1::uuid"
        );
        assert_eq!(
            SQL_SNAPSHOT_CONCEPTS,
            "SELECT canonical_name, type FROM trellion_concepts \
             WHERE snapshot_id = $1::uuid"
        );
        // ingest_loop.rs::fetch_ingested_uri_meta / backfill_metadata —
        // whitespace included: these were multiline string literals.
        assert!(SQL_INGESTED_URI_META.contains("SELECT jsonb_array_elements_text(metadata->'aliased_uris') AS uri,"));
        assert!(SQL_INGESTED_URI_META.contains("GROUP BY uri"));
        assert!(SQL_DOC_BACKFILL_METADATA.contains("SET metadata = $1::jsonb"));
        assert!(SQL_DOC_BACKFILL_METADATA.contains("AND (metadata IS NULL OR metadata = '{}'::jsonb)"));
        // ingest_loop.rs title-repair pass (drive_title slash fix).
        assert!(SQL_GDRIVE_TITLES.contains("WHERE source_uri LIKE 'gdrive://%'"));
        assert!(SQL_DOC_REPAIR_TITLE.contains("SET title = $1"));
        // Guarded so an unchanged title is a no-op, not a spurious write.
        assert!(SQL_DOC_REPAIR_TITLE.contains("AND title IS DISTINCT FROM $1"));
    }

    /// The prune-restore remap helper moved here verbatim from
    /// routes/knowledge.rs — same semantics.
    #[test]
    fn prune_remap_preserves_semantics() {
        assert_eq!(prune_remap(Some("a"), "a", "b"), "b");
        assert_eq!(prune_remap(Some("c"), "a", "b"), "c");
        assert_eq!(prune_remap(None, "a", "b"), "");
    }
}
