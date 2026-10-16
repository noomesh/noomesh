// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Memory routes — conversations, search, embeddings, diagnostics.
//!
//! Native Rust: storage stats, cleanup, relationships,
//!              conversations-with-preview, conversation stats/feedback/detail,
//!              health, search (TEI + pgvector), status, per-user stats,
//!              embed start/stop/status (Redis flag + SQL counts).
//! NATS delegation: batch-index.

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path, Query},
    Extension,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{holds_control_scope, scoped_user, ClusterNode, RequesterCtx, CONVERSATION_STATS_SCOPE};
use crate::auth::AuthActor;

use crate::state::AppState;
use super::{AppError, AppResult};
use super::delegation::delegate_post;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Native Rust (SQL queries) ──
        .route("/api/memory/storage-stats", get(storage_stats))
        .route("/api/memory/cleanup", post(cleanup))
        .route("/api/memory/relationships/{record_id}", get(relationships))
        // Conversations — all native Rust (SQL via sqlx)
        // Both paths, one handler. `/api/conversations` is the name every
        // client reaches for and the one the spec has always documented; it
        // was never registered, so `noo-py memory conversations`
        // (`memory_cli.py:318`) has been 404ing against a documented
        // endpoint. `with-preview` is kept because it is the name in the
        // contract the console builds against.
        .route("/api/conversations", get(conversations_with_preview))
        .route("/api/conversations/with-preview", get(conversations_with_preview))
        .route("/api/conversations/stats/tools", get(conv_stats_tools))
        .route("/api/conversations/stats/overview", get(conv_stats_overview))
        .route("/api/conversations/feedback/stats", get(conv_feedback_stats))
        .route("/api/conversations/feedback/export/dpo", get(conv_feedback_export_dpo))
        .route("/api/conversations/{conversation_id}", get(conv_detail))
        .route("/api/conversations/{conversation_id}/feedback", post(conv_feedback))

        // ── Native Rust (SQL + TEI HTTP) — ported from NATS delegation 2026-03-31 ──
        .route("/api/memory/health", get(memory_health))
        .route("/api/memory/status", get(memory_status))
        .route("/api/memory/stats/{user_id}", get(memory_stats))
        .route("/api/memory/search", get(memory_search))

        // ── Native Rust (Redis flag + SQL) — embed control (ported 2026-03-31) ──
        .route("/api/memory/embed/start", post(embed_start))
        .route("/api/memory/embed/status", get(embed_status))
        .route("/api/memory/embed/stop", post(embed_stop))

        // ── NATS delegation (needs Python runtime) ──
        .route("/api/memory/batch-index", post(delegate_post("worker.memory.batch_index")))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — pure SQL via sqlx
// ═══════════════════════════════════════════════════════════════

/// The one place that answers "is conversation-memory embedding configured?".
///
/// Returns `(embeddings_enabled, model_or_none)`.
///
/// Both `storage_stats` and `memory_status` used to emit a hardcoded
/// `"embeddings_enabled": true` — a constant masquerading as a check — while
/// `embed_status` on the same data resolved `embedding.model` from the YAML
/// config and could correctly report it empty. So an install with no embedding
/// model configured was told "embeddings enabled" by two endpoints and
/// "model: null" by a third. One resolution, three readers.
async fn resolve_embedding_model(state: &Arc<AppState>) -> Option<String> {
    let config_yaml = state.config_yaml.read().await;
    config_yaml
        .get("embedding")
        .and_then(|e| e.get("model"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Storage stats — count total, embedded, unembedded records.
///
/// `unique_users` counts PEOPLE, resolved through the channel-link table,
/// not distinct `user_id` strings.
///
/// A conversation records whatever id the sender arrived with. Before a
/// channel identity is linked to an account that is the raw channel id
/// (`8511512558`, `users/1152615…`); afterwards it is the canonical
/// username. Linking does NOT rewrite history — `link_channel` upserts one
/// row into `noo_user_channel_links` and never touches `noo_conversations`,
/// which is the right call for attribution but means the raw ids stay
/// forever.
///
/// So the old `COUNT(DISTINCT user_id)` reported one operator with a
/// Telegram and a Google Chat link as THREE users, permanently, and the
/// dashboard disagreed with `noo security user list` with no way to
/// reconcile them (operator, 2026-09-06: "why does it say 4 users when we
/// only saw 2?"). Same word, two populations.
///
/// The LEFT JOIN resolves each id to its account where one exists and
/// leaves it alone where it does not, so an unlinked sender still counts as
/// someone. History is untouched: this is a read-time fix, and rewriting
/// prior attribution would be the destructive way to get the same number.
async fn storage_stats(State(state): State<Arc<AppState>>) -> AppResult {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT COUNT(*) AS total, \
                COUNT(embedding) AS embedded, \
                (COUNT(*) - COUNT(embedding)) AS unembedded, \
                (SELECT COUNT(DISTINCT COALESCE(l.username, c.user_id)) \
                   FROM noo_conversations c \
                   LEFT JOIN noo_user_channel_links l \
                          ON l.channel_user_id = c.user_id) AS unique_users \
         FROM noo_entries"
    )
    .fetch_optional(&state.db)
    .await?;

    let emb_model = resolve_embedding_model(&state).await;

    match row {
        Some((total, embedded, unembedded, unique_users)) => Ok(Json(json!({
            "storage": "postgresql",
            "total_records": total,
            "embedded_records": embedded,
            "unembedded_records": unembedded,
            "unique_users": unique_users,
            // Was a literal `true`. Now derived from the same resolution
            // /api/memory/embed-status reports.
            "embeddings_enabled": emb_model.is_some(),
            "embedding_model": emb_model,
            "ready_for_indexing": unembedded > 0,
        }))),
        None => Ok(Json(json!({
            "storage": "postgresql",
            "total_records": 0,
            "embedded_records": 0,
            "unembedded_records": 0,
            "unique_users": 0,
        }))),
    }
}

// ═══════════════════════════════════════════════════════════════
// Ported from NATS delegation → native Rust
// health, search (TEI + pgvector), status, per-user stats
// ═══════════════════════════════════════════════════════════════

/// GET /api/memory/health — SQL health checks on noo_entries + noo_conversations.
pub(super) async fn memory_health(State(state): State<Arc<AppState>>) -> AppResult {
    // Entry stats
    let entry_row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*) AS total, \
                COUNT(embedding) AS embedded, \
                (COUNT(*) - COUNT(embedding)) AS unembedded \
         FROM noo_entries"
    )
    .fetch_one(&state.db)
    .await;

    // Conversation stats (30-day window)
    let conv_row = sqlx::query_as::<_, (i64, Option<i64>, Option<f64>)>(
        "SELECT COUNT(*), \
                SUM(total_messages), \
                AVG(total_messages)::float8 \
         FROM noo_conversations \
         WHERE started_at > NOW() - INTERVAL '30 days'"
    )
    .fetch_one(&state.db)
    .await;

    // Timestamps for oldest/newest entry
    let time_row = sqlx::query_as::<_, (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT MIN(created_at), MAX(created_at) FROM noo_entries"
    )
    .fetch_one(&state.db)
    .await;

    match (entry_row, conv_row, time_row) {
        (Ok((total, embedded, unembedded)), Ok((convs_30d, msgs_30d, avg_msgs)), Ok((oldest, newest))) => {
            let embed_pct = if total > 0 { (embedded as f64 / total as f64) * 100.0 } else { 0.0 };
            let mut warnings: Vec<String> = Vec::new();
            if total == 0 {
                warnings.push("No conversation entries recorded yet".into());
            } else if embed_pct < 50.0 {
                warnings.push(format!("Only {embed_pct:.1}% of entries embedded — search misses recent conversations"));
            }

            let score = if total > 0 { embed_pct } else { 0.0 };
            let grade = match score as u32 {
                90..=100 => "A",
                75..=89  => "B",
                50..=74  => "C",
                25..=49  => "D",
                _        => "F",
            };
            let warning_count = warnings.len();

            Ok(Json(json!({
                "conversation_memory": {
                    "total_entries": total,
                    "embedded_entries": embedded,
                    "unembedded_entries": unembedded,
                    "embedding_coverage_pct": (embed_pct * 10.0).round() / 10.0,
                    "conversations_30d": convs_30d,
                    "messages_30d": msgs_30d.unwrap_or(0),
                    "avg_messages_per_conversation": (avg_msgs.unwrap_or(0.0) * 10.0).round() / 10.0,
                    "oldest_record": oldest.map(|dt| dt.to_rfc3339()),
                    "newest_record": newest.map(|dt| dt.to_rfc3339()),
                    "coverage_score": (score * 10.0).round() / 10.0,
                    "warnings": warnings,
                },
                "overall": {
                    "score": (score * 10.0).round() / 10.0,
                    "grade": grade,
                    "systems_checked": 1,
                    "total_warnings": warning_count,
                },
            })))
        }
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            Ok(Json(json!({
                "conversation_memory": {"error": e.to_string()},
                "overall": {"score": 0, "grade": "F", "systems_checked": 0},
            })))
        }
    }
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    query: Option<String>,
    user_id: Option<String>,
    limit: Option<i64>,
    top_k: Option<i64>,
}

/// GET /api/memory/search — embed query via the configured embedding
/// backend, then pgvector cosine similarity.
async fn memory_search(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<SearchParams>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        params.user_id.as_deref(),
    )
    .map_err(AppError::Forbidden)?;
    let query_text = params.q
        .or(params.query)
        .unwrap_or_default();

    if query_text.is_empty() {
        return Err(AppError::BadRequest("Missing query parameter 'q' or 'query'".into()));
    }

    let top_k = params.limit.or(params.top_k).unwrap_or(5).min(50);

    // 1. Embed the query via the configured backend (tei | openai | ollama)
    // Truncate to 1500 chars (matching Python embed behaviour)
    let truncated: String = query_text.chars().take(1500).collect();

    let embedding = crate::embedding_client::resolve()
        .embed_one_with_mesh(&state, &truncated, std::time::Duration::from_secs(30))
        .await
        .map_err(|e| AppError::Internal(format!("query embedding failed: {e}")))?;

    // Format as pgvector literal: [0.1,0.2,...]
    let vec_str = crate::embedding_client::pgvector_literal(&embedding);

    memory_search_rows(&state, &query_text, &vec_str, scope.as_deref(), top_k)
        .await
        .map(Json)
}

/// Shared pgvector search + response shaping for `/api/memory/search` and
/// the native `noo_memory_search` tool executor (`tools::execute_native`).
/// The two callers embed differently (the route can fall back to mesh
/// embedding, the tool path uses the plain embedding client), so the query
/// vector arrives pre-computed; everything from SQL to the response JSON
/// `{query, count, results}` lives here exactly once.
pub(crate) async fn memory_search_rows(
    state: &AppState,
    query_text: &str,
    vec_str: &str,
    user_id: Option<&str>,
    top_k: i64,
) -> Result<Value, AppError> {
    // pgvector cosine similarity search on noo_entries
    let rows = if let Some(uid) = user_id {
        sqlx::query_as::<_, (String, String, String, Option<chrono::DateTime<chrono::Utc>>, f64)>(
            "SELECT e.id::text, e.type, e.content, e.created_at, \
                    1 - (e.embedding <=> CAST($1 AS vector)) AS score \
             FROM noo_entries e \
             JOIN noo_conversations c ON e.conversation_id = c.id \
             WHERE e.embedding IS NOT NULL \
               AND (c.user_id = $2 OR c.user_id IS NULL) \
             ORDER BY e.embedding <=> CAST($1 AS vector) \
             LIMIT $3"
        )
        .bind(vec_str)
        .bind(uid)
        .bind(top_k)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, Option<chrono::DateTime<chrono::Utc>>, f64)>(
            "SELECT e.id::text, e.type, e.content, e.created_at, \
                    1 - (e.embedding <=> CAST($1 AS vector)) AS score \
             FROM noo_entries e \
             WHERE e.embedding IS NOT NULL \
             ORDER BY e.embedding <=> CAST($1 AS vector) \
             LIMIT $2"
        )
        .bind(vec_str)
        .bind(top_k)
        .fetch_all(&state.db)
        .await?
    };

    let results: Vec<Value> = rows.iter().map(|(id, typ, content, created_at, score)| {
        let truncated = if content.chars().count() > 500 {
            format!("{}...", content.chars().take(500).collect::<String>())
        } else {
            content.clone()
        };
        json!({
            "id": id,
            "type": typ,
            "content": truncated,
            "score": (score * 1000.0).round() / 1000.0,
            "created_at": created_at.map(|dt| dt.to_rfc3339()),
        })
    }).collect();

    Ok(json!({
        "query": query_text,
        "count": results.len(),
        "results": results,
    }))
}

/// GET /api/memory/status — memory system status (record counts, embedding coverage).
async fn memory_status(State(state): State<Arc<AppState>>) -> AppResult {
    // Entry stats
    let entry_row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*) AS total, \
                COUNT(embedding) AS embedded, \
                (COUNT(*) - COUNT(embedding)) AS unembedded \
         FROM noo_entries"
    )
    .fetch_one(&state.db)
    .await;

    // Unique users
    let user_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT user_id) FROM noo_conversations"
    )
    .fetch_one(&state.db)
    .await;

    // Timestamps
    let time_row = sqlx::query_as::<_, (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT MIN(created_at), MAX(created_at) FROM noo_entries"
    )
    .fetch_one(&state.db)
    .await;

    let emb_model = resolve_embedding_model(&state).await;

    match (entry_row, user_count, time_row) {
        (Ok((total, embedded, unembedded)), Ok(users), Ok((oldest, newest))) => {
            let embed_pct = if total > 0 { (embedded as f64 / total as f64) * 100.0 } else { 0.0 };
            Ok(Json(json!({
                "status": "ok",
                "storage": "postgresql",
                "total_records": total,
                "embedded_records": embedded,
                "unembedded_records": unembedded,
                "embedding_coverage_pct": (embed_pct * 10.0).round() / 10.0,
                "unique_users": users,
                "oldest_record": oldest.map(|dt| dt.to_rfc3339()),
                "newest_record": newest.map(|dt| dt.to_rfc3339()),
                // Was a literal `true`; see resolve_embedding_model.
                "embeddings_enabled": emb_model.is_some(),
                "embedding_model": emb_model,
                "ready_for_indexing": unembedded > 0,
            })))
        }
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            Ok(Json(json!({
                "status": "error",
                "error": e.to_string(),
            })))
        }
    }
}

/// GET /api/memory/stats/{user_id} — per-user stats from noo_conversations + noo_entries.
async fn memory_stats(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(user_id): Path<String>,
) -> AppResult {
    scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        Some(&user_id),
    )
    .map_err(AppError::Forbidden)?;
    // Conversation stats for this user
    let conv_row = sqlx::query_as::<_, (i64, Option<i64>, Option<i64>, Option<f64>, Option<i64>, Option<i64>, Option<f64>)>(
        "SELECT COUNT(*), \
                SUM(total_messages), \
                SUM(total_tool_calls), \
                AVG(total_messages)::float8, \
                SUM(total_tokens_in), \
                SUM(total_tokens_out), \
                AVG(total_latency_ms)::float8 \
         FROM noo_conversations \
         WHERE user_id = $1"
    )
    .bind(&user_id)
    .fetch_one(&state.db)
    .await?;

    // Entry stats for this user
    let entry_row = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*), COUNT(embedding) \
         FROM noo_entries e \
         JOIN noo_conversations c ON e.conversation_id = c.id \
         WHERE c.user_id = $1"
    )
    .bind(&user_id)
    .fetch_one(&state.db)
    .await?;

    // Recent conversation timestamps
    let recent = sqlx::query_as::<_, (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT MIN(started_at), MAX(started_at) \
         FROM noo_conversations WHERE user_id = $1"
    )
    .bind(&user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "user_id": user_id,
        "total_conversations": conv_row.0,
        "total_messages": conv_row.1.unwrap_or(0),
        "total_tool_calls": conv_row.2.unwrap_or(0),
        "avg_messages_per_conversation": conv_row.3.unwrap_or(0.0),
        "total_tokens_in": conv_row.4.unwrap_or(0),
        "total_tokens_out": conv_row.5.unwrap_or(0),
        "avg_latency_ms": conv_row.6.unwrap_or(0.0),
        "total_entries": entry_row.0,
        "embedded_entries": entry_row.1,
        "first_conversation": recent.0.map(|dt| dt.to_rfc3339()),
        "last_conversation": recent.1.map(|dt| dt.to_rfc3339()),
    })))
}

#[derive(Deserialize)]
pub(crate) struct CleanupBody {
    max_age_days: Option<i64>,
}

/// Delete old conversations.
pub(crate) async fn cleanup(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    Json(body): Json<CleanupBody>,
) -> AppResult {
    let max_age_days = body.max_age_days.unwrap_or(90);
    let interval = format!("{max_age_days} days");

    let rows = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "WITH old_convos AS ( \
            SELECT id FROM noo_conversations \
            WHERE started_at < NOW() - INTERVAL '{interval}' \
         ), \
         deleted_entries AS ( \
            DELETE FROM noo_entries \
            WHERE conversation_id IN (SELECT id FROM old_convos) \
         ) \
         DELETE FROM noo_conversations \
         WHERE id IN (SELECT id FROM old_convos) \
         RETURNING 1"
    )))
    .fetch_all(&state.db)
    .await?;

    // Audit the data deletion (H-L1): who deleted, how much, retention window.
    let who = actor
        .as_ref()
        .map(|a| a.0 .0.clone())
        .unwrap_or_else(|| "unknown".to_string());
    crate::routes::core::audit_event(
        &state.db,
        "data_delete",
        "warning",
        &who,
        "memory:conversations",
        "ok",
        json!({ "removed": rows.len(), "max_age_days": max_age_days }),
    )
    .await;

    Ok(Json(json!({"removed": rows.len(), "max_age_days": max_age_days})))
}

/// Whether `entry_id` is one `user_id` may read.
///
/// The predicate is `memory_search`'s, spelled once: an entry is visible if
/// its conversation belongs to the caller, or to nobody (`user_id IS NULL` —
/// heartbeat, autonomy and pre-attribution records, which that search also
/// admits). An id that does not resolve is not visible, so a caller cannot
/// use "does this 404" as an existence oracle for the corpus.
async fn entry_visible_to(
    state: &AppState,
    entry_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let visible: Option<bool> = sqlx::query_scalar(
        "SELECT (c.user_id = $2 OR c.user_id IS NULL) \
         FROM noo_entries e \
         JOIN noo_conversations c ON e.conversation_id = c.id \
         WHERE e.id = $1::uuid",
    )
    .bind(entry_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?
    .flatten();
    Ok(visible.unwrap_or(false))
}

#[derive(Deserialize)]
struct RelationshipParams {
    limit: Option<i64>,
}

/// Semantic relationships for a record.
///
/// `noo_semantic_relationships` is provider-DERIVED data — the one
/// augmentation-plane read in this otherwise transcript-plane file
/// so it goes through the memory-provider facade
/// while every other query here stays direct SQL on purpose.
async fn relationships(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(record_id): Path<String>,
    Query(params): Query<RelationshipParams>,
) -> AppResult {
    // A relationship edge is derived from two ENTRIES, and
    // an entry belongs to whoever owns its conversation — the same ownership
    // `memory_search` scopes by. Unscoped, this route was a way to walk out
    // of your own transcript and into somebody else's: hand it one id you
    // are allowed to see and it names the nearest neighbours in the whole
    // corpus, then each of those is a new source id.
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    let limit = params.limit.unwrap_or(10).min(100);

    // 404 rather than 403 on the SOURCE: the id is addressable, so a 403
    // would confirm that somebody else's record exists.
    if let Some(ref me) = scope {
        if !entry_visible_to(&state, &record_id, me).await? {
            return Err(AppError::NotFound("Record not found".into()));
        }
    }

    let rows = state.memory().semantic_relationships(&record_id, limit).await;

    match rows {
        Ok(records) => {
            let mut rels: Vec<Value> = Vec::with_capacity(records.len());
            for (target_id, sim) in records.iter() {
                // And the TARGETS: a neighbour list is a read of the rows it
                // names, so each one is filtered too. Dropped silently — the
                // caller asked "what is near this", and the honest answer is
                // "these, of the ones you can see".
                if let Some(ref me) = scope {
                    if !entry_visible_to(&state, target_id, me).await? {
                        continue;
                    }
                }
                rels.push(json!({"target_id": target_id, "similarity": sim, "score": sim}));
            }
            Ok(Json(json!({"source_id": record_id, "relationships": rels, "count": rels.len()})))
        }
        // Table might not exist yet — graceful degradation
        Err(e) if e.to_string().contains("does not exist") => {
            Ok(Json(json!({"source_id": record_id, "relationships": [], "count": 0})))
        }
        Err(e) => Err(AppError::Internal(format!("Database error: {e}"))),
    }
}

// ═══════════════════════════════════════════════════════════════
// Conversation routes — all native SQL via sqlx
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ConversationListParams {
    user_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// List conversations with preview of first message.
async fn conversations_with_preview(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<ConversationListParams>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        params.user_id.as_deref(),
    )
    .map_err(AppError::Forbidden)?;
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    // Use live counts from noo_entries instead of stale denormalized columns
    let convos = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, chrono::DateTime<chrono::Utc>, i64)>(
        "SELECT c.id::text, c.user_id, c.model, c.persona_id, c.started_at, \
                (SELECT count(*) FROM noo_entries e WHERE e.conversation_id = c.id) as msg_count \
         FROM noo_conversations c \
         WHERE ($1::text IS NULL OR c.user_id = $1) \
         ORDER BY c.started_at DESC \
         LIMIT $2 OFFSET $3"
    )
    .bind(&scope)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let mut results = Vec::new();
    for (id, user_id, model, persona_id, started_at, msg_count) in convos {
        // Skip empty ghost conversations (no actual entries)
        if msg_count == 0 { continue; }

        // Fetch first user message as preview
        let preview = sqlx::query_scalar::<_, String>(
            "SELECT content FROM noo_entries \
             WHERE conversation_id = $1::uuid AND type = 'user' \
             ORDER BY created_at ASC LIMIT 1"
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|c| if c.chars().count() > 200 { format!("{}...", c.chars().take(200).collect::<String>()) } else { c });

        results.push(json!({
            "id": id,
            "user_id": user_id,
            "model": model,
            "persona_id": persona_id,
            "started_at": started_at,
            "total_messages": msg_count,
            "preview": preview,
        }));
    }
    // Total count across all pages (not just this page).
    //
    // `scope`, NOT `params.user_id`. The list above filters by the ENFORCED
    // scope; this counted by the RAW request parameter, so a User-tier caller
    // who passed no `user_id` got their own conversations beside a total
    // counting everybody's. Not content, but a cross-tenant fact — and a
    // pagination control that disagreed with the page it described.
    let total: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM noo_conversations WHERE ($1::text IS NULL OR user_id = $1)"
    )
    .bind(&scope)
    .fetch_one(&state.db)
    .await
    .unwrap_or((results.len() as i64,));

    Ok(Json(json!({"conversations": results, "total": total.0})))
}

// ═══════════════════════════════════════════════════════════════
// Conversation stats/feedback/detail — native SQL via sqlx
// (ported from Python NATS delegation 2026-03-31)
// ═══════════════════════════════════════════════════════════════

/// Upper bound of the `hours` window: 30 days, the longest default any of the
/// stats routes has had. A wider look is `days`.
const STATS_MAX_HOURS: i32 = 720;

/// The look-back every stats route shares, in hours (`None` = all time).
///
/// `hours` (1..=720; anything else is a 400) wins over `days`; with neither,
/// `default_days` applies (30 for tools and overview, all-time for feedback).
/// Hours exist because evolve's composite score scores the last hour or few,
/// and a day is the smallest window `days` could say.
fn stats_window_hours(
    hours: Option<i32>,
    days: Option<i32>,
    default_days: Option<i32>,
) -> Result<Option<i64>, AppError> {
    if let Some(h) = hours {
        if !(1..=STATS_MAX_HOURS).contains(&h) {
            return Err(AppError::BadRequest(format!(
                "hours must be between 1 and {STATS_MAX_HOURS}, got {h}"
            )));
        }
        return Ok(Some(i64::from(h)));
    }
    Ok(days.or(default_days).map(|d| i64::from(d) * 24))
}

/// `period_days` as it has always been reported (whole days) unless the
/// caller asked in hours, when it is the same span as a fraction of a day.
fn period_days_json(hours: Option<i32>, days: Option<i32>, default_days: Option<i32>) -> Value {
    match (hours, days.or(default_days)) {
        (Some(h), _) => json!(f64::from(h) / 24.0),
        (None, Some(d)) => json!(d),
        (None, None) => Value::Null,
    }
}

#[derive(Deserialize)]
struct StatsOverviewParams {
    user_id: Option<String>,
    days: Option<i32>,
    hours: Option<i32>,
}

/// Whose conversations the overview counts. Everything `scoped_user` allows,
/// plus one thing: a requester holding `conversation_stats` (evolve's key)
/// that names no user gets the fleet-wide aggregate. Naming a user is not
/// widened: with only this scope it is refused exactly as before, and the
/// scope never opens a person's rows on any other route.
fn overview_scope(
    requester: Option<&RequesterCtx>,
    cluster: Option<&ClusterNode>,
    requested: Option<&str>,
) -> Result<Option<String>, String> {
    let names_a_user = requested.is_some_and(|u| !u.trim().is_empty());
    if !names_a_user && holds_control_scope(requester, CONVERSATION_STATS_SCOPE) {
        return Ok(None);
    }
    scoped_user(requester, cluster, requested)
}

/// GET /api/conversations/stats/overview
/// Aggregate conversation statistics (COUNT, SUM, AVG) over a window:
/// `hours` (1..=720) if given, else `days`, else 30 days.
async fn conv_stats_overview(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<StatsOverviewParams>,
) -> AppResult {
    let hours = stats_window_hours(params.hours, params.days, Some(30))?.unwrap_or(30 * 24);
    let window = hours.to_string();
    let scope = overview_scope(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        params.user_id.as_deref(),
    )
    .map_err(AppError::Forbidden)?;

    let row = if let Some(ref uid) = scope {
        sqlx::query_as::<_, (i64, Option<i64>, Option<i64>, Option<f64>, Option<i64>, Option<i64>, Option<f64>)>(
            "SELECT COUNT(*), \
                    SUM(total_messages), \
                    SUM(total_tool_calls), \
                    AVG(total_messages)::float8, \
                    SUM(total_tokens_in), \
                    SUM(total_tokens_out), \
                    AVG(total_latency_ms)::float8 \
             FROM noo_conversations \
             WHERE started_at > NOW() - ($1 || ' hours')::interval \
               AND user_id = $2"
        )
        .bind(&window)
        .bind(uid)
        .fetch_one(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (i64, Option<i64>, Option<i64>, Option<f64>, Option<i64>, Option<i64>, Option<f64>)>(
            "SELECT COUNT(*), \
                    SUM(total_messages), \
                    SUM(total_tool_calls), \
                    AVG(total_messages)::float8, \
                    SUM(total_tokens_in), \
                    SUM(total_tokens_out), \
                    AVG(total_latency_ms)::float8 \
             FROM noo_conversations \
             WHERE started_at > NOW() - ($1 || ' hours')::interval"
        )
        .bind(&window)
        .fetch_one(&state.db)
        .await?
    };

    Ok(Json(json!({
        "period_days": period_days_json(params.hours, params.days, Some(30)),
        "period_hours": hours,
        "user_id": scope,
        "total_conversations": row.0,
        "total_messages": row.1.unwrap_or(0),
        "total_tool_calls": row.2.unwrap_or(0),
        "avg_messages_per_conversation": row.3.unwrap_or(0.0),
        "total_tokens_in": row.4.unwrap_or(0),
        "total_tokens_out": row.5.unwrap_or(0),
        "avg_latency_ms": row.6.unwrap_or(0.0),
    })))
}

#[derive(Deserialize)]
struct ToolStatsParams {
    days: Option<i32>,
    hours: Option<i32>,
}

/// GET /api/conversations/stats/tools
/// Tool usage statistics grouped by tool_name over a window: `hours`
/// (1..=720) if given, else `days`, else 30 days. Fleet-wide aggregates.
async fn conv_stats_tools(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ToolStatsParams>,
) -> AppResult {
    let hours = stats_window_hours(params.hours, params.days, Some(30))?.unwrap_or(30 * 24);
    let window = hours.to_string();

    let rows = sqlx::query_as::<_, (String, i64, i64, Option<f64>)>(
        "SELECT tool_name, \
                COUNT(*)::bigint AS total_calls, \
                SUM(CASE WHEN success = true THEN 1 ELSE 0 END)::bigint AS successful, \
                AVG(execution_ms)::float8 AS avg_execution_ms \
         FROM noo_tool_executions \
         WHERE created_at > NOW() - ($1 || ' hours')::interval \
         GROUP BY tool_name \
         ORDER BY COUNT(*) DESC"
    )
    .bind(&window)
    .fetch_all(&state.db)
    .await?;

    let tools: Vec<Value> = rows.iter().map(|(name, total, successful, avg_ms)| {
        let success_rate = if *total > 0 { *successful as f64 / *total as f64 } else { 0.0 };
        json!({
            "name": name,
            "total_calls": total,
            "successful": successful,
            "success_rate": success_rate,
            "avg_execution_ms": avg_ms,
        })
    }).collect();

    Ok(Json(json!({
        "period_days": period_days_json(params.hours, params.days, Some(30)),
        "period_hours": hours,
        "tools": tools,
    })))
}

#[derive(Deserialize)]
struct FeedbackStatsParams {
    days: Option<i32>,
    hours: Option<i32>,
}

/// GET /api/conversations/feedback/stats
/// Aggregate feedback statistics (thumbs up/down counts, avg rating,
/// corrections). All-time unless `hours` (1..=720) or `days` narrows it;
/// `noo_feedback.created_at` is the clock.
async fn conv_feedback_stats(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FeedbackStatsParams>,
) -> AppResult {
    let hours = stats_window_hours(params.hours, params.days, None)?;
    let window = hours.map(|h| h.to_string());

    // All counts in a single query for efficiency
    let row = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT COUNT(*) AS total, \
                COALESCE(SUM(CASE WHEN feedback_type = 'thumbs_up' THEN 1 ELSE 0 END), 0)::bigint AS thumbs_up, \
                COALESCE(SUM(CASE WHEN feedback_type = 'thumbs_down' THEN 1 ELSE 0 END), 0)::bigint AS thumbs_down, \
                COALESCE(SUM(CASE WHEN feedback_type = 'correction' THEN 1 ELSE 0 END), 0)::bigint AS corrections \
         FROM noo_feedback \
         WHERE ($1::text IS NULL OR created_at > NOW() - ($1 || ' hours')::interval)"
    )
    .bind(&window)
    .fetch_one(&state.db)
    .await?;

    let total = row.0;
    let thumbs_up = row.1;
    let thumbs_down = row.2;
    let corrections = row.3;

    // Avg rating — value is JSONB, cast numeric values
    let avg_rating: Option<f64> = sqlx::query_scalar(
        "SELECT AVG((value::text)::float8) \
         FROM noo_feedback \
         WHERE feedback_type = 'rating' \
           AND jsonb_typeof(value) = 'number' \
           AND ($1::text IS NULL OR created_at > NOW() - ($1 || ' hours')::interval)"
    )
    .bind(&window)
    .fetch_one(&state.db)
    .await
    .ok()
    .flatten();

    let thumbs_total = thumbs_up + thumbs_down;
    let thumbs_up_ratio = if thumbs_total > 0 { thumbs_up as f64 / thumbs_total as f64 } else { 0.0 };

    Ok(Json(json!({
        "period_days": period_days_json(params.hours, params.days, None),
        "period_hours": hours,
        "total_feedback": total,
        "thumbs_up": thumbs_up,
        "thumbs_down": thumbs_down,
        "thumbs_up_ratio": thumbs_up_ratio,
        "avg_rating": avg_rating,
        "corrections_count": corrections,
    })))
}

#[derive(Deserialize)]
struct DpoExportParams {
    min_rating: Option<i32>,
    /// Operator+ may name a user (or omit for the whole install); a
    /// User-tier caller naming anyone but itself gets a 403 from
    /// `scoped_user`, never a silent narrowing.
    user_id: Option<String>,
}

/// GET /api/conversations/feedback/export/dpo
/// Export DPO training pairs: (prompt, chosen, rejected) from rated feedback.
///
/// Scoped. This returns RAW MESSAGE CONTENT
/// (`e.content`) for every rated turn, and `scope_allows` waves every GET
/// through regardless of tier — so unscoped it was a whole-install
/// conversation export readable by any User-tier token. `noo_feedback` has no
/// owner column of its own; ownership is reachable only through
/// `noo_feedback.conversation_id → noo_conversations.user_id`, so the join
/// below is the tenant boundary and must not be dropped.
async fn conv_feedback_export_dpo(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<DpoExportParams>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        params.user_id.as_deref(),
    )
    .map_err(AppError::Forbidden)?;
    let min_rating = params.min_rating.unwrap_or(3);

    // Fetch all rated feedback joined with entry content
    let rows = sqlx::query_as::<_, (String, String, serde_json::Value, String)>(
        "SELECT f.conversation_id::text, \
                f.entry_id::text, \
                f.value, \
                e.content \
         FROM noo_feedback f \
         JOIN noo_entries e ON f.entry_id = e.id \
         JOIN noo_conversations c ON f.conversation_id = c.id \
         WHERE f.feedback_type = 'rating' \
           AND jsonb_typeof(f.value) = 'number' \
           AND ($1::text IS NULL OR c.user_id = $1)"
    )
    .bind(&scope)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        let jsonl = String::new();
        return Ok(Json(json!({"format": "dpo", "count": 0, "data": jsonl})));
    }

    // Group by conversation_id
    let mut conv_feedback: std::collections::HashMap<String, Vec<(String, Option<f64>, String)>> =
        std::collections::HashMap::new();

    for (conv_id, entry_id, value, content) in &rows {
        let rating = value.as_f64();
        conv_feedback
            .entry(conv_id.clone())
            .or_default()
            .push((entry_id.clone(), rating, content.clone()));
    }

    let mut dpo_pairs: Vec<Value> = Vec::new();

    for (conv_id, items) in &conv_feedback {
        let rated: Vec<_> = items.iter().filter(|(_, r, _)| r.is_some()).collect();
        if rated.is_empty() {
            continue;
        }

        let good: Vec<_> = rated.iter().filter(|(_, r, _)| r.unwrap() >= min_rating as f64).collect();
        let bad: Vec<_> = rated.iter().filter(|(_, r, _)| r.unwrap() < min_rating as f64).collect();
        if good.is_empty() || bad.is_empty() {
            continue;
        }

        // Get first user message as prompt
        // Scoped as well: the conversation ids above are already narrowed,
        // but a second unscoped read is exactly how a boundary comes back.
        let prompt: Option<String> = sqlx::query_scalar(
            "SELECT e.content FROM noo_entries e \
             JOIN noo_conversations c ON e.conversation_id = c.id \
             WHERE e.conversation_id = $1::uuid AND e.type = 'user' \
               AND ($2::text IS NULL OR c.user_id = $2) \
             ORDER BY e.created_at ASC LIMIT 1"
        )
        .bind(conv_id)
        .bind(&scope)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let prompt = match prompt {
            Some(p) => p,
            None => continue,
        };

        for g in &good {
            for b in &bad {
                if g.0 != b.0 {
                    dpo_pairs.push(json!({
                        "prompt": prompt,
                        "chosen": g.2,
                        "rejected": b.2,
                    }));
                }
            }
        }
    }

    // Serialize as JSONL string (matching Python endpoint format)
    let jsonl: String = dpo_pairs
        .iter()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");

    Ok(Json(json!({
        "format": "dpo",
        "count": dpo_pairs.len(),
        "data": jsonl,
    })))
}

/// GET /api/conversations/{conversation_id}
/// Full conversation detail with all entries.
async fn conv_detail(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(conversation_id): Path<String>,
) -> AppResult {
    // Scope comes from the ROW here: the id says nothing about who owns it,
    // so fetch first and compare.
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    // Fetch conversation row
    let conv_row = sqlx::query_as::<_, (
        String, Option<String>, Option<String>, Option<String>, Option<String>,
        Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>,
        i32, i32, i32, i32, i32, Option<serde_json::Value>,
    )>(
        "SELECT id::text, user_id, session_id, backend, model, \
                started_at, ended_at, \
                total_messages, total_tool_calls, \
                total_tokens_in, total_tokens_out, total_latency_ms, \
                metadata \
         FROM noo_conversations \
         WHERE id = $1::uuid"
    )
    .bind(&conversation_id)
    .fetch_optional(&state.db)
    .await?;

    let conv = match conv_row {
        Some(r) => r,
        None => return Err(AppError::NotFound("Conversation not found".into())),
    };
    // A scoped caller sees only their own conversations. Same 404 as a
    // missing row, so ids cannot be enumerated by response code.
    if let Some(ref want) = scope {
        if conv.1.as_deref() != Some(want.as_str()) {
            return Err(AppError::NotFound("Conversation not found".into()));
        }
    }

    // Fetch entries
    let entries = sqlx::query_as::<_, (
        String, Option<String>, String, String, Option<serde_json::Value>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        "SELECT id::text, parent_id::text, type, content, metadata, created_at \
         FROM noo_entries \
         WHERE conversation_id = $1::uuid \
         ORDER BY created_at ASC"
    )
    .bind(&conversation_id)
    .fetch_all(&state.db)
    .await?;

    let entry_list: Vec<Value> = entries.iter().map(|(id, parent_id, typ, content, meta, created_at)| {
        json!({
            "id": id,
            "parent_id": parent_id,
            "type": typ,
            "content": content,
            "metadata": meta,
            "created_at": created_at.map(|dt| dt.to_rfc3339()),
        })
    }).collect();

    Ok(Json(json!({
        "id": conv.0,
        "user_id": conv.1,
        "session_id": conv.2,
        "backend": conv.3,
        "model": conv.4,
        "started_at": conv.5.map(|dt| dt.to_rfc3339()),
        "ended_at": conv.6.map(|dt| dt.to_rfc3339()),
        "total_messages": conv.7,
        "total_tool_calls": conv.8,
        "total_tokens_in": conv.9,
        "total_tokens_out": conv.10,
        "total_latency_ms": conv.11,
        "metadata": conv.12,
        "entries": entry_list,
    })))
}

#[derive(Deserialize)]
struct FeedbackBody {
    feedback_type: String,
    value: serde_json::Value,
    entry_id: Option<String>,
}

/// POST /api/conversations/{conversation_id}/feedback
/// Record user feedback (thumbs up/down, correction, rating, etc.).
async fn conv_feedback(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(conversation_id): Path<String>,
    Json(body): Json<FeedbackBody>,
) -> AppResult {
    // Owner check. `/api/conversations` is on
    // CHAT_QUERY_PREFIXES, so a User-tier token may POST here — and the id
    // came straight off the path, so any user could rate ANY conversation.
    // That is not only a cross-tenant write: rated turns are what
    // `conv_feedback_export_dpo` above turns into training pairs, so it was
    // a path to poisoning the preference data.
    //
    // Same row-fetch-then-compare shape as `conv_detail`, including the 404
    // (not 403) so conversation ids cannot be enumerated by status code.
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    let owner: Option<(Option<String>,)> =
        sqlx::query_as("SELECT user_id FROM noo_conversations WHERE id = $1::uuid")
            .bind(&conversation_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((owner,)) = owner else {
        // Also closes the dangling-feedback case: the row used to be
        // inserted against a conversation that need not exist.
        return Err(AppError::NotFound("Conversation not found".into()));
    };
    if let Some(ref want) = scope {
        if owner.as_deref() != Some(want.as_str()) {
            return Err(AppError::NotFound("Conversation not found".into()));
        }
    }
    let feedback_id = uuid::Uuid::new_v4().to_string();

    // Build the INSERT — entry_id is optional
    if let Some(ref eid) = body.entry_id {
        sqlx::query(
            "INSERT INTO noo_feedback (id, conversation_id, entry_id, feedback_type, value) \
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)"
        )
        .bind(&feedback_id)
        .bind(&conversation_id)
        .bind(eid)
        .bind(&body.feedback_type)
        .bind(&body.value)
        .execute(&state.db)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO noo_feedback (id, conversation_id, feedback_type, value) \
             VALUES ($1::uuid, $2::uuid, $3, $4)"
        )
        .bind(&feedback_id)
        .bind(&conversation_id)
        .bind(&body.feedback_type)
        .bind(&body.value)
        .execute(&state.db)
        .await?;
    }

    Ok(Json(json!({
        "feedback_id": feedback_id,
        "status": "recorded",
    })))
}

// ═══════════════════════════════════════════════════════════════
// Embed control — Redis flag + SQL counts (ported 2026-03-31)
// ═══════════════════════════════════════════════════════════════

const EMBED_STATE_KEY: &str = "noo:embed:state";

/// Where the last drain pass recorded what happened, so `embed/status` can
/// say "stopped: no progress — <error>" instead of a bare "stopped".
const EMBED_LAST_KEY: &str = "noo:embed:last";

/// One bounded pass of the conversation-memory embedder: a single batch over
/// `worker.memory.batch_index`, which trellion's EmbeddingWorker serves and
/// answers with `{status, embedded, failed, processed, remaining}`. Bounded
/// so the reply fits the NATS deadline (see workers/memory.py).
pub(crate) async fn embed_conversation_batch(state: &AppState) -> Result<Value, String> {
    let payload = json!({"params": {"max_batches": 1}});
    crate::bus_principal::with_internal(
        "memory-embed",
        &["read", "write"],
        crate::worker_client::request(&state.nats, "worker.memory.batch_index", &payload),
    )
    .await
    .map_err(|e| e.to_string())
}

/// What one pass's reply means for the drain loop. Pure so the decision is
/// tested without a bus.
#[derive(Debug, PartialEq)]
pub(crate) enum DrainStep {
    /// Work was done and more remains: call again.
    More,
    /// Nothing left to embed.
    Done,
    /// The pass reported an error, or embedded nothing while entries remain
    /// (a dimension mismatch or a dead embedder fails EVERY record). Calling
    /// again would spin; stop and say why.
    Stuck(String),
}

pub(crate) fn drain_step(reply: &Value) -> DrainStep {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return DrainStep::Stuck(e.to_string());
    }
    if reply.get("status").and_then(Value::as_str) == Some("error") {
        return DrainStep::Stuck(reply.get("error").and_then(Value::as_str).unwrap_or("worker reported an error").to_string());
    }
    if reply.get("status").and_then(Value::as_str) == Some("not_supported") {
        return DrainStep::Stuck("the worker has no batch_index (trellion too old)".into());
    }
    let remaining = reply.get("remaining").and_then(Value::as_i64).unwrap_or(0);
    let embedded = reply.get("embedded").and_then(Value::as_i64).unwrap_or(0);
    if remaining <= 0 {
        return DrainStep::Done;
    }
    if embedded <= 0 {
        let failed = reply.get("failed").and_then(Value::as_i64).unwrap_or(0);
        return DrainStep::Stuck(format!("no progress: 0 embedded, {failed} failed, {remaining} remaining — check `noo stack logs trellion` for the embedder error"));
    }
    DrainStep::More
}

/// POST /api/memory/embed/start
///
/// Drains the conversation-memory backlog in the background, one bounded
/// batch at a time, until nothing is left, a pass makes no progress, or
/// `embed/stop` clears the flag.
///
/// Until 2026-10-01 this only SET a Redis flag that nothing read (the Python
/// worker that once polled it went with the Rust port), so `noo memory
/// embed` reported "started" and embedded nothing — host8 sat at 0 of 1439
/// entries embedded for three weeks while search answered "no relevant
/// context". The working path, `worker.memory.batch_index`, had no caller.
async fn embed_start(State(state): State<Arc<AppState>>) -> AppResult {
    let Some(redis) = state.redis.as_ref() else {
        return Ok(Json(json!({"status": "error", "error": "Redis unavailable: the drain's start/stop flag has nowhere to live"})));
    };
    if redis.get_string(EMBED_STATE_KEY).await.as_deref() == Some("running") {
        return Ok(Json(json!({"status": "already_running"})));
    }
    redis.set_string(EMBED_STATE_KEY, "running").await;
    let st = state.clone();
    tokio::spawn(async move {
        // RedisCache is not Clone; the task borrows it through its own Arc.
        let Some(redis) = st.redis.as_ref() else { return };
        let mut total: i64 = 0;
        let outcome = loop {
            if redis.get_string(EMBED_STATE_KEY).await.as_deref() != Some("running") {
                break json!({"result": "stopped", "embedded": total});
            }
            match embed_conversation_batch(&st).await {
                Ok(reply) => {
                    total += reply.get("embedded").and_then(Value::as_i64).unwrap_or(0);
                    match drain_step(&reply) {
                        DrainStep::More => continue,
                        DrainStep::Done => break json!({"result": "complete", "embedded": total}),
                        DrainStep::Stuck(why) => break json!({"result": "stuck", "embedded": total, "error": why}),
                    }
                }
                Err(e) => break json!({"result": "stuck", "embedded": total, "error": e}),
            }
        };
        tracing::info!(outcome = %outcome, "memory.embed_drain.finished");
        redis.set_string(EMBED_LAST_KEY, &outcome.to_string()).await;
        redis.set_string(EMBED_STATE_KEY, "stopped").await;
    });
    Ok(Json(json!({"status": "started"})))
}

/// POST /api/memory/embed/stop
/// Set embedding worker state to "stopped" via Redis flag.
async fn embed_stop(State(state): State<Arc<AppState>>) -> AppResult {
    match state.redis.as_ref() {
        Some(redis) => {
            redis.set_string(EMBED_STATE_KEY, "stopped").await;
            Ok(Json(json!({"status": "stopped"})))
        }
        None => Ok(Json(json!({"status": "stopped", "warning": "Redis unavailable, flag not persisted"}))),
    }
}

/// GET /api/memory/embed/status
/// Read embed state from Redis + embedding counts from SQL.
async fn embed_status(State(state): State<Arc<AppState>>) -> AppResult {
    // Read state from Redis (default to "stopped" if unavailable)
    let embed_state = match state.redis.as_ref() {
        Some(redis) => redis.get_string(EMBED_STATE_KEY).await.unwrap_or_else(|| "stopped".into()),
        None => "unknown".into(),
    };

    // Get embedding counts from SQL
    let row = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*) AS total, \
                COUNT(embedding) AS embedded \
         FROM noo_entries"
    )
    .fetch_one(&state.db)
    .await?;

    let total = row.0;
    let embedded = row.1;
    let unembedded = total - embedded;
    let progress = if total > 0 { embedded as f64 / total as f64 } else { 0.0 };

    // Read config from YAML cache (matches Python EmbeddingConfig defaults).
    // The model goes through resolve_embedding_model so this endpoint and the
    // `embeddings_enabled` flags elsewhere cannot disagree.
    let emb_model = resolve_embedding_model(&state).await;
    let config_yaml = state.config_yaml.read().await;
    let batch_size = config_yaml.get("embedding").and_then(|e| e.get("batch_size")).and_then(|v| v.as_i64()).unwrap_or(100);
    let build_rels = config_yaml.get("embedding").and_then(|e| e.get("build_relationships")).and_then(|v| v.as_bool()).unwrap_or(false);

    // What the last drain pass ended with ("complete", "stopped", or "stuck"
    // with the reason), so a stopped state is never unexplained.
    let last: Option<Value> = match state.redis.as_ref() {
        Some(redis) => redis.get_string(EMBED_LAST_KEY).await.and_then(|s| serde_json::from_str(&s).ok()),
        None => None,
    };

    Ok(Json(json!({
        "state": embed_state,
        "last_run": last,
        "stats": {
            "total": total,
            "embedded": embedded,
            "unembedded": unembedded,
            "progress": progress,
        },
        "config": {
            "batch_size": batch_size,
            "build_relationships": build_rels,
            "embeddings_enabled": emb_model.is_some(),
            "embedding_model": emb_model,
        }
    })))
}


#[cfg(test)]
mod embed_drain_tests {
    use super::{drain_step, DrainStep};
    use serde_json::json;

    #[test]
    fn progress_with_work_left_calls_again() {
        assert_eq!(drain_step(&json!({"status":"partial","embedded":100,"failed":0,"remaining":1339})), DrainStep::More);
    }

    #[test]
    fn nothing_left_is_done() {
        assert_eq!(drain_step(&json!({"status":"complete","embedded":39,"remaining":0})), DrainStep::Done);
    }

    #[test]
    fn a_pass_that_embeds_nothing_stops_instead_of_spinning() {
        // A dimension mismatch fails every record: embedded 0, remaining
        // unchanged. Looping on that is a hot spin against the embedder.
        match drain_step(&json!({"status":"partial","embedded":0,"failed":100,"remaining":1439})) {
            DrainStep::Stuck(why) => assert!(why.contains("no progress") && why.contains("100 failed"), "{why}"),
            other => panic!("expected Stuck, got {other:?}"),
        }
    }

    #[test]
    fn worker_errors_stop_with_their_reason() {
        assert_eq!(drain_step(&json!({"error":"Embedding worker not initialized"})), DrainStep::Stuck("Embedding worker not initialized".into()));
        assert_eq!(drain_step(&json!({"status":"error","error":"no embedder available"})), DrainStep::Stuck("no embedder available".into()));
        assert!(matches!(drain_step(&json!({"status":"not_supported"})), DrainStep::Stuck(_)));
    }
}

#[cfg(test)]
mod stats_scope_tests {
    use super::{overview_scope, period_days_json, stats_window_hours};
    use crate::auth::{RequesterCtx, Role, CONVERSATION_STATS_SCOPE};
    use serde_json::json;

    fn who(sub: &str, role: Role, scopes: &[&str]) -> RequesterCtx {
        RequesterCtx {
            sub: sub.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }
    }

    // Each route's default, as its handler calls the resolver.
    const TOOLS_AND_OVERVIEW_DEFAULT_DAYS: Option<i32> = Some(30);
    const FEEDBACK_DEFAULT_DAYS: Option<i32> = None;

    #[test]
    fn tools_and_overview_default_to_thirty_days_and_hours_win_over_days() {
        let d = TOOLS_AND_OVERVIEW_DEFAULT_DAYS;
        assert_eq!(stats_window_hours(None, None, d).unwrap(), Some(720));
        assert_eq!(stats_window_hours(None, Some(7), d).unwrap(), Some(168));
        assert_eq!(stats_window_hours(Some(6), None, d).unwrap(), Some(6));
        assert_eq!(stats_window_hours(Some(6), Some(7), d).unwrap(), Some(6), "hours wins");
    }

    #[test]
    fn feedback_is_all_time_until_a_window_is_asked_for() {
        let d = FEEDBACK_DEFAULT_DAYS;
        assert_eq!(stats_window_hours(None, None, d).unwrap(), None, "unchanged: all-time");
        assert_eq!(stats_window_hours(None, Some(2), d).unwrap(), Some(48));
        assert_eq!(stats_window_hours(Some(1), Some(2), d).unwrap(), Some(1), "hours wins");
    }

    #[test]
    fn hours_outside_one_to_seven_twenty_is_a_400_on_every_route() {
        for d in [TOOLS_AND_OVERVIEW_DEFAULT_DAYS, FEEDBACK_DEFAULT_DAYS] {
            for bad in [0, -1, 721, i32::MAX] {
                let e = stats_window_hours(Some(bad), Some(3), d).expect_err("out of range");
                assert!(matches!(e, super::AppError::BadRequest(_)), "{bad}");
            }
            assert!(stats_window_hours(Some(1), None, d).is_ok());
            assert!(stats_window_hours(Some(720), None, d).is_ok());
        }
    }

    #[test]
    fn the_reported_period_follows_the_window_asked_for() {
        assert_eq!(period_days_json(None, None, Some(30)), json!(30));
        assert_eq!(period_days_json(None, Some(7), Some(30)), json!(7));
        assert_eq!(period_days_json(Some(12), Some(7), Some(30)), json!(0.5));
        assert_eq!(period_days_json(None, None, None), json!(null));
    }

    #[test]
    fn without_the_scope_the_overview_stays_self_scoped() {
        let u = who("svc:evolve", Role::User, &["metrics"]);
        assert_eq!(overview_scope(Some(&u), None, None), Ok(Some("svc:evolve".into())));
    }

    #[test]
    fn with_the_scope_and_no_user_the_overview_is_fleet_wide() {
        let u = who("svc:evolve", Role::User, &[CONVERSATION_STATS_SCOPE]);
        assert_eq!(overview_scope(Some(&u), None, None), Ok(None));
        assert_eq!(overview_scope(Some(&u), None, Some("  ")), Ok(None), "a blank user_id names nobody");
    }

    #[test]
    fn a_user_id_with_only_the_scope_is_refused_as_before() {
        let u = who("svc:evolve", Role::User, &[CONVERSATION_STATS_SCOPE]);
        assert!(overview_scope(Some(&u), None, Some("alice")).is_err());
        // Naming oneself is what it always was.
        assert_eq!(overview_scope(Some(&u), None, Some("svc:evolve")), Ok(Some("svc:evolve".into())));
    }

    #[test]
    fn operators_are_unchanged() {
        let op = who("alice", Role::Operator, &["write"]);
        assert_eq!(overview_scope(Some(&op), None, None), Ok(None));
        assert_eq!(overview_scope(Some(&op), None, Some("alice")), Ok(Some("alice".into())));
    }
}
