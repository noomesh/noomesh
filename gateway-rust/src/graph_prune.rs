// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! graph_prune — staged knowledge-graph hygiene, native (the LAST Tier C
//! port, 2026-08-12). The Python handler was ~95% SQL around one string
//! metric; the "ML" never existed. Every semantic is preserved:
//!
//! - **Advisory lock** serializes prune runs (same key, same skip-not-race
//!   behavior). Taken and released on ONE pooled connection.
//! - **Staged deletes**: every removed entity/edge is snapshotted into
//!   `graph_prune_staging` / `graph_edge_prune_staging` first, with the
//!   SAME payload JSON shapes — restore tooling keeps working.
//! - **Budget** (`max_delete`) counts across all sections, in order.
//! - **Dry-run defaults ON** are the caller's job (config), as before.
//! - Near-duplicate similarity uses Ratcliff–Obershelp, the algorithm
//!   behind Python's `difflib.SequenceMatcher.ratio()`, so the tuned
//!   0.85 threshold keeps meaning the same thing.

use serde_json::{json, Value};
use sqlx::{Acquire, Row};

/// Ratcliff–Obershelp similarity (difflib.SequenceMatcher.ratio without
/// the junk heuristic): 2*M/T, M = sum of recursively-matched block
/// lengths, T = total length. Operates on chars.
pub fn sequence_ratio(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    let matches = matched(&a, &b);
    2.0 * matches as f64 / total as f64
}

fn matched(a: &[char], b: &[char]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    // Longest matching block (first-lowest on ties, like difflib).
    let (mut bi, mut bj, mut bsize) = (0usize, 0usize, 0usize);
    // DP row: j2len[j] = length of match ending at a[i], b[j].
    let mut j2len = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        let mut new = vec![0usize; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            if ca == cb {
                let k = j2len[j] + 1;
                new[j + 1] = k;
                if k > bsize {
                    bi = i + 1 - k;
                    bj = j + 1 - k;
                    bsize = k;
                }
            }
        }
        j2len = new;
    }
    if bsize == 0 {
        return 0;
    }
    bsize + matched(&a[..bi], &b[..bj]) + matched(&a[bi + bsize..], &b[bj + bsize..])
}

/// The junk-name step is OFF unless a task asks: junk names belong to
/// trellion's entity-quality gate (`noo graph entity-cleanup`, the
/// `entity_cleanup` task), the one place that knows "li" (person) and "3090"
/// (component) are real. This step's rule (too short / no letters) knows no
/// types and would delete them. The task schema shows this same constant.
pub(crate) const REMOVE_JUNK_DEFAULT: bool = false;

fn cfg_bool(config: &Value, key: &str, default: bool) -> bool {
    config.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}
fn cfg_f64(config: &Value, key: &str, default: f64) -> f64 {
    config.get(key).and_then(|v| v.as_f64()).unwrap_or(default)
}
fn cfg_i64(config: &Value, key: &str, default: i64) -> i64 {
    config.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

#[derive(sqlx::FromRow)]
struct EntityRow {
    entity_id: String,
    canonical_name: Option<String>,
    #[sqlx(rename = "type")]
    etype: Option<String>,
    aliases_json: Option<Value>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The owning account of a conversation-derived entity (NULL for a
    /// knowledge-base one). Carried into the staging payload so an erase of
    /// that account can find, and purge, what the prune set aside.
    user_id: Option<String>,
}

impl EntityRow {
    fn as_json(&self) -> Value {
        json!({
            "entity_id": self.entity_id,
            "canonical_name": self.canonical_name,
            "type": self.etype,
            "aliases_json": self.aliases_json,
            "created_at": self.created_at.map(|t| t.to_rfc3339()),
        })
    }
}

const ENTITY_COLS: &str =
    "entity_id::text AS entity_id, canonical_name, type, aliases_json, created_at, user_id";

async fn stage_entity(
    conn: &mut sqlx::PgConnection,
    ent: &EntityRow,
    reason: &str,
    payload: &Value,
    run_id: &str,
) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO graph_prune_staging \
             (entity_id, canonical_name, entity_type, reason, payload, run_id) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(&ent.entity_id)
    .bind(&ent.canonical_name)
    .bind(&ent.etype)
    .bind(reason)
    .bind(payload)
    .bind(run_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("stage entity: {e}"))?;
    Ok(())
}

async fn stage_edge(
    conn: &mut sqlx::PgConnection,
    edge_id: &str,
    reason: &str,
    run_id: &str,
) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO graph_edge_prune_staging \
             (edge_id, src_entity_id, rel_type, dst_entity_id, \
              confidence, evidence_json, reason, run_id, user_id) \
         SELECT edge_id, src_entity_id, rel_type, dst_entity_id, \
                confidence, evidence_json, $2, $3, user_id \
         FROM edges WHERE edge_id = $1::uuid",
    )
    .bind(edge_id)
    .bind(reason)
    .bind(run_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("stage edge: {e}"))?;
    Ok(())
}

/// Restore payload: the entity row + its edges + mentions. Embeddings and
/// signals are intentionally excluded — they regenerate via rag_reindex /
/// graph_signals after a restore. SAME field names as the Python payloads.
async fn snapshot_entity(
    conn: &mut sqlx::PgConnection,
    ent: &EntityRow,
) -> Result<Value, String> {
    let edges = sqlx::query(
        "SELECT edge_id::text, src_entity_id::text, rel_type, \
                dst_entity_id::text, evidence_json, created_at, \
                confidence, classified_at, classifier_model \
         FROM edges WHERE src_entity_id = $1::uuid OR dst_entity_id = $1::uuid",
    )
    .bind(&ent.entity_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("snapshot edges: {e}"))?
    .into_iter()
    .map(|r| {
        json!({
            "edge_id": r.get::<String, _>(0),
            "src_entity_id": r.get::<String, _>(1),
            "rel_type": r.get::<Option<String>, _>(2),
            "dst_entity_id": r.get::<String, _>(3),
            "evidence_json": r.get::<Option<Value>, _>(4),
            "created_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>(5).map(|t| t.to_rfc3339()),
            "confidence": r.get::<Option<f64>, _>(6),
            "classified_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>(7).map(|t| t.to_rfc3339()),
            "classifier_model": r.get::<Option<String>, _>(8),
        })
    })
    .collect::<Vec<_>>();

    let mentions = sqlx::query(
        "SELECT mention_id::text, entity_id::text, page_id::text, span_json, quote \
         FROM mentions WHERE entity_id = $1::uuid",
    )
    .bind(&ent.entity_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("snapshot mentions: {e}"))?
    .into_iter()
    .map(|r| {
        json!({
            "mention_id": r.get::<String, _>(0),
            "entity_id": r.get::<String, _>(1),
            "page_id": r.get::<Option<String>, _>(2),
            "span_json": r.get::<Option<Value>, _>(3),
            "quote": r.get::<Option<String>, _>(4),
        })
    })
    .collect::<Vec<_>>();

    // `user_id` at the top level: `payload->>'user_id'` is how the right-to-be-
    // forgotten erase finds a staged entity (`routes/users.rs`, `erase_targets`).
    Ok(json!({"entity": ent.as_json(), "edges": edges, "mentions": mentions, "user_id": ent.user_id}))
}

/// Merge `merge_id` into `keep_id`: reassign mentions + both edge
/// endpoints, delete the merged entity — the four statements trellion's
/// `merge_entities` ran.
async fn merge_entities(
    conn: &mut sqlx::PgConnection,
    keep_id: &str,
    merge_id: &str,
) -> Result<(), String> {
    for sql in [
        "UPDATE mentions SET entity_id = $1::uuid WHERE entity_id = $2::uuid",
        "UPDATE edges SET src_entity_id = $1::uuid WHERE src_entity_id = $2::uuid",
        "UPDATE edges SET dst_entity_id = $1::uuid WHERE dst_entity_id = $2::uuid",
        "DELETE FROM entities WHERE entity_id = $2::uuid",
    ] {
        sqlx::query(sql)
            .bind(keep_id)
            .bind(merge_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("merge_entities: {e}"))?;
    }
    Ok(())
}

pub async fn run(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<String, String> {
    let dry_run = cfg_bool(config, "dry_run", true);
    let remove_orphans = cfg_bool(config, "remove_orphans", true);
    let remove_junk = cfg_bool(config, "remove_junk", REMOVE_JUNK_DEFAULT);
    let merge_duplicates = cfg_bool(config, "merge_duplicates", true);
    let orphan_min_age_days = cfg_f64(config, "orphan_min_age_days", 7.0);
    let min_name_length = cfg_i64(config, "min_name_length", 2);
    let similarity_threshold = cfg_f64(config, "similarity_threshold", 0.85);
    let max_entities = cfg_i64(config, "max_entities", 200);
    let max_delete = cfg_i64(config, "max_delete", 500);
    let retention_days = cfg_f64(config, "staging_retention_days", 30.0);
    let prune_edges = cfg_bool(config, "prune_edges", true);
    let edge_conf_floor = cfg_f64(config, "edge_confidence_floor", 0.15);
    let edge_min_age_days = cfg_f64(config, "edge_min_age_days", 14.0);
    let dedup_edges = cfg_bool(config, "dedup_edges", true);

    let run_id: String = uuid::Uuid::new_v4().to_string()[..12].to_string();
    let prefix = if dry_run { "(dry-run) " } else { "" };
    let mut lines: Vec<String> = Vec::new();
    let mut budget = max_delete;

    // ONE connection for the whole run: the advisory lock is session-scoped.
    let mut pooled = state
        .db
        .acquire()
        .await
        .map_err(|e| format!("graph_prune: acquire connection: {e}"))?;
    let conn = pooled
        .acquire()
        .await
        .map_err(|e| format!("graph_prune: acquire: {e}"))?;

    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext('noo:graph_prune')::bigint)")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| format!("graph_prune: lock: {e}"))?;
    if !got_lock {
        return Ok("Graph prune: another prune run is in progress — skipped.".to_string());
    }

    // From here on, release the lock on EVERY exit path.
    let result = run_locked(
        conn,
        RunParams {
            dry_run,
            remove_orphans,
            remove_junk,
            merge_duplicates,
            orphan_min_age_days,
            min_name_length,
            similarity_threshold,
            max_entities,
            retention_days,
            prune_edges,
            edge_conf_floor,
            edge_min_age_days,
            dedup_edges,
            run_id: run_id.clone(),
        },
        &mut budget,
        &mut lines,
    )
    .await;

    // Best-effort unlock — the Python version leaked the lock on error and
    // relied on pool recycling; releasing here is strictly better.
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext('noo:graph_prune')::bigint)")
        .execute(&mut *conn)
        .await;

    result?;

    if lines.is_empty() {
        return Ok(format!("Graph prune: {prefix}nothing to do (run {run_id})."));
    }
    Ok(format!(
        "Graph prune: {prefix}{}. Run {run_id}; staged rows restorable for {retention_days:.0}d.",
        lines.join("; ")
    ))
}

struct RunParams {
    dry_run: bool,
    remove_orphans: bool,
    remove_junk: bool,
    merge_duplicates: bool,
    orphan_min_age_days: f64,
    min_name_length: i64,
    similarity_threshold: f64,
    max_entities: i64,
    retention_days: f64,
    prune_edges: bool,
    edge_conf_floor: f64,
    edge_min_age_days: f64,
    dedup_edges: bool,
    run_id: String,
}

async fn run_locked(
    conn: &mut sqlx::PgConnection,
    p: RunParams,
    budget: &mut i64,
    lines: &mut Vec<String>,
) -> Result<(), String> {
    // ── 0. Purge staged rows past the retention window ──────────────
    if p.dry_run {
        let expired: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM graph_prune_staging \
             WHERE staged_at < now() - ($1 * interval '1 day')",
        )
        .bind(p.retention_days)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("staging count: {e}"))?;
        if expired > 0 {
            lines.push(format!(
                "would purge {expired} staged rows past {:.0}d retention",
                p.retention_days
            ));
        }
    } else {
        let r = sqlx::query(
            "DELETE FROM graph_prune_staging \
             WHERE staged_at < now() - ($1 * interval '1 day')",
        )
        .bind(p.retention_days)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("staging purge: {e}"))?;
        if r.rows_affected() > 0 {
            lines.push(format!(
                "purged {} staged rows past {:.0}d retention",
                r.rows_affected(),
                p.retention_days
            ));
        }
        // Edge staging table may not exist on first run — ignore, as before.
        if let Ok(re) = sqlx::query(
            "DELETE FROM graph_edge_prune_staging \
             WHERE staged_at < now() - ($1 * interval '1 day')",
        )
        .bind(p.retention_days)
        .execute(&mut *conn)
        .await
        {
            if re.rows_affected() > 0 {
                lines.push(format!(
                    "purged {} staged edges past {:.0}d retention",
                    re.rows_affected(),
                    p.retention_days
                ));
            }
        }
    }

    // ── 1. Orphans: no edges, no mentions, older than min age ───────
    if p.remove_orphans && *budget > 0 {
        let rows: Vec<EntityRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {ENTITY_COLS} FROM entities e \
             WHERE NOT EXISTS (SELECT 1 FROM edges ed \
                               WHERE ed.src_entity_id = e.entity_id \
                                  OR ed.dst_entity_id = e.entity_id) \
               AND NOT EXISTS (SELECT 1 FROM mentions m \
                               WHERE m.entity_id = e.entity_id) \
               AND e.created_at < now() - ($1 * interval '1 day') \
             LIMIT $2"
        )))
        .bind(p.orphan_min_age_days)
        .bind(*budget)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("orphan select: {e}"))?;
        let mut done = 0i64;
        if p.dry_run {
            done = rows.len() as i64;
        } else {
            for ent in &rows {
                // Orphan by definition — empty edges/mentions snapshot.
                let payload = json!({"entity": ent.as_json(), "edges": [], "mentions": []});
                stage_entity(conn, ent, "orphan", &payload, &p.run_id).await?;
                sqlx::query("DELETE FROM entities WHERE entity_id = $1::uuid")
                    .bind(&ent.entity_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| format!("orphan delete: {e}"))?;
                done += 1;
            }
        }
        *budget -= done;
        if done > 0 {
            lines.push(format!(
                "{} {done} orphans (no edges/mentions, >{:.0}d old)",
                if p.dry_run { "would remove" } else { "staged+removed" },
                p.orphan_min_age_days
            ));
        }
    }

    // ── 2. Junk names: too short or containing no letters ───────────
    if p.remove_junk && *budget > 0 {
        let rows: Vec<EntityRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {ENTITY_COLS} FROM entities \
             WHERE length(canonical_name) < $1 \
                OR canonical_name !~ '[a-zA-Z]' \
             LIMIT $2"
        )))
        .bind(p.min_name_length as i32)
        .bind(*budget)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("junk select: {e}"))?;
        let examples: Vec<String> = rows
            .iter()
            .take(5)
            .map(|r| format!("{:?}", r.canonical_name.as_deref().unwrap_or("")))
            .collect();
        let mut done = 0i64;
        if p.dry_run {
            done = rows.len() as i64;
        } else {
            for ent in &rows {
                let payload = snapshot_entity(conn, ent).await?;
                stage_entity(conn, ent, "junk_name", &payload, &p.run_id).await?;
                sqlx::query("DELETE FROM entities WHERE entity_id = $1::uuid")
                    .bind(&ent.entity_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| format!("junk delete: {e}"))?;
                done += 1;
            }
        }
        *budget -= done;
        if done > 0 {
            lines.push(format!(
                "{} {done} junk names (e.g. {})",
                if p.dry_run { "would remove" } else { "staged+removed" },
                examples.join(", ")
            ));
        }
    }

    // ── 3. Near-duplicate names: merge, staging the loser ───────────
    if p.merge_duplicates && *budget > 0 {
        let sample: Vec<EntityRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {ENTITY_COLS} FROM entities ORDER BY RANDOM() LIMIT $1"
        )))
        .bind(p.max_entities)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("dup sample: {e}"))?;

        let mut by_type: std::collections::HashMap<String, Vec<&EntityRow>> =
            std::collections::HashMap::new();
        for e in &sample {
            by_type
                .entry(e.etype.clone().unwrap_or_default())
                .or_default()
                .push(e);
        }
        let mut duplicates: Vec<(&EntityRow, &EntityRow, f64)> = Vec::new();
        for ents in by_type.values() {
            for i in 0..ents.len() {
                for j in i + 1..ents.len() {
                    let a = ents[i].canonical_name.as_deref().unwrap_or("").to_lowercase();
                    let b = ents[j].canonical_name.as_deref().unwrap_or("").to_lowercase();
                    let ratio = sequence_ratio(&a, &b);
                    if ratio >= p.similarity_threshold {
                        duplicates.push((ents[i], ents[j], ratio));
                    }
                }
            }
        }
        let dup_pairs = duplicates.len();
        let mut merged = 0i64;
        if !p.dry_run {
            let mut merged_ids: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for (keep, merge, _ratio) in duplicates.iter().take(*budget as usize) {
                if merged_ids.contains(keep.entity_id.as_str())
                    || merged_ids.contains(merge.entity_id.as_str())
                {
                    continue;
                }
                let mut payload = snapshot_entity(conn, merge).await?;
                payload["merged_into"] = json!(keep.entity_id);
                stage_entity(conn, merge, "duplicate_merge", &payload, &p.run_id).await?;
                merge_entities(conn, &keep.entity_id, &merge.entity_id).await?;
                merged_ids.insert(merge.entity_id.as_str());
                merged += 1;
            }
            *budget -= merged;
        }
        if dup_pairs > 0 {
            let ex = duplicates
                .iter()
                .take(3)
                .map(|(k, m, r)| {
                    format!(
                        "'{}' -> '{}' ({:.0}%)",
                        m.canonical_name.as_deref().unwrap_or(""),
                        k.canonical_name.as_deref().unwrap_or(""),
                        r * 100.0
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "{} {dup_pairs} duplicate pairs in a {}-entity sample (e.g. {ex})",
                if p.dry_run {
                    "would merge".to_string()
                } else {
                    format!("merged {merged} of")
                },
                sample.len()
            ));
        }
    }

    // ── 4. EDGE TIER: dedup + age-gated low-confidence prune ────────
    // (edge metabolism — See the security documentation)
    let mut affected: std::collections::HashSet<String> = std::collections::HashSet::new();
    if (p.prune_edges || p.dedup_edges) && *budget > 0 {
        // 4a. Exact-duplicate edges.
        if p.dedup_edges && *budget > 0 {
            let dupes = sqlx::query(
                "SELECT edge_id::text, src_entity_id::text, dst_entity_id::text \
                 FROM ( \
                     SELECT edge_id, src_entity_id, dst_entity_id, \
                            row_number() OVER ( \
                              PARTITION BY src_entity_id, rel_type, dst_entity_id \
                              ORDER BY confidence DESC NULLS LAST, created_at DESC \
                            ) AS rn \
                     FROM edges \
                 ) ranked WHERE rn > 1 LIMIT $1",
            )
            .bind(*budget)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| format!("edge dedup select: {e}"))?;
            let n = dupes.len() as i64;
            if n > 0 && !p.dry_run {
                let ids: Vec<String> = dupes.iter().map(|r| r.get::<String, _>(0)).collect();
                for r in &dupes {
                    stage_edge(conn, &r.get::<String, _>(0), "duplicate", &p.run_id).await?;
                    affected.insert(r.get::<String, _>(1));
                    affected.insert(r.get::<String, _>(2));
                }
                sqlx::query("DELETE FROM edges WHERE edge_id = ANY($1::uuid[])")
                    .bind(&ids)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| format!("edge dedup delete: {e}"))?;
            }
            *budget -= n;
            if n > 0 {
                lines.push(format!(
                    "{} {n} duplicate edges",
                    if p.dry_run { "would collapse" } else { "collapsed" }
                ));
            }
        }

        // 4b. Age-gated low-confidence prune (classified edges only).
        if p.prune_edges && *budget > 0 {
            let weak = sqlx::query(
                "SELECT edge_id::text, src_entity_id::text, dst_entity_id::text, \
                        rel_type, confidence \
                 FROM edges \
                 WHERE classified_at IS NOT NULL \
                   AND confidence < $1 \
                   AND created_at < now() - ($2 * interval '1 day') \
                 ORDER BY confidence ASC LIMIT $3",
            )
            .bind(p.edge_conf_floor)
            .bind(p.edge_min_age_days)
            .bind(*budget)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| format!("weak edge select: {e}"))?;
            let n = weak.len() as i64;
            if n > 0 && !p.dry_run {
                let ids: Vec<String> = weak.iter().map(|r| r.get::<String, _>(0)).collect();
                for r in &weak {
                    stage_edge(conn, &r.get::<String, _>(0), "low_confidence", &p.run_id).await?;
                    affected.insert(r.get::<String, _>(1));
                    affected.insert(r.get::<String, _>(2));
                }
                sqlx::query("DELETE FROM edges WHERE edge_id = ANY($1::uuid[])")
                    .bind(&ids)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| format!("weak edge delete: {e}"))?;
            }
            *budget -= n;
            if n > 0 {
                let ex = weak
                    .iter()
                    .take(3)
                    .map(|r| {
                        format!(
                            "{}({:.2})",
                            r.get::<Option<String>, _>(3).unwrap_or_default(),
                            r.get::<Option<f64>, _>(4).unwrap_or(0.0)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!(
                    "{} {n} weak edges (<{}, >{:.0}d; e.g. {ex})",
                    if p.dry_run { "would snip" } else { "snipped" },
                    p.edge_conf_floor,
                    p.edge_min_age_days
                ));
            }
        }

        // 4c. Restructure trigger: stale the endpoints' embeddings.
        if !affected.is_empty() && !p.dry_run {
            let ids: Vec<String> = affected.iter().cloned().collect();
            sqlx::query("DELETE FROM entity_embeddings WHERE entity_id = ANY($1::uuid[])")
                .bind(&ids)
                .execute(&mut *conn)
                .await
                .map_err(|e| format!("embedding stale: {e}"))?;
            lines.push(format!(
                "marked {} entities for re-embedding (neighbourhood changed)",
                affected.len()
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sequence_ratio;

    // Values pinned against CPython difflib.SequenceMatcher(None, a, b).ratio().
    #[test]
    fn ratio_matches_difflib() {
        assert_eq!(sequence_ratio("", ""), 1.0);
        assert_eq!(sequence_ratio("abc", "abc"), 1.0);
        assert_eq!(sequence_ratio("abc", "xyz"), 0.0);
        let close = sequence_ratio("openai gpt-4", "openai gpt4");
        assert!((close - 0.9565217391304348).abs() < 1e-9, "got {close}");
        let apple = sequence_ratio("apple inc", "apple inc.");
        assert!((apple - 0.9473684210526315).abs() < 1e-9, "got {apple}");
        let far = sequence_ratio("kubernetes", "postgresql");
        assert!(far < 0.5, "got {far}");
    }

    #[test]
    fn threshold_meaning_preserved() {
        // The tuned production threshold is 0.85: near-identical names
        // cross it, genuinely different ones don't.
        assert!(sequence_ratio("tailscale", "tailscale inc") < 0.85);
        assert!(sequence_ratio("google chat", "google  chat") >= 0.85);
    }
}
