// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Temporal knowledge graph queries (Phase 1, OSS-safe).
//!
//! Read-side helpers for the bi-temporal graph stored in
//! ``noo_entities_typed`` + ``noo_temporal_edges``. Write-side
//! happens in Python (the conversation extractor and pro writers).
//!
//! See the knowledge add-on for the design.

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;

/// A currently-valid edge from the temporal graph (lightweight view).
#[derive(Debug, Clone)]
pub struct CurrentFact {
    pub subject_type: String,
    pub subject_name: String,
    pub predicate: String,
    pub object_value: Option<String>,
    pub object_entity_name: Option<String>,
    pub confidence: f64,
    pub valid_from: chrono::DateTime<chrono::Utc>,
}

/// Look up an entity_id by (type, canonical_name). Returns None if missing.
pub async fn find_entity_id(
    db: &PgPool,
    entity_type: &str,
    canonical_name: &str,
) -> Option<String> {
    let normalized = canonical_name.trim().to_lowercase();
    let row: Result<Option<(String,)>, _> = sqlx::query_as(
        "SELECT id::text FROM noo_entities_typed \
         WHERE type = $1 AND canonical_name = $2"
    )
    .bind(entity_type)
    .bind(&normalized)
    .fetch_optional(db)
    .await;

    row.ok().flatten().map(|(s,)| s)
}

/// Upsert an entity by (type, canonical_name), returning its id as text.
/// Names are normalized (trim + lowercase) to match `find_entity_id`.
/// `(type, canonical_name)` of one entity, or `None` if it is gone.
///
/// The scope check on `/api/temporal/facts` and `/api/temporal/evolution`
/// needs this: those routes address a subject by OPAQUE id as well as by
/// (type, name), and an id says nothing about whose data it is until the row
/// is read. See `routes::temporal::scope_entity`.
pub async fn entity_identity(
    db: &sqlx::PgPool,
    entity_id: &str,
) -> Option<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT type, canonical_name FROM noo_entities_typed WHERE id = $1::uuid",
    )
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

pub async fn upsert_entity(
    db: &PgPool,
    entity_type: &str,
    canonical_name: &str,
) -> Result<String> {
    let normalized = canonical_name.trim().to_lowercase();
    // DO UPDATE (no-op) rather than DO NOTHING so RETURNING yields the row
    // on conflict too.
    let row: (String,) = sqlx::query_as(
        "INSERT INTO noo_entities_typed (id, type, canonical_name) \
         VALUES (gen_random_uuid(), $1, $2) \
         ON CONFLICT (type, canonical_name) DO UPDATE SET type = EXCLUDED.type \
         RETURNING id::text",
    )
    .bind(entity_type)
    .bind(&normalized)
    .fetch_one(db)
    .await?;
    Ok(row.0)
}

/// Write a batch of agent_self self-adaptation edges into the temporal graph.
///
/// One `agent_self`--<predicate>--><value> edge per adaptation. The predicate is
/// the last dotted segment of the adaptation `path` (e.g. `self_identity.tone`
/// → `tone`). Any prior current edge for the same (subject, predicate) is
/// superseded (closed with `valid_to = now()`) so the graph reflects current
/// truth while preserving history. Returns the number of edges inserted.
///
/// Mirrors the former in-process Python graph writer; the gateway
/// is now the single writer to the graph (noo-evolve posts here over HTTP).
pub async fn write_adaptations(
    db: &PgPool,
    cycle_id: &str,
    adaptations: &[Value],
    composite_score: Option<f64>,
    score_delta: Option<f64>,
    reflection_summary: Option<&str>,
) -> Result<usize> {
    if adaptations.is_empty() {
        return Ok(0);
    }

    let agent_id = upsert_entity(db, "agent_self", "mesh").await?;
    let cycle_uuid = uuid::Uuid::parse_str(cycle_id).ok();

    let cap = |s: &str, n: usize| -> String { s.chars().take(n).collect() };

    let mut inserted = 0usize;
    for ad in adaptations {
        let path = ad
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| ad.get("field").and_then(Value::as_str))
            .unwrap_or("");
        let value = ad.get("value");
        if path.is_empty() || matches!(value, None | Some(Value::Null)) {
            continue;
        }
        let predicate = path.rsplit('.').next().unwrap_or(path).to_lowercase();
        let obj_value = match value.expect("checked above") {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let obj_value = cap(&obj_value, 1000);

        let mut meta = serde_json::Map::new();
        meta.insert("cycle_id".into(), json!(cycle_id));
        meta.insert("path".into(), json!(path));
        if let Some(pv) = ad.get("previous_value") {
            let s = pv.as_str().map(str::to_string).unwrap_or_else(|| pv.to_string());
            meta.insert("previous_value".into(), json!(cap(&s, 500)));
        }
        if let Some(j) = ad.get("justification").and_then(Value::as_str) {
            meta.insert("justification".into(), json!(cap(j, 500)));
        }
        if let Some(cs) = composite_score {
            meta.insert("composite_score".into(), json!(cs));
        }
        if let Some(sd) = score_delta {
            meta.insert("score_delta".into(), json!(sd));
        }
        if let Some(rs) = reflection_summary {
            meta.insert("reflection_summary".into(), json!(cap(rs, 300)));
        }
        let metadata = Value::Object(meta);

        // Supersede any prior current edge for this (subject, predicate).
        sqlx::query(
            "UPDATE noo_temporal_edges SET valid_to = now() \
             WHERE subject_id = $1::uuid AND predicate = $2 AND valid_to IS NULL",
        )
        .bind(&agent_id)
        .bind(&predicate)
        .execute(db)
        .await?;

        // Insert the new current edge.
        sqlx::query(
            "INSERT INTO noo_temporal_edges \
               (id, subject_id, predicate, object_value, confidence, source_cycle_id, metadata) \
             VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, $5, $6)",
        )
        .bind(&agent_id)
        .bind(&predicate)
        .bind(&obj_value)
        .bind(0.9_f64)
        .bind(cycle_uuid)
        .bind(&metadata)
        .execute(db)
        .await?;

        inserted += 1;
    }

    Ok(inserted)
}

/// Get currently-valid facts for a subject entity.
/// Joins to resolve the object entity's canonical_name when applicable.
pub async fn get_current_facts(
    db: &PgPool,
    subject_id: &str,
) -> Result<Vec<CurrentFact>> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, f64, chrono::DateTime<chrono::Utc>)>(
        "SELECT s.type, s.canonical_name, e.predicate, e.object_value, \
                o.canonical_name as object_entity_name, e.confidence, e.valid_from \
         FROM noo_temporal_edges e \
         JOIN noo_entities_typed s ON e.subject_id = s.id \
         LEFT JOIN noo_entities_typed o ON e.object_entity_id = o.id \
         WHERE e.subject_id = $1::uuid \
           AND e.valid_to IS NULL \
         ORDER BY e.valid_from DESC \
         LIMIT 100"
    )
    .bind(subject_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(stype, sname, pred, obj_v, obj_e, conf, vf)| CurrentFact {
            subject_type: stype,
            subject_name: sname,
            predicate: pred,
            object_value: obj_v,
            object_entity_name: obj_e,
            confidence: conf,
            valid_from: vf,
        })
        .collect())
}

/// Point-in-time snapshot of facts for a subject.
pub async fn get_facts_at(
    db: &PgPool,
    subject_id: &str,
    at_time: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<CurrentFact>> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, f64, chrono::DateTime<chrono::Utc>)>(
        "SELECT s.type, s.canonical_name, e.predicate, e.object_value, \
                o.canonical_name as object_entity_name, e.confidence, e.valid_from \
         FROM noo_temporal_edges e \
         JOIN noo_entities_typed s ON e.subject_id = s.id \
         LEFT JOIN noo_entities_typed o ON e.object_entity_id = o.id \
         WHERE e.subject_id = $1::uuid \
           AND e.valid_from <= $2 \
           AND (e.valid_to IS NULL OR e.valid_to > $2) \
         ORDER BY e.predicate, e.valid_from DESC"
    )
    .bind(subject_id)
    .bind(at_time)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(stype, sname, pred, obj_v, obj_e, conf, vf)| CurrentFact {
            subject_type: stype,
            subject_name: sname,
            predicate: pred,
            object_value: obj_v,
            object_entity_name: obj_e,
            confidence: conf,
            valid_from: vf,
        })
        .collect())
}

/// Get the evolution of a (subject, predicate) over time.
pub async fn get_evolution(
    db: &PgPool,
    subject_id: &str,
    predicate: &str,
) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, (Option<String>, Option<String>, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, f64)>(
        "SELECT object_value, \
                (SELECT canonical_name FROM noo_entities_typed WHERE id = e.object_entity_id), \
                valid_from, valid_to, confidence \
         FROM noo_temporal_edges e \
         WHERE subject_id = $1::uuid AND predicate = $2 \
         ORDER BY valid_from ASC \
         LIMIT 200"
    )
    .bind(subject_id)
    .bind(predicate)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(obj_v, obj_e, vf, vt, conf)| json!({
            "object_value": obj_v,
            "object_entity_name": obj_e,
            "valid_from": vf,
            "valid_to": vt,
            "confidence": conf,
        }))
        .collect())
}

/// Build a system-prompt-ready context block summarizing the user's
/// current standing facts, recent agent self-identity adaptations,
/// and ongoing project decisions. Returns None if nothing relevant.
///
/// This is **Layer D** of the long-conversation context stack
/// (alongside A: outline, B: rolling summary, C: semantic recall).
/// Resolve an identity's org (the tenant boundary). Handles both a user
/// (`noo_users.org_id`) and a `team:<name>` identity (space→team, PR5c —
/// `noo_kb_teams.org_id`). None when unknown / single-org.
async fn resolve_org(db: &PgPool, user_id: Option<&str>) -> Option<String> {
    let uid = user_id?;
    if let Some(team) = uid.strip_prefix("team:") {
        return sqlx::query_scalar::<_, Option<String>>(
            "SELECT org_id FROM noo_kb_teams WHERE name = $1",
        )
        .bind(team)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten();
    }
    crate::repo::users::org_of(db, uid).await.ok().flatten()
}

pub async fn fetch_temporal_context(
    db: &PgPool,
    user_id: Option<&str>,
) -> Option<String> {
    let mut sections: Vec<String> = Vec::new();
    // PR5b-3: the requester's org bounds cross-entity sections (projects) so one
    // tenant's state never leaks into another's prompt. None = single-org.
    let org = resolve_org(db, user_id).await;

    // Section 1: User's current preferences (only if user_id is known)
    if let Some(uid) = user_id {
        if let Some(user_entity_id) = find_entity_id(db, "user", uid).await {
            if let Ok(facts) = get_current_facts(db, &user_entity_id).await {
                if !facts.is_empty() {
                    let mut buf = String::from("[Your current understanding of the user]");
                    for f in facts.iter().take(15) {
                        let obj = f.object_value.as_deref()
                            .or(f.object_entity_name.as_deref())
                            .unwrap_or("?");
                        buf.push_str(&format!(
                            "\n- {} {} (since {})",
                            f.predicate,
                            obj,
                            f.valid_from.format("%Y-%m-%d"),
                        ));
                    }
                    sections.push(buf);
                }
            }
        }
    }

    // Section 2: Agent self-identity (if any has been adapted)
    if let Some(agent_id) = find_entity_id(db, "agent_self", "mesh").await {
        if let Ok(facts) = get_current_facts(db, &agent_id).await {
            if !facts.is_empty() {
                let mut buf = String::from("[Your current self-identity (live, may have been adapted)]");
                for f in facts.iter().take(10) {
                    let obj = f.object_value.as_deref()
                        .or(f.object_entity_name.as_deref())
                        .unwrap_or("?");
                    buf.push_str(&format!(
                        "\n- {} {} (since {})",
                        f.predicate,
                        obj,
                        f.valid_from.format("%Y-%m-%d"),
                    ));
                }
                sections.push(buf);
            }
        }
    }

    // Section 3: Recent project decisions (across the requester's org only —
    // PR5b-3; without the org bound this surfaced every tenant's projects).
    if let Ok(rows) = sqlx::query_as::<_, (String, String, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT s.canonical_name, e.predicate, e.object_value, e.valid_from \
         FROM noo_temporal_edges e \
         JOIN noo_entities_typed s ON e.subject_id = s.id \
         WHERE s.type = 'project' \
           AND e.valid_to IS NULL \
           AND ($1::text IS NULL OR s.org_id = $1) \
         ORDER BY e.valid_from DESC \
         LIMIT 8"
    )
    .bind(org.as_deref())
    .fetch_all(db)
    .await
    {
        if !rows.is_empty() {
            let mut buf = String::from("[Recent project state]");
            for (proj, pred, obj, vf) in &rows {
                let obj_str = obj.as_deref().unwrap_or("?");
                buf.push_str(&format!(
                    "\n- {} {} {} ({})",
                    proj, pred, obj_str, vf.format("%Y-%m-%d"),
                ));
            }
            sections.push(buf);
        }
    }

    if sections.is_empty() {
        return None;
    }
    Some(sections.join("\n\n"))
}

/// Convenience: fetch temporal context with a timeout, used during
/// system prompt assembly. Returns None if the query takes too long.
pub async fn fetch_temporal_context_timeout(
    db: &PgPool,
    user_id: Option<&str>,
    timeout: Duration,
) -> Option<String> {
    match tokio::time::timeout(timeout, fetch_temporal_context(db, user_id)).await {
        Ok(result) => result,
        Err(_) => {
            tracing::debug!("fetch_temporal_context timed out");
            None
        }
    }
}
