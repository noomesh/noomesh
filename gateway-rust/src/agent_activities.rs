// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent activities — long-running pursuits the agent tracks across runs.
//!
//! Phase 3 of the meta-loop. Schema in migration
//! `008_agent_activities`. See that file's docstring for the conceptual
//! rationale; this module is the Rust-side CRUD + helpers.
//!
//! Lifecycle: create → (operator/agent updates progress) → complete
//! or abandon. Linked heartbeat tasks and self-develop cycles bump
//! `last_activity_at` automatically when they fire.
//!
//! Phase A (current): pure CRUD via HTTP + MCP tool.
//! Phase B (queued, task #106): heartbeat task config gets activity_id;
//!   digest summarizes active activities.
//! Phase C (deferred, task #107): autonomous activity inference +
//!   pursuit scheduling.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

pub const VALID_KINDS: &[&str] = &[
    "research",
    "knowledge_curation",
    "investigation",
    "monitoring",
    "user_pursuit",
    "other",
];

pub const VALID_STATUSES: &[&str] = &["active", "paused", "completed", "abandoned"];

/// Create a new activity. Validates `kind` and inserts the row.
/// Returns the inserted id on success.
pub async fn create_activity(
    db: &PgPool,
    name: &str,
    kind: &str,
    description: &str,
    success_when: Option<&str>,
    created_by: &str,
) -> Result<Uuid, String> {
    if name.trim().is_empty() {
        return Err("name is required".into());
    }
    if !VALID_KINDS.contains(&kind) {
        return Err(format!(
            "invalid kind '{kind}'. Valid: {}",
            VALID_KINDS.join(", ")
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO noo_agent_activities \
            (id, name, kind, status, description, success_when, created_by) \
         VALUES ($1, $2, $3, 'active', $4, $5, $6)",
    )
    .bind(id)
    .bind(name.trim())
    .bind(kind)
    .bind(description)
    .bind(success_when)
    .bind(created_by)
    .execute(db)
    .await
    .map_err(|e| format!("insert_failed: {e}"))?;
    Ok(id)
}

/// List activities. Optional filters on status / kind. Most-recently-
/// active first.
pub async fn list_activities(
    db: &PgPool,
    status_filter: Option<&str>,
    kind_filter: Option<&str>,
    limit: i64,
) -> Result<Vec<Value>, String> {
    // Hand-build the WHERE clause to avoid Postgres NULL-= surprises
    // for optional filters.
    let mut sql = String::from(
        "SELECT id::text, name, kind, status, description, success_when, \
                progress, related_task_ids, related_cycle_ids, \
                created_by, created_at, last_activity_at, completed_at \
         FROM noo_agent_activities WHERE 1=1",
    );
    if status_filter.is_some() {
        sql.push_str(" AND status = $1");
    }
    if kind_filter.is_some() {
        sql.push_str(if status_filter.is_some() {
            " AND kind = $2"
        } else {
            " AND kind = $1"
        });
    }
    sql.push_str(" ORDER BY last_activity_at DESC LIMIT $");
    sql.push_str(
        &(1 + status_filter.is_some() as usize + kind_filter.is_some() as usize).to_string(),
    );

    let mut q = sqlx::query_as::<
        _,
        (
            String, String, String, String, String, Option<String>,
            Value, Value, Value,
            String, DateTime<Utc>, DateTime<Utc>, Option<DateTime<Utc>>,
        ),
    >(&sql);
    if let Some(s) = status_filter {
        q = q.bind(s);
    }
    if let Some(k) = kind_filter {
        q = q.bind(k);
    }
    q = q.bind(limit);

    let rows = q
        .fetch_all(db)
        .await
        .map_err(|e| format!("list_failed: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.0,
                "name": r.1,
                "kind": r.2,
                "status": r.3,
                "description": r.4,
                "success_when": r.5,
                "progress": r.6,
                "related_task_ids": r.7,
                "related_cycle_ids": r.8,
                "created_by": r.9,
                "created_at": r.10,
                "last_activity_at": r.11,
                "completed_at": r.12,
            })
        })
        .collect())
}

/// Append a progress entry to an activity. Bumps last_activity_at.
/// `entry` is an arbitrary JSON object — suggested shape:
///   { "at": "<iso>", "summary": "...", "kind": "milestone"|"finding"|... }
/// Caller's responsibility to provide structure that makes sense for
/// the activity kind.
pub async fn append_progress(
    db: &PgPool,
    activity_id: Uuid,
    entry: Value,
) -> Result<(), String> {
    // Use jsonb_set with the array-append idiom. Initialize progress.entries
    // to [] if missing, then append.
    let res = sqlx::query(
        "UPDATE noo_agent_activities \
         SET progress = jsonb_set( \
                 COALESCE(progress, '{}'::jsonb), \
                 '{entries}', \
                 COALESCE(progress->'entries', '[]'::jsonb) || $2::jsonb, \
                 true), \
             last_activity_at = NOW() \
         WHERE id = $1",
    )
    .bind(activity_id)
    .bind(entry)
    .execute(db)
    .await
    .map_err(|e| format!("append_progress_failed: {e}"))?;
    if res.rows_affected() == 0 {
        return Err(format!("activity not found: {activity_id}"));
    }
    Ok(())
}

/// Link a heartbeat task to an activity (idempotent). When the task
/// fires, callers can `append_progress` to record what the task did.
pub async fn link_task(
    db: &PgPool,
    activity_id: Uuid,
    task_id: &str,
) -> Result<(), String> {
    let res = sqlx::query(
        "UPDATE noo_agent_activities \
         SET related_task_ids = CASE \
                 WHEN related_task_ids @> to_jsonb($2::text) THEN related_task_ids \
                 ELSE related_task_ids || to_jsonb($2::text) \
             END, \
             last_activity_at = NOW() \
         WHERE id = $1",
    )
    .bind(activity_id)
    .bind(task_id)
    .execute(db)
    .await
    .map_err(|e| format!("link_task_failed: {e}"))?;
    if res.rows_affected() == 0 {
        return Err(format!("activity not found: {activity_id}"));
    }
    Ok(())
}

/// Mark an activity terminal: completed or abandoned.
pub async fn complete_activity(
    db: &PgPool,
    activity_id: Uuid,
    final_status: &str,
    final_note: Option<&str>,
) -> Result<(), String> {
    if final_status != "completed" && final_status != "abandoned" {
        return Err(format!(
            "final_status must be 'completed' or 'abandoned', got '{final_status}'"
        ));
    }
    let note_entry = final_note.map(|n| {
        json!({
            "at": Utc::now().to_rfc3339(),
            "kind": "final",
            "summary": n,
        })
    });
    let res = sqlx::query(
        "UPDATE noo_agent_activities \
         SET status = $2, \
             completed_at = NOW(), \
             last_activity_at = NOW(), \
             progress = CASE WHEN $3::jsonb IS NULL THEN progress \
                             ELSE jsonb_set( \
                                 COALESCE(progress, '{}'::jsonb), \
                                 '{entries}', \
                                 COALESCE(progress->'entries', '[]'::jsonb) || $3::jsonb, \
                                 true) \
                        END \
         WHERE id = $1",
    )
    .bind(activity_id)
    .bind(final_status)
    .bind(note_entry)
    .execute(db)
    .await
    .map_err(|e| format!("complete_activity_failed: {e}"))?;
    if res.rows_affected() == 0 {
        return Err(format!("activity not found: {activity_id}"));
    }
    Ok(())
}

/// Toggle pause/resume on an active or paused activity. No-op on
/// terminal statuses.
pub async fn pause_or_resume(
    db: &PgPool,
    activity_id: Uuid,
    new_status: &str,
) -> Result<(), String> {
    if new_status != "active" && new_status != "paused" {
        return Err("new_status must be 'active' or 'paused'".into());
    }
    let res = sqlx::query(
        "UPDATE noo_agent_activities \
         SET status = $2, last_activity_at = NOW() \
         WHERE id = $1 AND status IN ('active', 'paused')",
    )
    .bind(activity_id)
    .bind(new_status)
    .execute(db)
    .await
    .map_err(|e| format!("pause_resume_failed: {e}"))?;
    if res.rows_affected() == 0 {
        return Err(format!(
            "activity not found or already terminal: {activity_id}"
        ));
    }
    Ok(())
}
