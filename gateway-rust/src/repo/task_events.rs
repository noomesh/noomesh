// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Task event outbox — `noo_task_events`, the reads the delivery loop makes
//! when it decides where to resume.
//!
//! Every function takes the raw `uuid::Uuid` and returns the raw
//! `sqlx::Error`: a failed read is never folded into "no events retained"
//! (that would turn an outage into a skip). Runtime-checked statements.

use sqlx::PgPool;
use uuid::Uuid;

/// The oldest retained seq for the task, `None` when the outbox is empty.
pub async fn earliest_seq(db: &PgPool, task_id: Uuid) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT min(seq) FROM noo_task_events WHERE task_id = $1")
        .bind(task_id)
        .fetch_one(db)
        .await
}

/// The oldest retained seq strictly above `after`, `None` when nothing
/// retained is newer.
pub async fn next_retained_seq(db: &PgPool, task_id: Uuid, after: i64) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT min(seq) FROM noo_task_events WHERE task_id = $1 AND seq > $2")
        .bind(task_id)
        .bind(after)
        .fetch_one(db)
        .await
}
