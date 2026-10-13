// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Background drain worker for the NATS publish dead-letter queue.
//!
//! When `worker_client::publish_fire_and_forget` exhausts its in-process
//! retry budget, the message lands in `noo_nats_dlq`. This worker wakes
//! periodically, locks a batch of pending rows with `FOR UPDATE SKIP LOCKED`
//! (so multiple gateway instances can drain concurrently without contention),
//! re-publishes them, and updates row state.
//!
//! Per-row state machine:
//!
//!   pending           — `succeeded_at IS NULL AND attempt_count < MAX_ATTEMPTS
//!                       AND (next_retry_at IS NULL OR next_retry_at <= NOW())`
//!   → republish OK    → set `succeeded_at = NOW()`
//!   → republish FAIL  → bump `attempt_count`; schedule next attempt
//!                       with exponential backoff
//!   → exhausted       → mark abandoned: `next_retry_at = NULL`,
//!                       `succeeded_at` stays NULL (operator triage signal).

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use sqlx::Row;

use crate::state::AppState;

const DRAIN_INTERVAL_SECS: u64 = 30;
const BATCH_SIZE: i64 = 100;
const MAX_DRAIN_ATTEMPTS: i32 = 10;
/// Backoff applied AFTER the first drain failure. `attempt_count = 1` uses
/// index 0 (60s); attempt_count >= len uses the last entry (8h).
const DRAIN_BACKOFFS_SECS: [i64; 9] = [60, 120, 300, 600, 1800, 3600, 7200, 14400, 28800];

/// Spawn the drain background task. Idempotent in the sense that calling
/// twice spawns two tasks — caller must only invoke once at startup.
pub fn spawn(state: Arc<AppState>) {
    tracing::info!(batch_size = BATCH_SIZE, "dlq_drain.started");
    // Immediate first tick — historical behavior: the first drain pass
    // runs right at startup, recovering rows queued while we were down.
    crate::managed_loop::ManagedLoop::new("dlq_drain", DRAIN_INTERVAL_SECS)
        .immediate_first_tick()
        .spawn(state, |state| async move {
            match drain_pass(&state).await? {
                0 => {}
                n => tracing::info!(processed = n, "dlq_drain.pass_complete"),
            }
            Ok(())
        });
}

async fn drain_pass(state: &Arc<AppState>) -> Result<usize> {
    // Pull a batch in a single transaction. SKIP LOCKED lets concurrent
    // drainers (e.g. multiple gateway replicas) operate without contention.
    let mut tx = state.db.begin().await?;
    let rows = sqlx::query(
        "SELECT id, subject, payload, attempt_count \
         FROM noo_nats_dlq \
         WHERE succeeded_at IS NULL \
           AND attempt_count < $1 \
           AND (next_retry_at IS NULL OR next_retry_at <= NOW()) \
         ORDER BY created_at ASC \
         LIMIT $2 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(MAX_DRAIN_ATTEMPTS)
    .bind(BATCH_SIZE)
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }

    let count = rows.len();
    for row in rows {
        let row_id: uuid::Uuid = row.try_get("id")?;
        let subject: String = row.try_get("subject")?;
        let payload: Value = row.try_get("payload")?;
        let attempt_count: i32 = row.try_get("attempt_count")?;
        process_row(state, &mut tx, row_id, &subject, &payload, attempt_count).await;
    }
    tx.commit().await?;
    Ok(count)
}

async fn process_row(
    state: &Arc<AppState>,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row_id: uuid::Uuid,
    subject: &str,
    payload: &Value,
    attempt_count: i32,
) {
    // The row carries the principal that originally published it (claims
    // only — `worker_client::insert_dlq`). Re-sign from those and strip the
    // key, so a replay arrives as the same caller rather than as whatever
    // the drain loop happens to be. A row written before this change has no
    // key and replays as a scopeless `internal:dlq-drain`.
    let (payload, principal) = crate::bus_principal::extract_from_dlq(payload);
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(row_id = %row_id, error = %e, "dlq_drain.payload_encode_failed");
            mark_abandoned(tx, row_id, &format!("payload_encode_failed: {e}")).await;
            return;
        }
    };

    let published = match crate::bus_principal::headers_for_principal(&principal, subject) {
        Some(h) => {
            state
                .nats
                .publish_with_headers(subject.to_string(), h, bytes.into())
                .await
        }
        None => state.nats.publish(subject.to_string(), bytes.into()).await,
    };
    match published {
        Ok(()) => {
            mark_succeeded(tx, row_id).await;
            let mut labels = std::collections::HashMap::new();
            labels.insert("subject".to_string(), subject.to_string());
            state
                .metrics
                .inc_counter("nats_dlq_drain_succeeded_total", Some(&labels), 1)
                .await;
        }
        Err(pub_err) => {
            let next_attempt = attempt_count + 1;
            let mut labels = std::collections::HashMap::new();
            labels.insert("subject".to_string(), subject.to_string());

            if next_attempt >= MAX_DRAIN_ATTEMPTS {
                mark_abandoned(tx, row_id, &pub_err.to_string()).await;
                tracing::warn!(
                    row_id = %row_id,
                    subject,
                    attempt = next_attempt,
                    error = %pub_err,
                    "dlq_drain.abandoned"
                );
                state
                    .metrics
                    .inc_counter("nats_dlq_abandoned_total", Some(&labels), 1)
                    .await;
            } else {
                let backoff_idx = ((next_attempt - 1) as usize).min(DRAIN_BACKOFFS_SECS.len() - 1);
                let backoff_secs = DRAIN_BACKOFFS_SECS[backoff_idx];
                schedule_retry(tx, row_id, next_attempt, &pub_err.to_string(), backoff_secs).await;
                state
                    .metrics
                    .inc_counter("nats_dlq_drain_failed_total", Some(&labels), 1)
                    .await;
            }
        }
    }
}

async fn mark_succeeded(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, row_id: uuid::Uuid) {
    let _ = sqlx::query("UPDATE noo_nats_dlq SET succeeded_at = NOW() WHERE id = $1")
        .bind(row_id)
        .execute(&mut **tx)
        .await;
}

async fn schedule_retry(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row_id: uuid::Uuid,
    attempt: i32,
    error: &str,
    backoff_secs: i64,
) {
    let truncated = crate::text::clip(error, 500);
    let _ = sqlx::query(
        "UPDATE noo_nats_dlq \
         SET attempt_count = $1, last_error = $2, next_retry_at = NOW() + ($3 || ' seconds')::interval \
         WHERE id = $4",
    )
    .bind(attempt)
    .bind(truncated)
    .bind(backoff_secs.to_string())
    .bind(row_id)
    .execute(&mut **tx)
    .await;
}

async fn mark_abandoned(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row_id: uuid::Uuid,
    error: &str,
) {
    let truncated = crate::text::clip(error, 500);
    let _ = sqlx::query(
        "UPDATE noo_nats_dlq \
         SET attempt_count = attempt_count + 1, last_error = $1, next_retry_at = NULL \
         WHERE id = $2",
    )
    .bind(truncated)
    .bind(row_id)
    .execute(&mut **tx)
    .await;
}
