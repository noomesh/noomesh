// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// STUB: replaced by part D. Only the surface part B (the add-on delegated
// token routes) calls.

use serde::Serialize;

/// One page of a task's events, for `GET /api/tasks/{id}/events?after=<seq>`.
#[derive(Debug, Clone, Serialize)]
pub struct EventsPage {
    pub events: Vec<serde_json::Value>,
    pub earliest_seq: i64,
    pub last_seq: i64,
}

/// Record an event in the task's outbox. STUB: records nothing.
pub async fn emit(_db: &sqlx::PgPool, _task_id: &str, _kind: &str, _data: serde_json::Value) -> anyhow::Result<()> {
    Ok(())
}

/// A task's events after `after`, at most `limit`. STUB: an empty page.
pub async fn list_after(_db: &sqlx::PgPool, _task_id: &str, _after: i64, _limit: i64) -> anyhow::Result<EventsPage> {
    Ok(EventsPage { events: Vec::new(), earliest_seq: 0, last_seq: 0 })
}
