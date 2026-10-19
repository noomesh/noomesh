// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// STUB: replaced by part C. Only the surface part B (the add-on delegated
// token routes) calls.

/// What became of a pushed context revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextOutcome {
    Accepted,
    Duplicate { current: i32 },
    Conflict { current: i32 },
    Terminal { state: String },
    TooLarge,
}

/// Submit context revision `revision` for a task. STUB: accepts nothing.
pub async fn submit(_db: &sqlx::PgPool, _task_id: &str, _revision: i32, _text: &str) -> anyhow::Result<ContextOutcome> {
    Err(anyhow::anyhow!("task context is not implemented in this build"))
}
