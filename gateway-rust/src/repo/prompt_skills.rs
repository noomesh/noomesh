// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Prompt skill usage stats — `noo_prompt_skill_stats`.
//!
//! This table has existed, fully specified, without a writer. It has an ORM
//! model, three indexes, a migration adding `user_id` for multi-user, another
//! adding `org_id` for tenancy, and a GDPR erasure target in `routes/users.rs`
//! — and zero rows, because nothing ever inserted into it.
//!
//! The signal was dropped twice on the way here:
//!
//! 1. The Rust agent loop published `worker.prompt_skills.record_usage` before
//!    any handler existed. The Python handler added on 2026-07-18 says so in
//!    its own docstring: *"No handler existed before 2026-07-18, so the counts
//!    were silently dropped."*
//! 2. That handler then incremented an **in-memory** counter, not this table.
//!    The fix looked complete and still persisted nothing.
//!
//! Usage rows are the input the evolve add-on reads when it scores skills.

use sqlx::PgPool;

/// Record that a set of skills was injected into a prompt.
///
/// Best-effort by design: this is telemetry on the inference hot path, and a
/// stats insert must never fail a user's request. Errors are logged, not
/// returned — but they ARE logged, unlike the two silent drops above.
///
/// `fitness_delta` is left at the column default (0.0). Usage is not itself a
/// fitness judgement; recording it is what finally makes a judgement possible.
pub async fn record_usage(
    pool: &PgPool,
    skill_names: &[String],
    conversation_id: &str,
) {
    if skill_names.is_empty() {
        return;
    }
    for name in skill_names {
        // One row per (skill, conversation) use — the table is an event log
        // (`used_at`, indexed descending), not a counter. That is what allows
        // "fitness over the last N uses" rather than an all-time total.
        let res = sqlx::query!(
            "INSERT INTO noo_prompt_skill_stats (skill_name, conversation_id, context) \
             VALUES ($1, $2, '{}'::jsonb)",
            name,
            conversation_id,
        )
        .execute(pool)
        .await;

        if let Err(e) = res {
            tracing::warn!(
                skill = %name,
                error = %e,
                "prompt_skill_usage_insert_failed"
            );
        }
    }
}
