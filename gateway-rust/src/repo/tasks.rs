// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Background tasks — `noo_tasks`.
//!
//! Single-table statements on the task row: create, state transitions, the
//! loop checkpoint, the token accounting, and the clarification (ask/answer)
//! columns. What stays in `tasks.rs` is the `Task` read model (`SELECT`, a
//! LEFT JOIN to `noo_users` for the owner name, mapped by `row_to_task`) and
//! the statements whose subject is another table (`noo_task_idempotency`,
//! `noo_task_events`, `noo_task_context`, the retention sweep): those name
//! `noo_tasks` only in a sub-select.
//!
//! Every function takes the raw `uuid::Uuid` — parsing the caller's string id
//! (and what a bad one means) is the caller's job. Everything is
//! runtime-checked (`query` / `query_as` / `query_scalar`): statements moved
//! verbatim, and a new `query!` would need the `.sqlx` cache regenerated.
//! Each returns the raw `sqlx::Error`.

use serde_json::Value;
use uuid::Uuid;

/// States in which a task can still be stopped, finished or checkpointed.
/// (Spelled out in each statement below, not interpolated.)
pub const LIVE_STATES: [&str; 3] = ["open", "running", "checkpointed"];

/// Everything `create` writes. `owner` is a username, resolved to its
/// `user_uuid` inside the statement (`None` = no owner).
pub struct NewTaskRow<'a> {
    pub id: Uuid,
    pub objective: &'a str,
    pub owner: Option<&'a str>,
    pub conversation_id: Uuid,
    pub thread_id: &'a str,
    pub channel: &'a str,
    pub model: Option<&'a str>,
    pub loop_budget: i32,
    pub parent_id: Option<Uuid>,
    pub role: Option<&'a str>,
    pub budget_default: bool,
    pub token_budget: Option<i64>,
    pub created_via: Option<&'a str>,
}

/// Insert a task in state `open`.
pub async fn insert<'e, E>(db: E, t: &NewTaskRow<'_>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO noo_tasks (id, objective, owner_uuid, state, conversation_id, thread_id, channel, model, loop_budget, parent_id, role, budget_default, token_budget, created_via) \
         VALUES ($1, $2, (SELECT user_uuid FROM noo_users WHERE username = $3), 'open', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(t.id)
    .bind(t.objective)
    .bind(t.owner)
    .bind(t.conversation_id)
    .bind(t.thread_id)
    .bind(t.channel)
    .bind(t.model)
    .bind(t.loop_budget)
    .bind(t.parent_id)
    .bind(t.role)
    .bind(t.budget_default)
    .bind(t.token_budget)
    .bind(t.created_via)
    .execute(db)
    .await?;
    Ok(())
}

/// Replace a task's loop budget, only while it still carries the default.
pub async fn set_loop_budget_if_default<'e, E>(db: E, id: Uuid, budget: i32) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_tasks SET loop_budget = $2, updated_at = now() WHERE id = $1 AND budget_default")
        .bind(id)
        .bind(budget)
        .execute(db)
        .await?;
    Ok(())
}

/// Ids of `owner`'s unfinished tasks created `via` (an add-on's background work).
pub async fn live_ids_via<'e, E>(db: E, owner: &str, via: &str) -> Result<Vec<Uuid>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT id FROM noo_tasks \
         WHERE owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = $1) AND created_via = $2 \
         AND state IN ('open','running','checkpointed')",
    )
    .bind(owner)
    .bind(via)
    .fetch_all(db)
    .await
}

/// Per node, the live tasks it holds (i227 fix 4): (node, running or
/// checkpointed, open, seconds since the oldest running one's last
/// progress, seconds the oldest open one has waited). Children count; a
/// parked task (`budget_state`) and an aggregation parent (`loop_budget` 0)
/// do not.
pub async fn holds_by_node<'e, E>(db: E) -> Result<Vec<(String, i64, i64, Option<f64>, Option<f64>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT node, \
                COUNT(*) FILTER (WHERE state IN ('running','checkpointed')), \
                COUNT(*) FILTER (WHERE state = 'open'), \
                EXTRACT(EPOCH FROM now() - MIN(COALESCE(last_checkpoint, updated_at)) FILTER (WHERE state IN ('running','checkpointed')))::float8, \
                EXTRACT(EPOCH FROM now() - MIN(updated_at) FILTER (WHERE state = 'open'))::float8 \
         FROM noo_tasks \
         WHERE node IS NOT NULL AND state IN ('open','running','checkpointed') AND budget_state IS NULL AND loop_budget > 0 \
         GROUP BY node",
    )
    .fetch_all(db)
    .await
}

/// Delete a task that never left `open`.
pub async fn delete_if_open<'e, E>(db: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("DELETE FROM noo_tasks WHERE id = $1 AND state = 'open'").bind(id).execute(db).await?;
    Ok(())
}

/// Set the state, and the node when one is given (`None` keeps it).
pub async fn set_state<'e, E>(db: E, id: Uuid, state: &str, node: Option<&str>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_tasks SET state = $2, node = COALESCE($3, node), updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(state)
        .bind(node)
        .execute(db)
        .await?;
    Ok(())
}

/// The task's state, `None` when there is no such task.
pub async fn state_of<'e, E>(db: E, id: Uuid) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT state FROM noo_tasks WHERE id = $1").bind(id).fetch_optional(db).await
}

/// The task's state if (and only if) it is still live.
pub async fn live_state_of<'e, E>(db: E, id: Uuid) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT state FROM noo_tasks WHERE id = $1 AND state IN ('open','running','checkpointed')")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// `created_via` (`addon:<name>` for a delegated task); `None` for no such
/// task AND for a direct create — no caller distinguishes them.
pub async fn created_via<'e, E>(db: E, id: Uuid) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query_scalar::<_, Option<String>>("SELECT created_via FROM noo_tasks WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?
        .flatten())
}

/// Finish a live task: `done` with `result = text`, or `failed` with
/// `error = text`. Returns rows affected (`0` = it was not live).
pub async fn finish<'e, E>(db: E, id: Uuid, ok: bool, text: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let (state, col) = if ok { ("done", "result") } else { ("failed", "error") };
    let n = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE noo_tasks SET state = $2, {col} = $3, updated_at = now() \
         WHERE id = $1 AND state IN ('open','running','checkpointed')"
    )))
    .bind(id)
    .bind(state)
    .bind(text)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n)
}

/// Stop a live task. Returns rows affected (`0` = it was not live).
pub async fn stop_live<'e, E>(db: E, id: Uuid) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query("UPDATE noo_tasks SET state = 'stopped', updated_at = now() WHERE id = $1 AND state IN ('open','running','checkpointed')")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected())
}

/// Record a checkpoint: loops so far, the note (kept when `None`), and
/// `running` -> `checkpointed`.
pub async fn checkpoint<'e, E>(db: E, id: Uuid, loops: i32, note: Option<&str>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE noo_tasks SET loops = $2, last_checkpoint = now(), last_note = COALESCE($3, last_note), \
         state = CASE WHEN state = 'running' THEN 'checkpointed' ELSE state END, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(loops)
    .bind(note)
    .execute(db)
    .await?;
    Ok(())
}

// ── Token accounting ────────────────────────────────────────────────────

/// The accounting UPDATE: one statement, atomic, returning the new total.
pub const ADD_SPENT_SQL: &str =
    "UPDATE noo_tasks SET tokens_spent = tokens_spent + $2, updated_at = now() WHERE id = $1 RETURNING tokens_spent";

/// Add tokens to the task. Returns the new total, `None` for an unknown task.
pub async fn add_spent<'e, E>(db: E, id: Uuid, tokens: i64) -> Result<Option<i64>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, i64>(ADD_SPENT_SQL).bind(id).bind(tokens).fetch_optional(db).await
}

/// Change the token cap, nothing else.
pub async fn set_token_budget<'e, E>(db: E, id: Uuid, budget: Option<i64>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_tasks SET token_budget = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(budget)
        .execute(db)
        .await?;
    Ok(())
}

/// Resume an `exhausted` task, optionally with a new cap: compare-and-set on
/// the parked state, so two resubmits cannot start two runners. Returns rows
/// affected (`0` = it changed under the caller).
pub async fn resume_exhausted<'e, E>(db: E, id: Uuid, new_budget: Option<i64>) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_tasks SET token_budget = COALESCE($2, token_budget), budget_state = NULL, updated_at = now() \
         WHERE id = $1 AND budget_state = 'exhausted' AND state IN ('open','running','checkpointed')",
    )
    .bind(id)
    .bind(new_budget)
    .execute(db)
    .await?
    .rows_affected())
}

/// Park a live, unparked task at the boundary: `checkpointed`, `budget_state`
/// set, note recorded. Returns rows affected.
pub async fn park<'e, E>(db: E, id: Uuid, budget_state: &str, note: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_tasks SET budget_state = $2, last_note = $3, last_checkpoint = now(), \
         state = CASE WHEN state IN ('open','running') THEN 'checkpointed' ELSE state END, updated_at = now() \
         WHERE id = $1 AND state IN ('open','running','checkpointed') AND budget_state IS NULL",
    )
    .bind(id)
    .bind(budget_state)
    .bind(note)
    .execute(db)
    .await?
    .rows_affected())
}

// ── Clarification (ask / answer) ────────────────────────────────────────

/// The stored clarification JSON, `None` when unset or no such task.
pub async fn clarification<'e, E>(db: E, id: Uuid) -> Result<Option<Value>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query_scalar::<_, Option<Value>>("SELECT clarification FROM noo_tasks WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?
        .flatten())
}

/// Hand an ANSWERED clarification over exactly once: clear it and return what
/// it held. `None` when there is nothing answered.
pub async fn take_answered_clarification<'e, E>(db: E, id: Uuid) -> Result<Option<Value>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "WITH old AS (SELECT id, clarification FROM noo_tasks WHERE id = $1 FOR UPDATE) \
         UPDATE noo_tasks t SET clarification = NULL FROM old \
         WHERE t.id = old.id AND old.clarification ? 'answer' RETURNING old.clarification",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// Record a question on an unparked live task. NEVER sets `budget_state`:
/// only the boundary parks a task (see [`park`]). Returns rows affected.
pub async fn set_question<'e, E>(db: E, id: Uuid, question: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_tasks SET clarification = jsonb_build_object('question', $2::text), last_note = $2, updated_at = now() \
         WHERE id = $1 AND budget_state IS NULL AND state IN ('open','running','checkpointed')",
    )
    .bind(id)
    .bind(question)
    .execute(db)
    .await?
    .rows_affected())
}

/// Record the owner's answer to a parked question and unpark the task.
/// Returns rows affected (`0` = it is not waiting for an answer).
pub async fn set_answer<'e, E>(db: E, id: Uuid, answer: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_tasks SET budget_state = NULL, \
         clarification = jsonb_build_object('question', COALESCE(clarification->>'question', last_note, ''), 'answer', $2::text), \
         updated_at = now() WHERE id = $1 AND budget_state = 'awaiting_clarification'",
    )
    .bind(id)
    .bind(answer)
    .execute(db)
    .await?
    .rows_affected())
}

// ── Context revisions ───────────────────────────────────────────────────

/// Lock the task row and read `(state, context_revision)`. Call inside a
/// transaction; `None` when there is no such task.
pub async fn lock_state_and_revision<'e, E>(db: E, id: Uuid) -> Result<Option<(String, i32)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("SELECT state, context_revision FROM noo_tasks WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Point the task at its newest accepted context revision.
pub async fn set_context_revision<'e, E>(db: E, id: Uuid, revision: i32) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_tasks SET context_revision = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(revision)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Asking must not park the task mid-turn: only the boundary sets
    /// `budget_state` (moved here from `task_budget`'s own source scan when
    /// the statement moved).
    #[test]
    fn asking_never_sets_budget_state() {
        let src = include_str!("tasks.rs");
        let body = &src[src.find("pub async fn set_question<").unwrap()..src.find("pub async fn set_answer<").unwrap()];
        assert!(!body.contains("budget_state = $"), "set_question must not park the task");
    }
}
