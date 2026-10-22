// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Token budgets: a switch at the loop boundary (i83 G).
//!
//! A task carries a token budget beside its loop budget (`token_budget`,
//! NULL = no cap), set by its owner and adjustable while it runs; a person
//! may carry a standing allowance per period (`noo_token_allowances`), set
//! by an operator. The rules, in the operator's terms:
//!
//! 1. **The running turn is never interrupted.** A loop that crosses the
//!    budget finishes, its tool results stand, the task checkpoints. The
//!    check is [`check`], and the runners call it only BEFORE a loop starts
//!    (`tasks::run_task_loops`, `harness::driver`; the `budget_check` rail op
//!    for a runner on a node, which never reads the database).
//! 2. **Exhausted means no more turns.** The task is parked — `checkpointed`
//!    with `budget_state = exhausted`, never failed — and its last note,
//!    posted to its thread, says why with the numbers.
//! 3. **Two ways out.** RESUBMIT ([`resubmit`]): the owner raises the budget
//!    and the task resumes from its checkpoint. ASK ([`ask`]): a loop that
//!    cannot go on without the owner posts a question; at the next boundary
//!    the task parks `awaiting_clarification`, and the owner's answer
//!    ([`answer`]) starts a NEW loop whose prompt carries both. Nothing is
//!    re-run, nothing is lost.
//! 4. **Cloud is counted as cloud.** Every loop's tokens land in
//!    `noo_token_usage` with the task id and the real backend
//!    (`cloud-anthropic`…, `harness:<kind>`, or the node's backend), so the
//!    report keeps node and cloud apart. The budget is one number.
//!
//! A `budget_state` is set ONLY at the boundary — by [`check`] — so a set
//! state always means the runner has stopped. That is what lets resubmit and
//! answer start a new runner without ever running two.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use crate::state::AppState;
use crate::tasks::Task;

/// `budget_state` when the task or the person's allowance ran out.
pub const EXHAUSTED: &str = "exhausted";
/// `budget_state` when a loop asked the owner a question.
pub const AWAITING_CLARIFICATION: &str = "awaiting_clarification";
/// The periods an allowance may run over (`date_trunc` units).
pub const PERIODS: &[&str] = &["day", "week", "month"];
/// The longest question or answer kept.
pub const MAX_TEXT: usize = 4000;

/// What a task has spent against its own cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskSpend {
    pub token_budget: Option<i64>,
    pub tokens_spent: i64,
}

impl From<&Task> for TaskSpend {
    fn from(t: &Task) -> Self {
        TaskSpend { token_budget: t.token_budget, tokens_spent: t.tokens_spent }
    }
}

/// What a person has spent against their allowance this period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowanceSpend {
    pub period: String,
    pub limit: i64,
    pub spent: i64,
}

impl AllowanceSpend {
    pub fn remaining(&self) -> i64 {
        (self.limit - self.spent).max(0)
    }
}

/// The switch's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Proceed,
    Exhausted { reason: String },
}

/// `day` → `daily`, for the reason text.
fn adjective(period: &str) -> &'static str {
    match period {
        "day" => "daily",
        "week" => "weekly",
        _ => "monthly",
    }
}

/// THE SWITCH, pure: may another loop start? The task's own cap first (the
/// owner can raise it), then the person's allowance (an operator can). A
/// spend AT the limit is exhausted: the loop that reached it already ran.
pub fn budget_verdict(task: TaskSpend, allowance: Option<&AllowanceSpend>) -> Verdict {
    if let Some(b) = task.token_budget {
        if task.tokens_spent >= b {
            return Verdict::Exhausted {
                reason: format!(
                    "token budget exhausted: this task has spent {} of its {} tokens. No more loops run until the \
                     owner resubmits it with a larger budget (noo tasks resubmit <id> --token-budget <n>).",
                    task.tokens_spent, b
                ),
            };
        }
    }
    if let Some(a) = allowance {
        if a.spent >= a.limit {
            return Verdict::Exhausted {
                reason: format!(
                    "{} token allowance exhausted: {} of {} tokens used this {}. No more loops run until an operator \
                     raises the allowance or the {} turns over; then resubmit the task.",
                    adjective(&a.period),
                    a.spent,
                    a.limit,
                    a.period,
                    a.period
                ),
            };
        }
    }
    Verdict::Proceed
}

/// What a task may still spend against its own cap; `None` = no cap.
pub fn remaining_task(task: TaskSpend) -> Option<i64> {
    task.token_budget.map(|b| (b - task.tokens_spent).max(0))
}

/// One loop's tokens as one number: prompt + completion.
pub fn loop_tokens(prompt: u64, completion: u64) -> i64 {
    prompt.saturating_add(completion).min(i64::MAX as u64) as i64
}

/// The question a loop asked, and the owner's answer once it arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clarification {
    pub question: String,
    #[serde(default)]
    pub answer: Option<String>,
}

/// The first loop after an answer: the question, the answer, the objective.
pub fn clarification_prompt(objective: &str, c: &Clarification, loop_no: u32, budget: u32) -> String {
    format!(
        "Continue the task (loop {loop_no} of {budget}). Objective:\n\n{objective}\n\n\
         In an earlier loop you could not go on without the owner, and asked:\n\n{q}\n\n\
         The owner answered:\n\n{a}\n\n\
         Take the answer into account, review what this conversation already did, and take the next concrete \
         step. Call noo_task_done when the objective is achieved (or failed=true if it cannot be).",
        q = c.question.trim(),
        a = c.answer.as_deref().unwrap_or("").trim(),
    )
}

/// What the boundary check tells a runner. Also the `budget_check` rail
/// op's reply (the gateway adds `ok`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BudgetCheck {
    /// Another loop may start.
    pub proceed: bool,
    /// Why not, with the numbers.
    #[serde(default)]
    pub reason: Option<String>,
    /// Tokens left under the task's own cap; `None` = no cap.
    #[serde(default)]
    pub remaining_task: Option<i64>,
    /// Tokens left under the person's allowance; `None` = no allowance.
    #[serde(default)]
    pub remaining_allowance: Option<i64>,
    /// The task's state after the check.
    #[serde(default)]
    pub state: String,
    /// A question and its answer, for the next loop's prompt. Handed over
    /// once: the check that returns it clears it.
    #[serde(default)]
    pub clarification: Option<Clarification>,
    /// Context the owner added since the last loop (i143 C), already
    /// phrased as "The owner updated this task's context (revision N): …".
    /// Handed over once, like `clarification`: the check that returns it
    /// marks it applied. A runner prepends it to the loop's prompt
    /// ([`with_context`]). An older harness does not know the field and
    /// ignores it (serde skips unknown fields), so the revision is marked
    /// applied but that harness's loop never sees it.
    #[serde(default)]
    pub context: Option<String>,
}

/// The loop prompt with the owner's new context in front, when there is some.
pub fn with_context(prompt: String, context: Option<&str>) -> String {
    match context.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => format!("{c}\n\n{prompt}"),
        None => prompt,
    }
}

impl BudgetCheck {
    fn stop(state: &str, reason: impl Into<String>) -> Self {
        BudgetCheck { proceed: false, reason: Some(reason.into()), state: state.to_string(), ..Default::default() }
    }
}

fn live(state: &str) -> bool {
    matches!(state, "open" | "running" | "checkpointed")
}

// ── the database ────────────────────────────────────────────────────────

/// The person's allowance, if an operator set one: `(period, limit)`.
pub async fn allowance_of(db: &sqlx::PgPool, username: &str) -> Result<Option<(String, i64)>> {
    let row = sqlx::query(
        "SELECT a.period, a.limit_tokens, a.updated_by, a.updated_at FROM noo_token_allowances a \
         JOIN noo_users u ON u.user_uuid = a.user_uuid WHERE u.username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| (r.get::<String, _>("period"), r.get::<i64, _>("limit_tokens"))))
}

/// The SQL for a person's spend in the current period: every row charged to
/// them since the period began, node, cloud and harness alike. Raw rows only:
/// the current period is always inside the raw retention window.
pub const PERIOD_SPEND_SQL: &str = "SELECT COALESCE(SUM(prompt_tokens::bigint + completion_tokens::bigint), 0)::bigint \
     FROM noo_token_usage \
     WHERE user_uuid = (SELECT u.user_uuid FROM noo_users u WHERE u.username = $1) \
       AND ts >= date_trunc($2, now())";

/// What the person has spent this period. One query per call — a check is
/// one call, so it is computed per request, never kept as a running count.
pub async fn period_spend(db: &sqlx::PgPool, username: &str, period: &str) -> Result<i64> {
    if !PERIODS.contains(&period) {
        return Err(anyhow!("unknown period {period:?}"));
    }
    Ok(sqlx::query_scalar::<_, i64>(PERIOD_SPEND_SQL).bind(username).bind(period).fetch_one(db).await?)
}

/// The person's allowance and what they have spent against it, if they
/// have one.
pub async fn allowance_use(db: &sqlx::PgPool, username: &str) -> Result<Option<AllowanceSpend>> {
    let Some((period, limit)) = allowance_of(db, username).await? else { return Ok(None) };
    let spent = period_spend(db, username, &period).await?;
    Ok(Some(AllowanceSpend { period, limit, spent }))
}

/// The accounting UPDATE: one statement, atomic, returning the new total.
pub const ADD_SPENT_SQL: &str =
    "UPDATE noo_tasks SET tokens_spent = tokens_spent + $2, updated_at = now() WHERE id = $1 RETURNING tokens_spent";

/// Add one loop's tokens to the task. Returns the new total, or `None` for
/// an unknown task.
pub async fn add_spent(db: &sqlx::PgPool, task_id: &str, tokens: i64) -> Result<Option<i64>> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    Ok(sqlx::query_scalar::<_, i64>(ADD_SPENT_SQL).bind(uuid).bind(tokens.max(0)).fetch_optional(db).await?)
}

/// Account one loop: the usage row (with the task id, awaited so the next
/// check sees it) and the task's running total.
pub async fn account(db: &sqlx::PgPool, u: &crate::usage::TaskUsage) -> Result<Option<i64>> {
    crate::usage::record_task(db, u).await;
    add_spent(db, &u.task_id, loop_tokens(u.prompt_tokens as u64, u.completion_tokens as u64)).await
}

async fn load_clarification(db: &sqlx::PgPool, task_id: &str) -> Result<Option<Clarification>> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let v: Option<serde_json::Value> = sqlx::query_scalar("SELECT clarification FROM noo_tasks WHERE id = $1")
        .bind(uuid)
        .fetch_optional(db)
        .await?
        .flatten();
    Ok(v.and_then(|v| serde_json::from_value(v).ok()))
}

/// Hand an answered clarification over, once.
async fn take_clarification(db: &sqlx::PgPool, task_id: &str) -> Result<Option<Clarification>> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let v: Option<serde_json::Value> = sqlx::query_scalar(
        "WITH old AS (SELECT id, clarification FROM noo_tasks WHERE id = $1 FOR UPDATE) \
         UPDATE noo_tasks t SET clarification = NULL FROM old \
         WHERE t.id = old.id AND old.clarification ? 'answer' RETURNING old.clarification",
    )
    .bind(uuid)
    .fetch_optional(db)
    .await?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()))
}

/// Park a live task at the boundary: `checkpointed`, the state set, the note
/// recorded. Only an unparked live task parks.
async fn park(db: &sqlx::PgPool, task_id: &str, budget_state: &str, note: &str) -> Result<bool> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let n = sqlx::query(
        "UPDATE noo_tasks SET budget_state = $2, last_note = $3, last_checkpoint = now(), \
         state = CASE WHEN state IN ('open','running') THEN 'checkpointed' ELSE state END, updated_at = now() \
         WHERE id = $1 AND state IN ('open','running','checkpointed') AND budget_state IS NULL",
    )
    .bind(uuid)
    .bind(budget_state)
    .bind(note)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Post a line to the task's thread, from its owner, as the task.
async fn post(state: &AppState, task: &Task, kind: &str, body: serde_json::Value) {
    let Some(owner) = task.owner.as_deref() else { return };
    let env = crate::agent_messages::Envelope::new(owner, "thread", kind, body, Some(&task.thread_id), vec![])
        .with_from(crate::agent_messages::Identity::new(Some(owner), task.node.as_deref(), Some(owner), Some("task")));
    if let Err(e) = crate::agent_messages::publish(&state.js, &env).await {
        tracing::warn!(error = %e, task = %task.id, "task_budget: thread post failed");
    }
}

/// THE BOUNDARY CHECK. Runners call it before a loop starts and never inside
/// one. It stops a runner that must stop (a parked task, a finished one, a
/// question waiting for the owner, a spent budget or allowance) and parks
/// the task when this check is the one that decided; otherwise it lets the
/// loop start, handing over an answered question once.
pub async fn check(state: &AppState, task_id: &str) -> Result<BudgetCheck> {
    let db = &state.db;
    let Some(task) = crate::tasks::get(db, task_id).await? else { return Err(anyhow!("task {task_id} not found")) };
    if !live(&task.state) {
        return Ok(BudgetCheck::stop(&task.state, format!("the task is {}", task.state)));
    }
    if task.budget_state.is_some() {
        let why = task.last_note.clone().unwrap_or_else(|| format!("the task is {}", task.budget_state.as_deref().unwrap_or("")));
        return Ok(BudgetCheck::stop(&task.state, why));
    }
    let clarification = load_clarification(db, task_id).await?;
    if let Some(c) = clarification.as_ref().filter(|c| c.answer.is_none()) {
        // A loop asked during the turn that just ended: park now, at the
        // boundary. The question was posted when it was asked.
        park(db, task_id, AWAITING_CLARIFICATION, &c.question).await?;
        tracing::info!(task = task_id, "task_budget: parked awaiting the owner's answer");
        return Ok(BudgetCheck::stop("checkpointed", format!("waiting for the owner's answer to: {}", c.question)));
    }
    let allowance = match task.owner.as_deref() {
        Some(o) => allowance_use(db, o).await?,
        None => None,
    };
    let spend = TaskSpend::from(&task);
    match budget_verdict(spend, allowance.as_ref()) {
        Verdict::Exhausted { reason } => {
            if park(db, task_id, EXHAUSTED, &reason).await? {
                tracing::info!(task = task_id, spent = task.tokens_spent, budget = ?task.token_budget, "task_budget: exhausted; parked");
                post(state, &task, "note", json!({"text": reason, "task_id": task.id, "loop": task.loops, "budget_state": EXHAUSTED})).await;
            }
            let mut out = BudgetCheck::stop("checkpointed", reason);
            out.remaining_task = remaining_task(spend);
            out.remaining_allowance = allowance.as_ref().map(AllowanceSpend::remaining);
            Ok(out)
        }
        Verdict::Proceed => {
            let handed = if clarification.is_some() { take_clarification(db, task_id).await? } else { None };
            // The owner's new context, once (i143 C). A read failure leaves
            // the revisions unapplied for the next boundary.
            let context = match crate::task_context::take_pending(db, task_id).await {
                Ok(c) => c.map(|(rev, text)| crate::task_context::preamble(rev, &text)),
                Err(e) => {
                    tracing::warn!(task = task_id, error = %e, "task_budget: pending context not read");
                    None
                }
            };
            Ok(BudgetCheck {
                proceed: true,
                reason: None,
                remaining_task: remaining_task(spend),
                remaining_allowance: allowance.as_ref().map(AllowanceSpend::remaining),
                state: task.state.clone(),
                clarification: handed,
                context,
            })
        }
    }
}

/// Why a resubmit, ask or answer was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The task is not in a state this applies to (409).
    Conflict(String),
    /// The arguments are wrong (400).
    Invalid(String),
    /// Something broke (500).
    Internal(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Conflict(m) | Refusal::Invalid(m) | Refusal::Internal(m) => f.write_str(m),
        }
    }
}

impl From<Refusal> for crate::routes::AppError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Conflict(m) => crate::routes::AppError::Conflict(m),
            Refusal::Invalid(m) => crate::routes::AppError::BadRequest(m),
            Refusal::Internal(m) => crate::routes::AppError::Internal(m),
        }
    }
}

fn internal(e: impl std::fmt::Display) -> Refusal {
    Refusal::Internal(e.to_string())
}

fn clean(text: &str, what: &str) -> Result<String, Refusal> {
    let t = text.trim();
    if t.is_empty() || t.chars().count() > MAX_TEXT {
        return Err(Refusal::Invalid(format!("{what} must be 1–{MAX_TEXT} characters")));
    }
    Ok(t.to_string())
}

/// What a resubmit may do to a task, decided from its row alone.
#[derive(Debug, PartialEq, Eq)]
pub enum ResubmitPlan {
    /// Parked exhausted: set the budget, clear the state, resume.
    Resume,
    /// Live and not parked: only the budget changes (adjusting a running task).
    Adjust,
}

/// The resubmit rule, pure. `allowance` is the owner's current one.
pub fn resubmit_plan(task: &Task, new_budget: Option<i64>, allowance: Option<&AllowanceSpend>) -> Result<ResubmitPlan, Refusal> {
    if let Some(b) = new_budget {
        if b <= 0 {
            return Err(Refusal::Invalid("token_budget must be a positive number of tokens".into()));
        }
    }
    if !live(&task.state) {
        return Err(Refusal::Conflict(format!("task {} is {}; there is nothing to resubmit", task.id, task.state)));
    }
    match task.budget_state.as_deref() {
        Some(AWAITING_CLARIFICATION) => Err(Refusal::Conflict(format!(
            "task {} is waiting for your answer to its question; answer it (noo tasks answer {} <text>)",
            task.id, task.id
        ))),
        Some(_) => {
            let spend = TaskSpend { token_budget: new_budget.or(task.token_budget), tokens_spent: task.tokens_spent };
            match budget_verdict(spend, allowance) {
                Verdict::Proceed => Ok(ResubmitPlan::Resume),
                Verdict::Exhausted { reason } => Err(Refusal::Conflict(format!("still exhausted: {reason}"))),
            }
        }
        None if new_budget.is_none() => Err(Refusal::Invalid(format!(
            "task {} is not out of budget; give token_budget to change its budget",
            task.id
        ))),
        None => Ok(ResubmitPlan::Adjust),
    }
}

/// RESUBMIT: the owner raises the budget (or, for an allowance that has
/// since been raised or turned over, just asks again) and a parked task
/// resumes from its checkpoint. On a running task it only changes the cap,
/// which the next boundary reads. Returns the task after, and whether it
/// was resumed (and where).
pub async fn resubmit(state: &std::sync::Arc<AppState>, task: &Task, new_budget: Option<i64>) -> Result<(Task, Option<crate::tasks::Started>), Refusal> {
    let allowance = match task.owner.as_deref() {
        Some(o) => allowance_use(&state.db, o).await.map_err(internal)?,
        None => None,
    };
    let plan = resubmit_plan(task, new_budget, allowance.as_ref())?;
    let uuid = uuid::Uuid::parse_str(&task.id).map_err(internal)?;
    let started = match plan {
        ResubmitPlan::Adjust => {
            sqlx::query("UPDATE noo_tasks SET token_budget = $2, updated_at = now() WHERE id = $1")
                .bind(uuid)
                .bind(new_budget)
                .execute(&state.db)
                .await
                .map_err(internal)?;
            None
        }
        ResubmitPlan::Resume => {
            // Compare-and-set on the parked state: two resubmits cannot
            // start two runners.
            let n = sqlx::query(
                "UPDATE noo_tasks SET token_budget = COALESCE($2, token_budget), budget_state = NULL, updated_at = now() \
                 WHERE id = $1 AND budget_state = 'exhausted' AND state IN ('open','running','checkpointed')",
            )
            .bind(uuid)
            .bind(new_budget)
            .execute(&state.db)
            .await
            .map_err(internal)?
            .rows_affected();
            if n == 0 {
                return Err(Refusal::Conflict(format!("task {} changed under the resubmit; read it again", task.id)));
            }
            let fresh = crate::tasks::get(&state.db, &task.id).await.map_err(internal)?.ok_or_else(|| internal("task vanished"))?;
            post(state, &fresh, "note", json!({"text": format!("resubmitted with a token budget of {}", fresh.token_budget.map(|b| b.to_string()).unwrap_or_else(|| "no cap".into())), "task_id": fresh.id})).await;
            Some(crate::tasks::start(state, &fresh).await.map_err(internal)?)
        }
    };
    let after = crate::tasks::get(&state.db, &task.id).await.map_err(internal)?.ok_or_else(|| internal("task vanished"))?;
    Ok((after, started))
}

/// ASK: a loop that cannot go on without its owner records a question and
/// posts it to the task's thread. The turn is not interrupted: the task
/// parks `awaiting_clarification` at the next boundary ([`check`]).
pub async fn ask(state: &AppState, task: &Task, question: &str) -> Result<(), Refusal> {
    let q = clean(question, "question")?;
    if !live(&task.state) {
        return Err(Refusal::Conflict(format!("task {} is {}", task.id, task.state)));
    }
    if task.budget_state.is_some() {
        return Err(Refusal::Conflict(format!("task {} is already {}", task.id, task.budget_state.as_deref().unwrap_or(""))));
    }
    let uuid = uuid::Uuid::parse_str(&task.id).map_err(internal)?;
    let n = sqlx::query(
        "UPDATE noo_tasks SET clarification = jsonb_build_object('question', $2::text), last_note = $2, updated_at = now() \
         WHERE id = $1 AND budget_state IS NULL AND state IN ('open','running','checkpointed')",
    )
    .bind(uuid)
    .bind(&q)
    .execute(&state.db)
    .await
    .map_err(internal)?
    .rows_affected();
    if n == 0 {
        return Err(Refusal::Conflict(format!("task {} changed under the question; read it again", task.id)));
    }
    post(state, task, "note", json!({"text": q, "task_id": task.id, "question": true, "loop": task.loops})).await;
    // i143 D: the question, to an add-on's task's event stream.
    crate::task_events::emit_logged(&state.db, &task.id, "question", json!({"question": q})).await;
    Ok(())
}

/// ANSWER: the owner answers a parked task's question. The state clears, the
/// answer is posted to the thread, and a NEW loop starts whose prompt
/// carries the question and the answer ([`clarification_prompt`]).
pub async fn answer(state: &std::sync::Arc<AppState>, task: &Task, text: &str) -> Result<(Task, crate::tasks::Started), Refusal> {
    let a = clean(text, "answer")?;
    if task.budget_state.as_deref() != Some(AWAITING_CLARIFICATION) {
        return Err(Refusal::Conflict(format!("task {} is not waiting for an answer", task.id)));
    }
    let uuid = uuid::Uuid::parse_str(&task.id).map_err(internal)?;
    let n = sqlx::query(
        "UPDATE noo_tasks SET budget_state = NULL, \
         clarification = jsonb_build_object('question', COALESCE(clarification->>'question', last_note, ''), 'answer', $2::text), \
         updated_at = now() WHERE id = $1 AND budget_state = 'awaiting_clarification'",
    )
    .bind(uuid)
    .bind(&a)
    .execute(&state.db)
    .await
    .map_err(internal)?
    .rows_affected();
    if n == 0 {
        return Err(Refusal::Conflict(format!("task {} is not waiting for an answer", task.id)));
    }
    post(state, task, "message", json!({"text": a, "task_id": task.id, "answer": true})).await;
    let fresh = crate::tasks::get(&state.db, &task.id).await.map_err(internal)?.ok_or_else(|| internal("task vanished"))?;
    let started = crate::tasks::start(state, &fresh).await.map_err(internal)?;
    Ok((fresh, started))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(limit: i64, spent: i64) -> AllowanceSpend {
        AllowanceSpend { period: "month".into(), limit, spent }
    }
    fn t(budget: Option<i64>, spent: i64) -> TaskSpend {
        TaskSpend { token_budget: budget, tokens_spent: spent }
    }

    /// PINNED: the switch's table.
    #[test]
    fn budget_verdict_table() {
        let cases: &[(TaskSpend, Option<AllowanceSpend>, bool)] = &[
            (t(None, 0), None, true),
            (t(None, 1_000_000), None, true),
            (t(Some(1000), 999), None, true),
            (t(Some(1000), 1000), None, false),
            (t(Some(1000), 1500), None, false),
            (t(None, 0), Some(a(500, 499)), true),
            (t(None, 0), Some(a(500, 500)), false),
            (t(Some(10_000), 10), Some(a(500, 900)), false),
            (t(Some(10), 20), Some(a(500, 0)), false),
            (t(None, 0), Some(a(0, 0)), false),
        ];
        for (task, allowance, proceed) in cases {
            let v = budget_verdict(*task, allowance.as_ref());
            assert_eq!(v == Verdict::Proceed, *proceed, "{task:?} {allowance:?} → {v:?}");
        }
    }

    /// The reason names the numbers, and the task cap is reported before
    /// the allowance (the owner can fix the first one).
    #[test]
    fn the_reason_carries_the_numbers_and_the_way_out() {
        let Verdict::Exhausted { reason } = budget_verdict(t(Some(1000), 1234), Some(&a(10, 99))) else { panic!() };
        assert!(reason.contains("1234 of its 1000 tokens") && reason.contains("resubmit"), "{reason}");
        let Verdict::Exhausted { reason } = budget_verdict(t(None, 5), Some(&AllowanceSpend { period: "week".into(), limit: 100, spent: 120 })) else { panic!() };
        assert!(reason.starts_with("weekly token allowance exhausted: 120 of 100 tokens used this week"), "{reason}");
    }

    #[test]
    fn remaining_is_never_negative_and_none_without_a_cap() {
        assert_eq!(remaining_task(t(None, 50)), None);
        assert_eq!(remaining_task(t(Some(100), 40)), Some(60));
        assert_eq!(remaining_task(t(Some(100), 140)), Some(0));
        assert_eq!(a(100, 140).remaining(), 0);
        assert_eq!(a(100, 30).remaining(), 70);
    }

    /// The accounting UPDATE is one atomic statement that adds and returns.
    #[test]
    fn accounting_adds_atomically_and_returns_the_total() {
        assert!(ADD_SPENT_SQL.contains("tokens_spent = tokens_spent + $2"));
        assert!(ADD_SPENT_SQL.contains("RETURNING tokens_spent"));
        assert_eq!(loop_tokens(120, 30), 150);
        assert_eq!(loop_tokens(0, 0), 0);
        assert_eq!(loop_tokens(u64::MAX, 1), i64::MAX);
        // The period spend counts prompt + completion of every row charged
        // to the person since the period began — node, cloud and harness.
        assert!(PERIOD_SPEND_SQL.contains("prompt_tokens::bigint + completion_tokens::bigint"));
        assert!(PERIOD_SPEND_SQL.contains("date_trunc($2, now())"));
        assert!(!PERIOD_SPEND_SQL.contains("backend"), "the allowance is one number across node and cloud");
    }

    fn task(state: &str, budget_state: Option<&str>, budget: Option<i64>, spent: i64) -> Task {
        Task {
            id: "t1".into(), objective: "o".into(), owner: Some("alice".into()), node: None, state: state.into(),
            conversation_id: "c".into(), thread_id: "thr".into(), channel: "task".into(), model: None, loops: 3,
            loop_budget: 20, last_checkpoint: None, last_note: None, result: None, error: None, created_at: String::new(),
            updated_at: String::new(), parent_id: None, role: None, budget_default: false, stale: false,
            token_budget: budget, tokens_spent: spent, budget_state: budget_state.map(str::to_string), remaining: None, created_via: None,
        }
    }

    /// PINNED: resubmit raises and resumes a parked task, only adjusts a
    /// running one, and refuses what it cannot help.
    #[test]
    fn resubmit_rules() {
        // Parked exhausted + a larger budget → resume.
        assert_eq!(resubmit_plan(&task("checkpointed", Some(EXHAUSTED), Some(100), 150), Some(1000), None), Ok(ResubmitPlan::Resume));
        // A budget still below the spend is refused, nothing changes.
        assert!(matches!(resubmit_plan(&task("checkpointed", Some(EXHAUSTED), Some(100), 150), Some(120), None), Err(Refusal::Conflict(m)) if m.contains("still exhausted")));
        // The allowance, not the task, is spent: raising the task cap does not help.
        assert!(matches!(resubmit_plan(&task("checkpointed", Some(EXHAUSTED), None, 10), Some(1000), Some(&a(100, 100))), Err(Refusal::Conflict(_))));
        // The allowance was raised since: a bare resubmit resumes.
        assert_eq!(resubmit_plan(&task("checkpointed", Some(EXHAUSTED), None, 10), None, Some(&a(1000, 100))), Ok(ResubmitPlan::Resume));
        // A running task: the cap is adjusted, nothing restarts.
        assert_eq!(resubmit_plan(&task("running", None, Some(100), 50), Some(500), None), Ok(ResubmitPlan::Adjust));
        assert!(matches!(resubmit_plan(&task("running", None, Some(100), 50), None, None), Err(Refusal::Invalid(_))));
        // Waiting for an answer: answer it instead.
        assert!(matches!(resubmit_plan(&task("checkpointed", Some(AWAITING_CLARIFICATION), None, 0), Some(5), None), Err(Refusal::Conflict(m)) if m.contains("answer")));
        // Finished tasks and bad budgets.
        assert!(matches!(resubmit_plan(&task("done", None, None, 0), Some(5), None), Err(Refusal::Conflict(_))));
        assert!(matches!(resubmit_plan(&task("checkpointed", Some(EXHAUSTED), None, 0), Some(0), None), Err(Refusal::Invalid(_))));
    }

    /// The first loop after an answer carries the question AND the answer.
    #[test]
    fn the_answer_loop_carries_question_and_answer() {
        let c = Clarification { question: "Which region, eu or us?".into(), answer: Some("eu".into()) };
        let p = clarification_prompt("migrate the bucket", &c, 4, 20);
        assert!(p.contains("migrate the bucket") && p.contains("Which region, eu or us?") && p.contains("The owner answered:\n\neu"));
        assert!(p.contains("loop 4 of 20") && p.contains("noo_task_done"));
        let wire: Clarification = serde_json::from_value(serde_json::json!({"question": "q"})).unwrap();
        assert_eq!(wire.answer, None);
    }

    /// The check's reply reads with fields missing (an older gateway's
    /// reply, or the rail's extra `ok`).
    #[test]
    fn the_check_reply_reads_tolerantly() {
        let c: BudgetCheck = serde_json::from_value(serde_json::json!({"ok": true, "proceed": true, "state": "checkpointed"})).unwrap();
        assert!(c.proceed && c.reason.is_none() && c.clarification.is_none());
        assert_eq!(c.state, "checkpointed");
    }

    #[test]
    fn questions_and_answers_are_bounded() {
        assert!(matches!(clean("  ", "question"), Err(Refusal::Invalid(_))));
        assert!(matches!(clean(&"x".repeat(MAX_TEXT + 1), "answer"), Err(Refusal::Invalid(_))));
        assert_eq!(clean(" why? ", "question").unwrap(), "why?");
    }

    /// A parked state is set only at the boundary: `ask` writes the
    /// question, never `budget_state`; only `check` (via `park`) does.
    #[test]
    fn only_the_boundary_parks_a_task() {
        let src = include_str!("task_budget.rs");
        let ask_body = &src[src.find("pub async fn ask(").unwrap()..src.find("pub async fn answer(").unwrap()];
        assert!(!ask_body.contains("budget_state = $"), "ask must not park the task mid-turn");
        assert!(!ask_body.contains("park("), "ask must not park the task mid-turn");
        let check_body = &src[src.find("pub async fn check(").unwrap()..src.find("pub enum Refusal").unwrap()];
        assert_eq!(check_body.matches("park(db, task_id, ").count(), 2, "check parks for a question and for a spent budget");
    }
}
