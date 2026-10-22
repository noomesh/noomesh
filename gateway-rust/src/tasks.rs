// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Tasks: an objective a harness owns across many
//! loops.
//!
//! A task is created for a person, gets its own conversation (the loops
//! accumulate there) and its own agent-message thread (notes and the
//! result post there), and is handed to the harness on the node that
//! holds its model — or run in this process when no harness answers.
//! The runner ([`run_task_loops`]) is generic over the runtime, so the
//! gateway and a node-hosted harness run the same loops.
//!
//! Between loops the runner CHECKPOINTS: it records the loop count and a
//! note, reads the task's state back (the model may have called
//! `noo_task_done`, the operator may have stopped it), and — on a node —
//! receives a renewed credential for the person (decision 1 of the
//! proposal: a task acts as the person, never as a service).
//!
//! State machine: `open → running ⇄ checkpointed → done | failed | stopped`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::coordinator::TaskRuntime;
use crate::state::AppState;

pub const STATES: &[&str] = &["open", "running", "checkpointed", "done", "failed", "stopped"];

/// Loops per task when neither the request nor the node says otherwise.
pub const DEFAULT_LOOP_BUDGET: u32 = 20;

/// The cluster's default loop budget: `NOO_TASK_LOOP_BUDGET` (a
/// `noo_settings` override or the env), else [`DEFAULT_LOOP_BUDGET`].
pub fn cluster_loop_budget() -> u32 {
    crate::settings::get("NOO_TASK_LOOP_BUDGET")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|b| (1..=500).contains(b))
        .unwrap_or(DEFAULT_LOOP_BUDGET)
}

/// A node's default loop budget, from its config row, if set.
pub async fn node_loop_budget(db: &sqlx::PgPool, node: &str) -> Option<u32> {
    sqlx::query_scalar::<_, Option<i32>>("SELECT default_loop_budget FROM noo_node_config WHERE node_id = $1")
        .bind(node)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
        .filter(|b| *b > 0)
        .map(|b| b as u32)
}

/// The subject a node's harness takes tasks on.
pub fn task_subject(node: &str) -> String {
    format!("harness.task.{}", node.replace(['.', '*', '>', ' '], "_"))
}

/// The subject a harness announces itself on when it starts, so the
/// gateway can hand back the node's checkpointed tasks.
pub fn ready_subject(node: &str) -> String {
    format!("harness.ready.{}", node.replace(['.', '*', '>', ' '], "_"))
}

/// A task, as the API returns it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub id: String,
    pub objective: String,
    pub owner: Option<String>,
    pub node: Option<String>,
    pub state: String,
    pub conversation_id: String,
    pub thread_id: String,
    pub channel: String,
    pub model: Option<String>,
    pub loops: u32,
    pub loop_budget: u32,
    pub last_checkpoint: Option<String>,
    pub last_note: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// The task that delegated this one, or fanned it out (phase 3).
    #[serde(default)]
    pub parent_id: Option<String>,
    /// The role its loops run under (`agent_roles::AgentRole`), if any.
    #[serde(default)]
    pub role: Option<String>,
    /// The budget was not given: the node's default applies where the
    /// task lands.
    #[serde(default)]
    pub budget_default: bool,
    /// Computed on read: a live task whose last checkpoint (or start) is
    /// older than [`stale_after`] — its runner has probably died. Never
    /// re-run on its own (its tools may have executed); surfaced so the
    /// operator decides.
    #[serde(default)]
    pub stale: bool,
    /// The task's own token cap (i83 G); `None` = no cap.
    #[serde(default)]
    pub token_budget: Option<i64>,
    /// Prompt + completion tokens its loops have spent, native and harness.
    #[serde(default)]
    pub tokens_spent: i64,
    /// `exhausted` | `awaiting_clarification` when the loop-boundary switch
    /// has parked it (`task_budget`); `None` otherwise.
    #[serde(default)]
    pub budget_state: Option<String>,
    /// Computed on read: tokens left under `token_budget`; `None` = no cap.
    #[serde(default)]
    pub remaining: Option<i64>,
    /// Who started it on the person's behalf: `addon:<name>` for a task an
    /// add-on created with a delegated token (i143); `None` = created directly.
    #[serde(default)]
    pub created_via: Option<String>,
}

impl Task {
    /// A parent with no loop budget of its own: it exists to hold its
    /// children and finishes when they do.
    pub fn is_aggregation(&self) -> bool {
        self.loop_budget == 0
    }
}

/// A task as handed to a runner (a node's harness, or this process).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskRequest {
    pub task_id: String,
    pub objective: String,
    pub conversation_id: String,
    pub thread_id: String,
    pub channel: String,
    pub user: String,
    #[serde(default)]
    pub model: Option<String>,
    pub loops_done: u32,
    pub loop_budget: u32,
    pub max_iterations: u32,
    /// The person's harness token, pinned to the task's conversation.
    pub token: String,
    /// The role's system prompt, for a delegated or fanned-out child.
    #[serde(default)]
    pub role_prompt: Option<String>,
}

fn row_to_task(r: &sqlx::postgres::PgRow) -> Task {
    let ts = |k: &str| r.try_get::<chrono::DateTime<chrono::Utc>, _>(k).ok().map(|t| t.to_rfc3339());
    Task {
        id: r.try_get::<uuid::Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
        objective: r.try_get("objective").unwrap_or_default(),
        owner: r.try_get("owner").ok().flatten(),
        node: r.try_get("node").ok().flatten(),
        state: r.try_get("state").unwrap_or_default(),
        conversation_id: r.try_get::<uuid::Uuid, _>("conversation_id").map(|u| u.to_string()).unwrap_or_default(),
        thread_id: r.try_get("thread_id").unwrap_or_default(),
        channel: r.try_get("channel").unwrap_or_default(),
        model: r.try_get("model").ok().flatten(),
        loops: r.try_get::<i32, _>("loops").unwrap_or(0).max(0) as u32,
        loop_budget: r.try_get::<i32, _>("loop_budget").unwrap_or(0).max(0) as u32,
        last_checkpoint: ts("last_checkpoint"),
        last_note: r.try_get("last_note").ok().flatten(),
        result: r.try_get("result").ok().flatten(),
        error: r.try_get("error").ok().flatten(),
        created_at: ts("created_at").unwrap_or_default(),
        updated_at: ts("updated_at").unwrap_or_default(),
        parent_id: r.try_get::<Option<uuid::Uuid>, _>("parent_id").ok().flatten().map(|u| u.to_string()),
        role: r.try_get("role").ok().flatten(),
        budget_default: r.try_get("budget_default").unwrap_or(false),
        token_budget: r.try_get::<Option<i64>, _>("token_budget").ok().flatten(),
        tokens_spent: r.try_get::<i64, _>("tokens_spent").unwrap_or(0),
        budget_state: r.try_get::<Option<String>, _>("budget_state").ok().flatten(),
        created_via: r.try_get::<Option<String>, _>("created_via").ok().flatten(),
        remaining: crate::task_budget::remaining_task(crate::task_budget::TaskSpend {
            token_budget: r.try_get::<Option<i64>, _>("token_budget").ok().flatten(),
            tokens_spent: r.try_get::<i64, _>("tokens_spent").unwrap_or(0),
        }),
        stale: {
            let state: String = r.try_get("state").unwrap_or_default();
            let last: Option<chrono::DateTime<chrono::Utc>> = r
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_checkpoint")
                .ok()
                .flatten()
                .or_else(|| r.try_get("updated_at").ok());
            let budget: i32 = r.try_get("loop_budget").unwrap_or(0);
            // A parked task (out of budget, or waiting for its owner) is
            // quiet on purpose: its runner stopped at the boundary.
            let parked = r.try_get::<Option<String>, _>("budget_state").ok().flatten().is_some();
            is_stale(&state, last, budget > 0 && !parked, chrono::Utc::now())
        },
    }
}

/// How long a live task may go without a checkpoint before it is
/// reported stale: twice the loop deadline, so one slow loop is not an
/// alarm. `NOO_TASK_STALE_SECS` overrides.
pub fn stale_after() -> chrono::Duration {
    let secs = std::env::var("NOO_TASK_STALE_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or_else(|| (crate::coordinator::turn_deadline().as_secs() as i64) * 2);
    chrono::Duration::seconds(secs)
}

/// The staleness rule, pure: a task that loops (`loops_itself`), is
/// live, and has not checkpointed within [`stale_after`]. An aggregation
/// parent never loops, so it is never stale by itself.
pub fn is_stale(state: &str, last: Option<chrono::DateTime<chrono::Utc>>, loops_itself: bool, now: chrono::DateTime<chrono::Utc>) -> bool {
    if !loops_itself || !matches!(state, "running" | "checkpointed") {
        return false;
    }
    match last {
        Some(t) => now - t > stale_after(),
        None => false,
    }
}

const SELECT: &str = "SELECT t.id, t.objective, u.username AS owner, t.node, t.state, t.conversation_id, t.thread_id, \
    t.channel, t.model, t.loops, t.loop_budget, t.last_checkpoint, t.last_note, t.result, t.error, t.created_at, t.updated_at, \
    t.parent_id, t.role, t.budget_default, t.token_budget, t.tokens_spent, t.budget_state, t.created_via \
    FROM noo_tasks t LEFT JOIN noo_users u ON u.user_uuid = t.owner_uuid";

/// How a task is created: who for, under which parent, in which thread.
#[derive(Debug, Clone, Default)]
pub struct NewTask<'a> {
    pub owner: Option<&'a str>,
    pub objective: &'a str,
    pub model: Option<&'a str>,
    /// `None` = the default (the node's where it lands, else the cluster's);
    /// `Some(0)` = an aggregation-only parent (phase 3); else 1..=500.
    pub loop_budget: Option<u32>,
    pub parent: Option<&'a Task>,
    pub role: Option<&'a str>,
    /// The task's token cap (i83 G); `None` = no cap.
    pub token_budget: Option<i64>,
    /// `addon:<name>` when an add-on creates it through a delegated token.
    pub created_via: Option<&'a str>,
}

/// The most children one task may fan out or delegate, and how deep a
/// delegation chain may go (a child of a child may not delegate).
pub const MAX_CHILDREN: i64 = 8;
pub const MAX_DEPTH: u32 = 2;

/// The role's system prompt, for a child that runs as one.
pub fn role_prompt_for(role: Option<&str>) -> Option<String> {
    role.and_then(crate::agent_roles::AgentRole::parse).map(|r| r.system_prompt().to_string())
}

pub async fn create_task(db: &sqlx::PgPool, new: NewTask<'_>) -> Result<Task> {
    let id = uuid::Uuid::new_v4();
    let conversation = uuid::Uuid::new_v4();
    // A child loops in its own conversation but posts to its PARENT's
    // thread, so a collaboration reads as one conversation.
    let thread = match new.parent {
        Some(p) => p.thread_id.clone(),
        None => crate::agent_messages::new_id("thr"),
    };
    if let Some(r) = new.role {
        if crate::agent_roles::AgentRole::parse(r).is_none() {
            return Err(anyhow!("unknown role {r:?}; known: {:?}", crate::agent_roles::AgentRole::known_names()));
        }
    }
    let (budget, budget_default) = match new.loop_budget {
        None => (cluster_loop_budget(), true),
        Some(0) => (0, false),
        Some(b) => (b.clamp(1, 500), false),
    };
    let parent_uuid = new.parent.and_then(|p| uuid::Uuid::parse_str(&p.id).ok());
    let channel = new.parent.map(|p| p.channel.as_str()).unwrap_or("task");
    sqlx::query(
        "INSERT INTO noo_tasks (id, objective, owner_uuid, state, conversation_id, thread_id, channel, model, loop_budget, parent_id, role, budget_default, token_budget, created_via) \
         VALUES ($1, $2, (SELECT user_uuid FROM noo_users WHERE username = $3), 'open', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(id)
    .bind(new.objective)
    .bind(new.owner)
    .bind(conversation)
    .bind(&thread)
    .bind(channel)
    .bind(new.model)
    .bind(budget as i32)
    .bind(parent_uuid)
    .bind(new.role)
    .bind(budget_default)
    .bind(new.token_budget.filter(|b| *b > 0))
    .bind(new.created_via)
    .execute(db)
    .await?;
    // i143 D: the first event of an add-on's task (a no-op for any other).
    crate::task_events::emit_state(db, &id.to_string(), "open", None).await;
    get(db, &id.to_string()).await?.ok_or_else(|| anyhow!("task vanished after insert"))
}

/// Apply the node's default budget to a task that had none, now that the
/// node is known. Returns the budget in force.
pub async fn apply_node_budget(db: &sqlx::PgPool, task: &Task, node: &str) -> Result<u32> {
    if !task.budget_default {
        return Ok(task.loop_budget);
    }
    let Some(b) = node_loop_budget(db, node).await else { return Ok(task.loop_budget) };
    let uuid = uuid::Uuid::parse_str(&task.id)?;
    sqlx::query("UPDATE noo_tasks SET loop_budget = $2, updated_at = now() WHERE id = $1 AND budget_default")
        .bind(uuid)
        .bind(b as i32)
        .execute(db)
        .await?;
    Ok(b)
}

/// The children of a task, oldest first.
pub async fn children(db: &sqlx::PgPool, parent_id: &str) -> Result<Vec<Task>> {
    let Ok(uuid) = uuid::Uuid::parse_str(parent_id) else { return Ok(Vec::new()) };
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE t.parent_id = $1 ORDER BY t.created_at")))
        .bind(uuid)
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_task).collect())
}

/// How deep a task sits: 0 for a root, 1 for its child, and so on.
pub async fn depth(db: &sqlx::PgPool, task: &Task) -> Result<u32> {
    let mut d = 0;
    let mut cur = task.parent_id.clone();
    while let Some(pid) = cur {
        d += 1;
        if d > MAX_DEPTH + 1 {
            break;
        }
        cur = get(db, &pid).await?.and_then(|p| p.parent_id);
    }
    Ok(d)
}

/// Whether a set of children has settled, and into what: `None` while
/// any is still live; otherwise done with their results joined, or
/// failed naming the ones that failed.
pub fn aggregate(children: &[Task]) -> Option<(bool, String)> {
    if children.iter().any(|c| matches!(c.state.as_str(), "open" | "running" | "checkpointed")) {
        return None;
    }
    let failed: Vec<&Task> = children.iter().filter(|c| c.state != "done").collect();
    if failed.is_empty() {
        let text = children
            .iter()
            .map(|c| format!("[{}] {}", c.role.as_deref().unwrap_or("task"), c.result.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n\n");
        Some((true, text))
    } else {
        let text = failed
            .iter()
            .map(|c| format!("[{}] {}: {}", c.role.as_deref().unwrap_or("task"), c.state, c.error.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        Some((false, text))
    }
}

/// An aggregation-only parent finishes when its children have settled.
/// A looping parent is left to its own `noo_task_done`.
pub async fn settle_parent(db: &sqlx::PgPool, child: &Task) -> Result<()> {
    let Some(pid) = child.parent_id.as_deref() else { return Ok(()) };
    let Some(parent) = get(db, pid).await? else { return Ok(()) };
    if !parent.is_aggregation() || !matches!(parent.state.as_str(), "open" | "running" | "checkpointed") {
        return Ok(());
    }
    if let Some((ok, text)) = aggregate(&children(db, pid).await?) {
        // A settled aggregation may itself be someone's child: one more
        // level, no recursion — depth is capped at two anyway.
        if finish_row(db, pid, ok, &text).await? {
            if let Some(grand) = parent.parent_id.as_deref() {
                if let Some(gp) = get(db, grand).await? {
                    if gp.is_aggregation() {
                        if let Some((ok2, text2)) = aggregate(&children(db, grand).await?) {
                            finish_row(db, grand, ok2, &text2).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn create(db: &sqlx::PgPool, owner: &str, objective: &str, model: Option<&str>, loop_budget: Option<u32>, token_budget: Option<i64>, created_via: Option<&str>) -> Result<Task> {
    create_task(db, NewTask { owner: Some(owner), objective, model, loop_budget: loop_budget.map(|b| b.max(1)), parent: None, role: None, token_budget, created_via }).await
}

pub async fn get(db: &sqlx::PgPool, id: &str) -> Result<Option<Task>> {
    let Ok(uuid) = uuid::Uuid::parse_str(id) else { return Ok(None) };
    let row = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE t.id = $1"))).bind(uuid).fetch_optional(db).await?;
    Ok(row.as_ref().map(row_to_task))
}

pub async fn list(db: &sqlx::PgPool, owner: Option<&str>, state: Option<&str>, limit: i64) -> Result<Vec<Task>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE ($1::text IS NULL OR u.username = $1) AND ($2::text IS NULL OR t.state = $2) \
         AND t.parent_id IS NULL ORDER BY t.created_at DESC LIMIT $3"
    )))
    .bind(owner)
    .bind(state)
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(row_to_task).collect())
}

/// `owner`'s tasks that were created `via` (`addon:<name>`), newest first.
/// What an add-on's delegated token lists: never another account's, never a
/// directly created task.
pub async fn list_via(db: &sqlx::PgPool, owner: &str, via: &str, state: Option<&str>, limit: i64) -> Result<Vec<Task>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE u.username = $1 AND t.created_via = $2 AND ($3::text IS NULL OR t.state = $3) \
         AND t.parent_id IS NULL ORDER BY t.created_at DESC LIMIT $4"
    )))
    .bind(owner)
    .bind(via)
    .bind(state)
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(row_to_task).collect())
}

/// Stop every unfinished task of `owner` that was created `via`: "revoke this
/// add-on's background work". Each goes through [`stop_with`], the single stop
/// path (it records the `revoked` event), so it is honoured at the task's next
/// checkpoint like any stop. Returns the ids it stopped.
pub async fn stop_via(db: &sqlx::PgPool, owner: &str, via: &str) -> Result<Vec<String>> {
    let live: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM noo_tasks \
         WHERE owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = $1) AND created_via = $2 \
         AND state IN ('open','running','checkpointed')",
    )
    .bind(owner)
    .bind(via)
    .fetch_all(db)
    .await?;
    let mut stopped = Vec::new();
    for id in live {
        let id = id.to_string();
        if stop_with(db, &id, "background_revoked").await? {
            stopped.push(id);
        }
    }
    Ok(stopped)
}

/// How long an `Idempotency-Key` is remembered.
pub const IDEMPOTENCY_HOURS: i32 = 24;

/// The task a recent create with this key made, if any. `via` is the empty
/// string for a direct create, `addon:<name>` for a delegated one, so a key
/// never crosses from one to the other.
pub async fn idempotent_task(db: &sqlx::PgPool, owner: &str, via: &str, key: &str) -> Result<Option<String>> {
    let id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT i.task_id FROM noo_task_idempotency i JOIN noo_tasks t ON t.id = i.task_id \
         WHERE i.owner = $1 AND i.via = $2 AND i.key = $3 AND i.created_at > now() - make_interval(hours => $4)",
    )
    .bind(owner)
    .bind(via)
    .bind(key)
    .bind(IDEMPOTENCY_HOURS)
    .fetch_optional(db)
    .await?;
    Ok(id.map(|u| u.to_string()))
}

/// Record that `task_id` is the answer to `(owner, via, key)` and return the
/// task id that now owns the key. Race-safe: of two concurrent creates with
/// one key exactly one wins and both get its id; an expired or orphaned entry
/// is taken over. A caller that gets back an id other than its own has lost.
pub async fn claim_idempotency(db: &sqlx::PgPool, owner: &str, via: &str, key: &str, task_id: &str) -> Result<String> {
    let mine = uuid::Uuid::parse_str(task_id)?;
    let won: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO noo_task_idempotency (owner, via, key, task_id) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (owner, via, key) DO UPDATE SET task_id = EXCLUDED.task_id, created_at = now() \
         WHERE noo_task_idempotency.created_at <= now() - make_interval(hours => $5) \
            OR NOT EXISTS (SELECT 1 FROM noo_tasks WHERE id = noo_task_idempotency.task_id) \
         RETURNING task_id",
    )
    .bind(owner)
    .bind(via)
    .bind(key)
    .bind(mine)
    .bind(IDEMPOTENCY_HOURS)
    .fetch_optional(db)
    .await?;
    if let Some(id) = won {
        return Ok(id.to_string());
    }
    // Lost: the live entry's task is the answer.
    idempotent_task(db, owner, via, key).await?.ok_or_else(|| anyhow!("idempotency entry vanished"))
}

/// Remove a task that lost an idempotency race before it was ever started.
pub async fn discard_unstarted(db: &sqlx::PgPool, id: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(id)?;
    sqlx::query("DELETE FROM noo_tasks WHERE id = $1 AND state = 'open'").bind(uuid).execute(db).await?;
    Ok(())
}

/// The running task of a conversation, for the person — what
/// `noo_task_done` acts on.
pub async fn for_conversation(db: &sqlx::PgPool, conversation_id: &str, owner: &str) -> Result<Option<Task>> {
    let Ok(conv) = uuid::Uuid::parse_str(conversation_id) else { return Ok(None) };
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE t.conversation_id = $1 AND u.username = $2 AND t.state IN ('open','running','checkpointed') \
         ORDER BY t.created_at DESC LIMIT 1"
    )))
    .bind(conv)
    .bind(owner)
    .fetch_optional(db)
    .await?;
    Ok(row.as_ref().map(row_to_task))
}

async fn set_state(db: &sqlx::PgPool, id: &str, state: &str, node: Option<&str>) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(id)?;
    sqlx::query("UPDATE noo_tasks SET state = $2, node = COALESCE($3, node), updated_at = now() WHERE id = $1")
        .bind(uuid)
        .bind(state)
        .bind(node)
        .execute(db)
        .await?;
    Ok(())
}

/// Finish a task: the model said so (`noo_task_done`), or the budget ran
/// out, or the runner gave up. Only an unfinished task can finish. Then
/// settle its parent, if it has one and the parent only aggregates.
///
/// A claim of SUCCESS (`ok`) passes the evidence gate first — see
/// [`evidence_verdict`]. A refusal comes back as an `Err` whose message is
/// what the model reads as the tool result ("could not finish task: …");
/// the task stays unfinished. Failure is never gated: owning up needs no proof.
///
/// `require_tool_use` says whether that gate applies. The loop's own
/// `noo_task_done` passes `true`: its tool calls are recorded in the task's
/// conversation, so "called nothing" is a fact. The user door's passes
/// `false`: its caller is an external agent whose tool use happens outside
/// that conversation, so the gate would have nothing to look at
/// (`mcp_user_tasks`).
pub async fn finish(db: &sqlx::PgPool, id: &str, ok: bool, text: &str, require_tool_use: bool) -> Result<bool> {
    let mut text = text.to_string();
    if ok && require_tool_use {
        if let Some(task) = get(db, id).await? {
            if matches!(task.state.as_str(), "open" | "running" | "checkpointed") {
                let looked = tools_used(db, &task.conversation_id).await;
                match evidence_verdict(looked, refused_before(id)) {
                    Evidence::Refuse => {
                        note_refusal(id);
                        return Err(anyhow!(
                            "refused: this task has not called a single tool, so nothing in the result can have come \
                             from looking at anything. Use a tool to find out, then call noo_task_done again. If the \
                             objective truly needs no tools, call noo_task_done again and say so in the result."
                        ));
                    }
                    Evidence::DoneWithoutTools => text = format!("{NO_TOOLS_MARK} {text}"),
                    Evidence::Done => {}
                }
            }
        }
    }
    let changed = finish_row(db, id, ok, &text).await?;
    if changed {
        if let Some(t) = get(db, id).await? {
            if let Err(e) = settle_parent(db, &t).await {
                tracing::warn!(task = id, error = %e, "task: parent not settled");
            }
        }
    }
    Ok(changed)
}

/// Prefix on a result the model gave having called no tool at all (its
/// second attempt after a refusal). A reader — a person, or a parent
/// task — can see the answer was written, not looked up.
pub const NO_TOOLS_MARK: &str = "[completed without calling any tool]";

/// Tools that are not looking at anything: the loop's own bookkeeping.
pub(crate) const BOOKKEEPING_TOOLS: &[&str] = &["noo_task_done", "noo_task_ask", "noo_agent_message"];

/// What the evidence gate says about a success claim.
#[derive(Debug, PartialEq, Eq)]
pub enum Evidence {
    /// The task called at least one tool.
    Done,
    /// No tool, first attempt: refuse once.
    Refuse,
    /// No tool, and it was already refused once: honoured, and marked.
    DoneWithoutTools,
}

/// `tools_used` — non-bookkeeping tool calls the task's conversation has
/// made across all its loops; `refused` — whether this task was already
/// refused once. A task that genuinely needs no tools ("write a limerick")
/// still finishes, one call late.
pub fn evidence_verdict(tools_used: i64, refused: bool) -> Evidence {
    match (tools_used > 0, refused) {
        (true, _) => Evidence::Done,
        (false, false) => Evidence::Refuse,
        (false, true) => Evidence::DoneWithoutTools,
    }
}

/// Tasks refused once, in this process. In memory on purpose: it must not
/// depend on the tool-call record having been written (it is
/// fire-and-forget), or a lost row would refuse a task forever. A restart
/// forgets it, costing one more refusal and nothing else.
static REFUSED: std::sync::Mutex<Option<std::collections::HashSet<String>>> = std::sync::Mutex::new(None);

fn refused_before(id: &str) -> bool {
    REFUSED.lock().map(|g| g.as_ref().is_some_and(|s| s.contains(id))).unwrap_or(true)
}

fn note_refusal(id: &str) {
    if let Ok(mut g) = REFUSED.lock() {
        g.get_or_insert_with(Default::default).insert(id.to_string());
    }
}

/// The tools a task's conversation has actually called: how many calls and
/// which tools. The one place this is computed: the evidence gate, the
/// result envelope and `GET /api/tasks/{id}` all read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolsCalled {
    /// Non-bookkeeping calls, across all the task's loops.
    pub count: i64,
    /// Distinct tool names, most-called first.
    pub names: Vec<String>,
}

/// Fold per-tool counts (any order) into a [`ToolsCalled`].
pub fn fold_tools(rows: Vec<(String, i64)>) -> ToolsCalled {
    let mut rows: Vec<(String, i64)> = rows.into_iter().filter(|(n, _)| !BOOKKEEPING_TOOLS.contains(&n.as_str())).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ToolsCalled { count: rows.iter().map(|r| r.1).sum(), names: rows.into_iter().map(|r| r.0).collect() }
}

impl ToolsCalled {
    /// The result envelope's `refs`: `tool:<name>` per distinct tool, so a
    /// reader (or a parent task) sees what the answer stood on. Capped to
    /// what an envelope accepts; an empty list IS the "zero tools" evidence.
    pub fn refs(&self) -> Vec<String> {
        self.names
            .iter()
            .map(|n| format!("tool:{n}"))
            .filter(|r| r.len() <= crate::agent_messages::MAX_ID_LEN)
            .take(crate::agent_messages::MAX_REFS)
            .collect()
    }
}

/// Which tools the task's conversation has called. `None` when the record
/// could not be read: the caller must not present that as "zero tools".
pub async fn tools_called(db: &sqlx::PgPool, conversation_id: &str) -> Option<ToolsCalled> {
    let conv = uuid::Uuid::parse_str(conversation_id).ok()?;
    let bookkeeping: Vec<String> = BOOKKEEPING_TOOLS.iter().map(|s| s.to_string()).collect();
    match sqlx::query_as::<_, (String, i64)>(
        "SELECT tool_name, count(*) FROM noo_tool_executions WHERE conversation_id = $1 AND NOT (tool_name = ANY($2)) GROUP BY tool_name",
    )
    .bind(conv)
    .bind(&bookkeeping)
    .fetch_all(db)
    .await
    {
        Ok(rows) => Some(fold_tools(rows)),
        Err(e) => {
            tracing::warn!(error = %e, "task: could not read tool calls");
            None
        }
    }
}

/// How many tools the task's conversation has actually called. A failed
/// lookup counts as none: the model is refused once and then honoured, so
/// a broken record can delay a finish by one call but never block it.
async fn tools_used(db: &sqlx::PgPool, conversation_id: &str) -> i64 {
    tools_called(db, conversation_id).await.map_or(0, |t| t.count)
}

/// The row update alone — no parent settlement, so `settle_parent` can
/// use it without the two calling each other forever.
async fn finish_row(db: &sqlx::PgPool, id: &str, ok: bool, text: &str) -> Result<bool> {
    let uuid = uuid::Uuid::parse_str(id)?;
    let (state, col) = if ok { ("done", "result") } else { ("failed", "error") };
    let n = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE noo_tasks SET state = $2, {col} = $3, updated_at = now() \
         WHERE id = $1 AND state IN ('open','running','checkpointed')"
    )))
    .bind(uuid)
    .bind(state)
    .bind(text)
    .execute(db)
    .await?
    .rows_affected();
    if n > 0 {
        // i143 D: `result` (the answer, or null on failure) then the final
        // `state`. Here, not in `finish`, so a parent settled by
        // `settle_parent` reports too.
        crate::task_events::emit_finished(db, id, ok, text).await;
    }
    Ok(n > 0)
}

/// The owner's stop: honoured at the next checkpoint.
pub async fn stop(db: &sqlx::PgPool, id: &str) -> Result<bool> {
    stop_with(db, id, "stopped_by_owner").await
}

/// Stop a live task, telling an add-on why (i143 D): a `revoked {reason}`
/// event, then the state change, then the final `state` event.
/// `reason` is `stopped_by_owner` | `background_revoked` | `account_disabled`.
/// Every stop path goes through here so the final `state` event always
/// follows the revoked one.
pub async fn stop_with(db: &sqlx::PgPool, id: &str, reason: &str) -> Result<bool> {
    let uuid = uuid::Uuid::parse_str(id)?;
    let live: Option<String> = sqlx::query_scalar("SELECT state FROM noo_tasks WHERE id = $1 AND state IN ('open','running','checkpointed')")
        .bind(uuid)
        .fetch_optional(db)
        .await?;
    if live.is_none() {
        return Ok(false);
    }
    crate::task_events::emit_revoked(db, id, reason).await;
    let n = sqlx::query("UPDATE noo_tasks SET state = 'stopped', updated_at = now() WHERE id = $1 AND state IN ('open','running','checkpointed')")
        .bind(uuid)
        .execute(db)
        .await?
        .rows_affected();
    if n > 0 {
        crate::task_events::emit_final_state(db, id, Some(reason)).await;
    }
    Ok(n > 0)
}

/// Record a checkpoint and return the task's state AFTER it — which is
/// where the runner learns that the model finished, the operator stopped
/// it, or it may go on. A note becomes a `note` message in the task's
/// thread from the person, so progress reads like a conversation.
pub async fn checkpoint(state: &AppState, id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String> {
    let Some(task) = get(&state.db, id).await? else { return Err(anyhow!("task {id} not found")) };
    if exhausted && matches!(task.state.as_str(), "open" | "running" | "checkpointed") {
        finish(&state.db, id, false, &format!("loop budget of {} exhausted", task.loop_budget), true).await?;
    }
    let uuid = uuid::Uuid::parse_str(id)?;
    sqlx::query(
        "UPDATE noo_tasks SET loops = $2, last_checkpoint = now(), last_note = COALESCE($3, last_note), \
         state = CASE WHEN state = 'running' THEN 'checkpointed' ELSE state END, updated_at = now() WHERE id = $1",
    )
    .bind(uuid)
    .bind(loops as i32)
    .bind(note)
    .execute(&state.db)
    .await?;
    if let (Some(n), Some(owner)) = (note.filter(|n| !n.trim().is_empty()), task.owner.as_deref()) {
        let env = crate::agent_messages::Envelope::new(owner, "thread", "note", json!({"text": n, "task_id": id, "loop": loops}), Some(&task.thread_id), vec![])
            .with_from(crate::agent_messages::Identity::new(Some(owner), task.node.as_deref(), Some(owner), Some("task")));
        if let Err(e) = crate::agent_messages::publish(&state.js, &env).await {
            tracing::warn!(error = %e, task = id, "task note not posted");
        }
    }
    let after = get(&state.db, id).await?.map(|t| t.state).unwrap_or_else(|| "failed".into());
    // i143 D: progress at each checkpoint with a note, and the state change
    // it caused. Nothing after a terminal state (the exhausted path above
    // already emitted its final one).
    if matches!(after.as_str(), "open" | "running" | "checkpointed") {
        if let Some(n) = note.filter(|n| !n.trim().is_empty()) {
            crate::task_events::emit_logged(&state.db, id, "progress", json!({"loop": loops, "note": n})).await;
        }
        if task.state == "running" && after == "checkpointed" {
            crate::task_events::emit_state(&state.db, id, "checkpointed", None).await;
        }
    }
    Ok(after)
}

/// Keep the task `open`, assigned to `node`, for the node's busy harness to
/// take when a slot frees (its `harness.ready` hand-back lists open tasks
/// on the node).
pub async fn mark_queued(db: &sqlx::PgPool, id: &str, node: &str) -> Result<()> {
    set_state(db, id, "open", Some(node)).await
}

/// Mark the task running on `node` (or in process when `None`) before a
/// runner takes it.
pub async fn mark_running(db: &sqlx::PgPool, id: &str, node: Option<&str>) -> Result<()> {
    let before = match uuid::Uuid::parse_str(id) {
        Ok(u) => sqlx::query_scalar::<_, String>("SELECT state FROM noo_tasks WHERE id = $1").bind(u).fetch_optional(db).await.ok().flatten(),
        Err(_) => None,
    };
    set_state(db, id, "running", node).await?;
    // i143 D: a state change, once (a resume of a running task is not one).
    if before.as_deref() != Some("running") {
        crate::task_events::emit_state(db, id, "running", None).await;
    }
    Ok(())
}

// ── the runner ──────────────────────────────────────────────────────────

/// The first loop's prompt: the objective and the contract.
pub fn objective_prompt(objective: &str, thread_id: &str, budget: u32) -> String {
    format!(
        "You are working on a TASK, not answering a question. Objective:\n\n{objective}\n\n\
         Work toward it with your tools, one concrete step at a time. You have up to {budget} loops; \
         this conversation carries what you did in earlier loops. Post progress notes with \
         noo_agent_message (kind \"note\", to \"thread\", thread_id \"{thread_id}\"). When the objective is fully \
         achieved, call noo_task_done with a short result. If it cannot be achieved, call noo_task_done \
         with failed=true and the reason. If you cannot go on without the owner deciding something, call \
         noo_task_ask with one clear question and end the loop: the task waits for the answer. Do not claim \
         completion without calling noo_task_done."
    )
}

/// Every later loop's prompt.
pub fn continuation_prompt(objective: &str, loop_no: u32, budget: u32) -> String {
    format!(
        "Continue the task (loop {loop_no} of {budget}). Objective:\n\n{objective}\n\n\
         Review what this conversation already did, take the next concrete step, and call noo_task_done \
         when the objective is achieved (or failed=true if it cannot be)."
    )
}

/// Whether a runner keeps looping after a checkpoint.
pub fn keep_looping(state_after: &str, loops: u32, budget: u32) -> bool {
    matches!(state_after, "running" | "checkpointed") && loops < budget
}

/// A few hundred characters of the loop's answer, for the checkpoint note.
pub fn excerpt(text: &str) -> String {
    let t = text.trim();
    let mut s: String = t.chars().take(400).collect();
    if t.chars().count() > 400 {
        s.push('…');
    }
    s
}

/// Run a task's loops on any runtime until it is done, failed, stopped or
/// out of budget. Each loop is one `run_inner` in the task's conversation;
/// each checkpoint reads the state back and, remotely, renews the token.
pub async fn run_task_loops<R: TaskRuntime>(mut rt: R, req: &TaskRequest) -> Result<String> {
    let mut loops = req.loops_done;
    let mut failures = 0u32;
    loop {
        if loops >= req.loop_budget {
            return rt.checkpoint(&req.task_id, loops, Some("loop budget exhausted"), true).await;
        }
        // THE TOKEN SWITCH (i83 G): before a loop starts, never inside one.
        // A loop that crossed the budget has finished and checkpointed; this
        // is where the task stops, parked, for its owner.
        let check = match rt.budget_check(&req.task_id).await {
            Ok(c) => c,
            Err(e) => {
                // No verdict, no loop: stop at the checkpoint (not failed), so
                // a restart of the runner picks the task up again.
                tracing::warn!(task = %req.task_id, error = %e, "task: budget check failed; stopping at the checkpoint");
                return rt.checkpoint(&req.task_id, loops, Some(&format!("budget check failed: {e}")), false).await;
            }
        };
        if !check.proceed {
            tracing::info!(task = %req.task_id, reason = check.reason.as_deref().unwrap_or(""), "task: budget switch says no more loops");
            return Ok(check.state);
        }
        let prompt = match &check.clarification {
            Some(c) => crate::task_budget::clarification_prompt(&req.objective, c, loops + 1, req.loop_budget),
            None if loops == 0 => objective_prompt(&req.objective, &req.thread_id, req.loop_budget),
            None => continuation_prompt(&req.objective, loops + 1, req.loop_budget),
        };
        // The owner's context since the last loop (i143 C), in front.
        let prompt = crate::task_budget::with_context(prompt, check.context.as_deref());
        let outcome = crate::coordinator::run_inner(
            &rt,
            &prompt,
            &req.conversation_id,
            &req.channel,
            req.max_iterations,
            req.model.as_deref(),
            (!req.user.is_empty()).then_some(req.user.as_str()),
            req.role_prompt.as_deref(),
            true,
        )
        .await;
        loops += 1;
        // The loop's tokens, against the task (and in the usage table with
        // its id and real backend) before the next boundary reads them.
        if let Ok(r) = &outcome {
            if let Err(e) = rt.loop_usage(&req.task_id, r).await {
                tracing::warn!(task = %req.task_id, error = %e, "task: loop usage not recorded");
            }
        }
        let note = match &outcome {
            Ok(r) => {
                failures = 0;
                excerpt(&r.response)
            }
            Err(e) => {
                failures += 1;
                format!("loop {loops} failed: {e}")
            }
        };
        let after = rt.checkpoint(&req.task_id, loops, Some(&note), false).await?;
        if failures >= 3 {
            return rt.checkpoint(&req.task_id, loops, Some("three consecutive loop failures; giving up"), true).await;
        }
        if !keep_looping(&after, loops, req.loop_budget) {
            return Ok(after);
        }
    }
}

// ── dispatch and resume (gateway side) ──────────────────────────────────

/// Where a task went, and — when it stayed here — why.
///
/// "It ran in process" used to be reported as the controller's container
/// id and nothing else: a twelve-hex string that reads as a node nobody
/// recognises, with no hint that dispatch was even considered. `why` is
/// the missing half.
#[derive(Debug, Clone)]
pub struct Started {
    pub node: String,
    pub dispatched: bool,
    /// The node's harness is busy: the task stays `open` on that node and
    /// is handed back when a slot frees (noomesh-internal i176). Never
    /// run on the controller for that.
    pub queued: bool,
    pub why: Option<String>,
}

impl Started {
    fn dispatched(node: String) -> Self {
        Self { node, dispatched: true, queued: false, why: None }
    }
    fn here(node: String, why: impl Into<String>) -> Self {
        Self { node, dispatched: false, queued: false, why: Some(why.into()) }
    }
    fn queued(node: String, why: impl Into<String>) -> Self {
        Self { node, dispatched: false, queued: true, why: Some(why.into()) }
    }
    /// Where it went, for callers that only need the name.
    pub fn node(&self) -> &str {
        &self.node
    }
}

/// Hand a task to the harness on the node that holds its model, or run
/// it in this process when no harness answers. Returns where it went,
/// and why, when it stayed.
pub async fn start(state: &std::sync::Arc<AppState>, task: &Task) -> Result<Started> {
    if task.is_aggregation() {
        // Nothing to run: it settles when its children do.
        mark_running(&state.db, &task.id, None).await?;
        return Ok(Started::here("(children)".into(), "an aggregation runs nowhere; it settles when its children do"));
    }
    // An unattended task (no person — an internal caller's collaboration)
    // runs in process only: a harness acts as someone.
    let owner = task.owner.as_deref().unwrap_or("");
    let max_iterations = state.config.coordinator.max_iterations;
    let role_prompt = role_prompt_for(task.role.as_deref());
    let target = if owner.is_empty() {
        Err("this task has no owner, and a harness acts as a person — so it runs here".to_string())
    } else {
        crate::coordinator::harness_node_explained(state, task.model.as_deref()).await
    };
    let mut why = match &target {
        Ok(_) => String::new(),
        Err(e) => e.clone(),
    };
    if let Ok(node) = target {
        if let Some(role) = crate::coordinator::role_of(state, owner).await {
            let ttl = crate::coordinator::turn_deadline().as_secs() + 60;
            if let Some(token) = crate::auth::mint_harness_jwt(owner, role, &node, &task.conversation_id, ttl) {
                let loop_budget = apply_node_budget(&state.db, task, &node).await.unwrap_or(task.loop_budget);
                let req = TaskRequest {
                    task_id: task.id.clone(),
                    objective: task.objective.clone(),
                    conversation_id: task.conversation_id.clone(),
                    thread_id: task.thread_id.clone(),
                    channel: task.channel.clone(),
                    user: owner.to_string(),
                    model: task.model.clone(),
                    loops_done: task.loops,
                    loop_budget,
                    max_iterations,
                    token,
                    role_prompt: role_prompt.clone(),
                };
                let ack = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    // Reply on the node's own prefix: survives a NATS reload (i70).
                    state.nats.send_request(task_subject(&node), crate::coordinator::node_request(&state.nats, &node, serde_json::to_vec(&req)?)),
                )
                .await;
                let mut answered = false;
                if let Ok(Ok(msg)) = ack {
                    answered = true;
                    let body: Value = serde_json::from_slice(&msg.payload).unwrap_or(Value::Null);
                    if body.get("ack").and_then(|a| a.as_bool()) == Some(true) {
                        if body.get("already").and_then(|a| a.as_bool()) == Some(true) {
                            tracing::info!(task = %task.id, node = %node, "task_already_on_node");
                        } else {
                            tracing::info!(task = %task.id, node = %node, "task_dispatched");
                        }
                        mark_running(&state.db, &task.id, Some(&node)).await?;
                        return Ok(Started::dispatched(node));
                    }
                    if body.get("busy").and_then(|b| b.as_bool()) == Some(true) {
                        // Busy is not dead: the task waits for THIS node's
                        // harness, which hands it back when a slot frees.
                        let running = body.get("running").and_then(Value::as_u64).unwrap_or(0);
                        let capacity = body.get("capacity").and_then(Value::as_u64).unwrap_or(0);
                        mark_queued(&state.db, &task.id, &node).await?;
                        tracing::info!(task = %task.id, node = %node, running, capacity, "task_queued_for_node");
                        return Ok(Started::queued(node.clone(), format!("node '{node}' has a harness and it is busy ({running} of {capacity} running); the task is queued for it")));
                    }
                }
                // No ack at all (or a refusal): the dead case. Running a
                // node-placed task on the controller is a fallback, said
                // so in the record and at warn in the log.
                why = if answered {
                    format!("node '{node}' has a harness and it refused the task; running in process (fallback)")
                } else {
                    format!("node '{node}' has a harness and it did not answer within 3s — check `noo cluster status` and the harness service on that node; running in process (fallback)")
                };
                tracing::warn!(task = %task.id, node = %node, answered, "task: harness did not take it; running in process (fallback)");
            } else {
                why = format!("no harness token could be minted for '{owner}' on node '{node}'");
            }
        } else {
            why = format!("'{owner}' has no role on this gateway, so no harness turn could be authorised");
        }
    }
    // In process: the controller's own harness.
    let here = crate::agent_messages::controller_node();
    mark_running(&state.db, &task.id, Some(&here)).await?;
    let loop_budget = apply_node_budget(&state.db, task, &here).await.unwrap_or(task.loop_budget);
    let req = TaskRequest {
        task_id: task.id.clone(),
        objective: task.objective.clone(),
        conversation_id: task.conversation_id.clone(),
        thread_id: task.thread_id.clone(),
        channel: task.channel.clone(),
        user: owner.to_string(),
        model: task.model.clone(),
        loops_done: task.loops,
        loop_budget,
        max_iterations,
        token: String::new(),
        role_prompt,
    };
    tokio::spawn(run_in_process(state.clone(), req));
    Ok(Started::here(here, why))
}

/// The in-process runner as a boxed, type-erased future. A loop's tool
/// call (`noo_task_delegate`) starts a runner whose loops make tool calls;
/// without the erasure the three futures are one opaque type that refers
/// to itself, and the compiler cannot decide whether it is `Send`.
fn run_in_process(st: std::sync::Arc<AppState>, req: TaskRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        use futures::FutureExt;
        // A panic inside a spawned runner would end the tokio task and
        // leave the record `running` forever with no notice
        // Catch it, and finish the task as failed so the person sees
        // it and a resume does not pick a poisoned task back up.
        let outcome = std::panic::AssertUnwindSafe(async {
            let rt = crate::coordinator::InProcessRuntime::new(&st);
            // The owner's REAL role and scopes. This runner is spawned, so
            // no request principal reaches it, and the no-principal fallback
            // is the read-only floor. A disabled or unresolvable owner (and a
            // task with no owner) runs on that floor, never wider.
            let principal = if req.user.is_empty() {
                None
            } else {
                crate::bus_principal::account_principal(&st.db, &req.user).await
            };
            match principal {
                Some(p) => crate::bus_principal::with_principal(p, run_task_loops(rt, &req)).await,
                None => run_task_loops(rt, &req).await,
            }
        })
        .catch_unwind()
        .await;
        match outcome {
            Ok(Ok(final_state)) => tracing::info!(task = %req.task_id, state = %final_state, "task_finished"),
            Ok(Err(e)) => {
                tracing::error!(task = %req.task_id, error = %e, "task_runner_failed");
                let _ = finish(&st.db, &req.task_id, false, &format!("runner failed: {e}"), true).await;
            }
            Err(panic) => {
                let what = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown panic".into());
                tracing::error!(task = %req.task_id, panic = %what, "task_runner_panicked");
                let _ = finish(&st.db, &req.task_id, false, &format!("runner panicked: {}", crate::text::clip(&what, 500)), true).await;
            }
        }
    })
}

/// Re-dispatch a node's unfinished tasks when its harness announces
/// itself, and take back this controller's own at boot. Tasks that were
/// `running` on a node whose harness never returns stay where they are
/// until the operator stops them — silently re-running them elsewhere
/// could double-execute their tools.
pub fn spawn_ready_watcher(state: std::sync::Arc<AppState>) {
    tokio::spawn(async move {
        use futures::StreamExt;
        // Boot: resume what THIS controller was running when it went down.
        let here = crate::agent_messages::controller_node();
        if let Ok(tasks) = list_unfinished_on(&state.db, &here).await {
            for t in tasks {
                tracing::info!(task = %t.id, "task: resuming in process after restart");
                if let Err(e) = start(&state, &t).await {
                    tracing::warn!(task = %t.id, error = %e, "task: resume failed");
                }
            }
        }
        let mut sub = match state.nats.subscribe("harness.ready.*".to_string()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "task: cannot watch harness.ready.*");
                return;
            }
        };
        while let Some(msg) = sub.next().await {
            let Some(node) = msg.subject.strip_prefix("harness.ready.") else { continue };
            let node = node.to_string();
            match list_unfinished_on(&state.db, &node).await {
                Ok(tasks) if !tasks.is_empty() => {
                    tracing::info!(node = %node, count = tasks.len(), "task: harness ready; handing back its tasks");
                    for t in tasks {
                        if let Err(e) = start(&state, &t).await {
                            tracing::warn!(task = %t.id, error = %e, "task: hand-back failed");
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "task: resume query failed"),
            }
        }
    });
}

/// Every live task that has gone quiet (see [`is_stale`]), oldest first.
pub async fn list_stale(db: &sqlx::PgPool) -> Result<Vec<Task>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE t.state IN ('running','checkpointed') AND t.loop_budget > 0 AND t.budget_state IS NULL ORDER BY t.updated_at")))
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_task).filter(|t| t.stale).collect())
}

/// The stale-task sweep: every few minutes, name the live
/// tasks whose runner has gone quiet — to the log and to the operator
/// alert funnel, once per task per cooldown. It never re-runs or fails
/// them: a task's loops may have executed tools, and only the operator
/// knows whether the node is coming back. `noo tasks list` shows the
/// same tasks flagged; `noo tasks stop <id>` is the operator's answer.
pub fn spawn_stale_sweep(state: std::sync::Arc<AppState>) {
    const INTERVAL_SECS: u64 = 300;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(INTERVAL_SECS)).await;
            crate::loop_health::record_tick("task_stale_sweep", INTERVAL_SECS);
            let stale = match list_stale(&state.db).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "task_stale_sweep: query failed");
                    continue;
                }
            };
            for t in stale {
                let since = t.last_checkpoint.clone().unwrap_or_else(|| t.updated_at.clone());
                tracing::warn!(task = %t.id, node = ?t.node, owner = ?t.owner, since = %since, "task_stale");
                crate::operator_alert::send_operator_alert_detached_with(
                    &state,
                    stale_alert(&t, &since),
                    3600,
                )
                .await;
            }
        }
    });
}

/// How to name the thing that was running a task, for an operator.
///
/// A node id is actionable. A CONTAINER id is not: it belonged to a gateway
/// that has since been recreated, so there is no harness anywhere that will
/// claim the task back, and telling someone to restart it wastes their time.
/// The container id itself is evidence for the log, not the channel.
fn describe_runner(node: Option<&str>) -> String {
    match node {
        None => "an unnamed runner".to_string(),
        Some(n) if crate::agent_messages::is_container_id(n) => {
            "a gateway container that no longer exists — nothing will resume this".to_string()
        }
        Some(n) => n.to_string(),
    }
}

/// A node's tasks to hand back. A PARKED task (`budget_state` set) is not
/// one: it waits for its owner's resubmit or answer, not for a harness.
async fn list_unfinished_on(db: &sqlx::PgPool, node: &str) -> Result<Vec<Task>> {
    // `open` with a node: queued for that node's busy harness (i176).
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE t.node = $1 AND t.state IN ('open','running','checkpointed') AND t.budget_state IS NULL ORDER BY t.created_at")))
        .bind(node)
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_task).collect())
}

/// The operator's page for a task nobody is running.
///
/// It opened with the UUID and named the node by whatever the record held,
/// so a morning's worth of pages read as six identical hex strings on a
/// container id ("Task e39546d9-… on 86c47f153ae0"), and the operator
/// asked what was actually running. What a page is FOR comes
/// first: the objective, then a short id to tell siblings apart; the full
/// id appears once, inside the command that shows it. What to do next
/// (stop it, or restart the harness), the runner's raw id and the loop
/// count are the log's.
pub fn stale_alert(t: &Task, since: &str) -> crate::operator_alert::OperatorAlert {
    let short: String = t.id.chars().take(8).collect();
    let resume = match t.node.as_deref() {
        // A container id here means the controller had no stable name when
        // it claimed the task, so no harness can be restarted to resume it
        // (#378).
        Some(n) if crate::agent_messages::is_container_id(n) => {
            "nothing will resume it; stop it, and set NODE_ID so the controller keeps its name"
        }
        _ => "restarting the node's harness resumes it",
    };
    crate::operator_alert::OperatorAlert::new(
        "task.stale",
        &t.id,
        format!(
            "⏳ Stale task: “{}” ({short}) on {} — {}, no checkpoint since {}.\n\
             Its runner has probably died. It is NOT re-run on its own — its loops may have executed tools.",
            excerpt(&t.objective),
            describe_runner(t.node.as_deref()),
            t.state,
            since,
        ),
    )
    .detail(format!(
        "runner {}; loop {} of {}; `noo tasks stop {}` ends it, {resume}",
        t.node.as_deref().unwrap_or("-"),
        t.loops,
        t.loop_budget,
        t.id,
    ))
    .investigate(format!("noo tasks show {}", t.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_called_counts_names_and_drops_bookkeeping() {
        let t = fold_tools(vec![
            ("noo_task_done".into(), 1),
            ("noo_rag_status".into(), 2),
            ("noo_agent_message".into(), 3),
            ("noo_graph_stats".into(), 5),
        ]);
        assert_eq!(t.count, 7);
        assert_eq!(t.names, vec!["noo_graph_stats", "noo_rag_status"]);
        assert_eq!(t.refs(), vec!["tool:noo_graph_stats", "tool:noo_rag_status"]);
    }

    #[test]
    fn a_task_that_called_nothing_has_empty_evidence_not_missing_evidence() {
        let t = fold_tools(vec![("noo_task_done".into(), 1)]);
        assert_eq!(t, ToolsCalled { count: 0, names: vec![] });
        assert!(t.refs().is_empty());
        assert_eq!(serde_json::to_value(&t).unwrap(), serde_json::json!({"count": 0, "names": []}));
    }

    #[test]
    fn evidence_refs_stay_within_what_an_envelope_accepts() {
        let t = ToolsCalled { count: 99, names: (0..40).map(|i| format!("t{i}")).chain(["x".repeat(200)]).collect() };
        let refs = t.refs();
        assert!(refs.len() <= crate::agent_messages::MAX_REFS);
        assert!(refs.iter().all(|r| r.len() <= crate::agent_messages::MAX_ID_LEN));
    }

    #[test]
    fn a_task_that_called_no_tool_is_refused_once_then_honoured_and_marked() {
        // The first live task finished on loop 1 with
        // invented numbers and no tool call behind them.
        assert_eq!(evidence_verdict(0, false), Evidence::Refuse);
        assert_eq!(evidence_verdict(0, true), Evidence::DoneWithoutTools);
        assert_eq!(evidence_verdict(3, false), Evidence::Done);
        assert_eq!(evidence_verdict(1, true), Evidence::Done);
    }

    #[test]
    fn a_refusal_is_remembered_per_task() {
        assert!(!refused_before("t-216-a"));
        note_refusal("t-216-a");
        assert!(refused_before("t-216-a"));
        assert!(!refused_before("t-216-b"));
    }

    #[test]
    fn a_stale_page_leads_with_the_objective_not_the_uuid() {
        let t = Task {
            id: "e39546d9-563e-4cc4-a5bc-e4466ea4ca9f".into(),
            objective: "Reply with the single word: ok".into(),
            owner: Some("owner".into()),
            node: Some("host3".into()),
            state: "checkpointed".into(),
            conversation_id: "c".into(),
            thread_id: "thr_1".into(),
            channel: "task".into(),
            model: None,
            loops: 1,
            loop_budget: 1,
            last_checkpoint: None,
            last_note: None,
            result: None,
            error: None,
            created_at: "t0".into(),
            updated_at: "t1".into(),
            parent_id: None,
            role: None,
            budget_default: false,
            stale: true,
            token_budget: None,
            tokens_spent: 0,
            budget_state: None,
            remaining: None,
            created_via: None,
        };
        let alert = stale_alert(&t, "2026-09-22T00:20:26Z");
        let text = crate::egress::system(&alert, "ref-0").into_string();
        let obj = text.find("Reply with the single word: ok").expect("objective present");
        let uuid = text.find("e39546d9-563e").expect("full id present, in the command");
        assert!(obj < uuid, "the objective must come before the uuid: {text}");
        assert!(text.contains("(e39546d9)"), "{text}");
        assert!(text.contains("on host3"), "{text}");
        assert!(text.contains("Next: `noo tasks show e39546d9-563e-4cc4-a5bc-e4466ea4ca9f`"), "{text}");
        assert_eq!(text.matches("e39546d9-563e").count(), 1, "the full id appears once: {text}");
        // How to end it is the log's, with the loop count.
        assert!(alert.detail.contains("noo tasks stop e39546d9-563e-4cc4-a5bc-e4466ea4ca9f"), "{}", alert.detail);
        assert!(alert.detail.contains("loop 1 of 1"), "{}", alert.detail);
    }

    #[test]
    fn subjects_and_prompts_are_shaped() {
        assert_eq!(task_subject("host8"), "harness.task.host8");
        assert_eq!(ready_subject("a.b"), "harness.ready.a_b");
        let p = objective_prompt("ship it", "thr_1", 5);
        assert!(p.contains("ship it") && p.contains("noo_task_done") && p.contains("thr_1") && p.contains("5 loops"));
        assert!(continuation_prompt("ship it", 3, 5).contains("loop 3 of 5"));
    }

    /// PINNED: a runner stops on any terminal state and on the budget,
    /// and continues only while the task is live.
    /// noomesh-internal i176: a busy harness keeps the task on its node;
    /// only no answer at all runs it on the controller, and says so.
    #[test]
    fn a_busy_node_queues_the_task_and_only_silence_falls_back() {
        let q = Started::queued("mcmini".into(), "busy");
        assert!(q.queued && !q.dispatched && q.node() == "mcmini");
        assert!(!Started::dispatched("mcmini".into()).queued && !Started::here("pop-os".into(), "x").queued);
        let src = include_str!("tasks.rs").split("fn a_busy_node_queues_the_task_and_only_silence_falls_back").next().unwrap();
        let start = src.split("pub async fn start(").nth(1).unwrap().split("\nfn run_in_process(").next().unwrap();
        let busy = start.find("get(\"busy\")").expect("the busy reply is read");
        let after = &start[busy..];
        let queued = after.find("mark_queued(").expect("a busy node queues the task");
        let returned = after.find("return Ok(Started::queued(").expect("and returns queued");
        let fallback = after.find("running in process (fallback)").expect("the fallback wording");
        assert!(queued < returned && returned < fallback, "queued is returned before any fallback path: {queued} {returned} {fallback}");
        assert!(start.contains("running in process (fallback)"), "the controller run is named a fallback");
        assert!(start.contains("tracing::warn!(task = %task.id, node = %node, answered"), "and logged at warn");
        let unfinished = &src[src.find("async fn list_unfinished_on").unwrap()..];
        assert!(unfinished[..500].contains("t.state IN ('open','running','checkpointed')"), "a queued (open) task is handed back");
    }

    #[test]
    fn keep_looping_rule() {
        assert!(keep_looping("checkpointed", 1, 5));
        assert!(keep_looping("running", 4, 5));
        assert!(!keep_looping("checkpointed", 5, 5));
        for s in ["done", "failed", "stopped", "open"] {
            assert!(!keep_looping(s, 1, 5), "{s}");
        }
    }

    fn t(state: &str, role: &str, result: Option<&str>, error: Option<&str>) -> Task {
        Task {
            id: "x".into(), objective: "o".into(), owner: None, node: None, state: state.into(), conversation_id: "c".into(),
            thread_id: "thr".into(), channel: "task".into(), model: None, loops: 0, loop_budget: 5, last_checkpoint: None,
            last_note: None, result: result.map(str::to_string), error: error.map(str::to_string), created_at: String::new(),
            updated_at: String::new(), parent_id: Some("p".into()), role: Some(role.into()), budget_default: false, stale: false,
            token_budget: None, tokens_spent: 0, budget_state: None, remaining: None, created_via: None,
        }
    }

    /// PINNED (phase 3): a parent settles only when every child has, into
    /// done with the results joined or failed naming the failures.
    #[test]
    fn aggregation_waits_for_every_child_then_settles() {
        assert_eq!(aggregate(&[t("done", "researcher", Some("a"), None), t("running", "analyst", None, None)]), None);
        let (ok, text) = aggregate(&[t("done", "researcher", Some("a"), None), t("done", "analyst", Some("b"), None)]).unwrap();
        assert!(ok && text.contains("[researcher] a") && text.contains("[analyst] b"));
        let (ok, text) = aggregate(&[t("done", "researcher", Some("a"), None), t("failed", "analyst", None, Some("boom"))]).unwrap();
        assert!(!ok && text.contains("[analyst] failed: boom") && !text.contains("researcher"));
        let (ok, _) = aggregate(&[t("stopped", "coder", None, None)]).unwrap();
        assert!(!ok);
        assert_eq!(aggregate(&[]), Some((true, String::new())));
    }

    /// PINNED: stale = live, loops itself, quiet longer than
    /// the window. Terminal states, aggregation parents and fresh
    /// checkpoints are never stale; an unknown last time is not either.
    #[test]
    fn staleness_is_quiet_live_looping_tasks_only() {
        std::env::set_var("NOO_TASK_STALE_SECS", "600");
        let now = chrono::Utc::now();
        let old = Some(now - chrono::Duration::seconds(601));
        let fresh = Some(now - chrono::Duration::seconds(30));
        assert!(is_stale("running", old, true, now));
        assert!(is_stale("checkpointed", old, true, now));
        assert!(!is_stale("running", fresh, true, now));
        assert!(!is_stale("done", old, true, now));
        assert!(!is_stale("stopped", old, true, now));
        assert!(!is_stale("running", old, false, now), "an aggregation parent never loops");
        assert!(!is_stale("running", None, true, now));
        std::env::remove_var("NOO_TASK_STALE_SECS");
    }

    /// PINNED (i83 G): the token switch runs at the loop boundary — once per
    /// loop, BEFORE the loop's `run_inner`, after the loop-budget check —
    /// and the loop's tokens are accounted AFTER it. Nothing inside a turn
    /// (the agent loop, the coordinator) ever consults the budget, so a
    /// running turn is never interrupted.
    #[test]
    fn the_budget_switch_sits_at_the_loop_boundary_never_inside_a_turn() {
        let src = include_str!("tasks.rs");
        let body = &src[src.find("pub async fn run_task_loops").unwrap()..src.find("// ── dispatch and resume").unwrap()];
        assert_eq!(body.matches("rt.budget_check(").count(), 1, "one check per loop");
        let check = body.find("rt.budget_check(").unwrap();
        let run = body.find("crate::coordinator::run_inner(").expect("the loop");
        let loop_budget = body.find("if loops >= req.loop_budget").unwrap();
        let usage = body.find("rt.loop_usage(").expect("the loop's tokens are accounted");
        assert!(loop_budget < check && check < run, "the check comes before the loop starts");
        assert!(run < usage, "the tokens are accounted after the loop ends");
        assert!(body[check..run].contains("if !check.proceed"), "a no stops the runner before the loop");
        for (name, other) in [
            ("coordinator/agent_loop.rs", include_str!("coordinator/agent_loop.rs")),
            ("tools.rs", include_str!("tools.rs")),
        ] {
            assert!(!other.contains("task_budget::check("), "{name} must not check the budget mid-turn");
        }
    }

    /// A parked task is neither handed back to a harness nor paged stale:
    /// it waits for its owner.
    #[test]
    fn parked_tasks_are_not_resumed_or_paged() {
        let src = include_str!("tasks.rs");
        let unfinished = &src[src.find("async fn list_unfinished_on").unwrap()..];
        assert!(unfinished[..400].contains("t.budget_state IS NULL"));
        let stale = &src[src.find("pub async fn list_stale").unwrap()..];
        assert!(stale[..400].contains("t.budget_state IS NULL"));
    }

    #[test]
    fn the_cluster_budget_is_bounded_and_defaults() {
        std::env::remove_var("NOO_TASK_LOOP_BUDGET");
        assert_eq!(cluster_loop_budget(), DEFAULT_LOOP_BUDGET);
        std::env::set_var("NOO_TASK_LOOP_BUDGET", "7");
        assert_eq!(cluster_loop_budget(), 7);
        std::env::set_var("NOO_TASK_LOOP_BUDGET", "0");
        assert_eq!(cluster_loop_budget(), DEFAULT_LOOP_BUDGET);
        std::env::set_var("NOO_TASK_LOOP_BUDGET", "9999");
        assert_eq!(cluster_loop_budget(), DEFAULT_LOOP_BUDGET);
        std::env::remove_var("NOO_TASK_LOOP_BUDGET");
    }

    #[test]
    fn roles_resolve_to_their_prompts_and_aggregations_have_no_budget() {
        assert!(role_prompt_for(Some("Reviewer")).unwrap().len() > 20);
        assert_eq!(role_prompt_for(Some("nope")), None);
        assert_eq!(role_prompt_for(None), None);
        let mut p = t("open", "x", None, None);
        p.loop_budget = 0;
        assert!(p.is_aggregation());
    }

    #[test]
    fn task_requests_round_trip_and_excerpts_cap() {
        let req = TaskRequest {
            task_id: "t".into(), objective: "o".into(), conversation_id: "c".into(), thread_id: "thr".into(),
            channel: "task".into(), user: "alice".into(), model: None, loops_done: 0, loop_budget: 3, max_iterations: 8, token: "k".into(),
            role_prompt: Some("be terse".into()),
        };
        let back: TaskRequest = serde_json::from_value(serde_json::to_value(&req).unwrap()).unwrap();
        assert_eq!(back, req);
        assert_eq!(excerpt("  hi  "), "hi");
        assert!(excerpt(&"x".repeat(1000)).ends_with('…'));
    }
}

#[cfg(test)]
mod stale_alert_tests {
    use super::describe_runner;

    #[test]
    fn a_node_name_is_reported_as_itself() {
        assert_eq!(describe_runner(Some("host3")), "host3");
    }

    #[test]
    fn a_container_id_says_nothing_will_resume_it() {
        // The failure this replaced: the alert named a container that no
        // longer existed and told the operator to restart its harness.
        let msg = describe_runner(Some("86c47f153ae0"));
        assert!(msg.contains("no longer exists"), "{msg}");
        assert!(msg.contains("nothing will resume"), "{msg}");
        assert!(!msg.contains("86c47f153ae0"), "the container id is the log's, not the channel's: {msg}");
    }

    #[test]
    fn a_container_runner_page_says_how_to_stop_it_recurring() {
        let t = super::Task {
            id: "e39546d9-563e-4cc4-a5bc-e4466ea4ca9f".into(),
            objective: "o".into(),
            owner: None,
            node: Some("86c47f153ae0".into()),
            state: "running".into(),
            conversation_id: "c".into(),
            thread_id: "t".into(),
            channel: "task".into(),
            model: None,
            loops: 2,
            loop_budget: 5,
            last_checkpoint: None,
            last_note: None,
            result: None,
            error: None,
            created_at: "t0".into(),
            updated_at: "t1".into(),
            parent_id: None,
            role: None,
            budget_default: false,
            stale: true,
            token_budget: None,
            tokens_spent: 0,
            budget_state: None,
            remaining: None,
            created_via: None,
        };
        let alert = super::stale_alert(&t, "t1");
        assert!(alert.detail.contains("NODE_ID"), "it must say how to stop it recurring: {}", alert.detail);
        assert!(alert.detail.contains("86c47f153ae0"), "{}", alert.detail);
        assert!(!alert.summary.contains("86c47f153ae0"), "{}", alert.summary);
    }

    #[test]
    fn no_node_at_all_is_said_plainly() {
        assert_eq!(describe_runner(None), "an unnamed runner");
    }
}
