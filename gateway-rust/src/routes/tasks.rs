// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Tasks.
//!
//!   POST /api/tasks              {objective, model?, loop_budget?, token_budget?}  → the task, started
//!   GET  /api/tasks?state=&limit=                                 → own tasks (operators: all)
//!   GET  /api/tasks/{id}                                          → with its budget and the owner's allowance
//!   POST /api/tasks/{id}/stop                                     → stopped at the next checkpoint
//!   POST /api/tasks/{id}/resubmit {token_budget?}                 → more tokens; a parked task resumes
//!   POST /api/tasks/{id}/ask      {question}                      → a question to the owner; parks at the boundary
//!   POST /api/tasks/{id}/answer   {text}                          → the owner's answer; a new loop starts
//!
//! Resubmit, ask and answer are the token-budget switch's ways out (i83 G,
//! `task_budget`): only the task's OWNER may use them — an operator reads
//! and stops anyone's task, but does not spend or answer for them.
//!
//! A task is created FOR the caller — the person — and runs as them: on
//! the harness of the node holding its model, or in this process. Only
//! the owner or an operator may read or stop it.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{RequesterCtx, Role};
use crate::routes::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tasks", get(tasks_list).post(tasks_create))
        .route("/api/tasks/{id}", get(tasks_get))
        .route("/api/tasks/{id}/stop", post(tasks_stop))
        .route("/api/tasks/{id}/resubmit", post(tasks_resubmit))
        .route("/api/tasks/{id}/ask", post(tasks_ask))
        .route("/api/tasks/{id}/answer", post(tasks_answer))
}

#[derive(Deserialize)]
struct CreateReq {
    objective: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    loop_budget: Option<u32>,
    /// Tokens its loops may spend; omit for no cap of its own.
    #[serde(default)]
    token_budget: Option<i64>,
}

/// Whose task this is, and whether they may see everyone's.
///
/// The owner is the ACCOUNT, not the calling identity. A connection —
/// `owner/window-a1b2`, what an MCP window or a minted persona presents —
/// is not a row in `noo_users`, and the task insert resolves its owner to
/// a user UUID. So a task created from any connection landed with a NULL
/// owner, and an ownerless task never dispatches: "a harness acts as a
/// person" and there was no person. Every MCP window and every persona
/// token silently got controller-only turns.
///
/// `account_of` is the same rule permissions, history and usage already
/// use; provenance stays on the connection, ownership resolves to the
/// account.
fn person(ctx: &Option<Extension<RequesterCtx>>) -> Result<(String, bool), AppError> {
    match ctx {
        Some(Extension(r)) => Ok((crate::auth::account_of(&r.sub).to_string(), r.role >= Role::Operator)),
        None => Err(AppError::Forbidden("tasks belong to a person: a user token is required".into())),
    }
}

/// Create a task for the caller and start it on the node holding its model, or here.
async fn tasks_create(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Json(req): Json<CreateReq>) -> AppResult {
    let (user, _) = person(&ctx)?;
    let objective = req.objective.trim();
    if objective.is_empty() || objective.len() > 8000 {
        return Err(AppError::BadRequest("objective must be 1–8000 characters".into()));
    }
    if req.token_budget.is_some_and(|b| b <= 0) {
        return Err(AppError::BadRequest("token_budget must be a positive number of tokens".into()));
    }
    let task = crate::tasks::create(&state.db, &user, objective, req.model.as_deref(), req.loop_budget, req.token_budget)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let started = crate::tasks::start(&state, &task).await.map_err(|e| AppError::Internal(e.to_string()))?;
    crate::routes::core::audit_event(&state.db, "task_created", "info", &user, &task.id, "started", json!({"node": started.node, "dispatched": started.dispatched, "loop_budget": task.loop_budget, "token_budget": task.token_budget})).await;
    let task = crate::tasks::get(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?.unwrap_or(task);
    // `dispatched` and `why` say whether a NODE took the turn and, when
    // none did, what stopped it. Without them the answer is a container
    // id the caller cannot interpret — see `harness_node_explained`.
    Ok(Json(json!({
        "task": task,
        "node": started.node,
        "dispatched": started.dispatched,
        "why": started.why,
    })))
}

#[derive(Deserialize, Default)]
struct ListQuery {
    state: Option<String>,
    limit: Option<i64>,
    user: Option<String>,
}

/// List the caller's tasks (an operator may list everyone's, or one person's with `user=`).
async fn tasks_list(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Query(q): Query<ListQuery>) -> AppResult {
    let (user, privileged) = person(&ctx)?;
    let owner = if privileged { q.user } else { Some(user) };
    let tasks = crate::tasks::list(&state.db, owner.as_deref(), q.state.as_deref(), q.limit.unwrap_or(50))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"tasks": tasks})))
}

async fn owned(state: &AppState, ctx: &Option<Extension<RequesterCtx>>, id: &str) -> Result<crate::tasks::Task, AppError> {
    let (user, privileged) = person(ctx)?;
    let task = crate::tasks::get(&state.db, id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    let Some(task) = task else { return Err(AppError::NotFound("task not found".into())) };
    if !privileged && task.owner.as_deref() != Some(user.as_str()) {
        return Err(AppError::NotFound("task not found".into()));
    }
    Ok(task)
}

/// One task, with its loops, state, result — and its children, if it delegated or fanned out.
async fn tasks_get(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Path(id): Path<String>) -> AppResult {
    let task = owned(&state, &ctx, &id).await?;
    let children = crate::tasks::children(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    // Additive: what the task actually called. Omitted when unreadable, so
    // a reader never mistakes "could not tell" for "called nothing".
    let mut out = json!({"task": task, "children": children});
    if let Some(t) = crate::tasks::tools_called(&state.db, &task.conversation_id).await {
        out["tools"] = json!({"count": t.count, "names": t.names});
    }
    // The owner's allowance beside the task's own budget: the switch reads
    // both. Null when the owner has none (or it could not be read).
    if let Some(owner) = task.owner.as_deref() {
        if let Ok(Some(a)) = crate::task_budget::allowance_use(&state.db, owner).await {
            out["allowance"] = json!({"period": a.period, "limit": a.limit, "spent": a.spent, "remaining": a.remaining()});
        }
    }
    Ok(Json(out))
}

/// The task, if the caller OWNS it — not merely may read it. The budget's
/// ways out spend the owner's tokens and speak for the owner.
async fn owner_only(state: &AppState, ctx: &Option<Extension<RequesterCtx>>, id: &str) -> Result<crate::tasks::Task, AppError> {
    let (user, _) = person(ctx)?;
    let task = owned(state, ctx, id).await?;
    if task.owner.as_deref() != Some(user.as_str()) {
        return Err(AppError::Forbidden("only the task's owner may do this".into()));
    }
    Ok(task)
}

#[derive(Deserialize, Default)]
struct ResubmitReq {
    #[serde(default)]
    token_budget: Option<i64>,
}

/// Give a task more tokens: a task parked because its budget ran out resumes from its checkpoint; on a running task only its cap changes.
async fn tasks_resubmit(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Path(id): Path<String>, body: Option<Json<ResubmitReq>>) -> AppResult {
    let task = owner_only(&state, &ctx, &id).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let (after, started) = crate::task_budget::resubmit(&state, &task, req.token_budget).await?;
    let (user, _) = person(&ctx)?;
    crate::routes::core::audit_event(&state.db, "task_resubmitted", "info", &user, &task.id, if started.is_some() { "resumed" } else { "adjusted" }, json!({"token_budget": after.token_budget, "tokens_spent": after.tokens_spent})).await;
    Ok(Json(json!({
        "task": after,
        "resumed": started.is_some(),
        "node": started.as_ref().map(|s| s.node.clone()),
        "dispatched": started.as_ref().map(|s| s.dispatched),
    })))
}

#[derive(Deserialize)]
struct AskReq {
    question: String,
}

/// Ask the task's owner a question the loop cannot go on without: posted to its thread; the task waits for the answer from the next loop boundary.
async fn tasks_ask(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Path(id): Path<String>, Json(req): Json<AskReq>) -> AppResult {
    let task = owner_only(&state, &ctx, &id).await?;
    crate::task_budget::ask(&state, &task, &req.question).await?;
    Ok(Json(json!({"asked": true, "task_id": task.id})))
}

#[derive(Deserialize)]
struct AnswerReq {
    text: String,
}

/// Answer the question a task asked: a new loop starts with the question and the answer.
async fn tasks_answer(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Path(id): Path<String>, Json(req): Json<AnswerReq>) -> AppResult {
    let task = owner_only(&state, &ctx, &id).await?;
    let (after, started) = crate::task_budget::answer(&state, &task, &req.text).await?;
    let (user, _) = person(&ctx)?;
    crate::routes::core::audit_event(&state.db, "task_answered", "info", &user, &task.id, "resumed", json!({"node": started.node})).await;
    Ok(Json(json!({"task": after, "node": started.node, "dispatched": started.dispatched, "why": started.why})))
}

/// Stop a task: it ends at its next checkpoint, and its loops' tool calls stand.
async fn tasks_stop(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, Path(id): Path<String>) -> AppResult {
    let task = owned(&state, &ctx, &id).await?;
    let stopped = crate::tasks::stop(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    let (user, _) = person(&ctx)?;
    crate::routes::core::audit_event(&state.db, "task_stopped", "info", &user, &task.id, if stopped { "stopped" } else { "not_running" }, json!({"was": task.state})).await;
    Ok(Json(json!({"stopped": stopped, "task_id": task.id})))
}

#[cfg(test)]
mod owner_tests {
    use super::person;
    use crate::auth::{RequesterCtx, Role};
    use axum::Extension;

    fn ctx(sub: &str) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: sub.into(),
            scopes: vec!["read".into(), "write".into()],
            role: Role::Admin,
            harness: None,
            act: None,
        }))
    }

    /// A task's owner is the ACCOUNT, never the connection.
    ///
    /// `noo_tasks.owner_uuid` resolves through `noo_users`, and a
    /// connection (`owner/window-a1b2` — an MCP window, a minted persona)
    /// has no row there. Owning a task by the raw subject wrote NULL, and
    /// `tasks::start` refuses to dispatch an ownerless task because "a
    /// harness acts as a person". Every window and every persona silently
    /// got controller-only turns.
    ///
    /// This exercises `person` itself: an earlier version of this test
    /// asserted on `account_of`, which was already correct, so restoring
    /// the bug did not trip it.
    #[test]
    fn a_connection_owns_its_task_as_its_account() {
        let (owner, _) = person(&ctx("owner/window-a1b2")).expect("a person");
        assert_eq!(owner, "owner", "a connection must own its task as its ACCOUNT, or the task is ownerless and never dispatches");
        let (owner, _) = person(&ctx("personifai-prov/persona-alice")).expect("a person");
        assert_eq!(owner, "personifai-prov");
    }

    /// The common case must be untouched.
    #[test]
    fn an_account_owns_its_task_as_itself() {
        let (owner, _) = person(&ctx("owner")).expect("a person");
        assert_eq!(owner, "owner");
    }

    /// PINNED (i83 G): resubmit, ask and answer go through `owner_only` —
    /// an operator who may READ a task may not spend or answer for it.
    #[test]
    fn the_budget_ways_out_are_owner_only() {
        let src = include_str!("tasks.rs");
        for f in ["async fn tasks_resubmit(", "async fn tasks_ask(", "async fn tasks_answer("] {
            let body = &src[src.find(f).expect(f)..];
            let body = &body[..body.find("\n}\n").unwrap()];
            assert!(body.contains("owner_only(&state, &ctx, &id)"), "{f} must check the owner");
        }
        let guard = &src[src.find("async fn owner_only(").unwrap()..];
        assert!(guard[..600].contains("task.owner.as_deref() != Some(user.as_str())"));
    }

    /// No identity at all is still a refusal, not an ownerless task.
    #[test]
    fn no_requester_is_refused() {
        assert!(person(&None).is_err());
    }
}
