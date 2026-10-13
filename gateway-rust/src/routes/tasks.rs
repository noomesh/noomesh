// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Tasks.
//!
//!   POST /api/tasks              {objective, model?, loop_budget?}  → the task, started
//!   GET  /api/tasks?state=&limit=                                 → own tasks (operators: all)
//!   GET  /api/tasks/{id}
//!   POST /api/tasks/{id}/stop                                     → stopped at the next checkpoint
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
}

#[derive(Deserialize)]
struct CreateReq {
    objective: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    loop_budget: Option<u32>,
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
    let task = crate::tasks::create(&state.db, &user, objective, req.model.as_deref(), req.loop_budget)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let started = crate::tasks::start(&state, &task).await.map_err(|e| AppError::Internal(e.to_string()))?;
    crate::routes::core::audit_event(&state.db, "task_created", "info", &user, &task.id, "started", json!({"node": started.node, "dispatched": started.dispatched, "loop_budget": task.loop_budget})).await;
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
    Ok(Json(out))
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

    /// No identity at all is still a refusal, not an ownerless task.
    #[test]
    fn no_requester_is_refused() {
        assert!(person(&None).is_err());
    }
}
