// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Tasks.
//!
//!   POST /api/tasks              {objective, model?, loop_budget?, token_budget?}  → the task, started
//!                                (Idempotency-Key: a retry within 24 h returns the same task, "idempotent_replay": true)
//!   GET  /api/tasks?state=&limit=                                 → own tasks (operators: all)
//!   GET  /api/tasks/{id}                                          → with its budget and the owner's allowance
//!   POST /api/tasks/{id}/stop                                     → stopped at the next checkpoint
//!   POST /api/tasks/stop         {via, user?}                     → stop the caller's own tasks created via `addon:<name>`
//!   POST /api/tasks/{id}/resubmit {token_budget?}                 → more tokens; a parked task resumes
//!   POST /api/tasks/{id}/ask      {question}                      → a question to the owner; parks at the boundary
//!   POST /api/tasks/{id}/answer   {text}                          → the owner's answer; a new loop starts
//!   POST /api/tasks/{id}/context  {text, revision}                → context an add-on pushes; applied at the next loop
//!   GET  /api/tasks/{id}/events?after=&limit=                     → the task's events after a sequence number
//!
//! An add-on acting through a delegated token (`addon_delegation`) reaches
//! these routes except resubmit, and sees ONLY the tasks it created for that
//! person (`created_via = addon:<name>`): its list is never the operator's
//! all-tasks view, and any other task answers 404, even to an operator's token.
//!
//! Resubmit, ask and answer are the token-budget switch's ways out (i83 G,
//! `task_budget`): only the task's OWNER may use them — an operator reads
//! and stops anyone's task, but does not spend or answer for them.
//!
//! A task is created FOR the caller — the person — and runs as them: on
//! the harness of the node holding its model, or in this process. Only
//! the owner or an operator may read or stop it.

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::addon_delegation::AddonDelegation;
use crate::auth::{RequesterCtx, Role};
use crate::routes::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tasks", get(tasks_list).post(tasks_create))
        .route("/api/tasks/{id}", get(tasks_get))
        .route("/api/tasks/stop", post(tasks_stop_via))
        .route("/api/tasks/{id}/stop", post(tasks_stop))
        .route("/api/tasks/{id}/resubmit", post(tasks_resubmit))
        .route("/api/tasks/{id}/ask", post(tasks_ask))
        .route("/api/tasks/{id}/answer", post(tasks_answer))
        .route("/api/tasks/{id}/context", post(tasks_context))
        .route("/api/tasks/{id}/events", get(tasks_events))
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
    /// Context to start from (at most 32 KiB), saved as revision 1; never part of `objective`.
    #[serde(default)]
    context: Option<String>,
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
async fn tasks_create(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, headers: HeaderMap, Json(req): Json<CreateReq>) -> AppResult {
    let (user, _) = person(&ctx)?;
    let via = adt.as_ref().map(|Extension(a)| a.via());
    // A retried create returns the task the first one made (24 h, per owner
    // and per origin: a key never crosses from a direct create to an add-on's).
    let key = idempotency_key(&headers)?;
    let scope = via.clone().unwrap_or_default();
    if let Some(k) = key.as_deref() {
        if let Some(id) = crate::tasks::idempotent_task(&state.db, &user, &scope, k).await.map_err(|e| AppError::Internal(e.to_string()))? {
            return replay(&state, &id).await;
        }
    }
    let objective = req.objective.trim();
    if objective.is_empty() || objective.len() > 8000 {
        return Err(AppError::BadRequest("objective must be 1–8000 characters".into()));
    }
    if req.token_budget.is_some_and(|b| b <= 0) {
        return Err(AppError::BadRequest("token_budget must be a positive number of tokens".into()));
    }
    let task = crate::tasks::create(&state.db, &user, objective, req.model.as_deref(), req.loop_budget, req.token_budget, via.as_deref())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    // Starting context is revision 1 of the task's context, saved before it runs.
    if let Some(text) = req.context.as_deref().filter(|t| !t.is_empty()) {
        use crate::task_context::ContextOutcome;
        let outcome = crate::task_context::submit(&state.db, &task.id, 1, text).await;
        if !matches!(outcome, Ok(ContextOutcome::Accepted)) {
            let _ = crate::tasks::discard_unstarted(&state.db, &task.id).await;
            return Err(match outcome {
                Ok(ContextOutcome::TooLarge) => AppError::BadRequest("context must be at most 32 KiB".into()),
                Ok(_) => AppError::Internal("the task's starting context was not accepted".into()),
                Err(e) => AppError::Internal(e.to_string()),
            });
        }
    }
    // Claim the key BEFORE starting: of two racing creates one wins; the loser
    // discards its never-started task and answers with the winner's.
    if let Some(k) = key.as_deref() {
        let winner = crate::tasks::claim_idempotency(&state.db, &user, &scope, k, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
        if winner != task.id {
            let _ = crate::tasks::discard_unstarted(&state.db, &task.id).await;
            return replay(&state, &winner).await;
        }
    }
    let started = crate::tasks::start(&state, &task).await.map_err(|e| AppError::Internal(e.to_string()))?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::TaskCreated, &user, &task.id)
            .outcome(crate::audit::Outcome::custom("started"))
            .details(json!({"node": started.node, "dispatched": started.dispatched, "loop_budget": task.loop_budget, "token_budget": task.token_budget})),
    ).await;
    let task = crate::tasks::get(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?.unwrap_or(task);
    // `dispatched` and `why` say whether a NODE took the turn and, when
    // none did, what stopped it. Without them the answer is a container
    // id the caller cannot interpret — see `harness_node_explained`.
    Ok(Json(json!({
        "task": task,
        "node": started.node,
        "dispatched": started.dispatched,
        "queued": started.queued,
        "why": started.why,
    })))
}

/// The `Idempotency-Key` header: 1-200 visible characters, or absent.
fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let Some(v) = headers.get("idempotency-key") else { return Ok(None) };
    let k = v.to_str().map(str::trim).unwrap_or("");
    if k.is_empty() || k.len() > 200 || !k.chars().all(|c| c.is_ascii_graphic()) {
        return Err(AppError::BadRequest("Idempotency-Key must be 1-200 visible ASCII characters".into()));
    }
    Ok(Some(k.to_string()))
}

/// The answer to a create whose key was seen before: the same shape as a
/// fresh create, from the task as it is now.
async fn replay(state: &AppState, id: &str) -> AppResult {
    let task = crate::tasks::get(&state.db, id).await.map_err(|e| AppError::Internal(e.to_string()))?.ok_or_else(|| AppError::NotFound("task not found".into()))?;
    Ok(Json(json!({
        "task": task,
        "node": task.node,
        "dispatched": task.state != "open",
        "why": null,
        "idempotent_replay": true,
    })))
}

#[derive(Deserialize, Default)]
struct ListQuery {
    state: Option<String>,
    limit: Option<i64>,
    user: Option<String>,
}

/// List the caller's tasks (an operator may list everyone's, or one person's with `user=`).
async fn tasks_list(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Query(q): Query<ListQuery>) -> AppResult {
    let (user, privileged) = person(&ctx)?;
    // An add-on sees the caller's tasks it created and nothing else, even when
    // the person is an operator: this path never takes the all-tasks branch.
    if let Some(Extension(a)) = adt {
        let tasks = crate::tasks::list_via(&state.db, &user, &a.via(), q.state.as_deref(), q.limit.unwrap_or(50))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(Json(json!({"tasks": tasks})));
    }
    let owner = if privileged { q.user } else { Some(user) };
    let tasks = crate::tasks::list(&state.db, owner.as_deref(), q.state.as_deref(), q.limit.unwrap_or(50))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"tasks": tasks})))
}

async fn owned(state: &AppState, ctx: &Option<Extension<RequesterCtx>>, adt: &Option<Extension<AddonDelegation>>, id: &str) -> Result<crate::tasks::Task, AppError> {
    let (user, privileged) = person(ctx)?;
    let task = crate::tasks::get(&state.db, id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    let Some(task) = task else { return Err(AppError::NotFound("task not found".into())) };
    if !visible(&task, &user, privileged, adt.as_ref().map(|Extension(a)| a)) {
        return Err(AppError::NotFound("task not found".into()));
    }
    Ok(task)
}

/// May this caller see `task` at all? A person sees their own (an operator,
/// anyone's); an add-on's delegated token sees only what that add-on created
/// for that person, whoever the person is: a task id confers nothing.
fn visible(task: &crate::tasks::Task, user: &str, privileged: bool, adt: Option<&AddonDelegation>) -> bool {
    match adt {
        Some(a) => task.owner.as_deref() == Some(user) && task.created_via.as_deref() == Some(a.via().as_str()),
        None => privileged || task.owner.as_deref() == Some(user),
    }
}

/// One task, with its loops, state, result — and its children, if it delegated or fanned out.
async fn tasks_get(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>) -> AppResult {
    let task = owned(&state, &ctx, &adt, &id).await?;
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
async fn owner_only(state: &AppState, ctx: &Option<Extension<RequesterCtx>>, adt: &Option<Extension<AddonDelegation>>, id: &str) -> Result<crate::tasks::Task, AppError> {
    let (user, _) = person(ctx)?;
    let task = owned(state, ctx, adt, id).await?;
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
async fn tasks_resubmit(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>, body: Option<Json<ResubmitReq>>) -> AppResult {
    // Raising a budget spends the owner's tokens: it needs the person directly.
    if adt.is_some() {
        return Err(AppError::Forbidden("resubmit needs the person directly, not an add-on".into()));
    }
    let task = owner_only(&state, &ctx, &adt, &id).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let (after, started) = crate::task_budget::resubmit(&state, &task, req.token_budget).await?;
    let (user, _) = person(&ctx)?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::TaskResubmitted, &user, &task.id)
            .outcome(if started.is_some() { crate::audit::Outcome::custom("resumed") } else { crate::audit::Outcome::custom("adjusted") })
            .details(json!({"token_budget": after.token_budget, "tokens_spent": after.tokens_spent})),
    ).await;
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
async fn tasks_ask(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>, Json(req): Json<AskReq>) -> AppResult {
    let task = owner_only(&state, &ctx, &adt, &id).await?;
    crate::task_budget::ask(&state, &task, &req.question).await?;
    Ok(Json(json!({"asked": true, "task_id": task.id})))
}

#[derive(Deserialize)]
struct AnswerReq {
    text: String,
}

/// Answer the question a task asked: a new loop starts with the question and the answer.
async fn tasks_answer(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>, Json(req): Json<AnswerReq>) -> AppResult {
    let task = owner_only(&state, &ctx, &adt, &id).await?;
    let (after, started) = crate::task_budget::answer(&state, &task, &req.text).await?;
    let (user, _) = person(&ctx)?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::TaskAnswered, &user, &task.id)
            .outcome(crate::audit::Outcome::custom("resumed"))
            .details(json!({"node": started.node})),
    ).await;
    Ok(Json(json!({"task": after, "node": started.node, "dispatched": started.dispatched, "queued": started.queued, "why": started.why})))
}

/// Stop a task: it ends at its next checkpoint, and its loops' tool calls stand.
async fn tasks_stop(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>) -> AppResult {
    let task = owned(&state, &ctx, &adt, &id).await?;
    let stopped = crate::tasks::stop(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    let (user, _) = person(&ctx)?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::TaskStopped, &user, &task.id)
            .outcome(if stopped { crate::audit::Outcome::custom("stopped") } else { crate::audit::Outcome::custom("not_running") })
            .details(json!({"was": task.state})),
    ).await;
    Ok(Json(json!({"stopped": stopped, "task_id": task.id})))
}

#[derive(Deserialize)]
struct StopViaReq {
    via: String,
    #[serde(default)]
    user: Option<String>,
}

/// Revoke background work: stop every unfinished task the caller owns that was
/// created `via` an add-on. The owner, or that add-on's own delegated token,
/// stops the caller's; an operator may name another person with `user`.
async fn tasks_stop_via(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Json(req): Json<StopViaReq>) -> AppResult {
    let (user, privileged) = person(&ctx)?;
    let via = req.via.trim();
    if via.strip_prefix(crate::addon_delegation::ACTOR_PREFIX).is_none_or(str::is_empty) {
        return Err(AppError::BadRequest("via must be addon:<name>".into()));
    }
    let owner = match (adt.as_ref(), req.user) {
        // An add-on revokes its own work for the person it holds a token for, nothing else.
        (Some(_), Some(_)) => return Err(AppError::Forbidden("an add-on's token cannot name another user".into())),
        (Some(Extension(a)), None) if a.via() != via => return Err(AppError::Forbidden("an add-on's token may revoke only its own work".into())),
        (Some(_), None) => user.clone(),
        (None, Some(u)) if privileged => u,
        (None, Some(_)) => return Err(AppError::Forbidden("naming another user needs the operator role".into())),
        (None, None) => user.clone(),
    };
    let ids = crate::tasks::stop_via(&state.db, &owner, via).await.map_err(|e| AppError::Internal(e.to_string()))?;
    for id in &ids {
        crate::audit::record(
            &state.db,
            AuditEvent::new(AuditKind::TaskStopped, &user, id)
                .outcome(crate::audit::Outcome::custom("background_revoked"))
                .details(json!({"via": via, "owner": owner})),
        ).await;
    }
    Ok(Json(json!({"stopped": ids, "count": ids.len(), "via": via, "owner": owner})))
}

#[derive(Deserialize)]
struct ContextReq {
    text: String,
    revision: i32,
}

/// Context an add-on pushes into a running task: revisions are monotonic per
/// task and a retry of the same revision is a no-op, picked up at the next
/// loop boundary. Distinct from `answer`, which needs a pending question.
async fn tasks_context(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>, Json(req): Json<ContextReq>) -> Result<Response, AppError> {
    use crate::task_context::ContextOutcome;
    // Context speaks for the owner, like an answer: an operator reads and
    // stops anyone's task but does not tell it what its owner meant.
    let task = owner_only(&state, &ctx, &adt, &id).await?;
    if req.revision < 1 {
        return Err(AppError::BadRequest("revision must be an integer >= 1".into()));
    }
    if req.text.is_empty() {
        return Err(AppError::BadRequest("text must not be empty".into()));
    }
    let outcome = crate::task_context::submit(&state.db, &task.id, req.revision, &req.text).await.map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(match outcome {
        ContextOutcome::Accepted => Json(json!({"task_id": task.id, "revision": req.revision, "accepted": true, "applies": "next_loop"})).into_response(),
        ContextOutcome::Duplicate { current } => Json(json!({"task_id": task.id, "revision": req.revision, "accepted": false, "current_revision": current})).into_response(),
        ContextOutcome::Conflict { current } => (StatusCode::CONFLICT, Json(json!({"error": "revision conflict: a lower revision, or the same revision with different text", "current_revision": current}))).into_response(),
        ContextOutcome::Terminal { state } => (StatusCode::CONFLICT, Json(json!({"error": "the task has finished", "state": state}))).into_response(),
        ContextOutcome::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({"error": "context text is larger than 32 KiB"}))).into_response(),
    })
}

#[derive(Deserialize, Default)]
struct EventsQuery {
    after: Option<i64>,
    limit: Option<i64>,
}

/// The task's events after `after` (default: from the start), oldest first.
async fn tasks_events(State(state): State<Arc<AppState>>, ctx: Option<Extension<RequesterCtx>>, adt: Option<Extension<AddonDelegation>>, Path(id): Path<String>, Query(q): Query<EventsQuery>) -> AppResult {
    let task = owned(&state, &ctx, &adt, &id).await?;
    let page = crate::task_events::list_after(&state.db, &task.id, q.after.unwrap_or(0).max(0), q.limit.unwrap_or(100).clamp(1, 500))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(page)))
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
        for f in ["async fn tasks_resubmit(", "async fn tasks_ask(", "async fn tasks_answer(", "async fn tasks_context("] {
            let body = &src[src.find(f).expect(f)..];
            let body = &body[..body.find("\n}\n").unwrap()];
            assert!(body.contains("owner_only(&state, &ctx, &adt, &id)"), "{f} must check the owner");
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
