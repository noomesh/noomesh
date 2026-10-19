// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness rail.
//!
//!   POST /api/harness/call   {"op": "...", ...}  →  {"ok": true, ...}
//!
//! The one route a node-hosted harness talks to. It is authenticated by
//! the token the gateway minted for the turn (`auth::mint_harness_jwt`):
//! a USER token with `harness = "node:<id>"` and the conversation pinned
//! in `conv`. The auth middleware confines such a token to this prefix
//! and attaches [`HarnessTurn`]; this handler takes the conversation and
//! the person from there and never from the body. Every op then runs
//! through [`InProcessRuntime`] — the same functions the gateway's own
//! loop calls — so a remote turn reads, writes, audits and is
//! rate-limited exactly as a local one.
//!
//! Tool execution runs under `mcp_bridge::CALLER` = the person, so the
//! external-tool audience rule and the approval gate see the right
//! identity. Approval notices for a remote turn take the channel and
//! broadcast paths (there is no dashboard socket on this side);
//! `DASHBOARD_APPROVAL_TX` is not set here.

use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, routing::post, Extension, Json, Router};
use serde_json::json;

use crate::auth::{HarnessTurn, RequesterCtx};
use crate::coordinator::{HarnessOp, HarnessRuntime, InProcessRuntime};
use crate::routes::AppError;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/harness/call", post(harness_call))
}

/// What a harness op can fail with. `CloudGate` is the closed cloud gate: a
/// policy refusal that keeps the same 403 body the inference route returns
/// (`cloud_gate_body`); every other failure stays an `AppError`.
enum HarnessErr {
    App(AppError),
    CloudGate(serde_json::Value),
}

impl From<AppError> for HarnessErr {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl IntoResponse for HarnessErr {
    fn into_response(self) -> Response {
        match self {
            Self::App(e) => e.into_response(),
            Self::CloudGate(body) => (StatusCode::FORBIDDEN, Json(body)).into_response(),
        }
    }
}

/// Map a `run_cloud_completion` failure: the typed gate refusal first (403),
/// anything else (provider error, missing key) stays 400 as before.
fn cloud_run_error(e: anyhow::Error) -> HarnessErr {
    match crate::coordinator::cloud_gate_refusal(&e) {
        Some(r) => HarnessErr::CloudGate(crate::coordinator::cloud_gate_body(r.0)),
        None => HarnessErr::App(AppError::BadRequest(e.to_string())),
    }
}

/// Serve one harness-rail operation for the turn the caller's token was
/// minted for. Conversation and user come from the token, never the body.
async fn harness_call(
    State(state): State<Arc<AppState>>,
    turn: Option<Extension<HarnessTurn>>,
    requester: Option<Extension<RequesterCtx>>,
    Json(op): Json<HarnessOp>,
) -> Result<Json<serde_json::Value>, HarnessErr> {
    // Both extensions are set together by the auth middleware for a
    // node-harness token; anything else on this route is refused, even
    // an admin — the rail is for harness tokens only.
    let (Some(Extension(turn)), Some(Extension(ctx))) = (turn, requester) else {
        return Err(AppError::Forbidden("harness rail: node-harness token required".into()).into());
    };
    let user = ctx.sub.as_str();
    let conv = turn.conversation_id.as_str();
    let rt = InProcessRuntime::new(&state);
    tracing::debug!(op = op.name(), node = %turn.node, user, conversation = conv, "harness_call");

    let reply = match op {
        HarnessOp::Config => json!({
            "max_context_tokens": rt.max_context_tokens(),
            "max_session_messages": rt.max_session_messages(),
            "preferred_skills": rt.preferred_skills().await,
        }),
        HarnessOp::Catalogs => json!({
            "skills": state.prompt_skills.catalog_for_node(),
            "runbooks": state.runbooks,
        }),
        HarnessOp::ModelPreference => json!({"model": rt.user_model_preference(user).await}),
        HarnessOp::DetectModel { prompt } => json!({"model": rt.detect_model_from_prompt(&prompt).await}),
        HarnessOp::ResolveBackend { model, exclude_urls } => {
            // A node harness has no provider keys: cloud models run on the
            // controller (dispatch keeps those turns in process).
            if let Some(m) = model.as_deref().filter(|m| crate::coordinator::is_cloud_model(m)) {
                return Err(AppError::BadRequest(format!("'{m}' is a cloud model; cloud models run on the controller, not on a node harness")).into());
            }
            let backend = rt.resolve_backend_excluding(model.as_deref(), &exclude_urls).await.map_err(|e| AppError::BadRequest(e.to_string()))?;
            json!({"backend": backend})
        }
        HarnessOp::CloudRun { prompt, channel, model } => {
            let result = rt.run_cloud_completion(&prompt, conv, &channel, &model).await.map_err(cloud_run_error)?;
            json!({"result": result})
        }
        HarnessOp::SessionLoad { channel } => json!({"session": rt.load_session(conv, &channel).await}),
        HarnessOp::SessionSave { role, content, metadata } => {
            rt.save_message(conv, &role, &content, metadata.as_ref(), Some(user)).await.map_err(|e| AppError::Internal(e.to_string()))?;
            json!({})
        }
        HarnessOp::SessionMetadata { metadata } => {
            rt.update_conversation_metadata(conv, &metadata).await.map_err(|e| AppError::Internal(e.to_string()))?;
            json!({})
        }
        HarnessOp::TurnNumber => json!({"turn": rt.turn_number(conv).await}),
        HarnessOp::Persona => json!({"text": rt.persona_prompt().await}),
        HarnessOp::ClusterAwareness => json!({"text": rt.cluster_awareness().await}),
        HarnessOp::Rag { prompt } => json!({"text": rt.rag_context(&prompt, Some(user)).await}),
        HarnessOp::Memory { prompt } => json!({"text": rt.memory_context(&prompt, Some(user)).await}),
        HarnessOp::CrossChannel { prompt, channel } => json!({"text": rt.cross_channel_context(&prompt, &channel, Some(user)).await}),
        HarnessOp::Video { prompt } => json!({"text": rt.video_context(&prompt).await}),
        HarnessOp::Companion => json!({"text": rt.companion_context().await}),
        HarnessOp::Skills { prompt, preferred } => match rt.prompt_skills_context(&prompt, &preferred) {
            Some((text, names)) => json!({"text": text, "names": names}),
            None => json!({"text": null, "names": []}),
        },
        HarnessOp::Runbook { prompt } => json!({"text": rt.runbook_context(&prompt)}),
        HarnessOp::Temporal { timeout_ms } => json!({"text": rt.temporal_context(Some(user), Duration::from_millis(timeout_ms.min(30_000))).await}),
        HarnessOp::RunningSummary => json!({"text": rt.running_summary(conv).await}),
        HarnessOp::Recall { query, top_k } => json!({"text": rt.conversation_recall(conv, &query, top_k.min(50)).await}),
        HarnessOp::ToolSchemas => json!({
            "native": rt.tool_schemas().await,
            "external": rt.external_tool_schemas(Some(user)).await,
        }),
        HarnessOp::ExecuteTool { call } => {
            // INFO, with the tool and the name it runs as: the harness
            // rail's calls were invisible in Loki (the line above is
            // debug), which is why a loop reading the wrong inbox took an
            // hour to explain.
            tracing::info!(tool = %call.name, r#as = user, node = %turn.node, conversation = conv, "harness_tool_call");
            // The person, and the class the call arrived on — a tool that
            // records who acted (agent messages) stamps both from here.
            let harness = Some(format!("{}{}", crate::auth::HARNESS_NODE_PREFIX, turn.node));
            // Approval cards for this call go where the turn came from —
            // the dashboard socket or channel the dispatcher registered —
            // exactly as they would had the loop run in process.
            let origin = crate::routes::communication::origin_for(conv).unwrap_or_default();
            // The gated-call record (denied HIGH calls, completed identical
            // calls) lives in per-task locals; seed them from the turn's
            // shared record, run the call, store the record back — so the
            // dedup works across a remote turn's loops and the dispatcher
            // can hand the failures to the channel pipeline's banner.
            let seed = origin.gated_record();
            let (result, after) = crate::routes::communication::GATED_TOOL_FAILURES
                .scope(
                    Default::default(),
                    crate::routes::communication::COMPLETED_GATED_CALLS.scope(Default::default(), async {
                        seed.replay();
                        let result = crate::routes::communication::DASHBOARD_APPROVAL_TX
                            .scope(
                                origin.dashboard.clone(),
                                crate::routes::communication::CHANNEL_APPROVAL_TARGET.scope(
                                    origin.channel.clone(),
                                    crate::mcp_bridge::CONVERSATION.scope(
                                        Some(conv.to_string()),
                                        crate::mcp_bridge::HARNESS.scope(
                                            harness,
                                            crate::mcp_bridge::CALLER.scope(
                                                Some(user.to_string()),
                                                // The turn's conversation is bound here as it is on every other
                                                // coordinator surface, so a gate that reads it (the scheduled-task
                                                // tool ceiling, approval binding) sees this turn.
                                                crate::routes::communication::with_turn_principal(
                                                    crate::routes::communication::TurnPrincipal {
                                                        requester: user.to_string(),
                                                        conversation_id: conv.to_string(),
                                                        channel: "harness".to_string(),
                                                        run_id: String::new(),
                                                    },
                                                    rt.execute_tool(&call),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            )
                            .await;
                        (result, crate::routes::communication::GatedRecord::capture())
                    }),
                )
                .await;
            origin.store_gated(after);
            json!({"result": result})
        }
        HarnessOp::RecordToolCall { tool_name, arguments, success, output, error, elapsed_ms } => {
            rt.record_tool_call(conv, &tool_name, &arguments, success, &output, error.as_deref(), elapsed_ms).await;
            json!({})
        }
        HarnessOp::RetrievalFeedback { tool_name, success } => {
            rt.record_retrieval_feedback(conv, &tool_name, success).await;
            json!({})
        }
        HarnessOp::SkillUsage { names } => {
            rt.record_skill_usage(&names, conv).await;
            json!({})
        }
        HarnessOp::PreHooks { prompt } => {
            rt.fire_pre_inference_hooks(conv, &prompt).await;
            json!({})
        }
        HarnessOp::PostHooks { result } => {
            rt.fire_post_response_hooks(conv, &result).await;
            json!({})
        }
        HarnessOp::Shard => {
            rt.tag_conversation_shard(conv).await;
            json!({})
        }
        HarnessOp::TemporalExtract { user_message, assistant_response } => {
            rt.fire_temporal_extraction(conv, &user_message, &assistant_response, Some(user)).await;
            json!({})
        }
        HarnessOp::MaybeSummary { backend, turn } => {
            rt.maybe_regenerate_summary(conv, &backend, turn).await;
            json!({})
        }
        HarnessOp::TaskCheckpoint { task_id, loops, note, exhausted } => {
            // The task must be the one this token was minted for: same
            // conversation, same person. Then record, read the state back,
            // and renew the person's credential.
            let task = crate::tasks::get(&state.db, &task_id).await.map_err(|e| AppError::Internal(e.to_string()))?;
            let Some(task) = task.filter(|t| t.conversation_id == conv && t.owner.as_deref() == Some(user)) else {
                return Err(AppError::Forbidden("harness rail: that task is not this turn's".into()).into());
            };
            let after = crate::tasks::checkpoint(&state, &task.id, loops, note.as_deref(), exhausted).await.map_err(|e| AppError::Internal(e.to_string()))?;
            let token = match crate::coordinator::role_of(&state, user).await {
                Some(role) => crate::auth::mint_harness_jwt(user, role, &turn.node, conv, crate::coordinator::turn_deadline().as_secs() + 60),
                None => None,
            };
            json!({"state": after, "token": token})
        }
        HarnessOp::Usage { prompt_tokens, completion_tokens, total_tokens, calls, model, kind, task_id } => {
            // A foreign loop's model calls, counted by the harness's wire
            // translator. Charged to the token's user on the token's node —
            // the body names neither — and the kind must be a declared one.
            if !crate::harness_kinds::names().contains(&kind.as_str()) {
                return Err(AppError::BadRequest(format!("harness rail: unknown harness kind {kind:?}")).into());
            }
            let model = if model.trim().is_empty() { "unknown".to_string() } else { model };
            tracing::info!(
                node = %turn.node, user, conversation = conv, kind = %kind, model = %model,
                task = task_id.as_deref().unwrap_or(""), calls, prompt_tokens, completion_tokens, total_tokens,
                "harness_usage"
            );
            let clamp = |n: u64| n.min(i32::MAX as u64) as u32;
            // A task's loop (i83 G): the row carries the task id and the
            // tokens count against the task, before the driver's next
            // boundary check reads them. Only the turn's own task; anything
            // else is still recorded, just not charged to a task.
            let task = match task_id.as_deref() {
                Some(id) => turn_task(&state, id, conv, user).await.ok(),
                None => None,
            };
            match task {
                Some(task) => {
                    let u = crate::usage::TaskUsage {
                        node_id: Some(turn.node.clone()),
                        backend: format!("harness:{kind}"),
                        model,
                        source: crate::usage::HARNESS_SOURCE,
                        username: user.to_string(),
                        harness_kind: Some(kind),
                        task_id: task.id.clone(),
                        prompt_tokens: clamp(prompt_tokens),
                        completion_tokens: clamp(completion_tokens),
                    };
                    let spent = crate::task_budget::account(&state.db, &u).await.map_err(|e| AppError::Internal(e.to_string()))?;
                    json!({"tokens_spent": spent})
                }
                None => {
                    crate::usage::record_harness(
                        state.db.clone(),
                        turn.node.clone(),
                        model,
                        kind,
                        user.to_string(),
                        clamp(prompt_tokens),
                        clamp(completion_tokens),
                    );
                    json!({})
                }
            }
        }
        HarnessOp::BudgetCheck { task_id } => {
            let task = turn_task(&state, &task_id, conv, user).await?;
            let check = crate::task_budget::check(&state, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
            serde_json::to_value(check).map_err(|e| AppError::Internal(e.to_string()))?
        }
        HarnessOp::TaskUsage { task_id, prompt_tokens, completion_tokens, model, backend } => {
            // A native loop on a node: it ran on this token's node, never on
            // a cloud model (those run on the controller), and is not a
            // foreign kind (that is the `usage` op).
            let task = turn_task(&state, &task_id, conv, user).await?;
            if backend.starts_with("cloud-") || backend.starts_with("harness:") {
                return Err(AppError::BadRequest(format!("harness rail: backend {backend:?} is not a node backend")).into());
            }
            let clamp = |n: u64| n.min(i32::MAX as u64) as u32;
            let u = crate::usage::TaskUsage {
                node_id: Some(turn.node.clone()),
                backend: if backend.trim().is_empty() { "unknown".into() } else { backend },
                model: if model.trim().is_empty() { "unknown".into() } else { model },
                source: crate::usage::TASK_SOURCE,
                username: user.to_string(),
                harness_kind: None,
                task_id: task.id.clone(),
                prompt_tokens: clamp(prompt_tokens),
                completion_tokens: clamp(completion_tokens),
            };
            let spent = crate::task_budget::account(&state.db, &u).await.map_err(|e| AppError::Internal(e.to_string()))?;
            json!({"tokens_spent": spent})
        }
        HarnessOp::TaskAsk { task_id, question } => {
            let task = turn_task(&state, &task_id, conv, user).await?;
            crate::task_budget::ask(&state, &task, &question).await.map_err(AppError::from)?;
            json!({"asked": true})
        }
        HarnessOp::TaskDone { task_id, result, failed } => {
            // The same ownership rule as the checkpoint: this token's
            // conversation, this token's person.
            let task = crate::tasks::get(&state.db, &task_id).await.map_err(|e| AppError::Internal(e.to_string()))?;
            let Some(task) = task.filter(|t| t.conversation_id == conv && t.owner.as_deref() == Some(user)) else {
                return Err(AppError::Forbidden("harness rail: that task is not this turn's".into()).into());
            };
            // The door's rule (`noo_task_done` from /mcp/user): no evidence
            // gate — the CLI's tools ran on the node, outside the record —
            // and the same unprefixed result, posted the same way.
            let changed = crate::tasks::finish(&state.db, &task.id, !failed, &result, /* require_tool_use */ false)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if changed {
                crate::tools::post_task_result(&state, &task, user, !failed, &result).await;
            }
            let after = crate::tasks::get(&state.db, &task.id).await.map_err(|e| AppError::Internal(e.to_string()))?.map(|t| t.state).unwrap_or_else(|| "failed".into());
            json!({"state": after, "changed": changed})
        }
        HarnessOp::DoorKey => {
            // The person must still hold an active account: a disabled one
            // gets no key (the door would refuse it anyway, but say so here).
            if crate::coordinator::role_of(&state, user).await.is_none() {
                return Err(AppError::Forbidden("harness rail: no active account to mint a door key for".into()).into());
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let Some(ttl) = door_key_ttl(turn.exp, now, crate::coordinator::turn_deadline().as_secs()) else {
                return Err(AppError::Forbidden("harness rail: the turn's token has expired".into()).into());
            };
            let consumer = crate::service_keys::door_key_consumer(&turn.node, conv);
            let k = crate::service_keys::mint_door_key(&state.db, user, &consumer, ttl).await.map_err(|e| AppError::Internal(e.to_string()))?;
            tracing::info!(r#as = user, node = %turn.node, conversation = conv, key_id = %k.id, ttl, "harness_door_key_minted");
            json!({"key": k.key, "key_id": k.id.to_string(), "expires_at": k.expires_at.to_rfc3339()})
        }
        HarnessOp::DoorKeyRevoke { key_id } => {
            let revoked = crate::service_keys::revoke_door_key(&state.db, &key_id, user).await.map_err(|e| AppError::BadRequest(e.to_string()))?;
            json!({"revoked": revoked})
        }
        HarnessOp::OperatorAlert { kind, target, cooldown_secs, message } => {
            // A harness may raise the alert kinds the loop raises, nothing else.
            if kind != "inference.backend_failover" {
                return Err(AppError::BadRequest(format!("harness rail: alert kind {kind:?} not allowed")).into());
            }
            // The node's text is evidence only: the channel summary and the
            // command come from the gateway's own copy of this alert.
            rt.operator_alert(
                crate::coordinator::backend_failover_alert(&target, message),
                cooldown_secs.clamp(0, 86_400),
            )
            .await;
            json!({})
        }
    };
    let mut body = reply;
    if let Some(obj) = body.as_object_mut() {
        obj.insert("ok".into(), json!(true));
    }
    Ok(Json(body))
}

/// The task a rail op names, if it is this turn's: same conversation, same
/// person. Anything else is refused — a token reaches only its own task.
async fn turn_task(state: &AppState, task_id: &str, conv: &str, user: &str) -> Result<crate::tasks::Task, AppError> {
    let task = crate::tasks::get(&state.db, task_id).await.map_err(|e| AppError::Internal(e.to_string()))?;
    task.filter(|t| t.conversation_id == conv && t.owner.as_deref() == Some(user))
        .ok_or_else(|| AppError::Forbidden("harness rail: that task is not this turn's".into()))
}

/// How long a door key may live: until the turn's token expires, and never
/// longer than one turn deadline. `None` when the token is already past its
/// expiry (nothing to mint for).
pub(crate) fn door_key_ttl(token_exp: u64, now: u64, deadline_secs: u64) -> Option<u64> {
    let remaining = token_exp.checked_sub(now).filter(|r| *r > 0)?;
    Some(remaining.min(deadline_secs.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PINNED: a door key never outlives the token it was minted under, and
    /// never lives longer than one turn deadline.
    #[test]
    fn a_door_key_never_outlives_the_turn() {
        assert_eq!(door_key_ttl(1_000 + 960, 1_000, 900), Some(900), "capped at the deadline");
        assert_eq!(door_key_ttl(1_000 + 120, 1_000, 900), Some(120), "capped at the token");
        assert_eq!(door_key_ttl(1_000, 1_000, 900), None, "an expiring token mints nothing");
        assert_eq!(door_key_ttl(999, 1_000, 900), None, "an expired token mints nothing");
        for exp in [1_001u64, 1_500, 5_000, u64::MAX] {
            let ttl = door_key_ttl(exp, 1_000, 900).unwrap();
            assert!(ttl <= 900 && 1_000 + ttl <= exp, "{exp}: {ttl}");
        }
    }

    /// The closed cloud gate on the rail is 403 with the shared body; any
    /// other cloud failure stays the 400 it always was.
    #[tokio::test]
    async fn cloud_run_gate_refusal_is_403_other_errors_stay_400() {
        let gate = anyhow::Error::new(crate::coordinator::CloudGateClosed("Cloud models are off: x"))
            .context("rail");
        let resp = cloud_run_error(gate).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "cloud_providers_disabled");
        assert_eq!(v["setting"], "CLOUD_PROVIDERS_ENABLED");

        let other = cloud_run_error(anyhow::anyhow!("ANTHROPIC_API_KEY not configured")).into_response();
        assert_eq!(other.status(), StatusCode::BAD_REQUEST);
    }
}
