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
            "skills": state.prompt_skills.list_all(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
