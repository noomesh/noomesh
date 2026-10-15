// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Coordinator agent — the primary agentic loop.
//!
//! Full coordinator implementation matching Python's CoordinatorAgent:
//! - Backend resolution (gossip → mesh → KV, with retry)
//! - Multi-format LLM calls (OpenAI, Ollama /api/chat, llamacpp /completion)
//! - RAG + memory context injection via NATS workers (graceful degradation)
//! - Keyword-based tool schema selection
//! - Streaming via WebSocket + non-streaming REST entry points
//! - Conversation metadata tracking (tokens, latency, tool counts)
//! - Persona support (system prompt from file, NATS KV, or config)
//! - Context window fitting
//! - Think-block stripping before persistence
//!
//! Resolution chain (fastest → slowest):
//!   1. Gossip peer table (local dict, 0ms)
//!   2. Mesh discovery via NATS request/reply (~50ms)
//!   3. NATS KV registry (~20ms)
//!
//! ML-dependent operations (RAG, memory, embeddings) are delegated to
//! Python workers via NATS. If workers are down, the coordinator proceeds
//! in degraded mode (no context injection but still functional).

mod agent_loop;
mod backend;
pub mod classes;
mod cloud;
mod context;
mod dispatch;
mod rail;
mod remote;
mod runtime;
mod session;
mod summary;

// Public API — preserves the pre-split `crate::coordinator::X` paths.
// (`allow(unused_imports)`: some re-exports are reachable-but-unreferenced
// right now; they existed as `pub`/`pub(crate)` items pre-split and the
// paths are kept stable.)
#[allow(unused_imports)]
pub use agent_loop::{run, run_streaming, run_with_thinking, CoordinatorResult, UsageStats, run_with_role};
pub use agent_loop::backend_failover_alert;
pub(crate) use agent_loop::{MAX_LLM_BACKEND_ATTEMPTS, BACKEND_FAILOVER_ALERT_COOLDOWN_SECS};
pub(crate) use backend::is_retryable_llm_http_error;
#[cfg(test)]
pub(crate) use backend::ModelNotServed;
pub(crate) use backend::non_chat_backends;
pub use backend::{backend_model_not_found, resolve_failure_status, resolve_backend, resolve_backend_for_model, get_tool_nats_subject, local_backend_url, ResolvedBackend};
pub use session::{evict_stale_sessions};
#[allow(unused_imports)]
pub(crate) use runtime::{HarnessRuntime, InProcessRuntime, TaskRuntime};
#[allow(unused_imports)]
pub(crate) use rail::HarnessOp;
#[allow(unused_imports)]
pub(crate) use dispatch::{harness_default_policy, harness_node_explained, harness_node_for, harness_run_subject, node_request, role_of, turn_deadline, TurnRequest};
#[allow(unused_imports)]
pub(crate) use agent_loop::{run_inner, run_streaming_on};
#[allow(unused_imports)]
pub(crate) use backend::api_format_for;
#[allow(unused_imports)]
pub(crate) use backend::model_hint;
#[allow(unused_imports)]
pub(crate) use remote::RemoteRuntime;
#[allow(unused_imports)]
pub(crate) use agent_loop::{StreamedResponse, collect_streaming_response, looks_like_malformed_tool_call, strip_think_blocks, verify_no_scheduling_hallucination};
pub(crate) use backend::{is_node_agent_url, with_backend_hint_url, warn_if_node_agent_outdated, node_from_backend_url};

// Intra-module shared items, surfaced here so sibling files can reach
// them via `use super::*` (private to this module tree).
use backend::{is_cloud_model, with_backend_hint};
use context::{dedup_context_lines, record_layer_chars, time_layer};
use session::{build_history_summary};

pub use cloud::{cloud_gate, cloud_gate_body, cloud_gate_refusal};
#[cfg(test)]
pub use cloud::CloudGateClosed;

/// Run a cloud-model completion (Anthropic / OpenAI / Gemini).
///
/// Public wrapper over `cloud::run_cloud_completion`, which is `pub(super)`.
/// Exposed so route handlers can reach the same provider clients the agent
/// loop uses, instead of delegating cloud work elsewhere.
pub async fn run_cloud(
    state: &crate::state::AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    model: &str,
) -> anyhow::Result<serde_json::Value> {
    let result = cloud::run_cloud_completion(state, prompt, conversation_id, channel, model).await?;
    Ok(serde_json::json!({
        "response": result.response,
        "model": result.model,
        "conversation_id": conversation_id,
        "engine": "rust-cloud",
    }))
}
