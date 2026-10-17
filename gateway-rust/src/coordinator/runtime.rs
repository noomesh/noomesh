// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The runtime seam.
//!
//! Everything the agent loop consumes from the cluster — sessions,
//! context layers, backend resolution, tool execution, the side effects
//! of a turn — named once, as a trait. The loop in `agent_loop.rs` is
//! written against this trait and nothing else; it no longer reaches
//! into `AppState`.
//!
//! Phase A ships one implementation, [`InProcessRuntime`], which is the
//! gateway's own: every method delegates to the function the loop called
//! before, so behaviour is unchanged. Phase B adds a remote
//! implementation over the gateway's HTTP API and NATS, and phase C runs
//! the loop with that implementation inside a container placed on the
//! node that holds the model. The acceptance test for this seam is the
//! one the design named: could the loop leave the process without the
//! runtime noticing?
//!
//! Granularity is the granularity the code already had. Where the loop
//! called `fetch_rag_context(&state.nats, …)`, the trait has
//! `rag_context`; where it ran three SQL statements through
//! `session::save_message`, the trait has `save_message`. Nothing here is
//! a new abstraction over the cluster — it is the list of what the loop
//! actually asks for, measured.
//!
//! `async fn` in traits is used directly (stable since 1.75). The loop is
//! generic over `R: HarnessRuntime` rather than `dyn`, so the futures stay
//! unboxed and `Send` is checked at each concrete instantiation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

use crate::session::Session;
use crate::state::AppState;
use crate::tools::{ToolCall, ToolResult};

use super::backend::ResolvedBackend;
use super::CoordinatorResult;

/// What the agent loop needs from the world it runs in.
#[allow(async_fn_in_trait)]
pub(crate) trait HarnessRuntime: Sync {
    // ── configuration ──────────────────────────────────────────────────

    /// `coordinator.max_context_tokens`; `None` = derive from the model's
    /// context window.
    fn max_context_tokens(&self) -> Option<u32>;
    /// `coordinator.max_session_messages`.
    fn max_session_messages(&self) -> usize;
    /// `self_identity.preferred_skills` from the live YAML.
    async fn preferred_skills(&self) -> Vec<String>;
    /// Per-layer latency and size counters.
    fn metrics(&self) -> &Arc<crate::metrics::MetricsState>;

    // ── the model ──────────────────────────────────────────────────────

    async fn user_model_preference(&self, user_id: &str) -> Option<String>;
    async fn detect_model_from_prompt(&self, prompt: &str) -> Option<String>;
    async fn resolve_backend_for_model(&self, model: Option<&str>) -> Result<ResolvedBackend>;
    async fn resolve_backend_excluding(&self, model: Option<&str>, exclude_urls: &[String]) -> Result<ResolvedBackend>;
    /// A cloud model, single turn, no tools. NOT the loop's path: the loop
    /// resolves a cloud model to a cloud backend and runs it with tools
    /// (i83 phase C). Kept for the harness rail's `CloudRun` op.
    async fn run_cloud_completion(&self, prompt: &str, conversation_id: &str, channel: &str, model: &str) -> Result<CoordinatorResult>;

    // ── the session ────────────────────────────────────────────────────

    async fn load_session(&self, conversation_id: &str, channel: &str) -> Session;
    async fn cache_session(&self, conversation_id: &str, session: Session);
    async fn save_message(&self, conversation_id: &str, role: &str, content: &str, metadata: Option<&Value>, user_id: Option<&str>) -> Result<()>;
    async fn update_conversation_metadata(&self, conversation_id: &str, metadata: &Value) -> Result<()>;
    /// The conversation's message count, used as the turn number.
    async fn turn_number(&self, conversation_id: &str) -> u32;

    // ── context layers ─────────────────────────────────────────────────

    async fn persona_prompt(&self) -> String;
    async fn cluster_awareness(&self) -> String;
    async fn rag_context(&self, prompt: &str, user_id: Option<&str>) -> Option<String>;
    async fn memory_context(&self, prompt: &str, user_id: Option<&str>) -> Option<String>;
    async fn cross_channel_context(&self, prompt: &str, channel: &str, user_id: Option<&str>) -> Option<String>;
    async fn video_context(&self, prompt: &str) -> Option<String>;
    async fn companion_context(&self) -> Option<String>;
    fn prompt_skills_context(&self, prompt: &str, preferred: &[String]) -> Option<(String, Vec<String>)>;
    fn runbook_context(&self, prompt: &str) -> Option<String>;
    async fn temporal_context(&self, user_id: Option<&str>, timeout: Duration) -> Option<String>;
    async fn running_summary(&self, conversation_id: &str) -> Option<String>;
    async fn conversation_recall(&self, conversation_id: &str, query: &str, top_k: u32) -> Option<String>;

    // ── tools ──────────────────────────────────────────────────────────

    /// The full native catalog (the loop selects from it per message).
    async fn tool_schemas(&self) -> Vec<Value>;
    /// External MCP tools this person may see.
    async fn external_tool_schemas(&self, user_id: Option<&str>) -> Vec<Value>;
    /// Run one tool call inside the security bracket (sanitise, classify,
    /// approval gate, audit). The caller sets `mcp_bridge::CALLER`.
    async fn execute_tool(&self, call: &ToolCall) -> ToolResult;

    // ── a turn's side effects ──────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn record_tool_call(&self, conversation_id: &str, tool_name: &str, arguments: &Value, success: bool, output: &str, error: Option<&str>, elapsed_ms: u64);
    async fn record_retrieval_feedback(&self, conversation_id: &str, tool_name: &str, success: bool);
    async fn record_skill_usage(&self, skill_names: &[String], conversation_id: &str);
    async fn fire_pre_inference_hooks(&self, conversation_id: &str, prompt: &str);
    async fn fire_post_response_hooks(&self, conversation_id: &str, result: &CoordinatorResult);
    async fn tag_conversation_shard(&self, conversation_id: &str);
    async fn fire_temporal_extraction(&self, conversation_id: &str, user_message: &str, assistant_response: &str, user_id: Option<&str>);
    /// Regenerate the running summary in the background when the turn
    /// count says so.
    async fn maybe_regenerate_summary(&self, conversation_id: &str, backend: &ResolvedBackend, current_turn: u32);
    /// Tell the operator something a request survived but should not have
    /// had to (backend failover). Deduplicated per target for `cooldown_secs`.
    /// Structured, like every alert: the summary is general, the evidence
    /// rides in `detail` and is logged, never sent.
    async fn operator_alert(&self, alert: crate::operator_alert::OperatorAlert, cooldown_secs: i64);
}

/// What a task runner needs beyond the loop: the
/// checkpoint between loops. It records progress, reads the task's state
/// back — the model may have called `noo_task_done`, the operator may
/// have stopped it — and, away from the gateway, renews the person's
/// credential so a long task never runs on a stale token.
#[allow(async_fn_in_trait)]
pub(crate) trait TaskRuntime: HarnessRuntime {
    /// Returns the task's state after the checkpoint. `exhausted` ends the
    /// task as failed (loop budget) before reading the state.
    async fn checkpoint(&mut self, task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String>;
    /// The token switch (i83 G), called at the loop boundary BEFORE a loop
    /// starts: may it start? Parks the task when the answer is no.
    async fn budget_check(&mut self, task_id: &str) -> Result<crate::task_budget::BudgetCheck>;
    /// One finished loop's tokens, against the task and in the usage table
    /// with the task id and the backend that served it.
    async fn loop_usage(&mut self, task_id: &str, result: &CoordinatorResult) -> Result<()>;
}

/// The gateway's own runtime: the loop running in the same process as
/// the database pool, the bus client and the caches. Every method is the
/// call the loop made before the seam existed.
pub(crate) struct InProcessRuntime<'a> {
    pub(crate) state: &'a AppState,
}

impl<'a> InProcessRuntime<'a> {
    pub(crate) fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl TaskRuntime for InProcessRuntime<'_> {
    async fn checkpoint(&mut self, task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String> {
        crate::tasks::checkpoint(self.state, task_id, loops, note, exhausted).await
    }

    async fn budget_check(&mut self, task_id: &str) -> Result<crate::task_budget::BudgetCheck> {
        crate::task_budget::check(self.state, task_id).await
    }

    async fn loop_usage(&mut self, task_id: &str, result: &CoordinatorResult) -> Result<()> {
        let Some(task) = crate::tasks::get(&self.state.db, task_id).await? else { return Ok(()) };
        let usage = crate::usage::TaskUsage {
            node_id: result.node.clone(),
            backend: result.backend.clone(),
            model: result.model.clone(),
            source: crate::usage::TASK_SOURCE,
            username: task.owner.clone().unwrap_or_default(),
            harness_kind: None,
            task_id: task.id.clone(),
            prompt_tokens: result.usage.prompt_tokens,
            completion_tokens: result.usage.completion_tokens,
        };
        crate::task_budget::account(&self.state.db, &usage).await.map(|_| ())
    }
}

impl HarnessRuntime for InProcessRuntime<'_> {
    fn max_context_tokens(&self) -> Option<u32> {
        self.state.config.coordinator.max_context_tokens
    }

    fn max_session_messages(&self) -> usize {
        self.state.config.coordinator.max_session_messages as usize
    }

    async fn preferred_skills(&self) -> Vec<String> {
        let yaml = self.state.config_yaml.read().await;
        yaml.get("self_identity")
            .and_then(|si| si.get("preferred_skills"))
            .and_then(|ps| ps.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
            .unwrap_or_default()
    }

    fn metrics(&self) -> &Arc<crate::metrics::MetricsState> {
        &self.state.metrics
    }

    async fn user_model_preference(&self, user_id: &str) -> Option<String> {
        super::backend::fetch_user_model_preference(self.state, user_id).await
    }

    async fn detect_model_from_prompt(&self, prompt: &str) -> Option<String> {
        super::backend::detect_model_from_prompt(self.state, prompt).await
    }

    async fn resolve_backend_for_model(&self, model: Option<&str>) -> Result<ResolvedBackend> {
        super::backend::resolve_backend_for_model(self.state, model).await
    }

    async fn resolve_backend_excluding(&self, model: Option<&str>, exclude_urls: &[String]) -> Result<ResolvedBackend> {
        super::backend::resolve_backend_excluding(self.state, model, exclude_urls).await
    }

    async fn run_cloud_completion(&self, prompt: &str, conversation_id: &str, channel: &str, model: &str) -> Result<CoordinatorResult> {
        super::cloud::run_cloud_completion(self.state, prompt, conversation_id, channel, model).await
    }

    async fn load_session(&self, conversation_id: &str, channel: &str) -> Session {
        super::session::get_or_load_session(self.state, conversation_id, channel).await
    }

    async fn cache_session(&self, conversation_id: &str, session: Session) {
        super::session::cache_session(self.state, conversation_id, session).await
    }

    async fn save_message(&self, conversation_id: &str, role: &str, content: &str, metadata: Option<&Value>, user_id: Option<&str>) -> Result<()> {
        crate::session::save_message(&self.state.db, conversation_id, role, content, metadata, user_id).await
    }

    async fn update_conversation_metadata(&self, conversation_id: &str, metadata: &Value) -> Result<()> {
        crate::session::update_conversation_metadata(&self.state.db, conversation_id, metadata).await
    }

    async fn turn_number(&self, conversation_id: &str) -> u32 {
        sqlx::query_scalar::<_, i32>("SELECT COUNT(*)::int FROM noo_entries WHERE conversation_id = $1::uuid")
            .bind(conversation_id)
            .fetch_one(&self.state.db)
            .await
            .unwrap_or(0)
            .max(0) as u32
    }

    async fn persona_prompt(&self) -> String {
        super::context::load_persona_prompt(self.state).await
    }

    async fn cluster_awareness(&self) -> String {
        super::context::format_cluster_awareness(self.state).await
    }

    async fn rag_context(&self, prompt: &str, user_id: Option<&str>) -> Option<String> {
        super::context::fetch_rag_context(&self.state.nats, prompt, user_id).await
    }

    async fn memory_context(&self, prompt: &str, user_id: Option<&str>) -> Option<String> {
        // A shared room never gets one member's personal memory.
        if super::in_shared_room() {
            return None;
        }
        super::context::fetch_memory_context(&self.state.nats, prompt, user_id).await
    }

    async fn cross_channel_context(&self, prompt: &str, channel: &str, user_id: Option<&str>) -> Option<String> {
        if super::in_shared_room() {
            return None;
        }
        super::context::fetch_cross_channel_context(&self.state.nats, prompt, channel, user_id).await
    }

    async fn video_context(&self, prompt: &str) -> Option<String> {
        super::context::fetch_video_context(&self.state.nats, prompt).await
    }

    async fn companion_context(&self) -> Option<String> {
        super::context::fetch_companion_context(self.state).await
    }

    fn prompt_skills_context(&self, prompt: &str, preferred: &[String]) -> Option<(String, Vec<String>)> {
        super::context::fetch_prompt_skills_context(&self.state.prompt_skills, prompt, preferred)
    }

    fn runbook_context(&self, prompt: &str) -> Option<String> {
        super::context::select_runbook_context(&self.state.runbooks, prompt)
    }

    async fn temporal_context(&self, user_id: Option<&str>, timeout: Duration) -> Option<String> {
        // Per-user preferences and decisions: personal, so not in a shared room.
        if super::in_shared_room() {
            return None;
        }
        crate::temporal_graph::fetch_temporal_context_timeout(&self.state.db, user_id, timeout).await
    }

    async fn running_summary(&self, conversation_id: &str) -> Option<String> {
        super::summary::fetch_running_summary(&self.state.db, conversation_id).await
    }

    async fn conversation_recall(&self, conversation_id: &str, query: &str, top_k: u32) -> Option<String> {
        super::context::fetch_conversation_recall(self.state, conversation_id, query, top_k).await
    }

    async fn tool_schemas(&self) -> Vec<Value> {
        self.state.tool_schemas.read().await.clone()
    }

    async fn external_tool_schemas(&self, user_id: Option<&str>) -> Vec<Value> {
        crate::mcp_bridge::llm_schemas_for(self.state, user_id).await
    }

    async fn execute_tool(&self, call: &ToolCall) -> ToolResult {
        crate::tools::execute_tool(self.state, call).await
    }

    async fn record_tool_call(&self, conversation_id: &str, tool_name: &str, arguments: &Value, success: bool, output: &str, error: Option<&str>, elapsed_ms: u64) {
        super::agent_loop::record_tool_call(self.state, conversation_id, tool_name, arguments, success, output, error, elapsed_ms).await
    }

    async fn record_retrieval_feedback(&self, conversation_id: &str, tool_name: &str, success: bool) {
        super::agent_loop::record_retrieval_feedback(self.state, conversation_id, tool_name, success).await
    }

    async fn record_skill_usage(&self, skill_names: &[String], conversation_id: &str) {
        super::agent_loop::record_skill_usage(self.state, skill_names, conversation_id).await
    }

    async fn fire_pre_inference_hooks(&self, conversation_id: &str, prompt: &str) {
        super::agent_loop::fire_pre_inference_hooks(self.state, conversation_id, prompt).await
    }

    async fn fire_post_response_hooks(&self, conversation_id: &str, result: &CoordinatorResult) {
        super::agent_loop::fire_post_response_hooks(self.state, conversation_id, result).await
    }

    async fn tag_conversation_shard(&self, conversation_id: &str) {
        super::summary::tag_conversation_shard(self.state, conversation_id).await
    }

    async fn fire_temporal_extraction(&self, conversation_id: &str, user_message: &str, assistant_response: &str, user_id: Option<&str>) {
        super::summary::fire_temporal_extraction(self.state, conversation_id, user_message, assistant_response, user_id).await
    }

    async fn maybe_regenerate_summary(&self, conversation_id: &str, backend: &ResolvedBackend, current_turn: u32) {
        if super::summary::should_regenerate_summary(&self.state.db, conversation_id, current_turn).await {
            let db = self.state.db.clone();
            let conv_id = conversation_id.to_string();
            let url = backend.url.clone();
            let model = backend.model.clone();
            tokio::spawn(async move {
                super::summary::generate_running_summary(db, url, model, conv_id, current_turn).await;
            });
        }
    }

    async fn operator_alert(&self, alert: crate::operator_alert::OperatorAlert, cooldown_secs: i64) {
        crate::operator_alert::send_operator_alert_detached_with(self.state, alert, cooldown_secs).await;
    }
}

#[cfg(test)]
mod tests {
    /// PINNED (the design's acceptance test): the
    /// loop is written against `HarnessRuntime` and nothing else. Neither
    /// loop body nor the send-with-fallback path may name `state` or
    /// `AppState` — every cluster capability they use goes through the
    /// trait, so a second implementation can take the loop out of the
    /// process without touching it.
    #[test]
    fn the_loop_never_reaches_app_state() {
        let src = include_str!("agent_loop.rs");
        let sealed = ["run_streaming_on", "run_inner", "send_llm_with_fallback"];
        let mut current: Option<&str> = None;
        let mut offenders = Vec::new();
        for (i, line) in src.lines().enumerate() {
            if let Some(rest) = line.trim_start().strip_prefix("pub(crate) async fn ").or_else(|| line.trim_start().strip_prefix("pub async fn ")).or_else(|| line.trim_start().strip_prefix("async fn ")).or_else(|| line.trim_start().strip_prefix("fn ")) {
                let name = rest.split(['<', '(']).next().unwrap_or("");
                current = sealed.iter().copied().find(|s| *s == name);
                continue;
            }
            if let Some(f) = current {
                let code = line.split("//").next().unwrap_or("");
                let names_state = code.contains("AppState")
                    || code.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "state");
                if names_state {
                    offenders.push(format!("{f} line {}: {}", i + 1, line.trim()));
                }
            }
        }
        assert!(offenders.is_empty(), "the loop reached into AppState:\n{}", offenders.join("\n"));
        // And the scan actually covered the three functions.
        for s in sealed {
            assert!(src.contains(&format!("fn {s}<R: HarnessRuntime")), "{s} is not generic over the runtime");
        }
    }
}
