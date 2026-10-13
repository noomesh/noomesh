// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The remote runtime: the agent loop's view of the
//! cluster from a process that is NOT the gateway.
//!
//! Every [`HarnessRuntime`] method becomes one [`HarnessOp`] posted to
//! `POST {gateway}/api/harness/call` under the turn's harness token. The
//! gateway runs the op through its own in-process runtime and answers;
//! this side only serialises and deserialises. There is no database pool,
//! no bus client, no Redis here — a node-hosted harness holds the model
//! endpoint, the gateway URL, and a token good for one conversation.
//!
//! Degradation matches the in-process runtime: a context layer that
//! cannot be fetched is `None` and the turn proceeds without it; a
//! side effect that fails is logged and dropped. Session load is the
//! exception — losing history silently is worse than failing the turn,
//! so a failed load surfaces as an error the caller sees.
//!
//! `cache_session` is a no-op: the per-process LRU is the gateway's, and
//! the ownership key is claimed on the gateway side by the
//! `session_load` op, so two processes never serve one conversation from
//! stale copies.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::session::Session;
use crate::tools::{ToolCall, ToolResult};

use super::backend::ResolvedBackend;
use super::rail::HarnessOp;
use super::runtime::HarnessRuntime;
use super::CoordinatorResult;

/// How long a single rail call may take. Tool execution can legitimately
/// wait on an approval (up to `NOO_EXEC_APPROVAL_TIMEOUT_SECS`, max 3600),
/// so this is generous; every other op returns in well under a second.
const RAIL_TIMEOUT: Duration = Duration::from_secs(3700);

pub struct RemoteRuntime {
    gateway: String,
    token: String,
    client: reqwest::Client,
    metrics: Arc<crate::metrics::MetricsState>,
    /// Loaded once from the `config` op; the loop asks for these
    /// synchronously.
    max_context_tokens: Option<u32>,
    max_session_messages: usize,
    /// The prompt-skill registry and runbooks, as the gateway shipped them
    /// at connect: selection is the same pure scoring the gateway runs.
    skills: crate::prompt_skills::SkillRegistry,
    runbooks: Vec<(String, String)>,
    /// The model endpoint this harness was placed next to (phase C). When
    /// set, backend resolution never asks the gateway: the harness is
    /// configured to point at ONE endpoint, and a failure there is the
    /// turn's failure — the gateway's fallback runs at dispatch, not here.
    pinned: Option<ResolvedBackend>,
}

impl RemoteRuntime {
    /// Connect to `gateway` (scheme + host + port, no path) with the turn's
    /// harness token, and fetch the loop's configuration once. `client`
    /// carries the cluster CA (`crate::tls::cluster_client()` on a node
    /// with `NOO_TLS_CA` set).
    pub async fn connect(gateway: &str, token: &str, client: reqwest::Client) -> Result<Self> {
        let mut rt = Self {
            gateway: gateway.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
            metrics: Arc::new(crate::metrics::MetricsState::new()),
            max_context_tokens: None,
            max_session_messages: 100,
            skills: crate::prompt_skills::SkillRegistry::default(),
            runbooks: Vec::new(),
            pinned: None,
        };
        let cfg = rt.call(HarnessOp::Config).await?;
        rt.max_context_tokens = cfg.get("max_context_tokens").and_then(|v| v.as_u64()).map(|v| v as u32);
        rt.max_session_messages = cfg.get("max_session_messages").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
        // The catalogs: a gateway that cannot ship them (an older one, a
        // transient failure) leaves the loop without those two layers, as
        // before — logged, not fatal.
        match rt.call(HarnessOp::Catalogs).await {
            Ok(v) => {
                let skills: Vec<crate::prompt_skills::PromptSkill> = Self::field(&v, "skills").unwrap_or_default();
                let runbooks: Vec<(String, String)> = Self::field(&v, "runbooks").unwrap_or_default();
                tracing::info!(skills = skills.len(), runbooks = runbooks.len(), "harness: catalogs received");
                rt.skills = crate::prompt_skills::SkillRegistry::from_skills(skills);
                rt.runbooks = runbooks;
            }
            Err(e) => tracing::warn!(error = %e, "harness: no catalogs from the gateway; skills and runbooks layers off"),
        }
        Ok(rt)
    }

    /// Point every turn at `backend` instead of asking the gateway.
    pub fn pin_backend(mut self, backend: ResolvedBackend) -> Self {
        self.pinned = Some(backend);
        self
    }

    /// One rail call. Non-2xx and non-JSON answers are errors; the body's
    /// `error` field, when the gateway sent one, is the message.
    pub async fn call(&self, op: HarnessOp) -> Result<Value> {
        let name = op.name();
        let resp = self
            .client
            .post(format!("{}/api/harness/call", self.gateway))
            .bearer_auth(&self.token)
            .timeout(RAIL_TIMEOUT)
            .json(&op)
            .send()
            .await
            .map_err(|e| anyhow!("harness rail {name}: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = body.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string();
            return Err(anyhow!("harness rail {name}: HTTP {} {msg}", status.as_u16()));
        }
        Ok(body)
    }

    async fn text(&self, op: HarnessOp) -> Option<String> {
        match self.call(op).await {
            Ok(v) => v.get("text").and_then(|t| t.as_str()).map(str::to_string),
            Err(e) => {
                tracing::warn!(error = %e, "harness rail: context layer unavailable");
                None
            }
        }
    }

    async fn fire(&self, op: HarnessOp) {
        if let Err(e) = self.call(op).await {
            tracing::warn!(error = %e, "harness rail: side effect dropped");
        }
    }

    fn field<T: serde::de::DeserializeOwned>(v: &Value, key: &str) -> Result<T> {
        let inner = v.get(key).ok_or_else(|| anyhow!("harness rail: reply lacks {key:?}"))?;
        serde_json::from_value(inner.clone()).map_err(|e| anyhow!("harness rail: {key}: {e}"))
    }
}

impl super::runtime::TaskRuntime for RemoteRuntime {
    async fn checkpoint(&mut self, task_id: &str, loops: u32, note: Option<&str>, exhausted: bool) -> Result<String> {
        let v = self
            .call(HarnessOp::TaskCheckpoint { task_id: task_id.to_string(), loops, note: note.map(str::to_string), exhausted })
            .await?;
        // Decision 1: the task keeps acting as the person
        // on a credential the gateway renews at every checkpoint.
        if let Some(t) = v.get("token").and_then(|t| t.as_str()).filter(|t| !t.is_empty()) {
            self.token = t.to_string();
        }
        Self::field(&v, "state")
    }
}

impl HarnessRuntime for RemoteRuntime {
    fn max_context_tokens(&self) -> Option<u32> {
        self.max_context_tokens
    }

    fn max_session_messages(&self) -> usize {
        self.max_session_messages
    }

    async fn preferred_skills(&self) -> Vec<String> {
        match self.call(HarnessOp::Config).await {
            Ok(v) => Self::field(&v, "preferred_skills").unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    fn metrics(&self) -> &Arc<crate::metrics::MetricsState> {
        &self.metrics
    }

    async fn user_model_preference(&self, _user_id: &str) -> Option<String> {
        // The person is the token's subject; the gateway resolves it.
        self.call(HarnessOp::ModelPreference).await.ok().and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
    }

    async fn detect_model_from_prompt(&self, prompt: &str) -> Option<String> {
        self.call(HarnessOp::DetectModel { prompt: prompt.to_string() }).await.ok().and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
    }

    async fn resolve_backend_for_model(&self, model: Option<&str>) -> Result<ResolvedBackend> {
        self.resolve_backend_excluding(model, &[]).await
    }

    async fn resolve_backend_excluding(&self, model: Option<&str>, exclude_urls: &[String]) -> Result<ResolvedBackend> {
        if let Some(pinned) = &self.pinned {
            if exclude_urls.contains(&pinned.url) {
                anyhow::bail!("harness: the placed model endpoint {} failed and a harness has no other", pinned.url);
            }
            return Ok(pinned.clone());
        }
        let v = self.call(HarnessOp::ResolveBackend { model: model.map(str::to_string), exclude_urls: exclude_urls.to_vec() }).await?;
        Self::field(&v, "backend")
    }

    async fn run_cloud_completion(&self, prompt: &str, _conversation_id: &str, channel: &str, model: &str) -> Result<CoordinatorResult> {
        let v = self.call(HarnessOp::CloudRun { prompt: prompt.to_string(), channel: channel.to_string(), model: model.to_string() }).await?;
        Self::field(&v, "result")
    }

    async fn load_session(&self, conversation_id: &str, channel: &str) -> Session {
        match self.call(HarnessOp::SessionLoad { channel: channel.to_string() }).await.and_then(|v| Self::field::<Session>(&v, "session")) {
            Ok(s) => s,
            Err(e) => {
                // Same degradation as the in-process path on a DB miss: a
                // fresh session — but say so loudly, because here it means
                // the rail failed, not that the conversation is new.
                tracing::error!(error = %e, conversation = conversation_id, "harness rail: session load failed; starting the turn without history");
                Session::new(conversation_id.to_string(), channel.to_string())
            }
        }
    }

    async fn cache_session(&self, _conversation_id: &str, _session: Session) {}

    async fn save_message(&self, _conversation_id: &str, role: &str, content: &str, metadata: Option<&Value>, _user_id: Option<&str>) -> Result<()> {
        self.call(HarnessOp::SessionSave { role: role.to_string(), content: content.to_string(), metadata: metadata.cloned() }).await.map(|_| ())
    }

    async fn update_conversation_metadata(&self, _conversation_id: &str, metadata: &Value) -> Result<()> {
        self.call(HarnessOp::SessionMetadata { metadata: metadata.clone() }).await.map(|_| ())
    }

    async fn turn_number(&self, _conversation_id: &str) -> u32 {
        self.call(HarnessOp::TurnNumber).await.ok().and_then(|v| v.get("turn").and_then(|t| t.as_u64())).unwrap_or(0) as u32
    }

    async fn persona_prompt(&self) -> String {
        self.text(HarnessOp::Persona).await.unwrap_or_default()
    }

    async fn cluster_awareness(&self) -> String {
        self.text(HarnessOp::ClusterAwareness).await.unwrap_or_default()
    }

    async fn rag_context(&self, prompt: &str, _user_id: Option<&str>) -> Option<String> {
        self.text(HarnessOp::Rag { prompt: prompt.to_string() }).await
    }

    async fn memory_context(&self, prompt: &str, _user_id: Option<&str>) -> Option<String> {
        self.text(HarnessOp::Memory { prompt: prompt.to_string() }).await
    }

    async fn cross_channel_context(&self, prompt: &str, channel: &str, _user_id: Option<&str>) -> Option<String> {
        self.text(HarnessOp::CrossChannel { prompt: prompt.to_string(), channel: channel.to_string() }).await
    }

    async fn video_context(&self, prompt: &str) -> Option<String> {
        self.text(HarnessOp::Video { prompt: prompt.to_string() }).await
    }

    async fn companion_context(&self) -> Option<String> {
        self.text(HarnessOp::Companion).await
    }

    fn prompt_skills_context(&self, prompt: &str, preferred: &[String]) -> Option<(String, Vec<String>)> {
        // The same selection the gateway runs, over the catalog it shipped
        // at connect. Usage is recorded through the `skill_usage` op.
        super::context::fetch_prompt_skills_context(&self.skills, prompt, preferred)
    }

    fn runbook_context(&self, prompt: &str) -> Option<String> {
        super::context::select_runbook_context(&self.runbooks, prompt)
    }

    async fn temporal_context(&self, _user_id: Option<&str>, timeout: Duration) -> Option<String> {
        self.text(HarnessOp::Temporal { timeout_ms: timeout.as_millis() as u64 }).await
    }

    async fn running_summary(&self, _conversation_id: &str) -> Option<String> {
        self.text(HarnessOp::RunningSummary).await
    }

    async fn conversation_recall(&self, _conversation_id: &str, query: &str, top_k: u32) -> Option<String> {
        self.text(HarnessOp::Recall { query: query.to_string(), top_k }).await
    }

    async fn tool_schemas(&self) -> Vec<Value> {
        self.call(HarnessOp::ToolSchemas).await.ok().and_then(|v| Self::field(&v, "native").ok()).unwrap_or_default()
    }

    async fn external_tool_schemas(&self, _user_id: Option<&str>) -> Vec<Value> {
        self.call(HarnessOp::ToolSchemas).await.ok().and_then(|v| Self::field(&v, "external").ok()).unwrap_or_default()
    }

    async fn execute_tool(&self, call: &ToolCall) -> ToolResult {
        match self.call(HarnessOp::ExecuteTool { call: call.clone() }).await.and_then(|v| Self::field::<ToolResult>(&v, "result")) {
            Ok(r) => r,
            Err(e) => ToolResult {
                name: call.name.clone(),
                tool_call_id: call.id.clone(),
                success: false,
                output: String::new(),
                error: Some(format!("harness rail: {e}")),
            },
        }
    }

    async fn record_tool_call(&self, _conversation_id: &str, tool_name: &str, arguments: &Value, success: bool, output: &str, error: Option<&str>, elapsed_ms: u64) {
        self.fire(HarnessOp::RecordToolCall {
            tool_name: tool_name.to_string(),
            arguments: arguments.clone(),
            success,
            output: output.chars().take(2000).collect(),
            error: error.map(str::to_string),
            elapsed_ms,
        })
        .await
    }

    async fn record_retrieval_feedback(&self, _conversation_id: &str, tool_name: &str, success: bool) {
        self.fire(HarnessOp::RetrievalFeedback { tool_name: tool_name.to_string(), success }).await
    }

    async fn record_skill_usage(&self, skill_names: &[String], _conversation_id: &str) {
        self.fire(HarnessOp::SkillUsage { names: skill_names.to_vec() }).await
    }

    async fn fire_pre_inference_hooks(&self, _conversation_id: &str, prompt: &str) {
        self.fire(HarnessOp::PreHooks { prompt: prompt.to_string() }).await
    }

    async fn fire_post_response_hooks(&self, _conversation_id: &str, result: &CoordinatorResult) {
        self.fire(HarnessOp::PostHooks { result: result.clone() }).await
    }

    async fn tag_conversation_shard(&self, _conversation_id: &str) {
        self.fire(HarnessOp::Shard).await
    }

    async fn fire_temporal_extraction(&self, _conversation_id: &str, user_message: &str, assistant_response: &str, _user_id: Option<&str>) {
        self.fire(HarnessOp::TemporalExtract { user_message: user_message.to_string(), assistant_response: assistant_response.to_string() }).await
    }

    async fn maybe_regenerate_summary(&self, _conversation_id: &str, backend: &ResolvedBackend, current_turn: u32) {
        self.fire(HarnessOp::MaybeSummary { backend: backend.clone(), turn: current_turn }).await
    }

    async fn operator_alert(&self, alert: crate::operator_alert::OperatorAlert, cooldown_secs: i64) {
        // Only the evidence crosses the rail: the gateway re-authors the
        // summary and command from `kind` (routes/harness.rs), so a node
        // never writes channel text. The wire field keeps its name so an
        // older gateway still parses the op.
        self.fire(HarnessOp::OperatorAlert { kind: alert.kind, target: alert.target, cooldown_secs, message: alert.detail }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::sync::Mutex;

    /// A stand-in gateway that records every op and the bearer it came
    /// with, and answers a fixed body per op name.
    async fn fake_gateway(seen: Arc<Mutex<Vec<(String, Value)>>>) -> String {
        let app = Router::new().route(
            "/api/harness/call",
            post(move |headers: axum::http::HeaderMap, Json(op): Json<Value>| {
                let seen = seen.clone();
                async move {
                    let bearer = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
                    seen.lock().unwrap().push((bearer, op.clone()));
                    let name = op["op"].as_str().unwrap_or("");
                    Json(match name {
                        "config" => serde_json::json!({"ok": true, "max_context_tokens": 4096, "max_session_messages": 7, "preferred_skills": ["a"]}),
                        "catalogs" => serde_json::json!({"ok": true,
                            "skills": [{"name": "kubernetes-ops", "version": "1", "description": "cluster ops", "author": "t", "tags": ["ops"],
                                        "trigger_keywords": ["kubernetes", "pod"], "priority": 5, "fitness": 0.9, "generation": 0, "is_core": true,
                                        "max_context_chars": 2000, "composable": true, "requires_tools": [], "parent_skill": null,
                                        "content": "Check the pods first.", "file_path": null}],
                            "runbooks": [["nats-messaging", "How the bus works."]]}),
                        "rag" => serde_json::json!({"ok": true, "text": "from the kb"}),
                        "memory" => serde_json::json!({"ok": true, "text": null}),
                        "session_load" => serde_json::json!({"ok": true, "session": {"conversation_id": "c1", "messages": [{"role": "user", "content": "hi"}], "channel": "dashboard", "turn_count": 1}}),
                        "execute_tool" => serde_json::json!({"ok": true, "result": {"name": "web_search", "tool_call_id": "t1", "success": true, "output": "42", "error": null}}),
                        "turn_number" => serde_json::json!({"ok": true, "turn": 9}),
                        _ => serde_json::json!({"ok": true}),
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// PINNED: every runtime call becomes exactly one rail op under the
    /// turn's bearer, identity travels only in the token, and the reply
    /// shapes the gateway sends decode into what the loop expects.
    #[tokio::test]
    async fn remote_runtime_speaks_the_rail() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let url = fake_gateway(seen.clone()).await;
        let rt = RemoteRuntime::connect(&url, "tok-123", reqwest::Client::new()).await.unwrap();
        assert_eq!(rt.max_context_tokens(), Some(4096));
        assert_eq!(rt.max_session_messages(), 7);
        // The catalogs arrived and select LOCALLY — no rail call per layer.
        let (skills_text, names) = rt.prompt_skills_context("how do I restart a kubernetes pod", &[]).expect("a skill matched");
        assert_eq!(names, vec!["kubernetes-ops".to_string()]);
        assert!(skills_text.contains("Check the pods first."));
        assert!(rt.runbook_context("publish on nats").unwrap().contains("How the bus works."));
        assert!(rt.runbook_context("the weather").is_none());

        assert_eq!(rt.rag_context("q", Some("alice")).await.as_deref(), Some("from the kb"));
        assert_eq!(rt.memory_context("q", Some("alice")).await, None);
        let s = rt.load_session("c1", "dashboard").await;
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.turn_count, 1);
        let r = rt.execute_tool(&ToolCall { id: "t1".into(), name: "web_search".into(), arguments: serde_json::json!({"query": "x"}) }).await;
        assert!(r.success && r.output == "42");
        assert_eq!(rt.turn_number("c1").await, 9);
        rt.record_retrieval_feedback("c1", "web_search", true).await;

        let calls = seen.lock().unwrap().clone();
        assert!(calls.iter().all(|(b, _)| b == "Bearer tok-123"));
        let names: Vec<&str> = calls.iter().map(|(_, op)| op["op"].as_str().unwrap()).collect();
        assert_eq!(names, ["config", "catalogs", "rag", "memory", "session_load", "execute_tool", "turn_number", "retrieval_feedback"]);
        for (_, op) in &calls {
            let text = op.to_string();
            assert!(!text.contains("alice") && !text.contains("\"c1\""), "identity in the body: {text}");
        }
    }

    #[tokio::test]
    async fn a_failed_tool_call_is_a_failed_result_not_a_panic() {
        let rt = RemoteRuntime {
            gateway: "http://127.0.0.1:9".into(), // nothing listens
            token: "t".into(),
            client: reqwest::Client::new(),
            metrics: Arc::new(crate::metrics::MetricsState::new()),
            max_context_tokens: None,
            max_session_messages: 1,
            skills: crate::prompt_skills::SkillRegistry::default(),
            runbooks: Vec::new(),
            pinned: None,
        };
        let r = rt.execute_tool(&ToolCall { id: "1".into(), name: "x".into(), arguments: Value::Null }).await;
        assert!(!r.success);
        assert!(r.error.unwrap().starts_with("harness rail:"));
        assert_eq!(rt.rag_context("q", None).await, None);
    }

    #[tokio::test]
    async fn a_pinned_backend_never_asks_the_gateway_and_has_no_fallback() {
        let pinned = ResolvedBackend { url: "http://noo-llamacpp:8085".into(), model: "qwen".into(), backend_type: "llamacpp".into(), api_format: "llamacpp".into() };
        let rt = RemoteRuntime {
            gateway: "http://127.0.0.1:9".into(),
            token: "t".into(),
            client: reqwest::Client::new(),
            metrics: Arc::new(crate::metrics::MetricsState::new()),
            max_context_tokens: None,
            max_session_messages: 1,
            skills: crate::prompt_skills::SkillRegistry::default(),
            runbooks: Vec::new(),
            pinned: None,
        }
        .pin_backend(pinned.clone());
        assert_eq!(rt.resolve_backend_for_model(Some("anything")).await.unwrap(), pinned);
        assert!(rt.resolve_backend_excluding(None, std::slice::from_ref(&pinned.url)).await.is_err());
    }
}
