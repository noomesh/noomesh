// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness rail's vocabulary.
//!
//! One operation per [`HarnessRuntime`](super::HarnessRuntime) method that
//! needs the cluster, carried as `{"op": "...", ...}` to a single route,
//! `POST /api/harness/call`. The gateway side (`routes::harness`) turns an
//! op into the in-process runtime call; the node side
//! (`coordinator::remote::RemoteRuntime`) turns a runtime call into an op.
//! Both use this enum, so the two cannot drift.
//!
//! Two things are deliberately NOT in any op: the conversation and the
//! user. Both come from the harness token (`Claims::conv`, `sub`), which
//! the gateway minted for exactly one turn. A harness cannot name another
//! conversation or another person, whatever it puts in the body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::backend::ResolvedBackend;
use super::CoordinatorResult;
use crate::tools::ToolCall;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HarnessOp {
    // configuration
    Config,
    /// The boot-loaded catalogs a loop selects from per message: prompt
    /// skills and runbooks. Fetched once when a remote runtime connects.
    Catalogs,
    // the model
    ModelPreference,
    DetectModel { prompt: String },
    ResolveBackend { model: Option<String>, #[serde(default)] exclude_urls: Vec<String> },
    CloudRun { prompt: String, channel: String, model: String },
    // the session
    SessionLoad { channel: String },
    SessionSave { role: String, content: String, #[serde(default)] metadata: Option<Value> },
    SessionMetadata { metadata: Value },
    TurnNumber,
    // context layers
    Persona,
    ClusterAwareness,
    Rag { prompt: String },
    Memory { prompt: String },
    CrossChannel { prompt: String, channel: String },
    Video { prompt: String },
    Companion,
    Skills { prompt: String, #[serde(default)] preferred: Vec<String> },
    Runbook { prompt: String },
    Temporal { timeout_ms: u64 },
    RunningSummary,
    Recall { query: String, top_k: u32 },
    // tools
    ToolSchemas,
    ExecuteTool { call: ToolCall },
    // a turn's side effects
    RecordToolCall { tool_name: String, arguments: Value, success: bool, output: String, #[serde(default)] error: Option<String>, elapsed_ms: u64 },
    RetrievalFeedback { tool_name: String, success: bool },
    SkillUsage { names: Vec<String> },
    PreHooks { prompt: String },
    PostHooks { result: CoordinatorResult },
    Shard,
    TemporalExtract { user_message: String, assistant_response: String },
    MaybeSummary { backend: ResolvedBackend, turn: u32 },
    /// `message` is the alert's evidence (its `detail`) — logged, never
    /// rendered. The gateway authors the channel text from `kind`.
    OperatorAlert { kind: String, target: String, cooldown_secs: i64, message: String },
    // a task's loops
    TaskCheckpoint { task_id: String, loops: u32, #[serde(default)] note: Option<String>, #[serde(default)] exhausted: bool },
}

impl HarnessOp {
    /// Every wire name, in declaration order. Pinned to the `name()` match
    /// by a test, and to `docs/reference/harness-protocol.md` by another.
    pub const ALL_NAMES: &'static [&'static str] = &[
        "config",
        "catalogs",
        "model_preference",
        "detect_model",
        "resolve_backend",
        "cloud_run",
        "session_load",
        "session_save",
        "session_metadata",
        "turn_number",
        "persona",
        "cluster_awareness",
        "rag",
        "memory",
        "cross_channel",
        "video",
        "companion",
        "skills",
        "runbook",
        "temporal",
        "running_summary",
        "recall",
        "tool_schemas",
        "execute_tool",
        "record_tool_call",
        "retrieval_feedback",
        "skill_usage",
        "pre_hooks",
        "post_hooks",
        "shard",
        "temporal_extract",
        "maybe_summary",
        "operator_alert",
        "task_checkpoint",
    ];

    /// The op's wire name, for audit rows and logs.
    pub fn name(&self) -> &'static str {
        match self {
            HarnessOp::Config => "config",
            HarnessOp::Catalogs => "catalogs",
            HarnessOp::ModelPreference => "model_preference",
            HarnessOp::DetectModel { .. } => "detect_model",
            HarnessOp::ResolveBackend { .. } => "resolve_backend",
            HarnessOp::CloudRun { .. } => "cloud_run",
            HarnessOp::SessionLoad { .. } => "session_load",
            HarnessOp::SessionSave { .. } => "session_save",
            HarnessOp::SessionMetadata { .. } => "session_metadata",
            HarnessOp::TurnNumber => "turn_number",
            HarnessOp::Persona => "persona",
            HarnessOp::ClusterAwareness => "cluster_awareness",
            HarnessOp::Rag { .. } => "rag",
            HarnessOp::Memory { .. } => "memory",
            HarnessOp::CrossChannel { .. } => "cross_channel",
            HarnessOp::Video { .. } => "video",
            HarnessOp::Companion => "companion",
            HarnessOp::Skills { .. } => "skills",
            HarnessOp::Runbook { .. } => "runbook",
            HarnessOp::Temporal { .. } => "temporal",
            HarnessOp::RunningSummary => "running_summary",
            HarnessOp::Recall { .. } => "recall",
            HarnessOp::ToolSchemas => "tool_schemas",
            HarnessOp::ExecuteTool { .. } => "execute_tool",
            HarnessOp::RecordToolCall { .. } => "record_tool_call",
            HarnessOp::RetrievalFeedback { .. } => "retrieval_feedback",
            HarnessOp::SkillUsage { .. } => "skill_usage",
            HarnessOp::PreHooks { .. } => "pre_hooks",
            HarnessOp::PostHooks { .. } => "post_hooks",
            HarnessOp::Shard => "shard",
            HarnessOp::TemporalExtract { .. } => "temporal_extract",
            HarnessOp::MaybeSummary { .. } => "maybe_summary",
            HarnessOp::OperatorAlert { .. } => "operator_alert",
            HarnessOp::TaskCheckpoint { .. } => "task_checkpoint",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ops_round_trip_on_the_wire_and_carry_no_identity() {
        let ops = vec![
            HarnessOp::Config,
            HarnessOp::Rag { prompt: "q".into() },
            HarnessOp::ResolveBackend { model: None, exclude_urls: vec![] },
            HarnessOp::ExecuteTool { call: ToolCall { id: "1".into(), name: "web_search".into(), arguments: json!({"query": "x"}) } },
            HarnessOp::MaybeSummary { backend: ResolvedBackend { url: "u".into(), model: "m".into(), backend_type: "vllm".into(), api_format: "openai".into() }, turn: 4 },
        ];
        for op in ops {
            let wire = serde_json::to_value(&op).unwrap();
            assert_eq!(wire["op"], op.name(), "{op:?}");
            let back: HarnessOp = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(back, op);
            let text = wire.to_string();
            assert!(!text.contains("conversation_id") && !text.contains("user_id"), "identity leaked into an op: {text}");
        }
    }

    /// One of every variant, so `ALL_NAMES` cannot silently lag the enum.
    fn one_of_each() -> Vec<HarnessOp> {
        let backend = ResolvedBackend { url: "u".into(), model: "m".into(), backend_type: "vllm".into(), api_format: "openai".into() };
        vec![
            HarnessOp::Config,
            HarnessOp::Catalogs,
            HarnessOp::ModelPreference,
            HarnessOp::DetectModel { prompt: String::new() },
            HarnessOp::ResolveBackend { model: None, exclude_urls: vec![] },
            HarnessOp::CloudRun { prompt: String::new(), channel: String::new(), model: String::new() },
            HarnessOp::SessionLoad { channel: String::new() },
            HarnessOp::SessionSave { role: String::new(), content: String::new(), metadata: None },
            HarnessOp::SessionMetadata { metadata: json!({}) },
            HarnessOp::TurnNumber,
            HarnessOp::Persona,
            HarnessOp::ClusterAwareness,
            HarnessOp::Rag { prompt: String::new() },
            HarnessOp::Memory { prompt: String::new() },
            HarnessOp::CrossChannel { prompt: String::new(), channel: String::new() },
            HarnessOp::Video { prompt: String::new() },
            HarnessOp::Companion,
            HarnessOp::Skills { prompt: String::new(), preferred: vec![] },
            HarnessOp::Runbook { prompt: String::new() },
            HarnessOp::Temporal { timeout_ms: 0 },
            HarnessOp::RunningSummary,
            HarnessOp::Recall { query: String::new(), top_k: 0 },
            HarnessOp::ToolSchemas,
            HarnessOp::ExecuteTool { call: ToolCall { id: "1".into(), name: "t".into(), arguments: json!({}) } },
            HarnessOp::RecordToolCall { tool_name: String::new(), arguments: json!({}), success: true, output: String::new(), error: None, elapsed_ms: 0 },
            HarnessOp::RetrievalFeedback { tool_name: String::new(), success: true },
            HarnessOp::SkillUsage { names: vec![] },
            HarnessOp::PreHooks { prompt: String::new() },
            HarnessOp::PostHooks { result: CoordinatorResult { response: String::new(), model: String::new(), backend: String::new(), node: None, iterations: 0, tool_calls: vec![], elapsed_secs: 0.0, usage: Default::default() } },
            HarnessOp::Shard,
            HarnessOp::TemporalExtract { user_message: String::new(), assistant_response: String::new() },
            HarnessOp::MaybeSummary { backend, turn: 0 },
            HarnessOp::OperatorAlert { kind: String::new(), target: String::new(), cooldown_secs: 0, message: String::new() },
            HarnessOp::TaskCheckpoint { task_id: String::new(), loops: 0, note: None, exhausted: false },
        ]
    }

    #[test]
    fn all_names_is_exactly_the_set_of_wire_names() {
        let live: Vec<&str> = one_of_each().iter().map(|o| o.name()).collect();
        assert_eq!(live, HarnessOp::ALL_NAMES, "ALL_NAMES must list every variant, in order");
        for (op, name) in one_of_each().iter().zip(HarnessOp::ALL_NAMES) {
            assert_eq!(serde_json::to_value(op).unwrap()["op"], *name, "serde tag and name() disagree");
        }
    }

    /// The protocol doc names every op as a backticked token, and the
    /// subjects and route a foreign runner has to know.
    #[test]
    fn the_protocol_doc_lists_every_op() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/reference/harness-protocol.md");
        let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for name in HarnessOp::ALL_NAMES {
            assert!(doc.contains(&format!("`{name}`")), "docs/reference/harness-protocol.md does not list the op `{name}`");
        }
        for needle in ["harness.run.", "harness.task.", "harness.ready.", "harness.turn.", "/api/harness/call", "harness_result"] {
            assert!(doc.contains(needle), "docs/reference/harness-protocol.md does not mention {needle}");
        }
    }

    #[test]
    fn unknown_ops_are_refused() {
        assert!(serde_json::from_value::<HarnessOp>(json!({"op": "drop_tables"})).is_err());
    }
}
