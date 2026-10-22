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
    // metering
    /// The tokens a foreign loop's model calls used, as the harness's wire
    /// translator counted them (i83 E1b). Recorded on the gateway as the
    /// token's user, on the token's node; `kind` is the harness kind.
    Usage {
        prompt_tokens: u64,
        completion_tokens: u64,
        total_tokens: u64,
        calls: u32,
        model: String,
        kind: String,
        #[serde(default)]
        task_id: Option<String>,
    },
    /// A foreign CLI's verdict on its task (`harness::driver`): the
    /// `noo_task_done` a native loop calls as a tool, for a loop the gateway
    /// cannot see into.
    ///
    /// `text_answer` (i171): a NATIVE loop's answer given in text with no
    /// tool call, sent by the runner on the model's behalf; the gateway then
    /// applies the native evidence mark. Absent from older runners: false.
    TaskDone { task_id: String, result: String, #[serde(default)] failed: bool, #[serde(default)] text_answer: bool },
    // a foreign CLI's way back in
    /// Mint the short-lived user-door key a foreign CLI reaches noomesh's
    /// tools with: bound to the token's person, expiring with the turn.
    DoorKey,
    DoorKeyRevoke { key_id: String },
    // token budgets (i83 G)
    /// The loop-boundary switch: may the task's next loop start? Asked
    /// BEFORE a loop, never inside one; a no parks the task.
    BudgetCheck { task_id: String },
    /// A native loop's tokens, run on a node: charged to the task and to the
    /// token's user on the token's node, under the backend that served it.
    TaskUsage { task_id: String, prompt_tokens: u64, completion_tokens: u64, model: String, backend: String },
    /// A loop's question to its owner: the task parks at the next boundary
    /// and the owner's answer starts a new loop.
    TaskAsk { task_id: String, question: String },
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
        "usage",
        "task_done",
        "door_key",
        "door_key_revoke",
        "budget_check",
        "task_usage",
        "task_ask",
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
            HarnessOp::Usage { .. } => "usage",
            HarnessOp::TaskDone { .. } => "task_done",
            HarnessOp::DoorKey => "door_key",
            HarnessOp::DoorKeyRevoke { .. } => "door_key_revoke",
            HarnessOp::BudgetCheck { .. } => "budget_check",
            HarnessOp::TaskUsage { .. } => "task_usage",
            HarnessOp::TaskAsk { .. } => "task_ask",
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
            HarnessOp::Usage { prompt_tokens: 120, completion_tokens: 30, total_tokens: 150, calls: 3, model: "qwen".into(), kind: "copilot".into(), task_id: Some("t1".into()) },
            HarnessOp::TaskDone { task_id: "t1".into(), result: "shipped".into(), failed: false, text_answer: true },
            HarnessOp::DoorKey,
            HarnessOp::DoorKeyRevoke { key_id: "k1".into() },
            HarnessOp::BudgetCheck { task_id: "t1".into() },
            HarnessOp::TaskUsage { task_id: "t1".into(), prompt_tokens: 9, completion_tokens: 3, model: "qwen".into(), backend: "vllm".into() },
            HarnessOp::TaskAsk { task_id: "t1".into(), question: "eu or us?".into() },
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
            HarnessOp::Usage { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, calls: 0, model: String::new(), kind: String::new(), task_id: None },
            HarnessOp::TaskDone { task_id: String::new(), result: String::new(), failed: false, text_answer: false },
            HarnessOp::DoorKey,
            HarnessOp::DoorKeyRevoke { key_id: String::new() },
            HarnessOp::BudgetCheck { task_id: String::new() },
            HarnessOp::TaskUsage { task_id: String::new(), prompt_tokens: 0, completion_tokens: 0, model: String::new(), backend: String::new() },
            HarnessOp::TaskAsk { task_id: String::new(), question: String::new() },
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

    /// The `usage` op's wire form: what a foreign runner posts, with
    /// `task_id` optional.
    #[test]
    fn the_usage_op_reads_its_documented_wire_form() {
        let op: HarnessOp = serde_json::from_value(json!({
            "op": "usage", "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
            "calls": 2, "model": "qwen", "kind": "claude-code",
        }))
        .unwrap();
        assert_eq!(
            op,
            HarnessOp::Usage { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15, calls: 2, model: "qwen".into(), kind: "claude-code".into(), task_id: None }
        );
    }

    #[test]
    fn unknown_ops_are_refused() {
        assert!(serde_json::from_value::<HarnessOp>(json!({"op": "drop_tables"})).is_err());
    }
}
