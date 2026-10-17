// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agentic loop: LLM request building/parsing, tool-call execution,
//! streaming + non-streaming entry points (`run_streaming` / `run`).

use anyhow::Result;
use serde_json::{json, Value};

use std::time::{Duration, Instant};

use crate::state::AppState;
use crate::tools;

use super::runtime::{HarnessRuntime, InProcessRuntime};

#[allow(unused_imports)]
use super::*;

/// Default output-token budget (`VLLM_MAX_TOKENS` / `inference.vllm_max_tokens`).
/// Declared ONCE: request building and the context budget's output reserve
/// are the same quantity and used to carry different fallbacks (4096 vs
/// 8192), so the window shrank by a different amount than the request asked
/// the backend to generate. `docs/reference/env.md` documents this value.
pub(crate) const DEFAULT_VLLM_MAX_TOKENS: u64 = 4096;

/// The configured output-token budget; every reader goes through here.
fn vllm_max_tokens() -> u32 {
    crate::config::env_or_yaml_u64(
        "VLLM_MAX_TOKENS",
        |c| c.inference.vllm_max_tokens.map(u64::from),
        DEFAULT_VLLM_MAX_TOKENS,
    ) as u32
}

// ═══════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════

/// Result of a coordinator run.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CoordinatorResult {
    pub response: String,
    pub model: String,
    pub backend: String,
    /// Node that served the completion (usage attribution).
    /// Derived from the resolved backend's URL host; `None` for cloud.
    pub node: Option<String>,
    pub iterations: u32,
    pub tool_calls: Vec<Value>,
    pub elapsed_secs: f64,
    pub usage: UsageStats,
}

/// Conversation-level usage statistics (mirrors Python's metadata tracking).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UsageStats {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub total_tool_calls: u32,
    pub total_latency_ms: u64,
}

/// Sanitize tool output — delegates to the security kernel.
fn sanitize_tool_output(output: &str) -> String {
    crate::security::sanitize_tool_output(output)
}

// ═══════════════════════════════════════════════════════════════
// Backend resolution
// ═══════════════════════════════════════════════════════════════

/// After noo_tool_search executes, scan the result for tool names and
/// add matching schemas to the active tool set. This allows iterative
/// tool discovery — the LLM can search for tools, then use them.
fn expand_tools_from_search(
    active_schemas: &mut Vec<Value>,
    all_schemas: &[Value],
    tool_result_output: &str,
) {
    // Collect names already in the active set
    let active_names: std::collections::HashSet<String> = active_schemas.iter()
        .filter_map(|s| {
            s.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    // Scan the tool search result for tool names from the full catalog
    let output_lower = tool_result_output.to_lowercase();
    for schema in all_schemas {
        if let Some(name) = schema.get("function")
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str())
        {
            if !active_names.contains(name) && output_lower.contains(&name.to_lowercase()) {
                active_schemas.push(schema.clone());
                tracing::debug!(tool = name, "tool_expanded_from_search");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Feedback & recording (Items 6, 8, 9)
// ═══════════════════════════════════════════════════════════════

/// Fire-and-forget: record a tool call + result to the conversation store.
/// Provides an audit trail and enables tool usage analytics.
///
/// Until 2026-04-27 this published `worker.tool.record` to NATS where a
/// Python handler did the INSERTs. That added a NATS hop per tool call —
/// ~5-15 calls per agent turn — for what's a couple of plain SQL
/// statements. Now writes directly via sqlx, mirroring trellion's
/// `add_tool_call` + `add_tool_result` from `conversation_store.py`.
/// the design port. The Python NATS handler is kept as a fallback for
/// Python-primary deployments.
pub(super) async fn record_tool_call(
    state: &AppState,
    conversation_id: &str,
    tool_name: &str,
    arguments: &Value,
    success: bool,
    output: &str,
    error: Option<&str>,
    elapsed_ms: u64,
) {
    let conv_id = crate::session::coerce_conversation_id(conversation_id);
    let entry_id = uuid::Uuid::new_v4().to_string();
    // Own every value we touch inside the tokio::spawn — borrowed `&str`
    // doesn't satisfy the spawned future's `'static` bound.
    let tool_name_owned = tool_name.to_string();
    let truncated_output: String = output.chars().take(2000).collect();
    let stored_output: Option<String> = if !success && error.is_some() {
        None
    } else {
        Some(truncated_output.clone())
    };
    let arguments_json = serde_json::to_string(arguments).unwrap_or_else(|_| "{}".into());
    let metadata_json = json!({
        "tool_name": tool_name,
        "arguments": arguments,
    })
    .to_string();
    let result_metadata_json = json!({
        "success": success,
        "execution_ms": elapsed_ms,
    })
    .to_string();
    let content_call = format!(
        "Tool: {tool_name}\nArguments: {}",
        serde_json::to_string_pretty(arguments).unwrap_or_else(|_| "{}".into())
    );
    let content_result: String = if success {
        if truncated_output.is_empty() {
            String::new()
        } else {
            truncated_output.clone()
        }
    } else {
        format!("Error: {}", error.unwrap_or("(unspecified)"))
    };
    let error_str = error.map(|e| e.to_string());

    let db = state.db.clone();
    tokio::spawn(async move {
        // 1. Ensure the noo_conversations row exists (heartbeat / autonomy /
        //    system tools may invoke us before any user message has created it).
        //
        //    org_id is stamped 'default' here because a tool record has no
        //    user in scope. It must not be left NULL: `conversation_store.py`
        //    applies a HARD org boundary (`c.org_id = :org`), and a NULL org
        //    matches no org at all, so an org-scoped read comes back EMPTY
        //    rather than shorter. 'default' is the org a single-user install's
        //    only account is in, and the org every system caller belongs to.
        //
        //    'default' is a floor, not a verdict. `save_message` upgrades a
        //    'default' row to the user's real org the first time an identified
        //    message arrives, exactly as it fills in a NULL `user_id`.
        if let Err(e) = sqlx::query(
            "INSERT INTO noo_conversations (id, total_messages, total_tool_calls, metadata, org_id) \
             VALUES ($1::uuid, 0, 0, '{}', 'default') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&conv_id)
        .execute(&db)
        .await
        {
            tracing::debug!(error = %e, "tool_record.upsert_conversation_failed");
        }

        // 2. Insert the tool_call entry.
        let call_entry_id = entry_id.clone();
        if let Err(e) = sqlx::query(
            "INSERT INTO noo_entries (id, conversation_id, type, content, metadata) \
             VALUES ($1::uuid, $2::uuid, 'tool_call', $3, $4::jsonb)",
        )
        .bind(&call_entry_id)
        .bind(&conv_id)
        .bind(&content_call)
        .bind(&metadata_json)
        .execute(&db)
        .await
        {
            tracing::debug!(error = %e, "tool_record.insert_call_failed");
            return;
        }

        // 3. Insert the tool_executions row paired with the call entry.
        let _ = sqlx::query(
            "INSERT INTO noo_tool_executions \
             (id, conversation_id, entry_id, tool_name, arguments, success, output, error, execution_ms) \
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::jsonb, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET \
                 success = EXCLUDED.success, \
                 output = EXCLUDED.output, \
                 error = EXCLUDED.error, \
                 execution_ms = EXCLUDED.execution_ms",
        )
        .bind(&call_entry_id)
        .bind(&conv_id)
        .bind(&call_entry_id)
        .bind(&tool_name_owned)
        .bind(&arguments_json)
        .bind(success)
        .bind(stored_output.as_deref())
        .bind(error_str.as_deref())
        .bind(elapsed_ms as i64)
        .execute(&db)
        .await;

        // 4. Insert the tool_result entry as a child of the call.
        let result_entry_id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT INTO noo_entries (id, conversation_id, parent_id, type, content, metadata) \
             VALUES ($1::uuid, $2::uuid, $3::uuid, 'tool_result', $4, $5::jsonb)",
        )
        .bind(&result_entry_id)
        .bind(&conv_id)
        .bind(&call_entry_id)
        .bind(&content_result)
        .bind(&result_metadata_json)
        .execute(&db)
        .await;

        // 5. Increment the conversation's tool-call counter.
        let _ = sqlx::query(
            "UPDATE noo_conversations \
             SET total_tool_calls = COALESCE(total_tool_calls, 0) + 1 \
             WHERE id = $1::uuid",
        )
        .bind(&conv_id)
        .execute(&db)
        .await;
    });
}

/// Fire-and-forget: send implicit retrieval feedback on tool success.
/// An add-on may consume this feedback; the stack itself only publishes it.
pub(super) async fn record_retrieval_feedback(
    state: &AppState,
    conversation_id: &str,
    tool_name: &str,
    success: bool,
) {
    crate::tools::publish_retrieval_feedback(
        state,
        crate::tools::retrieval_feedback_payload(conversation_id, tool_name, success, Vec::new()),
    )
    .await;
}

/// Record prompt skill usage.
///
/// In-process as of the prompt_skills port. This used to publish
/// fire-and-forget to `worker.prompt_skills.record_usage` — a NATS message,
/// a metered publish and a Python handler, to increment an integer that
/// nothing persisted. The Python counters were process-local too, so this is
/// the same durability with none of the plumbing.
///
/// Still fire-and-forget in effect: unknown names are ignored rather than
/// creating counters, so a stale skill name cannot grow the map unbounded.
pub(super) async fn record_skill_usage(state: &AppState, skill_names: &[String], conversation_id: &str) {
    for name in skill_names {
        state.prompt_skill_usage.record(name);
    }
    // Durable, finally. The process-local counters above are kept for the
    // in-memory view; `noo_prompt_skill_stats` survives restarts.
    crate::repo::prompt_skills::record_usage(&state.db, skill_names, conversation_id).await;
}

// ═══════════════════════════════════════════════════════════════
// Hook system (Item 10) — pre/post-inference extensibility
// ═══════════════════════════════════════════════════════════════

/// Fire pre-inference hooks. Each hook receives the session state via NATS.
/// Add-ons register hooks at startup.
pub(super) async fn fire_pre_inference_hooks(state: &AppState, conversation_id: &str, prompt: &str) {
    let hooks = state.hooks.read().await;
    for hook in &hooks.pre_inference {
        let payload = json!({
            "hook": hook.name,
            "conversation_id": conversation_id,
            "prompt": prompt,
        });
        // A hook's subject is registered at runtime, so this is a second
        // caller-chosen `worker.*` subject (with autonomy's custom action).
        // It signs as the hook runner, never as the turn's user.
        crate::bus_principal::with_internal("hooks", &["read", "write"], async {
            crate::worker_client::publish_fire_and_forget_metered(
                state.nats.clone(),
                state.db.clone(),
                hook.nats_subject.clone(),
                payload,
                state.metrics.clone(),
            );
        })
        .await;
    }
}

/// Fire post-response hooks with result metrics for learning/feedback.
pub(super) async fn fire_post_response_hooks(
    state: &AppState,
    conversation_id: &str,
    result: &CoordinatorResult,
) {
    let hooks = state.hooks.read().await;
    if hooks.post_response.is_empty() {
        return;
    }
    let payload = json!({
        "conversation_id": conversation_id,
        "model": result.model,
        "backend": result.backend,
        "iterations": result.iterations,
        "tool_calls_count": result.tool_calls.len(),
        "elapsed_secs": result.elapsed_secs,
        "tokens_in": result.usage.prompt_tokens,
        "tokens_out": result.usage.completion_tokens,
        "response_length": result.response.len(),
    });
    for hook in &hooks.post_response {
        crate::bus_principal::with_internal("hooks", &["read", "write"], async {
            crate::worker_client::publish_fire_and_forget_metered(
                state.nats.clone(),
                state.db.clone(),
                hook.nats_subject.clone(),
                payload.clone(),
                state.metrics.clone(),
            );
        })
        .await;
    }
}

// ═══════════════════════════════════════════════════════════════
// Session cache (Item 11) — in-memory with TTL
// ═══════════════════════════════════════════════════════════════

/// Core tools always included in every request.
const CORE_TOOLS: &[&str] = &[
    "noo_tool_search",
    "noo_rag_query",
    "noo_rag_ingest",       // save→knowledge workflow needs this
    "noo_inference",
    "noo_memory_search",
    "web_search",
    "noo_channel_send",
    "python_tool",
    "local_files",          // file r/w to /workspace + watched dirs (save-to-knowledge skill)
];

/// Tool groups with trigger keywords.
/// Format: (group_name, tool_names, keywords)
const TOOL_GROUPS: &[(&str, &[&str], &[&str])] = &[
    ("rag", &["noo_rag_ingest", "noo_rag_status", "noo_docs_list", "noo_memory_health"],
     &["ingest", "document", "upload", "rag", "knowledge base", "pageindex", "embed", "index"]),
    ("graph", &["noo_graph_search_entities", "noo_graph_entity_detail", "noo_graph_neighbors",
                "noo_graph_stats", "noo_graph_navigate", "noo_graph_traverse_with_intent",
                "noo_graph_explain_path", "noo_graph_semantic_search"],
     &["graph", "entity", "entities", "relationship", "knowledge graph", "connected",
       "neighbor", "traverse", "navigate", "cluster", "semantic search"]),
    ("jobs", &["noo_job_submit", "noo_job_status", "noo_job_list", "noo_job_cancel"],
     &["job", "queue", "scheduler", "submit", "batch", "async task"]),
    ("agents", &["noo_agents_collaborate", "noo_workflow_run", "noo_workflow_list", "noo_agentic_inference"],
     &["agent", "collaborate", "workflow", "pipeline", "multi-agent", "team"]),
    ("cluster", &["noo_cluster_status", "noo_models_cached", "noo_models_pull"],
     &["cluster", "node", "gpu", "vram", "backend", "model", "pull", "status", "health",
       "running", "online", "offline"]),
    ("files", &["local_files"],
     &["file", "read", "write", "directory", "folder", "path", "filesystem"]),
    ("devices", &["noo_device_camera", "noo_device_location", "noo_device_clipboard",
                  "noo_device_screenshot", "noo_device_audio", "noo_device_battery"],
     &["camera", "photo", "gps", "location", "clipboard", "screenshot", "phone", "device"]),
    ("coding", &["noo_coding_task"],
     &["code", "implement", "fix bug", "refactor", "coding task", "claude code"]),
    ("channels", &["noo_channel_list", "noo_channel_list_recipients", "noo_channel_read_messages"],
     &["channel", "telegram", "whatsapp", "google chat", "messaging"]),
    // Renamed from the (deprecated) video-memory group; "video memory"
    // stays a keyword because people still say it.
    ("recall_memory", &["noo_recall_search", "noo_recall_status"],
     &["recall memory", "video memory", "recall", "past conversation", "remember", "system 1"]),
    ("config", &["noo_config_get", "noo_config_set"],
     &["config", "setting", "configuration"]),
    ("heartbeat", &["noo_heartbeat_list_actions", "noo_heartbeat_list_tasks",
                    "noo_heartbeat_create_task", "noo_heartbeat_run_task",
                    "noo_heartbeat_toggle_task", "noo_heartbeat_delete_task"],
     // Trigger keywords — kept fairly specific because heartbeat tasks
     // are MEDIUM-risk and we don't want them surfaced on unrelated
     // prompts. Phrases like "every morning", "every monday", "every
     // week" cover the natural-language ways users describe schedules;
     // `daily`/`weekly`/`nightly`/`hourly` cover the adjective forms;
     // `recurring`/`automate`/`set up` cover explicit task-management
     // intent. Bare `every` is intentionally NOT included — too noisy.
     &["heartbeat", "cron", "scheduled", "schedule", "briefing", "periodic",
       "recurring", "daily", "weekly", "nightly", "hourly", "monthly",
       "every morning", "every evening", "every night", "every day",
       "every week", "every monday", "every tuesday", "every wednesday",
       "every thursday", "every friday", "every saturday", "every sunday",
       "each morning", "each day", "each week",
       "automate", "set up a recurring", "set up a scheduled", "set up an automatic"]),
    ("autonomy", &["noo_autonomy_status", "noo_autonomy_audit",
                   "noo_autonomy_enable", "noo_autonomy_disable"],
     &["autonomy", "self-healing", "monitoring"]),
];

/// Select relevant tool schemas based on user message keywords.
/// Always includes core tools. Adds extended groups when keywords match.
fn select_tool_schemas(all_schemas: &[Value], user_message: &str) -> Vec<Value> {
    let msg_lower = user_message.to_lowercase();

    // Build the set of active tool names
    let mut active_names: std::collections::HashSet<&str> = CORE_TOOLS.iter().copied().collect();

    for &(_group, tool_names, keywords) in TOOL_GROUPS {
        if keywords.iter().any(|kw| msg_lower.contains(kw)) {
            for name in tool_names {
                active_names.insert(name);
            }
        }
    }

    // Filter schemas
    let selected: Vec<Value> = all_schemas.iter()
        .filter(|schema| {
            schema.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|name| active_names.contains(name))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    // Safety: if nothing matched, return all core tools from schemas
    if selected.is_empty() {
        return all_schemas.iter()
            .filter(|schema| {
                schema.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|name| CORE_TOOLS.contains(&name))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
    }

    tracing::debug!(
        total = all_schemas.len(),
        selected = selected.len(),
        "tool_schemas_selected"
    );

    selected
}

// ═══════════════════════════════════════════════════════════════
// Multi-format LLM request building
// ═══════════════════════════════════════════════════════════════

/// Build the HTTP request URL and JSON body for the given backend API format.
///
/// Supports:
/// - "openai" (vLLM) — POST /v1/chat/completions {model, messages, tools, stream}
/// - "ollama" — POST /api/chat {model, messages, tools, stream}
/// - "llamacpp" — POST /completion {prompt, stream} (messages flattened to prompt)
/// - "anthropic" (cloud) — POST /v1/messages (see `anthropic_wire`)
///
/// A cloud OpenAI/Gemini backend takes the OpenAI branch with the
/// vLLM-only extras left off (`chat_template_kwargs`, the `max_tokens`
/// guessed from `VLLM_MAX_MODEL_LEN`): a provider rejects parameters it
/// does not know, and each model's own output limit is the right default.
/// `enable_thinking` maps to nothing on a cloud backend in this phase.
///
/// The match is on the WIRE format (`backend::wire_format`), not on
/// `api_format`: a llama.cpp backend takes the OpenAI branch — native
/// tool calls under `--jinja` — unless it has refused tools before.
fn build_llm_request(
    backend: &ResolvedBackend,
    messages: &[Value],
    tools: Option<&[Value]>,
    stream: bool,
    enable_thinking: bool,
) -> (String, Value) {
    let cloud = super::backend::is_cloud_backend(backend);
    match super::backend::wire_format(backend) {
        "anthropic" => {
            let url = format!("{}/v1/messages", backend.url);
            let body = super::anthropic_wire::request_body(
                &backend.model, messages, tools, stream, super::cloud::DEFAULT_MAX_TOKENS,
            );
            (url, body)
        }
        "ollama" => {
            // Ollama uses /api/chat with a slightly different schema.
            // Messages format is the same (OpenAI-compatible since Ollama 0.1.24).
            let url = format!("{}/api/chat", backend.url);
            let mut body = json!({
                "model": backend.model,
                "messages": messages,
                "stream": stream,
            });
            if let Some(tools) = tools {
                if !tools.is_empty() {
                    body["tools"] = Value::Array(tools.to_vec());
                }
            }
            (url, body)
        }
        "llamacpp" => {
            // The fallback for a llama-server running WITHOUT `--jinja`
            // (it refused `tools`): /completion with a flattened prompt,
            // tools described in prose, calls parsed back out of text.
            let url = format!("{}/completion", backend.url);

            // Flatten messages to a prompt string
            let prompt = flatten_messages_to_prompt(messages, tools);

            let body = json!({
                "prompt": prompt,
                "stream": stream,
                "n_predict": 4096,
                "temperature": 0.7,
            });
            (url, body)
        }
        _ => {
            // OpenAI-compatible (vLLM, etc.) — /v1/chat/completions.
            // Gemini's OpenAI surface has no `/v1` under its base.
            let url = if backend.backend_type == "cloud-gemini" {
                format!("{}/chat/completions", backend.url)
            } else {
                format!("{}/v1/chat/completions", backend.url)
            };
            if cloud {
                let mut body = json!({
                    "model": backend.model,
                    "messages": cloud_openai_messages(messages),
                    "stream": stream,
                });
                if stream {
                    body["stream_options"] = json!({"include_usage": true});
                }
                if let Some(tools) = tools {
                    if !tools.is_empty() {
                        body["tools"] = Value::Array(tools.to_vec());
                    }
                }
                return (url, body);
            }

            // Dynamic max_tokens: use env default but cap to fit within max_model_len.
            let configured_max = vllm_max_tokens();
            let max_model_len = crate::config::env_or_yaml_u64(
                "VLLM_MAX_MODEL_LEN", |c| c.inference.vllm_max_model_len.map(u64::from), 16384) as u32;
            let input_estimate = messages.iter()
                .map(|m| m.get("content").and_then(|c| c.as_str()).map(|s| s.len()).unwrap_or(50))
                .sum::<usize>() as u32 * 10 / 25 + 200; // ~2.5 chars/token + overhead
            let mut body = json!({
                "model": backend.model,
                "messages": messages,
                "stream": stream,
            });
            if let Some(max_tokens) = output_budget(configured_max, max_model_len, input_estimate) {
                body["max_tokens"] = json!(max_tokens);
            }
            if stream {
                body["stream_options"] = json!({"include_usage": true});
            }
            if let Some(tools) = tools {
                if !tools.is_empty() {
                    body["tools"] = Value::Array(tools.to_vec());
                }
            }
            // For thinking-style models (Qwen3.5, DeepSeek-R1, etc.), vLLM respects
            // chat_template_kwargs to enable/disable the <think> reasoning block.
            // Explicitly set true/false — some models (Qwen3.5) don't produce
            // <think> tags without an explicit enable_thinking=true.
            body["chat_template_kwargs"] = json!({"enable_thinking": enable_thinking});
            (url, body)
        }
    }
}

/// The loop's messages as a cloud OpenAI-compatible API accepts them: a
/// `role:"tool"` message carries only `role`, `content` and `tool_call_id`
/// (the session also records the tool's `name`, which vLLM ignores and a
/// strict provider schema need not).
fn cloud_openai_messages(messages: &[Value]) -> Vec<Value> {
    messages
        .iter()
        .map(|m| {
            if m.get("role").and_then(|r| r.as_str()) == Some("tool") {
                let mut t = json!({"role": "tool", "content": m.get("content").cloned().unwrap_or(json!(""))});
                if let Some(id) = m.get("tool_call_id") {
                    t["tool_call_id"] = id.clone();
                }
                t
            } else {
                m.clone()
            }
        })
        .collect()
}

/// The `max_tokens` to send, or `None` to let the server fill the window.
///
/// The input side is a character-count GUESS (2.5 chars/token) that runs
/// high on English prose — a research prompt measured at 11,110 real tokens
/// was guessed at ~16k. Clamping to "window minus guess" with a 256 floor
/// then capped every reply at 256 tokens with 5k of real room left: the
/// model began planning, never reached a tool call, and every weekly report
/// failed as a stub. So the guess only decides whether the
/// configured cap plainly fits; when it might not, the field is omitted and
/// the server — which knows the real prompt length — uses what is left.
fn output_budget(configured_max: u32, max_model_len: u32, input_estimate: u32) -> Option<u32> {
    (input_estimate.saturating_add(configured_max) <= max_model_len).then_some(configured_max)
}

/// Flatten chat messages into a single prompt string for backends that
/// don't support the chat API (llama.cpp /completion).
fn flatten_messages_to_prompt(messages: &[Value], tools: Option<&[Value]>) -> String {
    let mut prompt = String::new();

    // Inject tool descriptions into the system context
    if let Some(tools) = tools {
        if !tools.is_empty() {
            prompt.push_str("You have access to the following tools:\n\n");
            for tool in tools {
                if let Some(func) = tool.get("function") {
                    let name = func.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let desc = func.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    prompt.push_str(&format!("- {name}: {desc}\n"));
                    if let Some(params) = func.get("parameters") {
                        prompt.push_str(&format!("  Parameters: {}\n", params));
                    }
                }
            }
            prompt.push_str("\nTo use a tool, respond with JSON: {\"tool_calls\": [{\"name\": \"...\", \"arguments\": {...}}]}\n\n");
        }
    }

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
        let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
        match role {
            "system" => prompt.push_str(&format!("System: {content}\n\n")),
            "user" => prompt.push_str(&format!("User: {content}\n\n")),
            "assistant" => prompt.push_str(&format!("Assistant: {content}\n\n")),
            "tool" => {
                let name = msg.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
                prompt.push_str(&format!("Tool result ({name}): {content}\n\n"));
            }
            _ => prompt.push_str(&format!("{role}: {content}\n\n")),
        }
    }

    prompt.push_str("Assistant: ");
    prompt
}

/// Accumulator for the streaming-SSE response shape used by the
/// non-streaming `run` path (heartbeat tasks, agent runs, anything
/// without a WebSocket sink).
///
/// Why streaming for the non-streaming path: vLLM's pythonic tool
/// parser reliably extracts tool_calls from per-delta SSE chunks for
/// gemma-4 but fails to extract them from the full non-streaming
/// response (the model emits a "thought:" prefix that confuses the
/// post-hoc parser). Mirroring the streaming accumulation here lets
/// the heartbeat path benefit from the same parser behavior the
/// dashboard chat does, without needing a model swap.
///
/// Mirrors the per-chunk logic in `run_streaming` but skips all
/// `send_event` calls (no WebSocket sink). If we later refactor
/// `run_streaming` to use this helper with an optional callback, both
/// paths would share one implementation.
pub(crate) struct StreamedResponse {
    pub content: String,
    pub reasoning: String,
    pub tool_calls_json: Vec<Value>,
    pub finish_reason: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

pub(crate) async fn collect_streaming_response(resp: reqwest::Response) -> Result<StreamedResponse, String> {
    use futures::StreamExt;

    let mut full_content = String::new();
    let mut full_reasoning = String::new();
    let mut tool_calls_json: Vec<Value> = Vec::new();
    let mut finish_reason = String::new();
    let mut prompt_tokens: u64 = 0;
    let mut completion_tokens: u64 = 0;
    let mut total_tokens: u64 = 0;
    let mut in_think = false;
    let mut tag_buffer = String::new();
    let mut buf = String::new();
    // gemma-4 emits a literal `thought\n` prefix at the start of each
    // turn (the format vLLM's dropped `gemma4` reasoning parser used to
    // catch). Synthesize a virtual `<think>` open at the start so the
    // existing tag-based dispatcher routes the reasoning to the UI's
    // collapsible panel. We close it virtually when a tool call delta
    // arrives (reasoning is over → action) or at end of stream.
    // Models that emit proper `<think>` tags themselves (Qwen, DeepSeek)
    // override this — the real `<think>` open will set in_think=true
    // and we never inject a virtual one.
    let mut gemma_thought_pending = true;
    let mut reasoning_filter = super::gemma_channel::ChannelFilter::reasoning();
    let mut content_filter = super::gemma_channel::ChannelFilter::content();

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("SSE stream error: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(line_end) = buf.find('\n') {
            let line = buf[..line_end].trim().to_string();
            buf = buf[line_end + 1..].to_string();
            if !line.starts_with("data: ") { continue; }
            let data = &line[6..];
            if data == "[DONE]" { continue; }
            let Ok(chunk_json) = serde_json::from_str::<Value>(data) else { continue };

            let delta = chunk_json.get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("delta"))
                .cloned()
                .unwrap_or(json!({}));

            if let Some(fr) = chunk_json.get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("finish_reason"))
                .and_then(|f| f.as_str())
            {
                finish_reason = fr.to_string();
            }

            // Reasoning field (vLLM reasoning parser — gemma uses "reasoning")
            let reasoning_val = delta.get("reasoning").and_then(|r| r.as_str())
                .or_else(|| delta.get("reasoning_content").and_then(|r| r.as_str()));
            if let Some(reasoning) = reasoning_val {
                full_reasoning.push_str(&reasoning_filter.push(reasoning));
            }

            // Content tokens — buffer-based <think> tag parsing, mirrors
            // the streaming path in `run_streaming` so reasoning split via
            // <think>...</think> in content is routed to full_reasoning.
            if let Some(token) = delta.get("content").and_then(|c| c.as_str()) {
                let token = content_filter.push(token);
                if !token.is_empty() {
                    tag_buffer.push_str(&token);
                    // gemma-4: detect the literal `thought\n` (or
                    // `Thought\n`) prefix and convert to a virtual
                    // <think> open. Only applies if the buffer hasn't
                    // already been consumed (first content tokens of
                    // the turn) and we haven't already entered <think>
                    // via a real tag.
                    if gemma_thought_pending && !in_think {
                        let lower = tag_buffer.trim_start().to_ascii_lowercase();
                        if lower.starts_with("thought\n") || lower.starts_with("thought:") {
                            // Strip the literal "thought" + delimiter from
                            // the buffer; everything that follows is
                            // reasoning until end-of-stream or first tool call.
                            if let Some(idx) = tag_buffer.find('\n').or_else(|| tag_buffer.find(':')) {
                                tag_buffer = tag_buffer[idx + 1..].to_string();
                            }
                            in_think = true;
                            gemma_thought_pending = false;
                        } else if tag_buffer.len() > 16 {
                            // Past the point where "thought" prefix could
                            // appear — give up on the virtual open
                            gemma_thought_pending = false;
                        }
                    }
                    loop {
                        if tag_buffer.is_empty() { break; }
                        if in_think {
                            if let Some(close_idx) = tag_buffer.find("</think>") {
                                full_reasoning.push_str(&tag_buffer[..close_idx]);
                                tag_buffer = tag_buffer[close_idx + 8..].to_string();
                                in_think = false;
                            } else if tag_buffer.ends_with('<') || tag_buffer.ends_with("</")
                                || tag_buffer.ends_with("</t") || tag_buffer.ends_with("</th")
                                || tag_buffer.ends_with("</thi") || tag_buffer.ends_with("</thin")
                                || tag_buffer.ends_with("</think")
                            { break; } else {
                                full_reasoning.push_str(&tag_buffer);
                                tag_buffer.clear();
                            }
                        } else {
                            if let Some(open_idx) = tag_buffer.find("<think>") {
                                full_content.push_str(&tag_buffer[..open_idx]);
                                tag_buffer = tag_buffer[open_idx + 7..].to_string();
                                in_think = true;
                            } else if tag_buffer.ends_with('<') || tag_buffer.ends_with("<t")
                                || tag_buffer.ends_with("<th") || tag_buffer.ends_with("<thi")
                                || tag_buffer.ends_with("<thin") || tag_buffer.ends_with("<think")
                            { break; } else {
                                full_content.push_str(&tag_buffer);
                                tag_buffer.clear();
                            }
                        }
                    }
                }
            }

            // Tool-call deltas: vLLM emits incremental name/arguments per
            // index. This is the path that works for gemma-4 — accumulate
            // by index, parse arguments JSON at the end.
            if let Some(tc_deltas) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                // First tool call delta closes the virtual `thought\n`
                // reasoning block (transition from planning → action).
                // Flush any remaining tag_buffer to reasoning and exit.
                // gemma_thought_pending=false + in_think=true means we
                // entered via the virtual gemma path (real <think> tags
                // leave gemma_thought_pending unchanged at true).
                if in_think && !gemma_thought_pending {
                    full_reasoning.push_str(&tag_buffer);
                    tag_buffer.clear();
                    in_think = false;
                }
                for tc in tc_deltas {
                    let idx = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                    while tool_calls_json.len() <= idx {
                        tool_calls_json.push(json!({"id": "", "type": "function", "function": {"name": "", "arguments": ""}}));
                    }
                    if let Some(func) = tc.get("function") {
                        if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                            tool_calls_json[idx]["function"]["name"] = json!(name);
                        }
                        if let Some(args) = func.get("arguments").and_then(|a| a.as_str()) {
                            let existing = tool_calls_json[idx]["function"]["arguments"].as_str().unwrap_or("");
                            tool_calls_json[idx]["function"]["arguments"] = json!(format!("{}{}", existing, args));
                        }
                    }
                    if let Some(id) = tc.get("id").and_then(|i| i.as_str()) {
                        tool_calls_json[idx]["id"] = json!(id);
                    }
                }
            }

            if let Some(u) = chunk_json.get("usage") {
                prompt_tokens += u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                completion_tokens += u.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                total_tokens += u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            }
        }
    }

    // Flush remaining tag buffer
    full_reasoning.push_str(&reasoning_filter.finish());
    tag_buffer.push_str(&content_filter.finish());
    if !tag_buffer.is_empty() {
        if in_think { full_reasoning.push_str(&tag_buffer); }
        else { full_content.push_str(&tag_buffer); }
    }

    Ok(StreamedResponse {
        content: full_content,
        reasoning: full_reasoning,
        tool_calls_json,
        finish_reason,
        prompt_tokens,
        completion_tokens,
        total_tokens,
    })
}

/// Parse a response from any supported backend format into a normalised
/// OpenAI-style message with `role`, `content`, and optional `tool_calls`.
fn parse_llm_response(api_format: &str, body: &Value) -> Value {
    match api_format {
        "anthropic" => super::anthropic_wire::parse_response(body),
        "ollama" => {
            // Ollama response: {"message": {"role": ..., "content": ..., "tool_calls": [...]}}
            if let Some(msg) = body.get("message") {
                return msg.clone();
            }
            // Streaming chunks also have this format
            json!({"role": "assistant", "content": ""})
        }
        "llamacpp" => {
            // llama.cpp response: {"content": "..."} or {"choices": [...]}
            let content = body.get("content")
                .and_then(|c| c.as_str())
                .or_else(|| {
                    body.get("choices")
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("text"))
                        .and_then(|t| t.as_str())
                })
                .unwrap_or("");

            // Try to extract tool calls from the text (llama.cpp has no native tool support)
            if let Some(tool_calls) = parse_text_tool_calls(content) {
                json!({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": tool_calls,
                })
            } else {
                json!({"role": "assistant", "content": content})
            }
        }
        _ => {
            // OpenAI format: {"choices": [{"message": {...}}]}
            let mut msg = body.get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .cloned()
                .unwrap_or(json!({"role": "assistant", "content": ""}));

            // Some models put thinking in a separate field: Gemma 4 uses "reasoning",
            // Qwen3/DeepSeek-R1 use "reasoning_content". Merge into <think> tags so
            // send_content_with_thinking can split them for the UI.
            let reasoning_text = msg.get("reasoning").and_then(|r| r.as_str())
                .or_else(|| msg.get("reasoning_content").and_then(|r| r.as_str()));
            // gemma's channel tokens: dropped from reasoning, think tags in content.
            let reasoning = reasoning_text.map(super::gemma_channel::drop_channel_tokens).unwrap_or_default();
            let content = msg.get("content").and_then(|c| c.as_str()).map(|c| {
                let mut f = super::gemma_channel::ChannelFilter::content();
                let mut out = f.push(c);
                out.push_str(&f.finish());
                out
            });
            if let Some(content) = &content {
                msg["content"] = json!(content);
            }
            if !reasoning.is_empty() {
                let merged = format!("<think>{}</think>\n\n{}", reasoning, content.unwrap_or_default());
                msg["content"] = json!(merged);
            }
            msg
        }
    }
}

/// Try to parse tool calls from text output (for backends without native tool_use).
/// Looks for JSON blocks like: {"tool_calls": [{"name": "...", "arguments": {...}}]}
/// Detect the `<execute_tool>` failure mode — gemma occasionally emits
/// a tool-call attempt as literal XML text using a non-supported syntax
/// (`<execute_tool> name{arg:value, ...} </execute_tool>`), bypassing
/// both the structured tool_calls field AND the `<tool_call>` JSON
/// format that `parse_text_tool_calls` handles. The malformed call has
/// unquoted JS-style keys, so parsing it is brittle and risks executing
/// the wrong thing. Better: detect, refuse to save as the answer, and
/// re-prompt the model to either use the real tool protocol or write a
/// text answer.
///
/// Moved to `crate::verify::response::looks_like_malformed_tool_call`.
/// Re-exported here so existing call sites compile without churn.
pub(crate) use crate::verify::response::looks_like_malformed_tool_call;

fn parse_text_tool_calls(text: &str) -> Option<Value> {
    // Hermes format: <tool_call>{"name": "...", "arguments": {...}}</tool_call>
    let mut hermes_calls = Vec::new();
    let mut search = text;
    while let Some(start) = search.find("<tool_call>") {
        let after_tag = &search[start + 11..]; // 11 = len("<tool_call>")
        if let Some(end) = after_tag.find("</tool_call>") {
            let json_str = after_tag[..end].trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(json_str) {
                let name = parsed.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if !name.is_empty() {
                    let args = parsed.get("arguments").cloned().unwrap_or(json!({}));
                    hermes_calls.push(json!({
                        "id": format!("call_{}", &uuid::Uuid::new_v4().to_string()[..8]),
                        "type": "function",
                        "function": {"name": name, "arguments": args.to_string()}
                    }));
                }
            }
            search = &after_tag[end + 12..]; // 12 = len("</tool_call>")
        } else {
            break;
        }
    }
    if !hermes_calls.is_empty() {
        return Some(Value::Array(hermes_calls));
    }

    // JSON format: {"tool_calls": [...]}
    if let Some(start) = text.find("{\"tool_calls\"") {
        let remainder = &text[start..];
        // Find matching closing brace
        let mut depth = 0;
        let mut end = 0;
        for (i, ch) in remainder.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        if end > 0 {
            if let Ok(parsed) = serde_json::from_str::<Value>(&remainder[..end]) {
                if let Some(calls) = parsed.get("tool_calls").and_then(|t| t.as_array()) {
                    // Convert to OpenAI format
                    let openai_calls: Vec<Value> = calls.iter()
                        .filter_map(|tc| {
                            let name = tc.get("name").and_then(|n| n.as_str())?;
                            let args = tc.get("arguments").cloned().unwrap_or(json!({}));
                            Some(json!({
                                "id": format!("call_{}", &uuid::Uuid::new_v4().to_string()[..8]),
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": if args.is_string() { args } else { Value::String(args.to_string()) },
                                },
                            }))
                        })
                        .collect();
                    if !openai_calls.is_empty() {
                        return Some(Value::Array(openai_calls));
                    }
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════
// Context window management
// ═══════════════════════════════════════════════════════════════

/// Estimate token count for a set of messages (~2.5 chars/token, conservative).
fn estimate_tokens(messages: &[Value]) -> usize {
    let mut total = 0;
    for m in messages {
        let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
        total += content.len() * 10 / 25 + 4;
        // Tool calls add tokens too
        if let Some(tcs) = m.get("tool_calls").and_then(|t| t.as_array()) {
            for tc in tcs {
                let args = tc.get("function")
                    .and_then(|f| f.get("arguments"))
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                total += args.len() * 10 / 25 + 10;
            }
        }
    }
    total
}

/// Estimate token count consumed by tool schemas.
fn estimate_tool_tokens(tools: &[Value]) -> usize {
    let mut total = 0;
    for t in tools {
        if let Some(func) = t.get("function") {
            total += func.get("name").and_then(|n| n.as_str()).map(|s| s.len()).unwrap_or(0) * 10 / 25 + 4;
            total += func.get("description").and_then(|d| d.as_str()).map(|s| s.len()).unwrap_or(0) * 10 / 25 + 4;
            if let Some(params) = func.get("parameters") {
                total += params.to_string().len() * 10 / 25 + 8;
            }
        }
    }
    total
}

/// Truncate messages to fit within the model's context window.
/// Keeps system message + last N messages, drops oldest middle messages.
/// Fit messages into the context window, returning dropped messages so
/// callers can build a synthetic summary (Option A for long conversations).
fn fit_context_window(messages: &mut Vec<Value>, max_input_tokens: usize, tool_tokens: usize) -> Vec<Value> {
    let budget = max_input_tokens.saturating_sub(tool_tokens).max(1024);

    if estimate_tokens(messages) <= budget {
        return Vec::new();
    }

    // Separate ALL system messages (must stay at beginning) from conversation
    let system_msgs: Vec<Value> = messages.iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .cloned()
        .collect();

    let non_system: Vec<Value> = messages.iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) != Some("system"))
        .cloned()
        .collect();

    // Adaptive tail size. The "last K messages" notion is wrong for agentic
    // loops where one logical turn is 1 user message + N (assistant tool_call,
    // tool_result) pairs — N can be 1 in trivial chats and 20+ in research
    // sessions. A constant tail either bloats trivial chats or amputates the
    // current research turn. Strategy:
    //   - Always keep everything since the most recent user message
    //     (the entire current agentic turn — synthesis step needs all of it)
    //   - Optionally extend back through the prior turn (one user message
    //     before that), giving the model recent conversational context
    //   - Floor at MIN_TAIL = 4 (cold-start / non-agentic chats)
    //   - Cap at MAX_TAIL = 24 (runaway agentic loops can't starve the rest)
    const MIN_TAIL: usize = 4;
    const MAX_TAIL: usize = 24;
    let user_indices: Vec<usize> = non_system
        .iter()
        .enumerate()
        .filter(|(_, m)| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .map(|(i, _)| i)
        .collect();
    // Prefer one-prior-turn boundary; fall back to current-turn boundary;
    // fall back to MIN_TAIL from the end.
    let tail_start_pref = if user_indices.len() >= 2 {
        user_indices[user_indices.len() - 2]
    } else if let Some(&last) = user_indices.last() {
        last
    } else {
        non_system.len().saturating_sub(MIN_TAIL)
    };
    let mut tail_start = tail_start_pref;
    // Floor: ensure at least MIN_TAIL messages
    if non_system.len().saturating_sub(tail_start) < MIN_TAIL {
        tail_start = non_system.len().saturating_sub(MIN_TAIL);
    }
    // Cap: don't let tail eat the entire history
    if non_system.len().saturating_sub(tail_start) > MAX_TAIL {
        tail_start = non_system.len().saturating_sub(MAX_TAIL);
    }
    let tail = &non_system[tail_start..];
    let mut middle: Vec<Value> = non_system[..tail_start].to_vec();

    // Pre-compress oversized tool results in the middle BEFORE attempting to
    // drop messages. Heuristic version of layer-3 — losing a tool_result
    // entirely also loses the citation chain ("we searched X and found Y"),
    // which the synthesis step needs to write a grounded report. Compressing
    // to a 400-char abstract preserves the structural breadcrumb (this tool
    // ran with this query, the gist of the result) at ~10% of original cost.
    // The full content stays in noo_entries and is recoverable via Layer C
    // (semantic recall) or noo_memory_search if the model needs detail.
    const TOOL_COMPRESS_THRESHOLD: usize = 800;
    const TOOL_COMPRESS_TARGET: usize = 400;
    for m in middle.iter_mut() {
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
        if role != "tool" {
            continue;
        }
        if let Some(content) = m.get("content").and_then(|c| c.as_str()) {
            let total = content.chars().count();
            if total > TOOL_COMPRESS_THRESHOLD {
                let truncated: String = content.chars().take(TOOL_COMPRESS_TARGET).collect();
                let elided = total - TOOL_COMPRESS_TARGET;
                m["content"] = json!(format!(
                    "{truncated}... [tool result compressed: {elided} more chars elided — recoverable via noo_memory_search]"
                ));
            }
        }
    }

    // Track dropped messages so callers can build a synthetic summary (Option A)
    let mut dropped_msgs: Vec<Value> = Vec::new();

    // Drop oldest middle messages until under budget
    while !middle.is_empty() {
        let combined: Vec<Value> = system_msgs.iter()
            .chain(middle.iter())
            .chain(tail.iter())
            .cloned()
            .collect();
        if estimate_tokens(&combined) <= budget {
            break;
        }
        dropped_msgs.push(middle.remove(0));
    }

    let dropped = dropped_msgs.len();
    if dropped > 0 {
        tracing::info!(
            dropped_messages = dropped,
            remaining = system_msgs.len() + middle.len() + tail.len(),
            "context_window_truncated"
        );
    }

    // Rebuild messages
    *messages = system_msgs;
    messages.extend(middle);
    messages.extend(tail.to_vec());

    // If still over budget, truncate large message content (any role) to 1000 chars.
    // This preserves the conversation thread while shedding bulky content.
    if estimate_tokens(messages) > budget {
        // Skip the last message (current user prompt) — always keep that intact
        let last_idx = messages.len().saturating_sub(1);
        for (i, m) in messages.iter_mut().enumerate() {
            if i == last_idx { continue; }
            let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
            // Never truncate the first system message (persona + injected context)
            if role == "system" && i == 0 { continue; }
            if let Some(content) = m.get("content").and_then(|c| c.as_str()) {
                let max_len = if role == "tool" { 500 } else { 1000 };
                if content.chars().count() > max_len {
                    let truncated: String = content.chars().take(max_len).collect();
                    m["content"] = json!(format!("{truncated}... (truncated)"));
                }
            }
        }
    }

    // Legacy path: final tool-only truncation if still over
    if estimate_tokens(messages) > budget {
        for m in messages.iter_mut() {
            if m.get("role").and_then(|r| r.as_str()) == Some("tool") {
                if let Some(content) = m.get("content").and_then(|c| c.as_str()) {
                    if content.chars().count() > 500 {
                        let truncated: String = content.chars().take(500).collect();
                        m["content"] = json!(format!("{truncated}... (truncated)"));
                    }
                }
            }
        }
    }

    dropped_msgs
}

// ═══════════════════════════════════════════════════════════════
// Think-block stripping
// ═══════════════════════════════════════════════════════════════

/// Send content to WebSocket, splitting <think> blocks into separate events.
/// chat.js expects: "thinking" events for reasoning, "content" events for response.
async fn send_content_with_thinking<S: crate::websocket::TurnSink>(writer: &S, text: &str) {
    let mut remaining = text;

    while let Some(start) = remaining.find("<think>") {
        // Send any content before the think block
        let before = remaining[..start].trim();
        if !before.is_empty() {
            let _ = writer.send_event("content", json!(before)).await;
        }

        // Extract and send the thinking content
        if let Some(end) = remaining[start..].find("</think>") {
            let think_content = &remaining[start + 7..start + end]; // 7 = len("<think>")
            if !think_content.trim().is_empty() {
                let _ = writer.send_event("thinking", json!(think_content.trim())).await;
            }
            remaining = &remaining[start + end + 8..]; // 8 = len("</think>")
        } else {
            // Unclosed think block — send rest as thinking
            let think_content = &remaining[start + 7..];
            if !think_content.trim().is_empty() {
                let _ = writer.send_event("thinking", json!(think_content.trim())).await;
            }
            return;
        }
    }

    // Send remaining content after all think blocks
    let remaining = remaining.trim();
    if !remaining.is_empty() {
        let _ = writer.send_event("content", json!(remaining)).await;
    }
}

/// Moved to `crate::verify::response::strip_think_blocks`.
/// Re-exported here so existing call sites compile without churn.
pub(crate) use crate::verify::response::strip_think_blocks;

// Stall-recovery nudges. A nudge is pushed to the session and recorded for
// escalation tracking; the same nudge firing three times in a row is the
// "give up and tell the user" threshold — the Ralph-loop pattern is "keep
// iterating with corrective nudges until the model fixes itself," but a
// model that genuinely cannot produce the right tool call should not burn
// all 15 iterations repeating the same failure.
//
// Nudges are `&'static str` (string literals from `verify::response` or
// inline below), so pointer-equality compare is enough.
//
// (This was a `///` block with a blank line under it, so it documented
// nothing — the function it described moved away and rustc dropped the
// text silently.)

/// Honest nudge for a short-but-nonempty post-tool answer. Sent at most
/// ONCE per turn: if the model answers short again, the short answer is
/// ACCEPTED as final. The old behavior reused the empty-response nudge
/// ("no user-visible content" — false for a 35-char reply) and repeated
/// it until escalation, so a correct short answer to a simple question
/// ("run print(1+1)" → "2") looped three times and surfaced the give-up
/// message to the operator (live, 2026-08-08). Short answers are answers.
const SHORT_SYNTHESIS_NUDGE: &str =
    "Your answer after the tool call was very short. If that IS the complete \
     answer, state it again and it will be accepted; otherwise expand it with \
     the tool result and any needed context.";

/// Every nudge the loop injects is labelled as the harness speaking. It
/// rides in the history as a `user` turn (the only role every backend
/// accepts mid-conversation), and without the label a model reads it AS
/// the user: gemma-4 narrated "the user is pointing out that my previous
/// response was empty" and apologised to a person who had said nothing
/// (2026-09-22, five iterations of it).
pub(crate) const NUDGE_PREFIX: &str = "[harness note — not a message from the user] ";

fn push_nudge_with_escalation(
    session: &mut crate::session::Session,
    nudge_history: &mut Vec<&'static str>,
    nudge: &'static str,
) -> Option<String> {
    session.messages.push(json!({
        "role": "user",
        "content": format!("{NUDGE_PREFIX}{nudge}"),
    }));
    nudge_history.push(nudge);

    if nudge_history.len() < 3 {
        return None;
    }
    let n = nudge_history.len();
    let escalate = nudge_history[n - 1] == nudge_history[n - 2]
        && nudge_history[n - 2] == nudge_history[n - 3];
    if !escalate {
        return None;
    }
    let count = nudge_history.iter().filter(|x| **x == nudge).count();
    let nudge_preview: String = nudge.chars().take(160).collect();
    tracing::warn!(
        consecutive_count = count,
        "loop.same_nudge_3x_escalating"
    );
    Some(format!(
        "I tried {count} times in a row to recover from the same issue and the model couldn't \
         fix itself. Stopping. Specific issue I kept flagging: \"{nudge_preview}…\"\n\n\
         If this is for a scheduling task, please use the dashboard `/tasks` panel directly, \
         or retry the request and ask for `engine=\"claude\"` on any coding/tool dispatch."
    ))
}

// ═══════════════════════════════════════════════════════════════
// LLM send with bounded multi-backend fallback
// ═══════════════════════════════════════════════════════════════

/// Hard cap on backend attempts per LLM call. Bounds the fallback loop
/// even when later resolution stages (mesh discovery, Python auto-start)
/// ignore the exclusion list and could re-offer a failed backend.
pub(crate) const MAX_LLM_BACKEND_ATTEMPTS: usize = 3;

/// Dedup window for the backend-failover alert, keyed per failed backend
/// URL. A wedged backend fails on *every* request, so without a window
/// this would alert per request. 15 minutes is long enough to stay quiet
/// during an incident, short enough to keep reminding while it's unfixed.
pub(crate) const BACKEND_FAILOVER_ALERT_COOLDOWN_SECS: i64 = 900;

/// The backend-failover alert, authored in one place for both runtimes.
///
/// The summary is fixed and general; `detail` carries the evidence (backend
/// URLs, the upstream failure) to the log under the alert's reference. The
/// gateway's harness rail rebuilds the alert with this same function from
/// the kind a node sends, so a node-hosted turn cannot author channel text:
/// what it sends as `message` is only ever `detail`.
pub fn backend_failover_alert(target: &str, detail: impl Into<String>) -> crate::operator_alert::OperatorAlert {
    crate::operator_alert::OperatorAlert::new(
        "inference.backend_failover",
        target,
        "⚠️ An inference backend failed and requests fell back to another one. \
         They still succeed, so this is otherwise silent; if it repeats, the \
         backend may be wedged while its container reports healthy.",
    )
    .detail(detail)
    .investigate("noo cluster status")
}

/// Send one LLM request, falling back to the next viable backend on
/// unreachable-backend failures.
///
/// Retryable failures — the request is expected to succeed elsewhere:
///   - transport errors (connection refused, timeout, TLS/dial failures)
///   - HTTP 502/503/504 whose body marks the backend itself as down
///     (node-agent proxy `backend_unreachable` / `node_agent_proxy_error`,
///     bare intermediary 502s) — see `is_retryable_llm_http_error`.
///
/// On a retryable failure the backend's URL is pushed to `failed_urls`
/// (each backend is tried at most once per request) and the next candidate
/// is resolved via `resolve_backend_excluding`. `backend` is updated in
/// place so subsequent loop iterations stick with the working backend.
///
/// `force_stream`: `true` always requests SSE (streaming loop); `false`
/// requests SSE only for OpenAI-format backends (non-streaming loop's
/// existing per-format behaviour) — recompute `api_format`-dependent
/// handling from `backend` AFTER this returns, since fallback may have
/// switched formats.
///
/// A cloud backend (`is_cloud_backend`) never fails over, in either
/// direction: a pinned cloud model that errors is reported as that
/// provider's error, never silently answered by a node's model, and a
/// failed node is never replaced by a paid provider. It goes out on the
/// public-internet client with the provider's auth instead of the node
/// hint, and retries 429/5xx/transport failures on the same provider
/// within the same bounded attempts (`send_cloud_attempt`).
async fn send_llm_with_fallback<R: HarnessRuntime>(
    rt: &R,
    backend: &mut ResolvedBackend,
    failed_urls: &mut Vec<String>,
    effective_model: Option<&str>,
    messages: &[Value],
    tools: Option<&[Value]>,
    force_stream: bool,
    enable_thinking: bool,
) -> Result<reqwest::Response> {
    let client = crate::tls::cluster_client();
    for attempt in 1..=MAX_LLM_BACKEND_ATTEMPTS {
        let stream = force_stream || super::backend::wire_format(backend) == "openai";
        let (url, body) = build_llm_request(backend, messages, tools, stream, enable_thinking);
        if super::backend::is_cloud_backend(backend) {
            match send_cloud_attempt(backend, &url, &body, attempt).await? {
                Some(resp) => return Ok(resp),
                None => continue,
            }
        }
        let failure = match with_backend_hint(client.post(&url).json(&body), backend).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(resp);
                }
                warn_if_node_agent_outdated(status, &url);
                let err_body = resp.text().await.unwrap_or_default();
                tracing::error!(
                    status = %status,
                    backend = %backend.url,
                    attempt,
                    body = %err_body.chars().take(500).collect::<String>(),
                    "llm_http_error"
                );
                // A llama-server without `--jinja` refuses the `tools`
                // parameter outright. Remember it for this backend and
                // retry the SAME backend on the prompt-flattening path —
                // this is a capability, not a failure, so no failover
                // and no operator alert.
                if backend.api_format == "llamacpp"
                    && !super::backend::uses_legacy_completion(&backend.url)
                    && super::backend::refuses_tools(status.as_u16(), &err_body)
                {
                    tracing::warn!(
                        backend = %backend.url,
                        "llama.cpp refused native tool calls (llama-server without --jinja); using the /completion prompt path for this backend from now on"
                    );
                    super::backend::mark_legacy_completion(&backend.url);
                    continue;
                }
                if !is_retryable_llm_http_error(status.as_u16(), &err_body) {
                    // A pinned model this backend does not hold: say so as a
                    // refusal (4xx), not as a backend fault.
                    if let Some(pin) = effective_model {
                        if let Some(refusal) = super::backend::backend_model_not_found(status.as_u16(), &err_body, pin, &backend.url) {
                            return Err(refusal.into());
                        }
                    }
                    anyhow::bail!("{}", backend_error_message(status.as_u16(), &err_body));
                }
                if super::backend::is_context_overflow_body(&err_body) {
                    // The failover alert should say what actually happened —
                    // "unreachable" for a context overflow sent operators
                    // chasing network faults.
                    format!("HTTP {status} (prompt exceeds this backend's context window)")
                } else {
                    format!("HTTP {status} (backend unreachable)")
                }
            }
            Err(e) => {
                tracing::error!(error = %e, backend = %backend.url, attempt, "LLM connection failed");
                if e.is_timeout() {
                    // A timeout is a stall: demote this node for the next
                    // unpinned turns too (`classes::STALL_DEMOTION`), the
                    // same memory the raw chat failover writes.
                    super::classes::note_stall(&backend.url, &backend.backend_type);
                }
                e.to_string()
            }
        };

        // Mark this backend failed for the remainder of the request and
        // resolve the next viable one. Capture the failed backend's identity
        // first — `*backend` is overwritten below.
        let failed_url = backend.url.clone();
        let failed_type = backend.backend_type.clone();
        failed_urls.push(backend.url.clone());
        match rt.resolve_backend_excluding(effective_model, failed_urls).await {
            Ok(fallback) if super::backend::is_cloud_backend(&fallback) => {
                anyhow::bail!("All node backends failed ({failure}); a cloud provider is never a fallback");
            }
            Ok(fallback) if !failed_urls.contains(&fallback.url) => {
                tracing::info!(
                    failed_url = %backend.url,
                    fallback_backend = %fallback.backend_type,
                    fallback_model = %fallback.model,
                    fallback_url = %fallback.url,
                    attempt,
                    "llm_backend_fallback"
                );
                // Falling back keeps the request working, which is exactly why
                // a dead backend can sit unnoticed for days — a wedged vLLM
                // engine still reports its container healthy, and heartbeat
                // tasks keep succeeding on another node. Tell the operator
                // once per backend per cooldown window; detached so the
                // already-degraded request pays no delivery latency.
                rt.operator_alert(
                    backend_failover_alert(
                        &failed_url,
                        format!(
                            "failed: {failed_type} at {failed_url}; reason: {failure}; \
                             now serving: {} at {}",
                            fallback.backend_type, fallback.url,
                        ),
                    ),
                    BACKEND_FAILOVER_ALERT_COOLDOWN_SECS,
                )
                .await;
                *backend = fallback;
            }
            Ok(_) => {
                // Later resolution stages ignore the exclusion list and
                // re-offered an already-failed backend — stop here.
                anyhow::bail!("All viable backends failed: {failure}");
            }
            Err(e) => {
                anyhow::bail!("All backends failed ({failure}); no fallback available: {e}");
            }
        }
    }
    anyhow::bail!("All backends failed after {MAX_LLM_BACKEND_ATTEMPTS} attempts")
}

/// One request to a cloud provider. `Ok(Some)` = success; `Ok(None)` =
/// a retryable failure (429, 5xx, 529 overloaded, transport) with attempts
/// left — the caller retries the SAME provider after the backoff slept
/// here; `Err` = the provider's error as the user sees it (status and
/// reason), on a non-retryable status or the last attempt.
async fn send_cloud_attempt(
    backend: &ResolvedBackend,
    url: &str,
    body: &Value,
    attempt: usize,
) -> Result<Option<reqwest::Response>> {
    let label = super::cloud::provider_label(&backend.backend_type);
    let req = super::cloud::with_provider_auth(
        crate::tls::external_client().post(url).json(body),
        &backend.backend_type,
    )?;
    let last = attempt >= MAX_LLM_BACKEND_ATTEMPTS;
    let retry_after = match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                return Ok(Some(resp));
            }
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let err_body = resp.text().await.unwrap_or_default();
            let message = super::cloud::provider_error_message(&backend.backend_type, status, &err_body);
            tracing::error!(status = %status, provider = label, model = %backend.model, attempt, "cloud_llm_http_error: {message}");
            let code = status.as_u16();
            let retryable = code == 429 || code == 529 || (500..=599).contains(&code);
            if !retryable || last {
                anyhow::bail!("{message}");
            }
            retry_after
        }
        Err(e) => {
            tracing::error!(error = %e, provider = label, model = %backend.model, attempt, "cloud LLM request failed");
            if last {
                anyhow::bail!("{label} API request failed: {e}");
            }
            None
        }
    };
    let wait = retry_after.unwrap_or(2 * attempt as u64).min(10);
    tokio::time::sleep(Duration::from_secs(wait)).await;
    Ok(None)
}

// ═══════════════════════════════════════════════════════════════
// Agentic loop — streaming (WebSocket entry point)
// ═══════════════════════════════════════════════════════════════

/// Run the full agentic loop with streaming events via WebSocket.
///
/// This is the primary coordinator logic:
/// 1. Load persona prompt
/// 2. Resolve backend (with retry on failure)
/// 3. Load session + inject RAG/memory context (concurrent, timeout-gated)
/// 4. Select relevant tool schemas based on user message
/// 5. Loop: call LLM → stream content → parse tool calls → execute → inject results
/// 6. Persist conversation (with think-block stripping)
/// 7. Track usage metadata
#[allow(clippy::too_many_arguments)]
pub async fn run_streaming(
    writer: &crate::websocket::WsWriter,
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // A node with a placed harness runs the turn;
    // otherwise, or when nobody answers, the gateway runs it here.
    if let Some(result) = super::dispatch::try_dispatch(
        state, writer, true, prompt, conversation_id, "dashboard", max_iterations, model, user_id, None, enable_thinking,
    )
    .await?
    {
        return Ok(result);
    }
    let rt = InProcessRuntime::new(state);
    run_streaming_on(writer, &rt, prompt, conversation_id, max_iterations, model, user_id, enable_thinking).await
}

/// The streaming loop against any [`HarnessRuntime`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_streaming_on<R: HarnessRuntime, S: crate::websocket::TurnSink>(
    writer: &S,
    rt: &R,
    prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // Bind the principal for the WHOLE turn — see `TURN_PRINCIPAL`. The
    // exec-approval gate fires deep inside the tool loop and has no other
    // way to learn whose turn it is interrupting.
    crate::routes::communication::with_turn_principal(
        turn_principal(user_id, conversation_id, "dashboard"),
        run_streaming_on_bound(writer, rt, prompt, conversation_id, max_iterations, model, user_id, enable_thinking),
    )
    .await
}

/// Build the binding stamped onto any approval request raised by this turn.
fn turn_principal(
    user_id: Option<&str>,
    conversation_id: &str,
    channel: &str,
) -> crate::routes::communication::TurnPrincipal {
    crate::routes::communication::TurnPrincipal {
        requester: user_id.unwrap_or("").to_string(),
        conversation_id: conversation_id.to_string(),
        channel: channel.to_string(),
        run_id: uuid::Uuid::new_v4().to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_streaming_on_bound<R: HarnessRuntime, S: crate::websocket::TurnSink>(
    writer: &S,
    rt: &R,
    prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // "default"/"auto"/blank are placeholders, not a pinned model — drop them
    // before anything keys off `model.is_some()`, or they suppress the user's
    // saved preference AND the prompt-detected model while matching no
    // candidate at all (see `backend::model_hint`).
    let model = super::backend::model_hint(model);
    // Resolve model: explicit selection → user preference → natural language detection
    let user_pref = if model.is_none() {
        rt.user_model_preference(user_id.unwrap_or("")).await
    } else {
        None
    };
    let prompt_model = if model.is_none() && user_pref.is_none() {
        rt.detect_model_from_prompt(prompt).await
    } else {
        None
    };
    let effective_model = model
        .map(|s| s.to_string())
        .or(user_pref)
        .or(prompt_model);
    let effective_model = effective_model.as_deref();

    // A cloud model (claude-/gpt-/gemini-) resolves to a cloud backend below
    // and runs this same loop — tools, context, session, usage, hooks.

    let start = Instant::now();
    let mut usage = UsageStats::default();

    // 1. Resolve backend — pass user's model preference for targeted routing
    let mut backend = match rt.resolve_backend_for_model(effective_model).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "Backend resolution failed, retrying...");
            tokio::time::sleep(Duration::from_millis(500)).await;
            rt.resolve_backend_for_model(effective_model).await?
        }
    };
    // Backends that already failed this request (send_llm_with_fallback
    // marks them so each backend is tried at most once per request).
    let mut failed_backend_urls: Vec<String> = Vec::new();

    let _ = writer.send_event("metadata", json!({
        "conversation_id": conversation_id,
        "model": backend.model,
        "backend": backend.backend_type,
        "api_format": backend.api_format,
        "engine": "rust",
    })).await;

    // 2. Build session — try cache first, then DB
    let mut session = rt.load_session(conversation_id, "dashboard").await;
    super::context::strip_data_frames(&mut session.messages);
    let mut persona_prompt = rt.persona_prompt().await;
    persona_prompt.push_str(&rt.cluster_awareness().await);
    persona_prompt.push_str(&super::context::clock_context());
    session.set_system_prompt(&persona_prompt);

    // Fire pre-inference hooks (registered by add-ons)
    rt.fire_pre_inference_hooks(conversation_id, prompt).await;

    // 3. Inject all context sources concurrently (graceful degradation)
    // Merged into a single system message — vLLM/Qwen only allows ONE system message.
    let preferred_skills = rt.preferred_skills().await;

    // Phase 6: dynamic context layers — fetched concurrently, with per-layer
    // latency & invocation counters recorded. Results are NOT written to the
    // system prompt yet; we hold them until after fit_context_window so the
    // final assembly can use the priority ordering (structural first).
    let (rag_ctx, mem_ctx, channel_ctx, video_ctx, skills_ctx, companion_ctx) = tokio::join!(
        time_layer(rt.metrics(), "rag", rt.rag_context(prompt, user_id)),
        time_layer(rt.metrics(), "memory", rt.memory_context(prompt, user_id)),
        time_layer(rt.metrics(), "channel", rt.cross_channel_context(prompt, &session.channel, user_id)),
        time_layer(rt.metrics(), "video", rt.video_context(prompt)),
        time_layer(rt.metrics(), "skills", async { rt.prompt_skills_context(prompt, &preferred_skills) }),
        time_layer(rt.metrics(), "companion", rt.companion_context()),
    );

    // Skills come back as (injection_text, selected_names): the text goes in
    // the prompt, the names go to usage recording. Splitting here keeps the
    // rest of this function reading as before.
    let (skills_ctx, selected_skill_names) = match skills_ctx {
        Some((text, names)) => (Some(text), Some(names)),
        None => (None, None),
    };

    let has_rag = rag_ctx.is_some();
    let has_memory = mem_ctx.is_some();
    let has_channel = channel_ctx.is_some();
    let has_video = video_ctx.is_some();
    let has_skills = skills_ctx.is_some();
    let has_companion = companion_ctx.is_some();
    let runbook_ctx = rt.runbook_context(prompt);
    let has_runbook = runbook_ctx.is_some();

    // Record skill usage.
    //
    // Records what was SELECTED, not what was preferred. The previous call
    // passed `preferred_skills` — the caller's hint — so with no preference
    // set it recorded nothing, and with one set it recorded that skill
    // whether or not scoring chose it.
    if let Some(names) = selected_skill_names.as_ref() {
        rt.record_skill_usage(names, conversation_id).await;
    }

    session.add_user_message(prompt);

    // 4. Select relevant tool schemas based on user message
    let mut all_schemas = rt.tool_schemas().await;
    // External MCP tools this caller may see join
    // the list before relevance selection, so they compete on equal terms.
    all_schemas.extend(rt.external_tool_schemas(user_id).await);
    let mut tool_schemas = select_tool_schemas(&all_schemas, prompt);

    // Fit context window (configurable, defaults to max_model_len minus output reserve)
    let tool_toks = estimate_tool_tokens(&tool_schemas);
    let max_input = rt.max_context_tokens().unwrap_or_else(|| {
        let max_len = crate::config::env_or_yaml_u64(
            "VLLM_MAX_MODEL_LEN", |c| c.inference.vllm_max_model_len.map(u64::from), 16384) as u32;
        let out_reserve = vllm_max_tokens();
        max_len.saturating_sub(out_reserve).max(2048)
    }) as usize;

    let dropped = fit_context_window(&mut session.messages, max_input, tool_toks);

    // (D) Temporal graph — always-on. Surfaces user preferences, agent
    // self-identity, and recent project decisions from the bi-temporal graph.
    let temporal_ctx = time_layer(
        rt.metrics(),
        "temporal",
        rt.temporal_context(user_id, Duration::from_secs(2)),
    ).await;

    // (A/B/C) Long-conversation continuity — only when history was dropped.
    let abc_ctx: Option<String> = if !dropped.is_empty() {
        let mut s = String::new();
        if let Some(outline) = build_history_summary(&dropped, conversation_id) {
            s.push_str("\n\n");
            s.push_str(&outline);
        }
        if let Some(summary) = time_layer(
            rt.metrics(),
            "rolling_summary",
            rt.running_summary(conversation_id),
        ).await {
            s.push_str("\n\n[Conversation so far]\n");
            s.push_str(&summary);
        }
        if let Some(recall) = time_layer(
            rt.metrics(),
            "semantic_recall",
            rt.conversation_recall(conversation_id, prompt, 5),
        ).await {
            s.push_str("\n\n");
            s.push_str(&recall);
        }
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    };

    // Phase 6 assembly: structural/identity first (temporal, A+B+C, runbook),
    // then dynamic/domain (rag, memory, channel, video, skills, companion).
    // Rationale: if truncation bites downstream (model-side context window),
    // the LLM keeps "who/what/continuity" and loses fungible domain facts,
    // not vice versa.
    let mut extra_context = String::new();
    let mut push_layer = |label: &str, tagged: &str| {
        extra_context.push_str("\n\n");
        if !label.is_empty() {
            extra_context.push_str(label);
            extra_context.push('\n');
        }
        extra_context.push_str(tagged);
    };

    // Only the gateway's own text goes in the system message. Everything
    // FETCHED (temporal facts, knowledge base, memory, other channels, video
    // recall) is third-party-authored and travels as a delimited data block
    // in the user's message instead - see `context::build_data_frame`.
    if let Some(ref c) = abc_ctx { push_layer("", c); }
    if let Some(ref c) = runbook_ctx { push_layer("", c); }
    if let Some(ref c) = skills_ctx { push_layer("", c); }
    if let Some(ref c) = companion_ctx { push_layer("", c); }

    // Dedup redundant lines across layers (same fact surfacing in Layer B
    // summary and Layer C recall, etc.) Labels and blank lines preserved.
    let deduped = dedup_context_lines(&extra_context);
    record_layer_chars(rt.metrics(), "total_pre_dedup", &extra_context).await;
    record_layer_chars(rt.metrics(), "total_post_dedup", &deduped).await;

    if !deduped.is_empty() {
        if let Some(first) = session.messages.first_mut() {
            if first.get("role").and_then(|r| r.as_str()) == Some("system") {
                let existing = first.get("content").and_then(|c| c.as_str()).unwrap_or("");
                *first = json!({"role": "system", "content": format!("{}{}", existing, deduped)});
            }
        }
    }

    let data_frame = attach_retrieved_data(
        &mut session.messages,
        &[
            ("Known facts about the user", temporal_ctx.as_deref()),
            ("Knowledge base", rag_ctx.as_deref()),
            ("Memory", mem_ctx.as_deref()),
            ("Other channels", channel_ctx.as_deref()),
            ("Video recall", video_ctx.as_deref()),
        ],
    );
    if let Some(f) = data_frame.as_deref() {
        record_layer_chars(rt.metrics(), "retrieved_data_frame", f).await;
    }

    tracing::info!(
        has_rag = has_rag,
        has_memory = has_memory,
        has_channel = has_channel,
        has_video = has_video,
        has_skills = has_skills,
        has_companion = has_companion,
        has_runbook = has_runbook,
        has_temporal = temporal_ctx.is_some(),
        has_abc = abc_ctx.is_some(),
        dropped = dropped.len(),
        pre_dedup_chars = extra_context.len(),
        post_dedup_chars = deduped.len(),
        "context_injected"
    );

    // 5. Agentic loop
    let mut result = CoordinatorResult {
        response: String::new(),
        model: backend.model.clone(),
        backend: backend.backend_type.clone(),
        // No node did a cloud backend's work — the summary layer renders
        // NULL as "cloud".
        node: if super::backend::is_cloud_backend(&backend) { None } else { super::backend::node_from_backend_url(&backend.url) },
        iterations: 0,
        tool_calls: Vec::new(),
        elapsed_secs: 0.0,
        usage: UsageStats::default(),
    };

    // Ralph-loop nudge history. Each stall/hallucination push appends
    // here; helper detects same-nudge-3x to escalate instead of looping
    // forever on a model that can't recover.
    let mut nudge_history: Vec<&'static str> = Vec::new();

    let mut repeat_guard = super::repeat_guard::RepeatGuard::default();
    for iteration in 1..=max_iterations {
        result.iterations = iteration;
        let iter_start = Instant::now();

        // Debug: log message roles to diagnose ordering issues
        let roles: Vec<&str> = session.messages.iter()
            .filter_map(|m| m.get("role").and_then(|r| r.as_str()))
            .collect();
        tracing::debug!(roles = ?roles, count = roles.len(), "llm_request_messages");

        // Send with bounded multi-backend fallback: unreachable backends
        // (connection refused, 502 backend_unreachable from the node-agent
        // proxy, timeouts) are excluded and the next viable backend is
        // tried — each backend at most once per request.
        let pre_send_url = backend.url.clone();
        let resp = match send_llm_with_fallback(
            rt, &mut backend, &mut failed_backend_urls, effective_model,
            &session.messages, Some(&tool_schemas), true, enable_thinking,
        ).await {
            Ok(r) => {
                if backend.url != pre_send_url {
                    // Fallback switched backends — surface it to the client.
                    let _ = writer.send_event("metadata", json!({
                        "fallback": true,
                        "model": backend.model,
                        "backend": backend.backend_type,
                    })).await;
                }
                r
            }
            Err(e) => {
                let _ = writer.send_event("error", json!(format!("{e}"))).await;
                break;
            }
        };

        // Read SSE stream, accumulate content + tool calls, stream tokens to WebSocket
        let mut full_content = String::new();
        let mut full_reasoning = String::new();
        let mut tool_calls_json: Vec<Value> = Vec::new();
        let mut in_think = false;
        let mut finish_reason = String::new();
        // Tag buffer for handling <think>/<​/think> tags split across SSE chunks
        // (matches Python's tag_buffer approach in coordinator.py:1476-1511)
        let mut tag_buffer = String::new();
        // gemma-4 emits a literal `thought\n` prefix at the start of each
        // turn (the format vLLM's dropped `gemma4` reasoning parser used
        // to catch). Synthesize a virtual `<think>` open at the start so
        // the existing tag-based dispatcher routes the reasoning to the
        // dashboard's collapsible thinking panel. Closes on first tool
        // call delta (transition reasoning → action).
        let mut gemma_thought_pending = true;
        let mut reasoning_filter = super::gemma_channel::ChannelFilter::reasoning();
        let mut content_filter = super::gemma_channel::ChannelFilter::content();

        // Buffer for reading SSE lines
        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        // Anthropic streams its own events (`content_block_delta`, ...):
        // each is translated to the OpenAI chunk this reader accumulates,
        // so everything below is shared by every wire.
        let mut anthropic_sse = (super::backend::wire_format(&backend) == "anthropic")
            .then(super::anthropic_wire::SseTranslator::new);
        let mut stream_failed = false;

        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "SSE stream error");
                    break;
                }
            };

            buf.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE lines
            while let Some(line_end) = buf.find('\n') {
                let line = buf[..line_end].trim().to_string();
                buf = buf[line_end + 1..].to_string();

                if !line.starts_with("data: ") { continue; }
                let data = &line[6..];
                if data == "[DONE]" { continue; }

                let parsed = serde_json::from_str::<Value>(data).ok();
                let parsed = match (parsed, anthropic_sse.as_mut()) {
                    (Some(event), Some(t)) => match t.translate(&event) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!(error = %e, "SSE stream error");
                            let _ = writer.send_event("error", json!(e)).await;
                            stream_failed = true;
                            break;
                        }
                    },
                    (p, _) => p,
                };
                if let Some(chunk_json) = parsed {
                    // Extract delta from SSE chunk
                    let delta = chunk_json.get("choices")
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("delta"))
                        .cloned()
                        .unwrap_or(json!({}));

                    // Check finish reason
                    if let Some(fr) = chunk_json.get("choices")
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("finish_reason"))
                        .and_then(|f| f.as_str())
                    {
                        finish_reason = fr.to_string();
                    }

                    // Handle reasoning/reasoning_content (separate field from vLLM reasoning parser)
                    // Gemma 4 uses "reasoning", Qwen3/DeepSeek-R1 use "reasoning_content"
                    let reasoning_val = delta.get("reasoning").and_then(|r| r.as_str())
                        .or_else(|| delta.get("reasoning_content").and_then(|r| r.as_str()));
                    if let Some(reasoning) = reasoning_val {
                        let reasoning = reasoning_filter.push(reasoning);
                        if !reasoning.is_empty() {
                            full_reasoning.push_str(&reasoning);
                            let _ = writer.send_event("thinking", json!(reasoning)).await;
                        }
                    }

                    // Handle content tokens — buffer-based <think> tag parsing
                    // (matches Python coordinator.py:1476-1511)
                    if let Some(token) = delta.get("content").and_then(|c| c.as_str()) {
                        let token = content_filter.push(token);
                        if !token.is_empty() {
                            tag_buffer.push_str(&token);

                            // gemma-4 virtual <think> open: detect literal
                            // "thought\n" or "thought:" prefix at start of
                            // turn and synthesize the <think> open so the
                            // tag-dispatcher below routes everything that
                            // follows to the thinking channel.
                            if gemma_thought_pending && !in_think {
                                let lower = tag_buffer.trim_start().to_ascii_lowercase();
                                if lower.starts_with("thought\n") || lower.starts_with("thought:") {
                                    if let Some(idx) = tag_buffer.find('\n').or_else(|| tag_buffer.find(':')) {
                                        tag_buffer = tag_buffer[idx + 1..].to_string();
                                    }
                                    in_think = true;
                                    gemma_thought_pending = false;
                                } else if tag_buffer.len() > 16 {
                                    gemma_thought_pending = false;
                                }
                            }

                            // Process buffer for think tags (loop until we need more data)
                            loop {
                                if tag_buffer.is_empty() { break; }

                                if in_think {
                                    if let Some(close_idx) = tag_buffer.find("</think>") {
                                        // Emit thinking content before the close tag
                                        let thinking_text = &tag_buffer[..close_idx];
                                        if !thinking_text.is_empty() {
                                            full_reasoning.push_str(thinking_text);
                                            let _ = writer.send_event("thinking", json!(thinking_text)).await;
                                        }
                                        tag_buffer = tag_buffer[close_idx + 8..].to_string();
                                        in_think = false;
                                        // Continue loop — remaining buffer may have more tags
                                    } else if tag_buffer.ends_with('<')
                                        || tag_buffer.ends_with("</")
                                        || tag_buffer.ends_with("</t")
                                        || tag_buffer.ends_with("</th")
                                        || tag_buffer.ends_with("</thi")
                                        || tag_buffer.ends_with("</thin")
                                        || tag_buffer.ends_with("</think")
                                    {
                                        // Partial close tag at end — wait for more data
                                        break;
                                    } else {
                                        // No close tag found, emit all as thinking
                                        full_reasoning.push_str(&tag_buffer);
                                        let _ = writer.send_event("thinking", json!(&tag_buffer)).await;
                                        tag_buffer.clear();
                                    }
                                } else {
                                    if let Some(open_idx) = tag_buffer.find("<think>") {
                                        // Emit content before the open tag
                                        let before = &tag_buffer[..open_idx];
                                        if !before.is_empty() {
                                            full_content.push_str(before);
                                            let _ = writer.send_event("content", json!(before)).await;
                                        }
                                        tag_buffer = tag_buffer[open_idx + 7..].to_string();
                                        in_think = true;
                                        // Continue loop — remaining buffer may have close tag
                                    } else if tag_buffer.ends_with('<')
                                        || tag_buffer.ends_with("<t")
                                        || tag_buffer.ends_with("<th")
                                        || tag_buffer.ends_with("<thi")
                                        || tag_buffer.ends_with("<thin")
                                        || tag_buffer.ends_with("<think")
                                    {
                                        // Partial open tag at end — wait for more data
                                        break;
                                    } else {
                                        // No open tag, emit all as content
                                        full_content.push_str(&tag_buffer);
                                        let _ = writer.send_event("content", json!(&tag_buffer)).await;
                                        tag_buffer.clear();
                                    }
                                }
                            }
                        }
                    }

                    // Accumulate tool call deltas
                    if let Some(tc_deltas) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                        // Close any open virtual gemma <think> block —
                        // tool call signals reasoning is over.
                        if in_think && !gemma_thought_pending {
                            if !tag_buffer.is_empty() {
                                full_reasoning.push_str(&tag_buffer);
                                let _ = writer.send_event("thinking", json!(&tag_buffer)).await;
                                tag_buffer.clear();
                            }
                            in_think = false;
                        }
                        for tc in tc_deltas {
                            let idx = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                            while tool_calls_json.len() <= idx {
                                tool_calls_json.push(json!({"id": "", "type": "function", "function": {"name": "", "arguments": ""}}));
                            }
                            if let Some(func) = tc.get("function") {
                                if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                                    tool_calls_json[idx]["function"]["name"] = json!(name);
                                }
                                if let Some(args) = func.get("arguments").and_then(|a| a.as_str()) {
                                    let existing = tool_calls_json[idx]["function"]["arguments"].as_str().unwrap_or("");
                                    tool_calls_json[idx]["function"]["arguments"] = json!(format!("{}{}", existing, args));
                                }
                            }
                            if let Some(id) = tc.get("id").and_then(|i| i.as_str()) {
                                tool_calls_json[idx]["id"] = json!(id);
                            }
                        }
                    }

                    // Track usage from final chunk
                    if let Some(u) = chunk_json.get("usage") {
                        usage.prompt_tokens += u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        usage.completion_tokens += u.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        usage.total_tokens += u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    }
                }
            }
            if stream_failed { break; }
        }
        if stream_failed {
            // The provider ended the stream with an error event (already
            // sent to the client): end the turn, as a failed send does.
            break;
        }

        // Flush remaining tag buffer after stream ends
        let reasoning_tail = reasoning_filter.finish();
        if !reasoning_tail.is_empty() {
            full_reasoning.push_str(&reasoning_tail);
            let _ = writer.send_event("thinking", json!(reasoning_tail)).await;
        }
        tag_buffer.push_str(&content_filter.finish());
        if !tag_buffer.is_empty() {
            if in_think {
                full_reasoning.push_str(&tag_buffer);
                let _ = writer.send_event("thinking", json!(&tag_buffer)).await;
            } else {
                full_content.push_str(&tag_buffer);
                let _ = writer.send_event("content", json!(&tag_buffer)).await;
            }
            tag_buffer.clear();
        }

        usage.total_latency_ms += iter_start.elapsed().as_millis() as u64;

        // Reconstruct the full message for session history
        let combined_content = if !full_reasoning.is_empty() && !full_content.is_empty() {
            format!("<think>{}</think>\n\n{}", full_reasoning, full_content)
        } else if !full_reasoning.is_empty() {
            format!("<think>{}</think>", full_reasoning)
        } else {
            full_content.clone()
        };

        let mut assistant_msg = json!({"role": "assistant", "content": combined_content});
        if !tool_calls_json.is_empty() {
            assistant_msg["tool_calls"] = Value::Array(tool_calls_json.clone());
        }
        tools::fix_tool_call_fields(&mut assistant_msg);
        session.messages.push(assistant_msg);

        // Parse tool calls from accumulated data
        tracing::info!(
            tool_calls_count = tool_calls_json.len(),
            finish_reason = %finish_reason,
            content_len = combined_content.len(),
            reasoning_len = full_reasoning.len(),
            "stream_complete"
        );

        let mut tool_calls = if !tool_calls_json.is_empty() {
            // Structured tool calls from SSE deltas (Gemma4, native parsers)
            tool_calls_json.iter().filter_map(|tc| {
                let func = tc.get("function")?;
                let name = func.get("name")?.as_str()?;
                if name.is_empty() { return None; }
                let args_str = func.get("arguments").and_then(|a| a.as_str()).unwrap_or("{}");
                let arguments: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
                let id = tc.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                Some(tools::ToolCall { name: name.to_string(), arguments, id })
            }).collect::<Vec<_>>()
        } else {
            // Fallback: parse tool calls from text content (Hermes/llama.cpp format)
            tools::parse_tool_calls(&json!({"role": "assistant", "content": &combined_content}))
        };

        if tool_calls.is_empty() {
            // No tools called this turn. Three sub-cases to distinguish a
            // legitimate "I'm done answering" from a stall:
            //   1) finish_reason == "length"  → model was cut off mid-thought.
            //      Auto-continue with a nudge so we don't silently truncate.
            //   2) empty user-facing content (regardless of internal reasoning)
            //      → stall. The model may have produced <think>...</think>
            //      saying "I have enough" but then never wrote the answer.
            //      From the user's seat that's identical to a hang. Auto-nudge
            //      and loop again so the model writes the actual response.
            //   3) normal stop WITH content   → final answer, exit cleanly.
            // Measure USER-VISIBLE content, not raw model output. The
            // dashboard hides anything inside `<think>...</think>` (it
            // becomes the "Thinking (done)" block), so a response of
            // `<think>5000 chars of reasoning</think>` is functionally
            // empty from the user's seat — even though combined_content
            // is 5000+ chars long. Failure mode seen 2026-05-17 with
            // gemma-4-E4B: content_len:5366 reasoning_len:5351 →
            // visible answer was ~0 chars but the old check (which used
            // raw `combined_content.trim()`) thought it was a real
            // answer and exited the loop without recovery.
            let visible = strip_think_blocks(&combined_content);
            let trimmed = visible.trim();
            let length_truncated = finish_reason == "length";
            // Stall = no user-visible content (reasoning is internal only —
            // it doesn't reach the user, so reasoning-only output IS a stall).
            //
            // We ALSO treat a trivially-short response (≤50 trimmed chars)
            // as a stall when there were prior tool results in this turn.
            // Earlier failure mode: gemma called web_search successfully
            // then produced 8 chars of content + 0 reasoning and stopped.
            const POST_TOOL_MIN_SYNTHESIS_CHARS: usize = 50;
            let had_prior_tool_result = session.messages.iter().any(|m| {
                m.get("role").and_then(|r| r.as_str()) == Some("tool")
            });
            // Short NON-empty answers nudge at most once (see
            // SHORT_SYNTHESIS_NUDGE): once the model has been asked and
            // answers short again, the short answer is accepted as final.
            let trivial_after_tool = !length_truncated
                && had_prior_tool_result
                && !trimmed.is_empty()
                && trimmed.chars().count() < POST_TOOL_MIN_SYNTHESIS_CHARS
                && !nudge_history.contains(&SHORT_SYNTHESIS_NUDGE);
            // Third failure mode: model emitted `<execute_tool>...</execute_tool>`
            // as text (malformed tool-call syntax). Caught a heartbeat report
            // that landed in Drive as literal XML on 2026-05-21.
            let malformed_tool_call = !length_truncated
                && looks_like_malformed_tool_call(trimmed);
            let stalled_empty = !length_truncated
                && (trimmed.is_empty() || trivial_after_tool || malformed_tool_call);

            if length_truncated && iteration < max_iterations {
                tracing::info!(
                    iteration,
                    chars = combined_content.chars().count(),
                    "loop.auto_continue_on_length_truncation"
                );
                let _ = writer.send_event("metadata", json!({
                    "auto_continue": "length_truncated",
                    "iteration": iteration,
                })).await;
                // The partial assistant response is already in session.messages
                // (line ~2734 above). Add a continuation nudge — the next
                // iteration's `fit_context_window` will handle compaction
                // proactively, freeing room for the model to finish.
                const CONTINUE_NUDGE: &str = "Continue from exactly where you left off. \
                    Do not repeat what you already produced — pick up the next sentence/section.";
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, CONTINUE_NUDGE,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            if stalled_empty && iteration < max_iterations {
                let had_reasoning = !full_reasoning.trim().is_empty();
                tracing::warn!(
                    iteration,
                    had_reasoning,
                    reasoning_chars = full_reasoning.chars().count(),
                    "loop.stall_detected_empty_response"
                );
                let _ = writer.send_event("metadata", json!({
                    "auto_continue": "stall_recovery",
                    "iteration": iteration,
                    "had_reasoning": had_reasoning,
                })).await;
                // Tailor the nudge based on whether the model thought first
                // (typical case after a tool call: it reasons "I have enough"
                // but forgets to actually write the answer).
                // Short, structural nudges — the full do/don't rules live
                // in `heartbeat-discipline` skill (loaded into context for
                // both heartbeat tasks and chat-report mode). Restating
                // them here would drift out of sync with the skill file.
                let nudge: &'static str = if malformed_tool_call {
                    "Your previous message used `<execute_tool>` XML which is not a supported tool-call \
                     syntax — see the Tool Usage Rules in your system prompt. Either call the tool \
                     via the structured tool_calls field, or write the final answer in plain text."
                } else if trivial_after_tool {
                    SHORT_SYNTHESIS_NUDGE
                } else if had_reasoning {
                    "Your previous message had no user-visible content — only `<think>` reasoning. \
                     Every tool result you asked for is already in this conversation; nothing is \
                     still pending. Write the answer for the user now, as plain text outside any \
                     `<think>` block."
                } else {
                    "Your previous message was empty. If more tools are needed, call them now. \
                     Otherwise write the final answer (see Tool Usage Rules in your system prompt)."
                };
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: hallucinated scheduling claim — model said
            // "task scheduled" without invoking the scheduling tool.
            // Push a corrective nudge and iterate again (instead of
            // letting the user see a false success and then post-loop
            // verifier warning).
            if !stalled_empty
                && iteration < max_iterations
                && crate::verify::response::detect_scheduling_hallucination(
                    &combined_content,
                    &result.tool_calls,
                )
            {
                tracing::warn!(
                    iteration,
                    "loop.scheduling_hallucination_nudging"
                );
                let _ = writer.send_event("metadata", json!({
                    "auto_continue": "scheduling_hallucination_recovery",
                    "iteration": iteration,
                })).await;
                let nudge = crate::verify::response::scheduling_hallucination_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: tool-error hidden by success claim. Model
            // called a tool, tool errored, model said "successfully
            // triggered" anyway. Force a retry with explicit instruction
            // to be honest about the failure.
            if !stalled_empty
                && iteration < max_iterations
                && crate::verify::response::detect_tool_error_hidden_by_success_claim(
                    &combined_content,
                    &result.tool_calls,
                )
            {
                tracing::warn!(
                    iteration,
                    "loop.tool_error_hidden_nudging"
                );
                let nudge = crate::verify::response::tool_error_hidden_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: validation errors. ≥2 tool calls this turn
            // failed schema validation (e.g. missing required field).
            // Model is about to misinterpret that as "tools broken."
            // Push a nudge BEFORE it produces final text — the threshold
            // is 2 so we don't fire on a single typo, but kick in once
            // the pattern is real.
            if !stalled_empty
                && iteration < max_iterations
                && crate::verify::response::count_validation_errors(&result.tool_calls) >= 2
            {
                tracing::warn!(
                    iteration,
                    "loop.validation_errors_nudging"
                );
                let nudge = crate::verify::response::validation_errors_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Normal exit — model gave a final answer with content.
            result.response = combined_content;
            break;
        }

        // Tell the UI to clear any streamed content before showing tool activity.
        // This is critical for Hermes/text-format tool calls where the raw markup
        // was already streamed as "content" events. Matches Python's content_clear
        // in coordinator.py:1320,1353 — chat.js:272 calls clearStreamedContent().
        let _ = writer.send_event("content_clear", json!({})).await;

        // Execute tools. Auto-inject coordinator-side context (conv id +
        // channel="dashboard" since this is the streaming/WS path) into
        // tools that benefit from it (currently noo_coding_task).
        for call in &mut tool_calls {
            tools::inject_coordinator_context(call, conversation_id, "dashboard");
            let _ = writer.send_event("tool_call", json!({
                "name": call.name,
                "arguments": call.arguments,
            })).await;

            let tool_start = Instant::now();
            let repeat = repeat_guard.check(call, iteration);
            let repeated = repeat.is_some();
            let tool_result = match repeat {
                Some(r) => r,
                None => crate::mcp_bridge::CONVERSATION
                    .scope(
                        Some(conversation_id.to_string()),
                        crate::mcp_bridge::CALLER.scope(user_id.map(str::to_string), rt.execute_tool(call)),
                    )
                    .await,
            };
            let tool_elapsed_ms = tool_start.elapsed().as_millis() as u64;

            let output_preview: String = tool_result.output.chars().take(500).collect();
            let _ = writer.send_event("tool_result", json!({
                "name": tool_result.name,
                "success": tool_result.success,
                "output": output_preview,
                "error": tool_result.error,
                "elapsed_ms": tool_elapsed_ms,
            })).await;

            usage.total_tool_calls += 1;
            usage.total_latency_ms += tool_elapsed_ms;

            result.tool_calls.push(json!({
                "name": call.name,
                "arguments": call.arguments,
                "result": {
                    "success": tool_result.success,
                    "output": output_preview,
                    "error": tool_result.error,
                },
            }));

            // Record tool call for audit trail (fire-and-forget). A repeat
            // the guard refused never ran: nothing to audit, and recording it
            // would put one more "Tool: ... trading" row in memory for the
            // next search to find.
            if !repeated {
                rt.record_tool_call(
                    conversation_id, &call.name,
                    &call.arguments, tool_result.success, &tool_result.output,
                    tool_result.error.as_deref(), tool_elapsed_ms,
                ).await;
            }

            // Implicit retrieval feedback for learning loops
            if tool_result.success {
                rt.record_retrieval_feedback(
                    conversation_id, &call.name, true,
                ).await;
            }

            // Tool expansion: if this was noo_tool_search, discover new tools
            if call.name == "noo_tool_search" && tool_result.success {
                let all_schemas = rt.tool_schemas().await;
                expand_tools_from_search(&mut tool_schemas, &all_schemas, &tool_result.output);
            }

            let sanitized_output = sanitize_tool_output(&tool_result.output);
            session.add_tool_result(
                &tool_result.name,
                &sanitized_output,
                &tool_result.tool_call_id,
            );
        }

        // Capture any content alongside tool calls
        if !full_content.is_empty() {
            result.response = combined_content;
        }

        // Re-fit context window after tool results
        fit_context_window(&mut session.messages, max_input, tool_toks);
    }

    // Safety net: if we exhausted iterations without a final text response
    if result.response.is_empty() && !result.tool_calls.is_empty() {
        let summaries: Vec<String> = result.tool_calls.iter()
            .rev()
            .take(3)
            .filter_map(|tc| {
                tc.get("result")
                    .and_then(|r| r.get("output"))
                    .and_then(|o| o.as_str())
                    .map(|s| s.chars().take(500).collect::<String>())
            })
            .collect();
        result.response = if summaries.is_empty() {
            "I processed your request using tools but couldn't generate a summary.".to_string()
        } else {
            summaries.join("\n\n")
        };
    }

    // 6. Persist conversation (with think-block stripping)
    let clean_response = strip_think_blocks(&result.response);

    if let Err(e) = rt.save_message(conversation_id, "user", prompt, None, user_id,
    ).await {
        tracing::warn!(error = %e, "Failed to save user message");
    }
    if !clean_response.is_empty() {
        let metadata = json!({
            "model": result.model,
            "backend": result.backend,
            "engine": "rust",
            "tokens_in": usage.prompt_tokens,
            "tokens_out": usage.completion_tokens,
            "tool_calls": usage.total_tool_calls,
        });
        // Same attribution as the user turn: the row is scoped by whose
        // conversation this is, not by who authored the individual message.
        if let Err(e) = rt.save_message(conversation_id, "assistant", &clean_response, Some(&metadata), user_id,
        ).await {
            tracing::warn!(error = %e, "Failed to save assistant message");
        }
    }

    // Update conversation metadata
    if let Err(e) = rt.update_conversation_metadata(
        conversation_id,
        &json!({
            "engine": "rust",
            "model": result.model,
            "backend": result.backend,
            "tokens_in": usage.prompt_tokens,
            "tokens_out": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "tool_calls": usage.total_tool_calls,
            "latency_ms": usage.total_latency_ms,
        }),
    ).await {
        tracing::warn!(error = %e, "Failed to update conversation metadata");
    }

    result.elapsed_secs = start.elapsed().as_secs_f64();
    result.usage = usage.clone();

    let _ = writer.send_event("done", json!({
        "iterations": result.iterations,
        "tool_calls": result.tool_calls.len(),
        "elapsed_seconds": (result.elapsed_secs * 10.0).round() / 10.0,
        "tokens_in": usage.prompt_tokens,
        "tokens_out": usage.completion_tokens,
        "engine": "rust",
    })).await;

    // Fire post-response hooks (registered by add-ons)
    rt.fire_post_response_hooks(conversation_id, &result).await;

    // Tag conversation with this node's shard key (idempotent — first write wins)
    rt.tag_conversation_shard(conversation_id).await;

    // Fire-and-forget: extract triples from this turn's user + assistant
    // messages into the temporal graph. Layer D (always-on) will surface
    // them on subsequent turns.
    rt.fire_temporal_extraction(conversation_id, prompt, &result.response, user_id).await;

    // Background: regenerate running summary every N turns (Option B).
    // Use the DB's actual message count as the turn number (accurate across sessions).
    let current_turn: u32 = rt.turn_number(conversation_id).await;
    rt.maybe_regenerate_summary(conversation_id, &backend, current_turn).await;

    // Catch hallucinated scheduling claims (see fn comment).
    verify_no_scheduling_hallucination(&mut result);

    // Trim session and cache for next call
    session.trim(rt.max_session_messages());
    rt.cache_session(conversation_id, session).await;

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
// Agentic loop — non-streaming (REST entry point for POST /api/inference)
// ═══════════════════════════════════════════════════════════════

/// Run the agentic loop without WebSocket — returns the final result.
///
/// Used by `POST /api/inference` and other REST endpoints.
/// Same logic as `run_streaming` but without WebSocket event emission.
///
/// If `model` is provided and is a cloud model (claude-*, gpt-*, gemini-*),
/// the entire request is delegated to the Python coordinator via NATS.
/// Run the agentic loop with the configured persona.
///
/// Thin wrapper over [`run_inner`] so the seven existing call sites are
/// untouched — adding a parameter to this signature would have churned
/// channels, heartbeat and /api/inference for a feature none of them use.
pub async fn run(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
) -> Result<CoordinatorResult> {
    dispatch_or_run_inner(state, prompt, conversation_id, channel, max_iterations, model, user_id, None, true).await
}

/// The non-streaming entry points' shared front: a node with a placed
/// harness runs the turn; otherwise, or when nobody
/// answers, it runs here.
#[allow(clippy::too_many_arguments)]
async fn dispatch_or_run_inner(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    role_prompt: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // A shared-room turn runs here: a node harness would build its context
    // without the room flag.
    if super::in_shared_room() {
        return run_inner(&InProcessRuntime::new(state), prompt, conversation_id, channel, max_iterations, model, user_id, role_prompt, enable_thinking).await;
    }
    if let Some(result) = super::dispatch::try_dispatch(
        state, &crate::websocket::NullSink, false, prompt, conversation_id, channel, max_iterations, model, user_id, role_prompt, enable_thinking,
    )
    .await?
    {
        return Ok(result);
    }
    run_inner(&InProcessRuntime::new(state), prompt, conversation_id, channel, max_iterations, model, user_id, role_prompt, enable_thinking).await
}

/// Like [`run`] but with explicit control over the model's `<think>`
/// reasoning block. `enable_thinking: false` is for unattended synthesis
/// turns (heartbeat research section writes) where nobody sees the
/// reasoning panel and every think token comes out of the same
/// `max_tokens` budget as the deliverable text.
pub async fn run_with_thinking(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    dispatch_or_run_inner(
        state, prompt, conversation_id, channel, max_iterations, model, user_id, None,
        enable_thinking,
    )
    .await
}

/// Run the loop under a ROLE system prompt instead of the persona.
///
/// Backs the agent-role surface (`/api/agent/run`, `/api/agents/collaborate`).
/// A "role" in the Python implementation was never more than a system prompt —
/// `AgentRole` is a five-value enum and `AgentSpec` carries `system_prompt` —
/// so this reuses the audited loop rather than standing up a second agent
/// implementation beside it. Tools, session handling and context injection all
/// come along unchanged.
pub async fn run_with_role(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    role_prompt: &str,
) -> Result<CoordinatorResult> {
    dispatch_or_run_inner(
        state, prompt, conversation_id, channel, max_iterations, model, user_id,
        Some(role_prompt), true,
    )
    .await
}

/// The non-streaming loop against any [`HarnessRuntime`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_inner<R: HarnessRuntime>(
    rt: &R,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    role_prompt: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // Bind the principal for the WHOLE turn — see `TURN_PRINCIPAL`.
    crate::routes::communication::with_turn_principal(
        turn_principal(user_id, conversation_id, channel),
        run_inner_bound(rt, prompt, conversation_id, channel, max_iterations, model, user_id, role_prompt, enable_thinking),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_inner_bound<R: HarnessRuntime>(
    rt: &R,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    role_prompt: Option<&str>,
    enable_thinking: bool,
) -> Result<CoordinatorResult> {
    // "default"/"auto"/blank are placeholders, not a pinned model — drop them
    // before anything keys off `model.is_some()`, or they suppress the user's
    // saved preference AND the prompt-detected model while matching no
    // candidate at all (see `backend::model_hint`).
    let model = super::backend::model_hint(model);
    // Resolve model: explicit selection → user preference → natural language detection
    let user_pref = if model.is_none() {
        rt.user_model_preference(user_id.unwrap_or("")).await
    } else {
        None
    };
    let prompt_model = if model.is_none() && user_pref.is_none() {
        rt.detect_model_from_prompt(prompt).await
    } else {
        None
    };
    let effective_model = model
        .map(|s| s.to_string())
        .or(user_pref)
        .or(prompt_model);
    let effective_model = effective_model.as_deref();

    // A cloud model (claude-/gpt-/gemini-) resolves to a cloud backend below
    // and runs this same loop — tools, context, session, usage, hooks.

    let start = Instant::now();
    let mut usage = UsageStats::default();

    // Resolve backend — pass user's model preference for targeted routing
    let mut backend = match rt.resolve_backend_for_model(effective_model).await {
        Ok(b) => b,
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            rt.resolve_backend_for_model(effective_model).await?
        }
    };
    // Backends that already failed this request (send_llm_with_fallback
    // marks them so each backend is tried at most once per request).
    let mut failed_backend_urls: Vec<String> = Vec::new();

    // Build session — try cache first, then DB
    let mut session = rt.load_session(conversation_id, channel).await;
    super::context::strip_data_frames(&mut session.messages);
    // A role REPLACES the persona rather than appending to it: the Python
    // implementation built a fresh agent per role whose system prompt was the
    // role spec alone, so appending would blend two personas and change the
    // behaviour these roles exist to produce. Cluster awareness still rides
    // along — it is situational fact, not persona.
    let mut persona_prompt = match role_prompt {
        Some(rp) => rp.to_string(),
        None => rt.persona_prompt().await,
    };
    persona_prompt.push_str(&rt.cluster_awareness().await);
    persona_prompt.push_str(&super::context::clock_context());
    session.set_system_prompt(&persona_prompt);

    // Fire pre-inference hooks (registered by add-ons)
    rt.fire_pre_inference_hooks(conversation_id, prompt).await;

    // Phase 6: concurrent dynamic fetches with per-layer metrics.
    // Results are held until after fit_context_window so final assembly
    // can use priority ordering (structural first).
    let (rag_ctx, mem_ctx, channel_ctx, video_ctx, companion_ctx, skills_ctx) = tokio::join!(
        time_layer(rt.metrics(), "rag", rt.rag_context(prompt, user_id)),
        time_layer(rt.metrics(), "memory", rt.memory_context(prompt, user_id)),
        time_layer(rt.metrics(), "channel", rt.cross_channel_context(prompt, &session.channel, user_id)),
        time_layer(rt.metrics(), "video", rt.video_context(prompt)),
        time_layer(rt.metrics(), "companion", rt.companion_context()),
        // Prompt skills were previously injected ONLY in run_streaming, i.e.
        // only for the dashboard WebSocket. Every other caller of run() —
        // /api/inference, the Telegram and Google Chat pipelines, and
        // heartbeat's RustLlm action path — got no skill context at all.
        // Nothing marked that as intentional; skills are described as
        // expertise the agent can invoke, not a dashboard feature.
        time_layer(rt.metrics(), "skills", async {
            rt.prompt_skills_context(prompt, &[])
        }),
    );

    // Split (injection_text, selected_names): text goes in the prompt, names
    // go to usage recording.
    let (skills_ctx, selected_skill_names) = match skills_ctx {
        Some((text, names)) => (Some(text), Some(names)),
        None => (None, None),
    };
    if let Some(names) = selected_skill_names.as_ref() {
        rt.record_skill_usage(names, conversation_id).await;
    }

    let runbook_ctx = rt.runbook_context(prompt);

    session.add_user_message(prompt);

    // Select relevant tool schemas
    let mut all_schemas = rt.tool_schemas().await;
    // External MCP tools this caller may see join
    // the list before relevance selection, so they compete on equal terms.
    all_schemas.extend(rt.external_tool_schemas(user_id).await);
    let mut tool_schemas = select_tool_schemas(&all_schemas, prompt);

    let tool_toks = estimate_tool_tokens(&tool_schemas);
    let max_input = rt.max_context_tokens().unwrap_or_else(|| {
        let max_len = crate::config::env_or_yaml_u64(
            "VLLM_MAX_MODEL_LEN", |c| c.inference.vllm_max_model_len.map(u64::from), 16384) as u32;
        let out_reserve = vllm_max_tokens();
        max_len.saturating_sub(out_reserve).max(2048)
    }) as usize;
    let dropped_run = fit_context_window(&mut session.messages, max_input, tool_toks);

    // (D) Temporal graph context — always-on.
    let temporal_ctx = time_layer(
        rt.metrics(),
        "temporal",
        rt.temporal_context(user_id, Duration::from_secs(2)),
    ).await;

    // (A/B/C) Long-conversation continuity.
    let abc_ctx: Option<String> = if !dropped_run.is_empty() {
        let mut s = String::new();
        if let Some(outline) = build_history_summary(&dropped_run, conversation_id) {
            s.push_str("\n\n");
            s.push_str(&outline);
        }
        if let Some(summary) = time_layer(
            rt.metrics(),
            "rolling_summary",
            rt.running_summary(conversation_id),
        ).await {
            s.push_str("\n\n[Conversation so far]\n");
            s.push_str(&summary);
        }
        if let Some(recall) = time_layer(
            rt.metrics(),
            "semantic_recall",
            rt.conversation_recall(conversation_id, prompt, 5),
        ).await {
            s.push_str("\n\n");
            s.push_str(&recall);
        }
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    };

    // Assembly: structural/identity first, dynamic last.
    let mut extra_context = String::new();
    let mut push_layer = |label: &str, tagged: &str| {
        extra_context.push_str("\n\n");
        if !label.is_empty() {
            extra_context.push_str(label);
            extra_context.push('\n');
        }
        extra_context.push_str(tagged);
    };
    // Only the gateway's own text goes in the system message. Everything
    // FETCHED (temporal facts, knowledge base, memory, other channels, video
    // recall) is third-party-authored and travels as a delimited data block
    // in the user's message instead - see `context::build_data_frame`.
    if let Some(ref c) = abc_ctx { push_layer("", c); }
    if let Some(ref c) = runbook_ctx { push_layer("", c); }
    if let Some(ref c) = skills_ctx { push_layer("", c); }
    if let Some(ref c) = companion_ctx { push_layer("", c); }

    let deduped = dedup_context_lines(&extra_context);
    record_layer_chars(rt.metrics(), "total_pre_dedup", &extra_context).await;
    record_layer_chars(rt.metrics(), "total_post_dedup", &deduped).await;

    if !deduped.is_empty() {
        if let Some(first) = session.messages.first_mut() {
            if first.get("role").and_then(|r| r.as_str()) == Some("system") {
                let existing = first.get("content").and_then(|c| c.as_str()).unwrap_or("");
                *first = json!({"role": "system", "content": format!("{}{}", existing, deduped)});
            }
        }
    }

    let data_frame = attach_retrieved_data(
        &mut session.messages,
        &[
            ("Known facts about the user", temporal_ctx.as_deref()),
            ("Knowledge base", rag_ctx.as_deref()),
            ("Memory", mem_ctx.as_deref()),
            ("Other channels", channel_ctx.as_deref()),
            ("Video recall", video_ctx.as_deref()),
        ],
    );
    if let Some(f) = data_frame.as_deref() {
        record_layer_chars(rt.metrics(), "retrieved_data_frame", f).await;
    }

    tracing::info!(
        has_temporal = temporal_ctx.is_some(),
        has_abc = abc_ctx.is_some(),
        dropped = dropped_run.len(),
        pre_dedup_chars = extra_context.len(),
        post_dedup_chars = deduped.len(),
        "context_injected_nonstream"
    );

    let mut result = CoordinatorResult {
        response: String::new(),
        model: backend.model.clone(),
        backend: backend.backend_type.clone(),
        // No node did a cloud backend's work — the summary layer renders
        // NULL as "cloud".
        node: if super::backend::is_cloud_backend(&backend) { None } else { super::backend::node_from_backend_url(&backend.url) },
        iterations: 0,
        tool_calls: Vec::new(),
        elapsed_secs: 0.0,
        usage: UsageStats::default(),
    };

    // Ralph-loop nudge history (see streaming-loop counterpart).
    let mut nudge_history: Vec<&'static str> = Vec::new();

    // An LLM transport failure that aborts the loop. Held rather than
    // returned immediately: an earlier iteration may already have produced
    // content, and partial progress beats a lost answer. Checked after the
    // loop — see the empty-response return below.
    let mut llm_failure: Option<anyhow::Error> = None;

    let mut repeat_guard = super::repeat_guard::RepeatGuard::default();
    for iteration in 1..=max_iterations {
        result.iterations = iteration;
        let iter_start = Instant::now();

        // For OpenAI-compat (vLLM, node-agent proxy), use stream=true even
        // though there's no WebSocket sink — vLLM's pythonic tool parser
        // reliably extracts tool_calls from per-delta SSE chunks for
        // gemma-4 but fails on the full non-streaming response.
        // collect_streaming_response accumulates SSE deltas into the same
        // message shape the rest of this loop expects.
        // For ollama (NDJSON) and a llama.cpp that refused tools (the
        // /completion shape), keep the non-streaming POST +
        // parse_llm_response path.
        // Send with bounded multi-backend fallback (see run_streaming's
        // counterpart). force_stream=false: SSE is requested only for
        // OpenAI-format backends, so `use_streaming` must be recomputed
        // AFTER the call — fallback may have switched api_format.
        let resp = match send_llm_with_fallback(
            rt, &mut backend, &mut failed_backend_urls, effective_model,
            &session.messages, Some(&tool_schemas), false, enable_thinking,
        ).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "llm_all_backends_failed");
                llm_failure = Some(e);
                break;
            }
        };
        let use_streaming = super::backend::wire_format(&backend) == "openai";

        let (assistant_msg, content, mut tool_calls) = if use_streaming {
            let streamed = match collect_streaming_response(resp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "SSE collection failed");
                    llm_failure = Some(anyhow::anyhow!("SSE collection failed: {e}"));
                    break;
                }
            };

            usage.prompt_tokens += streamed.prompt_tokens as u32;
            usage.completion_tokens += streamed.completion_tokens as u32;
            usage.total_tokens += streamed.total_tokens as u32;

            let combined_content = if !streamed.reasoning.is_empty() && !streamed.content.is_empty() {
                format!("<think>{}</think>\n\n{}", streamed.reasoning, streamed.content)
            } else if !streamed.reasoning.is_empty() {
                format!("<think>{}</think>", streamed.reasoning)
            } else {
                streamed.content.clone()
            };
            let content = streamed.content.clone();

            let mut msg = json!({"role": "assistant", "content": combined_content});
            if !streamed.tool_calls_json.is_empty() {
                msg["tool_calls"] = Value::Array(streamed.tool_calls_json.clone());
            }
            tools::fix_tool_call_fields(&mut msg);

            // Prefer SSE-accumulated structured tool calls; fall back to
            // a content scan via parse_tool_calls otherwise.
            let calls = if !streamed.tool_calls_json.is_empty() {
                streamed.tool_calls_json.iter().filter_map(|tc| {
                    let func = tc.get("function")?;
                    let name = func.get("name")?.as_str()?;
                    if name.is_empty() { return None; }
                    let args_str = func.get("arguments").and_then(|a| a.as_str()).unwrap_or("{}");
                    let arguments: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
                    let id = tc.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                    Some(tools::ToolCall { name: name.to_string(), arguments, id })
                }).collect::<Vec<_>>()
            } else {
                tools::parse_tool_calls(&msg)
            };
            (msg, content, calls)
        } else {
            // ollama / llamacpp / anthropic non-streaming — one JSON body.
            let llm_response = match resp.json::<Value>().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse LLM response");
                    break;
                }
            };
            if let Some(u) = llm_response.get("usage") {
                // OpenAI-shaped, or Anthropic's input/output_tokens.
                let (p, c, t) = super::anthropic_wire::usage_tokens(u);
                usage.prompt_tokens += p as u32;
                usage.completion_tokens += c as u32;
                usage.total_tokens += t as u32;
            }
            let message = parse_llm_response(super::backend::wire_format(&backend), &llm_response);
            let content = message.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let mut msg = message.clone();
            tools::fix_tool_call_fields(&mut msg);
            let calls = tools::parse_tool_calls(&message);
            (msg, content, calls)
        };

        usage.total_latency_ms += iter_start.elapsed().as_millis() as u64;
        session.messages.push(assistant_msg);

        if tool_calls.is_empty() {
            // Stall guard — mirrors the streaming path. When the model
            // called tools earlier, got results, then produced a
            // trivially short response on the synthesis step (or only
            // reasoning inside `<think>` with no user-visible answer),
            // treat it as a stall and re-prompt with an explicit "write
            // the answer" nudge. Measure VISIBLE content only — a model
            // that produces 5000 chars of `<think>` reasoning and 0
            // user-facing text is functionally ghosted, not "done."
            const POST_TOOL_MIN_SYNTHESIS_CHARS: usize = 50;
            let visible = strip_think_blocks(&content);
            let trimmed = visible.trim();
            let trimmed_len = trimmed.chars().count();
            let had_prior_tool_result = session.messages.iter().any(|m| {
                m.get("role").and_then(|r| r.as_str()) == Some("tool")
            });
            // A short NON-empty answer nudges at most once (see
            // SHORT_SYNTHESIS_NUDGE): if the model already got that nudge
            // this turn and answered short again, the answer stands.
            let trivial_after_tool = had_prior_tool_result
                && !trimmed.is_empty()
                && trimmed_len < POST_TOOL_MIN_SYNTHESIS_CHARS
                && !nudge_history.contains(&SHORT_SYNTHESIS_NUDGE);
            let malformed_tool_call = looks_like_malformed_tool_call(trimmed);

            if (trimmed.is_empty() || trivial_after_tool || malformed_tool_call)
                && iteration < max_iterations
            {
                tracing::warn!(
                    iteration,
                    visible_chars = trimmed_len,
                    raw_chars = content.chars().count(),
                    had_prior_tool_result,
                    malformed_tool_call,
                    "loop.stall_detected_empty_response (non-streaming)"
                );
                // Short structural nudge — see streaming path comment.
                let nudge: &'static str = if malformed_tool_call {
                    "Your previous message used `<execute_tool>` XML which is not a supported tool-call \
                     syntax — see the Tool Usage Rules in your system prompt. Either call the tool \
                     via the structured tool_calls field, or write the final answer in plain text."
                } else if trivial_after_tool {
                    SHORT_SYNTHESIS_NUDGE
                } else {
                    "Your previous message had no user-visible content — only `<think>` reasoning. \
                     Every tool result you asked for is already in this conversation; nothing is \
                     still pending. Write the answer for the user now, as plain text outside any \
                     `<think>` block."
                };
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: hallucinated scheduling claim (non-streaming
            // path mirror of the streaming-loop block).
            if !trimmed.is_empty()
                && !trivial_after_tool
                && !malformed_tool_call
                && iteration < max_iterations
                && crate::verify::response::detect_scheduling_hallucination(
                    trimmed,
                    &result.tool_calls,
                )
            {
                tracing::warn!(
                    iteration,
                    "loop.scheduling_hallucination_nudging (non-streaming)"
                );
                let nudge = crate::verify::response::scheduling_hallucination_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: tool-error hidden by success claim (non-streaming).
            if !trimmed.is_empty()
                && !trivial_after_tool
                && !malformed_tool_call
                && iteration < max_iterations
                && crate::verify::response::detect_tool_error_hidden_by_success_claim(
                    trimmed,
                    &result.tool_calls,
                )
            {
                tracing::warn!(
                    iteration,
                    "loop.tool_error_hidden_nudging (non-streaming)"
                );
                let nudge = crate::verify::response::tool_error_hidden_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            // Ralph-loop: validation errors (non-streaming).
            if !trimmed.is_empty()
                && !trivial_after_tool
                && !malformed_tool_call
                && iteration < max_iterations
                && crate::verify::response::count_validation_errors(&result.tool_calls) >= 2
            {
                tracing::warn!(
                    iteration,
                    "loop.validation_errors_nudging (non-streaming)"
                );
                let nudge = crate::verify::response::validation_errors_nudge();
                if let Some(escalation) = push_nudge_with_escalation(
                    &mut session, &mut nudge_history, nudge,
                ) {
                    result.response = escalation;
                    break;
                }
                continue;
            }

            if !content.is_empty() {
                result.response = content;
            }
            break;
        }

        // Execute tools. Auto-inject coordinator-side context (conv id +
        // channel) into tools that benefit from it (currently
        // noo_coding_task) so progress updates can flow back to chat.
        for call in &mut tool_calls {
            tools::inject_coordinator_context(call, conversation_id, channel);
            let tool_start = Instant::now();
            let repeat = repeat_guard.check(call, iteration);
            let repeated = repeat.is_some();
            let tool_result = match repeat {
                Some(r) => r,
                None => crate::mcp_bridge::CONVERSATION
                    .scope(
                        Some(conversation_id.to_string()),
                        crate::mcp_bridge::CALLER.scope(user_id.map(str::to_string), rt.execute_tool(call)),
                    )
                    .await,
            };
            let tool_elapsed_ms = tool_start.elapsed().as_millis() as u64;

            usage.total_tool_calls += 1;
            usage.total_latency_ms += tool_elapsed_ms;

            let output_truncated: String = tool_result.output.chars().take(2000).collect();
            result.tool_calls.push(json!({
                "name": call.name,
                "arguments": call.arguments,
                "result": {
                    "success": tool_result.success,
                    "output": output_truncated,
                    "error": tool_result.error,
                },
            }));

            // Record tool call for audit trail (fire-and-forget). A repeat
            // the guard refused never ran: nothing to audit, and recording it
            // would put one more "Tool: ... trading" row in memory for the
            // next search to find.
            if !repeated {
                rt.record_tool_call(
                    conversation_id, &call.name,
                    &call.arguments, tool_result.success, &tool_result.output,
                    tool_result.error.as_deref(), tool_elapsed_ms,
                ).await;
            }

            // Implicit retrieval feedback for learning loops
            if tool_result.success {
                rt.record_retrieval_feedback(
                    conversation_id, &call.name, true,
                ).await;
            }

            // Tool expansion: if this was noo_tool_search, discover new tools
            if call.name == "noo_tool_search" && tool_result.success {
                let all_schemas = rt.tool_schemas().await;
                expand_tools_from_search(&mut tool_schemas, &all_schemas, &tool_result.output);
            }

            let sanitized_output = sanitize_tool_output(&tool_result.output);
            session.add_tool_result(
                &tool_result.name,
                &sanitized_output,
                &tool_result.tool_call_id,
            );
        }

        if !content.is_empty() {
            result.response = content;
        }

        fit_context_window(&mut session.messages, max_input, tool_toks);
    }

    // An LLM failure with NOTHING produced is an Err, not an empty success.
    // Ok("") here is what let four days of node-cert TLS failures surface as
    // "unusable output: model produced no user-visible content (all wrapped
    // in <think> tags)" — the quality gate's classification of an empty
    // string — instead of the transport error the operator needed to see.
    // Content from an earlier iteration (or completed tool calls, handled by
    // the safety net below) still returns Ok.
    if result.response.is_empty() && result.tool_calls.is_empty() {
        if let Some(e) = llm_failure {
            return Err(e);
        }
    }

    // Safety net
    if result.response.is_empty() && !result.tool_calls.is_empty() {
        let summaries: Vec<String> = result.tool_calls.iter()
            .rev()
            .take(3)
            .filter_map(|tc| {
                tc.get("result")
                    .and_then(|r| r.get("output"))
                    .and_then(|o| o.as_str())
                    .map(|s| s.chars().take(500).collect::<String>())
            })
            .collect();
        result.response = if summaries.is_empty() {
            "I processed your request using tools but couldn't generate a summary.".to_string()
        } else {
            summaries.join("\n\n")
        };
    }

    // Persist conversation
    let clean_response = strip_think_blocks(&result.response);

    if let Err(e) =
        rt.save_message(conversation_id, "user", prompt, None, user_id).await
    {
        tracing::warn!(error = %e, "Failed to save user message");
    }
    if !clean_response.is_empty() {
        let metadata = json!({
            "model": result.model,
            "backend": result.backend,
            "engine": "rust",
            "tokens_in": usage.prompt_tokens,
            "tokens_out": usage.completion_tokens,
        });
        if let Err(e) = rt.save_message(conversation_id, "assistant", &clean_response, Some(&metadata), user_id,
        ).await {
            tracing::warn!(error = %e, "Failed to save assistant message");
        }
    }

    if let Err(e) = rt.update_conversation_metadata(
        conversation_id,
        &json!({
            "engine": "rust",
            "model": result.model,
            "backend": result.backend,
            "tokens_in": usage.prompt_tokens,
            "tokens_out": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "tool_calls": usage.total_tool_calls,
            "latency_ms": usage.total_latency_ms,
        }),
    ).await {
        tracing::warn!(error = %e, "Failed to update conversation metadata");
    }

    result.elapsed_secs = start.elapsed().as_secs_f64();
    result.usage = usage;

    // Fire post-response hooks (registered by add-ons)
    rt.fire_post_response_hooks(conversation_id, &result).await;

    // Tag conversation with this node's shard key
    rt.tag_conversation_shard(conversation_id).await;

    // Fire-and-forget temporal extraction (mirrors streaming path)
    rt.fire_temporal_extraction(conversation_id, prompt, &result.response, user_id).await;

    // Background: regenerate running summary every N turns (Option B)
    let current_turn_run: u32 = rt.turn_number(conversation_id).await;
    rt.maybe_regenerate_summary(conversation_id, &backend, current_turn_run).await;

    // Catch hallucinated scheduling claims (see fn comment).
    verify_no_scheduling_hallucination(&mut result);

    // Trim session and cache for next call
    session.trim(rt.max_session_messages());
    rt.cache_session(conversation_id, session).await;

    Ok(result)
}

/// Moved to `crate::verify::response::verify_no_scheduling_hallucination`.
/// Thin adapter kept here so the two call sites in `run` / `run_streaming`
/// don't need to know about the (response, tool_calls) split — they
/// pass `&mut result` and we destructure here.
pub(crate) fn verify_no_scheduling_hallucination(result: &mut CoordinatorResult) {
    crate::verify::response::verify_no_scheduling_hallucination(
        &mut result.response,
        &result.tool_calls,
    );
}

/// The sentence a non-retryable backend refusal leaves on the task.
///
/// It read `Backend error: 400 Bad Request` and nothing else, while the
/// body — `"harrier:latest" does not support chat` — went only to the
/// gateway's tracing log, which a container recreate erases. Task
/// e7dd417b went stale carrying the status alone and its reason
/// was recovered from the audit table hours later. The task record is the
/// place an operator looks first, so the reason travels with the status:
/// one line, bounded, and the OpenAI-shaped `error.message` unwrapped when
/// the body has one so the sentence reads as the backend wrote it.
fn backend_error_message(status: u16, body: &str) -> String {
    const MAX: usize = 300;
    let reason = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/message").and_then(|m| m.as_str()).map(str::to_string))
        .unwrap_or_else(|| body.to_string());
    let reason: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut reason: String = reason.chars().take(MAX).collect();
    if reason.is_empty() {
        return format!("Backend error: {status}");
    }
    if reason.chars().count() == MAX {
        reason.push('…');
    }
    format!("Backend error: {status}: {reason}")
}

#[cfg(test)]
mod output_budget_tests {
    use super::output_budget;

    #[test]
    fn the_configured_cap_is_sent_only_when_it_plainly_fits() {
        // Room to spare: the configured cap goes on the wire.
        assert_eq!(output_budget(4096, 16384, 5_000), Some(4096));
        assert_eq!(output_budget(4096, 16384, 12_288), Some(4096));
        // The 2026-09-29 research prompt: guessed at ~16k, really 11,110
        // tokens. The old clamp sent 256 here; now the field is omitted so
        // the server fills the ~5k that was really left.
        assert_eq!(output_budget(4096, 16384, 16_200), None);
        assert_eq!(output_budget(4096, 16384, 12_289), None);
        // A guess past the window must not wrap around into a huge cap.
        assert_eq!(output_budget(4096, 16384, u32::MAX), None);
    }
}

#[cfg(test)]
mod nudge_tests {
    use super::*;

    #[test]
    fn a_nudge_is_labelled_as_the_harness_not_the_user() {
        let mut session = crate::session::Session::new("c1".into(), "dashboard".into());
        let mut history: Vec<&'static str> = Vec::new();
        assert!(push_nudge_with_escalation(&mut session, &mut history, SHORT_SYNTHESIS_NUDGE).is_none());
        let last = session.messages.last().expect("the nudge was pushed");
        assert_eq!(last["role"], "user", "the one role every backend accepts mid-turn");
        let content = last["content"].as_str().unwrap();
        assert!(content.starts_with(NUDGE_PREFIX), "{content}");
        assert!(content.ends_with(SHORT_SYNTHESIS_NUDGE));
    }

    #[test]
    fn the_third_identical_nudge_escalates_and_the_label_does_not_change_that() {
        let mut session = crate::session::Session::new("c1".into(), "dashboard".into());
        let mut history: Vec<&'static str> = Vec::new();
        assert!(push_nudge_with_escalation(&mut session, &mut history, SHORT_SYNTHESIS_NUDGE).is_none());
        assert!(push_nudge_with_escalation(&mut session, &mut history, SHORT_SYNTHESIS_NUDGE).is_none());
        let stop = push_nudge_with_escalation(&mut session, &mut history, SHORT_SYNTHESIS_NUDGE)
            .expect("three in a row stops the loop");
        assert!(stop.contains("3 times in a row"), "{stop}");
    }
}

#[cfg(test)]
mod llamacpp_wire_tests {

    #[test]
    fn a_backend_refusal_carries_its_reason_onto_the_task() {
        // The live body from task e7dd417b, as ollama wrote it.
        let body = r#"{"error":{"message":"\"harrier:latest\" does not support chat","type":"api_error","code":null}}"#;
        assert_eq!(
            backend_error_message(400, body),
            "Backend error: 400: \"harrier:latest\" does not support chat"
        );
        // A body that is not OpenAI-shaped still travels, flattened to one line.
        assert_eq!(backend_error_message(502, "upstream\n  gone"), "Backend error: 502: upstream gone");
        // An empty body leaves the status alone — no trailing colon.
        assert_eq!(backend_error_message(400, ""), "Backend error: 400");
        // A body that goes on for pages is cut, and says so.
        let long = "x".repeat(1000);
        let out = backend_error_message(400, &long);
        assert!(out.ends_with('…'), "{out}");
        assert!(out.chars().count() < 330, "{}", out.chars().count());
    }
    use super::*;

    fn llamacpp(url: &str) -> ResolvedBackend {
        ResolvedBackend {
            url: url.to_string(),
            model: "qwen".to_string(),
            backend_type: "llamacpp".to_string(),
            api_format: "llamacpp".to_string(),
        }
    }

    fn tools() -> Vec<Value> {
        vec![json!({"type": "function", "function": {"name": "web_search", "description": "search", "parameters": {"type": "object"}}})]
    }

    /// PINNED: a llama.cpp backend gets the OpenAI chat request with the
    /// tool schemas in `tools` — never the prose-in-prompt shape — until
    /// it refuses them.
    #[test]
    fn llamacpp_native_request_carries_tools_and_streams() {
        let b = llamacpp("http://llamacpp-native-test:8085");
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let (url, body) = build_llm_request(&b, &messages, Some(&tools()), true, false);
        assert_eq!(url, "http://llamacpp-native-test:8085/v1/chat/completions");
        assert_eq!(body["tools"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["messages"][0]["content"], "hi");
        assert!(body.get("prompt").is_none());
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn llamacpp_that_refused_tools_gets_the_prompt_path() {
        let b = llamacpp("http://llamacpp-legacy-test:8085");
        super::super::backend::mark_legacy_completion(&b.url);
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let (url, body) = build_llm_request(&b, &messages, Some(&tools()), false, false);
        assert_eq!(url, "http://llamacpp-legacy-test:8085/completion");
        let prompt = body["prompt"].as_str().unwrap();
        assert!(prompt.contains("web_search"), "tools are described in the prompt");
        assert!(prompt.ends_with("Assistant: "));
        assert!(body.get("tools").is_none());
        // And the legacy response shape still parses tool calls out of text.
        let msg = parse_llm_response("llamacpp", &json!({"content": "<tool_call>{\"name\":\"web_search\",\"arguments\":{\"query\":\"x\"}}</tool_call>"}));
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "web_search");
    }
}

#[cfg(test)]
mod max_tokens_default_tests {
    /// Request building and the context budget's output reserve read
    /// `VLLM_MAX_TOKENS` through one helper over one declared default. Two
    /// literal readers with their own fallbacks (4096 vs 8192) is the bug.
    #[test]
    fn vllm_max_tokens_has_a_single_declared_default() {
        let src = include_str!("agent_loop.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let key = concat!("\"VLLM", "_MAX_TOKENS\"");
        assert_eq!(
            prod.matches(key).count(),
            1,
            "only `vllm_max_tokens()` may name the key (and carry the fallback)"
        );
        assert!(prod.matches("= vllm_max_tokens()").count() >= 3, "all three call sites use the helper");
        assert_eq!(super::DEFAULT_VLLM_MAX_TOKENS, 4096, "the value docs/reference/env.md documents");
    }
}

#[cfg(test)]
mod cloud_loop_tests {
    use super::*;

    /// PINNED (i83 phase C): a cloud model runs the full loop. Neither
    /// entry point may short-circuit to the single-turn, no-tool
    /// `run_cloud_completion` again — that is what made a one-box install
    /// with only an API key a chatbot instead of an agent.
    #[test]
    fn neither_loop_entry_point_short_circuits_to_the_single_turn_path() {
        let src = include_str!("agent_loop.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let sealed = [
            "run_streaming_on", "run_streaming_on_bound", "run_inner", "run_inner_bound",
            "send_llm_with_fallback", "send_cloud_attempt",
        ];
        let mut current: Option<&str> = None;
        let mut seen = std::collections::HashSet::new();
        let mut offenders = Vec::new();
        for (i, line) in prod.lines().enumerate() {
            if let Some(rest) = line.trim_start().strip_prefix("pub(crate) async fn ").or_else(|| line.trim_start().strip_prefix("pub async fn ")).or_else(|| line.trim_start().strip_prefix("async fn ")).or_else(|| line.trim_start().strip_prefix("fn ")) {
                let name = rest.split(['<', '(']).next().unwrap_or("");
                current = sealed.iter().copied().find(|s| *s == name);
                if let Some(f) = current {
                    seen.insert(f);
                }
                continue;
            }
            if let Some(f) = current {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("run_cloud_completion") || code.contains("run_cloud(") {
                    offenders.push(format!("{f} line {}: {}", i + 1, line.trim()));
                }
            }
        }
        assert!(offenders.is_empty(), "the loop short-circuits cloud models:\n{}", offenders.join("\n"));
        assert_eq!(seen.len(), sealed.len(), "the scan covered every entry point: saw {seen:?}");
    }

    fn cloud(backend_type: &str, api_format: &str, url: &str) -> ResolvedBackend {
        ResolvedBackend {
            url: url.to_string(),
            model: "m".to_string(),
            backend_type: backend_type.to_string(),
            api_format: api_format.to_string(),
        }
    }

    fn tools() -> Vec<Value> {
        vec![json!({"type": "function", "function": {"name": "web_search", "description": "search", "parameters": {"type": "object"}}})]
    }

    #[test]
    fn an_anthropic_backend_gets_a_messages_request_with_tools() {
        let b = cloud("cloud-anthropic", "anthropic", super::super::cloud::ANTHROPIC_BASE_URL);
        let messages = vec![json!({"role": "system", "content": "sys"}), json!({"role": "user", "content": "hi"})];
        let (url, body) = build_llm_request(&b, &messages, Some(&tools()), true, true);
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
        assert_eq!(body["system"], "sys");
        assert_eq!(body["tools"][0]["name"], "web_search");
        assert_eq!(body["max_tokens"], super::super::cloud::DEFAULT_MAX_TOKENS);
        assert_eq!(body["stream"], true);
        assert!(body.get("thinking").is_none(), "enable_thinking maps to nothing on Anthropic in this phase");
        assert!(body.get("chat_template_kwargs").is_none());
        // And its non-streaming response parses through the shared entry.
        let msg = parse_llm_response("anthropic", &json!({"content": [{"type": "tool_use", "id": "t1", "name": "web_search", "input": {}}], "stop_reason": "tool_use"}));
        assert_eq!(msg["tool_calls"][0]["function"]["name"], "web_search");
    }

    #[test]
    fn cloud_openai_and_gemini_get_plain_chat_completions() {
        let messages = vec![
            json!({"role": "user", "content": "hi"}),
            json!({"role": "tool", "name": "web_search", "content": "r", "tool_call_id": "c1"}),
        ];
        let o = cloud("cloud-openai", "openai", super::super::cloud::OPENAI_BASE_URL);
        let (url, body) = build_llm_request(&o, &messages, Some(&tools()), true, true);
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
        assert!(body.get("chat_template_kwargs").is_none(), "vLLM-only extras stay off a provider");
        assert!(body.get("max_tokens").is_none());
        assert_eq!(body["tools"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["messages"][1], json!({"role": "tool", "content": "r", "tool_call_id": "c1"}));
        let g = cloud("cloud-gemini", "openai", super::super::cloud::GEMINI_BASE_URL);
        let (url, _) = build_llm_request(&g, &messages, None, false, false);
        assert_eq!(url, "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
        // A node backend is untouched by any of this.
        let v = cloud("vllm", "openai", "https://noo-vllm:8000");
        let (url, body) = build_llm_request(&v, &messages, None, false, false);
        assert_eq!(url, "https://noo-vllm:8000/v1/chat/completions");
        assert!(body.get("chat_template_kwargs").is_some());
    }
}
