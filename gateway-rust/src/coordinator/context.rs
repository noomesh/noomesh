// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Context assembly: RAG/memory/video/companion/prompt-skills fetchers,
//! persona loading, awareness/identity prompt sections, layer timing.

use anyhow::Result;
use serde_json::{json, Value};

use std::time::{Duration, Instant};

use crate::state::AppState;
use crate::worker_client;

#[allow(unused_imports)]
use super::*;

/// Wrap a layer-fetch future with latency + invocation counters. Layers
/// run concurrently inside `tokio::join!` so per-future timing is the
/// only way to get breakdown visibility.
pub(super) async fn time_layer<T, F>(
    metrics: &std::sync::Arc<crate::metrics::MetricsState>,
    layer: &'static str,
    fut: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let result = fut.await;
    let ms = start.elapsed().as_millis() as u64;
    let mut labels = std::collections::HashMap::new();
    labels.insert("layer".to_string(), layer.to_string());
    metrics
        .inc_counter("context_injection_layer_latency_ms_total", Some(&labels), ms)
        .await;
    metrics
        .inc_counter("context_injection_layer_invocations_total", Some(&labels), 1)
        .await;
    result
}

/// Record per-layer char count as a most-recent gauge.
pub(super) async fn record_layer_chars(
    metrics: &std::sync::Arc<crate::metrics::MetricsState>,
    layer: &str,
    content: &str,
) {
    let mut labels = std::collections::HashMap::new();
    labels.insert("layer".to_string(), layer.to_string());
    metrics
        .set_gauge("context_injection_layer_chars", Some(&labels), content.len() as f64)
        .await;
}

/// Line-level dedup for the assembled context. Suppresses lines already
/// seen earlier in the string (normalised: trimmed + lowercased). Keeps
/// layer section headers (lines starting with `[`) intact so provenance
/// stays clear even when content is filtered. Blank lines pass through.
///
/// The audit's 3-gram suppression is theoretically richer but also slower
/// and more fragile on short lines; line-level catches the common case
/// (same sentence stated in two layers — Layer B summary ↔ Layer C recall)
/// with deterministic behaviour.
pub(super) fn dedup_context_lines(text: &str) -> String {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = String::with_capacity(text.len());
    for raw in text.split_inclusive('\n') {
        let line = raw.trim_end_matches('\n');
        let stripped = line.trim();
        // Always keep structural anchors
        if stripped.is_empty() || stripped.starts_with('[') {
            out.push_str(raw);
            continue;
        }
        let key = stripped.to_lowercase();
        if seen.insert(key) {
            out.push_str(raw);
        }
        // else: already seen, drop silently
    }
    out
}

/// Fetch RAG context for a query from the Python worker.
/// Times out after 5s — proceeds without RAG if worker is unavailable.
/// Select relevant operational runbook content based on keywords in the user's query.
/// Returns at most 2 runbooks (truncated to 3000 chars each) to avoid context bloat.
pub(crate) fn select_runbook_context(runbooks: &[(String, String)], query: &str) -> Option<String> {
    if runbooks.is_empty() { return None; }

    let query_lower = query.to_lowercase();
    let keyword_map: &[(&[&str], &str)] = &[
        (&["backend", "start", "stop", "vllm", "ollama", "llamacpp", "model"], "backend-lifecycle"),
        (&["cert", "pki", "tls", "ssl", "certificate", "rotate"], "pki-certificates"),
        (&["health", "offline", "quarantine", "heartbeat", "status"], "cluster-health"),
        (&["nats", "message", "subscribe", "publish", "kv", "jetstream"], "nats-messaging"),
        (&["job", "queue", "scheduler", "task", "dispatch"], "job-scheduler"),
        (&["autonomy", "patrol", "location", "self-heal", "monitor"], "autonomy-engine"),
        (&["inference", "route", "resolution", "context window"], "inference-routing"),
        (&["agent", "go agent", "node-agent", "gpu detect"], "go-node-agent"),
    ];

    let mut matches: Vec<(&str, usize)> = Vec::new();
    for (keywords, runbook_name) in keyword_map {
        let score = keywords.iter().filter(|kw| query_lower.contains(*kw)).count();
        if score > 0 {
            matches.push((runbook_name, score));
        }
    }
    if matches.is_empty() { return None; }

    matches.sort_by_key(|m| std::cmp::Reverse(m.1));
    let top = &matches[..matches.len().min(2)];

    let mut ctx = String::from("[Operational Runbooks]\n");
    for (name, _) in top {
        if let Some((_, content)) = runbooks.iter().find(|(stem, _)| stem == name) {
            let truncated = crate::text::clip(content, 3000);
            ctx.push_str(&format!("\n--- {} ---\n{}\n", name, truncated));
        }
    }

    if ctx.len() > 30 { Some(ctx) } else { None }
}

pub(super) async fn fetch_rag_context(
    nats: &async_nats::Client,
    query: &str,
    user_id: Option<&str>,
) -> Option<String> {
    // Use lightweight retrieval-only mode for context injection (no LLM synthesis).
    // The full rag.query pipeline takes 1-2 min (includes LLM answer generation),
    // which exceeds the timeout. Retrieval-only returns document chunks in ~5s.
    //
    // Multi-user (PR3a): forward the authenticated user_id so the worker scopes
    // KB retrieval to that user's audience (own + shared tiers) instead of
    // injecting the whole corpus into every system prompt. None = single-user
    // behaviour (or fail-closed when no scope resolves, decided worker-side).
    let result = worker_client::request_with_timeout(
        nats,
        "worker.rag.context",
        &json!({"question": query, "top_k": 5, "user_id": user_id}),
        Duration::from_secs(10),
    ).await.ok()?;

    let data = result.get("data").unwrap_or(&result);
    let answer = data.get("answer").and_then(|a| a.as_str()).unwrap_or("");
    if answer.is_empty() {
        return None;
    }

    let mut context = format!("[Knowledge Base]\n{answer}");

    if let Some(citations) = data.get("citations").and_then(|c| c.as_array()) {
        if !citations.is_empty() {
            context.push_str("\nSources:");
            for c in citations.iter().take(3) {
                let title = c.get("title").and_then(|t| t.as_str()).unwrap_or("?");
                context.push_str(&format!("\n  - {title}"));
            }
        }
    }

    // Include graph context if available
    if let Some(graph) = data.get("graph_context") {
        if let Some(hypotheses) = graph.get("hypotheses").and_then(|h| h.as_array()) {
            if !hypotheses.is_empty() {
                context.push_str("\nKnowledge graph relationships:");
                for h in hypotheses.iter().take(3) {
                    let desc = h.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    let confidence = h.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
                    if !desc.is_empty() {
                        context.push_str(&format!("\n  - {desc} (confidence: {:.0}%)", confidence * 100.0));
                    }
                }
            }
        }
        if let Some(entities) = graph.get("seed_entities").and_then(|e| e.as_array()) {
            let names: Vec<&str> = entities.iter()
                .take(5)
                .filter_map(|e| e.get("canonical_name").and_then(|n| n.as_str()))
                .collect();
            if !names.is_empty() {
                context.push_str(&format!("\nRelevant entities: {}", names.join(", ")));
            }
        }
    }

    Some(context)
}

/// Fetch conversation memory for context.
/// Times out after 5s — proceeds without memory if worker is unavailable.
pub(super) async fn fetch_memory_context(
    nats: &async_nats::Client,
    query: &str,
    user_id: Option<&str>,
) -> Option<String> {
    // H-D1: pass the authenticated user_id so the worker scopes memory search
    // to this user's entries (plus shared rows) instead of every user's data.
    let result = worker_client::request_with_timeout(
        nats,
        "worker.memory.search",
        &json!({"query": query, "top_k": 5, "user_id": user_id}),
        Duration::from_secs(5),
    ).await.ok()?;

    let data = result.get("data").unwrap_or(&result);
    let text = data.as_str().or_else(|| data.get("text").and_then(|t| t.as_str()))?;
    if text.is_empty() {
        return None;
    }
    Some(format!("[Conversation Memory]\n{text}"))
}

/// Fetch cross-channel context — recent messages from other channels (Google Chat,
/// Telegram, WhatsApp) that may be relevant to the current conversation.
/// This provides continuity when users switch between channels.
pub(super) async fn fetch_cross_channel_context(
    nats: &async_nats::Client,
    query: &str,
    current_channel: &str,
    user_id: Option<&str>,
) -> Option<String> {
    // H-D1: scope cross-channel activity to the requesting user.
    let result = worker_client::request_with_timeout(
        nats,
        "worker.memory.cross_channel",
        &json!({
            "query": query,
            "exclude_channel": current_channel,
            "top_k": 3,
            "max_age_hours": 24,
            "user_id": user_id,
        }),
        Duration::from_secs(5),
    ).await.ok()?;

    let data = result.get("data").unwrap_or(&result);
    let messages = data.get("messages").and_then(|m| m.as_array())?;
    if messages.is_empty() {
        return None;
    }

    let mut context = String::from("[Recent Activity from Other Channels]");
    for msg in messages.iter().take(3) {
        let channel = msg.get("channel").and_then(|c| c.as_str()).unwrap_or("?");
        let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
        let preview: String = content.chars().take(200).collect();
        context.push_str(&format!("\n- ({channel}) {preview}"));
    }
    Some(context)
}

// ═══════════════════════════════════════════════════════════════
// Additional context fetchers (Items 1-4: prompt skills, recall memory,
// companion context — mirrors Python coordinator._inject_context)
// ═══════════════════════════════════════════════════════════════

/// Fetch prompt skills catalog for injection into the system prompt.
/// Lists available expertise skills so the LLM knows what it can invoke.
///
/// In-process as of the prompt_skills port: this was a NATS round trip to
/// `worker.prompt_skills.list` with a 3s timeout, to read markdown files off
/// a disk the gateway can already see. The subject is gone.
fn fetch_prompt_skills_catalog(reg: &crate::prompt_skills::SkillRegistry) -> Option<String> {
    if reg.is_empty() {
        return None;
    }
    let mut catalog = String::from("\n\n## Available Expertise Skills");
    for skill in reg.list_all() {
        catalog.push_str(&format!("\n- **{}**: {}", skill.name, skill.description));
    }
    Some(catalog)
}

/// Select and inject prompt skills based on user intent.
/// Returns skill injection text for the current message context.
///
/// In-process as of the prompt_skills port — previously
/// `worker.prompt_skills.select` over NATS. Selection is pure scoring over
/// files already on disk, so the round trip bought nothing and could time
/// out (3s) and silently drop skills from the prompt.
/// Returns the injection text AND the names actually selected.
///
/// The names are returned because usage recording needs them and previously
/// did not have them: `record_skill_usage` was passed `preferred_skills` —
/// the caller's HINT — rather than the selection. With no preference set
/// (the common case) it recorded an empty list, and with one set it recorded
/// that skill whether or not scoring chose it. Combined with counters that
/// were never persisted, no real usage was recorded.
pub(crate) fn fetch_prompt_skills_context(
    reg: &crate::prompt_skills::SkillRegistry,
    prompt: &str,
    preferred_skills: &[String],
) -> Option<(String, Vec<String>)> {
    let selected = crate::prompt_skills::select(reg, prompt, "coordinator", &[], preferred_skills);
    if selected.is_empty() {
        return None;
    }
    let mut context = String::from("[Active Skills]");
    let mut names = Vec::with_capacity(selected.len());
    for skill in selected {
        context.push('\n');
        context.push_str(&skill.to_injection_text());
        names.push(skill.name.clone());
    }
    Some((context, names))
}

/// Fetch recall memory (System 1 compressed recall) for context.
/// Provides summaries of past conversations relevant to the current query.
pub(super) async fn fetch_video_context(nats: &async_nats::Client, query: &str) -> Option<String> {
    let result = worker_client::request_with_timeout(
        nats,
        "worker.recall.packs",
        &json!({"query": query, "top_k": 3}),
        Duration::from_secs(5),
    ).await.ok()?;

    let data = result.get("data").unwrap_or(&result);
    let packs = data.get("packs").and_then(|p| p.as_array())
        .or_else(|| data.get("results").and_then(|r| r.as_array()))?;
    if packs.is_empty() {
        return None;
    }

    let mut context = String::from("[Past Conversation Context]");
    for pack in packs.iter().take(3) {
        let summary = pack.get("summary").and_then(|s| s.as_str())
            .or_else(|| pack.get("content").and_then(|c| c.as_str()))
            .unwrap_or("");
        if !summary.is_empty() {
            let preview: String = summary.chars().take(300).collect();
            context.push_str(&format!("\n- {preview}"));
        }
    }
    Some(context)
}

/// Fetch companion device context from Tier 5 nodes (phones, tablets).
/// Provides battery, network, sensor state for context-aware responses.
pub(super) async fn fetch_companion_context(state: &AppState) -> Option<String> {
    // Read companion node state from NATS KV mesh_nodes
    let kv = state.js.get_key_value("mesh_nodes").await.ok()?;

    let mut companions = Vec::new();
    // Scan entries for companion-type nodes
    let mut entries = kv.keys().await.ok()?;
    use futures::StreamExt;
    while let Some(key) = entries.next().await {
        let key = match key {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(Some(entry)) = kv.get(&key).await {
            if let Ok(node) = serde_json::from_slice::<Value>(&entry) {
                let tier = node.get("tier").and_then(|t| t.as_u64()).unwrap_or(0);
                if tier == 5 {
                    companions.push(node);
                }
            }
        }
    }

    if companions.is_empty() {
        return None;
    }

    let mut context = String::from("[Companion Devices]");
    for comp in &companions {
        let name = comp.get("node_id").and_then(|n| n.as_str()).unwrap_or("?");
        let battery = comp.get("battery_pct").and_then(|b| b.as_u64());
        let network = comp.get("network_type").and_then(|n| n.as_str()).unwrap_or("?");
        let platform = comp.get("platform").and_then(|p| p.as_str()).unwrap_or("?");

        let mut line = format!("\n- {name} ({platform}, {network}");
        if let Some(batt) = battery {
            line.push_str(&format!(", {batt}% battery"));
        }
        line.push(')');

        // Sensors
        if let Some(sensors) = comp.get("active_sensors").and_then(|s| s.as_array()) {
            let names: Vec<&str> = sensors.iter()
                .filter_map(|s| s.as_str())
                .collect();
            if !names.is_empty() {
                line.push_str(&format!(" sensors: {}", names.join(", ")));
            }
        }
        context.push_str(&line);
    }
    Some(context)
}

// ═══════════════════════════════════════════════════════════════
// Tool expansion (Item 5) — discover new tools after noo_tool_search
// ═══════════════════════════════════════════════════════════════

/// Semantic recall within the current conversation. Uses pgvector cosine
/// similarity on noo_entries scoped to this conversation_id. Returns the
/// most relevant past messages regardless of recency — useful when older
/// content has been dropped by fit_context_window.
pub(super) async fn fetch_conversation_recall(
    state: &AppState,
    conversation_id: &str,
    query: &str,
    top_k: u32,
) -> Option<String> {
    if conversation_id.is_empty() || query.is_empty() {
        return None;
    }

    // 1. Embed the query — mesh, not the static endpoint. This used
    // embed_one() against the configured URL, which on a normal deployment
    // points at nothing on the controller; the `.ok()?` below then turned
    // every failure into "no recall", silently disabling this layer.
    let truncated: String = query.chars().take(1500).collect();
    let embedding = crate::embedding_client::resolve()
        .embed_one_with_mesh(state, &truncated, Duration::from_secs(5))
        .await
        .ok()?;

    let vec_str = crate::embedding_client::pgvector_literal(&embedding);

    // 2. Vector search scoped to THIS conversation only
    let rows: Result<Vec<(String, String, f64)>, _> = sqlx::query_as(
        "SELECT e.type, e.content, \
                1 - (e.embedding <=> CAST($1 AS vector)) AS score \
         FROM noo_entries e \
         WHERE e.conversation_id = $2::uuid \
           AND e.embedding IS NOT NULL \
         ORDER BY e.embedding <=> CAST($1 AS vector) \
         LIMIT $3"
    )
    .bind(&vec_str)
    .bind(conversation_id)
    .bind(top_k as i32)
    .fetch_all(&state.db)
    .await;

    let rows = rows.ok()?;
    if rows.is_empty() {
        return None;
    }

    let mut context = String::from("[Relevant earlier messages in this conversation]");
    for (msg_type, content, score) in rows.iter().take(top_k as usize) {
        // Filter low-relevance results (score below 0.5 = weak match)
        if *score < 0.5 { continue; }
        let preview: String = content.chars().take(300).collect();
        context.push_str(&format!("\n- ({msg_type}, score={:.2}) {preview}", score));
    }

    if context.lines().count() < 2 {
        return None; // No results passed the relevance threshold
    }
    Some(context)
}

// ═══════════════════════════════════════════════════════════════
// Long-conversation Option B: Rolling LLM-generated summary
// ═══════════════════════════════════════════════════════════════

/// Fetch persona/system prompt from file or config (in priority order).
///
/// A NATS KV read (`config` bucket, key `coordinator_prompt`) used to come
/// first, documented as "allows runtime prompt updates". No writer for that
/// bucket has ever existed in this repo, so the read was a per-request KV
/// round-trip that always missed. Runtime prompt changes
/// go through the settings surface, not a bucket nothing fills.
pub(super) async fn load_persona_prompt(state: &AppState) -> String {
    // 1. Try loading from file (prompts/coordinator.md)
    let prompt_paths = [
        "/app/prompts/coordinator.md",
        "prompts/coordinator.md",
    ];
    for path_str in &prompt_paths {
        if let Ok(contents) = tokio::fs::read_to_string(path_str).await {
            let prompt = contents.trim().to_string();
            if !prompt.is_empty() {
                tracing::debug!(source = "file", path = path_str, "persona_prompt_loaded");
                return prompt;
            }
        }
    }

    // 3. Fall back to config
    let base = state.config.coordinator.system_prompt.clone();

    // Inject runtime identity (matches Python _load_system_prompt)
    let model = state.config.cluster.backends
        .get(state.config.cluster.default_backend.as_str())
        .map(|b| b.model.as_str())
        .unwrap_or("auto");

    let mut prompt = format!(
        "{base}\n\n## Runtime Info\n\
         - Configured model: {model}\n\
         - Backend: auto-detected (local-first)\n\
         - Engine: Rust coordinator (native)\n\
         - All tool calls, memory, and RAG context are handled by the coordinator."
    );

    // Inject data awareness (mirrors Python _format_data_awareness)
    prompt.push_str(&format_data_awareness(state));

    // Inject self-identity (mirrors Python _format_self_identity)
    prompt.push_str(&format_self_identity(state).await);

    // Inject prompt skills catalog (mirrors Python lines 3054-3066)
    if let Some(catalog) = fetch_prompt_skills_catalog(&state.prompt_skills) {
        prompt.push_str(&catalog);
    }

    // Reasoning-channel hint: wrap planning/scratchpad reasoning in
    // <think>...</think> tags. The coordinator's streaming SSE handler
    // recognises these tags and routes their contents to the dashboard's
    // dedicated reasoning UI (collapsible thinking panel) instead of
    // showing them inline as the visible answer.
    //
    // Necessary because vLLM doesn't ship a dedicated reasoning parser
    // for gemma-4 (`*gemma-4*) VLLM_REASONING_PARSER="" ;;` in the vllm
    // container script). Without this hint, gemma's natural "thought\n..."
    // preamble shows up as plain content and clutters the answer.
    // Models with native reasoning support (Qwen3.5, DeepSeek-R1) emit
    // <think> tags by default and ignore this hint cleanly.
    prompt.push_str(
        "\n\n## Output Format\n\
         When you reason, plan, or work through a problem before answering, \
         wrap that scratchpad in `<think>` and `</think>` tags. The dashboard \
         routes anything inside those tags into a collapsible reasoning panel, \
         keeping the visible answer clean. Example:\n\n\
         <think>The user is asking X. Let me first check the KB, then synthesise.</think>\n\n\
         Here is the answer to your question..."
    );

    prompt
}

/// Live node ids + running backends for the system prompt. Grounds
/// node-directed requests ("ask host9 ...", "what's running on host8")
/// in current mesh state — the coordinator's graph memory goes stale, and
/// without this it answers node questions from memory or mis-routes
/// noo_inference to whatever backend resolves first.
pub(super) async fn format_cluster_awareness(state: &AppState) -> String {
    let mut nodes: Vec<String> = Vec::new();
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        if let Ok(keys) = kv.keys().await {
            use tokio_stream::StreamExt;
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect::<Vec<String>>().await;
            for key in keys {
                if let Ok(Some(value)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&value) {
                        let id = data.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&key)
                            .to_string();
                        let backends = data.get("running_backends")
                            .or_else(|| data.get("backends"))
                            .and_then(|b| b.as_object())
                            .map(|b| b.iter()
                                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?")))
                                .collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        if backends.is_empty() {
                            nodes.push(id);
                        } else {
                            nodes.push(format!("{id} ({backends})"));
                        }
                    }
                }
            }
        }
    }
    if nodes.is_empty() {
        return String::new();
    }
    format!(
        "\n\n## Cluster Nodes (live)\n\
         Nodes currently online: {}.\n\
         - For \"what is running on <node>\" or any node/cluster status question, call noo_cluster_status and answer from its LIVE output — never from memory or the knowledge graph, which go stale.\n\
         - To send a prompt to a SPECIFIC node's model (\"ask <node> ...\"), call noo_inference with node=\"<node_id>\". Without the node argument the prompt routes to the default backend, NOT the node the user named.\n\
         - Never attribute a model response to a node unless the call was pinned to it with node=\"...\".",
        nodes.join("; ")
    )
}

/// Tell the model about available data directories and knowledge base.
/// Without this, the LLM doesn't know it has internal knowledge and defaults
/// to web_search for everything.
fn format_data_awareness(state: &AppState) -> String {
    let mut parts = vec!["\n\n## Data Sources & Knowledge".to_string()];

    parts.push("You have an internal knowledge base (PageIndex) containing ingested documents.".into());
    parts.push("KNOWLEDGE WORKFLOW — both sources are valuable; use them in this order:".into());
    parts.push("  1. Call noo_rag_query FIRST to ground your answer in the user's curated material.".into());
    parts.push("  2. THEN call web_search to augment, fill gaps, or add current/external perspective.".into());
    parts.push("Do NOT skip step 1 because the topic is broad, strategic, or 'likely needs external knowledge' — that's exactly when the user has often ingested relevant material, and starting from their context produces a better, more grounded answer than a pure web summary.".into());
    parts.push("Cite which source each part of the answer came from when both were used.".into());
    parts.push("Skip step 1 ONLY for: trivially conversational replies, real-time data the KB cannot have (current weather, today's prices), or after a recent noo_rag_query in this same conversation already returned nothing relevant.".into());

    // Watched folders
    let wf = &state.config.watched_folders;
    if wf.enabled && !wf.folders.is_empty() {
        parts.push("Accessible file directories (use local_files tool):".into());
        for f in &wf.folders {
            match f {
                crate::config::FolderEntry::Detailed { mount, label, .. } => {
                    if label.is_empty() {
                        parts.push(format!("  - {mount}"));
                    } else {
                        parts.push(format!("  - {mount} [{label}]"));
                    }
                }
                crate::config::FolderEntry::Simple(s) => {
                    parts.push(format!("  - {s}"));
                }
            }
        }
    }

    parts.join("\n")
}

/// Inject the mutable self-identity section from noomesh.yaml.
/// This section defines tone, focus, user preferences, and learned behaviors.
async fn format_self_identity(state: &AppState) -> String {
    let yaml = state.config_yaml.read().await;
    let si = match yaml.get("self_identity") {
        Some(v) => v,
        None => return String::new(),
    };

    let mut parts = vec!["\n\n## Self-Identity (learned behavior)".to_string()];

    if let Some(tone) = si.get("tone").and_then(|v| v.as_str()) {
        parts.push(format!("- Tone: {tone}"));
    }
    if let Some(verbosity) = si.get("verbosity").and_then(|v| v.as_str()) {
        parts.push(format!("- Verbosity: {verbosity}"));
    }
    if let Some(focus) = si.get("focus").and_then(|v| v.as_str()) {
        parts.push(format!("- Current focus: {focus}"));
    }
    if let Some(strengths) = si.get("strengths").and_then(|v| v.as_str()) {
        parts.push(format!("- Strengths: {strengths}"));
    }
    if let Some(weaknesses) = si.get("weaknesses").and_then(|v| v.as_str()) {
        parts.push(format!("- Weaknesses: {weaknesses}"));
    }

    // User preferences
    if let Some(prefs) = si.get("user_preferences").and_then(|v| v.as_array()) {
        if !prefs.is_empty() {
            parts.push("- User preferences:".into());
            for pref in prefs {
                if let Some(s) = pref.as_str() {
                    parts.push(format!("  - {s}"));
                }
            }
        }
    }

    // Operating principles
    if let Some(principles) = si.get("operating_principles").and_then(|v| v.as_array()) {
        if !principles.is_empty() {
            parts.push("- Operating principles:".into());
            for p in principles {
                if let Some(s) = p.as_str() {
                    parts.push(format!("  - {s}"));
                }
            }
        }
    }

    // Things to avoid
    if let Some(avoid) = si.get("avoid").and_then(|v| v.as_array()) {
        if !avoid.is_empty() {
            parts.push("- Avoid:".into());
            for a in avoid {
                if let Some(s) = a.as_str() {
                    parts.push(format!("  - {s}"));
                }
            }
        }
    }

    // Preferred skills
    if let Some(skills) = si.get("preferred_skills").and_then(|v| v.as_array()) {
        if !skills.is_empty() {
            parts.push("- Preferred skills:".into());
            for s in skills {
                if let Some(name) = s.as_str() {
                    parts.push(format!("  - {name}"));
                }
            }
        }
    }

    parts.join("\n")
}

// ═══════════════════════════════════════════════════════════════
// Tool schema selection (keyword-based, mirrors Python _select_tools)
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// The clock
// ═══════════════════════════════════════════════════════════════

/// The clock, as prompt text. Every turn carries it.
///
/// The model has no other way to know what day it is. Without this line a
/// relative date resolves against whatever dates the evidence happens to
/// contain: on 2026-09-22 a request for "tasks from the previous meetings
/// going back 3 months" made the model decide the date was "roughly late
/// 2025/early 2026" from the Dec–Feb meeting notes in its retrieval
/// context, query that window twice, and report that the notes held no
/// tasks — while seven Jul–Sep 2026 meetings sat in the base unasked.
pub fn clock_context_at(now: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "\n\n## Clock\n\
         - Now: {} UTC ({}).\n\
         - Resolve every relative date (\"last 3 months\", \"yesterday\", \"this quarter\") \
         from this clock, never from dates found inside documents or tool results.",
        now.format("%Y-%m-%d %H:%M"),
        now.format("%A"),
    )
}

pub fn clock_context() -> String {
    clock_context_at(chrono::Utc::now())
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn the_prompt_names_the_day_and_says_what_to_measure_from() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-22T21:40:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let text = clock_context_at(now);
        assert!(text.contains("2026-09-22 21:40 UTC (Tuesday)"), "{text}");
        assert!(text.contains("never from dates found inside documents"), "{text}");
        // Appended to a persona prompt: it must start a new section, not
        // run into the previous line.
        assert!(text.starts_with("\n\n## Clock"));
    }

    #[test]
    fn the_live_clock_is_this_year_not_the_evidences() {
        let text = clock_context();
        let year = chrono::Utc::now().format("%Y").to_string();
        assert!(text.contains(&format!("- Now: {year}-")), "{text}");
    }
}
