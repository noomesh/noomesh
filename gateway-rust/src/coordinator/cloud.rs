// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Native cloud-provider completions (Anthropic, OpenAI, Gemini).
//!
//! Replaces the retired Python delegation (`worker.coordinator.run` over
//! NATS): cloud-model requests are now served directly by the Rust
//! coordinator with a single-turn, no-tool completion — which is all the
//! Python delegation ever effectively provided (the Python-side handler
//! was never registered in Rust-primary mode, so the path was dead).
//!
//! Provider specifics mirror `src/noomesh/gateway/cloud_providers.py`:
//! - Anthropic: POST /v1/messages, `x-api-key` + `anthropic-version`,
//!   `max_tokens` required, system prompt as top-level `system` field,
//!   text extracted from content blocks.
//! - OpenAI: POST /v1/chat/completions with `Authorization: Bearer`.
//! - Gemini: Google's OpenAI-compat endpoint with `Authorization: Bearer`
//!   (Python used the genai SDK keyed by GOOGLE_API_KEY; we honor
//!   GEMINI_API_KEY first, then GOOGLE_API_KEY).

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use crate::state::AppState;

use super::agent_loop::{CoordinatorResult, UsageStats};
use super::context::load_persona_prompt;

const CLOUD_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_TEMPERATURE: f64 = 0.7;

/// Which cloud provider serves a given model name.
enum Provider {
    Anthropic,
    OpenAi,
    Gemini,
}

fn provider_for(model: &str) -> Option<Provider> {
    if model.starts_with("claude-") {
        Some(Provider::Anthropic)
    } else if model.starts_with("gpt-") {
        Some(Provider::OpenAi)
    } else if model.starts_with("gemini-") {
        Some(Provider::Gemini)
    } else {
        None
    }
}

/// A provider key through `secret_env` — `NAME_FILE` (compose delivers the
/// keys as `/run/secrets` files), then `NOO_SECRET_NAME`, then `NAME`. None
/// when unset; an unreadable named file is logged at ERROR and refused by
/// preflight.
fn env_key(name: &str) -> Option<String> {
    crate::config::secret_env::secret_opt(name)
}

/// The setting that gates every cloud-model request.
pub const CLOUD_GATE_SETTING: &str = "CLOUD_PROVIDERS_ENABLED";

/// Refusal text for a cloud request while the gate is closed. Names the
/// setting and the remedy; the console toggle and `POST /api/settings/flags/set`
/// are the real ways to set a behavioural flag (noo-cli has no command for it).
pub const CLOUD_GATE_REFUSAL: &str = "Cloud models are off: CLOUD_PROVIDERS_ENABLED is not enabled. \
Turn it on in the console under Settings -> Features -> Cloud model routing \
(or POST /api/settings/flags/set {\"key\":\"CLOUD_PROVIDERS_ENABLED\",\"value\":true}). \
Nothing is sent to a cloud provider until you do.";

/// Typed refusal carried through `anyhow` so the HTTP edge can tell a policy
/// refusal (403) from a provider failure (500) by `downcast_ref`, the same way
/// `ModelNotServed` becomes a 404. Display is the refusal text unchanged.
#[derive(Debug)]
pub struct CloudGateClosed(pub &'static str);

impl std::fmt::Display for CloudGateClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CloudGateClosed {}

/// Machine-readable code for the refusal, on both the JSON and SSE surfaces.
pub const CLOUD_GATE_CODE: &str = "cloud_providers_disabled";

/// Short remedy line carried in the body next to the full refusal text.
const CLOUD_GATE_REMEDY: &str = "Enable CLOUD_PROVIDERS_ENABLED in the console under Settings -> Features -> Cloud model routing, or POST /api/settings/flags/set";

/// Body fields of a gate refusal: error, code, setting, remedy. One builder
/// for the JSON 403 and the SSE error event so the two cannot drift.
pub fn cloud_gate_body(msg: &str) -> Value {
    json!({
        "error": msg,
        "code": CLOUD_GATE_CODE,
        "setting": CLOUD_GATE_SETTING,
        "remedy": CLOUD_GATE_REMEDY,
    })
}

/// `Some(refusal)` when `e` is the closed-gate refusal (policy, HTTP 403),
/// `None` for any other failure (provider error, missing key: not a policy
/// refusal, stays whatever status the caller gives it).
pub fn cloud_gate_refusal(e: &anyhow::Error) -> Option<&CloudGateClosed> {
    e.downcast_ref::<CloudGateClosed>()
}

/// Pure gate decision. Absent setting = registry default = off = refused.
fn cloud_gate_decision(enabled: bool) -> Result<(), &'static str> {
    if enabled { Ok(()) } else { Err(CLOUD_GATE_REFUSAL) }
}

/// Gate for cloud-model routing: `noo_settings` row (15s hot reload) -> env
/// -> default false, via the shared `settings::flag` reader. That reader
/// cannot fail: an unloaded cache, an unreachable DB or a poisoned lock all
/// resolve to env/default, i.e. closed. The API-key check in
/// `run_cloud_completion` is an additional gate, not replaced by this one.
pub fn cloud_gate() -> Result<(), &'static str> {
    let r = cloud_gate_decision(crate::settings::flag(CLOUD_GATE_SETTING, false));
    if r.is_err() {
        tracing::warn!(setting = CLOUD_GATE_SETTING, "cloud_request_refused_gate_closed");
    }
    r
}

/// Run a single-turn cloud completion for a cloud model (claude-*, gpt-*,
/// gemini-*). Persona system prompt is included; no tool-calling, no
/// session context (parity with what the retired Python delegation
/// effectively provided).
pub(super) async fn run_cloud_completion(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    model: &str,
) -> Result<CoordinatorResult> {
    // Before any provider lookup or HTTP: every caller (agent loop, harness,
    // streaming route) passes through here.
    if let Err(msg) = cloud_gate() {
        return Err(anyhow::Error::new(CloudGateClosed(msg)));
    }
    let start = Instant::now();
    tracing::info!(
        model = model,
        conversation_id = conversation_id,
        channel = channel,
        "Running cloud model request natively (rust_cloud)"
    );

    let provider = match provider_for(model) {
        Some(p) => p,
        None => bail!("model '{model}' is not a recognized cloud model"),
    };

    let system_prompt = load_persona_prompt(state).await;
    let client = crate::tls::external_client();

    let (response_text, resolved_model, usage) = match provider {
        Provider::Anthropic => {
            let key = env_key("ANTHROPIC_API_KEY").context(
                "ANTHROPIC_API_KEY not configured — cloud model unavailable",
            )?;
            let mut body = json!({
                "model": model,
                "max_tokens": DEFAULT_MAX_TOKENS,
                "temperature": DEFAULT_TEMPERATURE,
                "messages": [{"role": "user", "content": prompt}],
            });
            if !system_prompt.is_empty() {
                body["system"] = json!(system_prompt);
            }
            let resp = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .timeout(CLOUD_TIMEOUT)
                .json(&body)
                .send()
                .await
                .context("Anthropic API request failed")?;
            let status = resp.status();
            let data: Value = parse_response(resp, "Anthropic").await?;
            if !status.is_success() {
                bail!("Anthropic API error {status}: {}", error_snippet(&data));
            }
            // Text lives in content blocks: [{"type":"text","text":...}, ...]
            let text = data
                .get("content")
                .and_then(|c| c.as_array())
                .map(|blocks| {
                    blocks
                        .iter()
                        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default();
            let resolved = data
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or(model)
                .to_string();
            let prompt_tokens = data
                .pointer("/usage/input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let completion_tokens = data
                .pointer("/usage/output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            (
                text,
                resolved,
                (prompt_tokens, completion_tokens, prompt_tokens + completion_tokens),
            )
        }
        Provider::OpenAi => {
            let key = env_key("OPENAI_API_KEY").context(
                "OPENAI_API_KEY not configured — cloud model unavailable",
            )?;
            openai_compat_completion(
                &client,
                "https://api.openai.com/v1/chat/completions",
                &key,
                model,
                &system_prompt,
                prompt,
                "OpenAI",
            )
            .await?
        }
        Provider::Gemini => {
            let key = env_key("GEMINI_API_KEY")
                .or_else(|| env_key("GOOGLE_API_KEY"))
                .context(
                    "GEMINI_API_KEY/GOOGLE_API_KEY not configured — cloud model unavailable",
                )?;
            openai_compat_completion(
                &client,
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                &key,
                model,
                &system_prompt,
                prompt,
                "Gemini",
            )
            .await?
        }
    };

    if response_text.is_empty() {
        tracing::warn!(model = model, "cloud completion returned empty response text");
    }

    let (prompt_tokens, completion_tokens, total_tokens) = usage;
    Ok(CoordinatorResult {
        response: response_text,
        model: resolved_model,
        backend: "cloud".to_string(),
        // No node did this work — the summary layer renders NULL as "cloud".
        node: None,
        iterations: 1,
        tool_calls: Vec::new(),
        elapsed_secs: start.elapsed().as_secs_f64(),
        usage: UsageStats {
            prompt_tokens,
            completion_tokens,
            total_tokens,
            total_tool_calls: 0,
            total_latency_ms: start.elapsed().as_millis() as u64,
        },
    })
}

/// POST an OpenAI-format chat completion and extract text + usage.
/// Shared by OpenAI proper and Gemini's OpenAI-compat endpoint.
async fn openai_compat_completion(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    model: &str,
    system_prompt: &str,
    prompt: &str,
    label: &str,
) -> Result<(String, String, (u32, u32, u32))> {
    let mut messages = Vec::new();
    if !system_prompt.is_empty() {
        messages.push(json!({"role": "system", "content": system_prompt}));
    }
    messages.push(json!({"role": "user", "content": prompt}));

    let body = json!({
        "model": model,
        "messages": messages,
        "max_tokens": DEFAULT_MAX_TOKENS,
        "temperature": DEFAULT_TEMPERATURE,
    });

    let resp = client
        .post(url)
        .bearer_auth(api_key)
        .timeout(CLOUD_TIMEOUT)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("{label} API request failed"))?;
    let status = resp.status();
    let data: Value = parse_response(resp, label).await?;
    if !status.is_success() {
        bail!("{label} API error {status}: {}", error_snippet(&data));
    }

    let text = data
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let resolved = data
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(model)
        .to_string();
    let prompt_tokens = data
        .pointer("/usage/prompt_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let completion_tokens = data
        .pointer("/usage/completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let total_tokens = data
        .pointer("/usage/total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or((prompt_tokens + completion_tokens) as u64) as u32;

    Ok((text, resolved, (prompt_tokens, completion_tokens, total_tokens)))
}

/// Parse a response body as JSON, preserving a text snippet on failure.
async fn parse_response(resp: reqwest::Response, label: &str) -> Result<Value> {
    let body = resp
        .text()
        .await
        .with_context(|| format!("{label} API response read failed"))?;
    Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": snippet(&body) })))
}

/// Pull a human-readable error message out of a provider error body.
fn error_snippet(data: &Value) -> String {
    data.pointer("/error/message")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
        .or_else(|| data.get("raw").and_then(|r| r.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| snippet(&data.to_string()))
}

fn snippet(s: &str) -> String {
    let t = s.trim();
    if t.len() <= 400 {
        return t.to_string();
    }
    let cut: String = t.chars().take(400).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    #[test]
    fn closed_gate_refuses_naming_setting_and_remedy() {
        let msg = cloud_gate_decision(false).unwrap_err();
        assert!(msg.contains("CLOUD_PROVIDERS_ENABLED"));
        assert!(msg.contains("Settings"));
        assert!(msg.contains("/api/settings/flags/set"));
    }

    #[test]
    fn open_gate_passes_on_to_the_key_check() {
        assert!(cloud_gate_decision(true).is_ok());
    }

    #[test]
    fn refusal_is_typed_and_body_carries_the_code() {
        let e = anyhow::Error::new(CloudGateClosed(CLOUD_GATE_REFUSAL));
        let r = cloud_gate_refusal(&e).expect("typed refusal");
        let body = cloud_gate_body(r.0);
        assert_eq!(body["code"], "cloud_providers_disabled");
        assert_eq!(body["setting"], "CLOUD_PROVIDERS_ENABLED");
        assert!(body["error"].as_str().unwrap().contains("Cloud models are off"));
        assert!(body["remedy"].as_str().unwrap().contains("Settings"));
        // A provider failure is not a policy refusal.
        assert!(cloud_gate_refusal(&anyhow::anyhow!("ANTHROPIC_API_KEY not configured")).is_none());
    }

    #[test]
    fn unset_setting_resolves_closed() {
        // No override row, no env var in the test process: default false.
        std::env::remove_var(CLOUD_GATE_SETTING);
        assert!(cloud_gate().is_err());
    }
}
