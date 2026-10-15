// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cloud providers (Anthropic, OpenAI, Gemini): the gate, the keys, the
//! endpoints, and the auth each provider wants.
//!
//! The agent loop runs cloud models like any other backend: a cloud model
//! resolves to a `ResolvedBackend` (`backend::cloud_backend`, built from
//! [`cloud_backend_with`] here) and goes through the full tool loop —
//! context layers, tools, session, usage, hooks (i83 phase C). Before that,
//! both loop entry points short-circuited to [`run_cloud_completion`], a
//! single-turn, no-tool completion; that function remains only for the
//! harness rail's `CloudRun` op and the `/api/inference/stream` route.
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
pub(crate) const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_TEMPERATURE: f64 = 0.7;

/// Which cloud provider serves a given model name.
enum Provider {
    Anthropic,
    OpenAi,
    Gemini,
}

impl Provider {
    /// `ResolvedBackend.backend_type` for this provider's cloud backend.
    fn backend_type(&self) -> &'static str {
        match self {
            Provider::Anthropic => "cloud-anthropic",
            Provider::OpenAi => "cloud-openai",
            Provider::Gemini => "cloud-gemini",
        }
    }

    fn from_backend_type(t: &str) -> Option<Provider> {
        match t {
            "cloud-anthropic" => Some(Provider::Anthropic),
            "cloud-openai" => Some(Provider::OpenAi),
            "cloud-gemini" => Some(Provider::Gemini),
            _ => None,
        }
    }

    /// Wire format: Anthropic's Messages API, or OpenAI chat completions
    /// (OpenAI itself, and Gemini's OpenAI-compatible surface).
    fn api_format(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi | Provider::Gemini => "openai",
        }
    }

    fn base_url(&self) -> &'static str {
        match self {
            Provider::Anthropic => ANTHROPIC_BASE_URL,
            Provider::OpenAi => OPENAI_BASE_URL,
            Provider::Gemini => GEMINI_BASE_URL,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Provider::Anthropic => "Anthropic",
            Provider::OpenAi => "OpenAI",
            Provider::Gemini => "Gemini",
        }
    }

    /// The provider's API key through `lookup` (production: [`env_key`]),
    /// or the "not configured" error every cloud path has always said.
    fn key_with(&self, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
        let (found, missing) = match self {
            Provider::Anthropic => (
                lookup("ANTHROPIC_API_KEY"),
                "ANTHROPIC_API_KEY not configured — cloud model unavailable",
            ),
            Provider::OpenAi => (
                lookup("OPENAI_API_KEY"),
                "OPENAI_API_KEY not configured — cloud model unavailable",
            ),
            Provider::Gemini => (
                lookup("GEMINI_API_KEY").or_else(|| lookup("GOOGLE_API_KEY")),
                "GEMINI_API_KEY/GOOGLE_API_KEY not configured — cloud model unavailable",
            ),
        };
        found.filter(|k| !k.trim().is_empty()).ok_or_else(|| anyhow::anyhow!(missing))
    }
}

/// Provider endpoints, declared once: the single-turn path below and the
/// agent loop's cloud backends both read them.
pub(crate) const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
pub(crate) const OPENAI_BASE_URL: &str = "https://api.openai.com";
/// Gemini's OpenAI-compatible surface. Its chat path is `/chat/completions`
/// directly under this base — no `/v1` segment, unlike OpenAI's.
pub(crate) const GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta/openai";
/// The `anthropic-version` header every Messages API request carries.
pub(crate) const ANTHROPIC_VERSION: &str = "2023-06-01";

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
pub(super) fn env_key(name: &str) -> Option<String> {
    crate::config::secret_env::secret_opt(name)
}

/// The `ResolvedBackend` a cloud model runs on, given the gate decision and
/// a key lookup (pure, so tests need neither the settings cache nor env).
///
/// Order matters and matches `run_cloud_completion`: the gate first, as the
/// typed [`CloudGateClosed`] (the routes answer it 403), then the key, as
/// the plain "not configured" error. No key ever goes into the backend —
/// `ResolvedBackend` crosses the harness rail; the key is attached at send
/// time by [`with_provider_auth`].
pub(crate) fn cloud_backend_with(
    model: &str,
    gate: Result<(), &'static str>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<crate::coordinator::ResolvedBackend> {
    if let Err(msg) = gate {
        return Err(anyhow::Error::new(CloudGateClosed(msg)));
    }
    let Some(provider) = provider_for(model) else {
        bail!("model '{model}' is not a recognized cloud model");
    };
    provider.key_with(lookup)?;
    Ok(crate::coordinator::ResolvedBackend {
        url: provider.base_url().to_string(),
        model: model.to_string(),
        backend_type: provider.backend_type().to_string(),
        api_format: provider.api_format().to_string(),
    })
}

/// Attach the provider's auth to a request for a cloud backend:
/// `x-api-key` + `anthropic-version` for Anthropic, a bearer token for
/// OpenAI and Gemini. The key is read at send time, never stored.
pub(crate) fn with_provider_auth(
    req: reqwest::RequestBuilder,
    backend_type: &str,
) -> Result<reqwest::RequestBuilder> {
    let Some(provider) = Provider::from_backend_type(backend_type) else {
        bail!("backend type '{backend_type}' is not a cloud provider");
    };
    let key = provider.key_with(env_key)?;
    Ok(match provider {
        Provider::Anthropic => req
            .header("x-api-key", key)
            .header("anthropic-version", ANTHROPIC_VERSION),
        Provider::OpenAi | Provider::Gemini => req.bearer_auth(key),
    })
}

/// Human name of a cloud backend's provider ("Anthropic", ...), for errors.
pub(crate) fn provider_label(backend_type: &str) -> &'static str {
    Provider::from_backend_type(backend_type).map(|p| p.label()).unwrap_or("Cloud provider")
}

/// A provider's HTTP error as the user sees it: `Anthropic API error 401
/// Unauthorized: invalid x-api-key` — the same shape the single-turn path
/// has always produced, so a pinned cloud model's failure names the
/// provider, its status and its reason.
pub(crate) fn provider_error_message(backend_type: &str, status: reqwest::StatusCode, body: &str) -> String {
    let data: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({ "raw": snippet(body) }));
    format!("{} API error {status}: {}", provider_label(backend_type), error_snippet(&data))
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
/// session context.
///
/// NOT the agent loop's path: since i83 phase C the loop resolves a cloud
/// model to a cloud `ResolvedBackend` and runs the full tool loop. This
/// stays for compatibility only — the harness rail's `CloudRun` op (older
/// node harnesses) and the `/api/inference/stream` route's cloud branch.
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
            let key = provider.key_with(env_key)?;
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
                .post(format!("{ANTHROPIC_BASE_URL}/v1/messages"))
                .header("x-api-key", key)
                .header("anthropic-version", ANTHROPIC_VERSION)
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
            let key = provider.key_with(env_key)?;
            openai_compat_completion(
                &client,
                &format!("{OPENAI_BASE_URL}/v1/chat/completions"),
                &key,
                model,
                &system_prompt,
                prompt,
                "OpenAI",
            )
            .await?
        }
        Provider::Gemini => {
            let key = provider.key_with(env_key)?;
            openai_compat_completion(
                &client,
                &format!("{GEMINI_BASE_URL}/chat/completions"),
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

    fn keys(names: &'static [&'static str]) -> impl Fn(&str) -> Option<String> {
        move |n: &str| names.contains(&n).then(|| format!("key-for-{n}"))
    }

    #[test]
    fn each_prefix_resolves_to_its_provider_backend() {
        let all = keys(&["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]);
        let a = cloud_backend_with("claude-sonnet-4-5", Ok(()), &all).unwrap();
        assert_eq!((a.url.as_str(), a.backend_type.as_str(), a.api_format.as_str()), ("https://api.anthropic.com", "cloud-anthropic", "anthropic"));
        assert_eq!(a.model, "claude-sonnet-4-5");
        let o = cloud_backend_with("gpt-4o", Ok(()), &all).unwrap();
        assert_eq!((o.url.as_str(), o.backend_type.as_str(), o.api_format.as_str()), ("https://api.openai.com", "cloud-openai", "openai"));
        let g = cloud_backend_with("gemini-2.5-pro", Ok(()), &all).unwrap();
        assert_eq!(
            (g.url.as_str(), g.backend_type.as_str(), g.api_format.as_str()),
            ("https://generativelanguage.googleapis.com/v1beta/openai", "cloud-gemini", "openai")
        );
        // GOOGLE_API_KEY still serves Gemini.
        assert!(cloud_backend_with("gemini-2.5-pro", Ok(()), keys(&["GOOGLE_API_KEY"])).is_ok());
        // No key never goes into the backend (it crosses the harness rail).
        assert!(!serde_json::to_string(&a).unwrap().contains("key-for"));
        for b in [&a, &o, &g] {
            assert!(super::super::backend::is_cloud_backend(b));
        }
        let node = crate::coordinator::ResolvedBackend { url: "https://noo-vllm:8000".into(), model: "q".into(), backend_type: "vllm".into(), api_format: "openai".into() };
        assert!(!super::super::backend::is_cloud_backend(&node));
    }

    #[test]
    fn a_closed_gate_is_the_typed_refusal_before_any_key_check() {
        let e = cloud_backend_with("claude-x", Err(CLOUD_GATE_REFUSAL), keys(&[])).unwrap_err();
        assert!(cloud_gate_refusal(&e).is_some(), "typed, so the routes answer 403: {e}");
        // The production entry, with the gate at its default (closed).
        std::env::remove_var(CLOUD_GATE_SETTING);
        let e = crate::coordinator::backend::cloud_backend("claude-x").unwrap_err();
        assert!(cloud_gate_refusal(&e).is_some(), "{e}");
        // ...and survives the `?` hops of the loop's resolution.
        let hop = || -> Result<()> { crate::coordinator::backend::cloud_backend("gpt-4o")?; Ok(()) };
        assert!(cloud_gate_refusal(&hop().unwrap_err()).is_some());
    }

    #[test]
    fn a_missing_key_says_which_key_as_before() {
        let e = cloud_backend_with("claude-x", Ok(()), keys(&[])).unwrap_err();
        assert_eq!(e.to_string(), "ANTHROPIC_API_KEY not configured — cloud model unavailable");
        assert!(cloud_gate_refusal(&e).is_none(), "not a policy refusal");
        let e = cloud_backend_with("gemini-x", Ok(()), keys(&[])).unwrap_err();
        assert!(e.to_string().starts_with("GEMINI_API_KEY/GOOGLE_API_KEY not configured"));
    }

    #[test]
    fn a_provider_error_names_provider_status_and_reason() {
        let m = provider_error_message(
            "cloud-anthropic",
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        );
        assert_eq!(m, "Anthropic API error 401 Unauthorized: invalid x-api-key");
        let m = provider_error_message("cloud-gemini", reqwest::StatusCode::BAD_GATEWAY, "upstream gone");
        assert_eq!(m, "Gemini API error 502 Bad Gateway: upstream gone");
    }

    #[test]
    fn unset_setting_resolves_closed() {
        // No override row, no env var in the test process: default false.
        std::env::remove_var(CLOUD_GATE_SETTING);
        assert!(cloud_gate().is_err());
    }
}
