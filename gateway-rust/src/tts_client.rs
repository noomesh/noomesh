// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Backend-agnostic TTS (text-to-speech) client — the ONE place that knows
//! how to talk to a synthesis server. Twin of `stt_client.rs`: one client,
//! multiple wire formats, config-driven provider selection, so piper is just
//! the first provider — LocalAI, speaches, kokoro-fastapi, openedai-speech
//! or OpenAI cloud slot in by flipping config, not code.
//!
//! Wire formats ("api formats"):
//!
//!   - `openai` — OpenAI-compatible speech API (DEFAULT — OpenAI cloud,
//!                LocalAI, speaches, kokoro-fastapi, openedai-speech, and our
//!                own docker/Dockerfile.piper shim all serve it):
//!                  POST {url}/v1/audio/speech
//!                  json: {model, input, voice, speed, response_format}
//!                  → raw audio bytes (content-type from the response)
//!                Voice inventory: GET {url}/v1/audio/voices when the server
//!                has one (kokoro-fastapi, openedai-speech, our shim).
//!   - `piper`  — the native shape the pre-provider proxy in
//!                routes/communication.rs spoke (and the retired in-process
//!                Python TTS HTTP service served):
//!                  POST {url}/synthesize
//!                  json: {text, voice, speed, backend, stream}
//!                  → raw audio bytes + optional `X-TTS-Backend` header
//!                Voice inventory: GET {url}/voices.
//!
//! Whatever the provider speaks, callers get back ONE contract —
//! [`Speech`] — the shape `noo voice synthesize` / `speak` have always
//! pinned: audio bytes + content-type + a backend label for the
//! `X-TTS-Backend` response header.
//!
//! ### Why edge-tts is NOT a provider here
//!
//! edge-tts is not an HTTP service: the `edge_tts` Python package opens a
//! **WebSocket** to Microsoft's Speech Studio endpoint and signs each
//! request with a derived `Sec-MS-GEC` token that rotates on a clock skew
//! window. There is no URL a generic HTTP client can POST text to, so it
//! cannot be expressed as `NOO_TTS_URL` + a wire format the way piper and
//! the OpenAI shape can. Two honest ways to keep edge voices:
//!   1. point `NOO_TTS_URL` at a service that wraps edge-tts behind the
//!      OpenAI shape (openedai-speech does exactly this) — zero gateway
//!      change, it is just another `openai` provider; or
//!   2. run the retired in-process Python path, which is not coming back.
//! Consequently `edge_tts_available` in `/api/voice/status` is now derived
//! from the configured provider's *advertised inventory* (does it list any
//! `edge-tts` voice?) rather than being hardcoded `true` — which is what
//! made status claim a backend nobody was serving.
//!
//! Config resolution (env → yaml → default — the STT pattern exactly):
//!   NOO_TTS_URL         / services.tts_url         → legacy voice.tts_url
//!                                                     → https://noo-piper:8000
//!   NOO_TTS_BACKEND     / services.tts_backend     → "piper" when the legacy
//!       voice.tts_url is what supplied the URL, else "openai"
//!   NOO_TTS_VOICE       / services.tts_voice       → "" (empty = honour the
//!       per-request client hint; else the provider's own default)
//!   NOO_TTS_API_KEY_ENV / services.tts_api_key_env → "" (NAME of the env var
//!       holding a bearer key — the key itself never lives in YAML)
//!
//! TLS (mTLS doors phase 2, i77): noo-piper serves TLS and REQUIRES a
//! cluster-CA client certificate, so the default is `https://noo-piper:8000`
//! and an `http://` URL is refused, never dialled ([`TTS_DOOR`]). An https
//! URL on the cluster's own names dials with the cluster client (the
//! gateway's leaf); any other https host — a cloud provider — dials with
//! `tls::external_client()` (public roots, no client certificate).

use std::time::Duration;

use serde_json::{json, Value};

use crate::config::env_or_yaml;

/// The default TTS door: the voice overlay's `piper` service.
pub const TTS_DEFAULT_URL: &str = "https://noo-piper:8000";

/// The TTS door's trust rule (see `tls::HttpsDoor`): the cluster's voice
/// names dial with the cluster client, any other https host publicly.
pub const TTS_DOOR: crate::tls::HttpsDoor = crate::tls::HttpsDoor {
    setting: "NOO_TTS_URL",
    default_url: TTS_DEFAULT_URL,
    cluster_hosts: crate::tls::VOICE_CLUSTER_HOSTS,
};

/// Piper's shipped default voice — the same one the retired in-process
/// `PiperTTS` defaulted to (src/noomesh/voice/tts.py), so a request with
/// no voice hint sounds the same as it always did.
pub const DEFAULT_PIPER_VOICE: &str = "en_US-lessac-medium";

/// Resolved TTS endpoint: where to POST, which wire format, which voice.
#[derive(Debug, Clone)]
pub struct TtsEndpoint {
    pub url: String,
    /// Wire format: "openai" | "piper" (see module docs).
    pub api_format: String,
    /// Configured voice pin. Empty = honour the per-request client hint.
    pub voice: String,
    /// Name of the env var holding a bearer API key. Empty = no auth header.
    pub api_key_env: String,
}

/// Per-request synthesis options (the JSON body fields the CLI sends).
#[derive(Debug, Default, Clone)]
pub struct SynthesizeOptions {
    /// Client-supplied voice hint. A non-empty configured
    /// [`TtsEndpoint::voice`] wins over this.
    pub voice: Option<String>,
    /// Speech rate multiplier (1.0 = natural). Validated by the route.
    pub speed: f64,
    /// Client-supplied backend hint (`noo voice synthesize --backend`).
    /// Forwarded on the `piper` wire format (which has such a field) and
    /// used as the model name on `openai` when it names a real model.
    pub backend: Option<String>,
}

/// The one response contract every provider is normalised into.
#[derive(Debug, Clone)]
pub struct Speech {
    pub audio: Vec<u8>,
    /// e.g. "audio/wav" / "audio/mpeg" — relayed to the HTTP client.
    pub content_type: String,
    /// Label for the `X-TTS-Backend` header (provider-declared, else the
    /// wire format name).
    pub backend: String,
}

#[derive(Debug)]
pub enum TtsError {
    /// Transport-level failure (connect/timeout) — provider unreachable.
    Unavailable(String),
    /// Provider answered with a non-2xx status (body kept, truncated).
    BadStatus(reqwest::StatusCode, String),
    /// Provider answered 2xx but the payload was unusable (empty audio,
    /// or a JSON error body where audio was promised).
    Parse(String),
    /// The configured URL is refused before any dial (plaintext).
    Refused(String),
}

impl std::fmt::Display for TtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TtsError::Unavailable(e) => write!(f, "TTS provider unreachable: {e}"),
            TtsError::BadStatus(s, body) => write!(f, "TTS provider returned {s}: {body}"),
            TtsError::Parse(e) => write!(f, "TTS provider parse error: {e}"),
            TtsError::Refused(e) => write!(f, "TTS provider refused: {e}"),
        }
    }
}

impl TtsError {
    /// The HTTP status the gateway should relay for this failure.
    pub fn http_status(&self) -> axum::http::StatusCode {
        match self {
            TtsError::Unavailable(_) | TtsError::Parse(_) => axum::http::StatusCode::BAD_GATEWAY,
            TtsError::Refused(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            TtsError::BadStatus(s, _) => axum::http::StatusCode::from_u16(s.as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        }
    }
}

/// Resolve the configured TTS endpoint (env → yaml → legacy → default).
///
/// `legacy_tts_url` is the raw `voice.tts_url` key from noomesh.yaml (the
/// pre-provider config surface) — passed in by the route because that
/// section never graduated into the typed AppConfig.
pub fn resolve(legacy_tts_url: Option<String>) -> TtsEndpoint {
    let configured_url = env_or_yaml("NOO_TTS_URL", |c| c.services.tts_url.clone(), "");

    // Which URL wins also picks the *default* wire format: an operator who
    // only ever configured the legacy voice.tts_url keeps the legacy native
    // shape until they say otherwise.
    let legacy = legacy_tts_url.filter(|u| !u.trim().is_empty());
    let (url, default_format) = if !configured_url.is_empty() {
        (configured_url, "openai")
    } else if let Some(l) = legacy {
        (l, "piper")
    } else {
        // mTLS (i77 phase 2): noo-piper requires the gateway's leaf.
        (TTS_DEFAULT_URL.to_string(), "openai")
    };

    let api_format = env_or_yaml(
        "NOO_TTS_BACKEND",
        |c| c.services.tts_backend.clone(),
        default_format,
    )
    .to_lowercase();

    let voice = env_or_yaml("NOO_TTS_VOICE", |c| c.services.tts_voice.clone(), "");
    let api_key_env = env_or_yaml(
        "NOO_TTS_API_KEY_ENV",
        |c| c.services.tts_api_key_env.clone(),
        "",
    );

    TtsEndpoint {
        url: url.trim_end_matches('/').to_string(),
        api_format,
        voice,
        api_key_env,
    }
}

impl TtsEndpoint {
    /// The URL to POST a synthesis request to in this wire format.
    fn request_url(&self) -> String {
        match self.api_format.as_str() {
            "piper" => format!("{}/synthesize", self.url),
            // "openai" (default) and anything unrecognized.
            _ => format!("{}/v1/audio/speech", self.url),
        }
    }

    /// The voice actually sent: config pin wins, else the client hint, else
    /// piper's default voice (parity with the retired in-process TTS).
    fn effective_voice(&self, opts: &SynthesizeOptions) -> String {
        if !self.voice.is_empty() {
            return self.voice.clone();
        }
        match &opts.voice {
            Some(v) if !v.is_empty() => v.clone(),
            _ => DEFAULT_PIPER_VOICE.to_string(),
        }
    }

    /// The JSON body for this wire format. Split out so tests can assert the
    /// wire contract without an HTTP server.
    fn request_body(&self, text: &str, opts: &SynthesizeOptions) -> Value {
        let speed = if opts.speed > 0.0 { opts.speed } else { 1.0 };
        match self.api_format.as_str() {
            "piper" => {
                let mut body = json!({
                    "text": text,
                    "voice": self.effective_voice(opts),
                    "speed": speed,
                });
                if let Some(b) = opts.backend.as_ref().filter(|b| !b.is_empty()) {
                    body["backend"] = Value::String(b.clone());
                }
                body
            }
            _ => json!({
                // `model` is required by the OpenAI schema. A client
                // --backend hint names the model when given (that is what
                // "which engine" means on a multi-engine server like
                // openedai-speech); otherwise "tts-1", the name every
                // OpenAI-compatible server accepts.
                "model": opts
                    .backend
                    .as_ref()
                    .filter(|b| !b.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "tts-1".to_string()),
                "input": text,
                "voice": self.effective_voice(opts),
                "speed": speed,
                // wav: the format piper produces natively and the only one
                // guaranteed without an mp3 encoder in the provider.
                "response_format": "wav",
            }),
        }
    }

    /// Synthesize one utterance. One HTTP round-trip; the reply is the
    /// [`Speech`] contract regardless of provider.
    pub async fn synthesize(
        &self,
        text: &str,
        opts: &SynthesizeOptions,
        timeout: Duration,
    ) -> Result<Speech, TtsError> {
        // The cluster client for noo-piper (presents the gateway's leaf),
        // the public client for a cloud provider; http:// never dials.
        let client = TTS_DOOR.client(&self.url).map_err(TtsError::Refused)?;
        self.synthesize_via(&client, text, opts, timeout).await
    }

    /// The round-trip itself, on a client already chosen by [`TTS_DOOR`].
    async fn synthesize_via(
        &self,
        client: &reqwest::Client,
        text: &str,
        opts: &SynthesizeOptions,
        timeout: Duration,
    ) -> Result<Speech, TtsError> {
        let mut req = client
            .post(self.request_url())
            .json(&self.request_body(text, opts))
            .timeout(timeout);
        if !self.api_key_env.is_empty() {
            if let Some(key) = crate::config::secret_env::secret_opt(&self.api_key_env) {
                if !key.is_empty() {
                    req = req.bearer_auth(key);
                }
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| TtsError::Unavailable(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(500);
            return Err(TtsError::BadStatus(status, body));
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("audio/wav")
            .to_string();
        // Provider-declared backend label if it sends one; else the wire
        // format name — never the hardcoded "piper" the old proxy assumed.
        let backend = resp
            .headers()
            .get("x-tts-backend")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.api_format.clone());

        let audio = resp
            .bytes()
            .await
            .map_err(|e| TtsError::Parse(e.to_string()))?
            .to_vec();
        Self::validate(audio, content_type, backend)
    }

    /// Shared post-conditions on a 2xx reply: audio must be non-empty and
    /// must not be a JSON error body wearing an audio content-type (some
    /// providers answer 200 + `{"error": …}`).
    fn validate(
        audio: Vec<u8>,
        content_type: String,
        backend: String,
    ) -> Result<Speech, TtsError> {
        if audio.is_empty() {
            return Err(TtsError::Parse("provider returned empty audio".into()));
        }
        if content_type.starts_with("application/json") || audio.starts_with(b"{") {
            let mut body = String::from_utf8_lossy(&audio).to_string();
            body.truncate(300);
            return Err(TtsError::Parse(format!(
                "expected audio, got JSON: {body}"
            )));
        }
        Ok(Speech {
            audio,
            content_type,
            backend,
        })
    }

    /// Health-probe URL appropriate for this wire format's server.
    pub fn health_url(&self) -> String {
        match self.api_format.as_str() {
            "piper" => format!("{}/health", self.url),
            _ => format!("{}/v1/models", self.url),
        }
    }

    /// Voice-inventory URL for this wire format.
    fn voices_url(&self) -> String {
        match self.api_format.as_str() {
            "piper" => format!("{}/voices", self.url),
            _ => format!("{}/v1/audio/voices", self.url),
        }
    }

    /// Normalise a provider voice list into the `/api/voice/voices` contract
    /// entry shape: {name, language, quality?, gender?, description, backend}.
    ///
    /// Accepts every inventory shape seen in the wild:
    ///   {"voices": [{…}|"name", …]}   (our shim, openedai-speech, kokoro)
    ///   {"data":   [{…}, …]}          (OpenAI-model-list style)
    ///   [ … ]                          (bare array)
    fn parse_voices(&self, data: Value) -> Vec<Value> {
        let items = data
            .get("voices")
            .or_else(|| data.get("data"))
            .cloned()
            .unwrap_or(data);
        let Some(arr) = items.as_array() else {
            return Vec::new();
        };
        arr.iter()
            .filter_map(|item| {
                // A bare string is just a voice name.
                if let Some(name) = item.as_str() {
                    return Some(json!({
                        "name": name,
                        "language": "",
                        "description": format!("{} voice: {name}", self.api_format),
                        "backend": self.default_backend_label(),
                    }));
                }
                let obj = item.as_object()?;
                let name = obj
                    .get("name")
                    .or_else(|| obj.get("id"))
                    .and_then(Value::as_str)?
                    .to_string();
                let language = obj
                    .get("language")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let backend = obj
                    .get("backend")
                    .and_then(Value::as_str)
                    .unwrap_or(self.default_backend_label())
                    .to_string();
                let mut out = json!({
                    "name": name,
                    "language": language,
                    "description": obj
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    "backend": backend,
                });
                if let Some(q) = obj.get("quality").and_then(Value::as_str) {
                    out["quality"] = Value::String(q.to_string());
                }
                if let Some(g) = obj.get("gender").and_then(Value::as_str) {
                    out["gender"] = Value::String(g.to_string());
                }
                Some(out)
            })
            .collect()
    }

    /// Backend label used for voices the provider didn't label itself.
    fn default_backend_label(&self) -> &str {
        match self.api_format.as_str() {
            "piper" => "piper",
            other => other,
        }
    }

    /// Fetch the provider's voice inventory. An empty list means "the
    /// provider is up but advertises nothing" or "unreachable" — the caller
    /// reports reachability separately, so this never invents voices.
    pub async fn list_voices(&self, timeout: Duration) -> Result<Vec<Value>, TtsError> {
        let client = TTS_DOOR.client(&self.url).map_err(TtsError::Refused)?;
        self.list_voices_via(&client, timeout).await
    }

    async fn list_voices_via(&self, client: &reqwest::Client, timeout: Duration) -> Result<Vec<Value>, TtsError> {
        let mut req = client.get(self.voices_url()).timeout(timeout);
        if !self.api_key_env.is_empty() {
            if let Some(key) = crate::config::secret_env::secret_opt(&self.api_key_env) {
                if !key.is_empty() {
                    req = req.bearer_auth(key);
                }
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| TtsError::Unavailable(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(300);
            return Err(TtsError::BadStatus(status, body));
        }
        let data: Value = resp
            .json()
            .await
            .map_err(|e| TtsError::Parse(e.to_string()))?;
        Ok(self.parse_voices(data))
    }

    /// Is this endpoint answering right now? Used by `/api/voice/status`.
    /// A refused (plaintext) URL is simply not available.
    pub async fn probe(&self, timeout: Duration) -> bool {
        let Ok(client) = TTS_DOOR.client(&self.url) else {
            return false;
        };
        client
            .get(self.health_url())
            .timeout(timeout)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(format: &str) -> TtsEndpoint {
        TtsEndpoint {
            url: "http://tts:8000".into(),
            api_format: format.into(),
            voice: String::new(),
            api_key_env: String::new(),
        }
    }

    fn opts() -> SynthesizeOptions {
        SynthesizeOptions { speed: 1.0, ..Default::default() }
    }

    // ── Wire contract: request side ──

    #[test]
    fn openai_request_shape() {
        let e = ep("openai");
        assert_eq!(e.request_url(), "http://tts:8000/v1/audio/speech");
        let body = e.request_body("Hello Mesh", &SynthesizeOptions {
            voice: Some("af_heart".into()),
            speed: 1.25,
            backend: None,
        });
        assert_eq!(body["input"], "Hello Mesh");
        assert_eq!(body["voice"], "af_heart");
        assert_eq!(body["speed"], 1.25);
        assert_eq!(body["model"], "tts-1");
        assert_eq!(body["response_format"], "wav");
        // the piper dialect must not leak into the openai body
        assert!(body.get("text").is_none());
    }

    #[test]
    fn openai_backend_hint_names_the_model() {
        let e = ep("openai");
        let body = e.request_body("hi", &SynthesizeOptions {
            backend: Some("piper".into()),
            speed: 1.0,
            ..Default::default()
        });
        assert_eq!(body["model"], "piper");
    }

    #[test]
    fn piper_request_shape() {
        let e = ep("piper");
        assert_eq!(e.request_url(), "http://tts:8000/synthesize");
        let body = e.request_body("Hello Mesh", &SynthesizeOptions {
            voice: Some("en_GB-alba-medium".into()),
            speed: 0.9,
            backend: Some("piper".into()),
        });
        assert_eq!(body["text"], "Hello Mesh");
        assert_eq!(body["voice"], "en_GB-alba-medium");
        assert_eq!(body["speed"], 0.9);
        assert_eq!(body["backend"], "piper");
        // the openai dialect must not leak into the piper body
        assert!(body.get("input").is_none());
        assert!(body.get("model").is_none());
    }

    #[test]
    fn configured_voice_pin_wins_over_client_hint() {
        let mut e = ep("openai");
        e.voice = "en_US-amy-low".into();
        let body = e.request_body("hi", &SynthesizeOptions {
            voice: Some("af_heart".into()),
            speed: 1.0,
            ..Default::default()
        });
        assert_eq!(body["voice"], "en_US-amy-low");
    }

    #[test]
    fn empty_hint_falls_back_to_piper_default_voice() {
        let body = ep("openai").request_body("hi", &opts());
        assert_eq!(body["voice"], DEFAULT_PIPER_VOICE);
    }

    #[test]
    fn zero_speed_is_normalised_to_one() {
        let body = ep("piper").request_body("hi", &SynthesizeOptions::default());
        assert_eq!(body["speed"], 1.0);
    }

    // ── Response validation ──

    #[test]
    fn valid_audio_passes_through() {
        let s = TtsEndpoint::validate(
            b"RIFF....WAVEfmt ".to_vec(),
            "audio/wav".into(),
            "piper".into(),
        )
        .unwrap();
        assert_eq!(s.content_type, "audio/wav");
        assert_eq!(s.backend, "piper");
        assert!(!s.audio.is_empty());
    }

    #[test]
    fn empty_audio_is_parse_error() {
        match TtsEndpoint::validate(Vec::new(), "audio/wav".into(), "piper".into()) {
            Err(TtsError::Parse(m)) => assert!(m.contains("empty")),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn json_body_with_audio_content_type_is_parse_error() {
        // A 200 + {"error": …} must not be handed to the client as "audio".
        match TtsEndpoint::validate(
            br#"{"error":"no such voice"}"#.to_vec(),
            "audio/wav".into(),
            "piper".into(),
        ) {
            Err(TtsError::Parse(m)) => assert!(m.contains("no such voice")),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    // ── Voice inventory normalisation ──

    #[test]
    fn parses_object_voice_list() {
        let e = ep("piper");
        let voices = e.parse_voices(json!({"voices": [
            {"name": "en_US-lessac-medium", "language": "en_US", "quality": "medium",
             "description": "Piper voice", "backend": "piper"},
            {"name": "en_GB-alba-medium", "language": "en_GB"},
        ]}));
        assert_eq!(voices.len(), 2);
        assert_eq!(voices[0]["name"], "en_US-lessac-medium");
        assert_eq!(voices[0]["quality"], "medium");
        // unlabelled entries inherit the provider's backend label
        assert_eq!(voices[1]["backend"], "piper");
    }

    #[test]
    fn parses_bare_string_and_data_shapes() {
        let e = ep("openai");
        let voices = e.parse_voices(json!({"voices": ["af_heart", "am_puck"]}));
        assert_eq!(voices.len(), 2);
        assert_eq!(voices[0]["name"], "af_heart");
        assert_eq!(voices[0]["backend"], "openai");

        let via_data = e.parse_voices(json!({"data": [{"id": "alloy"}]}));
        assert_eq!(via_data[0]["name"], "alloy");

        let bare = e.parse_voices(json!([{"name": "nova", "gender": "Female"}]));
        assert_eq!(bare[0]["name"], "nova");
        assert_eq!(bare[0]["gender"], "Female");
    }

    #[test]
    fn unparseable_inventory_yields_no_voices() {
        // Honest emptiness beats invented defaults.
        assert!(ep("openai").parse_voices(json!({"nope": 1})).is_empty());
    }

    // ── Health / error mapping ──

    #[test]
    fn health_and_voices_urls_per_format() {
        assert_eq!(ep("piper").health_url(), "http://tts:8000/health");
        assert_eq!(ep("piper").voices_url(), "http://tts:8000/voices");
        assert_eq!(ep("openai").health_url(), "http://tts:8000/v1/models");
        assert_eq!(ep("openai").voices_url(), "http://tts:8000/v1/audio/voices");
    }

    #[test]
    fn error_http_status_mapping() {
        assert_eq!(
            TtsError::Unavailable("x".into()).http_status(),
            axum::http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            TtsError::Parse("x".into()).http_status(),
            axum::http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            TtsError::BadStatus(reqwest::StatusCode::NOT_FOUND, "".into()).http_status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }

    // ── Mock server round-trip: exercises the REAL synthesize() path —
    //    JSON request, header handling, byte relay, contract mapping. ──

    /// One-shot HTTP mock: accepts a single connection, reads the full
    /// request, answers with `body` under `content_type` (+ X-TTS-Backend).
    async fn one_shot_mock(
        content_type: &'static str,
        backend: Option<&'static str>,
        body: &'static [u8],
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            let (mut header_end, mut content_len) = (0usize, 0usize);
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if header_end == 0 {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                        content_len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                    }
                }
                if header_end > 0 && buf.len() >= header_end + content_len {
                    break;
                }
            }
            let backend_hdr = backend
                .map(|b| format!("x-tts-backend: {b}\r\n"))
                .unwrap_or_default();
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {}\r\n{}content-length: {}\r\nconnection: close\r\n\r\n",
                content_type,
                backend_hdr,
                body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
            sock.shutdown().await.ok();
            buf
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn synthesize_round_trip_against_mock() {
        let (url, handle) =
            one_shot_mock("audio/wav", Some("piper"), b"RIFF$\0\0\0WAVEfmt fake").await;
        let e = TtsEndpoint {
            url,
            api_format: "openai".into(),
            voice: String::new(),
            api_key_env: String::new(),
        };
        // Loopback plaintext mock: drive the wire path with a plain client;
        // the door's client choice is pinned separately.
        let speech = e
            .synthesize_via(
                &reqwest::Client::new(),
                "Hello Mesh",
                &SynthesizeOptions { speed: 1.0, ..Default::default() },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(speech.content_type, "audio/wav");
        // provider-declared header wins over the wire-format fallback
        assert_eq!(speech.backend, "piper");
        assert!(speech.audio.starts_with(b"RIFF"));

        let raw = String::from_utf8_lossy(&handle.await.unwrap()).to_string();
        assert!(raw.starts_with("POST /v1/audio/speech HTTP/1.1"));
        assert!(raw.contains("\"input\":\"Hello Mesh\""));
        assert!(raw.contains("\"response_format\":\"wav\""));
    }

    #[tokio::test]
    async fn backend_falls_back_to_wire_format_without_header() {
        let (url, _h) = one_shot_mock("audio/mpeg", None, b"ID3fake").await;
        let e = TtsEndpoint {
            url,
            api_format: "openai".into(),
            voice: String::new(),
            api_key_env: String::new(),
        };
        let speech = e
            .synthesize_via(&reqwest::Client::new(), "hi", &SynthesizeOptions { speed: 1.0, ..Default::default() }, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(speech.backend, "openai");
        assert_eq!(speech.content_type, "audio/mpeg");
    }

    #[tokio::test]
    async fn synthesize_maps_unreachable_to_unavailable() {
        // Nothing listens on this port (bind + drop reserves then frees it).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let e = TtsEndpoint {
            url: format!("http://{addr}"),
            api_format: "openai".into(),
            voice: String::new(),
            api_key_env: String::new(),
        };
        match e
            .synthesize_via(&reqwest::Client::new(), "hi", &SynthesizeOptions { speed: 1.0, ..Default::default() }, Duration::from_secs(2))
            .await
        {
            Err(TtsError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
        assert!(!e.probe(Duration::from_secs(2)).await);
    }

    /// mTLS doors phase 2: the default door is https on noo-piper (a
    /// cluster name, so the gateway's leaf is presented); a cloud host gets
    /// the public client; a plaintext URL is refused BEFORE any connection
    /// on every call — the listener here would record one.
    #[tokio::test]
    async fn the_default_is_https_and_a_plaintext_url_is_refused_not_dialled() {
        assert_eq!(TTS_DEFAULT_URL, "https://noo-piper:8000");
        assert_eq!(TTS_DOOR.classify(TTS_DEFAULT_URL), Ok(crate::tls::DoorTrust::Cluster));
        assert_eq!(TTS_DOOR.classify("https://piper:8000"), Ok(crate::tls::DoorTrust::Cluster));
        assert_eq!(TTS_DOOR.classify("https://api.openai.com"), Ok(crate::tls::DoorTrust::Public));
        assert_eq!(TTS_DOOR.classify("https://localhost:8000"), Ok(crate::tls::DoorTrust::Cluster));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let e = TtsEndpoint {
            url: format!("{}://{addr}", "http"),
            api_format: "openai".into(),
            voice: String::new(),
            api_key_env: String::new(),
        };
        match e
            .synthesize("hi", &SynthesizeOptions { speed: 1.0, ..Default::default() }, Duration::from_secs(2))
            .await
        {
            Err(err @ TtsError::Refused(_)) => {
                assert!(err.to_string().contains("NOO_TTS_URL=https://noo-piper:8000"), "{err}");
                assert_eq!(err.http_status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(matches!(e.list_voices(Duration::from_secs(2)).await, Err(TtsError::Refused(_))));
        assert!(!e.probe(Duration::from_secs(1)).await);
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "a plaintext TTS URL was dialled");
    }

    /// Every dial in this module goes through the door; nothing reaches
    /// for the cluster client directly.
    #[test]
    fn every_tts_dial_goes_through_the_door() {
        let src = include_str!("tts_client.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(!prod.contains("tls::cluster_client()"), "a direct cluster_client() dial bypasses TTS_DOOR");
        assert_eq!(prod.matches("TTS_DOOR.client(").count(), 3, "synthesize + list_voices + probe");
    }

    #[tokio::test]
    async fn list_voices_round_trip_against_mock() {
        let (url, handle) = one_shot_mock(
            "application/json",
            None,
            br#"{"voices":[{"name":"en_US-lessac-medium","language":"en_US","backend":"piper"}]}"#,
        )
        .await;
        let e = TtsEndpoint {
            url,
            api_format: "piper".into(),
            voice: String::new(),
            api_key_env: String::new(),
        };
        let voices = e.list_voices_via(&reqwest::Client::new(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(voices.len(), 1);
        assert_eq!(voices[0]["name"], "en_US-lessac-medium");
        let raw = String::from_utf8_lossy(&handle.await.unwrap()).to_string();
        assert!(raw.starts_with("GET /voices HTTP/1.1"));
    }

    // ── REAL provider round-trip (opt-in) ──
    //
    // Run against a live server (e.g. the compose `piper` service on a
    // throwaway network):
    //   NOO_TTS_TEST_URL=https://piper:8000 \
    //   NOO_TTS_TEST_FORMAT=openai cargo test real_provider -- --nocapture
    // Skips silently when NOO_TTS_TEST_URL is unset so CI stays hermetic.
    #[tokio::test]
    async fn real_provider_round_trip() {
        let Ok(url) = std::env::var("NOO_TTS_TEST_URL") else {
            return;
        };
        let e = TtsEndpoint {
            url,
            api_format: std::env::var("NOO_TTS_TEST_FORMAT").unwrap_or_else(|_| "openai".into()),
            voice: std::env::var("NOO_TTS_TEST_VOICE").unwrap_or_default(),
            api_key_env: String::new(),
        };

        let voices = e
            .list_voices(Duration::from_secs(30))
            .await
            .expect("real TTS voice inventory failed");
        println!("REAL VOICES ({}): {:?}", voices.len(), &voices[..voices.len().min(3)]);
        assert!(!voices.is_empty(), "provider advertises no voices");

        let speech = e
            .synthesize(
                "The quick brown fox jumps over the lazy dog.",
                &SynthesizeOptions { speed: 1.0, ..Default::default() },
                Duration::from_secs(120),
            )
            .await
            .expect("real TTS provider call failed");

        println!(
            "REAL AUDIO: {} bytes, content-type {}, backend {}",
            speech.audio.len(),
            speech.content_type,
            speech.backend
        );
        assert!(
            speech.content_type.contains("wav") || speech.content_type.contains("audio"),
            "unexpected content-type {}",
            speech.content_type
        );

        // Decode the WAV header (RIFF/WAVE + fmt chunk) and derive the
        // duration — proof this is real audio of a plausible length, without
        // requiring playback.
        let a = &speech.audio;
        assert!(a.len() > 1024, "audio suspiciously small: {} bytes", a.len());
        assert_eq!(&a[0..4], b"RIFF", "not a RIFF container");
        assert_eq!(&a[8..12], b"WAVE", "not a WAVE payload");
        let sample_rate = u32::from_le_bytes([a[24], a[25], a[26], a[27]]) as f64;
        let byte_rate = u32::from_le_bytes([a[28], a[29], a[30], a[31]]) as f64;
        assert!(
            (8000.0..=48000.0).contains(&sample_rate),
            "implausible sample rate {sample_rate}"
        );
        let seconds = (a.len() as f64 - 44.0) / byte_rate;
        println!("REAL AUDIO DURATION: {seconds:.2}s @ {sample_rate}Hz");
        // "The quick brown fox…" is ~2-5s of speech at natural rate.
        assert!(
            (1.0..=15.0).contains(&seconds),
            "implausible duration {seconds}s"
        );
    }
}
