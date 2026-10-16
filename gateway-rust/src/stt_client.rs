// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Backend-agnostic STT (speech-to-text) client — the ONE place that knows
//! how to talk to a transcription server. Mirrors `embedding_client.rs`:
//! one client, multiple wire formats, config-driven provider selection, so
//! whisper is just the first provider — a vLLM audio model, speaches,
//! LocalAI or OpenAI cloud slot in by flipping config, not code.
//!
//! Wire formats ("api formats"):
//!
//!   - `openai`  — OpenAI-compatible audio API (DEFAULT — OpenAI cloud,
//!                 vLLM audio models, speaches, LocalAI, and our own
//!                 docker/Dockerfile.whisper shim all serve it):
//!                 POST {url}/v1/audio/transcriptions
//!                 multipart: file, model, [language], response_format=verbose_json
//!                 → {"text", "language", "duration", "segments": [
//!                    {"start","end","text","avg_logprob",…}]}
//!   - `whisper` — the legacy native faster-whisper HTTP service shape the
//!                 pre-provider proxy in routes/communication.rs spoke:
//!                 POST {url}/transcribe[/detailed]
//!                 multipart: file, [model], [language], [detailed=true]
//!                 → already the gateway contract shape (passthrough).
//!
//! Whatever the provider speaks, callers get back ONE response contract —
//! the shape `noo voice transcribe` has always pinned (voice_cli parity):
//!   { "text", "language", "confidence", "duration",
//!     ["language_probability"], ["segments": [{start,end,text,avg_logprob}]] }
//!
//! Config resolution (env → yaml → default, phase-2 pattern):
//!   NOO_STT_URL         / services.stt_url         → legacy voice.whisper_url
//!                                                     → https://noo-whisper:8000
//!   NOO_STT_BACKEND     / services.stt_backend     → "whisper" when the legacy
//!       voice.whisper_url is what supplied the URL, else "openai"
//!   NOO_STT_MODEL       / services.stt_model       → "" (empty = honour the
//!       per-request client hint; the CLI sends model=base)
//!   NOO_STT_API_KEY_ENV / services.stt_api_key_env → "" (name of the env var
//!       holding a bearer key — the key itself never lives in YAML)
//!
//! Placement note: embeddings graduated from a configured URL to mesh
//! placements (role=embed) because stale config silently outvoted the fleet.
//! STT should follow the same path once a node-agent backend spec exists for
//! whisper (backends.go, like embedding/reranker) — at which point the URL
//! config here becomes the direct-path escape hatch only. Today no node
//! advertises an `stt` capability, so env → yaml → default is the honest
//! source of truth and there is nothing for config to restate.
//!
//! TLS (mTLS doors phase 2, i77): noo-whisper serves TLS and REQUIRES a
//! cluster-CA client certificate, so the default is `https://noo-whisper:8000`
//! and an `http://` URL is refused, never dialled ([`STT_DOOR`]). An https
//! URL on the cluster's own names dials with the cluster client (the
//! gateway's leaf); any other https host — a cloud provider — dials with
//! `tls::external_client()` (public roots, no client certificate).

use std::time::Duration;

use serde_json::{json, Value};

use crate::config::env_or_yaml;

/// The default STT door: the voice overlay's `whisper` service.
pub const STT_DEFAULT_URL: &str = "https://noo-whisper:8000";

/// The STT door's trust rule (see `tls::HttpsDoor`): the cluster's voice
/// names dial with the cluster client, any other https host publicly.
pub const STT_DOOR: crate::tls::HttpsDoor = crate::tls::HttpsDoor {
    setting: "NOO_STT_URL",
    default_url: STT_DEFAULT_URL,
    cluster_hosts: crate::tls::VOICE_CLUSTER_HOSTS,
};

/// Resolved STT endpoint: where to POST, which wire format, which model.
#[derive(Debug, Clone)]
pub struct SttEndpoint {
    pub url: String,
    /// Wire format: "openai" | "whisper" (see module docs).
    pub api_format: String,
    /// Configured model pin. Empty = honour the per-request client hint.
    pub model: String,
    /// Name of the env var holding a bearer API key. Empty = no auth header.
    pub api_key_env: String,
}

/// Per-request transcription options (multipart text fields).
#[derive(Debug, Default, Clone)]
pub struct TranscribeOptions {
    /// Client-supplied model hint (the CLI sends "base" by default).
    /// A non-empty configured `SttEndpoint::model` wins over this.
    pub model: Option<String>,
    /// Source language code (e.g. "en"). None = provider auto-detect.
    pub language: Option<String>,
    /// Include segment-level timestamps in the response.
    pub detailed: bool,
}

#[derive(Debug)]
pub enum SttError {
    /// Transport-level failure (connect/timeout) — provider unreachable.
    Unavailable(String),
    /// Provider answered with a non-2xx status (body kept, truncated).
    BadStatus(reqwest::StatusCode, String),
    /// Provider answered 2xx but the body didn't match the wire format.
    Parse(String),
    /// The configured URL is refused before any dial (plaintext).
    Refused(String),
}

impl std::fmt::Display for SttError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SttError::Unavailable(e) => write!(f, "STT provider unreachable: {e}"),
            SttError::BadStatus(s, body) => write!(f, "STT provider returned {s}: {body}"),
            SttError::Parse(e) => write!(f, "STT provider parse error: {e}"),
            SttError::Refused(e) => write!(f, "STT provider refused: {e}"),
        }
    }
}

impl SttError {
    /// The HTTP status the gateway should relay for this failure.
    pub fn http_status(&self) -> axum::http::StatusCode {
        match self {
            SttError::Unavailable(_) | SttError::Parse(_) => axum::http::StatusCode::BAD_GATEWAY,
            SttError::Refused(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            SttError::BadStatus(s, _) => axum::http::StatusCode::from_u16(s.as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        }
    }
}

/// Resolve the configured STT endpoint (env → yaml → legacy → default).
///
/// `legacy_whisper_url` is the raw `voice.whisper_url` key from
/// noomesh.yaml (the pre-provider config surface) — passed in by the
/// route because that section never graduated into the typed AppConfig.
pub fn resolve(legacy_whisper_url: Option<String>) -> SttEndpoint {
    let configured_url = env_or_yaml("NOO_STT_URL", |c| c.services.stt_url.clone(), "");

    // Which URL wins also picks the *default* wire format: an operator who
    // only ever configured the legacy voice.whisper_url keeps the legacy
    // native shape until they say otherwise.
    let legacy = legacy_whisper_url.filter(|u| !u.trim().is_empty());
    let (url, default_format) = if !configured_url.is_empty() {
        (configured_url, "openai")
    } else if let Some(l) = legacy {
        (l, "whisper")
    } else {
        // mTLS (i77 phase 2): noo-whisper requires the gateway's leaf.
        (STT_DEFAULT_URL.to_string(), "openai")
    };

    let api_format = env_or_yaml(
        "NOO_STT_BACKEND",
        |c| c.services.stt_backend.clone(),
        default_format,
    )
    .to_lowercase();

    let model = env_or_yaml("NOO_STT_MODEL", |c| c.services.stt_model.clone(), "");
    let api_key_env = env_or_yaml(
        "NOO_STT_API_KEY_ENV",
        |c| c.services.stt_api_key_env.clone(),
        "",
    );

    SttEndpoint {
        url: url.trim_end_matches('/').to_string(),
        api_format,
        model,
        api_key_env,
    }
}

impl SttEndpoint {
    /// The URL to POST a transcription request to in this wire format.
    fn request_url(&self, detailed: bool) -> String {
        match self.api_format.as_str() {
            "whisper" => {
                if detailed {
                    format!("{}/transcribe/detailed", self.url)
                } else {
                    format!("{}/transcribe", self.url)
                }
            }
            // "openai" (default) and anything unrecognized.
            _ => format!("{}/v1/audio/transcriptions", self.url),
        }
    }

    /// The model actually sent: config pin wins, else the client hint,
    /// else "base" (faster-whisper's balanced default — voice_cli parity).
    fn effective_model(&self, opts: &TranscribeOptions) -> String {
        if !self.model.is_empty() {
            return self.model.clone();
        }
        match &opts.model {
            Some(m) if !m.is_empty() => m.clone(),
            _ => "base".to_string(),
        }
    }

    /// Multipart text fields for this wire format (the binary `file` part is
    /// attached by [`transcribe`]). Split out so tests can assert the wire
    /// contract without an HTTP server.
    fn form_fields(&self, opts: &TranscribeOptions) -> Vec<(String, String)> {
        let mut fields = vec![("model".to_string(), self.effective_model(opts))];
        if let Some(lang) = opts.language.as_ref().filter(|l| !l.is_empty()) {
            fields.push(("language".to_string(), lang.clone()));
        }
        match self.api_format.as_str() {
            "whisper" => {
                if opts.detailed {
                    fields.push(("detailed".to_string(), "true".to_string()));
                }
            }
            _ => {
                // verbose_json always: it is the only response_format that
                // carries language/duration/segments, and the contract needs
                // language + duration even on the non-detailed path.
                fields.push(("response_format".to_string(), "verbose_json".to_string()));
            }
        }
        fields
    }

    /// Normalise a 2xx response body into the gateway contract shape.
    fn parse_response(&self, data: Value, detailed: bool) -> Result<Value, SttError> {
        match self.api_format.as_str() {
            // The legacy whisper service already answers in contract shape.
            "whisper" => Ok(data),
            _ => {
                let text = data
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SttError::Parse("missing 'text' field".into()))?
                    .trim()
                    .to_string();
                let language = data.get("language").cloned().unwrap_or(Value::Null);
                let duration = data.get("duration").and_then(Value::as_f64);

                // Segments (verbose_json): keep the contract's field subset.
                let segments: Vec<Value> = data
                    .get("segments")
                    .and_then(Value::as_array)
                    .map(|segs| {
                        segs.iter()
                            .map(|s| {
                                json!({
                                    "start": s.get("start").and_then(Value::as_f64).unwrap_or(0.0),
                                    "end": s.get("end").and_then(Value::as_f64).unwrap_or(0.0),
                                    "text": s.get("text").and_then(Value::as_str).unwrap_or("").trim(),
                                    "avg_logprob": s.get("avg_logprob").and_then(Value::as_f64).unwrap_or(0.0),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Confidence: exp(mean(avg_logprob)) over segments — the same
                // math the in-process faster-whisper transcriber used, so the
                // number means the same thing across providers.
                let confidence = if segments.is_empty() {
                    0.0
                } else {
                    let sum: f64 = segments
                        .iter()
                        .map(|s| s.get("avg_logprob").and_then(Value::as_f64).unwrap_or(0.0))
                        .sum();
                    let mean = sum / segments.len() as f64;
                    (mean.exp() * 10_000.0).round() / 10_000.0
                };

                let mut out = json!({
                    "text": text,
                    "language": language,
                    "confidence": confidence,
                    "duration": duration,
                });
                if detailed {
                    out["segments"] = Value::Array(segments);
                }
                Ok(out)
            }
        }
    }

    /// Transcribe one audio blob. One HTTP round-trip; the reply is the
    /// gateway contract shape regardless of provider.
    pub async fn transcribe(
        &self,
        audio: Vec<u8>,
        filename: &str,
        mime: &str,
        opts: &TranscribeOptions,
        timeout: Duration,
    ) -> Result<Value, SttError> {
        // The cluster client for noo-whisper (presents the gateway's leaf),
        // the public client for a cloud provider; http:// never dials.
        let client = STT_DOOR.client(&self.url).map_err(SttError::Refused)?;
        self.transcribe_via(&client, audio, filename, mime, opts, timeout).await
    }

    /// The round-trip itself, on a client already chosen by [`STT_DOOR`].
    async fn transcribe_via(
        &self,
        client: &reqwest::Client,
        audio: Vec<u8>,
        filename: &str,
        mime: &str,
        opts: &TranscribeOptions,
        timeout: Duration,
    ) -> Result<Value, SttError> {
        let part = reqwest::multipart::Part::bytes(audio.clone())
            .file_name(filename.to_string())
            .mime_str(mime)
            .unwrap_or_else(|_| reqwest::multipart::Part::bytes(audio));
        let mut form = reqwest::multipart::Form::new().part("file", part);
        for (name, value) in self.form_fields(opts) {
            form = form.text(name, value);
        }

        let mut req = client
            .post(self.request_url(opts.detailed))
            .multipart(form)
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
            .map_err(|e| SttError::Unavailable(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(500);
            return Err(SttError::BadStatus(status, body));
        }
        let data: Value = resp
            .json()
            .await
            .map_err(|e| SttError::Parse(e.to_string()))?;
        self.parse_response(data, opts.detailed)
    }

    /// Health-probe URL appropriate for this wire format's server.
    pub fn health_url(&self) -> String {
        match self.api_format.as_str() {
            "whisper" => format!("{}/health", self.url),
            _ => format!("{}/v1/models", self.url),
        }
    }

    /// Is this endpoint answering right now? Used by `/api/voice/status`.
    /// A refused (plaintext) URL is simply not available.
    pub async fn probe(&self, timeout: Duration) -> bool {
        let Ok(client) = STT_DOOR.client(&self.url) else {
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

    fn ep(format: &str) -> SttEndpoint {
        SttEndpoint {
            url: "http://stt:8000".into(),
            api_format: format.into(),
            model: String::new(),
            api_key_env: String::new(),
        }
    }

    // ── Wire contract: request side ──

    #[test]
    fn openai_request_shape() {
        let e = ep("openai");
        assert_eq!(e.request_url(false), "http://stt:8000/v1/audio/transcriptions");
        // detailed does NOT change the URL for openai — verbose_json carries it
        assert_eq!(e.request_url(true), "http://stt:8000/v1/audio/transcriptions");
        let fields = e.form_fields(&TranscribeOptions {
            model: Some("base".into()),
            language: Some("en".into()),
            detailed: false,
        });
        assert!(fields.contains(&("model".into(), "base".into())));
        assert!(fields.contains(&("language".into(), "en".into())));
        assert!(fields.contains(&("response_format".into(), "verbose_json".into())));
    }

    #[test]
    fn whisper_request_shape() {
        let e = ep("whisper");
        assert_eq!(e.request_url(false), "http://stt:8000/transcribe");
        assert_eq!(e.request_url(true), "http://stt:8000/transcribe/detailed");
        let fields = e.form_fields(&TranscribeOptions {
            model: None,
            language: None,
            detailed: true,
        });
        assert!(fields.contains(&("detailed".into(), "true".into())));
        assert!(!fields.iter().any(|(k, _)| k == "response_format"));
        // no language field when none supplied
        assert!(!fields.iter().any(|(k, _)| k == "language"));
    }

    #[test]
    fn configured_model_pin_wins_over_client_hint() {
        let mut e = ep("openai");
        e.model = "whisper-1".into();
        let fields = e.form_fields(&TranscribeOptions {
            model: Some("base".into()),
            ..Default::default()
        });
        assert!(fields.contains(&("model".into(), "whisper-1".into())));
    }

    #[test]
    fn empty_hint_falls_back_to_base() {
        let e = ep("openai");
        let fields = e.form_fields(&TranscribeOptions::default());
        assert!(fields.contains(&("model".into(), "base".into())));
    }

    // ── Wire contract: response side ──

    #[test]
    fn openai_verbose_json_maps_to_contract() {
        let e = ep("openai");
        let body = json!({
            "task": "transcribe",
            "language": "en",
            "duration": 2.5,
            "text": " Hello world. ",
            "segments": [
                {"id": 0, "start": 0.0, "end": 1.2, "text": " Hello", "avg_logprob": -0.2, "no_speech_prob": 0.01},
                {"id": 1, "start": 1.2, "end": 2.5, "text": " world.", "avg_logprob": -0.4, "no_speech_prob": 0.01},
            ]
        });
        let out = e.parse_response(body, true).unwrap();
        assert_eq!(out["text"], "Hello world.");
        assert_eq!(out["language"], "en");
        assert_eq!(out["duration"], 2.5);
        // exp(mean(-0.2, -0.4)) — the exact math the in-process
        // faster-whisper transcriber used (avg logprob first, then exp)
        let expected = ((-0.2f64 + -0.4f64) / 2.0).exp();
        let expected = (expected * 10_000.0).round() / 10_000.0;
        assert_eq!(out["confidence"].as_f64().unwrap(), expected);
        let segs = out["segments"].as_array().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0]["text"], "Hello");
        assert_eq!(segs[0]["avg_logprob"], -0.2);
        // contract subset only — provider extras must not leak through
        assert!(segs[0].get("no_speech_prob").is_none());
    }

    #[test]
    fn openai_non_detailed_drops_segments() {
        let e = ep("openai");
        let body = json!({
            "text": "hi", "language": "en", "duration": 1.0,
            "segments": [{"start": 0.0, "end": 1.0, "text": "hi", "avg_logprob": -0.1}]
        });
        let out = e.parse_response(body, false).unwrap();
        assert!(out.get("segments").is_none());
        assert!(out["confidence"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn openai_plain_json_still_parses() {
        // A provider that ignores response_format and answers {"text": ...}
        let e = ep("openai");
        let out = e.parse_response(json!({"text": "hi"}), false).unwrap();
        assert_eq!(out["text"], "hi");
        assert_eq!(out["confidence"], 0.0);
        assert!(out["language"].is_null());
    }

    #[test]
    fn openai_missing_text_is_parse_error() {
        let e = ep("openai");
        match e.parse_response(json!({"nope": 1}), false) {
            Err(SttError::Parse(_)) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn whisper_response_is_passthrough() {
        let e = ep("whisper");
        let body = json!({"text": "hi", "language": "en", "confidence": 0.93,
                          "duration": 1.1, "language_probability": 0.99});
        assert_eq!(e.parse_response(body.clone(), false).unwrap(), body);
    }

    // ── Health / error mapping ──

    #[test]
    fn health_urls_per_format() {
        assert_eq!(ep("whisper").health_url(), "http://stt:8000/health");
        assert_eq!(ep("openai").health_url(), "http://stt:8000/v1/models");
    }

    #[test]
    fn error_http_status_mapping() {
        assert_eq!(
            SttError::Unavailable("x".into()).http_status(),
            axum::http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            SttError::Parse("x".into()).http_status(),
            axum::http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            SttError::BadStatus(reqwest::StatusCode::NOT_FOUND, "".into()).http_status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }

    // ── Mock server round-trip: exercises the REAL transcribe() path —
    //    multipart upload, bearer auth wiring, JSON decode, contract map. ──

    /// One-shot HTTP mock: accepts a single connection, reads the full
    /// request (headers + content-length body), answers with `body_json`.
    async fn one_shot_mock(body_json: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read until headers complete, then drain content-length.
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
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
            buf
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn transcribe_round_trip_against_mock() {
        let (url, handle) = one_shot_mock(
            r#"{"text":" mock transcript ","language":"en","duration":1.5,
                "segments":[{"start":0.0,"end":1.5,"text":" mock transcript","avg_logprob":-0.1}]}"#,
        )
        .await;
        let e = SttEndpoint {
            url,
            api_format: "openai".into(),
            model: String::new(),
            api_key_env: String::new(),
        };
        // The mock is loopback plaintext, so the wire path is driven with a
        // plain client; the door's client choice is pinned separately.
        let out = e
            .transcribe_via(
                &reqwest::Client::new(),
                b"RIFFfakewav".to_vec(),
                "a.wav",
                "audio/wav",
                &TranscribeOptions { detailed: true, ..Default::default() },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out["text"], "mock transcript");
        assert_eq!(out["segments"].as_array().unwrap().len(), 1);

        // What actually went over the wire: OpenAI-compatible multipart.
        let raw = handle.await.unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.starts_with("POST /v1/audio/transcriptions HTTP/1.1"));
        assert!(raw_str.contains("name=\"file\""));
        assert!(raw_str.contains("filename=\"a.wav\""));
        assert!(raw_str.contains("RIFFfakewav"));
        assert!(raw_str.contains("name=\"model\""));
        assert!(raw_str.contains("name=\"response_format\""));
        assert!(raw_str.contains("verbose_json"));
    }

    #[tokio::test]
    async fn transcribe_maps_unreachable_to_unavailable() {
        // Nothing listens on this port (bind + drop reserves then frees it).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let e = SttEndpoint {
            url: format!("http://{addr}"),
            api_format: "openai".into(),
            model: String::new(),
            api_key_env: String::new(),
        };
        match e
            .transcribe_via(&reqwest::Client::new(), vec![1], "a.wav", "audio/wav", &TranscribeOptions::default(), Duration::from_secs(2))
            .await
        {
            Err(SttError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    /// mTLS doors phase 2: the default door is https on noo-whisper (a
    /// cluster name, so the gateway's leaf is presented), and a plaintext
    /// URL is refused BEFORE any connection — the listener here would
    /// record one.
    #[tokio::test]
    async fn the_default_is_https_and_a_plaintext_url_is_refused_not_dialled() {
        assert_eq!(STT_DEFAULT_URL, "https://noo-whisper:8000");
        assert_eq!(STT_DOOR.classify(STT_DEFAULT_URL), Ok(crate::tls::DoorTrust::Cluster));
        assert_eq!(STT_DOOR.classify("https://api.openai.com"), Ok(crate::tls::DoorTrust::Public));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let e = SttEndpoint {
            url: format!("{}://{addr}", "http"),
            api_format: "openai".into(),
            model: String::new(),
            api_key_env: String::new(),
        };
        match e
            .transcribe(vec![1], "a.wav", "audio/wav", &TranscribeOptions::default(), Duration::from_secs(2))
            .await
        {
            Err(err @ SttError::Refused(_)) => {
                assert!(err.to_string().contains("not https"), "{err}");
                assert_eq!(err.http_status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(!e.probe(Duration::from_secs(1)).await);
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "a plaintext STT URL was dialled");
    }

    /// Every dial in this module goes through the door; nothing reaches
    /// for the cluster client directly (which would present the gateway's
    /// leaf to a cloud provider and fail to verify its public CA).
    #[test]
    fn every_stt_dial_goes_through_the_door() {
        let src = include_str!("stt_client.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(!prod.contains("tls::cluster_client()"), "a direct cluster_client() dial bypasses STT_DOOR");
        assert_eq!(prod.matches("STT_DOOR.client(").count(), 2, "transcribe + probe");
    }

    // ── REAL provider round-trip (opt-in) ──
    //
    // Run against a live server (e.g. the compose `whisper` service on a
    // throwaway network):
    //   NOO_STT_TEST_URL=https://whisper:8000 NOO_TTS_TEST_URL=https://noo-piper:8000 \
    //   NOO_STT_TEST_EXPECT="hello" cargo test real_provider -- --nocapture
    // Skips when NOO_STT_TEST_URL or NOO_TTS_TEST_URL is unset so CI stays hermetic.
    #[tokio::test]
    async fn real_provider_round_trip() {
        let Ok(url) = std::env::var("NOO_STT_TEST_URL") else {
            return;
        };
        let e = SttEndpoint {
            url,
            api_format: std::env::var("NOO_STT_TEST_FORMAT").unwrap_or_else(|_| "openai".into()),
            model: std::env::var("NOO_STT_TEST_MODEL").unwrap_or_default(),
            api_key_env: String::new(),
        };
        // The sample is synthesized at run time by the configured TTS
        // provider (no audio fixture ships in the tree).
        let Ok(tts_url) = std::env::var("NOO_TTS_TEST_URL") else {
            eprintln!("skipping real_provider_round_trip: NOO_TTS_TEST_URL is unset (no TTS provider to synthesize the sample)");
            return;
        };
        let tts = crate::tts_client::TtsEndpoint {
            url: tts_url,
            api_format: std::env::var("NOO_TTS_TEST_FORMAT").unwrap_or_else(|_| "openai".into()),
            voice: String::new(),
            api_key_env: String::new(),
        };
        let speech = tts
            .synthesize(
                "hello mesh",
                &crate::tts_client::SynthesizeOptions { speed: 1.0, ..Default::default() },
                Duration::from_secs(120),
            )
            .await
            .expect("TTS provider could not synthesize the sample");
        let out = e
            .transcribe(
                speech.audio,
                "hello_mesh.wav",
                &speech.content_type,
                &TranscribeOptions { detailed: true, ..Default::default() },
                Duration::from_secs(120),
            )
            .await
            .expect("real STT provider call failed");
        let text = out["text"].as_str().unwrap_or("").to_lowercase();
        println!("REAL TRANSCRIPT: {text:?} (full: {out})");
        let expect = std::env::var("NOO_STT_TEST_EXPECT").unwrap_or_else(|_| "hello".into());
        assert!(
            text.contains(&expect.to_lowercase()),
            "transcript {text:?} does not contain {expect:?}"
        );
        assert!(out["confidence"].as_f64().unwrap_or(0.0) > 0.0);
    }
}
