// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node → gateway → Loki log ingest (fleet logging plan, phase 2).
//!
//! `POST /api/cluster/nodes/{node_id}/logs` is a NODE route: the caller is a
//! node-agent proving itself with the fleet cluster token (and its client
//! certificate where mTLS is on), and `{node_id}` must be the node it proved
//! itself to be. Nothing else may call it — not an operator JWT, not one of
//! the stack's own services on the controller secret. The reason is
//! attribution: the `node=` label on every stream is OVERWRITTEN here with
//! the verified id, so a line in Loki that says `node="host3"` was pushed by
//! host3 and by nobody else. Loki itself cannot make that promise (it
//! accepts any cluster-CA leaf and any label the body claims), which is why
//! the push goes through this route and Loki stays unpublished.
//!
//! WIRE CONTRACT (what the phase-3 shipper is written against):
//!
//! * body: the Loki push shape, `{"streams":[{"stream":{<labels>},
//!   "values":[["<unix ns as a decimal string>","<line>"],…]},…]}`, JSON,
//!   optionally `Content-Encoding: gzip`. Chosen over a bespoke shape so the
//!   gateway validates it once and forwards it with ONE transform (the
//!   `node` label); a third element in a value (structured metadata) is
//!   dropped, not refused.
//! * labels: keys outside [`ALLOWED_LABELS`] are dropped silently; `node` is
//!   replaced whatever the body said; a value longer than
//!   [`MAX_LABEL_VALUE`] bytes or more than [`MAX_LABELS`] keys in one stream
//!   is refused (400) — a shipper that sends those is broken, not chatty.
//! * limits: [`MAX_BODY`] on the wire and after decoding (413); at most
//!   [`MAX_STREAMS`] streams and [`MAX_ENTRIES`] values per push (400); per
//!   node, [`DEFAULT_BYTES_PER_MIN`] decoded bytes and
//!   [`DEFAULT_REQUESTS_PER_MIN`] pushes a minute (429 with `Retry-After`),
//!   overridable with `NOO_LOGS_INGEST_BYTES_PER_MIN` /
//!   `NOO_LOGS_INGEST_REQUESTS_PER_MIN`.
//! * status codes, and what the shipper does with them:
//!   - 204: accepted by Loki — drop the batch.
//!   - 400 / 413: malformed or oversize — DROP the batch (log the body once);
//!     retrying cannot make it acceptable. 400 also carries Loki's own text
//!     when LOKI refused it.
//!   - 401 / 403: not a node, or not THIS node — a credential problem, not a
//!     batch problem; keep the batch and fix the credential.
//!   - 429: over budget — keep the batch, wait `Retry-After` seconds.
//!   - 503: Loki unreachable, timed out, answered 5xx, or unconfigured —
//!     keep the batch and retry with backoff. The gateway holds NOTHING: it
//!     is a stateless relay, so the node's queue is the only buffer.
//!   Every refusal body is `{"error","reason","retry"}`; `retry` says which
//!   of the above applies without the shipper parsing the text.
//!
//! The gateway's own access log SKIPS this route (`middleware::
//! access_log_suppressed`): the controller's agent ships the gateway
//! container's stdout, so a logged push would be a line that causes a push
//! that logs a line.

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, LazyLock, Mutex};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::auth::ClusterNode;
use crate::state::AppState;

/// Body cap, on the wire AND after gzip decoding. A shipper flushing at
/// 512 KB never approaches it; a 4 MB decoded limit is what makes a gzip
/// bomb a 413 instead of an allocation.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const MAX_STREAMS: usize = 64;
pub const MAX_ENTRIES: usize = 20_000;
/// Labels a stream may carry (the body's count, before dropping).
pub const MAX_LABELS: usize = 8;
pub const MAX_LABEL_VALUE: usize = 128;
/// The fixed, low-cardinality label set. `node` is not here because the
/// body never supplies it — the gateway does.
pub const ALLOWED_LABELS: &[&str] = &["source", "name", "stream", "level", "compose_service"];
pub const NODE_LABEL: &str = "node";
pub const DEFAULT_BYTES_PER_MIN: u64 = 8 * 1024 * 1024;
pub const DEFAULT_REQUESTS_PER_MIN: u64 = 120;
pub const BYTES_PER_MIN_ENV: &str = "NOO_LOGS_INGEST_BYTES_PER_MIN";
pub const REQUESTS_PER_MIN_ENV: &str = "NOO_LOGS_INGEST_REQUESTS_PER_MIN";
const LOKI_PUSH_TIMEOUT_SECS: u64 = 10;

/// Why a push was not accepted. Each variant is one status code and one
/// `reason` label on `noo_logs_ingest_refused_total`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No node credential, a service credential, or another node's id (403).
    NotThisNode(String),
    /// The body cannot be made acceptable by retrying (400).
    Malformed(String),
    /// Over [`MAX_BODY`] on the wire or decoded (413).
    TooLarge(String),
    /// Over the per-node budget (429).
    RateLimited { what: &'static str, retry_after: u64 },
    /// Loki refused the batch with a 4xx of its own (400, text forwarded).
    LokiRefused(String),
    /// Loki unreachable, 5xx, timed out, or not configured (503).
    LokiDown(String),
}

impl Refusal {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotThisNode(_) => StatusCode::FORBIDDEN,
            Self::Malformed(_) | Self::LokiRefused(_) => StatusCode::BAD_REQUEST,
            Self::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::LokiDown(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The metric label; bounded by construction.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotThisNode(_) => "not_this_node",
            Self::Malformed(_) => "malformed",
            Self::TooLarge(_) => "too_large",
            Self::RateLimited { what, .. } => what,
            Self::LokiRefused(_) => "loki_refused",
            Self::LokiDown(_) => "loki_down",
        }
    }

    /// Should the shipper keep the batch and try again later?
    pub fn retry(&self) -> bool {
        matches!(self, Self::NotThisNode(_) | Self::RateLimited { .. } | Self::LokiDown(_))
    }

    pub fn message(&self) -> String {
        match self {
            Self::NotThisNode(m) | Self::Malformed(m) | Self::TooLarge(m) | Self::LokiDown(m) => m.clone(),
            Self::LokiRefused(m) => format!("Loki refused the batch: {m}"),
            Self::RateLimited { what, retry_after } => {
                format!("over the per-node log budget ({what}); retry in {retry_after}s")
            }
        }
    }

    pub fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.message(),
            "reason": self.reason(),
            "retry": self.retry(),
        }));
        let mut resp = (self.status(), body).into_response();
        if let Self::RateLimited { retry_after, .. } = self {
            if let Ok(v) = retry_after.to_string().parse() {
                resp.headers_mut().insert("Retry-After", v);
            }
        }
        resp
    }
}

// ── Who may push ───────────────────────────────────────────────────

/// The binding: only a NODE credential, and only for its own id.
///
/// `None` is every non-cluster caller (a JWT of any tier, a service key,
/// a kiosk or add-on token): `require_any_auth` lets an Operator JWT
/// through to every route, so the handler must refuse it here. An
/// `Internal` cluster token (the worker, trellion, the CLI on the
/// controller secret) is a container the controller's agent already ships;
/// it must not be able to write streams "as" a node either. Pure, so the
/// table is pinned without a request.
pub fn caller_refusal(caller: Option<&ClusterNode>, node_id: &str) -> Result<(), Refusal> {
    match caller {
        None => Err(Refusal::NotThisNode(
            "log ingest is a node route: a node-agent's cluster credential is required".into(),
        )),
        Some(c) if c.is_internal() => Err(Refusal::NotThisNode(format!(
            "'{}' is a stack service, not a node; the controller's agent ships its logs",
            c.0
        ))),
        Some(c) if c.0 != node_id => Err(Refusal::NotThisNode(format!(
            "node '{}' may only push logs as itself, not as '{node_id}'",
            c.0
        ))),
        Some(_) => Ok(()),
    }
}

// ── Body ───────────────────────────────────────────────────────────

/// The wire body as bytes the parser can read: identity or gzip, both
/// capped at [`MAX_BODY`]. The decoder reads one byte past the cap so an
/// exactly-4-MB body is fine and a 4-MB-and-one body is a 413, not a
/// silently truncated batch.
pub fn decode_body(raw: &[u8], content_encoding: Option<&str>) -> Result<Vec<u8>, Refusal> {
    if raw.len() > MAX_BODY {
        return Err(Refusal::TooLarge(format!("body is {} bytes; the cap is {MAX_BODY}", raw.len())));
    }
    let enc = content_encoding.map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
    match enc.as_str() {
        "" | "identity" => Ok(raw.to_vec()),
        "gzip" | "x-gzip" => {
            let mut out = Vec::with_capacity(raw.len().saturating_mul(4).min(MAX_BODY));
            let mut dec = flate2::read::GzDecoder::new(raw).take(MAX_BODY as u64 + 1);
            dec.read_to_end(&mut out)
                .map_err(|e| Refusal::Malformed(format!("Content-Encoding: gzip body did not decode: {e}")))?;
            if out.len() > MAX_BODY {
                return Err(Refusal::TooLarge(format!("decoded body exceeds the {MAX_BODY}-byte cap")));
            }
            Ok(out)
        }
        other => Err(Refusal::Malformed(format!(
            "unsupported Content-Encoding {other:?}; send identity or gzip"
        ))),
    }
}

/// A validated push, ready to forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// The JSON Loki receives: the body's streams with `node` set by us.
    pub body: Vec<u8>,
    pub streams: usize,
    pub lines: u64,
    /// Label keys dropped because they are not in [`ALLOWED_LABELS`].
    pub dropped_labels: u64,
    /// Credential shapes scrubbed out of lines here (`redact::scrub_secrets`).
    /// Zero when the shipper already did its job; a steady non-zero from
    /// one node means that node's agent predates the scrubber.
    pub redacted: u64,
}

/// Validate the decoded body and rewrite it for Loki. Two transforms:
/// every stream's `node` label becomes `node`, whatever the body said and
/// whether or not it said anything; and every line passes through the
/// credential scrubber (`redact::scrub_secrets`, the same table the
/// shipper applies at intake), so a secret in a known shape never reaches
/// Loki even from an agent that did not scrub.
pub fn prepare_push(decoded: &[u8], node: &str) -> Result<Push, Refusal> {
    let root: Value =
        serde_json::from_slice(decoded).map_err(|e| Refusal::Malformed(format!("body is not JSON: {e}")))?;
    let streams = root
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::Malformed("body must be an object with a \"streams\" array".into()))?;
    if streams.len() > MAX_STREAMS {
        return Err(Refusal::Malformed(format!("{} streams; the cap is {MAX_STREAMS}", streams.len())));
    }
    let mut out_streams: Vec<Value> = Vec::with_capacity(streams.len());
    let mut lines: u64 = 0;
    let mut dropped_labels: u64 = 0;
    let mut redacted: u64 = 0;
    for (i, s) in streams.iter().enumerate() {
        let labels = s
            .get("stream")
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::Malformed(format!("streams[{i}].stream must be a label object")))?;
        if labels.len() > MAX_LABELS {
            return Err(Refusal::Malformed(format!(
                "streams[{i}] carries {} labels; the cap is {MAX_LABELS}",
                labels.len()
            )));
        }
        let mut kept = serde_json::Map::new();
        for (k, v) in labels {
            if k == NODE_LABEL {
                // Overwritten below; a body naming another node is not an
                // error, it is simply not believed.
                continue;
            }
            if !ALLOWED_LABELS.contains(&k.as_str()) {
                dropped_labels += 1;
                continue;
            }
            let v = v
                .as_str()
                .ok_or_else(|| Refusal::Malformed(format!("streams[{i}].stream.{k} must be a string")))?;
            if v.len() > MAX_LABEL_VALUE {
                return Err(Refusal::Malformed(format!(
                    "streams[{i}].stream.{k} is {} bytes; the cap is {MAX_LABEL_VALUE}",
                    v.len()
                )));
            }
            kept.insert(k.clone(), Value::String(v.to_string()));
        }
        kept.insert(NODE_LABEL.to_string(), Value::String(node.to_string()));

        let values = s
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| Refusal::Malformed(format!("streams[{i}].values must be an array")))?;
        let mut out_values: Vec<Value> = Vec::with_capacity(values.len());
        // Whether the previous entry of this stream ended in a PEM body line
        // (as scrubbed): the context a body's short last line is recognised
        // by (`pem-tail`). A bool, not a copy of every line.
        let mut after_pem_body = false;
        for (j, entry) in values.iter().enumerate() {
            let pair = entry
                .as_array()
                .filter(|a| a.len() >= 2)
                .ok_or_else(|| Refusal::Malformed(format!("streams[{i}].values[{j}] must be [ts, line]")))?;
            let ts = pair[0].as_str().filter(|t| !t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit()));
            let Some(ts) = ts else {
                return Err(Refusal::Malformed(format!(
                    "streams[{i}].values[{j}][0] must be unix nanoseconds as a decimal string"
                )));
            };
            let Some(line) = pair[1].as_str() else {
                return Err(Refusal::Malformed(format!("streams[{i}].values[{j}][1] must be a string")));
            };
            let prev = if after_pem_body { crate::redact::PEM_BODY_PLACEHOLDER } else { "" };
            let (line, n) = crate::redact::scrub_secrets_after(prev, line);
            redacted += n;
            after_pem_body = line.rsplit('\n').next() == Some(crate::redact::PEM_BODY_PLACEHOLDER);
            out_values.push(json!([ts, line.as_ref()]));
        }
        lines += out_values.len() as u64;
        if lines > MAX_ENTRIES as u64 {
            return Err(Refusal::Malformed(format!("more than {MAX_ENTRIES} entries in one push")));
        }
        if out_values.is_empty() {
            continue;
        }
        out_streams.push(json!({"stream": Value::Object(kept), "values": out_values}));
    }
    if out_streams.is_empty() {
        return Err(Refusal::Malformed("no entries in the push".into()));
    }
    let streams = out_streams.len();
    let body = serde_json::to_vec(&json!({"streams": out_streams}))
        .map_err(|e| Refusal::Malformed(format!("could not re-encode the push: {e}")))?;
    Ok(Push { body, streams, lines, dropped_labels, redacted })
}

// ── Per-node budget ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub bytes_per_min: u64,
    pub requests_per_min: u64,
}

impl Limits {
    /// From the environment; a missing, empty, zero or unparsable value
    /// keeps the default — a typo must not turn the budget off.
    pub fn from_env() -> Self {
        fn read(key: &str, default: u64) -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        }
        Self {
            bytes_per_min: read(BYTES_PER_MIN_ENV, DEFAULT_BYTES_PER_MIN),
            requests_per_min: read(REQUESTS_PER_MIN_ENV, DEFAULT_REQUESTS_PER_MIN),
        }
    }
}

#[derive(Debug, Clone)]
struct Window {
    minute: u64,
    bytes: u64,
    requests: u64,
}

/// Fixed one-minute windows per node. Charged on ADMISSION, before the
/// forward: the budget protects the gateway, so a batch Loki then refuses
/// still cost what it cost. Bounded: one entry per node id that has ever
/// pushed, which is the fleet.
#[derive(Default)]
pub struct NodeBudget {
    windows: Mutex<HashMap<String, Window>>,
}

impl NodeBudget {
    /// Admit `bytes` for `node` at `now_secs`, or say how long to wait.
    pub fn admit(&self, node: &str, bytes: u64, now_secs: u64, limits: &Limits) -> Result<(), Refusal> {
        let minute = now_secs / 60;
        let retry_after = (60 - now_secs % 60).max(1);
        let mut map = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        let w = map.entry(node.to_string()).or_insert(Window { minute, bytes: 0, requests: 0 });
        if w.minute != minute {
            *w = Window { minute, bytes: 0, requests: 0 };
        }
        if w.requests + 1 > limits.requests_per_min {
            return Err(Refusal::RateLimited { what: "requests_per_min", retry_after });
        }
        if w.bytes + bytes > limits.bytes_per_min {
            return Err(Refusal::RateLimited { what: "bytes_per_min", retry_after });
        }
        w.requests += 1;
        w.bytes += bytes;
        Ok(())
    }
}

static BUDGET: LazyLock<NodeBudget> = LazyLock::new(NodeBudget::default);

// ── Forward ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forward {
    /// Loki answered 2xx.
    Accepted,
    /// Loki answered 4xx: the batch is bad, retrying will not help.
    Refused(String),
    /// Loki answered 5xx, timed out or could not be reached: retry later.
    Down(String),
}

/// `POST {loki_url}/loki/api/v1/push` with the gateway's own leaf. The
/// caller passes the client so a test can aim it at a local listener.
pub async fn forward_to_loki(client: &reqwest::Client, loki_url: &str, body: Vec<u8>) -> Forward {
    let url = format!("{}/loki/api/v1/push", loki_url.trim_end_matches('/'));
    let sent = client
        .post(&url)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(LOKI_PUSH_TIMEOUT_SECS))
        .body(body)
        .send()
        .await;
    match sent {
        Ok(resp) if resp.status().is_success() => Forward::Accepted,
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text: String = resp.text().await.unwrap_or_default().chars().take(500).collect();
            if (400..500).contains(&status) {
                Forward::Refused(format!("{status} {text}"))
            } else {
                Forward::Down(format!("Loki answered {status} {text}"))
            }
        }
        Err(e) if e.is_timeout() => Forward::Down(format!("Loki timed out after {LOKI_PUSH_TIMEOUT_SECS}s")),
        Err(e) => Forward::Down(format!("Loki unreachable: {e}")),
    }
}

/// The metric label for a node id: the verified id when there is one,
/// otherwise a fixed word, so a path a JWT caller typed never becomes a
/// series.
fn metric_node(caller: Option<&ClusterNode>) -> String {
    match caller {
        Some(c) if !c.is_internal() => c.0.clone(),
        Some(_) => "internal".into(),
        None => "none".into(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn count_refusal(state: &AppState, node: &str, refusal: &Refusal) {
    let labels = HashMap::from([
        ("node".to_string(), node.to_string()),
        ("reason".to_string(), refusal.reason().to_string()),
    ]);
    state.metrics.inc_counter("noo_logs_ingest_refused_total", Some(&labels), 1).await;
}

/// Node log ingest: a node-agent pushes a batch of its own log lines and
/// the gateway relays it to Loki with the verified `node` label.
///
/// POST /api/cluster/nodes/{node_id}/logs — node credential only, and only
/// for its own id. Body: Loki push JSON, optionally gzip. See the module
/// docs for the full wire contract (labels, limits, status codes).
pub async fn node_logs_ingest(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    caller: Option<Extension<ClusterNode>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = caller.as_ref().map(|Extension(c)| c);
    let node_label = metric_node(caller);
    let refuse = |r: Refusal| async {
        count_refusal(&state, &node_label, &r).await;
        r.into_response()
    };

    if let Err(r) = caller_refusal(caller, &node_id) {
        tracing::warn!(requested = %node_id, caller = %node_label, "log ingest refused: {}", r.message());
        return refuse(r).await;
    }
    let loki_url = crate::config::env_or_yaml("NOO_LOKI_URL", |c| c.services.loki_url.clone(), "");
    if loki_url.is_empty() {
        return refuse(Refusal::LokiDown("Loki is not configured on this controller (NOO_LOKI_URL)".into())).await;
    }
    let encoding = headers.get("content-encoding").and_then(|v| v.to_str().ok());
    let decoded = match decode_body(&body, encoding) {
        Ok(d) => d,
        Err(r) => return refuse(r).await,
    };
    if let Err(r) = BUDGET.admit(&node_id, decoded.len() as u64, now_secs(), &Limits::from_env()) {
        return refuse(r).await;
    }
    let push = match prepare_push(&decoded, &node_id) {
        Ok(p) => p,
        Err(r) => return refuse(r).await,
    };
    match forward_to_loki(&crate::tls::cluster_client(), &loki_url, push.body).await {
        Forward::Accepted => {
            let labels = HashMap::from([("node".to_string(), node_id.clone())]);
            state.metrics.inc_counter("noo_logs_ingest_lines_total", Some(&labels), push.lines).await;
            state.metrics.inc_counter("noo_logs_ingest_bytes_total", Some(&labels), decoded.len() as u64).await;
            state.metrics.set_gauge("noo_logs_last_seen_unix", Some(&labels), now_secs() as f64).await;
            if push.dropped_labels > 0 {
                tracing::debug!(node = %node_id, dropped = push.dropped_labels, "log ingest dropped labels outside the fixed set");
            }
            if push.redacted > 0 {
                // The shipper scrubs first, so a count here means an agent
                // older than the scrubber (or a line that arrived another
                // way). Counted per node so `cluster verify` can name it.
                state.metrics.inc_counter("noo_logs_ingest_redacted_total", Some(&labels), push.redacted).await;
                tracing::debug!(node = %node_id, redacted = push.redacted, lines = push.lines, "log ingest scrubbed credential shapes the shipper missed");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Forward::Refused(text) => refuse(Refusal::LokiRefused(text)).await,
        Forward::Down(text) => {
            tracing::warn!(node = %node_id, "log ingest: {text}");
            refuse(Refusal::LokiDown(text)).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ClusterKind;
    use std::io::Write;

    fn node(id: &str) -> ClusterNode {
        ClusterNode(id.into(), ClusterKind::Node)
    }

    fn push_json(node_label: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"streams":[{
            "stream": {"node": node_label, "source": "journal", "name": "noo-hostd", "level": "info"},
            "values": [["1700000000000000000", "hello"], ["1700000000000000001", "world"]]
        }]}))
        .unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn labels_of(body: &[u8]) -> serde_json::Map<String, Value> {
        let v: Value = serde_json::from_slice(body).unwrap();
        v["streams"][0]["stream"].as_object().unwrap().clone()
    }

    // ── who may push ──

    #[test]
    fn a_node_may_push_only_as_itself() {
        assert!(caller_refusal(Some(&node("host3")), "host3").is_ok());
        let r = caller_refusal(Some(&node("host3")), "host9").unwrap_err();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "node A pushing as node B");
        assert!(r.message().contains("host3") && r.message().contains("host9"));
    }

    #[test]
    fn a_jwt_or_service_credential_cannot_push_at_all() {
        // No ClusterNode extension = a JWT of any tier, a service key, kiosk, add-on.
        let r = caller_refusal(None, "host3").unwrap_err();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // An Internal cluster token (worker / trellion / CLI on the controller
        // secret) — even one whose actor happens to equal the path.
        let internal = ClusterNode("host3".into(), ClusterKind::Internal);
        let r = caller_refusal(Some(&internal), "host3").unwrap_err();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.retry(), "a credential problem keeps the batch");
    }

    /// The route is on the node allow-list with `{self}` — the middleware
    /// half of the same binding.
    #[test]
    fn the_route_is_a_self_scoped_node_route() {
        use crate::auth::node_route_allowed;
        assert!(node_route_allowed("POST", "/api/cluster/nodes/host3/logs", "host3"));
        assert!(!node_route_allowed("POST", "/api/cluster/nodes/host9/logs", "host3"));
        assert!(!node_route_allowed("GET", "/api/cluster/nodes/host3/logs", "host3"));
    }

    // ── labels ──

    #[test]
    fn the_node_label_is_overwritten_with_the_verified_id() {
        let push = prepare_push(&push_json("host9"), "host3").unwrap();
        let labels = labels_of(&push.body);
        assert_eq!(labels["node"], "host3", "the body's node= is never believed");
        assert_eq!(labels["source"], "journal");
        assert_eq!(push.lines, 2);
        assert_eq!(push.streams, 1);
        // A body that says nothing about node gets it too.
        let body = serde_json::to_vec(&json!({"streams":[{"stream":{"source":"self"},"values":[["1","x"]]}]})).unwrap();
        let push = prepare_push(&body, "host3").unwrap();
        assert_eq!(labels_of(&push.body)["node"], "host3");
    }

    /// Defence in depth: a line the shipper did not scrub (an older agent)
    /// still loses its credential here, counted, and a clean push counts
    /// zero. The shapes themselves are proven against the shared corpus in
    /// `redact::secret_shape_tests`; this proves the route applies them.
    /// A key printed one line per entry (`cat key.pem` in a container):
    /// the short last line is recognised by the entry before it, per
    /// stream. .
    #[test]
    fn a_pem_body_s_last_line_is_scrubbed_across_entries_within_a_stream() {
        let body = serde_json::to_vec(&json!({"streams":[
            {"stream":{"source":"docker","name":"a"},"values":[
                ["1", "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g"],
                ["2", "cFH/X3aYjOOuafKrMDCg63ZAt76NozQ5v1bfUr5Lu0WTf92P1rxM2u8qnA+yF9cm"],
                ["3", "Qw3rTy+Uio=="],
                ["4", "Qw3rTy+Uio=="],
            ]},
            {"stream":{"source":"docker","name":"b"},"values":[
                ["1", "Qw3rTy+Uio=="],
                ["2", "r99fs95P7g2wFWzNUbBYYGy/XOMULJwrBOuVuFNI+p+Xzl7df2A/zcDObldNNj5g"],
                ["3", "done"],
            ]},
        ]}))
        .unwrap();
        let push = prepare_push(&body, "host3").unwrap();
        let doc: Value = serde_json::from_slice(&push.body).unwrap();
        let lines = |i: usize| -> Vec<String> {
            doc["streams"][i]["values"].as_array().unwrap().iter().map(|v| v[1].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(
            lines(0),
            ["<redacted:pem-body>", "<redacted:pem-body>", "<redacted:pem-tail>", "Qw3rTy+Uio=="],
            "only the line right after a body line is its tail"
        );
        assert_eq!(
            lines(1),
            ["Qw3rTy+Uio==", "<redacted:pem-body>", "done"],
            "the context is per stream, and a plain word is not a tail"
        );
        assert_eq!(push.redacted, 4);
    }

    #[test]
    fn lines_are_scrubbed_on_ingest_and_counted() {
        let secret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";  // leak-ok: sha256("test"), a well-known test digest, not a secret
        let body = serde_json::to_vec(&json!({"streams":[{"stream":{"source":"docker"},"values":[
            ["1", format!("auth failed for host3:1727512345:{secret}")],
            ["2", "level=info msg=\"heartbeat ok\""],
        ]}]}))
        .unwrap();
        let push = prepare_push(&body, "host3").unwrap();
        let out = String::from_utf8(push.body.clone()).unwrap();
        assert!(!out.contains(secret), "the signature reached the Loki body: {out}");
        assert!(out.contains("auth failed for <redacted:cluster-token>"), "{out}");
        assert!(out.contains("heartbeat ok"), "the clean line is intact: {out}");
        assert_eq!(push.redacted, 1);
        assert_eq!(push.lines, 2);
        let clean = prepare_push(&push_json("host3"), "host3").unwrap();
        assert_eq!(clean.redacted, 0, "a clean push counts nothing");
    }

    #[test]
    fn unknown_labels_are_dropped_and_the_allowed_set_is_exactly_the_plan() {
        let body = serde_json::to_vec(&json!({"streams":[{
            "stream": {"source":"docker","name":"vllm","stream":"stderr","level":"warn","compose_service":"gateway",
                       "module":"free text","event":"cardinality bomb"},
            "values": [["1","x"]]
        }]}))
        .unwrap();
        let push = prepare_push(&body, "host3").unwrap();
        let labels = labels_of(&push.body);
        let mut keys: Vec<&str> = labels.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["compose_service", "level", "name", "node", "source", "stream"]);
        assert_eq!(push.dropped_labels, 2);
    }

    #[test]
    fn oversize_values_and_too_many_labels_are_refused_not_trimmed() {
        let long = "x".repeat(MAX_LABEL_VALUE + 1);
        let body = serde_json::to_vec(&json!({"streams":[{"stream":{"name": long},"values":[["1","x"]]}]})).unwrap();
        let r = prepare_push(&body, "host3").unwrap_err();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(!r.retry(), "malformed = drop the batch");
        let ok = "x".repeat(MAX_LABEL_VALUE);
        let body = serde_json::to_vec(&json!({"streams":[{"stream":{"name": ok},"values":[["1","x"]]}]})).unwrap();
        assert!(prepare_push(&body, "host3").is_ok(), "exactly the cap is fine");

        let mut labels = serde_json::Map::new();
        for i in 0..(MAX_LABELS + 1) {
            labels.insert(format!("k{i}"), Value::String("v".into()));
        }
        let body = serde_json::to_vec(&json!({"streams":[{"stream": labels, "values":[["1","x"]]}]})).unwrap();
        let r = prepare_push(&body, "host3").unwrap_err();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(r.message().contains("labels"));
    }

    #[test]
    fn malformed_bodies_are_400_and_named() {
        let cases: Vec<(Value, &str)> = vec![
            (json!({"nope": []}), "streams"),
            (json!({"streams": [{"stream": "notobj", "values": []}]}), "label object"),
            (json!({"streams": [{"stream": {}, "values": [["abc", "x"]]}]}), "nanoseconds"),
            (json!({"streams": [{"stream": {}, "values": [[1, "x"]]}]}), "nanoseconds"),
            (json!({"streams": [{"stream": {}, "values": [["1", 2]]}]}), "string"),
            (json!({"streams": [{"stream": {}, "values": []}]}), "no entries"),
            (json!({"streams": [{"stream": {"source": 1}, "values": [["1", "x"]]}]}), "string"),
        ];
        for (body, want) in cases {
            let r = prepare_push(&serde_json::to_vec(&body).unwrap(), "host3").unwrap_err();
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{body}");
            assert!(r.message().contains(want), "{body}: {}", r.message());
        }
        let r = prepare_push(b"not json", "host3").unwrap_err();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn stream_and_entry_caps_hold() {
        let streams: Vec<Value> = (0..(MAX_STREAMS + 1))
            .map(|_| json!({"stream": {}, "values": [["1", "x"]]}))
            .collect();
        let body = serde_json::to_vec(&json!({"streams": streams})).unwrap();
        assert_eq!(prepare_push(&body, "host3").unwrap_err().status(), StatusCode::BAD_REQUEST);

        let values: Vec<Value> = (0..(MAX_ENTRIES + 1)).map(|_| json!(["1", "x"])).collect();
        let body = serde_json::to_vec(&json!({"streams": [{"stream": {}, "values": values}]})).unwrap();
        let r = prepare_push(&body, "host3").unwrap_err();
        assert!(r.message().contains("entries"), "{}", r.message());
    }

    // ── body size and encoding ──

    #[test]
    fn gzip_round_trips_and_the_cap_holds_after_decoding() {
        let plain = push_json("host9");
        let gz = gzip(&plain);
        assert_ne!(gz, plain);
        assert_eq!(decode_body(&gz, Some("gzip")).unwrap(), plain);
        assert_eq!(decode_body(&gz, Some(" GZIP ")).unwrap(), plain, "header case and whitespace");
        assert_eq!(decode_body(&plain, None).unwrap(), plain);
        assert_eq!(decode_body(&plain, Some("identity")).unwrap(), plain);
        let push = prepare_push(&decode_body(&gz, Some("gzip")).unwrap(), "host3").unwrap();
        assert_eq!(labels_of(&push.body)["node"], "host3");

        // Not gzip, claimed gzip.
        let r = decode_body(&plain, Some("gzip")).unwrap_err();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // An encoding we do not speak.
        let r = decode_body(&plain, Some("br")).unwrap_err();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);

        // Over the cap on the wire.
        let big = vec![b' '; MAX_BODY + 1];
        assert_eq!(decode_body(&big, None).unwrap_err().status(), StatusCode::PAYLOAD_TOO_LARGE);
        // Under the cap on the wire, over it decoded (the bomb).
        let bomb = gzip(&vec![b'a'; MAX_BODY + 1]);
        assert!(bomb.len() < MAX_BODY);
        let r = decode_body(&bomb, Some("gzip")).unwrap_err();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!r.retry());
        // Exactly the cap decoded is accepted.
        let exact = gzip(&vec![b'a'; MAX_BODY]);
        assert_eq!(decode_body(&exact, Some("gzip")).unwrap().len(), MAX_BODY);
    }

    // ── budget ──

    #[test]
    fn the_per_node_budget_refuses_with_a_retry_after_and_resets_each_minute() {
        let b = NodeBudget::default();
        let limits = Limits { bytes_per_min: 100, requests_per_min: 3 };
        assert!(b.admit("host3", 40, 600, &limits).is_ok());
        assert!(b.admit("host3", 40, 610, &limits).is_ok());
        // Bytes first: 80 + 40 > 100.
        let r = b.admit("host3", 40, 620, &limits).unwrap_err();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.retry());
        assert_eq!(r, Refusal::RateLimited { what: "bytes_per_min", retry_after: 40 });
        // Small enough for bytes, but that is the 3rd request; the 4th is over.
        assert!(b.admit("host3", 1, 620, &limits).is_ok());
        let r = b.admit("host3", 1, 659, &limits).unwrap_err();
        assert_eq!(r, Refusal::RateLimited { what: "requests_per_min", retry_after: 1 });
        // Another node has its own window.
        assert!(b.admit("host9", 100, 659, &limits).is_ok());
        // The next minute starts clean.
        assert!(b.admit("host3", 100, 660, &limits).is_ok());

        let resp = Refusal::RateLimited { what: "bytes_per_min", retry_after: 7 }.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("Retry-After").unwrap(), "7");
    }

    #[test]
    fn the_limits_come_from_the_environment_with_sane_defaults() {
        // Not touching the process environment (other tests run in
        // parallel): the parse rule is what matters and it is exercised via
        // the defaults path — a value of 0 or garbage keeps the default.
        let d = Limits::from_env();
        assert!(d.bytes_per_min >= 1024 * 1024 && d.requests_per_min >= 1);
        assert_eq!(DEFAULT_BYTES_PER_MIN, 8 * 1024 * 1024);
        assert_eq!(DEFAULT_REQUESTS_PER_MIN, 120);
    }

    // ── Loki ──

    /// A listener that answers one request with `status` and `body`.
    async fn one_shot_loki(status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some(idx) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                        .unwrap_or(0);
                    if got.len() >= idx + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let reason = match status { 204 => "No Content", 400 => "Bad Request", _ => "Server Error" };
            let resp = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
            got
        });
        (url, handle)
    }

    #[tokio::test]
    async fn loki_down_is_a_503_that_keeps_the_batch_on_the_node() {
        // A port nothing listens on.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            drop(l);
            url
        };
        let client = reqwest::Client::new();
        let got = forward_to_loki(&client, &dead, b"{}".to_vec()).await;
        assert!(matches!(got, Forward::Down(_)), "{got:?}");
        let r = match got { Forward::Down(t) => Refusal::LokiDown(t), _ => unreachable!() };
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(r.retry(), "5xx/unreachable = the node keeps the batch");

        // Loki up but failing.
        let (url, srv) = one_shot_loki(500, "boom").await;
        let got = forward_to_loki(&client, &url, b"{}".to_vec()).await;
        srv.await.unwrap();
        assert_eq!(got, Forward::Down("Loki answered 500 boom".into()));
    }

    #[tokio::test]
    async fn loki_accepts_the_rewritten_body_and_refuses_are_400() {
        let client = reqwest::Client::new();
        let push = prepare_push(&push_json("host9"), "host3").unwrap();
        let (url, srv) = one_shot_loki(204, "").await;
        let got = forward_to_loki(&client, &url, push.body.clone()).await;
        let seen = srv.await.unwrap();
        assert_eq!(got, Forward::Accepted);
        let seen = String::from_utf8_lossy(&seen);
        assert!(seen.starts_with("POST /loki/api/v1/push HTTP/1.1"), "{seen}");
        assert!(seen.contains("\"node\":\"host3\""), "Loki gets the verified id: {seen}");
        assert!(!seen.contains("host9"), "and never the claimed one: {seen}");

        let (url, srv) = one_shot_loki(400, "entry too far behind").await;
        let got = forward_to_loki(&client, &url, push.body).await;
        srv.await.unwrap();
        assert_eq!(got, Forward::Refused("400 entry too far behind".into()));
        let r = Refusal::LokiRefused("400 entry too far behind".into());
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(!r.retry(), "Loki's 4xx = drop the batch");
    }

    /// Every refusal's response carries the machine-readable half the
    /// shipper branches on.
    #[test]
    fn refusal_bodies_say_whether_to_retry() {
        for (r, retry) in [
            (Refusal::NotThisNode("x".into()), true),
            (Refusal::Malformed("x".into()), false),
            (Refusal::TooLarge("x".into()), false),
            (Refusal::RateLimited { what: "bytes_per_min", retry_after: 1 }, true),
            (Refusal::LokiRefused("x".into()), false),
            (Refusal::LokiDown("x".into()), true),
        ] {
            assert_eq!(r.retry(), retry, "{r:?}");
            assert!(!r.reason().is_empty());
        }
    }

    /// The handler counts and stamps through `state.metrics` (the gateway's
    /// own registry), never the add-on door, and only stamps last-seen on an
    /// ACCEPTED push.
    #[test]
    fn the_handler_records_the_planned_metrics_on_the_gateway_registry() {
        let src = include_str!("logs_ingest.rs");
        let body = src.split("pub async fn node_logs_ingest(").nth(1).unwrap().split("#[cfg(test)]").next().unwrap();
        for m in ["noo_logs_ingest_lines_total", "noo_logs_ingest_bytes_total", "noo_logs_last_seen_unix", "noo_logs_ingest_redacted_total"] {
            assert!(body.contains(m), "{m}");
        }
        assert!(src.contains("noo_logs_ingest_refused_total"));
        assert!(!body.contains("inc_addon_counter") && !body.contains("set_addon_gauge"));
        let accepted = body.split("Forward::Accepted =>").nth(1).unwrap();
        assert!(accepted.contains("noo_logs_last_seen_unix"), "last-seen is stamped on acceptance");
        let before = body.split("Forward::Accepted =>").next().unwrap();
        assert!(!before.contains("noo_logs_last_seen_unix"), "and nowhere before it");
    }
}
