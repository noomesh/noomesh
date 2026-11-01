// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node → gateway → Tempo span ingest (i359 C2).
//!
//! `POST /api/cluster/nodes/{node_id}/traces` is a NODE route, the twin of
//! the log ingest beside it (`logs_ingest.rs`): a node-agent's spans for the
//! requests it served continue the gateway's traces, and Tempo is on the
//! controller's Docker network only, so they come through here. Only a node
//! credential, only for its own id: an operator JWT, a service key, a kiosk
//! or add-on token, or one of the stack's own services on the controller
//! secret is refused (403), because `require_any_auth` lets an Operator JWT
//! reach every route and the handler is where "nodes only" is decided.
//!
//! WIRE CONTRACT:
//!
//! * body: OTLP/HTTP JSON (`{"resourceSpans":[…]}`), identity encoding, at
//!   most [`MAX_BODY`] bytes (413).
//! * what is kept: per span `traceId` (32 hex), `spanId` (16 hex),
//!   `parentSpanId` (16 hex, REQUIRED: a node never starts a trace, it
//!   continues the gateway's), `name` (≤ [`MAX_NAME`]), `kind`, the two
//!   timestamps, `status`, and at most [`MAX_ATTRS`] attributes with string
//!   or integer values (strings ≤ 256 bytes) whose KEY is on
//!   [`ALLOWED_ATTRS`] or under [`AGENT_ATTR_PREFIX`]: a node cannot put
//!   `enduser.id`, `service.name` or `noo.node` on a span and attribute a
//!   request to someone. Any other attribute is dropped and counted. Anything
//!   else on a span (events, links, other fields) is dropped.
//! * time: a span must END within [`TIME_WINDOW_NS`] of when the gateway
//!   receives it, start no later than it ends, and last at most
//!   [`MAX_DURATION_NS`], so a node cannot backdate or future-date one out of
//!   (or to the top of) the retention window.
//! * a span that fails a rule is dropped and counted, not the whole batch.
//!   At most [`MAX_SPANS`] spans.
//! * identity: the resource is REPLACED with `service.name=noo-node-agent`
//!   and `noo.node=<the verified id>`, whatever the body claimed, so a span
//!   in Tempo that names a node was sent by that node.
//! * budget: per node, [`REQUESTS_PER_MIN`] pushes and [`BYTES_PER_MIN`]
//!   bytes a minute (429 with `Retry-After`). Fixed constants, not settings.
//! * status codes: 204 accepted by Tempo; 400 / 413 drop the batch; 403 a
//!   credential problem; 429 wait `Retry-After`; 503 Tempo down or not
//!   configured (the agent drops the batch: traces are best effort, and the
//!   gateway holds nothing).
//!
//! Every refusal is counted in `noo_traces_ingest_refused_total{node,reason}`,
//! every dropped span in `noo_traces_ingest_dropped_spans_total{node}` and
//! every dropped attribute in `noo_traces_ingest_dropped_attrs_total{node}`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Map, Value};

use super::logs_ingest::{Limits, NodeBudget};
use crate::auth::ClusterNode;
use crate::state::AppState;

pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_SPANS: usize = 2_000;
pub const MAX_NAME: usize = 128;
pub const MAX_ATTRS: usize = 32;
const MAX_ATTR_VALUE: usize = 256;
/// The span attribute keys a node may send: what its agent writes today.
pub const ALLOWED_ATTRS: &[&str] = &["noo.backend", "http.response.status_code"];
/// Room for the agent's own later attributes, never an identity key.
pub const AGENT_ATTR_PREFIX: &str = "noo.agent.";
/// How far a span's end may be from the time the gateway receives it.
pub const TIME_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;
/// The longest span a node may report (a long streamed answer is minutes).
pub const MAX_DURATION_NS: u64 = 60 * 60 * 1_000_000_000;
pub const REQUESTS_PER_MIN: u64 = 120;
pub const BYTES_PER_MIN: u64 = 8 * 1024 * 1024;
/// What the resource of every forwarded span says it is.
pub const NODE_SERVICE: &str = "noo-node-agent";
const TEMPO_PUSH_TIMEOUT_SECS: u64 = 10;

/// Why a push was not accepted: one status and one metric `reason` each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotThisNode(String),
    Malformed(String),
    TooLarge(String),
    RateLimited { what: &'static str, retry_after: u64 },
    TempoRefused(String),
    TempoDown(String),
}

impl Refusal {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotThisNode(_) => StatusCode::FORBIDDEN,
            Self::Malformed(_) | Self::TempoRefused(_) => StatusCode::BAD_REQUEST,
            Self::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::TempoDown(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotThisNode(_) => "not_this_node",
            Self::Malformed(_) => "malformed",
            Self::TooLarge(_) => "too_large",
            Self::RateLimited { what, .. } => what,
            Self::TempoRefused(_) => "tempo_refused",
            Self::TempoDown(_) => "tempo_down",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::NotThisNode(m) | Self::Malformed(m) | Self::TooLarge(m) | Self::TempoDown(m) => m.clone(),
            Self::TempoRefused(m) => format!("Tempo refused the batch: {m}"),
            Self::RateLimited { what, retry_after } => format!(
                "over the per-node span budget ({what}: {REQUESTS_PER_MIN} pushes and {BYTES_PER_MIN} bytes a minute); retry in {retry_after}s"
            ),
        }
    }

    pub fn into_response(self) -> Response {
        let body = Json(json!({"error": self.message(), "reason": self.reason()}));
        let mut resp = (self.status(), body).into_response();
        if let Self::RateLimited { retry_after, .. } = self {
            if let Ok(v) = retry_after.to_string().parse() {
                resp.headers_mut().insert("Retry-After", v);
            }
        }
        resp
    }
}

/// Only a node credential, and only for its own id. Pure, so the table is
/// pinned without a request.
pub fn caller_refusal(caller: Option<&ClusterNode>, node_id: &str) -> Result<(), Refusal> {
    match caller {
        None => Err(Refusal::NotThisNode(
            "span ingest is a node route: a node-agent's cluster credential is required, no user or operator token".into(),
        )),
        Some(c) if c.is_internal() => {
            Err(Refusal::NotThisNode(format!("'{}' is a stack service, not a node; it sends its spans to Tempo itself", c.0)))
        }
        Some(c) if c.0 != node_id => {
            Err(Refusal::NotThisNode(format!("node '{}' may only send spans as itself, not as '{node_id}'", c.0)))
        }
        Some(_) => Ok(()),
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()) && s.bytes().any(|b| b != b'0')
}

fn key_allowed(key: &str) -> bool {
    ALLOWED_ATTRS.contains(&key) || (key.len() > AGENT_ATTR_PREFIX.len() && key.len() <= 64 && key.starts_with(AGENT_ATTR_PREFIX))
}

/// One attribute as kept, or None when it breaks a rule.
fn clean_attr(a: &Value) -> Option<Value> {
    let key = a.get("key")?.as_str()?;
    if !key_allowed(key) {
        return None;
    }
    let v = a.get("value")?;
    let value = if let Some(s) = v.get("stringValue").and_then(Value::as_str) {
        if s.len() > MAX_ATTR_VALUE {
            return None;
        }
        json!({"stringValue": s})
    } else {
        let i = v.get("intValue")?;
        let n = i.as_str().map(str::to_string).or_else(|| i.as_i64().map(|n| n.to_string()))?;
        n.parse::<i64>().ok()?;
        json!({"intValue": n})
    };
    Some(json!({"key": key, "value": value}))
}

/// One span as kept, with how many of its attributes were dropped, or None
/// when the span itself breaks a rule. `now_ns` is when the push arrived.
fn clean_span(s: &Value, now_ns: u64) -> Option<(Value, u64)> {
    let trace_id = s.get("traceId")?.as_str()?;
    let span_id = s.get("spanId")?.as_str()?;
    let parent = s.get("parentSpanId")?.as_str()?;
    if !is_hex(trace_id, 32) || !is_hex(span_id, 16) || !is_hex(parent, 16) {
        return None;
    }
    let name = s.get("name")?.as_str()?;
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let start = s.get("startTimeUnixNano")?.as_str()?;
    let end = s.get("endTimeUnixNano")?.as_str()?;
    let (start_ns, end_ns) = (start.parse::<u64>().ok()?, end.parse::<u64>().ok()?);
    if start_ns > end_ns || end_ns - start_ns > MAX_DURATION_NS || end_ns.abs_diff(now_ns) > TIME_WINDOW_NS {
        return None;
    }
    let (attrs, dropped_attrs) = match s.get("attributes") {
        None => (Vec::new(), 0),
        Some(Value::Array(a)) if a.len() <= MAX_ATTRS => {
            let kept: Vec<Value> = a.iter().filter_map(clean_attr).collect();
            let dropped = (a.len() - kept.len()) as u64;
            (kept, dropped)
        }
        Some(_) => return None,
    };
    let kind = s.get("kind").and_then(Value::as_u64).filter(|k| *k <= 5).unwrap_or(0);
    let code = s.get("status").and_then(|st| st.get("code")).and_then(Value::as_u64).filter(|c| *c <= 2).unwrap_or(0);
    Some((json!({
        "traceId": trace_id.to_ascii_lowercase(),
        "spanId": span_id.to_ascii_lowercase(),
        "parentSpanId": parent.to_ascii_lowercase(),
        "name": name,
        "kind": kind,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": attrs,
        "status": {"code": code},
    }), dropped_attrs))
}

/// What a push becomes: the OTLP body forwarded to Tempo, and the counts.
#[derive(Debug)]
pub struct Prepared {
    pub body: Value,
    pub kept: u64,
    pub dropped: u64,
    pub dropped_attrs: u64,
}

/// Parse, clean and re-stamp a push for `node_id`. Refuses only what no
/// retry could fix (not JSON, not OTLP, too many spans, nothing left).
pub fn prepare(raw: &[u8], node_id: &str, now_ns: u64) -> Result<Prepared, Refusal> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| Refusal::Malformed(format!("body is not JSON: {e}")))?;
    let rs = v
        .get("resourceSpans")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::Malformed("body must be an object with a \"resourceSpans\" array".into()))?;
    let mut spans = Vec::new();
    let mut seen = 0usize;
    let mut dropped = 0u64;
    let mut dropped_attrs = 0u64;
    for r in rs {
        for scope in r.get("scopeSpans").and_then(Value::as_array).into_iter().flatten() {
            for s in scope.get("spans").and_then(Value::as_array).into_iter().flatten() {
                seen += 1;
                if seen > MAX_SPANS {
                    return Err(Refusal::Malformed(format!("more than {MAX_SPANS} spans in one push")));
                }
                match clean_span(s, now_ns) {
                    Some((c, d)) => {
                        spans.push(c);
                        dropped_attrs += d;
                    }
                    None => dropped += 1,
                }
            }
        }
    }
    if spans.is_empty() {
        return Err(Refusal::Malformed(format!("no acceptable span in the push ({dropped} dropped)")));
    }
    let mut resource = Map::new();
    resource.insert(
        "attributes".into(),
        json!([
            {"key": "service.name", "value": {"stringValue": NODE_SERVICE}},
            {"key": "noo.node", "value": {"stringValue": node_id}},
        ]),
    );
    let kept = spans.len() as u64;
    let body = json!({
        "resourceSpans": [{"resource": resource, "scopeSpans": [{"scope": {"name": NODE_SERVICE}, "spans": spans}]}]
    });
    Ok(Prepared { body, kept, dropped, dropped_attrs })
}

static BUDGET: LazyLock<NodeBudget> = LazyLock::new(NodeBudget::default);

fn limits() -> Limits {
    Limits { bytes_per_min: BYTES_PER_MIN, requests_per_min: REQUESTS_PER_MIN }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The metric label for a caller: the verified id, or a fixed word, so a
/// path a JWT caller typed never becomes a series.
fn metric_node(caller: Option<&ClusterNode>) -> String {
    match caller {
        Some(c) if !c.is_internal() => c.0.clone(),
        Some(_) => "internal".into(),
        None => "none".into(),
    }
}

async fn forward(url: &str, body: &Value) -> Result<(), Refusal> {
    let sent = crate::tls::cluster_client()
        .post(url)
        .timeout(std::time::Duration::from_secs(TEMPO_PUSH_TIMEOUT_SECS))
        .json(body)
        .send()
        .await;
    match sent {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => {
            let status = r.status().as_u16();
            let text: String = r.text().await.unwrap_or_default().chars().take(300).collect();
            if (400..500).contains(&status) {
                Err(Refusal::TempoRefused(format!("{status} {text}")))
            } else {
                Err(Refusal::TempoDown(format!("Tempo answered {status} {text}")))
            }
        }
        Err(e) => Err(Refusal::TempoDown(format!("Tempo unreachable: {e}"))),
    }
}

/// Node span ingest: a node-agent sends the spans of the requests it
/// served, continuing the gateway's traces, and the gateway relays them to
/// Tempo stamped with the verified node.
///
/// POST /api/cluster/nodes/{node_id}/traces — node credential only, and
/// only for its own id. Body: OTLP/HTTP JSON, at most 1 MiB. See the module
/// docs for the wire contract (what is kept, limits, status codes).
pub async fn node_traces_ingest(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    caller: Option<Extension<ClusterNode>>,
    body: Bytes,
) -> Response {
    let caller = caller.as_ref().map(|Extension(c)| c);
    let node_label = metric_node(caller);
    let refuse = |r: Refusal| async {
        let labels = HashMap::from([("node".to_string(), node_label.clone()), ("reason".to_string(), r.reason().to_string())]);
        state.metrics.inc_counter("noo_traces_ingest_refused_total", Some(&labels), 1).await;
        r.into_response()
    };
    if let Err(r) = caller_refusal(caller, &node_id) {
        tracing::warn!(requested = %node_id, caller = %node_label, "span ingest refused: {}", r.message());
        return refuse(r).await;
    }
    if body.len() > MAX_BODY {
        return refuse(Refusal::TooLarge(format!("body is {} bytes; the cap is {MAX_BODY}", body.len()))).await;
    }
    if let Err(r) = BUDGET.admit(&node_id, body.len() as u64, now_secs(), &limits()) {
        let refusal = match r {
            super::logs_ingest::Refusal::RateLimited { what, retry_after } => Refusal::RateLimited { what, retry_after },
            other => Refusal::Malformed(other.message()),
        };
        return refuse(refusal).await;
    }
    let url = match crate::request_trace::tempo_traces_url(&std::env::var(crate::request_trace::TEMPO_URL_ENV).unwrap_or_default()) {
        Ok(Some(u)) => u,
        Ok(None) => return refuse(Refusal::TempoDown("Tempo is not configured on this controller (NOO_TEMPO_OTLP_URL)".into())).await,
        Err(e) => return refuse(Refusal::TempoDown(e)).await,
    };
    let prepared = match prepare(&body, &node_id, now_ns()) {
        Ok(p) => p,
        Err(r) => return refuse(r).await,
    };
    let labels = HashMap::from([("node".to_string(), node_id.clone())]);
    if prepared.dropped > 0 {
        state.metrics.inc_counter("noo_traces_ingest_dropped_spans_total", Some(&labels), prepared.dropped).await;
    }
    if prepared.dropped_attrs > 0 {
        state.metrics.inc_counter("noo_traces_ingest_dropped_attrs_total", Some(&labels), prepared.dropped_attrs).await;
    }
    match forward(&url, &prepared.body).await {
        Ok(()) => {
            state.metrics.inc_counter("noo_traces_ingest_spans_total", Some(&labels), prepared.kept).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(r) => refuse(r).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ClusterKind;

    fn node(id: &str) -> ClusterNode {
        ClusterNode(id.into(), ClusterKind::Node)
    }

    /// A fixed "now" for the pushes the tests build.
    const NOW: u64 = 1_793_400_000_000_000_000;

    fn span(parent: Option<&str>) -> Value {
        let mut s = json!({
            "traceId": "4bf92f3577b34da6a3ce929d0e0e4736", "spanId": "00f067aa0ba902b7",
            "name": "agent inference vllm", "kind": 2,
            "startTimeUnixNano": (NOW - 1_000).to_string(), "endTimeUnixNano": NOW.to_string(),
            "attributes": [{"key": "noo.backend", "value": {"stringValue": "vllm"}}, {"key": "http.response.status_code", "value": {"intValue": "200"}}],
            "status": {"code": 1},
            "events": [{"name": "x"}],
        });
        if let Some(p) = parent {
            s["parentSpanId"] = json!(p);
        }
        s
    }

    fn prepare_at(raw: &[u8], node: &str) -> Result<Prepared, Refusal> {
        prepare(raw, node, NOW)
    }

    fn push(spans: Vec<Value>, resource: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"resourceSpans": [{"resource": resource, "scopeSpans": [{"scope": {"name": "x"}, "spans": spans}]}]}))
            .expect("json")
    }

    /// No user, operator or service token reaches the relay: only a node,
    /// and only as itself.
    #[test]
    fn only_a_node_as_itself_may_push() {
        let e = caller_refusal(None, "host3").expect_err("no node credential (an operator JWT arrives as None)");
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert!(e.message().contains("no user or operator token"), "{}", e.message());
        let internal = ClusterNode("cluster".into(), ClusterKind::Internal);
        assert_eq!(caller_refusal(Some(&internal), "host3").map_err(|e| e.status()), Err(StatusCode::FORBIDDEN));
        assert_eq!(caller_refusal(Some(&node("host8")), "host3").map_err(|e| e.status()), Err(StatusCode::FORBIDDEN));
        assert_eq!(caller_refusal(Some(&node("host3")), "host3"), Ok(()));
        assert!(crate::auth::node_route_allowed("POST", "/api/cluster/nodes/host3/traces", "host3"));
        assert!(!crate::auth::node_route_allowed("POST", "/api/cluster/nodes/host8/traces", "host3"), "a node sends only its own spans");
    }

    #[test]
    fn the_resource_is_replaced_with_the_verified_node() {
        let claimed = json!({"attributes": [
            {"key": "service.name", "value": {"stringValue": "noo-gateway"}},
            {"key": "noo.node", "value": {"stringValue": "host8"}},
        ]});
        let p = prepare_at(&push(vec![span(Some("1111111111111111"))], claimed), "host3").expect("accepted");
        let res = &p.body["resourceSpans"][0]["resource"]["attributes"];
        assert_eq!(res[0]["value"]["stringValue"], json!(NODE_SERVICE));
        assert_eq!(res[1]["value"]["stringValue"], json!("host3"), "the body's node claim is overwritten");
        assert_eq!(res.as_array().map(Vec::len), Some(2), "nothing else the body claimed survives");
        let s = &p.body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert!(s.get("events").is_none(), "events are dropped");
        assert_eq!(s["attributes"].as_array().map(Vec::len), Some(2));
        assert_eq!((p.kept, p.dropped), (1, 0));
    }

    #[test]
    fn a_span_that_does_not_continue_a_trace_or_breaks_a_rule_is_dropped_and_counted() {
        let mut long = span(Some("1111111111111111"));
        long["name"] = json!("x".repeat(MAX_NAME + 1));
        let mut zero = span(Some("1111111111111111"));
        zero["traceId"] = json!("0".repeat(32));
        let mut big_attr = span(Some("1111111111111111"));
        big_attr["attributes"] = json!([{"key": "noo.backend", "value": {"stringValue": "v".repeat(MAX_ATTR_VALUE + 1)}}]);
        let p = prepare_at(&push(vec![span(None), long, zero, big_attr, span(Some("2222222222222222"))], json!({})), "host3")
            .expect("one span is fine");
        // The oversize attribute goes; its span stays.
        assert_eq!((p.kept, p.dropped, p.dropped_attrs), (2, 3, 1));
        let none = prepare_at(&push(vec![span(None)], json!({})), "host3").expect_err("nothing left");
        assert_eq!(none.status(), StatusCode::BAD_REQUEST);
    }

    /// A node cannot attribute a request to anyone: an identity attribute
    /// (or any key off the allow-list) is dropped from the span and counted;
    /// the span itself is kept.
    #[test]
    fn a_node_cannot_set_an_identity_attribute() {
        let mut s = span(Some("1111111111111111"));
        s["attributes"] = json!([
            {"key": "enduser.id", "value": {"stringValue": "alice"}},
            {"key": "service.name", "value": {"stringValue": "noo-gateway"}},
            {"key": "noo.node", "value": {"stringValue": "host8"}},
            {"key": "noo.backend", "value": {"stringValue": "vllm"}},
            {"key": "noo.agent.queue_ms", "value": {"intValue": "4"}},
        ]);
        let p = prepare_at(&push(vec![s], json!({})), "host3").expect("the span is kept");
        let attrs = p.body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"].as_array().expect("attrs").clone();
        let keys: Vec<&str> = attrs.iter().filter_map(|a| a["key"].as_str()).collect();
        assert_eq!(keys, ["noo.backend", "noo.agent.queue_ms"]);
        assert_eq!((p.kept, p.dropped, p.dropped_attrs), (1, 0, 3));
    }

    /// A span must end near now, start before it ends and last at most an
    /// hour: a node cannot backdate or future-date one.
    #[test]
    fn a_span_outside_the_time_window_is_dropped() {
        let at = |start: u64, end: u64| {
            let mut s = span(Some("1111111111111111"));
            s["startTimeUnixNano"] = json!(start.to_string());
            s["endTimeUnixNano"] = json!(end.to_string());
            s
        };
        let min = 60 * 1_000_000_000u64;
        let spans = vec![
            at(NOW - 2 * min, NOW - min),             // ended a minute ago: kept
            at(NOW - 30 * min, NOW - 20 * min),       // ended 20 min ago
            at(NOW + 20 * min, NOW + 21 * min),       // ends in the future
            at(NOW, NOW - 1),                         // ends before it starts
            at(NOW - 90 * min, NOW - min),            // 89 minutes long
        ];
        let p = prepare_at(&push(spans, json!({})), "host3").expect("one is fine");
        assert_eq!((p.kept, p.dropped), (1, 4));
    }

    #[test]
    fn limits_answer_with_the_number() {
        let too_many: Vec<Value> = (0..=MAX_SPANS).map(|_| span(Some("1111111111111111"))).collect();
        assert!(prepare_at(&push(too_many, json!({})), "host3").expect_err("over").message().contains(&MAX_SPANS.to_string()));
        let r = Refusal::RateLimited { what: "requests_per_min", retry_after: 7 };
        assert!(r.message().contains(&REQUESTS_PER_MIN.to_string()), "{}", r.message());
        let resp = r.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("Retry-After").and_then(|v| v.to_str().ok()), Some("7"));
        let b = NodeBudget::default();
        for _ in 0..REQUESTS_PER_MIN {
            b.admit("host3", 10, 60, &limits()).expect("within budget");
        }
        assert!(b.admit("host3", 10, 61, &limits()).is_err(), "the per-node request budget holds");
        assert!(b.admit("host4", 10, 61, &limits()).is_ok(), "per node, not global");
    }
}
