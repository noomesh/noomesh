// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Control over the bus: the gateway's side of i131 phase 1.
//!
//! A node that has said `control_transports.nats_rpc` holds an outbound NATS
//! connection and answers small control calls on `node.<id>.rpc.<op>`.
//! `NodeLink::request` routes a call here when (and only when) the node
//! advertises it, the bus is up and the call is one of the ops in
//! [`control_op`]; every other call, and every call to a node that has not
//! said, goes over HTTPS exactly as before.
//!
//! What this module owns:
//!
//! - [`control_op`]: which `(method, path)` pairs are control ops, their
//!   argument, whether they are idempotent (a repeated read) and whether they
//!   are long-running (acked at once, result on `node.<id>.evt.<op_id>`).
//! - [`route`]: bus or HTTPS, a pure decision, tested as a table.
//! - the signed envelope: `{op, node, ts, nonce, arg, query, op_id,
//!   timeout_s, body_sha256}` signed with the controller's leaf key (the
//!   gateway's own `NOO_TLS_KEY`; the node verifies the chain to the cluster
//!   CA and the controller organization, the same fact `ControllerOnly`
//!   checks for a TLS peer). The fleet code-signing key is NOT used: it is
//!   deliberately not on the gateway, so that a gateway compromise cannot
//!   sign code (`scripts/noo-apply.sh`).
//! - the failure policy: a bus failure on a non-idempotent op is surfaced as
//!   the node being unreachable and is never retried over HTTPS (the work may
//!   have run); an idempotent read may fall back to HTTPS once, logged and
//!   counted.
//! - per-node counters of control calls by transport, which the later
//!   "outbound-only" gate reads (`GET /api/cluster/nodes`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures::StreamExt;
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Envelope version; the node accepts only this one.
pub const ENVELOPE_VERSION: u32 = 1;

/// A long op that has said nothing for this long is treated as dead. The node
/// publishes a keepalive every 10 s.
const EVENT_IDLE: Duration = Duration::from_secs(45);
/// How long the immediate ack of a long op may take.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Used when the caller set no timeout.
const DEFAULT_SYNC: Duration = Duration::from_secs(30);
const DEFAULT_ASYNC: Duration = Duration::from_secs(1800);
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

// ── which calls are control ops ─────────────────────────────────────────

/// One control op, as derived from an HTTPS call it replaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlOp {
    /// The op name: the last tokens of the subject.
    pub op: &'static str,
    /// The one path value the op takes (a container, an MCP server, a cleanup
    /// kind); empty if none.
    pub arg: String,
    /// The URL query string, no `?`.
    pub query: String,
    /// A repeated call is harmless (a read). Only these may fall back to
    /// HTTPS after a bus failure.
    pub idempotent: bool,
    /// Long-running: acked at once, result on the event stream.
    pub asynchronous: bool,
}

fn plain_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.contains("..")
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// The control op an HTTPS call to the node agent is, if it is one. `path`
/// may carry a query. Streaming and bulk routes (inference, the container
/// proxy, device blobs, `/metrics`) are NOT control ops: they stay on HTTPS
/// until the tunnel (i131 phase 2). There is no `tools` op: the agent has no
/// such route.
pub fn control_op(method: &Method, path: &str) -> Option<ControlOp> {
    let (p, query) = match path.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (path, String::new()),
    };
    let simple = |op: &'static str, idempotent: bool, asynchronous: bool| {
        Some(ControlOp { op, arg: String::new(), query: query.clone(), idempotent, asynchronous })
    };
    let m = method.as_str();
    match (m, p) {
        ("GET", "/health") => simple("health", true, false),
        ("GET", "/gpu") => simple("gpu", true, false),
        ("GET", "/stats/containers") => simple("stats", true, false),
        ("GET", "/v1/models") => simple("models", true, false),
        ("POST", "/start") => simple("start", false, false),
        ("POST", "/stop") => simple("stop", false, false),
        ("POST", "/restart") => simple("restart", false, false),
        // A nudge is harmless to repeat (passes coalesce), so it may fall
        // back to HTTPS like a read.
        ("POST", "/reconcile") => simple("reconcile", true, false),
        ("POST", "/clean") => simple("clean", false, false),
        ("POST", "/pull") => simple("pull", false, true),
        ("POST", "/api/skills/run") => simple("skills.run", false, true),
        ("GET", "/api/mcp/servers") => simple("mcp.servers", true, false),
        ("GET", "/logs/containers") => simple("logs", true, false),
        ("POST", "/cleanup/images") | ("POST", "/cleanup/logs") => Some(ControlOp {
            op: "cleanup",
            arg: p.trim_start_matches("/cleanup/").to_string(),
            query,
            idempotent: false,
            asynchronous: false,
        }),
        ("GET", _) if p.starts_with("/logs/") => {
            let c = p.strip_prefix("/logs/")?;
            plain_token(c).then(|| ControlOp { op: "logs", arg: c.to_string(), query, idempotent: true, asynchronous: false })
        }
        ("POST", _) if p.starts_with("/api/mcp/") => {
            let server = p.strip_prefix("/api/mcp/").and_then(|r| r.strip_suffix("/call"))?;
            plain_token(server).then(|| ControlOp { op: "mcp.call", arg: server.to_string(), query, idempotent: false, asynchronous: false })
        }
        _ => None,
    }
}

// ── routing ─────────────────────────────────────────────────────────────

/// The operator's brake: `NOO_CONTROL_OVER_BUS=0` (or `false`/`off`) sends
/// every control call over HTTPS again, whatever nodes advertise. Default on.
pub fn enabled() -> bool {
    !matches!(
        std::env::var("NOO_CONTROL_OVER_BUS").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

/// The transport a call takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Bus,
    Https,
}

/// Bus when the node advertises `nats_rpc`, the gateway's bus is connected,
/// and the call is a control op; HTTPS in every other case. Pure.
pub fn route(node_nats_rpc: bool, bus_connected: bool, op: Option<&ControlOp>) -> Route {
    if node_nats_rpc && bus_connected && op.is_some() {
        Route::Bus
    } else {
        Route::Https
    }
}

/// What to do when the bus call failed (no responders, timeout, a node that
/// refused the envelope, a reply too big for the bus).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterFailure {
    /// Try HTTPS once, log it, count it.
    Https,
    /// Report the node unreachable. The call may have run; do not repeat it.
    Unreachable,
}

pub fn after_failure(op: &ControlOp) -> AfterFailure {
    if op.idempotent {
        AfterFailure::Https
    } else {
        AfterFailure::Unreachable
    }
}

// ── counters ────────────────────────────────────────────────────────────

/// Control calls by transport for one node (or one unattributed agent URL).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlCounts {
    /// Control-set calls that went over the bus.
    pub bus: u64,
    /// Control-set calls that went over HTTPS :8081.
    pub https_control: u64,
    /// Calls that are not in the control set (streaming, bulk, device,
    /// proxy) and therefore still HTTPS. The "outbound-only" gate needs both
    /// HTTPS numbers at zero.
    pub https_other: u64,
    /// Idempotent reads that fell back to HTTPS after a bus failure.
    pub fallbacks: u64,
    /// Calls and streams carried over the node-held tunnel (i131 phase 2).
    pub tunnel: u64,
    /// Tunnel streams that were cut by a dropped tunnel or a reset.
    pub tunnel_aborts: u64,
}

static COUNTS: OnceLock<Mutex<HashMap<String, ControlCounts>>> = OnceLock::new();

fn counts_map() -> &'static Mutex<HashMap<String, ControlCounts>> {
    COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn bump(key: &str, f: impl FnOnce(&mut ControlCounts)) {
    if let Ok(mut m) = counts_map().lock() {
        f(m.entry(key.to_string()).or_default());
    }
}

pub(crate) fn note_bus(key: &str) {
    bump(key, |c| c.bus += 1);
}
pub(crate) fn note_https(key: &str, is_control: bool) {
    bump(key, |c| if is_control { c.https_control += 1 } else { c.https_other += 1 });
}
pub(crate) fn note_fallback(key: &str) {
    bump(key, |c| c.fallbacks += 1);
}
pub(crate) fn note_tunnel(key: &str) {
    bump(key, |c| c.tunnel += 1);
}
pub(crate) fn note_tunnel_abort(key: &str) {
    bump(key, |c| c.tunnel_aborts += 1);
}

/// A snapshot of the counters, by node id (or agent URL host for a link that
/// was not resolved by node id).
pub fn counts() -> HashMap<String, ControlCounts> {
    counts_map().lock().map(|m| m.clone()).unwrap_or_default()
}

/// [`counts`] for one node as JSON, `null` fields never: a node never called
/// reads all zeros.
pub fn counts_json(node: &str) -> Value {
    let c = counts().get(node).copied().unwrap_or_default();
    json!({
        "bus": c.bus,
        "https_control": c.https_control,
        "https_other": c.https_other,
        "fallbacks": c.fallbacks,
        "tunnel": c.tunnel,
        "tunnel_aborts": c.tunnel_aborts,
        "tunnel_live": crate::tunnel::hub().live(node).is_some(),
    })
}

// ── the signed envelope ─────────────────────────────────────────────────

/// What signs an envelope. The gateway's leaf key in production; a test key
/// in tests.
pub trait EnvelopeSigner: Send + Sync {
    /// `"ES256"` or `"ES384"`.
    fn alg(&self) -> &'static str;
    /// ASN.1 DER ECDSA signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
    /// The signer's certificate, DER, base64 (standard alphabet).
    fn cert_b64(&self) -> &str;
}

/// The byte string that is signed. Plain lines so the Go verifier
/// (`node-agent-go/internal/ctrlrpc` `Envelope.Canonical`) cannot disagree
/// about framing; the vector in the tests of both sides pins them equal.
#[allow(clippy::too_many_arguments)]
pub fn canonical(
    op: &str,
    node: &str,
    ts: i64,
    nonce: &str,
    arg: &str,
    query: &str,
    op_id: &str,
    timeout_s: u64,
    body_sha256: &str,
) -> Result<String, String> {
    for f in [op, node, nonce, arg, query, op_id, body_sha256] {
        if f.contains(['\n', '\r']) {
            return Err("an envelope field contains a line break".into());
        }
    }
    Ok(format!(
        "noo-rpc-v{ENVELOPE_VERSION}\n{op}\n{node}\n{ts}\n{nonce}\n{arg}\n{query}\n{op_id}\n{timeout_s}\n{body_sha256}"
    ))
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Build and sign the envelope for one message.
#[allow(clippy::too_many_arguments)]
pub fn build_envelope(
    signer: &dyn EnvelopeSigner,
    cop: &ControlOp,
    node: &str,
    op_id: &str,
    timeout: Duration,
    body: &[u8],
    ts: i64,
    nonce: &str,
) -> Result<Value, String> {
    let body_sha = hex::encode(Sha256::digest(body));
    let timeout_s = timeout.as_secs().min(MAX_TIMEOUT.as_secs());
    let canon = canonical(cop.op, node, ts, nonce, &cop.arg, &cop.query, op_id, timeout_s, &body_sha)?;
    let sig = signer.sign(canon.as_bytes())?;
    Ok(json!({
        "v": ENVELOPE_VERSION,
        "op": cop.op,
        "node": node,
        "ts": ts,
        "nonce": nonce,
        "arg": cop.arg,
        "query": cop.query,
        "op_id": op_id,
        "timeout_s": timeout_s,
        "body_sha256": body_sha,
        "alg": signer.alg(),
        "sig": base64::engine::general_purpose::STANDARD.encode(sig),
        "cert": signer.cert_b64(),
    }))
}

/// The gateway's leaf (`NOO_TLS_CERT` / `NOO_TLS_KEY`), loaded on first use.
struct LeafSigner {
    key: Arc<dyn rustls::sign::SigningKey>,
    cert_b64: String,
    alg: &'static str,
}

impl LeafSigner {
    fn load() -> Result<Self, String> {
        let key_path = std::env::var("NOO_TLS_KEY").unwrap_or_default();
        let cert_path = std::env::var("NOO_TLS_CERT").unwrap_or_default();
        if key_path.trim().is_empty() || cert_path.trim().is_empty() {
            return Err("NOO_TLS_KEY / NOO_TLS_CERT are not set, so control envelopes cannot be signed".into());
        }
        let key_pem = std::fs::read(key_path.trim()).map_err(|e| format!("{key_path}: {e}"))?;
        let cert_pem = std::fs::read(cert_path.trim()).map_err(|e| format!("{cert_path}: {e}"))?;
        Self::from_pem(&key_pem, &cert_pem)
    }

    fn from_pem(key_pem: &[u8], cert_pem: &[u8]) -> Result<Self, String> {
        let mut kr = key_pem;
        let key = rustls_pemfile::private_key(&mut kr)
            .map_err(|e| format!("private key: {e}"))?
            .ok_or("the key file holds no private key")?;
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|e| format!("private key: {e}"))?;
        let mut cr = cert_pem;
        let leaf = rustls_pemfile::certs(&mut cr)
            .next()
            .ok_or("the certificate file holds no certificate")?
            .map_err(|e| format!("certificate: {e}"))?;
        let probe = key
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
            .ok_or("the controller leaf key is not ECDSA P-256 or P-384")?;
        let alg = match probe.scheme() {
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => "ES384",
            _ => "ES256",
        };
        Ok(Self { key, cert_b64: base64::engine::general_purpose::STANDARD.encode(leaf.as_ref()), alg })
    }
}

impl EnvelopeSigner for LeafSigner {
    fn alg(&self) -> &'static str {
        self.alg
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let signer = self
            .key
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
            .ok_or("the controller leaf key is not ECDSA P-256 or P-384")?;
        signer.sign(msg).map_err(|e| format!("signing failed: {e}"))
    }
    fn cert_b64(&self) -> &str {
        &self.cert_b64
    }
}

static LEAF: Mutex<Option<Arc<LeafSigner>>> = Mutex::new(None);

fn leaf_signer() -> Result<Arc<LeafSigner>, String> {
    let mut g = LEAF.lock().map_err(|_| "signer lock poisoned".to_string())?;
    if let Some(s) = g.as_ref() {
        return Ok(s.clone());
    }
    let s = Arc::new(LeafSigner::load()?);
    *g = Some(s.clone());
    Ok(s)
}

/// Sign `msg` with the controller leaf: `(alg, signature b64, cert b64)`.
/// The tunnel handshake signs its challenge with this (the same key that
/// signs control envelopes, for the same reason: it is the fact the node
/// already checks to believe "this is the controller").
pub(crate) fn sign_detached(msg: &[u8]) -> Result<(&'static str, String, String), String> {
    let signer = leaf_signer()?;
    let sig = signer.sign(msg)?;
    Ok((signer.alg(), base64::engine::general_purpose::STANDARD.encode(sig), signer.cert_b64().to_string()))
}

/// [`sign_detached`] with a key and certificate given as PEM, for tests.
#[cfg(test)]
pub(crate) fn sign_detached_with_pem(msg: &[u8], key_pem: &[u8], cert_pem: &[u8]) -> Result<(&'static str, String, String), String> {
    let signer = LeafSigner::from_pem(key_pem, cert_pem)?;
    let sig = signer.sign(msg)?;
    Ok((signer.alg(), base64::engine::general_purpose::STANDARD.encode(sig), signer.cert_b64().to_string()))
}

// ── a bus call ──────────────────────────────────────────────────────────

/// A node reached over the bus.
#[derive(Clone, Debug)]
pub struct BusTarget {
    pub nats: async_nats::Client,
    pub node: String,
}

/// What came back, before it is turned into a `reqwest::Response`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusReply {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// The reply did not fit one bus message; the same read works over HTTPS.
    pub overflow: bool,
}

fn header_str(h: &Option<async_nats::HeaderMap>, k: &str) -> Option<String> {
    h.as_ref().and_then(|h| h.get(k)).map(|v| v.as_str().to_string())
}

/// Parse a node's reply (or terminal event) message.
pub fn parse_reply(headers: &Option<async_nats::HeaderMap>, payload: &[u8]) -> BusReply {
    BusReply {
        status: header_str(headers, "Noo-Status").and_then(|s| s.parse().ok()).unwrap_or(502),
        content_type: header_str(headers, "Noo-Content-Type"),
        body: payload.to_vec(),
        overflow: header_str(headers, "Noo-Overflow").as_deref() == Some("1"),
    }
}

/// Turn a bus reply into the `reqwest::Response` the HTTPS call would have
/// produced: every caller of `NodeLink::request` keeps reading `status()`,
/// `json()` and `text()` as before.
pub fn into_response(r: BusReply) -> reqwest::Response {
    let mut b = axum::http::Response::builder().status(r.status);
    if let Some(ct) = r.content_type.filter(|c| !c.is_empty()) {
        b = b.header("content-type", ct);
    }
    let resp = b.body(r.body).unwrap_or_else(|_| {
        axum::http::Response::builder().status(502).body(Vec::new()).expect("static response")
    });
    reqwest::Response::from(resp)
}

/// Why a bus call failed, as one short token for the error and the log.
fn failure_reason(kind: async_nats::client::RequestErrorKind) -> &'static str {
    use async_nats::client::RequestErrorKind as K;
    match kind {
        K::NoResponders => "no-responders",
        K::TimedOut => "timeout",
        K::MaxPayloadExceeded => "payload-too-large",
        _ => "bus-error",
    }
}

/// One control call over the bus. `Ok` carries whatever the node answered,
/// including a refusal (403) or an error status from the handler; `Err` is a
/// transport failure, with a short reason.
pub async fn call(
    t: &BusTarget,
    cop: &ControlOp,
    body: &[u8],
    timeout: Option<Duration>,
) -> Result<BusReply, String> {
    let signer = leaf_signer()?;
    call_with(t, cop, body, timeout, signer.as_ref()).await
}

pub async fn call_with(
    t: &BusTarget,
    cop: &ControlOp,
    body: &[u8],
    timeout: Option<Duration>,
    signer: &dyn EnvelopeSigner,
) -> Result<BusReply, String> {
    let total = timeout.unwrap_or(if cop.asynchronous { DEFAULT_ASYNC } else { DEFAULT_SYNC }).min(MAX_TIMEOUT);
    let op_id = if cop.asynchronous { format!("op{}", uuid::Uuid::new_v4().simple()) } else { String::new() };
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let env = build_envelope(signer, cop, &t.node, &op_id, total, body, now_unix(), &nonce)?;

    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Noo-Envelope", env.to_string());

    let subject = format!("node.{}.rpc.{}", t.node, cop.op);
    let inbox = crate::nats_credentials::scoped_inbox(&t.nats, &crate::nats_credentials::node_reply_prefix(&t.node));
    // The reply wait: a sync op may take as long as its handler; an async op
    // answers with its ack at once.
    let wait = if cop.asynchronous { ACK_TIMEOUT } else { total + Duration::from_secs(5) };

    // Subscribe to the event stream BEFORE sending, or a fast op's result
    // could be published before we listen.
    let mut events = None;
    if cop.asynchronous {
        let sub = t
            .nats
            .subscribe(format!("node.{}.evt.{op_id}", t.node))
            .await
            .map_err(|e| format!("subscribe: {e}"))?;
        t.nats.flush().await.map_err(|e| format!("flush: {e}"))?;
        events = Some(sub);
    }

    let request = async_nats::Request::new()
        .payload(body.to_vec().into())
        .headers(headers)
        .timeout(Some(wait))
        .inbox(inbox);
    let msg = t
        .nats
        .send_request(subject, request)
        .await
        .map_err(|e| failure_reason(e.kind()).to_string())?;
    let ack = parse_reply(&msg.headers, &msg.payload);

    let Some(mut sub) = events else { return Ok(ack) };
    // Not an accepted-async ack: a refusal or an immediate answer. Return it.
    if ack.status != 202 || header_str(&msg.headers, "Noo-Async").as_deref() != Some("1") {
        return Ok(ack);
    }
    let deadline = Instant::now() + total;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timeout".into());
        }
        let wait = remaining.min(EVENT_IDLE);
        match tokio::time::timeout(wait, sub.next()).await {
            Err(_) if remaining <= EVENT_IDLE => return Err("timeout".into()),
            Err(_) => return Err("no-progress".into()),
            Ok(None) => return Err("bus-error".into()),
            Ok(Some(ev)) => {
                if header_str(&ev.headers, "Noo-Event").as_deref() == Some("done") {
                    return Ok(parse_reply(&ev.headers, &ev.payload));
                }
            }
        }
    }
}

/// Should a reply that arrived be treated like a transport failure for the
/// fallback decision? A node that refused the envelope (403: clock skew, a
/// rolled signing leaf), does not know the op (404) or could not fit the
/// answer on the bus (413) is not "down": an idempotent read can still be had
/// over HTTPS.
pub fn reply_wants_fallback(r: &BusReply) -> bool {
    r.overflow || matches!(r.status, 403 | 404 | 413 | 429)
}

/// A `reqwest::Error` for a node that could not be reached over the bus.
///
/// `NodeLink::request` hands back something whose `send()` yields
/// `reqwest::Error`, and every caller already formats it as "the node agent
/// is unreachable". reqwest cannot construct an error directly, but it
/// refuses a URL whose scheme is not http(s) before any I/O, so the error is
/// made by asking for exactly that: its text names the node and the reason
/// (`noo-node-unreachable://host9/no-responders`).
pub async fn unreachable_error(node: &str, reason: &str) -> reqwest::Error {
    let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect::<String>();
    tracing::warn!(node = %node, reason = %reason, "control over the bus failed; reporting the node unreachable (no HTTPS retry for this op)");
    crate::tls::cluster_client()
        .get(format!("noo-node-unreachable://{}/{}", clean(node), clean(reason)))
        .send()
        .await
        .expect_err("a non-http scheme is always refused by reqwest")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(m: &str, p: &str) -> Option<ControlOp> {
        control_op(&Method::from_bytes(m.as_bytes()).unwrap(), p)
    }

    #[test]
    fn the_control_set_is_exactly_the_small_calls() {
        let cases: &[(&str, &str, &str, &str, bool, bool)] = &[
            // method, path, op, arg, idempotent, async
            ("GET", "/health", "health", "", true, false),
            ("GET", "/gpu", "gpu", "", true, false),
            ("GET", "/stats/containers", "stats", "", true, false),
            ("GET", "/v1/models", "models", "", true, false),
            ("POST", "/start", "start", "", false, false),
            ("POST", "/stop", "stop", "", false, false),
            ("POST", "/restart", "restart", "", false, false),
            ("POST", "/reconcile", "reconcile", "", true, false),
            ("POST", "/clean", "clean", "", false, false),
            ("POST", "/pull", "pull", "", false, true),
            ("POST", "/api/skills/run", "skills.run", "", false, true),
            ("GET", "/api/mcp/servers", "mcp.servers", "", true, false),
            ("POST", "/api/mcp/files/call", "mcp.call", "files", false, false),
            ("GET", "/logs/containers", "logs", "", true, false),
            ("GET", "/logs/noo-gateway?tail=50", "logs", "noo-gateway", true, false),
            ("POST", "/cleanup/images", "cleanup", "images", false, false),
            ("POST", "/cleanup/logs", "cleanup", "logs", false, false),
        ];
        for (m, p, name, arg, idem, asy) in cases {
            let o = op(m, p).unwrap_or_else(|| panic!("{m} {p} should be a control op"));
            assert_eq!((o.op, o.arg.as_str(), o.idempotent, o.asynchronous), (*name, *arg, *idem, *asy), "{m} {p}");
        }
        assert_eq!(op("GET", "/logs/noo-gateway?tail=50").unwrap().query, "tail=50");
    }

    #[test]
    fn streaming_bulk_and_unlisted_routes_stay_on_https() {
        for (m, p) in [
            ("POST", "/v1/chat/completions"),
            ("POST", "/v1/completions"),
            ("POST", "/v1/embeddings"),
            ("POST", "/embed"),
            ("POST", "/rerank"),
            ("GET", "/metrics"),
            ("POST", "/api/containers/start"),
            ("POST", "/api/containers/stop"),
            ("GET", "/api/containers/noo-browser/proxy/status"),
            ("POST", "/api/device/camera_capture"),
            ("POST", "/api/device/screenshot"),
            ("GET", "/tailnet/whois?ip=1.2.3.4"),
            ("POST", "/tailnet/dialback"),
            ("POST", "/gpu/hold"),
            ("GET", "/tools"),
            ("GET", "/harness/placement"),
            // wrong method for a control path
            ("GET", "/stop"),
            ("POST", "/health"),
            // an argument that could widen a subject or smuggle a path
            ("GET", "/logs/a/b"),
            ("GET", "/logs/"),
            ("POST", "/api/mcp//call"),
            ("POST", "/api/mcp/call"),
            ("GET", "/logs/.."),
            ("POST", "/api/mcp/a b/call"),
            ("POST", "/cleanup/../etc"),
        ] {
            assert_eq!(op(m, p), None, "{m} {p} must not be a control op");
        }
    }

    #[test]
    fn routing_is_the_node_the_bus_and_the_op_all_agreeing() {
        let health = op("GET", "/health");
        let stop = op("POST", "/stop");
        let streaming = op("POST", "/v1/chat/completions");
        // (node advertises nats_rpc, bus connected, op) -> route
        assert_eq!(route(true, true, health.as_ref()), Route::Bus);
        assert_eq!(route(true, true, stop.as_ref()), Route::Bus);
        // an old node, or one that has not said: HTTPS, whatever the op
        assert_eq!(route(false, true, health.as_ref()), Route::Https);
        assert_eq!(route(false, true, stop.as_ref()), Route::Https);
        // the gateway's own bus is down: HTTPS (nothing was sent, so this is routing, not a retry)
        assert_eq!(route(true, false, health.as_ref()), Route::Https);
        // not a control op: HTTPS
        assert_eq!(route(true, true, streaming.as_ref()), Route::Https);
        assert_eq!(route(true, true, None), Route::Https);
    }

    #[test]
    fn only_reads_may_fall_back_to_https_after_a_bus_failure() {
        for (m, p, want) in [
            ("GET", "/health", AfterFailure::Https),
            ("GET", "/gpu", AfterFailure::Https),
            ("GET", "/stats/containers", AfterFailure::Https),
            ("GET", "/v1/models", AfterFailure::Https),
            ("GET", "/logs/x", AfterFailure::Https),
            ("GET", "/api/mcp/servers", AfterFailure::Https),
            ("POST", "/start", AfterFailure::Unreachable),
            ("POST", "/stop", AfterFailure::Unreachable),
            ("POST", "/restart", AfterFailure::Unreachable),
            ("POST", "/clean", AfterFailure::Unreachable),
            ("POST", "/cleanup/images", AfterFailure::Unreachable),
            ("POST", "/pull", AfterFailure::Unreachable),
            ("POST", "/api/skills/run", AfterFailure::Unreachable),
            ("POST", "/api/mcp/x/call", AfterFailure::Unreachable),
        ] {
            assert_eq!(after_failure(&op(m, p).unwrap()), want, "{m} {p}");
        }
    }

    #[test]
    fn a_reply_the_bus_could_not_carry_or_the_node_would_not_take_falls_back_for_reads() {
        let r = |status, overflow| BusReply { status, content_type: None, body: vec![], overflow };
        assert!(reply_wants_fallback(&r(413, true)));
        assert!(reply_wants_fallback(&r(403, false)));
        assert!(reply_wants_fallback(&r(404, false)));
        assert!(!reply_wants_fallback(&r(200, false)));
        assert!(!reply_wants_fallback(&r(500, false)), "a handler error is the answer, not a transport failure");
        assert!(!reply_wants_fallback(&r(503, false)), "Docker not available is the answer");
    }

    #[test]
    fn a_reply_becomes_the_response_the_https_call_would_have_been() {
        let r = BusReply { status: 503, content_type: Some("application/json".into()), body: br#"{"detail":"Docker not available"}"#.to_vec(), overflow: false };
        let resp = into_response(r);
        assert_eq!(resp.status().as_u16(), 503);
        assert_eq!(resp.headers().get("content-type").unwrap(), "application/json");
    }

    /// Byte-for-byte the vector in node-agent-go/internal/ctrlrpc
    /// (TestCanonicalVectorMatchesTheGatewaySigner). If either side changes
    /// the framing, both tests fail.
    #[test]
    fn the_canonical_string_matches_the_go_verifier_vector() {
        let c = canonical(
            "mcp.call",
            "host9",
            1_800_000_000,
            "0123456789abcdef0123456789abcdef",
            "files",
            "a=1",
            "op0123456789",
            120,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(
            c,
            "noo-rpc-v1\nmcp.call\nhost9\n1800000000\n0123456789abcdef0123456789abcdef\nfiles\na=1\nop0123456789\n120\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(canonical("a\nb", "n", 1, "x", "", "", "", 0, "h").is_err());
    }

    fn test_leaf() -> LeafSigner {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["gateway".to_string()]).unwrap().self_signed(&key).unwrap();
        LeafSigner::from_pem(key.serialize_pem().as_bytes(), cert.pem().as_bytes()).unwrap()
    }

    #[test]
    fn an_envelope_binds_op_node_body_and_is_signed_with_the_leaf() {
        let signer = test_leaf();
        let cop = op("POST", "/stop").unwrap();
        let body = br#"{"backend":"vllm"}"#;
        let env = build_envelope(&signer, &cop, "host9", "", Duration::from_secs(90), body, 1_800_000_000, "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(env["v"], 1);
        assert_eq!(env["op"], "stop");
        assert_eq!(env["node"], "host9");
        assert_eq!(env["ts"], 1_800_000_000i64);
        assert_eq!(env["timeout_s"], 90);
        assert_eq!(env["alg"], "ES256");
        assert_eq!(env["body_sha256"], hex::encode(Sha256::digest(body)));
        assert!(env["nonce"].as_str().unwrap().len() >= 16, "the node refuses short nonces");
        let sig = base64::engine::general_purpose::STANDARD.decode(env["sig"].as_str().unwrap()).unwrap();
        assert_eq!(sig[0], 0x30, "an ASN.1 DER ECDSA signature, which is what the Go verifier reads");
        assert!(!env["cert"].as_str().unwrap().is_empty());
        // The same message signs to a different value (ECDSA is randomised) but both
        // verify against the canonical text; the framing is pinned by the vector test.
    }

    #[test]
    fn a_missing_leaf_key_is_a_named_error_not_a_panic() {
        assert!(LeafSigner::from_pem(b"not a key", b"not a cert").is_err());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let e = LeafSigner::from_pem(key.serialize_pem().as_bytes(), b"").err().unwrap();
        assert!(e.contains("certificate"), "{e}");
    }

    #[tokio::test]
    async fn an_unreachable_node_is_an_error_naming_the_node_and_the_reason() {
        let e = unreachable_error("host9", "no-responders").await;
        let text = e.to_string();
        assert!(text.contains("host9") && text.contains("no-responders"), "{text}");
        assert!(e.is_builder(), "no I/O happened and none is retried: {text}");
    }

    #[test]
    fn counters_separate_bus_control_https_and_other_https_per_node() {
        note_bus("cnt-node");
        note_bus("cnt-node");
        note_https("cnt-node", true);
        note_https("cnt-node", false);
        note_fallback("cnt-node");
        let c = counts().get("cnt-node").copied().unwrap();
        assert_eq!(c, ControlCounts { bus: 2, https_control: 1, https_other: 1, fallbacks: 1, tunnel: 0, tunnel_aborts: 0 });
        note_tunnel("cnt-node");
        note_tunnel_abort("cnt-node");
        let c = counts().get("cnt-node").copied().unwrap();
        assert_eq!((c.tunnel, c.tunnel_aborts), (1, 1));
        assert_eq!(
            counts_json("never-called"),
            json!({"bus": 0, "https_control": 0, "https_other": 0, "fallbacks": 0, "tunnel": 0, "tunnel_aborts": 0, "tunnel_live": false})
        );
    }
}
