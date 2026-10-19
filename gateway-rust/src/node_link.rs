// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The one door from the controller to a node agent.
//!
//! Every gateway -> node-agent call is built here: the address of the agent,
//! the client, and the credential (`node_agent_auth`) are decided in this
//! module and nowhere else. A call site names a node (or an address it
//! already holds), a method and a path, and gets a `reqwest::RequestBuilder`
//! back to which it adds its own body, headers and timeout.
//!
//! Why a seam: the control plane is still inbound (the controller dials the
//! agent), which i131 wants to replace with node-initiated transports: NATS
//! request/reply for control calls and a node-held tunnel for streaming and
//! bulk traffic. Those phases swap what `request` / `stream` do inside this
//! module; no call site changes again.
//!
//! Two transports. HTTPS to the agent's mTLS listener on [`AGENT_PORT`],
//! through the shared cluster client, with the bearer decision
//! `node_agent_auth` already makes, is the original and still the default.
//! A node that advertises `control_transports.nats_rpc` also answers small
//! control calls over NATS request/reply on a connection it holds outbound
//! (i131 phase 1, [`crate::node_rpc`]): [`NodeLink::request`] sends those
//! over the bus and everything else (streaming, bulk, an old node, a link
//! resolved by address rather than by node id) over HTTPS unchanged.
//!
//! - [`NodeLink::request`]: a unary call (the body is read once, whole). It
//!   returns a [`NodeRequest`], which has the builder methods callers use
//!   (`json`, `timeout`, `header`, `body`) and a `send()` that picks the
//!   transport.
//! - [`NodeLink::stream`]: a call whose response body is read incrementally
//!   (SSE inference, log tails, the container proxy). Identical today; kept
//!   separate so a later phase can give streams an idle timeout instead of a
//!   total one.
//! - [`NodeLink::url`]: for the few callers that must hand an address to
//!   something else (a backend URL kept in coordinator state).
//! - [`is_agent_url`]: the one definition of "this URL is a node agent".

use reqwest::Method;
use serde_json::{json, Value};

use crate::routes::AppError;
use crate::state::AppState;

/// The node agent's mTLS listener. The only place the number lives in
/// gateway code.
pub const AGENT_PORT: u16 = 8081;

/// Heartbeat / node-record field naming the control transports an agent
/// offers. Absent = an older agent = the HTTPS listener only.
pub(crate) const TRANSPORTS_FIELD: &str = "control_transports";

/// What the gateway records for an agent that has not said (an old one).
pub(crate) fn default_transports() -> Value {
    json!({"https_listener": true, "nats_rpc": false, "tunnel": false})
}

/// The transports a heartbeat / registration body reports, normalised to the
/// three known booleans. A missing field, or one that is not an object, is an
/// older agent: HTTPS listener only. A key the body omits reads as the value
/// an old agent would have (listener on, the rest off).
pub(crate) fn reported_transports(body: &Value) -> Value {
    let Some(obj) = body.get(TRANSPORTS_FIELD).and_then(Value::as_object) else {
        return default_transports();
    };
    let flag = |k: &str, default: bool| obj.get(k).and_then(Value::as_bool).unwrap_or(default);
    json!({
        "https_listener": flag("https_listener", true),
        "nats_rpc": flag("nats_rpc", false),
        "tunnel": flag("tunnel", false),
    })
}

/// Is `url` the node-agent proxy? The same test `coordinator::backend` made
/// inline (`contains(":8081")`), now in one place.
pub fn is_agent_url(url: &str) -> bool {
    url.contains(&format!(":{AGENT_PORT}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Auth {
    /// A node's agent: `node_agent_auth::header_for`.
    Node,
    /// The controller's own agent: `node_agent_auth::header_for_self`.
    SelfAgent,
}

/// A node agent the gateway can call.
#[derive(Clone, Debug)]
pub struct NodeLink {
    base: String,
    node_id: Option<String>,
    auth: Auth,
    /// The node's record says it answers control calls on the bus.
    nats_rpc: bool,
    /// The gateway's bus, when this link was resolved with state.
    bus: Option<async_nats::Client>,
}

impl NodeLink {
    /// The agent of a node in the `mesh_nodes` KV: its `agent_url`, else
    /// `https://{ip_address}:AGENT_PORT`. `NotFound` when the node has
    /// neither (or is not in the KV).
    pub async fn for_node(state: &AppState, node_id: &str) -> Result<Self, AppError> {
        let mut record = None;
        if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
            if let Ok(Some(entry)) = kv.get(node_id).await {
                record = serde_json::from_slice::<Value>(&entry).ok();
            }
        }
        let mut link = Self::from_record(node_id, record.as_ref())?;
        link.bus = Some(state.nats.clone());
        Ok(link)
    }

    /// [`NodeLink::for_node`] over an already-read record.
    pub(crate) fn from_record(node_id: &str, record: Option<&Value>) -> Result<Self, AppError> {
        if let Some(data) = record {
            if let Some(url) = data.get("agent_url").and_then(|v| v.as_str()) {
                if !url.is_empty() {
                    return Ok(Self::with_node(url.to_string(), node_id).advertising(data));
                }
            }
            if let Some(ip) = data.get("ip_address").and_then(|v| v.as_str()) {
                if !ip.is_empty() {
                    return Ok(Self::with_node(format!("https://{ip}:{AGENT_PORT}"), node_id).advertising(data));
                }
            }
            // Registered, but with nowhere to send the call: say so, rather
            // than "not found".
            return Err(AppError::NotFound(no_address_message(node_id)));
        }
        Err(AppError::NotFound(format!("Node '{node_id}' not found in mesh_nodes")))
    }

    fn with_node(base: String, node_id: &str) -> Self {
        Self { base, node_id: Some(node_id.to_string()), auth: Auth::Node, nats_rpc: false, bus: None }
    }

    /// Read what the node says it offers from its record. `nats_rpc` needs a
    /// node id that is ONE subject token: the grant and the agent's
    /// subscription name the raw id, and an id with a dot would name a
    /// subject nobody listens on.
    fn advertising(mut self, record: &Value) -> Self {
        let says = record
            .get(TRANSPORTS_FIELD)
            .and_then(|t| t.get("nats_rpc"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let one_token = self
            .node_id
            .as_deref()
            .is_some_and(|id| crate::nats_credentials::subject_token(id) == id);
        self.nats_rpc = says && one_token;
        self
    }

    /// The agent on `ip` (`https://{ip}:AGENT_PORT`), for paths that already
    /// hold the address (inference discovery, the coordinator).
    pub fn for_ip(ip: &str) -> Self {
        Self { base: format!("https://{ip}:{AGENT_PORT}"), node_id: None, auth: Auth::Node, nats_rpc: false, bus: None }
    }

    /// The agent at an address the caller already holds (a record's
    /// `agent_url`, a backend URL).
    pub fn for_base(url: &str) -> Self {
        Self { base: url.to_string(), node_id: None, auth: Auth::Node, nats_rpc: false, bus: None }
    }

    /// The controller's own agent: `NOO_SELF_AGENT_URL`, else derived from
    /// the controller URL. `Err` carries the operator guidance a localhost
    /// controller URL needs.
    pub fn self_agent() -> Result<Self, String> {
        Ok(Self::self_agent_at(crate::routes::self_agent_base()?))
    }

    /// The controller's own agent at a known address.
    pub(crate) fn self_agent_at(base: String) -> Self {
        Self { base, node_id: None, auth: Auth::SelfAgent, nats_rpc: false, bus: None }
    }

    /// The agent's base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The node this link was resolved for, when it was resolved by id. The
    /// bus addresses a node by id (`node.{id}.rpc.*`); a link built from an
    /// address alone has none and always uses HTTPS.
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }

    /// `base` + `path` (`path` starts with `/` and may carry a query).
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), path)
    }

    /// The credential this link presents for `url`, if any.
    fn credential(&self, url: &str) -> Option<(String, String)> {
        match self.auth {
            Auth::Node => crate::node_agent_auth::header_for(url),
            Auth::SelfAgent => crate::node_agent_auth::header_for_self(url),
        }
    }

    /// The credential headers for a call this link hands to another
    /// consumer together with [`NodeLink::url`] (a `MeshTarget`): empty for
    /// an agent that admits the controller's leaf alone.
    pub fn auth_headers(&self) -> Vec<(String, String)> {
        self.credential(&self.base).map(|kv| vec![kv]).unwrap_or_default()
    }

    /// A unary call. Over HTTPS: the shared cluster client plus exactly the
    /// credential `node_agent_auth` decides for this agent. Over the bus: a
    /// signed control message, when the node advertises `nats_rpc`, the bus
    /// is connected and the call is a control op ([`crate::node_rpc::route`]).
    /// The caller adds body, headers and timeout, then `.send()`s.
    pub fn request(&self, method: Method, path: &str) -> NodeRequest {
        let cop = crate::node_rpc::control_op(&method, path);
        let target = match (&self.bus, &self.node_id) {
            (Some(nats), Some(node)) => {
                let connected = crate::node_rpc::enabled()
                    && nats.connection_state() == async_nats::connection::State::Connected;
                (crate::node_rpc::route(self.nats_rpc, connected, cop.as_ref()) == crate::node_rpc::Route::Bus)
                    .then(|| crate::node_rpc::BusTarget { nats: nats.clone(), node: node.clone() })
            }
            _ => None,
        };
        let count_key = self.node_id.clone().unwrap_or_else(|| {
            self.base.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string()
        });
        NodeRequest {
            http: self.build(method, path),
            bus: target.zip(cop.clone()),
            is_control: cop.is_some(),
            body: Some(Vec::new()),
            timeout: None,
            count_key,
        }
    }

    /// One `health` round trip over the bus, never falling back to HTTPS: the
    /// answer to "does control over the bus work for this node". `checked` is
    /// false (and `ok` false) when it could not be tried: the node does not
    /// advertise `nats_rpc`, or the gateway's own bus is down.
    pub async fn probe_bus(&self) -> Value {
        let node = self.node_id.clone().unwrap_or_default();
        if !self.nats_rpc {
            return json!({"advertised": false, "checked": false, "ok": false,
                "detail": "the node does not advertise control_transports.nats_rpc"});
        }
        let Some(nats) = self.bus.as_ref().filter(|n| n.connection_state() == async_nats::connection::State::Connected) else {
            return json!({"advertised": true, "checked": false, "ok": false,
                "detail": "the gateway's own bus connection is down"});
        };
        let Some(cop) = crate::node_rpc::control_op(&Method::GET, "/health") else {
            return json!({"advertised": true, "checked": false, "ok": false, "detail": "no health op"});
        };
        let target = crate::node_rpc::BusTarget { nats: nats.clone(), node };
        let started = std::time::Instant::now();
        match crate::node_rpc::call(&target, &cop, &[], Some(std::time::Duration::from_secs(10))).await {
            Ok(r) if r.status == 200 => json!({"advertised": true, "checked": true, "ok": true,
                "rtt_ms": started.elapsed().as_millis() as u64, "detail": "health answered over NATS"}),
            Ok(r) => json!({"advertised": true, "checked": true, "ok": false,
                "detail": format!("the node answered {} over the bus: {}", r.status,
                    String::from_utf8_lossy(&r.body).chars().take(200).collect::<String>())}),
            Err(e) => json!({"advertised": true, "checked": true, "ok": false,
                "detail": format!("no answer over the bus ({e}) although the node advertises nats_rpc")}),
        }
    }

    /// A call whose response body is read incrementally. Same client, same
    /// credential, same (total) timeout as [`NodeLink::request`] today. No
    /// call site holds a node link and streams yet (the SSE paths hold a
    /// backend URL and use [`backend_stream`]); this is the entry for the
    /// ones that will.
    #[allow(dead_code)]
    pub fn stream(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.build(method, path)
    }

    /// [`NodeLink::request`] on a caller-chosen client: for a caller that
    /// already holds the client it must use (the harness's, a test double).
    pub fn request_on(&self, client: &reqwest::Client, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.build_on(client, method, path)
    }

    fn build(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.build_on(&crate::tls::cluster_client(), method, path)
    }

    fn build_on(&self, client: &reqwest::Client, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = self.url(path);
        let mut req = client.request(method, &url);
        if let Some((k, v)) = self.credential(&url) {
            req = req.header(k, v);
        }
        req
    }
}

/// A unary call to a node agent, not yet sent. It has the builder methods
/// the call sites use; `send()` takes the bus or HTTPS.
///
/// The failure policy lives here (and is the one the i131 design states): a
/// bus failure on an op that is not idempotent is reported as the node being
/// unreachable and is NEVER retried over HTTPS (the node may have run it); a
/// read may fall back to HTTPS once, logged and counted.
pub struct NodeRequest {
    http: reqwest::RequestBuilder,
    /// Set when this call goes over the bus.
    bus: Option<(crate::node_rpc::BusTarget, crate::node_rpc::ControlOp)>,
    /// The call is in the control set (whatever transport it takes).
    is_control: bool,
    /// The body as bytes, for the bus. `None` once a body was set that cannot
    /// be read back (a stream): that call is sent over HTTPS.
    body: Option<Vec<u8>>,
    timeout: Option<std::time::Duration>,
    count_key: String,
}

impl NodeRequest {
    /// A JSON body, as `reqwest::RequestBuilder::json`.
    pub fn json<T: serde::Serialize + ?Sized>(mut self, value: &T) -> Self {
        self.body = serde_json::to_vec(value).ok();
        self.http = self.http.json(value);
        self
    }

    /// A raw body, as `reqwest::RequestBuilder::body`.
    pub fn body<B: Into<reqwest::Body>>(mut self, body: B) -> Self {
        let b: reqwest::Body = body.into();
        self.body = b.as_bytes().map(<[u8]>::to_vec);
        self.http = self.http.body(b);
        self
    }

    /// A total timeout, as `reqwest::RequestBuilder::timeout`.
    pub fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout = Some(d);
        self.http = self.http.timeout(d);
        self
    }

    /// An HTTP header. Headers are not carried over the bus (the envelope is
    /// the credential there); control ops need none.
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<axum::http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<axum::http::Error>,
    {
        self.http = self.http.header(key, value);
        self
    }

    /// Is this call going over the bus?
    #[allow(dead_code)]
    pub fn is_bus(&self) -> bool {
        self.bus.is_some() && self.body.is_some()
    }

    /// The HTTPS request, for a test or a caller that must hold the builder.
    pub fn into_http(self) -> reqwest::RequestBuilder {
        self.http
    }

    /// Send it.
    pub async fn send(self) -> Result<reqwest::Response, reqwest::Error> {
        let Self { http, bus, is_control, body, timeout, count_key } = self;
        let (Some((target, cop)), Some(body)) = (bus, body) else {
            crate::node_rpc::note_https(&count_key, is_control);
            return http.send().await;
        };
        match crate::node_rpc::call(&target, &cop, &body, timeout).await {
            Ok(reply) if !(cop.idempotent && crate::node_rpc::reply_wants_fallback(&reply)) => {
                crate::node_rpc::note_bus(&count_key);
                Ok(crate::node_rpc::into_response(reply))
            }
            outcome => {
                let why = match &outcome {
                    Ok(r) => format!("node answered {} over the bus", r.status),
                    Err(e) => e.clone(),
                };
                match crate::node_rpc::after_failure(&cop) {
                    crate::node_rpc::AfterFailure::Https => {
                        tracing::warn!(
                            node = %target.node, op = cop.op, reason = %why,
                            "control over the bus failed; reading over HTTPS once"
                        );
                        crate::node_rpc::note_fallback(&count_key);
                        crate::node_rpc::note_https(&count_key, true);
                        http.send().await
                    }
                    crate::node_rpc::AfterFailure::Unreachable => match outcome {
                        // The node answered (a refusal, a handler error): that
                        // IS the answer for a call that must not be repeated.
                        Ok(reply) => {
                            crate::node_rpc::note_bus(&count_key);
                            Ok(crate::node_rpc::into_response(reply))
                        }
                        Err(reason) => Err(crate::node_rpc::unreachable_error(&target.node, &reason).await),
                    },
                }
            }
        }
    }
}

/// A unary call to a backend URL the caller already holds. The URL may be a
/// node agent (`https://<ip>:AGENT_PORT`, which gets the `X-Noo-Backend` hint
/// and the agent credential) or a controller-local backend reached directly
/// (which gets neither): `coordinator::with_backend_hint_url` decides, and it
/// decides through [`is_agent_url`] / [`NodeLink::auth_headers`]. Uses the
/// shared cluster client; `backend_type` empty = no hint.
pub fn backend_request(method: Method, url: &str, backend_type: &str) -> reqwest::RequestBuilder {
    backend_request_on(&crate::tls::cluster_client(), method, url, backend_type)
}

/// [`backend_request`] on a caller-chosen client (the failover client, a
/// test double, a harness's pinned client).
pub fn backend_request_on(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    backend_type: &str,
) -> reqwest::RequestBuilder {
    crate::coordinator::with_backend_hint_url(client.request(method, url), url, backend_type)
}

/// [`backend_request`] for a response read incrementally (SSE).
pub fn backend_stream(method: Method, url: &str, backend_type: &str) -> reqwest::RequestBuilder {
    backend_stream_on(&crate::tls::cluster_client(), method, url, backend_type)
}

/// [`backend_stream`] on a caller-chosen client. Identical to
/// [`backend_request_on`] today; the seam for a stream-specific timeout.
pub fn backend_stream_on(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    backend_type: &str,
) -> reqwest::RequestBuilder {
    crate::coordinator::with_backend_hint_url(client.request(method, url), url, backend_type)
}

/// The node is in `mesh_nodes` but registered without `agent_url` or
/// `ip_address`, so the gateway has nowhere to send the call.
pub(crate) fn no_address_message(node_id: &str) -> String {
    format!(
        "Node '{node_id}' is registered but has no reachable address (no agent_url or ip_address in mesh_nodes). \
         Set NODE_IP in the node's agent env and restart the agent, or re-register the node (`noo cluster provision {node_id}`)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::node_agent_auth::TEST_SERIAL as SERIAL;

    #[test]
    fn agent_url_wins_then_the_ip_falls_back_and_a_missing_node_is_not_found() {
        let l = NodeLink::from_record(
            "n1",
            Some(&json!({"agent_url": "https://n1.tail:9000", "ip_address": "10.0.0.1"})),
        )
        .unwrap();
        assert_eq!(l.base(), "https://n1.tail:9000");
        assert_eq!(l.node_id(), Some("n1"));

        let l = NodeLink::from_record("n2", Some(&json!({"agent_url": "", "ip_address": "10.0.0.2"}))).unwrap();
        assert_eq!(l.base(), "https://10.0.0.2:8081");
        let l = NodeLink::from_record("n3", Some(&json!({"ip_address": "10.0.0.3"}))).unwrap();
        assert_eq!(l.url("/gpu"), "https://10.0.0.3:8081/gpu");

        for rec in [None, Some(json!({})), Some(json!({"agent_url": "", "ip_address": ""}))] {
            match NodeLink::from_record("ghost", rec.as_ref()) {
                Err(AppError::NotFound(m)) => assert!(m.contains("ghost")),
                other => panic!("expected NotFound, got {other:?}"),
            }
        }
    }

    #[test]
    fn url_joins_without_doubling_the_slash() {
        assert_eq!(NodeLink::for_ip("10.0.0.5").url("/health"), "https://10.0.0.5:8081/health");
        assert_eq!(NodeLink::for_base("https://h:8081/").url("/x?a=1"), "https://h:8081/x?a=1");
        assert_eq!(NodeLink::for_base("https://h:8081").url(""), "https://h:8081");
    }

    #[test]
    fn is_agent_url_truth_table() {
        assert!(is_agent_url("https://10.0.0.1:8081"));
        assert!(is_agent_url("https://10.0.0.1:8081/v1/chat/completions"));
        assert!(is_agent_url("http://host8:8081/v1"));
        assert!(!is_agent_url("http://noo-vllm:8000"));
        assert!(!is_agent_url("https://10.0.0.1:8082"));
        assert!(!is_agent_url("https://10.0.0.1"));
        assert!(!is_agent_url(""));
    }

    fn auth_of(rb: reqwest::RequestBuilder) -> Option<String> {
        let req = rb.build().unwrap();
        req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string)
    }

    #[test]
    fn request_applies_the_node_agent_auth_decision() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        crate::node_agent_auth::clear_for_test();
        std::env::set_var("NOO_NODE_AGENT_TOKEN", "static-test-token");
        crate::node_agent_auth::note(
            "leaf",
            &json!({"ip_address": "10.0.0.2", crate::node_agent_auth::CAPABILITY: true}),
        );
        crate::node_agent_auth::note("old", &json!({"ip_address": "10.0.0.3"}));

        let leaf = NodeLink::for_ip("10.0.0.2");
        let old = NodeLink::for_ip("10.0.0.3");
        assert_eq!(auth_of(leaf.request(Method::GET, "/gpu").into_http()), None, "leaf-only agent: no bearer");
        assert_eq!(auth_of(leaf.stream(Method::POST, "/v1/chat/completions")), None);
        assert_eq!(
            auth_of(old.request(Method::GET, "/gpu").into_http()).as_deref(),
            Some("Bearer static-test-token"),
            "an agent that has not said keeps the bearer"
        );
        // Same decision as calling node_agent_auth directly.
        assert_eq!(
            crate::node_agent_auth::header_for("https://10.0.0.3:8081/gpu").map(|(_, v)| v),
            auth_of(old.request(Method::GET, "/gpu").into_http())
        );
        let built = old.request(Method::DELETE, "/containers/x").into_http().build().unwrap();
        assert_eq!(built.method(), Method::DELETE);
        assert_eq!(built.url().as_str(), "https://10.0.0.3:8081/containers/x");
    }

    #[test]
    fn the_self_agent_uses_the_self_variant() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        crate::node_agent_auth::clear_for_test();
        std::env::set_var("NOO_NODE_AGENT_TOKEN", "static-test-token");
        let me = NodeLink::self_agent_at("https://controller.tail:8081".into());
        assert!(auth_of(me.request(Method::GET, "/tailnet/whois?ip=100.64.0.9").into_http()).is_some());
        crate::node_agent_auth::note(
            "host8",
            &json!({"ip_address": "100.64.0.1", "self_node": true, crate::node_agent_auth::CAPABILITY: true}),
        );
        assert_eq!(auth_of(me.request(Method::GET, "/tailnet/whois?ip=100.64.0.9").into_http()), None);
    }

    #[test]
    fn transports_default_to_the_listener_only_for_an_agent_that_has_not_said() {
        let old = json!({"status": "ok"});
        assert_eq!(reported_transports(&old), json!({"https_listener": true, "nats_rpc": false, "tunnel": false}));
        assert_eq!(reported_transports(&json!({TRANSPORTS_FIELD: "x"})), default_transports());
        let new = json!({TRANSPORTS_FIELD: {"https_listener": false, "nats_rpc": true, "tunnel": true, "extra": 1}});
        assert_eq!(
            reported_transports(&new),
            json!({"https_listener": false, "nats_rpc": true, "tunnel": true})
        );
    }

    #[test]
    fn a_record_advertising_nats_rpc_makes_a_bus_capable_link_only_for_a_one_token_id() {
        let says = |v: Value| json!({"ip_address": "10.0.0.9", TRANSPORTS_FIELD: v});
        let l = NodeLink::from_record("host9", Some(&says(json!({"nats_rpc": true})))).unwrap();
        assert!(l.nats_rpc);
        for rec in [
            says(json!({"nats_rpc": false})),
            says(json!({"https_listener": true})),
            says(json!({"nats_rpc": "true"})),
            says(json!("x")),
            json!({"ip_address": "10.0.0.9"}),
        ] {
            assert!(!NodeLink::from_record("host9", Some(&rec)).unwrap().nats_rpc, "{rec}");
        }
        // A dot would name a subject nobody listens on.
        assert!(!NodeLink::from_record("pop.os", Some(&says(json!({"nats_rpc": true})))).unwrap().nats_rpc);
    }

    #[test]
    fn a_link_with_no_bus_or_no_node_id_always_uses_https() {
        // from_record carries no client; a link resolved by address has no id.
        let by_id = NodeLink::from_record("host9", Some(&json!({"ip_address": "10.0.0.9", TRANSPORTS_FIELD: {"nats_rpc": true}}))).unwrap();
        assert!(!by_id.request(Method::GET, "/health").is_bus());
        assert!(!NodeLink::for_ip("10.0.0.9").request(Method::GET, "/health").is_bus());
        assert!(!NodeLink::for_base("https://h:8081").request(Method::POST, "/stop").is_bus());
        assert!(!NodeLink::self_agent_at("https://c:8081".into()).request(Method::GET, "/health").is_bus());
    }

    #[test]
    fn a_request_keeps_its_https_shape_when_it_takes_the_bus_path_off() {
        let l = NodeLink::for_ip("10.0.0.5");
        let built = l
            .request(Method::POST, "/pull")
            .json(&json!({"kind": "image"}))
            .timeout(std::time::Duration::from_secs(2700))
            .into_http()
            .build()
            .unwrap();
        assert_eq!(built.url().as_str(), "https://10.0.0.5:8081/pull");
        assert_eq!(built.timeout(), Some(&std::time::Duration::from_secs(2700)));
    }
}
