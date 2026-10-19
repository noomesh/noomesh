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
//! A node that advertises `control_transports.tunnel` also holds an outbound
//! WebSocket tunnel to the gateway (i131 phase 2, [`crate::tunnel`]). Streaming
//! and bulk calls (inference SSE, the container proxy, logs bodies, device
//! blobs) and any other call the bus does not take go down it while it is up;
//! with no live tunnel, an old node, or `NOO_NODE_TUNNEL=0` they go over HTTPS
//! exactly as before. Nothing about a call site changes: the signatures below
//! are the same, only how the request is carried differs.
//!
//! - [`NodeLink::request`]: a unary call (the body is read once, whole). It
//!   returns a [`NodeRequest`], which has the builder methods callers use
//!   (`json`, `timeout`, `header`, `body`) and a `send()` that picks the
//!   transport.
//! - [`NodeLink::stream`]: a call whose response body is read incrementally
//!   (SSE inference, log tails, the container proxy). Goes out on
//!   [`crate::tls::cluster_stream_client`]: no total timeout, an idle bound
//!   (`NOO_BACKEND_STREAM_IDLE_SECS`) between reads instead. A slow model
//!   that keeps sending is never cut; a silent one is, and the reader says
//!   so with [`stream_cut_message`].
//! - [`NodeLink::url`]: for the few callers that must hand an address to
//!   something else (a backend URL kept in coordinator state).
//! - [`is_agent_url`]: the one definition of "this URL is a node agent".
//!
//! openapi-drift: not-gateway-routes — this module only DIALS node agents and
//! model endpoints; it mounts nothing on the gateway's listener, and its
//! `.route(...)` calls are test servers standing in for a model endpoint.

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
    /// The node's record says it holds a tunnel to this gateway.
    tunnel: bool,
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
        Self { base, node_id: Some(node_id.to_string()), auth: Auth::Node, nats_rpc: false, bus: None, tunnel: false }
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
        self.tunnel = record
            .get(TRANSPORTS_FIELD)
            .and_then(|t| t.get("tunnel"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && self.node_id.is_some();
        self
    }

    /// The agent on `ip` (`https://{ip}:AGENT_PORT`), for paths that already
    /// hold the address (inference discovery, the coordinator).
    pub fn for_ip(ip: &str) -> Self {
        Self { base: format!("https://{ip}:{AGENT_PORT}"), node_id: None, auth: Auth::Node, nats_rpc: false, bus: None, tunnel: false }
    }

    /// The agent at an address the caller already holds (a record's
    /// `agent_url`, a backend URL).
    pub fn for_base(url: &str) -> Self {
        Self { base: url.to_string(), node_id: None, auth: Auth::Node, nats_rpc: false, bus: None, tunnel: false }
    }

    /// The controller's own agent: `NOO_SELF_AGENT_URL`, else derived from
    /// the controller URL. `Err` carries the operator guidance a localhost
    /// controller URL needs.
    pub fn self_agent() -> Result<Self, String> {
        Ok(Self::self_agent_at(crate::routes::self_agent_base()?))
    }

    /// The controller's own agent at a known address.
    pub(crate) fn self_agent_at(base: String) -> Self {
        Self { base, node_id: None, auth: Auth::SelfAgent, nats_rpc: false, bus: None, tunnel: false }
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

    /// The node whose tunnel this link may use, if any: a link resolved by node
    /// id uses it when the record advertises one; a link that only holds an
    /// address (`for_base`, `for_ip`: most call sites) finds the node by the
    /// `host:port` its tunnel registered, and only while that tunnel is live.
    /// Never the controller's own agent. `None` when tunnels are switched off.
    fn tunnel_node(&self) -> Option<String> {
        if !crate::tunnel::enabled() {
            return None;
        }
        match (&self.node_id, self.auth) {
            (Some(id), Auth::Node) if self.tunnel => Some(id.clone()),
            (None, Auth::Node) => crate::tunnel::node_for_base(&self.base),
            _ => None,
        }
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
        // The tunnel is chosen at send time (a tunnel can drop between here and
        // there); here we only record which node's tunnel to look for.
        let tunnel = self.tunnel_node();
        NodeRequest {
            http: self.build(method.clone(), path),
            bus: target.zip(cop.clone()),
            is_control: cop.is_some(),
            body: Some(Vec::new()),
            timeout: None,
            count_key,
            tunnel,
            method,
            path: path.to_string(),
            headers: Vec::new(),
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

    /// One stream round trip over the node's tunnel, never falling back to
    /// HTTPS: the answer to "does streaming over the tunnel work for this
    /// node". `checked` is false (and `ok` false) when it could not be tried:
    /// the node does not advertise `control_transports.tunnel`, or tunnels are
    /// switched off on this gateway.
    pub async fn probe_tunnel(&self) -> Value {
        let node = self.node_id.clone().unwrap_or_default();
        if !self.tunnel {
            return json!({"advertised": false, "checked": false, "ok": false,
                "detail": "the node does not advertise control_transports.tunnel"});
        }
        if !crate::tunnel::enabled() {
            return json!({"advertised": true, "checked": false, "ok": false,
                "detail": "node tunnels are switched off on this gateway (NOO_NODE_TUNNEL)"});
        }
        let Some(sess) = crate::tunnel::hub().live(&node) else {
            return json!({"advertised": true, "checked": true, "ok": false,
                "detail": "the node advertises a tunnel but this gateway holds no live tunnel for it (it reconnects within seconds after a gateway restart)"});
        };
        let started = std::time::Instant::now();
        let req = crate::tunnel::TunnelRequest {
            method: "GET".into(),
            path: "/health".into(),
            headers: Vec::new(),
            body: crate::tunnel::TunnelBody::Bytes(Vec::new()),
        };
        let outcome = async {
            let resp = sess.request(req, Some(std::time::Duration::from_secs(10))).await?;
            let status = resp.status;
            let mut body = resp.body;
            let mut n = 0usize;
            use futures::StreamExt;
            while let Some(chunk) = body.next().await {
                n += chunk?.len();
            }
            Ok::<_, crate::tunnel::TunnelError>((status, n))
        }
        .await;
        match outcome {
            Ok((200, n)) if n > 0 => json!({"advertised": true, "checked": true, "ok": true,
                "rtt_ms": started.elapsed().as_millis() as u64, "detail": "health answered over the tunnel"}),
            Ok((status, _)) => json!({"advertised": true, "checked": true, "ok": false,
                "detail": format!("the node answered {status} over the tunnel")}),
            Err(e) => json!({"advertised": true, "checked": true, "ok": false,
                "detail": format!("no answer over the tunnel ({e}) although the node advertises it")}),
        }
    }

    /// A call whose response body is read incrementally: the same
    /// credential as [`NodeLink::request`], on the stream client (no total
    /// timeout, an idle bound between reads). No call site holds a node link
    /// and streams yet (the SSE paths hold a
    /// backend URL and use [`backend_stream`]); this is the entry for the
    /// ones that will.
    ///
    /// When the node advertises a tunnel and one is live, the request is
    /// carried by it (through the loopback door, [`crate::tunnel_door`]): the
    /// returned builder is the same type, aimed at the door; the answer is
    /// read the same way. With no live tunnel it is the HTTPS request.
    #[allow(dead_code)]
    pub fn stream(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        if let Some(node) = self.tunnel_node() {
            if let Some(door) = crate::tunnel_door::door_url(&node, path) {
                let req = crate::tls::cluster_stream_client().request(method, door.as_str());
                return crate::tunnel_door::mark(req, &door);
            }
        }
        self.build_on(&crate::tls::cluster_stream_client(), method, path)
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
    /// The node, when it advertises a tunnel and tunnels are enabled.
    tunnel: Option<String>,
    method: Method,
    path: String,
    /// Headers set with [`NodeRequest::header`], for the tunnel (the bus
    /// carries none).
    headers: Vec<(String, String)>,
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
        if let (Ok(name), Ok(val)) =
            (reqwest::header::HeaderName::try_from(key), reqwest::header::HeaderValue::try_from(value))
        {
            self.headers.push((name.as_str().to_string(), String::from_utf8_lossy(val.as_bytes()).into_owned()));
            self.http = self.http.header(name, val);
        } else {
            // As before: an invalid header is an error when the call is sent,
            // not a silent omission.
            self.http = self.http.header("invalid header", "x");
        }
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
        let Self { http, bus, is_control, body, timeout, count_key, tunnel, method, path, headers } = self;
        // Not for the bus: the node's tunnel, when it has one live; HTTPS
        // otherwise. A call whose body cannot be read back (a stream) stays
        // on HTTPS, as it does for the bus.
        if bus.is_none() || body.is_none() {
            if let (Some(node), Some(bytes)) = (tunnel.as_deref(), body.as_ref()) {
                if let Some(sess) = crate::tunnel::hub().live(node) {
                    let treq = crate::tunnel::TunnelRequest {
                        method: method.as_str().to_string(),
                        path,
                        headers,
                        body: crate::tunnel::TunnelBody::Bytes(bytes.clone()),
                    };
                    match sess.request(treq, timeout).await {
                        Ok(resp) => return Ok(crate::tunnel::into_reqwest(resp)),
                        // The per-node cap is the answer, not a reason to find
                        // another door: that would defeat the cap.
                        Err(e @ crate::tunnel::TunnelError::Busy { .. }) => {
                            return Ok(crate::tunnel::busy_response(&e));
                        }
                        // Nothing reached the node (the tunnel closed between
                        // the check and the send): HTTPS is a first attempt.
                        Err(e) if e.nothing_sent() => {}
                        // The node may have started the work. A read may be
                        // repeated over HTTPS once; anything else is reported
                        // as the node being unreachable and never retried.
                        Err(e) => {
                            crate::node_rpc::note_tunnel_abort(&count_key);
                            if matches!(method, Method::GET | Method::HEAD) {
                                tracing::warn!(node = %node, error = %e, "call over the tunnel failed; reading over HTTPS once");
                                crate::node_rpc::note_fallback(&count_key);
                            } else {
                                return Err(crate::node_rpc::unreachable_error(node, "tunnel-lost").await);
                            }
                        }
                    }
                }
            }
            crate::node_rpc::note_https(&count_key, is_control);
            return http.send().await;
        }
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

/// [`backend_request`] for a response read incrementally (SSE), on
/// [`crate::tls::cluster_stream_client`]: no total timeout, the stream idle
/// bound between reads. Do not add a per-request `.timeout()` to what this
/// returns unless a total bound is really meant: it would cut a slow
/// model's stream at that bound again.
pub fn backend_stream(method: Method, url: &str, backend_type: &str) -> reqwest::RequestBuilder {
    backend_stream_on(&crate::tls::cluster_stream_client(), method, url, backend_type)
}

/// [`backend_stream`] on a caller-chosen client (the harness translator's
/// stream client, the failover lane, a test double). The caller picks a
/// client without a total timeout for a stream.
pub fn backend_stream_on(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    backend_type: &str,
) -> reqwest::RequestBuilder {
    // A node that holds a live tunnel carries the stream down it (through the
    // loopback door); anything else is the HTTPS request, counted. The hint
    // and credential are decided on the ORIGINAL url, as always.
    let target = crate::tunnel_door::carry(url);
    let req = crate::tunnel_door::mark(client.request(method, target.as_str()), &target);
    crate::coordinator::with_backend_hint_url(req, url, backend_type)
}

/// The node is in `mesh_nodes` but registered without `agent_url` or
/// `ip_address`, so the gateway has nowhere to send the call.
pub(crate) fn no_address_message(node_id: &str) -> String {
    format!(
        "Node '{node_id}' is registered but has no reachable address (no agent_url or ip_address in mesh_nodes). \
         Set NODE_IP in the node's agent env and restart the agent, or re-register the node (`noo cluster provision {node_id}`)."
    )
}

/// What a reader says when a streamed model response breaks before it
/// ended: "the model stream was cut after Ns: <cause>". `elapsed` is how
/// long the call had been running. The cause walks the error's sources,
/// because reqwest's own text for a body failure is only "error decoding
/// response body", which is what the 2026-10-17 harness log carried and is
/// no help to anyone; an idle timeout is named as such.
pub fn stream_cut_message(elapsed: std::time::Duration, err: &reqwest::Error) -> String {
    let mut cause = err.to_string();
    let mut src = std::error::Error::source(err);
    while let Some(e) = src {
        let t = e.to_string();
        if !t.is_empty() && !cause.contains(&t) {
            cause.push_str(": ");
            cause.push_str(&t);
        }
        src = std::error::Error::source(e);
    }
    if err.is_timeout() {
        cause.push_str(&format!(
            " (no data for {}s, NOO_BACKEND_STREAM_IDLE_SECS)",
            crate::tls::stream_idle().as_secs()
        ));
    }
    format!("the model stream was cut after {}s: {cause}", elapsed.as_secs())
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
    fn only_a_node_link_that_advertises_a_tunnel_looks_for_one_and_never_the_controllers_own_agent() {
        let adv = json!({"ip_address": "10.0.0.9", TRANSPORTS_FIELD: {"tunnel": true}});
        assert_eq!(NodeLink::from_record("host9", Some(&adv)).unwrap().tunnel_node().as_deref(), Some("host9"));
        let quiet = json!({"ip_address": "10.0.0.9", TRANSPORTS_FIELD: {"tunnel": false}});
        assert_eq!(NodeLink::from_record("host9", Some(&quiet)).unwrap().tunnel_node(), None);
        assert_eq!(NodeLink::from_record("host9", Some(&json!({"ip_address": "10.0.0.9"}))).unwrap().tunnel_node(), None);
        // The controller's own agent is reached the way it always was.
        assert_eq!(NodeLink::self_agent_at("https://host9.tail:8081".into()).tunnel_node(), None);
        // An address-only link finds nothing when no tunnel registered that address.
        assert_eq!(NodeLink::for_ip("10.99.99.99").tunnel_node(), None);
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

    // ── streams: an idle bound, never a total one ──────────────────────

    /// The stream client is built with no total timeout and the idle bound;
    /// the unary client keeps its total. reqwest does not expose either on
    /// a built client, so the values the clients are built FROM are pinned.
    #[test]
    fn the_stream_client_has_an_idle_bound_and_no_total() {
        let s = crate::tls::ClientTimeouts::cluster_stream();
        assert_eq!(s.total, None, "a total timeout cuts a slow model's stream mid-answer");
        assert_eq!(s.read_idle, Some(crate::tls::stream_idle()));
        assert_eq!(crate::tls::ClientTimeouts::external_stream().total, None);
        let u = crate::tls::ClientTimeouts::cluster();
        assert!(u.total.is_some(), "unary calls keep their whole-request bound");
        assert_eq!(u.read_idle, None);
        assert_eq!(s.connect, u.connect, "same connect budget as the unary client");
        assert_eq!(crate::tls::DEFAULT_STREAM_IDLE_SECS, 300, "the value docs/reference/env.md documents");
    }

    /// A model endpoint that sends `chunks` SSE frames, sleeping `gaps[i]`
    /// before frame i. Returns its URL.
    async fn sse_server(gaps: Vec<std::time::Duration>) -> String {
        use axum::{body::Body, routing::get, Router};
        let app = Router::new().route(
            "/sse",
            get(move || {
                let gaps = gaps.clone();
                async move {
                    let frames = futures::stream::unfold(0usize, move |i| {
                        let gaps = gaps.clone();
                        async move {
                            let gap = *gaps.get(i)?;
                            tokio::time::sleep(gap).await;
                            Some((Ok::<_, std::convert::Infallible>(format!("data: {i}\n\n")), i + 1))
                        }
                    });
                    axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(Body::from_stream(frames))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/sse")
    }

    /// Read the whole body; `Err` is the cut-stream message.
    async fn read_all(client: &reqwest::Client, url: &str) -> Result<String, String> {
        use futures::StreamExt;
        let started = std::time::Instant::now();
        let resp = client.get(url).send().await.map_err(|e| stream_cut_message(started.elapsed(), &e))?;
        let mut body = resp.bytes_stream();
        let mut out = String::new();
        while let Some(item) = body.next().await {
            match item {
                Ok(b) => out.push_str(&String::from_utf8_lossy(&b)),
                Err(e) => return Err(stream_cut_message(started.elapsed(), &e)),
            }
        }
        Ok(out)
    }

    /// Five seconds of frames a second apart pass a 2 s idle bound: the
    /// stream is longer than the bound and is not cut, because it never
    /// goes silent for that long.
    #[tokio::test]
    async fn a_stream_longer_than_the_idle_bound_is_not_cut_while_it_sends() {
        let one = std::time::Duration::from_secs(1);
        let url = sse_server(vec![one; 5]).await;
        let client = crate::tls::plain_client(crate::tls::ClientTimeouts::stream_with_idle(std::time::Duration::from_secs(2)));
        let body = read_all(&client, &url).await.expect("a live stream is not cut");
        for i in 0..5 {
            assert!(body.contains(&format!("data: {i}")), "frame {i} missing: {body}");
        }
    }

    /// Three seconds of silence after the first frame breaks a 2 s idle
    /// bound, and the reader names it as a cut stream.
    #[tokio::test]
    async fn a_silent_stream_is_cut_at_the_idle_bound() {
        let url = sse_server(vec![std::time::Duration::ZERO, std::time::Duration::from_secs(3), std::time::Duration::ZERO]).await;
        let client = crate::tls::plain_client(crate::tls::ClientTimeouts::stream_with_idle(std::time::Duration::from_secs(2)));
        let started = std::time::Instant::now();
        let err = read_all(&client, &url).await.expect_err("silence past the idle bound is a cut");
        assert!(err.starts_with("the model stream was cut after "), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(3), "cut at the idle bound, not after the gap: {:?}", started.elapsed());
    }
}
