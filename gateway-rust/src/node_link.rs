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
//! Today there is exactly one transport and it is the old one: HTTPS to the
//! agent's mTLS listener on [`AGENT_PORT`], through the shared cluster
//! client, with the bearer decision `node_agent_auth` already makes. This
//! module changes no byte on the wire.
//!
//! - [`NodeLink::request`]: a unary call (the body is read once, whole).
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
        Self::from_record(node_id, record.as_ref())
    }

    /// [`NodeLink::for_node`] over an already-read record.
    pub(crate) fn from_record(node_id: &str, record: Option<&Value>) -> Result<Self, AppError> {
        if let Some(data) = record {
            if let Some(url) = data.get("agent_url").and_then(|v| v.as_str()) {
                if !url.is_empty() {
                    return Ok(Self::with_node(url.to_string(), node_id));
                }
            }
            if let Some(ip) = data.get("ip_address").and_then(|v| v.as_str()) {
                if !ip.is_empty() {
                    return Ok(Self::with_node(format!("https://{ip}:{AGENT_PORT}"), node_id));
                }
            }
            // Registered, but with nowhere to send the call: say so, rather
            // than "not found".
            return Err(AppError::NotFound(no_address_message(node_id)));
        }
        Err(AppError::NotFound(format!("Node '{node_id}' not found in mesh_nodes")))
    }

    fn with_node(base: String, node_id: &str) -> Self {
        Self { base, node_id: Some(node_id.to_string()), auth: Auth::Node }
    }

    /// The agent on `ip` (`https://{ip}:AGENT_PORT`), for paths that already
    /// hold the address (inference discovery, the coordinator).
    pub fn for_ip(ip: &str) -> Self {
        Self { base: format!("https://{ip}:{AGENT_PORT}"), node_id: None, auth: Auth::Node }
    }

    /// The agent at an address the caller already holds (a record's
    /// `agent_url`, a backend URL).
    pub fn for_base(url: &str) -> Self {
        Self { base: url.to_string(), node_id: None, auth: Auth::Node }
    }

    /// The controller's own agent: `NOO_SELF_AGENT_URL`, else derived from
    /// the controller URL. `Err` carries the operator guidance a localhost
    /// controller URL needs.
    pub fn self_agent() -> Result<Self, String> {
        Ok(Self::self_agent_at(crate::routes::self_agent_base()?))
    }

    /// The controller's own agent at a known address.
    pub(crate) fn self_agent_at(base: String) -> Self {
        Self { base, node_id: None, auth: Auth::SelfAgent }
    }

    /// The agent's base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The node this link was resolved for, when it was resolved by id. The
    /// NATS phase addresses a node by id (`node.{id}.rpc.*`); nothing needs
    /// it while the only transport is the HTTPS listener.
    #[allow(dead_code)]
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

    /// A unary call: the shared cluster client plus exactly the credential
    /// `node_agent_auth` decides for this agent. The caller adds body,
    /// headers and timeout, then `.send()`s.
    pub fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.build(method, path)
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
        assert_eq!(auth_of(leaf.request(Method::GET, "/gpu")), None, "leaf-only agent: no bearer");
        assert_eq!(auth_of(leaf.stream(Method::POST, "/v1/chat/completions")), None);
        assert_eq!(
            auth_of(old.request(Method::GET, "/gpu")).as_deref(),
            Some("Bearer static-test-token"),
            "an agent that has not said keeps the bearer"
        );
        // Same decision as calling node_agent_auth directly.
        assert_eq!(
            crate::node_agent_auth::header_for("https://10.0.0.3:8081/gpu").map(|(_, v)| v),
            auth_of(old.request(Method::GET, "/gpu"))
        );
        let built = old.request(Method::DELETE, "/containers/x").build().unwrap();
        assert_eq!(built.method(), Method::DELETE);
        assert_eq!(built.url().as_str(), "https://10.0.0.3:8081/containers/x");
    }

    #[test]
    fn the_self_agent_uses_the_self_variant() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        crate::node_agent_auth::clear_for_test();
        std::env::set_var("NOO_NODE_AGENT_TOKEN", "static-test-token");
        let me = NodeLink::self_agent_at("https://controller.tail:8081".into());
        assert!(auth_of(me.request(Method::GET, "/tailnet/whois?ip=100.64.0.9")).is_some());
        crate::node_agent_auth::note(
            "host8",
            &json!({"ip_address": "100.64.0.1", "self_node": true, crate::node_agent_auth::CAPABILITY: true}),
        );
        assert_eq!(auth_of(me.request(Method::GET, "/tailnet/whois?ip=100.64.0.9")), None);
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
}
