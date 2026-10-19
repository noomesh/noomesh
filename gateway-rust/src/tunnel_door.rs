// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The loopback door onto the node tunnels.
//!
//! Four gateway call sites send inference as `node_link::backend_stream(...)`
//! and read the answer from the `reqwest::RequestBuilder` it returns; those
//! signatures are frozen (the harness session builds on them). A reqwest
//! client cannot be pointed at a custom transport, so a stream bound for a
//! tunnelled node is carried by rewriting its URL to this door: a tiny HTTP
//! server on 127.0.0.1 inside the gateway that turns each request into a
//! tunnel stream ([`crate::tunnel::Session::request`]) and streams the
//! answer back, byte for byte.
//!
//! What the door is NOT: it dials nothing. It forwards to a node that holds a
//! live tunnel to this gateway, by id, and to nowhere else. It binds loopback
//! only, starts with the first tunnel (a fleet with no tunnel has no
//! listener), and every request carries a 256-bit secret in the
//! `x-noo-tunnel-door` HEADER, generated per process and held only in memory
//! (never in env, a file, a metric or a URL); a request without it, or with a
//! wrong one, is a 404. It is a header and not part of the path because
//! reqwest prints the full URL in its error text and callers log that: a
//! secret in the URL would reach the gateway log on the first failed stream.
//! The secret is the only thing a process in the gateway's network namespace
//! lacks. The
//! node never sees the door: it sees a stream from its tunnel, served as the
//! controller; nothing in the request names a principal.
//!
//! A tunnel that drops mid-stream ends the door's response without the
//! terminating chunk (hyper reports an incomplete body to the caller); the
//! precise cause, `tunnel_lost`, is in the gateway's log and the per-node
//! `tunnel_aborts` counter. A tunnel that fails BEFORE the response head is a
//! plain 502 (`x-noo-tunnel-error`), which every caller already treats as the
//! backend being down, so inference may try another node: nothing was sent.

use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode};

/// The header that carries the door secret.
pub const DOOR_HEADER: &str = "x-noo-tunnel-door";
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::StreamExt;
use serde_json::json;

use crate::tunnel::{hub, TunnelBody, TunnelError, TunnelRequest};

struct Door {
    port: u16,
    secret: String,
}

static DOOR: OnceLock<Door> = OnceLock::new();
static START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Start the door once. Idempotent; a failure to bind is logged and leaves
/// the door absent, which means "no stream is carried by the tunnel" (calls
/// stay on HTTPS), never an error to the caller.
pub async fn ensure_started() {
    if DOOR.get().is_some() {
        return;
    }
    let _g = START.lock().await;
    if DOOR.get().is_some() {
        return;
    }
    let std_listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "tunnel door: could not bind loopback; streams stay on HTTPS");
            return;
        }
    };
    let _ = std_listener.set_nonblocking(true);
    let Ok(addr) = std_listener.local_addr() else { return };
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "tunnel door: could not listen; streams stay on HTTPS");
            return;
        }
    };
    let secret = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let app: Router = Router::new().fallback(door).with_state(Arc::new(secret.clone()));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "tunnel door stopped");
        }
    });
    let _ = DOOR.set(Door { port: addr.port(), secret });
}

fn host_key(u: &reqwest::Url) -> Option<String> {
    Some(format!("{}:{}", u.host_str()?.to_ascii_lowercase(), u.port_or_known_default()?))
}

/// Where a stream bound for `url` (a node agent's `https://host:8081/...`)
/// should be sent: the door, when that node advertises and holds a live
/// tunnel; else `url` unchanged, with the HTTPS stream counted against the
/// node. Pure routing: nothing is sent here.
pub fn carry(url: &str) -> String {
    if !crate::node_link::is_agent_url(url) {
        return url.to_string();
    }
    let Ok(u) = reqwest::Url::parse(url) else { return url.to_string() };
    let Some(key) = host_key(&u) else { return url.to_string() };
    let node = hub().node_for_host(&key);
    if let (Some(node), Some(door)) = (node.as_deref(), DOOR.get()) {
        if crate::tunnel::enabled() && hub().live(node).is_some() {
            let mut target = format!("http://127.0.0.1:{}/{}{}", door.port, urlencoding::encode(node), u.path());
            if let Some(q) = u.query() {
                target.push('?');
                target.push_str(q);
            }
            return target;
        }
    }
    crate::node_rpc::note_https(node.as_deref().unwrap_or(&key), false);
    url.to_string()
}

/// The door URL for a path on `node`, when `node` has a live tunnel.
pub fn door_url(node: &str, path: &str) -> Option<String> {
    let door = DOOR.get()?;
    if !crate::tunnel::enabled() || hub().live(node).is_none() {
        return None;
    }
    Some(format!("http://127.0.0.1:{}/{}{}", door.port, urlencoding::encode(node), path))
}

/// The door secret, for tests only.
#[cfg(test)]
pub fn test_secret() -> String {
    DOOR.get().map(|d| d.secret.clone()).unwrap_or_default()
}

/// Add the door secret to a request aimed at the door; any other request is
/// returned unchanged. The secret never appears in the URL.
pub fn mark(req: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
    match DOOR.get() {
        Some(d) if url.starts_with(&format!("http://127.0.0.1:{}/", d.port)) => req.header(DOOR_HEADER, d.secret.as_str()),
        _ => req,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn error_response(status: StatusCode, code: &str, detail: String) -> Response {
    let mut r = (status, axum::Json(json!({"detail": detail, "error": code}))).into_response();
    if let Ok(v) = HeaderValue::from_str(code) {
        r.headers_mut().insert("x-noo-tunnel-error", v);
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        r.headers_mut().insert("retry-after", HeaderValue::from_static("1"));
    }
    r
}

/// Split `/{node}/{rest}` into `(node, "/rest?query")`.
fn parse_target(path: &str, query: Option<&str>) -> Option<(String, String)> {
    let tail = path.strip_prefix('/')?;
    let (node_enc, rest) = match tail.split_once('/') {
        Some((n, r)) => (n, format!("/{r}")),
        None => (tail, "/".to_string()),
    };
    let node = urlencoding::decode(node_enc).ok()?.into_owned();
    if node.is_empty() {
        return None;
    }
    let mut target = rest;
    if let Some(q) = query {
        target.push('?');
        target.push_str(q);
    }
    Some((node, target))
}

async fn door(State(secret): State<Arc<String>>, req: axum::extract::Request) -> Response {
    let (parts, body) = req.into_parts();
    // Secret first, before the path is looked at; nothing below prints the
    // request path or headers.
    let presented = parts.headers.get(DOOR_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct_eq(presented, &secret) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some((node, target)) = parse_target(parts.uri.path(), parts.uri.query()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(sess) = hub().live(&node) else {
        return error_response(StatusCode::BAD_GATEWAY, "tunnel_unavailable", format!("node {node} has no live tunnel"));
    };
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(k, _)| k.as_str() != DOOR_HEADER)
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
        .collect();
    let stream = body.into_data_stream().map(|r| r.map_err(std::io::Error::other)).boxed();
    let treq = TunnelRequest { method: parts.method.as_str().to_string(), path: target, headers, body: TunnelBody::Stream(stream) };
    match sess.request(treq, None).await {
        Ok(resp) => {
            let mut b = Response::builder().status(resp.status);
            if let Some(h) = b.headers_mut() {
                for (k, v) in &resp.headers {
                    if crate::tunnel::drop_response_header(k) {
                        continue;
                    }
                    if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                        h.append(name, val);
                    }
                }
            }
            b.body(Body::from_stream(resp.body)).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e @ TunnelError::Busy { .. }) => error_response(StatusCode::SERVICE_UNAVAILABLE, "tunnel_busy", e.to_string()),
        Err(e @ TunnelError::BadRequest(_)) => error_response(StatusCode::BAD_REQUEST, "tunnel_request", e.to_string()),
        Err(e) => error_response(StatusCode::BAD_GATEWAY, "tunnel_lost", e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_door_path_is_node_and_the_untouched_rest() {
        let (n, t) = parse_target("/host9/v1/chat/completions", Some("a=1&b=%2F")).unwrap();
        assert_eq!((n.as_str(), t.as_str()), ("host9", "/v1/chat/completions?a=1&b=%2F"));
        let (n, t) = parse_target("/pop%2Dos/api/containers/x/proxy/a%2Fb", None).unwrap();
        assert_eq!((n.as_str(), t.as_str()), ("pop-os", "/api/containers/x/proxy/a%2Fb"), "the rest keeps its percent-encoding");
        assert_eq!(parse_target("/host9", None).unwrap().1, "/");
        assert!(parse_target("//gpu", None).is_none(), "an empty node id");
        assert!(parse_target("/", None).is_none());
        assert!(parse_target("", None).is_none());
    }

    #[test]
    fn constant_time_equality_is_equality() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "a"));
    }

    #[test]
    fn a_url_that_is_not_a_node_agent_is_never_carried() {
        assert_eq!(carry("http://noo-vllm:8000/v1/chat/completions"), "http://noo-vllm:8000/v1/chat/completions");
        assert_eq!(carry("not a url :8081"), "not a url :8081");
    }
}
