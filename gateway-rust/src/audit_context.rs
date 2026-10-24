// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Who and where an audit row came from, without touching 100 call sites.
//!
//! [`audit::record`] has ~120 callers and, until now, recorded no
//! source address: only the login rows (`audit_auth`) carried one. A request
//! layer ([`origin_layer`]) puts the caller's address in a task-local for the
//! whole handler, and `audit::record` folds it, and the conversation id of the
//! agent turn it runs inside, into the row's `details` ([`with_origin`]).
//!
//! The address follows the SAME rule as the login rows and the rate limiter
//! (`middleware::client_ip`): `X-Forwarded-For` / `X-Real-IP` count only when
//! the direct socket peer is a trusted proxy, and the rightmost untrusted
//! entry wins; otherwise it is the socket peer. A client therefore cannot
//! choose the address written to the log.
//!
//! A task-local does not cross `tokio::spawn`: an audit row written from a
//! spawned task (a websocket session, a background loop) carries no address,
//! and no key is added rather than a guessed one.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static SOURCE_IP: Option<String>;
}

/// The address a request is attributed to, or `None` when the server was not
/// built with connect info (no socket peer is known).
pub(crate) fn origin_of(request: &Request) -> Option<String> {
    let peer = crate::middleware::peer_ip(request)?;
    Some(crate::middleware::client_ip(request, Some(&peer)))
}

/// Request layer: bind the caller's address for the duration of the handler.
pub(crate) async fn origin_layer(request: Request, next: Next) -> Response {
    let ip = origin_of(&request);
    SOURCE_IP.scope(ip, next.run(request)).await
}

/// The bound address, if the caller is inside a request.
pub(crate) fn source_ip() -> Option<String> {
    SOURCE_IP.try_with(|v| v.clone()).ok().flatten()
}

/// `details` with `source_ip` and `conversation_id` added where known and not
/// already present. A value the caller put there itself is never overwritten.
/// `null` becomes an empty object; any other non-object is left alone.
pub(crate) fn with_origin(details: serde_json::Value) -> serde_json::Value {
    with_origin_of(details, source_ip(), &crate::routes::communication::turn_principal().conversation_id)
}

fn with_origin_of(details: serde_json::Value, ip: Option<String>, conversation_id: &str) -> serde_json::Value {
    let mut details = if details.is_null() { serde_json::json!({}) } else { details };
    if let Some(obj) = details.as_object_mut() {
        if let Some(ip) = ip {
            obj.entry("source_ip").or_insert(serde_json::Value::String(ip));
        }
        if !conversation_id.is_empty() {
            obj.entry("conversation_id").or_insert(serde_json::Value::String(conversation_id.to_string()));
        }
    }
    details
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use serde_json::json;
    use std::net::SocketAddr;

    fn req(peer: &str, headers: &[(&str, &str)]) -> Request {
        let mut b = axum::http::Request::builder().uri("/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut r: Request = b.body(axum::body::Body::empty()).expect("request");
        r.extensions_mut().insert(ConnectInfo(format!("{peer}:4000").parse::<SocketAddr>().expect("addr")));
        r
    }

    #[test]
    fn an_untrusted_peer_cannot_choose_the_address_that_is_logged() {
        let r = req("198.51.100.7", &[("x-forwarded-for", "203.0.113.99"), ("x-real-ip", "203.0.113.98")]);
        assert_eq!(origin_of(&r).as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn a_trusted_proxy_vouches_for_the_forwarded_client() {
        // Loopback is always a trusted proxy.
        let r = req("127.0.0.1", &[("x-forwarded-for", "203.0.113.5")]);
        assert_eq!(origin_of(&r).as_deref(), Some("203.0.113.5"));
        // Rightmost UNTRUSTED entry, not whatever the client wrote first.
        let r = req("127.0.0.1", &[("x-forwarded-for", "6.6.6.6, 203.0.113.5, 127.0.0.1")]);
        assert_eq!(origin_of(&r).as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn no_socket_peer_means_no_address() {
        let r: Request = axum::http::Request::builder().body(axum::body::Body::empty()).expect("request");
        assert_eq!(origin_of(&r), None);
    }

    #[tokio::test]
    async fn the_layer_binds_the_address_for_the_handler_and_not_beyond() {
        assert_eq!(source_ip(), None);
        let seen = SOURCE_IP.scope(Some("203.0.113.9".into()), async { source_ip() }).await;
        assert_eq!(seen.as_deref(), Some("203.0.113.9"));
        assert_eq!(source_ip(), None);
    }

    #[test]
    fn details_gain_the_address_and_conversation_without_losing_their_own() {
        let d = with_origin_of(json!({"what": "x"}), Some("203.0.113.9".into()), "conv-1");
        assert_eq!(d, json!({"what": "x", "source_ip": "203.0.113.9", "conversation_id": "conv-1"}));
        // Already present: kept as the caller wrote it.
        let d = with_origin_of(json!({"source_ip": "10.0.0.1", "conversation_id": "mine"}), Some("203.0.113.9".into()), "conv-1");
        assert_eq!(d, json!({"source_ip": "10.0.0.1", "conversation_id": "mine"}));
        // Nothing known: nothing invented.
        assert_eq!(with_origin_of(json!({"a": 1}), None, ""), json!({"a": 1}));
        assert_eq!(with_origin_of(json!(null), Some("203.0.113.9".into()), ""), json!({"source_ip": "203.0.113.9"}));
        // A non-object payload is left alone.
        assert_eq!(with_origin_of(json!([1]), Some("203.0.113.9".into()), "c"), json!([1]));
    }

    #[tokio::test]
    async fn inside_an_agent_turn_the_conversation_id_is_recorded() {
        let principal = crate::routes::communication::TurnPrincipal {
            conversation_id: "conv-42".into(),
            ..Default::default()
        };
        let d = crate::routes::communication::with_turn_principal(principal, async {
            SOURCE_IP.scope(Some("203.0.113.9".into()), async { with_origin(json!({"tool": "t"})) }).await
        })
        .await;
        assert_eq!(d["conversation_id"], "conv-42");
        assert_eq!(d["source_ip"], "203.0.113.9");
    }
}
