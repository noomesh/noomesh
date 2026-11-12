// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `GET /api/internal/prometheus/targets/node-agents`: Prometheus's
//! http_sd list of the node agents to scrape (i669).
//!
//! The static target `node-agent:8081` named a compose service that exists
//! only under the `node-agent-compose` profile; on the fleet every agent is a
//! host unit, so it was never up and paged the operator hourly. The agents
//! are listed here instead, from the registry, live:
//!
//! - **who may ask**: the scraper's own service leaf (CN=prometheus), by the
//!   verified client certificate, decided in the auth middleware before any
//!   bearer is read and again here. GET only. No token, header or other leaf
//!   opens it.
//! - **what is listed**: each registered node's agent address, exactly the
//!   one the gateway itself dials (`NodeLink::from_record`), and only when
//!   that node's PUBLIC leaf (`/app/pki/nodes/<id>/node.crt`, the key-free
//!   view) carries a SAN for the address's host. The scrape verifies server
//!   names, so a target its leaf does not cover could only fail; it is left
//!   out and logged (`scrape_target_skipped`, with the reissue command)
//!   instead, and `noo cluster verify` counts it as not scraped.
//! - **what is not**: nothing from the request reaches the body. The body is
//!   `[{"targets": ["<host>:<port>"], "labels": {"node": "<id>"}}]` and
//!   nothing else: no token, no key material, no URL path.
//!
//! When the gateway is down, Prometheus keeps the last list it fetched (its
//! http_sd keeps the current targets when a refresh fails), so a gateway
//! restart does not read as every agent down.

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde_json::{json, Value};

use crate::node_identity::VerifiedService;
use crate::node_link::NodeLink;
use crate::state::AppState;

/// The key-free view of the PKI's node certificates (the CLI's public view).
const NODES_VIEW: &str = "/app/pki/nodes";

pub fn router() -> Router<Arc<AppState>> {
    // A literal path: the OpenAPI generator and the drift checker read route
    // strings. Same value as `auth::SCRAPE_TARGETS_PATH`.
    Router::new().route("/api/internal/prometheus/targets/node-agents", get(node_agent_targets))
}

/// A node left out of the list, and why.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Skipped {
    pub node: String,
    pub reason: String,
}

/// The node id as one path component: never a traversal.
fn safe_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The host and port of an agent base URL (`https://host:port`).
fn host_port(base: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(base).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    // `host_str` brackets an IPv6 address; the SAN check and the target want it bare.
    let host = url.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    if host.is_empty() {
        return None;
    }
    Some((host, url.port_or_known_default()?))
}

/// Whether a PEM leaf carries a SAN for `host`: an IP SAN equal to it when the
/// host is an address, a DNS SAN equal to it (ASCII case-insensitive) when it
/// is a name. Anything unreadable is "no".
pub(crate) fn leaf_covers(pem: &str, host: &str) -> bool {
    let Ok((_, p)) = x509_parser::pem::parse_x509_pem(pem.as_bytes()) else { return false };
    let Ok(cert) = p.parse_x509() else { return false };
    let Ok(Some(san)) = cert.subject_alternative_name() else { return false };
    let want_ip: Option<IpAddr> = host.parse().ok();
    san.value.general_names.iter().any(|gn| match (gn, want_ip) {
        (x509_parser::extensions::GeneralName::IPAddress(b), Some(ip)) => match (ip, b.len()) {
            (IpAddr::V4(v4), 4) => v4.octets()[..] == b[..],
            (IpAddr::V6(v6), 16) => v6.octets()[..] == b[..],
            _ => false,
        },
        (x509_parser::extensions::GeneralName::DNSName(_), None) => true,
        _ => false,
    })
}

/// The http_sd body for `nodes` (id, mesh_nodes record), and the nodes left
/// out. `read_cert` reads a node's public leaf by id. Pure, so every check
/// is tested on its own.
pub(crate) fn targets(nodes: &[(String, Value)], read_cert: impl Fn(&str) -> Option<String>) -> (Vec<Value>, Vec<Skipped>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut skip = |node: &str, reason: String| skipped.push(Skipped { node: node.to_string(), reason });
    for (id, record) in nodes {
        if !safe_node_id(id) {
            skip(id, "the node id is not a single path component".into());
            continue;
        }
        let Ok(link) = NodeLink::from_record(id, Some(record)) else {
            skip(id, "the registry has no agent address for it".into());
            continue;
        };
        let Some((host, port)) = host_port(link.base()) else {
            skip(id, format!("its agent address {} is not an https URL with a host", link.base()));
            continue;
        };
        let Some(pem) = read_cert(id) else {
            skip(id, format!("no public leaf at {NODES_VIEW}/{id}/node.crt"));
            continue;
        };
        if !leaf_covers(&pem, &host) {
            skip(id, format!("its leaf has no SAN for {host}; reissue with `noo security pki issue-node {id} {host}`"));
            continue;
        }
        let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        out.push(json!({ "targets": [target], "labels": { "node": id } }));
    }
    (out, skipped)
}

fn refused(status: StatusCode, why: &str) -> Response {
    (status, Json(json!({ "error": why }))).into_response()
}

/// The handler's own gate (the middleware decides first, with the same
/// predicate): the scraper's verified leaf, GET only. A function, so what it
/// refuses is tested, not only that it is called.
fn gate(method: &Method, service: Option<&VerifiedService>) -> Result<(), Response> {
    if crate::auth::is_scrape_targets(method, crate::auth::SCRAPE_TARGETS_PATH, service) {
        Ok(())
    } else {
        Err(refused(StatusCode::FORBIDDEN, "answers the Prometheus scraper's own service leaf only"))
    }
}

/// `GET /api/internal/prometheus/targets/node-agents`: the scraper's leaf
/// only. Answers the http_sd list of node agents whose leaf covers the
/// address they are scraped at.
async fn node_agent_targets(
    State(state): State<Arc<AppState>>,
    svc: Option<Extension<Option<VerifiedService>>>,
    method: Method,
) -> Response {
    let service = svc.and_then(|Extension(s)| s);
    if let Err(r) = gate(&method, service.as_ref()) {
        return r;
    }
    let mut nodes: Vec<(String, Value)> = Vec::new();
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else {
        // An error, not an empty list: http_sd then keeps its last good list
        // rather than dropping every agent.
        return refused(StatusCode::SERVICE_UNAVAILABLE, "the node registry is unreadable");
    };
    let Ok(mut keys) = kv.keys().await else {
        return refused(StatusCode::SERVICE_UNAVAILABLE, "the node registry is unreadable");
    };
    use futures::StreamExt as _;
    while let Some(Ok(id)) = keys.next().await {
        if let Ok(Some(entry)) = kv.get(&id).await {
            if let Ok(record) = serde_json::from_slice::<Value>(&entry) {
                nodes.push((id, record));
            }
        }
    }
    nodes.sort_by(|a, b| a.0.cmp(&b.0));
    let (body, skipped) = targets(&nodes, |id| std::fs::read_to_string(format!("{NODES_VIEW}/{id}/node.crt")).ok());
    for s in &skipped {
        tracing::warn!(node = %s.node, reason = %s.reason, "scrape_target_skipped");
    }
    Json(Value::Array(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed leaf with these SANs (rcgen, as the PKI tests use).
    fn leaf(dns: &[&str], ips: &[&str]) -> String {
        let mut params = rcgen::CertificateParams::new(dns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        for ip in ips {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip.parse().unwrap()));
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn rec(url: &str) -> Value {
        json!({ "agent_url": url })
    }

    #[test]
    fn a_node_whose_leaf_covers_its_address_is_listed_with_only_host_port_and_node() {
        let pem = leaf(&["aserve", "localhost"], &["100.98.144.38", "127.0.0.1"]);
        let (body, skipped) = targets(&[("aserve".into(), rec("https://100.98.144.38:8081"))], |_| Some(pem.clone()));
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(body, vec![json!({ "targets": ["100.98.144.38:8081"], "labels": { "node": "aserve" } })]);
    }

    #[test]
    fn a_leaf_without_a_san_for_the_address_is_left_out_with_the_reissue_command() {
        let pem = leaf(&["aserve", "localhost"], &["10.0.0.9", "127.0.0.1"]);
        let (body, skipped) = targets(&[("aserve".into(), rec("https://100.98.144.38:8081"))], |_| Some(pem.clone()));
        assert!(body.is_empty(), "{body:?}");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("noo security pki issue-node aserve 100.98.144.38"), "{:?}", skipped[0]);
    }

    #[test]
    fn a_name_address_needs_a_dns_san_and_an_ip_san_never_stands_for_it() {
        let by_name = leaf(&["noo-controller", "localhost"], &["127.0.0.1"]);
        let (body, _) = targets(&[("pop-os".into(), rec("https://noo-controller:8081"))], |_| Some(by_name.clone()));
        assert_eq!(body.len(), 1, "a DNS SAN covers a name address");
        let ip_only = leaf(&["localhost"], &["100.72.99.2"]);
        let (body, skipped) = targets(&[("pop-os".into(), rec("https://noo-controller:8081"))], |_| Some(ip_only.clone()));
        assert!(body.is_empty() && skipped.len() == 1, "an IP SAN is not a name");
    }

    #[test]
    fn a_missing_or_unreadable_leaf_is_left_out() {
        let (body, skipped) = targets(&[("a".into(), rec("https://10.0.0.1:8081"))], |_| None);
        assert!(body.is_empty() && skipped[0].reason.contains("no public leaf"));
        let (body, skipped) = targets(&[("a".into(), rec("https://10.0.0.1:8081"))], |_| Some("not a pem".into()));
        assert!(body.is_empty() && skipped.len() == 1);
    }

    #[test]
    fn an_unsafe_node_id_never_reaches_a_path() {
        let read = std::cell::RefCell::new(Vec::new());
        for bad in ["../etc", "a/b", ".hidden", ""] {
            let (body, skipped) = targets(&[(bad.into(), rec("https://10.0.0.1:8081"))], |id| {
                read.borrow_mut().push(id.to_string());
                None
            });
            assert!(body.is_empty() && skipped.len() == 1, "{bad}");
        }
        assert!(read.borrow().is_empty(), "a leaf was read for an unsafe id: {:?}", read.borrow());
    }

    #[test]
    fn a_node_with_no_https_address_is_left_out() {
        let pem = leaf(&["a"], &["10.0.0.1"]);
        for r in [json!({}), rec("http://10.0.0.1:8081"), rec("not a url")] {
            let (body, skipped) = targets(&[("a".into(), r.clone())], |_| Some(pem.clone()));
            assert!(body.is_empty() && skipped.len() == 1, "{r}");
        }
    }

    #[test]
    fn the_ip_address_fallback_is_the_same_address_the_gateway_dials() {
        let pem = leaf(&["a"], &["10.0.0.7"]);
        let (body, _) = targets(&[("a".into(), json!({ "ip_address": "10.0.0.7" }))], |_| Some(pem.clone()));
        assert_eq!(body, vec![json!({ "targets": ["10.0.0.7:8081"], "labels": { "node": "a" } })]);
    }

    #[test]
    fn an_ipv6_target_is_bracketed() {
        let pem = leaf(&["a"], &["fd7a:115c:a1e0::1"]);
        let (body, _) = targets(&[("a".into(), rec("https://[fd7a:115c:a1e0::1]:8081"))], |_| Some(pem.clone()));
        assert_eq!(body[0]["targets"][0], "[fd7a:115c:a1e0::1]:8081");
    }

    #[test]
    fn only_the_scrapers_leaf_and_only_get_opens_the_route() {
        use crate::auth::{is_scrape_targets, SCRAPE_TARGETS_PATH};
        let scraper = VerifiedService(crate::auth::METRICS_SCRAPER_SERVICE.to_string());
        let other = VerifiedService("grafana".to_string());
        assert!(is_scrape_targets(&Method::GET, SCRAPE_TARGETS_PATH, Some(&scraper)));
        assert!(!is_scrape_targets(&Method::GET, SCRAPE_TARGETS_PATH, Some(&other)), "another service leaf");
        assert!(!is_scrape_targets(&Method::GET, SCRAPE_TARGETS_PATH, None), "no certificate");
        assert!(!is_scrape_targets(&Method::POST, SCRAPE_TARGETS_PATH, Some(&scraper)), "not GET");
        assert!(!is_scrape_targets(&Method::GET, "/metrics", Some(&scraper)), "another path");
    }

    /// The handler refuses on its own as well, before the registry is read:
    /// the middleware is not its only gate.
    #[test]
    fn the_handler_gates_before_reading_the_registry() {
        let code = crate::test_src::own_code(include_str!("scrape_targets.rs"));
        let body = crate::test_src::fn_body(&code, "async fn node_agent_targets(");
        let gate = body.find("if let Err(r) = gate(&method, service.as_ref()) {").expect("the gate");
        let read = body.find("get_key_value(\"mesh_nodes\")").expect("the registry read");
        assert!(gate < read, "{body}");
    }

    #[test]
    fn the_gate_refuses_everything_but_the_scrapers_get() {
        let scraper = VerifiedService(crate::auth::METRICS_SCRAPER_SERVICE.to_string());
        let other = VerifiedService("grafana".to_string());
        assert!(gate(&Method::GET, Some(&scraper)).is_ok());
        for (m, s, why) in [
            (Method::GET, Some(&other), "another service leaf"),
            (Method::GET, None, "no certificate"),
            (Method::POST, Some(&scraper), "not GET"),
        ] {
            let r = gate(&m, s).expect_err(why);
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{why}");
        }
    }

    #[test]
    fn the_router_path_is_the_auth_path() {
        let src = include_str!("scrape_targets.rs");
        assert!(src.contains(&format!("\"{}\"", crate::auth::SCRAPE_TARGETS_PATH)));
    }
}
