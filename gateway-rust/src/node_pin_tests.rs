// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller pins the node it dials (i1174): the address book, the
//! name check on real cluster-CA leaves, and two real TLS servers dialed
//! through the real `cluster_rustls_config` path.

use super::*;
use serde_json::json;
use std::sync::Arc;

/// A cluster CA and a NODE leaf it signed for `node` (CN and DNS SAN = the
/// node id, `O=Mesh Cluster Node`, the IP SANs given), as
/// `noo-cli/src/pki.rs` `issue_node_cert` issues it.
struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

fn ca() -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "pin test cluster CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { params, key, cert }
}

fn node_leaf(ca: &Ca, node: &str, org: &str, ips: &[&str]) -> rcgen::CertifiedKey<rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::new(vec![node.to_string(), "localhost".to_string()]).unwrap();
    for ip in ips {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip.parse().unwrap()));
    }
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, node);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, org);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &rcgen::Issuer::from_params(&ca.params, &ca.key)).unwrap();
    rcgen::CertifiedKey { cert, signing_key: key }
}

/// `host:AGENT_PORT`, the authority a record's `ip_address` gives a node.
fn at(host: &str) -> String {
    format!("{host}:{}", crate::node_link::AGENT_PORT)
}

#[test]
fn the_newest_report_owns_an_address_and_a_forgotten_node_owns_none() {
    note("pin-own-a", &json!({"ip_address": "10.231.0.1"}));
    assert_eq!(owner(&at("10.231.0.1")).as_deref(), Some("pin-own-a"));
    note("pin-own-b", &json!({"ip_address": "10.231.0.1"}));
    assert_eq!(owner(&at("10.231.0.1")).as_deref(), Some("pin-own-b"), "the newest report owns it");
    assert_eq!(owners_at_host("10.231.0.1"), vec!["pin-own-b".to_string()]);
    forget("pin-own-b");
    assert_eq!(owner(&at("10.231.0.1")), None);
}

#[test]
fn a_sensor_companion_is_the_same_machine_and_presents_its_node_leaf() {
    assert_eq!(accepted_names("host3-sensors"), vec!["host3-sensors".to_string(), "host3".to_string()]);
    assert!(same_machine("host3-sensors", "host3"));
    assert!(!same_machine("host3", "host4"));
    assert!(!same_machine("-sensors", "x"));
}

#[test]
fn a_link_for_one_node_may_not_dial_an_address_another_node_owns() {
    note("pin-dial-b", &json!({"ip_address": "10.231.1.2"}));
    let m = may_dial("pin-dial-a", &format!("https://{}", at("10.231.1.2"))).unwrap_err();
    assert_eq!(m.expected, vec!["pin-dial-a".to_string()]);
    assert!(m.to_string().starts_with("node_identity_mismatch"), "{m}");
    assert!(may_dial("pin-dial-b", &format!("https://{}", at("10.231.1.2"))).is_ok(), "its own address");
    assert!(may_dial("pin-dial-a", &format!("https://{}", at("10.231.1.9"))).is_ok(), "an address no node owns");
}

#[test]
fn a_leaf_for_another_node_is_refused_and_the_right_one_passes() {
    let ca = ca();
    let a = node_leaf(&ca, "node_a", NODE_ORG, &["10.231.2.1"]);
    let b = node_leaf(&ca, "node_b", NODE_ORG, &["10.231.2.1"]);
    let owners = vec!["node_a".to_string()];
    assert!(check_leaf("10.231.2.1", &owners, false, a.cert.der()).is_ok());
    let m = check_leaf("10.231.2.1", &owners, false, b.cert.der()).unwrap_err();
    assert_eq!(m.presented, vec!["node_b".to_string()]);
    assert_eq!(m.expected, vec!["node_a".to_string()]);
    // A host the book does not place a node on: nothing to pin.
    assert!(check_leaf("10.231.2.1", &[], false, b.cert.der()).is_ok());
    // At a node's address only that node's leaf passes: a service leaf
    // covering the address is refused, except on the controller's machine.
    let door = node_leaf(&ca, "some-door", "Mesh Cluster Service", &["10.231.2.1"]);
    let m = check_leaf("10.231.2.1", &owners, false, door.cert.der()).unwrap_err();
    assert!(m.presented[0].starts_with("a certificate that is not a node's"), "{:?}", m.presented);
    assert!(check_leaf("10.231.2.1", &owners, true, door.cert.der()).is_ok(), "the controller's own machine");
    // A sensor companion presents its machine's node leaf.
    assert!(check_leaf("10.231.2.1", &["node_a-sensors".to_string()], false, a.cert.der()).is_ok());
}

#[test]
fn the_mismatch_is_found_inside_a_wrapped_rustls_error() {
    let m = NodeIdentityMismatch { host: "h".into(), expected: vec!["a".into()], presented: vec!["b".into()] };
    let tls = rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(m.clone()))));
    let io = std::io::Error::new(std::io::ErrorKind::InvalidData, tls);
    assert_eq!(identity_mismatch(&io), Some(m));
    let other = std::io::Error::new(std::io::ErrorKind::Other, "refused");
    assert_eq!(identity_mismatch(&other), None);
}

/// A one-shot-per-connection HTTPS listener on `ip` presenting `leaf`.
async fn serve_at(ip: &str, leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> u16 {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = CertificateDer::from(leaf.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(leaf.signing_key.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind(format!("{ip}:0")).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..4 {
            let Ok((sock, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                if let Ok(mut s) = acceptor.accept(sock).await {
                    let mut buf = [0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                    let _ = s.flush().await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    port
}

/// The two-node real-leaf test: node_a and node_b each serve a real
/// cluster-CA leaf on their own address. node_a's record pointed at
/// node_b's server: the call is refused at the handshake, typed and named.
/// node_a's record at its own server: the call goes through. The client is
/// built from the real `cluster_rustls_config`.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_for_another_node_is_refused_at_dial() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = ca();
    let (ip_a, ip_b) = ("127.0.0.31", "127.0.0.32");
    let a = node_leaf(&ca, "pin-two-a", NODE_ORG, &[ip_a]);
    let b = node_leaf(&ca, "pin-two-b", NODE_ORG, &[ip_b]);
    let port_a = serve_at(ip_a, &a).await;
    let port_b = serve_at(ip_b, &b).await;

    let dir = std::env::temp_dir().join(format!("noo-pin-two-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca_pem = dir.join("ca.crt");
    std::fs::write(&ca_pem, ca.cert.pem()).unwrap();
    let cfg = {
        let _g = crate::tls::loopback_verification_tests::ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NOO_TLS_CA", &ca_pem);
        let cfg = crate::tls::cluster_rustls_config().unwrap().expect("the cluster config");
        std::env::remove_var("NOO_TLS_CA");
        cfg
    };
    let client = reqwest::Client::builder().tls_backend_preconfigured((*cfg).clone()).build().unwrap();

    // node_a's record at its own server: the call goes through.
    note("pin-two-a", &json!({"ip_address": ip_a, "agent_url": format!("https://{ip_a}:{port_a}")}));
    let ok = client.get(format!("https://{ip_a}:{port_a}/health")).send().await;
    assert!(ok.is_ok(), "the right node's leaf must pass: {:?}", ok.err());

    // node_a's record pointed at node_b's server: refused at the handshake.
    note("pin-two-a", &json!({"ip_address": ip_b, "agent_url": format!("https://{ip_b}:{port_b}")}));
    let err = client.get(format!("https://{ip_b}:{port_b}/health")).send().await.expect_err("node_b's leaf for node_a's call");
    let m = identity_mismatch(&err).expect("a typed node_identity_mismatch");
    assert_eq!(m.expected, vec!["pin-two-a".to_string()]);
    assert_eq!(m.presented, vec!["pin-two-b".to_string()]);

    // And once node_b reports its own address, a link for node_a is not
    // even built towards it.
    note("pin-two-b", &json!({"ip_address": ip_b, "agent_url": format!("https://{ip_b}:{port_b}")}));
    assert!(may_dial("pin-two-a", &format!("https://{ip_b}:{port_b}")).is_err());
    let ok_b = client.get(format!("https://{ip_b}:{port_b}/health")).send().await;
    assert!(ok_b.is_ok(), "node_b's own call passes: {:?}", ok_b.err());

    for n in ["pin-two-a", "pin-two-b"] {
        forget(n);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_cluster_client_carries_the_node_pin() {
    let own = crate::test_src::own_code(include_str!("tls.rs"));
    let f = crate::test_src::fn_body(&own, "pub fn cluster_rustls_config(");
    assert!(f.contains("crate::node_pin::NodePinVerifier::new("), "{f}");
    assert!(f.contains(".with_custom_certificate_verifier("), "{f}");
    assert!(!f.contains(".with_root_certificates("), "a stock verifier would skip the pin: {f}");
}

/// A client built from the real `cluster_rustls_config` over `ca`.
fn pin_client(ca: &Ca, tag: &str) -> reqwest::ClientBuilder {
    let dir = std::env::temp_dir().join(format!("noo-pin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca_pem = dir.join("ca.crt");
    std::fs::write(&ca_pem, ca.cert.pem()).unwrap();
    let cfg = {
        let _g = crate::tls::loopback_verification_tests::ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NOO_TLS_CA", &ca_pem);
        let cfg = crate::tls::cluster_rustls_config().unwrap().expect("the cluster config");
        std::env::remove_var("NOO_TLS_CA");
        cfg
    };
    let _ = std::fs::remove_dir_all(&dir);
    reqwest::Client::builder().tls_backend_preconfigured((*cfg).clone())
}

/// Every kind of peer the cluster clients reach, each serving a real leaf of
/// its kind, dialled through the real `cluster_rustls_config`:
///
/// - a node agent with its own leaf: passes;
/// - a node agent with another node's leaf: refused, typed, and kept for
///   `noo cluster verify` ([`last_mismatch`]);
/// - a SERVICE leaf (a backend door, loki, an add-on) at a node's address:
///   passes, the pin judges node leaves only;
/// - the self node's agent and the gateway's own leaf on the controller's
///   address: pass;
/// - a host not in the book: webpki alone (a node leaf naming any node
///   passes; a leaf from another CA is still refused);
/// - a docker service name (`noo-*`, `gateway`): never in the book, passes.
#[tokio::test(flavor = "multi_thread")]
async fn every_peer_kind_the_cluster_clients_reach() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = ca();
    let (ip_node, ip_ctrl, ip_free, ip_docker) = ("127.0.0.41", "127.0.0.42", "127.0.0.43", "127.0.0.44");

    // A node agent, right and wrong, at its booked address.
    let right = node_leaf(&ca, "pin-kind-a", NODE_ORG, &[ip_node]);
    let wrong = node_leaf(&ca, "pin-kind-b", NODE_ORG, &[ip_node]);
    // A backend door / service leaf on the same node's address.
    let door = node_leaf(&ca, "ollama", crate::node_identity::SERVICE_ORG, &[ip_node]);
    // The controller's machine: the self node's agent and the gateway.
    let self_agent = node_leaf(&ca, "pin-kind-self", NODE_ORG, &[ip_ctrl]);
    let gateway = node_leaf(&ca, "pin-kind-ctrl", "Mesh Cluster Gateway", &[ip_ctrl]);
    // An address no node owns.
    let stray = node_leaf(&ca, "pin-kind-z", NODE_ORG, &[ip_free]);
    let other_ca = ca();
    let foreign = node_leaf(&other_ca, "pin-kind-a", NODE_ORG, &[ip_free]);
    // A docker service name.
    let svc = node_leaf(&ca, "noo-trellion", crate::node_identity::SERVICE_ORG, &[]);

    let p_right = serve_at(ip_node, &right).await;
    let p_wrong = serve_at(ip_node, &wrong).await;
    let p_door = serve_at(ip_node, &door).await;
    let p_self = serve_at(ip_ctrl, &self_agent).await;
    let p_gw = serve_at(ip_ctrl, &gateway).await;
    let p_stray = serve_at(ip_free, &stray).await;
    let p_foreign = serve_at(ip_free, &foreign).await;
    let p_svc = serve_at(ip_docker, &svc).await;

    note("pin-kind-a", &json!({"ip_address": ip_node}));
    note("pin-kind-self", &json!({"ip_address": ip_ctrl, "self_node": true}));
    let client = pin_client(&ca, "kinds")
        .resolve("noo-trellion", format!("{ip_docker}:{p_svc}").parse().unwrap())
        .build()
        .unwrap();
    let get = |host: &str, port: u16| client.get(format!("https://{host}:{port}/health")).send();

    // A node agent with its own leaf.
    assert!(get(ip_node, p_right).await.is_ok(), "node_a's own leaf at node_a's address");
    // A node agent with another node's leaf: refused, typed, kept for verify.
    let err = get(ip_node, p_wrong).await.expect_err("node_b's leaf at node_a's address");
    let m = identity_mismatch(&err).expect("a typed node_identity_mismatch");
    assert_eq!(m.presented, vec!["pin-kind-b".to_string()]);
    let kept = last_mismatch("pin-kind-a").expect("verify reads the refusal");
    assert_eq!(kept["host"], json!(ip_node));
    assert_eq!(kept["presented"], json!(["pin-kind-b"]));
    assert!(last_mismatch("pin-kind-b").is_none(), "kept for the node the call was meant for");
    // A service leaf at a node's address: refused (only the node's own leaf
    // answers there; real door leaves never carry a node's address).
    let err = get(ip_node, p_door).await.expect_err("a service leaf at node_a's address");
    assert!(identity_mismatch(&err).is_some(), "refused by the pin, typed");
    // The self node's agent, and the gateway's own leaf, on the controller's address.
    let r = get(ip_ctrl, p_self).await;
    assert!(r.is_ok(), "the self node's own leaf: {:?}", r.err());
    let r = get(ip_ctrl, p_gw).await;
    assert!(r.is_ok(), "the gateway's leaf is not a node leaf: {:?}", r.err());
    // A host not in the book: webpki only.
    let r = get(ip_free, p_stray).await;
    assert!(r.is_ok(), "no owner, nothing to pin: {:?}", r.err());
    let err = get(ip_free, p_foreign).await.expect_err("webpki still refuses another CA's leaf");
    assert!(identity_mismatch(&err).is_none(), "that refusal is webpki's, not the pin's");
    // A docker service name.
    let r = get("noo-trellion", p_svc).await;
    assert!(r.is_ok(), "a docker service name is never in the book: {:?}", r.err());

    for n in ["pin-kind-a", "pin-kind-self"] {
        forget(n);
    }
}

#[test]
fn a_link_refused_before_the_dial_is_kept_for_verify() {
    note("pin-keep-b", &json!({"ip_address": "10.231.5.2"}));
    assert!(may_dial("pin-keep-a", &format!("https://{}", at("10.231.5.2"))).is_err());
    let kept = last_mismatch("PIN-KEEP-A").expect("kept, read case-blind");
    assert_eq!(kept["expected"], json!(["pin-keep-a"]));
    assert_eq!(kept["presented"], json!(["address owned by pin-keep-b"]));
    assert!(kept["at"].as_i64().unwrap_or(0) > 0);
    forget("pin-keep-b");
}
