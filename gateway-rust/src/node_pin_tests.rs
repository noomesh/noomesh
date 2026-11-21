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
    assert!(check_leaf("10.231.2.1", &owners, a.cert.der()).is_ok());
    let m = check_leaf("10.231.2.1", &owners, b.cert.der()).unwrap_err();
    assert_eq!(m.presented, vec!["node_b".to_string()]);
    assert_eq!(m.expected, vec!["node_a".to_string()]);
    // A host the book does not place a node on: nothing to pin.
    assert!(check_leaf("10.231.2.1", &[], b.cert.der()).is_ok());
    // A service leaf on a node's host (an add-on door) is not judged here.
    let door = node_leaf(&ca, "some-door", "Mesh Cluster Service", &["10.231.2.1"]);
    assert!(check_leaf("10.231.2.1", &owners, door.cert.der()).is_ok());
    // A sensor companion presents its machine's node leaf.
    assert!(check_leaf("10.231.2.1", &["node_a-sensors".to_string()], a.cert.der()).is_ok());
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
