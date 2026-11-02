// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Test-only TLS for in-crate mock gateways.
//!
//! The CLI has no plain-http lane (1242 finding 7): `http::resolve_trust`
//! refuses every `http://` URL, loopback included. A unit test that drives a
//! mock gateway therefore serves TLS with a throwaway CA minted once per test
//! process (nothing with a key is committed), and trusts it on the test
//! thread with [`trust`] (`http::trust_test_ca`, the in-crate counterpart of
//! the integration suites' `NOO_TLS_CA`; no process environment is touched).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub struct TestTls {
    pub ca_path: PathBuf,
    pub server: Arc<rustls::ServerConfig>,
}

pub fn test_tls() -> &'static TestTls {
    static TLS: OnceLock<TestTls> = OnceLock::new();
    TLS.get_or_init(|| {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "noo unit-test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let dir = std::env::temp_dir().join(format!("noo-unit-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("ca.crt");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
        TestTls { ca_path, server: Arc::new(server) }
    })
}

pub type TlsStream = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

/// Wrap one accepted connection in the mock gateway's TLS (the handshake
/// completes on the first read or write).
pub fn accept(tcp: std::net::TcpStream) -> Option<TlsStream> {
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let conn = rustls::ServerConnection::new(test_tls().server.clone()).ok()?;
    Some(rustls::StreamOwned::new(conn, tcp))
}

/// End the TLS session cleanly after the response is written.
pub fn close(stream: &mut TlsStream) {
    use std::io::Write as _;
    let _ = stream.flush();
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// Trust the mock gateways' CA for this test thread's requests until the
/// guard drops.
pub fn trust() -> impl Drop {
    crate::http::trust_test_ca(&test_tls().ca_path)
}
