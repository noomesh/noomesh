// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The integration suites' mock-gateway TLS (shared by
//! `gateway_integration.rs` and `cli_piece.rs` through `#[path]`).

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// The mock gateways' TLS identity: a throwaway CA and a 127.0.0.1 leaf,
/// minted once per test process (nothing with a key is committed). The CLI
/// has no plain-http lane (1242 finding 7), so every mock serves TLS and every
/// child trusts this CA through `NOO_TLS_CA` (see `run`).
pub struct TestTls {
    pub ca_path: std::path::PathBuf,
    pub server: std::sync::Arc<rustls::ServerConfig>,
}

pub fn test_tls() -> &'static TestTls {
    static TLS: std::sync::OnceLock<TestTls> = std::sync::OnceLock::new();
    TLS.get_or_init(|| {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "noo integration test CA");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let dir = std::env::temp_dir().join(format!("noo-it-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("ca.crt");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
        TestTls { ca_path, server: std::sync::Arc::new(server) }
    })
}

pub type TlsStream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// Wrap one accepted connection in the mock gateway's TLS (the handshake
/// completes on the first read).
pub fn tls_accept(tcp: TcpStream) -> Option<TlsStream> {
    tcp.set_nonblocking(false).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let conn = rustls::ServerConnection::new(test_tls().server.clone()).ok()?;
    Some(rustls::StreamOwned::new(conn, tcp))
}

/// Send `response` and close the TLS session cleanly.
pub fn tls_reply(stream: &mut TlsStream, response: &str) {
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    stream.conn.send_close_notify();
    let _ = stream.flush();
}
