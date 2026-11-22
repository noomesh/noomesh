//! The dial-back behind `noo security pki push-nodes <node> --prove` (i1074 A).
//!
//! A node's leaf must name the address the gateway dials it at. That address
//! comes from the node's own heartbeat, so it is a claim, and a leaf for it is
//! issued only once the address is PROVEN to be served by this node: the
//! controller dials `https://<addr>:<port>` and accepts only a server that
//!
//! - presents a leaf that chains to this cluster's CA (no name check: every
//!   leaf carries the generic `localhost` / `node-agent` SANs, so a name
//!   match proves nothing), and
//! - whose SubjectPublicKeyInfo equals the controller's own copy of
//!   `pki/nodes/<node>/node.crt`, and
//! - signs the TLS 1.3 handshake (CertificateVerify) with that key.
//!
//! Only the holder of the node's CURRENT `node.key` completes that, and the
//! handshake's signature over fresh randoms makes it unreplayable (no nonce).
//! If another node's agent answers at the address, its key is not this
//! node's, so the proof fails. A TCP relay at the address that reaches the
//! real node passes, and rightly: the gateway needs exactly that the
//! key-holder is reachable there. The host must be an IP literal (a DNS name
//! would bind only the answer of the moment); `prove_target` refuses names. The agent asks for a client certificate and
//! the dial-back sends none: the handshake then ends with an alert, AFTER the
//! server's CertificateVerify was checked, which is all the proof needs.
//!
//! Nothing here issues or stages anything; `pki_push_nodes` does, after this
//! returns `Ok`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

/// DER of the first PEM block in `pem` (a certificate or a PKCS#8 key).
pub(crate) fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem).map_err(|e| format!("not PEM: {e}"))?;
    Ok(block.contents)
}

/// The SubjectPublicKeyInfo of a DER certificate.
pub(crate) fn spki_of(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|e| format!("not a certificate: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// Accepts exactly one leaf: CA-chained, SPKI-equal to `pinned_spki`, and
/// proven by its TLS 1.3 signature. `proven` turns true only then.
#[derive(Debug)]
struct PinnedLeaf {
    roots: RootCertStore,
    pinned_spki: Vec<u8>,
    provider: Arc<CryptoProvider>,
    /// The end entity passed `verify_server_cert` (chain + pin).
    leaf_ok: AtomicBool,
    /// ... and then signed the handshake with its key.
    proven: Arc<AtomicBool>,
    /// Why it failed, for the operator (first reason wins).
    why: Arc<Mutex<Option<String>>>,
}

impl PinnedLeaf {
    fn refuse(&self, why: String) -> rustls::Error {
        let mut slot = self.why.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(why.clone());
        }
        rustls::Error::General(why)
    }
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)
            .map_err(|e| self.refuse(format!("the presented certificate does not parse: {e}")))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )
        .ok();
        let presented = spki_of(end_entity).map_err(|e| self.refuse(e))?;
        if presented != self.pinned_spki {
            return Err(self.refuse(
                "the presented certificate is not this node's current leaf (its key differs from pki/nodes/<node>/node.crt): \
                 whatever answers at this address does not hold the node's key"
                    .to_string(),
            ));
        }
        self.leaf_ok.store(true, Ordering::SeqCst);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The config allows TLS 1.3 only; a 1.2 signature is never a proof.
        Err(self.refuse("TLS 1.2 offered: the proof needs TLS 1.3".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let ok = rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
            .map_err(|e| self.refuse(format!("the handshake signature does not verify: {e}")))?;
        // The signature is over THIS cert's key; prove only when this cert is
        // the one that passed chain + pin above.
        if self.leaf_ok.load(Ordering::SeqCst) && spki_of(cert).ok().as_deref() == Some(self.pinned_spki.as_slice()) {
            self.proven.store(true, Ordering::SeqCst);
        }
        Ok(ok)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Dial `addr:port` and prove that the server there holds the key of
/// `pinned_cert_pem` (this controller's copy of the node's leaf), under the
/// CA in `ca_pem`. `Ok(())` only on a complete proof.
pub(crate) fn prove_node_at(ca_pem: &[u8], pinned_cert_pem: &[u8], addr: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pem_to_der(ca_pem).map_err(|e| format!("the cluster CA: {e}"))?))
        .map_err(|e| format!("the cluster CA is not usable as a trust anchor: {e}"))?;
    let pinned_spki = spki_of(&pem_to_der(pinned_cert_pem).map_err(|e| format!("the node's leaf: {e}"))?)
        .map_err(|e| format!("the node's leaf: {e}"))?;
    let proven = Arc::new(AtomicBool::new(false));
    let why = Arc::new(Mutex::new(None));
    let verifier = Arc::new(PinnedLeaf {
        roots,
        pinned_spki,
        provider: provider.clone(),
        leaf_ok: AtomicBool::new(false),
        proven: proven.clone(),
        why: why.clone(),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3 config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // A resumed session skips the server's CertificateVerify: never resume.
    // (Each call builds its own config today; this pins it against a refactor
    // that shares one, 97.)
    config.resumption = rustls::client::Resumption::disabled();
    let sni = ServerName::try_from(addr.to_string()).map_err(|e| format!("{addr} is not a host name or IP: {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), sni).map_err(|e| format!("TLS client: {e}"))?;
    let target: SocketAddr = (addr, port)
        .to_socket_addrs()
        .map_err(|e| format!("{addr}:{port} does not resolve: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr}:{port} does not resolve"))?;
    let mut sock = TcpStream::connect_timeout(&target, timeout).map_err(|e| format!("no answer at {addr}:{port}: {e}"))?;
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    // Drive the handshake. It may end in an alert once the server asks for a
    // client certificate we do not send; the proof is decided before that.
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let _ = tls.write_all(b"");
    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);
    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(tls.sock).is_err() {
            break;
        }
    }
    if proven.load(Ordering::SeqCst) {
        return Ok(());
    }
    let reason = why.lock().unwrap_or_else(|p| p.into_inner()).clone();
    Err(reason.unwrap_or_else(|| format!("the TLS handshake with {addr}:{port} ended before the node proved its key")))
}

/// Is `addr` a private address (RFC 1918, CGNAT 100.64/10, link-local, IPv6
/// unique-local or link-local)? Only a private, unclaimed address gets the
/// `--prove` remedy in verify; a public one keeps the explicit push.
pub(crate) fn is_private_addr(addr: &str) -> bool {
    match addr.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments()[0];
            (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{ClusterCa, NodeRole};
    use std::net::TcpListener;

    /// A fresh scratch dir under the system temp dir (the pki tests' form).
    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir()
            .join(format!("noo-prove-{}", std::process::id()))
            .join(format!("{tag}-{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A cluster CA in a scratch dir, with `node` issued for 127.0.0.1.
    fn cluster(tag: &str, node: &str) -> ClusterCa {
        let ca = ClusterCa::new(scratch(tag));
        ca.generate_ca("Mesh Cluster CA", 30).expect("ca");
        ca.issue_node_cert(node, "127.0.0.1", 30, &["node-agent".to_string()], &[], &NodeRole::Worker).expect("leaf");
        ca
    }

    fn read(p: std::path::PathBuf) -> Vec<u8> {
        std::fs::read(p).expect("read")
    }

    /// A TLS 1.3 server on 127.0.0.1 presenting `cert`/`key`; with
    /// `client_ca` it REQUIRES a client certificate from that CA, as the node
    /// agent does. Serves one connection. Returns the port.
    fn serve_once(cert_pem: Vec<u8>, key_pem: Vec<u8>, client_ca: Option<Vec<u8>>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let chain = vec![CertificateDer::from(pem_to_der(&cert_pem).unwrap())];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(pem_to_der(&key_pem).unwrap().into());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let config = match client_ca {
            Some(ca) => {
                let mut roots = RootCertStore::empty();
                roots.add(CertificateDer::from(pem_to_der(&ca).unwrap())).unwrap();
                let v = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
                builder.with_client_cert_verifier(v).with_single_cert(chain, key).unwrap()
            }
            None => builder.with_no_client_auth().with_single_cert(chain, key).unwrap(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
            }
        });
        port
    }

    const T: Duration = Duration::from_secs(5);

    #[test]
    fn the_node_holding_its_own_key_proves_it_even_when_it_demands_a_client_cert() {
        let ca = cluster("a", "node_a");
        let crt = read(ca.dir.join("nodes/node_a/node.crt"));
        let port = serve_once(crt.clone(), read(ca.dir.join("nodes/node_a/node.key")), Some(read(ca.ca_cert_path())));
        prove_node_at(&read(ca.ca_cert_path()), &crt, "127.0.0.1", port, T).expect("proven");
    }

    #[test]
    fn another_node_answering_at_the_address_does_not_prove_this_one() {
        let ca = cluster("a", "node_a");
        ca.issue_node_cert("node_b", "127.0.0.1", 30, &["node-agent".to_string()], &[], &NodeRole::Worker).unwrap();
        // node_b answers; the pin is node_a's leaf.
        let port = serve_once(read(ca.dir.join("nodes/node_b/node.crt")), read(ca.dir.join("nodes/node_b/node.key")), None);
        let e = prove_node_at(&read(ca.ca_cert_path()), &read(ca.dir.join("nodes/node_a/node.crt")), "127.0.0.1", port, T)
            .unwrap_err();
        assert!(e.contains("not this node's current leaf"), "{e}");
    }

    #[test]
    fn a_leaf_from_another_ca_does_not_chain_and_does_not_prove() {
        let ca = cluster("a", "node_a");
        let rogue = cluster("rogue", "node_a");
        let port = serve_once(read(rogue.dir.join("nodes/node_a/node.crt")), read(rogue.dir.join("nodes/node_a/node.key")), None);
        let e = prove_node_at(&read(ca.ca_cert_path()), &read(ca.dir.join("nodes/node_a/node.crt")), "127.0.0.1", port, T)
            .unwrap_err();
        assert!(e.contains("does not chain"), "{e}");
    }

    #[test]
    fn the_same_key_under_a_rogue_ca_still_does_not_chain() {
        // A stolen key re-certified by another CA: SPKI-equal, wrong chain.
        let ca = cluster("a", "node_a");
        let rogue = ClusterCa::new(scratch("r"));
        rogue.generate_ca("Mesh Cluster CA", 30).unwrap();
        let key_pem = String::from_utf8(read(ca.dir.join("nodes/node_a/node.key"))).unwrap();
        let key = rcgen::KeyPair::from_pem(&key_pem).unwrap();
        let rogue_issuer = rcgen::Issuer::from_ca_cert_pem(
            &String::from_utf8(read(rogue.ca_cert_path())).unwrap(),
            rcgen::KeyPair::from_pem(&String::from_utf8(read(rogue.ca_key_path())).unwrap()).unwrap(),
        )
        .unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["node_a".to_string()]).unwrap();
        p.subject_alt_names.push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let forged = p.signed_by(&key, &rogue_issuer).unwrap();
        let port = serve_once(forged.pem().into_bytes(), key_pem.into_bytes(), None);
        let e = prove_node_at(&read(ca.ca_cert_path()), &read(ca.dir.join("nodes/node_a/node.crt")), "127.0.0.1", port, T)
            .unwrap_err();
        assert!(e.contains("does not chain"), "{e}");
    }

    /// Serves `cert_pem` signed with `key_pem` even when they do not match
    /// (rustls' resolver does not check): a server replaying the node's
    /// PUBLIC certificate without its key.
    #[derive(Debug)]
    struct Fixed(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn serve_mismatched_once(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = provider
            .key_provider
            .load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(pem_to_der(&key_pem).unwrap().into()))
            .unwrap();
        let ck = rustls::sign::CertifiedKey::new(vec![CertificateDer::from(pem_to_der(&cert_pem).unwrap())], key);
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(ck))));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
            }
        });
        port
    }

    #[test]
    fn the_nodes_certificate_without_its_key_does_not_prove() {
        let ca = cluster("a", "node_a");
        ca.issue_node_cert("node_b", "127.0.0.1", 30, &["node-agent".to_string()], &[], &NodeRole::Worker).unwrap();
        // node_a's public certificate, but the handshake signed with node_b's key.
        let crt = read(ca.dir.join("nodes/node_a/node.crt"));
        let port = serve_mismatched_once(crt.clone(), read(ca.dir.join("nodes/node_b/node.key")));
        let e = prove_node_at(&read(ca.ca_cert_path()), &crt, "127.0.0.1", port, T).unwrap_err();
        assert!(e.contains("signature does not verify"), "{e}");
    }

    #[test]
    fn nothing_listening_is_no_proof() {
        let ca = cluster("a", "node_a");
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // dropped: closed
        let e = prove_node_at(&read(ca.ca_cert_path()), &read(ca.dir.join("nodes/node_a/node.crt")), "127.0.0.1", port, T)
            .unwrap_err();
        assert!(e.contains("no answer"), "{e}");
    }

    #[test]
    fn the_client_never_resumes_a_session() {
        let code = include_str!("node_prove.rs");
        let body = crate::test_src::fn_body(code, "pub(crate) fn prove_node_at(");
        assert!(body.contains("config.resumption = rustls::client::Resumption::disabled();"), "a resumed session would skip CertificateVerify");
    }

    #[test]
    fn private_addresses_are_rfc1918_cgnat_link_local_and_ula() {
        for a in ["10.1.2.3", "172.16.0.9", "192.168.1.5", "100.64.0.7", "100.64.0.255", "169.254.1.1", "fd00::1", "fe80::1"] {
            assert!(is_private_addr(a), "{a}");
        }
        for a in ["8.8.8.8", "100.128.0.1", "100.63.255.255", "2001:db8::1", "node_a", ""] {
            assert!(!is_private_addr(a), "{a}");
        }
    }
}
