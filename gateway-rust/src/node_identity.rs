// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node identity from the client certificate.
//!
//! ## The problem this replaces
//!
//! A node authenticates to the gateway with a cluster-HMAC token whose
//! first field NAMES the node. That name is a claim, not a proof: the
//! token is signed with `NOO_CLUSTER_SECRET`, which every node holds. So
//! wave A′ can scope a node token to `NODE_ROUTES` and to its own node id,
//! but nothing stops a node from minting a token that names a DIFFERENT
//! node and operating as it.
//!
//! Per-node certificates already exist and already carry a per-node
//! identity — they were just never used in this direction. Deriving the
//! identity from the verified client certificate removes a shared
//! credential rather than adding another, and revocation is the PKI's
//! job, which it already does.
//!
//! ## How it works
//!
//! `NOO_MTLS_GATEWAY` makes the gateway verify a presented client
//! certificate against the cluster CA (see `tls.rs`; verification is
//! optional, so callers without one — the dashboard, the CLI, the MCP
//! doors — are unaffected). This module wraps the TLS acceptor so that,
//! once the handshake completes, the verified peer's identity is attached
//! to every request on that connection as [`VerifiedPeer`].
//!
//! `auth.rs` then treats a `VerifiedPeer` as authoritative over the token's
//! claimed actor: a node presenting node A's certificate cannot act as
//! node B, whatever its token says.
//!
//! ## Blast radius
//!
//! The wrapper is installed ONLY when `NOO_MTLS_GATEWAY` is on. With it
//! off — the default — the serving path is exactly what it was, because
//! a bug in an acceptor takes down every request rather than one route.

use std::io;
use std::pin::Pin;

use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

/// The identity the gateway proved at the TLS handshake, as opposed to the
/// one a request claims. Present only when the peer presented a
/// certificate the cluster CA signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The node id the certificate names.
    pub node: String,
}

/// Pull the node id out of a verified peer certificate.
///
/// Node certs are issued by `pki issue-node` with the node id as the
/// subject CN and as the first DNS SAN. The SAN set also carries
/// `localhost` and `node-agent`, which are conveniences rather than
/// identities and must never be returned as one.
pub fn identity_from_cert(der: &[u8]) -> Option<VerifiedPeer> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    // A service leaf (`O=Mesh Cluster Service`, CN=prometheus, grafana, …)
    // names a sidecar, not a node. Reading its CN as a node id would let the
    // scraper's certificate stand for a node called "prometheus".
    if is_service_cert(&cert) {
        return None;
    }
    // An OPERATOR leaf (`O=Mesh Cluster Operator`) names a
    // person, never a node: its CN must not stand for a node id either.
    if is_operator_cert(&cert) {
        return None;
    }
    // Prefer the CN: `issue_node_cert` sets it to the node id, and it is a
    // single value rather than a set to choose from.
    if let Some(cn) = cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok()) {
        if is_identity(cn) {
            return Some(VerifiedPeer { node: cn.to_string() });
        }
    }
    // Fall back to the first DNS SAN that is not a convenience name.
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = gn {
                if is_identity(d) {
                    return Some(VerifiedPeer { node: (*d).to_string() });
                }
            }
        }
    }
    None
}

/// The cluster-PKI organization of a SERVICE leaf (`noo security pki
/// issue-service <svc>`): a sidecar such as the Prometheus scraper, never a
/// node, never the controller. The node agent reads the same value
/// (`node-agent-go/internal/auth/principal.go` `serviceOrg`).
pub const SERVICE_ORG: &str = "Mesh Cluster Service";

/// A verified service leaf: which sidecar is calling. Attached next to
/// [`VerifiedPeer`], and only when the CA verified the certificate at the
/// handshake. It opens exactly what `auth.rs` grants a named service —
/// today, `GET /metrics` for `prometheus` — and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedService(pub String);

fn is_service_cert(cert: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    cert.subject()
        .iter_organization()
        .filter_map(|o| o.as_str().ok())
        .any(|o| o.trim().eq_ignore_ascii_case(SERVICE_ORG))
}

/// The service a verified leaf names, if it is a service leaf.
pub fn service_from_cert(der: &[u8]) -> Option<VerifiedService> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    if !is_service_cert(&cert) {
        return None;
    }
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.trim();
    (!cn.is_empty()).then(|| VerifiedService(cn.to_string()))
}

/// The cluster-PKI organization of an OPERATOR leaf (`noo security pki
/// issue-client <operator>`): a person, never a node or a
/// service. Disjoint from the node, service and gateway organizations, so
/// no verifier that keys on those (here, `node_identity`; on a node,
/// `node-agent-go/internal/auth/principal.go`) grants it anything.
pub const OPERATOR_ORG: &str = "Mesh Cluster Operator";

/// The prefix the CLI puts on an operator leaf's CN: `operator:<account>`.
/// A CN that cannot be read as a node id even by a verifier that ignores
/// the organization.
pub const OPERATOR_CN_PREFIX: &str = "operator:";

/// A verified operator leaf: which mesh ACCOUNT the certificate was issued
/// to. Attached only when the CA verified the certificate at the handshake.
/// It grants nothing on its own — posture writes need it TOGETHER with an
/// Admin token bound to the same certificate (`crate::operator_auth`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOperator(pub String);

fn is_operator_cert(cert: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    cert.subject()
        .iter_organization()
        .filter_map(|o| o.as_str().ok())
        .any(|o| o.trim().eq_ignore_ascii_case(OPERATOR_ORG))
}

/// The account a verified operator leaf names, if it is one. Both halves
/// are required: the organization AND the `operator:` CN prefix.
pub fn operator_from_cert(der: &[u8]) -> Option<VerifiedOperator> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    if !is_operator_cert(&cert) {
        return None;
    }
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.trim();
    let name = cn.strip_prefix(OPERATOR_CN_PREFIX)?.trim();
    (!name.is_empty()).then(|| VerifiedOperator(name.to_string()))
}

/// The RFC 8705 confirmation value of a presented client certificate:
/// base64url(SHA-256(DER)), unpadded — the `x5t#S256` thumbprint.
///
/// Attached to every request on a connection that presented a certificate,
/// whether or not that certificate names a node. [`VerifiedPeer`] answers
/// "which node is this"; this answers "which certificate is this", and a
/// client certificate issued to an integrator names no node at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerThumbprint(pub String);

/// Compute the `x5t#S256` thumbprint of a DER-encoded certificate.
pub fn thumbprint_of(der: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// Names that appear in every node cert and identify nobody.
fn is_identity(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && !matches!(n, "localhost" | "node-agent" | "gateway")
}

/// Wraps the rustls acceptor and attaches [`VerifiedPeer`] to the
/// connection's requests.
#[derive(Clone)]
pub struct NodeIdentityAcceptor {
    inner: RustlsAcceptor,
}

impl NodeIdentityAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for NodeIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    // Two extensions, nested: the node identity (which node) and the
    // certificate thumbprint (which certificate). They are separate
    // because a client certificate can be one without the other — an
    // integrator's cert proves a holder and names no node.
    type Service = tower_http::add_extension::AddExtension<
        tower_http::add_extension::AddExtension<
            tower_http::add_extension::AddExtension<
                tower_http::add_extension::AddExtension<S, Option<VerifiedPeer>>,
                Option<PeerThumbprint>,
            >,
            Option<VerifiedService>,
        >,
        Option<VerifiedOperator>,
    >;
    type Future =
        Pin<Box<dyn std::future::Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            // After the handshake the connection knows what it verified.
            // `None` is the ordinary case: a browser, the CLI or an MCP
            // client presenting no certificate. Only a certificate the
            // cluster CA signed reaches here at all — `tls.rs` rejects an
            // invalid one before this point.
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|c| c.as_ref().to_vec());
            let thumbprint = leaf.as_deref().map(|der| PeerThumbprint(thumbprint_of(der)));
            let peer = leaf.as_deref().and_then(identity_from_cert);
            if let Some(p) = &peer {
                tracing::debug!(node = %p.node, "tls_peer_identified");
            }
            let service = tower_http::add_extension::AddExtension::new(service, peer);
            let service = tower_http::add_extension::AddExtension::new(service, thumbprint);
            let svc = leaf.as_deref().and_then(service_from_cert);
            let service = tower_http::add_extension::AddExtension::new(service, svc);
            let op = leaf.as_deref().and_then(operator_from_cert);
            let service = tower_http::add_extension::AddExtension::new(service, op);
            Ok((stream, service))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed leaf with the given subject; the parsers read the
    /// subject only, so the signer does not matter here.
    fn leaf(cn: &str, org: &str) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.distinguished_name.push(rcgen::DnType::OrganizationName, org);
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        p.self_signed(&kp).unwrap().der().to_vec()
    }

    /// The scraper's leaf is a service, not a node: it must not become a
    /// node identity called "prometheus", and it must be recognised as the
    /// service it names.
    #[test]
    fn a_service_leaf_names_a_service_and_never_a_node() {
        let der = leaf("prometheus", "Mesh Cluster Service");
        assert_eq!(identity_from_cert(&der), None);
        assert_eq!(service_from_cert(&der), Some(VerifiedService("prometheus".into())));
    }

    #[test]
    fn a_node_leaf_names_a_node_and_never_a_service() {
        let der = leaf("host3", "Mesh Cluster Node");
        assert_eq!(identity_from_cert(&der), Some(VerifiedPeer { node: "host3".into() }));
        assert_eq!(service_from_cert(&der), None);
        let gw = leaf("host8", "Mesh Cluster Gateway");
        assert_eq!(service_from_cert(&gw), None, "the controller's leaf is not a service");
    }

    /// an operator's leaf names a PERSON. It must never
    /// read as a node (whose CN it could otherwise collide with) or a
    /// service, and both the organization and the CN prefix are required.
    #[test]
    fn an_operator_leaf_names_an_account_and_never_a_node_or_service() {
        let der = leaf("operator:alice", OPERATOR_ORG);
        assert_eq!(operator_from_cert(&der), Some(VerifiedOperator("alice".into())));
        assert_eq!(identity_from_cert(&der), None, "an operator leaf is not a node");
        assert_eq!(service_from_cert(&der), None, "an operator leaf is not a service");
        // The prefix without the organization (a node called "operator:x"
        // is impossible anyway) and the organization without the prefix
        // are both refused.
        assert_eq!(operator_from_cert(&leaf("operator:alice", "Mesh Cluster Node")), None);
        assert_eq!(operator_from_cert(&leaf("alice", OPERATOR_ORG)), None);
        assert_eq!(operator_from_cert(&leaf("host3", "Mesh Cluster Node")), None);
    }

    #[test]
    fn convenience_names_are_not_identities() {
        // Every node cert carries these. Returning one as the peer's
        // identity would make every node look like the same principal —
        // the exact property this replaces.
        assert!(!is_identity("localhost"));
        assert!(!is_identity("node-agent"));
        assert!(!is_identity("gateway"));
        assert!(!is_identity("  "));
        assert!(is_identity("host3"));
        assert!(is_identity("host8"));
    }

    #[test]
    fn a_node_cert_yields_its_node_id() {
        // Issue a real cert the way the CLI does and read the identity
        // back out of the DER, so the two sides cannot drift apart.
        let tmp = std::env::temp_dir().join(format!("noo-nodeid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // A minimal self-signed cert with CN = the node id.
        let mut params = rcgen::CertificateParams::new(vec!["host3".to_string(), "localhost".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "host3");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();

        let id = identity_from_cert(&der).expect("identity");
        assert_eq!(id.node, "host3");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// noo-trellion and noo-trellion-intel dial this gateway
    /// presenting their OWN service leaves, where both used to present the
    /// controller's gateway leaf. Issued with the CLI's service profile
    /// (`ClusterCa::issue_service_cert`: CN=<svc>, O=Mesh Cluster Service,
    /// EKU clientAuth+serverAuth) under a CA, the leaf must pass the client
    /// verifier `tls::load_rustls_config` builds, and must name the SERVICE
    /// it is — never a node. The gateway's principal for trellion is its
    /// credential (svc:trellion's key, or the controller-secret actor
    /// `trellion`); the certificate only has to not contradict it. The old
    /// gateway leaf did: its CN (the controller's hostname) became a
    /// VerifiedPeer, which `auth.rs` compares against a fleet token's actor.
    #[test]
    fn a_trellion_addon_leaf_is_accepted_as_that_service() {
        use rustls::pki_types::{CertificateDer, UnixTime};
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Mesh Cluster CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        // The same builder tls.rs uses: optional client auth, cluster CA roots.
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
            .allow_unauthenticated()
            .build()
            .unwrap();

        let issue = |svc: &str, ekus: Vec<rcgen::ExtendedKeyUsagePurpose>| -> Vec<u8> {
            let mut p = rcgen::CertificateParams::new(vec![
                svc.to_string(), format!("noo-{svc}"), "localhost".into(),
            ]).unwrap();
            p.distinguished_name = rcgen::DistinguishedName::new();
            p.distinguished_name.push(rcgen::DnType::CommonName, svc);
            p.distinguished_name.push(rcgen::DnType::OrganizationName, SERVICE_ORG);
            p.extended_key_usages = ekus;
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            p.signed_by(&kp, &ca, &ca_key).unwrap().der().to_vec()
        };
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};
        // noo-worker joined in 1276's second half: same profile, same verdict.
        for svc in ["trellion", "trellion-intel", "worker"] {
            let der = issue(svc, vec![ClientAuth, ServerAuth]);
            verifier
                .verify_client_cert(&CertificateDer::from(der.clone()), &[], UnixTime::now())
                .unwrap_or_else(|e| panic!("{svc}'s own leaf refused at the handshake: {e}"));
            assert_eq!(service_from_cert(&der), Some(VerifiedService(svc.into())));
            assert_eq!(identity_from_cert(&der), None, "{svc} is a service, never a node");
        }
        // The verifier does read the EKU: a server-only leaf is refused, so
        // the clientAuth the CLI issues is load-bearing, not decoration.
        let server_only = issue("trellion", vec![ServerAuth]);
        assert!(verifier.verify_client_cert(&CertificateDer::from(server_only), &[], UnixTime::now()).is_err());
    }

    #[test]
    fn garbage_is_not_an_identity() {
        assert_eq!(identity_from_cert(b"not a certificate"), None);
        assert_eq!(identity_from_cert(&[]), None);
    }
}
