// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller pins the node it dials (i1174).
//!
//! The cluster CA signs every node's leaf, and a leaf carries the node's id
//! as its CN and first DNS SAN (`noo-cli/src/pki.rs` `issue_node_cert`,
//! `O=Mesh Cluster Node`). A stock rustls client checks only that the leaf
//! chains to the cluster CA and covers the dialed address. This module adds
//! the node's NAME to that check, in two places:
//!
//! 1. **The address book.** The gateway's own record of which node owns
//!    which agent address (`host:port`), fed ONLY by what the gateway
//!    accepted from a node's authenticated heartbeat or registration (and
//!    seeded from `mesh_nodes` at startup), the same way
//!    [`crate::node_agent_auth::note`] keeps its capability map. The newest
//!    accepted report owns its addresses; a heartbeat cannot claim another
//!    node's address (`routes::cluster::address_refusal`), so an address has
//!    one owner.
//! 2. **The verifier.** [`NodePinVerifier`] runs webpki's normal
//!    verification first, then: when the dialed host is in the book and the
//!    presented leaf is a NODE leaf, the leaf must name a node that owns an
//!    agent address on that host. Any other leaf (a service door, the
//!    gateway's own listener, an add-on) is verified exactly as before. It
//!    is installed in [`crate::tls::cluster_rustls_config`], so every client
//!    built from the cluster config carries it: the shared unary, stream and
//!    failover clients and the WebSocket relay.
//!
//! A link resolved BY NODE ([`crate::node_link::NodeLink::from_record`],
//! [`crate::node_link::NodeLink::for_node_ip`]) also checks the book before
//! it is built ([`may_dial`]): the address it would dial must not belong to
//! another node. Together: a call meant for node X leaves the gateway only
//! towards an address the book gives to X, and its handshake succeeds only
//! against a leaf that names X.
//!
//! Why a book read by the verifier rather than one client per node: the
//! connection pool is keyed by `host:port`, not by the call, and more than
//! sixty call sites hold an agent URL rather than a link. A per-call
//! expectation would need every one of them to carry the node; the book
//! gives each address its one expected owner instead, at the single point
//! every handshake passes through.
//!
//! What the verifier cannot see is the PORT (rustls hands it the server
//! name, not the socket address). Two agents on one host (a sensor
//! companion on :8082 beside the node's agent on :8081) therefore share a
//! host's accepted names. That is one machine, and the companion presents
//! the host node's leaf anyway (`docker-compose.cluster.yml`
//! `node-agent-sensors`); the agent's own target check
//! (`X-Noo-Node`, [`TARGET_HEADER`]) tells the two apart.
//!
//! A refusal is typed ([`NodeIdentityMismatch`], carried inside the rustls
//! error) and logged as `node_identity_mismatch` with the dialed host, the
//! expected node(s) and the names the leaf presented.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use serde_json::Value;

/// The header the gateway sends on every call to a node agent: the id of
/// the node the call is meant for. The agent refuses a call that names
/// another node (421 `wrong_node`), and, once the controller says so in its
/// desired config, a controller call that names none.
pub const TARGET_HEADER: &str = "X-Noo-Node";

/// The heartbeat field an agent that checks [`TARGET_HEADER`] reports.
pub(crate) const CHECKS_TARGET_FIELD: &str = "checks_target_node";

/// The heartbeat field naming whether the agent currently REFUSES a
/// header-less controller call (the desired-config flag it last applied).
pub(crate) const REQUIRES_TARGET_FIELD: &str = "requires_target_node";

/// The desired-config field that tells an agent to refuse a header-less
/// controller call.
pub(crate) const REQUIRE_TARGET_DESIRED: &str = "require_target_node";

/// The organization the cluster CA stamps on a node agent's leaf.
pub(crate) const NODE_ORG: &str = "Mesh Cluster Node";

/// A sensor companion (`<node>-sensors`) runs on its node's machine and
/// presents that node's leaf.
const COMPANION_SUFFIX: &str = "-sensors";

#[derive(Clone, Debug)]
struct Owned {
    authorities: Vec<String>,
    self_node: bool,
    /// When the gateway last accepted a report from the node.
    seen: std::time::Instant,
}

impl Owned {
    /// A node not heard from for [`BOOK_TTL`] owns nothing: the `mesh_nodes`
    /// record it came from has expired too (120 s TTL), and its address may
    /// be another machine's now.
    fn live(&self) -> bool {
        self.seen.elapsed() < BOOK_TTL
    }
}

const BOOK_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// node id → the agent addresses (`host:port`, lower-cased) it owns.
static BOOK: LazyLock<RwLock<HashMap<String, Owned>>> = LazyLock::new(Default::default);

/// Record the addresses a node's accepted heartbeat / registration gives it
/// (`record` as written to `mesh_nodes`). The newest report owns them: they
/// are struck from every other node first.
pub(crate) fn note(node_id: &str, record: &Value) {
    let authorities = crate::node_agent_auth::record_authorities(record);
    let self_node = record.get("self_node").and_then(Value::as_bool) == Some(true);
    let Ok(mut book) = BOOK.write() else { return };
    book.remove(node_id);
    for owned in book.values_mut() {
        owned.authorities.retain(|a| !authorities.contains(a));
    }
    if !authorities.is_empty() || self_node {
        book.insert(node_id.to_string(), Owned { authorities, self_node, seen: std::time::Instant::now() });
    }
}

/// A forgotten node owns nothing (`noo cluster forget`).
pub(crate) fn forget(node_id: &str) {
    if let Ok(mut book) = BOOK.write() {
        book.remove(node_id);
    }
}

/// The node that owns the agent address `authority` (`host:port`).
pub(crate) fn owner(authority: &str) -> Option<String> {
    let a = authority.to_ascii_lowercase();
    let book = BOOK.read().ok()?;
    book.iter().find(|(_, o)| o.live() && o.authorities.contains(&a)).map(|(n, _)| n.clone())
}

/// The node that owns the agent at `url`, if the book knows it.
pub(crate) fn owner_of_url(url: &str) -> Option<String> {
    owner(&crate::node_agent_auth::authority(url)?)
}

/// Every node that owns an agent address on `host`.
pub(crate) fn owners_at_host(host: &str) -> Vec<String> {
    let host = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    let Ok(book) = BOOK.read() else { return Vec::new() };
    let mut out: Vec<String> = book
        .iter()
        .filter(|(_, o)| o.live() && o.authorities.iter().any(|a| host_of_authority(a) == host))
        .map(|(n, _)| n.clone())
        .collect();
    out.sort();
    out
}

/// The node on the controller's own device (its record says `self_node`).
pub(crate) fn self_node() -> Option<String> {
    let book = BOOK.read().ok()?;
    book.iter().find(|(_, o)| o.live() && o.self_node).map(|(n, _)| n.clone())
}

/// Every address the book gives to a node other than `node_id`, as
/// `(owner, host)`: the claims a heartbeat's address is checked against.
pub(crate) fn hosts_claimed_by_others(node_id: &str) -> Vec<(String, String)> {
    let Ok(book) = BOOK.read() else { return Vec::new() };
    let mut out = Vec::new();
    for (n, o) in book.iter() {
        if !o.live() || n.eq_ignore_ascii_case(node_id) || same_machine(n, node_id) {
            continue;
        }
        for a in &o.authorities {
            out.push((n.clone(), host_of_authority(a).to_string()));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The hosts the self node's agent is reached at.
pub(crate) fn self_node_hosts() -> Vec<String> {
    let Ok(book) = BOOK.read() else { return Vec::new() };
    let mut out: Vec<String> = book
        .values()
        .filter(|o| o.live() && o.self_node)
        .flat_map(|o| o.authorities.iter().map(|a| host_of_authority(a).to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn host_of_authority(a: &str) -> &str {
    // `host:port`; an IPv6 host was stored without brackets, so split at
    // the LAST colon.
    a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
}

/// The names a leaf may carry to stand for `node`: its id, and for a sensor
/// companion its machine's node id.
pub(crate) fn accepted_names(node: &str) -> Vec<String> {
    let n = node.trim().to_ascii_lowercase();
    let mut out = vec![n.clone()];
    if let Some(stem) = n.strip_suffix(COMPANION_SUFFIX) {
        if !stem.is_empty() {
            out.push(stem.to_string());
        }
    }
    out
}

/// `a` and `b` are the same machine: the same node, or a node and its
/// sensor companion.
pub(crate) fn same_machine(a: &str, b: &str) -> bool {
    let (na, nb) = (accepted_names(a), accepted_names(b));
    na.iter().any(|x| nb.contains(x))
}

/// A link for `node` may dial `base` only when the book does not give that
/// address to another node.
pub(crate) fn may_dial(node: &str, base: &str) -> Result<(), NodeIdentityMismatch> {
    let Some(authority) = crate::node_agent_auth::authority(base) else { return Ok(()) };
    match owner(&authority) {
        Some(other) if !other.eq_ignore_ascii_case(node) => {
            let m = NodeIdentityMismatch {
                host: authority,
                expected: vec![node.to_string()],
                presented: vec![format!("address owned by {other}")],
            };
            let _ = node;
            m.log();
            Err(m)
        }
        _ => Ok(()),
    }
}

/// What a leaf says about itself: whether it is a node leaf, and the names
/// (CN and DNS SANs, lower-cased) it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafNames {
    pub node_leaf: bool,
    pub names: Vec<String>,
}

pub(crate) fn leaf_names(der: &[u8]) -> Option<LeafNames> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let node_leaf = cert
        .subject()
        .iter_organization()
        .filter_map(|o| o.as_str().ok())
        .any(|o| o.trim().eq_ignore_ascii_case(NODE_ORG));
    let mut names: Vec<String> = Vec::new();
    if let Some(cn) = cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok()) {
        names.push(cn.trim().to_ascii_lowercase());
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = gn {
                let d = d.trim().to_ascii_lowercase();
                if !names.contains(&d) {
                    names.push(d);
                }
            }
        }
    }
    names.retain(|n| !n.is_empty() && n != "localhost");
    Some(LeafNames { node_leaf, names })
}

/// The pin itself, pure: `owners` are the nodes the book places on the
/// dialed `host`. No owner: nothing to pin (the address is not a node
/// agent's the gateway knows). At an address the book gives to a node,
/// only a node leaf naming one of the owners passes (i1174). The one
/// exception is the controller's own machine (`self_owned`: an owner is
/// the self node), where the gateway's and the stack services' leaves
/// legitimately answer on the same address. Elsewhere no other leaf
/// carries a node's address (node backend doors name only 127.0.0.1;
/// add-on and role leaves carry no IP), so refusing one costs nothing
/// and keeps the pin from resting on how other leaves are issued.
pub(crate) fn check_leaf(host: &str, owners: &[String], self_owned: bool, der: &[u8]) -> Result<(), NodeIdentityMismatch> {
    if owners.is_empty() {
        return Ok(());
    }
    let expected: Vec<String> = owners.iter().flat_map(|o| accepted_names(o)).collect();
    let Some(leaf) = leaf_names(der) else {
        return Err(NodeIdentityMismatch {
            host: host.to_string(),
            expected,
            presented: vec!["an unreadable certificate".into()],
        });
    };
    if !leaf.node_leaf {
        if self_owned {
            return Ok(());
        }
        return Err(NodeIdentityMismatch {
            host: host.to_string(),
            expected,
            presented: vec![format!("a certificate that is not a node's ({})", leaf.names.join(", "))],
        });
    }
    if leaf.names.iter().any(|n| expected.contains(n)) {
        return Ok(());
    }
    Err(NodeIdentityMismatch { host: host.to_string(), expected, presented: leaf.names })
}

/// A node agent answered with a leaf that does not name the node the
/// gateway's records place at the dialed address (or a link for one node
/// would dial an address the book gives to another).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentityMismatch {
    /// The dialed host (or `host:port`).
    pub host: String,
    /// The node name(s) the gateway expected there.
    pub expected: Vec<String>,
    /// The names the leaf carried.
    pub presented: Vec<String>,
}

impl NodeIdentityMismatch {
    /// Keep this refusal as the latest for each of `nodes` (the nodes the
    /// call was meant for), for `noo cluster verify`'s `node identity` row.
    pub(crate) fn record_for(&self, nodes: &[String]) {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Ok(mut last) = LAST_MISMATCH.write() {
            for n in nodes {
                last.insert(n.trim().to_ascii_lowercase(), (self.clone(), std::time::Instant::now(), at));
            }
        }
    }

    pub(crate) fn log(&self) {
        // Once a minute per address and expectation: a held mismatch is
        // judged on every routing pass.
        let key = format!("node_identity_mismatch|{}|{}", self.host, self.expected.join(","));
        if !crate::legacy_lanes::log_due(&key, std::time::Duration::from_secs(60)) {
            return;
        }
        tracing::warn!(
            node = %self.expected.first().map(String::as_str).unwrap_or(""),
            host = %self.host,
            expected = %self.expected.join(","),
            presented = %self.presented.join(","),
            "node_identity_mismatch"
        );
    }
}

impl std::fmt::Display for NodeIdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node_identity_mismatch: the agent at {} is not {} (it presented {}); the call was refused",
            self.host,
            self.expected.join(" or "),
            self.presented.join(", ")
        )
    }
}

impl std::error::Error for NodeIdentityMismatch {}

/// The [`NodeIdentityMismatch`] inside a failed call's error chain, if the
/// call was refused by the pin.
pub(crate) fn identity_mismatch(err: &(dyn std::error::Error + 'static)) -> Option<NodeIdentityMismatch> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(m) = e.downcast_ref::<NodeIdentityMismatch>() {
            return Some(m.clone());
        }
        if let Some(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(o))) = e.downcast_ref::<rustls::Error>() {
            if let Some(m) = o.0.downcast_ref::<NodeIdentityMismatch>() {
                return Some(m.clone());
            }
        }
        // As `node_agent_auth::foreign_tls`: hyper wraps the rustls error in
        // io::Error, whose `source()` skips the error it wraps.
        cur = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io.get_ref().map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    None
}

fn server_host(name: &rustls::pki_types::ServerName<'_>) -> String {
    match name {
        rustls::pki_types::ServerName::DnsName(d) => d.as_ref().to_ascii_lowercase(),
        rustls::pki_types::ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        _ => String::new(),
    }
}

/// webpki's verification, then the node-name pin ([`check_leaf`] against
/// the book's owners of the dialed host).
#[derive(Debug)]
pub(crate) struct NodePinVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl NodePinVerifier {
    pub(crate) fn new(roots: Arc<rustls::RootCertStore>) -> Result<Self, rustls::client::VerifierBuilderError> {
        Ok(Self { inner: rustls::client::WebPkiServerVerifier::builder(roots).build()? })
    }
}

impl rustls::client::danger::ServerCertVerifier for NodePinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        let host = server_host(server_name);
        let owners = owners_at_host(&host);
        let self_owned = self_node().is_some_and(|s| owners.contains(&s));
        match check_leaf(&host, &owners, self_owned, end_entity.as_ref()) {
            Ok(()) => Ok(verified),
            Err(m) => {
                m.record_for(&owners);
                m.log();
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(m)))))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The node record field `/api/cluster/nodes` carries the latest refusal
/// in ([`last_mismatch`]), read by `noo cluster verify`'s `node identity`
/// row.
pub(crate) const MISMATCH_FIELD: &str = "node_identity_mismatch";

/// The heartbeat field an agent reports its latest `wrong_node` refusal in
/// (for ten minutes), carried onto the node record for `noo cluster
/// verify`'s `target-node check` row.
pub(crate) const WRONG_NODE_FIELD: &str = "wrong_node_refused";

/// The latest refusal per node the call was meant for (lower-cased): the
/// refusal, when it was recorded, and its Unix time.
type Recorded = (NodeIdentityMismatch, std::time::Instant, i64);
static LAST_MISMATCH: LazyLock<RwLock<HashMap<String, Recorded>>> = LazyLock::new(Default::default);

/// The latest refusal of a call meant for `node`, as the node record's
/// [`MISMATCH_FIELD`]: `{host, expected, presented, at}`. `None` when there
/// was none in the last [`BOOK_TTL`] (a fixed address stops refusing, and
/// the row clears with it).
pub(crate) fn last_mismatch(node: &str) -> Option<Value> {
    let last = LAST_MISMATCH.read().ok()?;
    let (m, seen, at) = last.get(&node.trim().to_ascii_lowercase())?;
    (seen.elapsed() < BOOK_TTL).then(|| {
        serde_json::json!({
            "host": m.host,
            "expected": m.expected,
            "presented": m.presented,
            "at": at,
        })
    })
}

#[cfg(test)]
#[path = "node_pin_tests.rs"]
mod tests;
