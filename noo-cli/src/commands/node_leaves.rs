// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A node's backend door leaves, on the rail.
//!
//! Every backend the node agent starts serves through a door that requires
//! a cluster-CA client certificate: a `noo-stunnel-<x>` sidecar (vLLM's
//! too since door generation 5, under the alias `noo-vllm`). Each door
//! serves with a service leaf at `$NOO_PKI_DIR/services/<x>/service.{crt,key}`
//! whose SANs name the host the agent dials it by, and the agent refuses to
//! start a backend whose leaf is missing or does not name its door
//! (`backendDoorCheck`, a `backend_tls` refusal on the heartbeat).
//!
//! This module is the controller half of getting those leaves there:
//!
//! - **issuance** — one leaf per (node, door service), `issue_node_service_cert`
//!   under `nodes/<node>/services/<x>/`, so a node's leaf is re-issued or
//!   dropped on its own and no node holds another node's key or the
//!   controller's own `services/<x>` key;
//! - **the fixed set** — every node gets a leaf for every door service
//!   ([`NODE_DOOR_LEAVES`]), not only the ones its placements name today.
//!   The CLI cannot read placements offline, a placement added later would
//!   otherwise be refused until someone remembered to re-provision, and a
//!   leaf for a backend the node never runs opens nothing: a door leaf is a
//!   Service-org leaf, which the gateway admits to nothing but `GET
//!   /metrics` for CN=prometheus and a node agent to its own `/metrics`;
//! - **packing** — two bundle kinds per service, `svc-<x>.crt` and
//!   `svc-<x>.key`, flat names like every other kind so the three
//!   allow-lists (`noo-apply.sh`, `sign-bundle.sh`, `node_fetch.rs`) stay
//!   plain string sets. The manifest signature covers them like the rest.
//!
//! What a node does with them is `noo-apply.sh` (Linux: `/etc/noo/pki/
//! services/<x>/`, root, key 0600, cert 0644, dir 0755, temp + rename) and
//! `node_fetch::install_service_leaves` (macOS: `~/noomesh/pki/services/<x>/`).
//! Neither deletes a leaf the bundle does not carry: dropping a node's leaf
//! is revocation, and revocation is its own verb, not a side effect of a
//! restage.

use crate::pki::ClusterCa;
use std::path::Path;

/// One door service a node may run, and everything the rail needs to know
/// about its leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDoorLeaf {
    /// The leaf's service name: `$NOO_PKI_DIR/services/<service>/` on the
    /// node, CN of the leaf.
    pub service: &'static str,
    /// The agent's backend keys whose door serves with this leaf
    /// (node-agent-go `backendDoors` / `doorLeafService`).
    pub backends: &'static [&'static str],
    /// The host names the agent dials the door by and VERIFIES — the leaf
    /// must name every one of them. `noo-<backend>` for vLLM's own
    /// listener, `noo-stunnel-<sidecar>` for a sidecar.
    pub doors: &'static [&'static str],
    /// Bundle kind carrying the certificate.
    pub crt_kind: &'static str,
    /// Bundle kind carrying the private key.
    pub key_kind: &'static str,
}

/// The node door table. Mirrors node-agent-go `internal/docker/client.go`
/// `backendDoors` (pinned by `tests/test_node_backend_leaves_on_the_rail.py`
/// once that table is on the base): vLLM (and vllm-secondary, which shares
/// its leaf and mount) serves natively; llama.cpp, ollama, TEI (`embedding`)
/// and the reranker sit behind a stunnel sidecar. airllm is plaintext by
/// named exception and has no row.
pub const NODE_DOOR_LEAVES: &[NodeDoorLeaf] = &[
    NodeDoorLeaf {
        service: "vllm",
        backends: &["vllm", "vllm-secondary"],
        doors: &["noo-vllm", "noo-vllm-secondary"],
        crt_kind: "svc-vllm.crt",
        key_kind: "svc-vllm.key",
    },
    NodeDoorLeaf {
        service: "llamacpp",
        backends: &["llamacpp"],
        doors: &["noo-stunnel-llamacpp"],
        crt_kind: "svc-llamacpp.crt",
        key_kind: "svc-llamacpp.key",
    },
    NodeDoorLeaf {
        service: "ollama",
        backends: &["ollama"],
        doors: &["noo-stunnel-ollama"],
        crt_kind: "svc-ollama.crt",
        key_kind: "svc-ollama.key",
    },
    NodeDoorLeaf {
        service: "tei",
        backends: &["embedding"],
        doors: &["noo-stunnel-tei"],
        crt_kind: "svc-tei.crt",
        key_kind: "svc-tei.key",
    },
    NodeDoorLeaf {
        service: "reranker",
        backends: &["reranker"],
        doors: &["noo-stunnel-reranker"],
        crt_kind: "svc-reranker.crt",
        key_kind: "svc-reranker.key",
    },
];

/// A leaf this close to expiry is re-issued by the next provision. Wider
/// than `cluster verify`'s 14-day failure window so a routine `noo upgrade
/// --nodes` renews it before verify ever complains.
pub const RENEW_WITHIN_SECS: i64 = 30 * 86_400;

/// The door row for a leaf service name.
pub fn door_leaf(service: &str) -> Option<&'static NodeDoorLeaf> {
    NODE_DOOR_LEAVES.iter().find(|l| l.service == service)
}

/// The door row whose door serves `backend` (an agent backend key).
pub fn door_leaf_for_backend(backend: &str) -> Option<&'static NodeDoorLeaf> {
    NODE_DOOR_LEAVES.iter().find(|l| l.backends.contains(&backend))
}

/// Extra DNS SANs for a node's `service` leaf, beyond `<service>` and
/// `localhost` (which the issuer adds): the names the controller's own
/// leaf carries (`onboard::steps::svc_extra_hostnames` — ONE derivation
/// for the compose aliases) plus the node door names the agent dials.
pub fn door_sans(service: &str) -> Vec<String> {
    // An add-on workload leaf (`addon-<addon>-<workload>`) names exactly its
    // door, `noo-stunnel-<addon>-<workload>` — nothing the controller's own
    // compose aliases would add.
    if let Some(rest) = service.strip_prefix("addon-") {
        return vec![format!("noo-stunnel-{rest}")];
    }
    let mut out = crate::onboard::steps::svc_extra_hostnames(service);
    if let Some(l) = door_leaf(service) {
        for d in l.doors {
            if !out.iter().any(|x| x == d) {
                out.push((*d).to_string());
            }
        }
    }
    out
}

/// What a leaf on disk says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafState {
    /// No certificate or no key.
    Missing,
    /// A file that does not parse as a certificate.
    Unreadable(String),
    Present {
        dns: Vec<String>,
        not_after: i64,
        /// Authority key identifier, when the leaf carries one.
        aki: Option<Vec<u8>>,
    },
}

/// Read the leaf at `dir/service.{crt,key}`.
pub fn read_leaf(dir: &Path) -> LeafState {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    let crt = dir.join("service.crt");
    if !crt.is_file() || !dir.join("service.key").is_file() {
        return LeafState::Missing;
    }
    let Ok(data) = std::fs::read(&crt) else { return LeafState::Unreadable("unreadable file".into()) };
    let pem = match x509_parser::pem::parse_x509_pem(&data) {
        Ok((_, p)) => p,
        Err(e) => return LeafState::Unreadable(format!("not PEM ({e})")),
    };
    let cert = match pem.parse_x509() {
        Ok(c) => c,
        Err(e) => return LeafState::Unreadable(format!("not a certificate ({e})")),
    };
    let mut dns = Vec::new();
    let mut aki = None;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    if let GeneralName::DNSName(d) = gn {
                        dns.push((*d).to_string());
                    }
                }
            }
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                aki = a.key_identifier.as_ref().map(|k| k.0.to_vec());
            }
            _ => {}
        }
    }
    LeafState::Present { dns, not_after: cert.validity().not_after.timestamp(), aki }
}

/// Subject key identifier of the FIRST certificate in `ca.crt` — the one
/// `load_ca` signs with (during a CA transition the anchor holds two).
pub fn ca_ski(ca_crt: &Path) -> Option<Vec<u8>> {
    use x509_parser::extensions::ParsedExtension;
    let data = std::fs::read(ca_crt).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data).ok()?;
    let cert = pem.parse_x509().ok()?;
    cert.extensions().iter().find_map(|e| match e.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
        _ => None,
    })
}

/// Why a node's `service` leaf must be (re-)issued now, or `None` when the
/// one on disk is good: present, names every door, more than
/// [`RENEW_WITHIN_SECS`] from expiry, and signed by the CURRENT CA (after
/// `pki rotate-ca` the old-CA leaves stay on disk until this says so).
pub fn reissue_reason(state: &LeafState, service: &str, current_ca_ski: Option<&[u8]>, now: i64) -> Option<String> {
    match state {
        LeafState::Missing => Some("no leaf yet".into()),
        LeafState::Unreadable(e) => Some(format!("the leaf on disk is unreadable: {e}")),
        LeafState::Present { dns, not_after, aki } => {
            let missing: Vec<String> = door_sans(service).into_iter().filter(|d| !dns.contains(d)).collect();
            if !missing.is_empty() {
                return Some(format!("its SANs do not name {}", missing.join(", ")));
            }
            if *not_after - now < RENEW_WITHIN_SECS {
                return Some(format!("it expires in {} days", (*not_after - now).max(0) / 86_400));
            }
            match (current_ca_ski, aki) {
                (Some(ca), Some(a)) if ca != a.as_slice() => Some("it was issued by a previous cluster CA".into()),
                _ => None,
            }
        }
    }
}

/// Issue or renew every door leaf `node` should hold. Returns what was
/// (re-)issued and why; a leaf already good is not in the list. Errors
/// only when issuance itself fails.
pub fn ensure_node_leaves(ca: &ClusterCa, node: &str, days: i64) -> Result<Vec<(&'static str, String)>, String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ski = ca_ski(&ca.ca_cert_path());
    let mut issued = Vec::new();
    for l in NODE_DOOR_LEAVES {
        let state = read_leaf(&ca.node_service_dir(node, l.service));
        if let Some(why) = reissue_reason(&state, l.service, ski.as_deref(), now) {
            ca.issue_node_service_cert(node, l.service, &door_sans(l.service), days)
                .map_err(|e| format!("{}: {e}", l.service))?;
            issued.push((l.service, why));
        }
    }
    Ok(issued)
}

/// One bundle payload: (kind, bytes).
pub type LeafPayload = (&'static str, Vec<u8>);

/// The bundle payloads for `node`'s door leaves: `svc-<x>.crt` +
/// `svc-<x>.key` for every service whose pair is on disk. A half pair is
/// skipped — the node would refuse it (exit 65) and the rest of the bundle
/// with it — and is named in the second return so the caller says so.
pub fn leaf_payloads(ca: &ClusterCa, node: &str) -> Result<(Vec<LeafPayload>, Vec<&'static str>), String> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for l in NODE_DOOR_LEAVES {
        let dir = ca.node_service_dir(node, l.service);
        let (crt, key) = (dir.join("service.crt"), dir.join("service.key"));
        if !crt.is_file() || !key.is_file() {
            skipped.push(l.service);
            continue;
        }
        let c = std::fs::read(&crt).map_err(|e| format!("{}: {e}", crt.display()))?;
        let k = std::fs::read(&key).map_err(|e| format!("{}: {e}", key.display()))?;
        out.push((l.crt_kind, c));
        out.push((l.key_kind, k));
    }
    Ok((out, skipped))
}

/// Can the node's applier read the `svc-*` kinds? Linux: always — the
/// applier rides every bundle and self-updates before the kind loop
/// (noo-apply §1b). macOS: the applier is the Mac's `noo` binary, which
/// refuses a kind it does not know unless the same bundle carries a newer
/// CLI (`node_fetch::verify_bundle`); the floor is the first noo-cli
/// release carrying `node_fetch::install_service_leaves`. Unknown or
/// unparseable version: assume it CAN — the same rule, for the same
/// reason, as `provision::applier_knows_harness_kinds`.
///
/// FLOOR: set to the release after noo-cli-v0.5.62 (the tag this branch
/// was cut from). If that number ships without this change, bump it.
pub fn applier_knows_leaf_kinds(darwin: bool, app_version: &str) -> bool {
    if !darwin {
        return true;
    }
    cli_version_triple(app_version).is_none_or(|v| v >= LEAF_KINDS_MAC_FLOOR)
}

/// `noo-cli-v0.5.63+abc` → `(0, 5, 63)`; None for anything unparseable
/// (empty, `dev`, a bare sha). Callers pick what None means: the stager
/// assumes a capable applier; `noo upgrade`'s wait treats it as not there yet.
pub fn cli_version_triple(app_version: &str) -> Option<(u32, u32, u32)> {
    let rest = app_version.split("noo-cli-v").nth(1)?;
    let nums: Vec<u32> = rest
        .split(['+', '-'])
        .next()
        .unwrap_or("")
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let [maj, min, pat] = nums[..] else { return None };
    Some((maj, min, pat))
}

/// Set to `1` by `noo upgrade --nodes` on its `cluster provision` children
/// when it will wait for a leafless Mac and restage it itself. Only the
/// wording of the "leaves withheld" note reads it.
pub const UPGRADE_RESTAGES_LEAVES_ENV: &str = "NOO_UPGRADE_RESTAGES_LEAVES";

pub fn upgrade_restages_leaves() -> bool {
    std::env::var(UPGRADE_RESTAGES_LEAVES_ENV).is_ok_and(|v| v == "1")
}

/// The note `cluster provision` prints when it withholds the leaves from a
/// Mac whose applier predates the kinds. Under `noo upgrade` the upgrade
/// restages the node itself; a direct provision leaves that to the operator.
pub fn withheld_leaves_note(node: &str, app_version: &str, from_upgrade: bool) -> String {
    let then = if from_upgrade {
        "this upgrade restages it with the leaves once the node reports the new CLI".to_string()
    } else {
        format!("once {node} reports the new CLI, run `noo cluster provision {node}` again for the leaves")
    };
    format!(
        "no backend door leaves in this bundle: {node} reports {app_version}, whose applier \
         predates the svc-* kinds and would refuse the whole bundle. It carries the newer CLI; {then}."
    )
}

/// First noo-cli release whose Mac applier installs the `svc-*` kinds.
pub const LEAF_KINDS_MAC_FLOOR: (u32, u32, u32) = (0, 5, 63);

// ── add-on node workload door leaves (i300 §10.1 A1) ─────────────────────
//
// One leaf per (node, enabled add-on node workload): service name
// `addon-<addon>-<workload>`, door host `noo-stunnel-<addon>-<workload>`,
// bundle kinds `svc-addon-<addon>-<workload>.crt|.key`. Issued under the
// same `nodes/<node>/services/<service>/` path with the same renewal
// logic as the static table; the three allow-lists judge the kinds by
// SHAPE (`addon_leaf_kind_ok` here, `addon_leaf_kind_ok()` in noo-apply.sh
// and sign-bundle.sh) because the set is open.

/// First noo-cli release whose applier installs `svc-addon-*` kinds. A node
/// reporting an older CLI gets none in its bundle (any OS); so does one whose
/// version is unknown or unparseable (see [`applier_knows_addon_leaf_kinds`]).
pub const APPLIER_ADDON_LEAVES_FLOOR: (u32, u32, u32) = (0, 6, 18);

/// Longest `<addon>-<workload>` (so the service name `addon-…` is at most 57).
pub const ADDON_DOOR_NAME_MAX: usize = 51;

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
fn dns_label_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// May `addon` + `workload` name a door? Each matches
/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$` and `addon-workload` is at most
/// [`ADDON_DOOR_NAME_MAX`] characters.
pub fn addon_door_name_ok(addon: &str, workload: &str) -> bool {
    dns_label_ok(addon) && dns_label_ok(workload) && addon.len() + 1 + workload.len() <= ADDON_DOOR_NAME_MAX
}

/// Is `kind` a well-formed `svc-addon-<name>.crt|.key` bundle kind? The same
/// rule as `addon_leaf_kind_ok` in noo-apply.sh / sign-bundle.sh: the stem
/// after `svc-` is `addon-<name>`, a lowercase DNS-style label of at most 57
/// characters (no `/`, no `.`, no uppercase, no leading or trailing `-`).
pub fn addon_leaf_kind_ok(kind: &str) -> bool {
    let Some(stem) = kind.strip_suffix(".crt").or_else(|| kind.strip_suffix(".key")) else { return false };
    let Some(stem) = stem.strip_prefix("svc-") else { return false };
    let Some(name) = stem.strip_prefix("addon-") else { return false };
    name.len() <= ADDON_DOOR_NAME_MAX && dns_label_ok(name)
}

/// The node workload doors of the enabled add-ons: `(addon, workload)`.
// SEAM(F2): personifai-df's decls.rs node-workloads parser replaces this body
pub fn node_workload_doors(_root: &Path) -> Vec<(String, String)> {
    Vec::new()
}

/// Leaf service name for an add-on workload door.
pub fn addon_service(addon: &str, workload: &str) -> String {
    format!("addon-{addon}-{workload}")
}

/// `(crt_kind, key_kind)` for an add-on workload door.
pub fn addon_leaf_kinds(addon: &str, workload: &str) -> (String, String) {
    let s = addon_service(addon, workload);
    (format!("svc-{s}.crt"), format!("svc-{s}.key"))
}

/// Refuse loudly a pair that cannot name a door, naming the pair.
fn check_addon_door(addon: &str, workload: &str) -> Result<(), String> {
    if addon_door_name_ok(addon, workload) {
        return Ok(());
    }
    Err(format!(
        "add-on node workload door '{addon}/{workload}' cannot be issued a leaf: each name must match \
         ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and addon-workload must be at most {ADDON_DOOR_NAME_MAX} characters"
    ))
}

/// Can the node's applier take `svc-addon-*` kinds? Every OS: below
/// [`APPLIER_ADDON_LEAVES_FLOOR`] the applier would refuse the whole bundle
/// on a kind it does not know (exit 76). Unknown or unparseable version:
/// WITHHOLD. Unlike the static kinds, no applier before the floor knows these
/// at all, so guessing "it can" would fail the whole bundle; withholding only
/// leaves the door unprovisioned, which the agent reports as
/// `door_leaf_missing`.
pub fn applier_knows_addon_leaf_kinds(app_version: &str) -> bool {
    cli_version_triple(app_version).is_some_and(|v| v >= APPLIER_ADDON_LEAVES_FLOOR)
}

/// The note `cluster provision` prints, one line per node, when it withholds
/// add-on door leaves from a node whose applier is not known to take them.
pub fn addon_leaves_withheld_note(node: &str, app_version: &str) -> String {
    let reports = if app_version.trim().is_empty() { "no CLI version" } else { app_version };
    format!(
        "no add-on door leaves in this bundle: {node} reports {reports}, which is not known to take \
         the svc-addon-* kinds; run `noo upgrade --nodes` to update it and deliver them."
    )
}

/// Issue or renew the add-on workload door leaves `node` should hold.
/// Returns `(service, why)` for each leaf (re-)issued. An invalid pair is an
/// error naming it, never skipped.
pub fn ensure_addon_leaves(
    ca: &ClusterCa,
    node: &str,
    days: i64,
    doors: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    for (a, w) in doors {
        check_addon_door(a, w)?;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ski = ca_ski(&ca.ca_cert_path());
    let mut issued = Vec::new();
    for (a, w) in doors {
        let service = addon_service(a, w);
        let state = read_leaf(&ca.node_service_dir(node, &service));
        if let Some(why) = reissue_reason(&state, &service, ski.as_deref(), now) {
            ca.issue_node_service_cert(node, &service, &door_sans(&service), days)
                .map_err(|e| format!("{service}: {e}"))?;
            issued.push((service, why));
        }
    }
    Ok(issued)
}

/// One add-on door bundle payload: (kind, bytes). The kind is owned
/// (`svc-addon-<a>-<w>.crt`), unlike [`LeafPayload`]'s fixed names.
pub type AddonLeafPayload = (String, Vec<u8>);

/// Bundle payloads for `node`'s add-on door leaves: `svc-addon-<a>-<w>.crt` +
/// `.key` for every door whose pair is on disk. A half pair is skipped and
/// named in the second return, as in [`leaf_payloads`].
pub fn addon_leaf_payloads(
    ca: &ClusterCa,
    node: &str,
    doors: &[(String, String)],
) -> Result<(Vec<AddonLeafPayload>, Vec<String>), String> {
    for (a, w) in doors {
        check_addon_door(a, w)?;
    }
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for (a, w) in doors {
        let service = addon_service(a, w);
        let dir = ca.node_service_dir(node, &service);
        let (crt, key) = (dir.join("service.crt"), dir.join("service.key"));
        if !crt.is_file() || !key.is_file() {
            skipped.push(service);
            continue;
        }
        let c = std::fs::read(&crt).map_err(|e| format!("{}: {e}", crt.display()))?;
        let k = std::fs::read(&key).map_err(|e| format!("{}: {e}", key.display()))?;
        let (ck, kk) = addon_leaf_kinds(a, w);
        out.push((ck, c));
        out.push((kk, k));
    }
    Ok((out, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn scratch(name: &str) -> ClusterCa {
        let dir = std::env::temp_dir().join(format!("noo-node-leaves-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = ClusterCa::new(dir);
        ca.generate_ca("noo-test-ca", 3650).expect("ca");
        ca
    }

    fn subject_of(crt: &Path) -> (String, String) {
        let data = std::fs::read(crt).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
        let cert = pem.parse_x509().unwrap();
        let cn = cert.subject().iter_common_name().next().unwrap().as_str().unwrap().to_string();
        let o = cert.subject().iter_organization().next().unwrap().as_str().unwrap().to_string();
        (cn, o)
    }

    #[test]
    fn every_door_leaf_names_its_doors_localhost_and_loopback() {
        let ca = scratch("sans");
        let issued = ensure_node_leaves(&ca, "host3", 90).unwrap();
        assert_eq!(issued.len(), NODE_DOOR_LEAVES.len(), "a fresh node gets every leaf: {issued:?}");
        for l in NODE_DOOR_LEAVES {
            let dir = ca.dir.join("nodes/host3/services").join(l.service);
            let crt = dir.join("service.crt");
            assert!(crt.is_file(), "{} leaf not under the node-scoped path", l.service);
            assert!(!ca.dir.join("services").join(l.service).exists(),
                "a node leaf must not land in the controller's own services/{}", l.service);
            let want: Vec<String> = [l.service.to_string(), "localhost".into()].into_iter()
                .chain(l.doors.iter().map(|d| d.to_string())).collect();
            assert!(ClusterCa::cert_covers_sans(&crt, &want, &["127.0.0.1".to_string()]),
                "{} leaf does not cover {want:?}", l.service);
            assert_eq!(subject_of(&crt), (l.service.to_string(), "Mesh Cluster Service".to_string()));
        }
        // The two doors that share one leaf both verify.
        assert!(ClusterCa::cert_covers_sans(&ca.dir.join("nodes/host3/services/vllm/service.crt"),
            &["noo-vllm".into(), "noo-vllm-secondary".into()], &[]));
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn a_node_leaf_key_is_owner_only_and_read_by_the_cli() {
        let ca = scratch("modes");
        ensure_node_leaves(&ca, "host9", 90).unwrap();
        for l in NODE_DOOR_LEAVES {
            let key = ca.node_service_dir("host9", l.service).join("service.key");
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} key is {mode:o}", l.service);
            assert_eq!(ca.key_reader(&key), crate::pki::KeyReader::Cli);
        }
        // The fixer agrees with the issuer (a 0644 plant is tightened).
        let key = ca.node_service_dir("host9", "ollama").join("service.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let fix = ca.apply_key_mode(&key);
        assert_eq!(fix.after, 0o600);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn nodes_hold_separate_keys() {
        let ca = scratch("separate");
        ensure_node_leaves(&ca, "a", 90).unwrap();
        ensure_node_leaves(&ca, "b", 90).unwrap();
        let ka = std::fs::read(ca.node_service_dir("a", "tei").join("service.key")).unwrap();
        let kb = std::fs::read(ca.node_service_dir("b", "tei").join("service.key")).unwrap();
        assert_ne!(ka, kb);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn a_good_leaf_is_kept_and_each_defect_reissues() {
        let ca = scratch("reissue");
        ensure_node_leaves(&ca, "n", 90).unwrap();
        assert!(ensure_node_leaves(&ca, "n", 90).unwrap().is_empty(), "a good leaf must not churn");
        // Missing.
        let dir = ca.node_service_dir("n", "reranker");
        std::fs::remove_file(dir.join("service.key")).unwrap();
        let got = ensure_node_leaves(&ca, "n", 90).unwrap();
        assert_eq!(got, vec![("reranker", "no leaf yet".to_string())]);
        // SANs that do not name the door (issued the controller's way).
        ca.issue_node_service_cert("n", "ollama", &["noo-ollama".into()], 90).unwrap();
        let got = ensure_node_leaves(&ca, "n", 90).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].1.contains("noo-stunnel-ollama"), "{got:?}");
        // Expiring inside the renewal window.
        ca.issue_node_service_cert("n", "tei", &door_sans("tei"), 10).unwrap();
        let got = ensure_node_leaves(&ca, "n", 90).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].1.contains("expires"), "{got:?}");
        // Issued by another CA.
        let other = scratch("reissue-other");
        other.issue_node_service_cert("n", "vllm", &door_sans("vllm"), 90).unwrap();
        for f in ["service.crt", "service.key"] {
            std::fs::copy(other.node_service_dir("n", "vllm").join(f), ca.node_service_dir("n", "vllm").join(f)).unwrap();
        }
        let got = ensure_node_leaves(&ca, "n", 90).unwrap();
        assert_eq!(got, vec![("vllm", "it was issued by a previous cluster CA".to_string())]);
        let _ = std::fs::remove_dir_all(&ca.dir);
        let _ = std::fs::remove_dir_all(&other.dir);
    }

    #[test]
    fn payloads_carry_every_pair_and_skip_a_half_one() {
        let ca = scratch("payloads");
        ensure_node_leaves(&ca, "n", 90).unwrap();
        let (p, skipped) = leaf_payloads(&ca, "n").unwrap();
        let kinds: Vec<&str> = p.iter().map(|(k, _)| *k).collect();
        for l in NODE_DOOR_LEAVES {
            assert!(kinds.contains(&l.crt_kind) && kinds.contains(&l.key_kind), "{kinds:?}");
        }
        assert!(skipped.is_empty());
        std::fs::remove_file(ca.node_service_dir("n", "llamacpp").join("service.crt")).unwrap();
        let (p, skipped) = leaf_payloads(&ca, "n").unwrap();
        assert!(!p.iter().any(|(k, _)| k.starts_with("svc-llamacpp")));
        assert_eq!(skipped, vec!["llamacpp"]);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn every_backend_key_maps_to_one_leaf_and_kinds_are_flat() {
        for b in ["vllm", "vllm-secondary", "llamacpp", "ollama", "embedding", "reranker"] {
            assert!(door_leaf_for_backend(b).is_some(), "{b}");
        }
        assert!(door_leaf_for_backend("airllm").is_none(), "airllm is plaintext by named exception");
        for l in NODE_DOOR_LEAVES {
            for k in [l.crt_kind, l.key_kind] {
                assert!(!k.contains('/') && k.starts_with("svc-"), "{k}");
            }
            // A door leaf must never be the scraper's identity.
            assert_ne!(l.service, "prometheus");
        }
    }

    #[test]
    fn the_withheld_note_names_who_restages() {
        let up = withheld_leaves_note("host6", "noo-cli-v0.5.62", true);
        assert!(up.contains("this upgrade restages it"), "{up}");
        assert!(!up.contains("noo cluster provision"), "{up}");
        let direct = withheld_leaves_note("host6", "noo-cli-v0.5.62", false);
        assert!(direct.contains("run `noo cluster provision host6` again"), "{direct}");
    }

    #[test]
    fn addon_door_names_follow_the_label_rule_and_the_length_cap() {
        assert!(addon_door_name_ok("rhaddon", "worker"));
        assert!(addon_door_name_ok("a", "b"));
        assert!(addon_door_name_ok("a1-b2", "w-0"));
        // 25 + 1 + 25 = 51: the cap, allowed; one more is refused.
        let (a25, w25, w26) = ("a".repeat(25), "w".repeat(25), "w".repeat(26));
        assert!(addon_door_name_ok(&a25, &w25));
        assert!(!addon_door_name_ok(&a25, &w26));
        for (a, w) in [
            ("a_b", "w"), ("a", "w_x"), ("Rh", "w"), ("a", "Worker"), ("-a", "w"), ("a-", "w"),
            ("a", "-w"), ("a", "w-"), ("", "w"), ("a", ""), ("a.b", "w"), ("a/b", "w"), ("..", "w"),
        ] {
            assert!(!addon_door_name_ok(a, w), "{a}/{w} must be refused");
        }
    }

    #[test]
    fn addon_kinds_are_flat_svc_addon_names_and_judged_by_shape() {
        assert_eq!(addon_service("rhaddon", "worker"), "addon-rhaddon-worker");
        assert_eq!(
            addon_leaf_kinds("rhaddon", "worker"),
            ("svc-addon-rhaddon-worker.crt".to_string(), "svc-addon-rhaddon-worker.key".to_string())
        );
        for k in ["svc-addon-rhaddon-worker.crt", "svc-addon-rhaddon-worker.key", "svc-addon-a-b.crt"] {
            assert!(addon_leaf_kind_ok(k), "{k}");
        }
        let longest = format!("svc-addon-{}.crt", "a".repeat(ADDON_DOOR_NAME_MAX));
        assert!(addon_leaf_kind_ok(&longest));
        let too_long = format!("svc-addon-{}.crt", "a".repeat(ADDON_DOOR_NAME_MAX + 1));
        assert!(!addon_leaf_kind_ok(&too_long));
        for k in [
            "svc-addon-Bad.crt", "svc-addon-a_b-w.crt", "svc-addon-../x.crt", "svc-addon-.crt",
            "svc-addon-a.b.crt", "svc-addon-a-.key", "svc-addon-a/b.crt", "svc-addon-a.crt.key",
            "svc-vllm.crt", "svc-addon-a", "addon-a.crt", "svc-addon-a-b.pem",
            "svc-addon--x.crt", "svc-addon--.key",
        ] {
            assert!(!addon_leaf_kind_ok(k), "{k} must be refused");
        }
    }

    #[test]
    fn an_addon_leaf_names_exactly_its_door() {
        assert_eq!(door_sans("addon-rhaddon-worker"), vec!["noo-stunnel-rhaddon-worker".to_string()]);
        let ca = scratch("addon-sans");
        let doors = vec![("rhaddon".to_string(), "worker".to_string())];
        let issued = ensure_addon_leaves(&ca, "host3", 90, &doors).unwrap();
        assert_eq!(issued.len(), 1, "{issued:?}");
        assert_eq!(issued[0].0, "addon-rhaddon-worker");
        let dir = ca.node_service_dir("host3", "addon-rhaddon-worker");
        assert!(dir.join("service.crt").is_file() && dir.join("service.key").is_file());
        assert!(dir.starts_with(ca.dir.join("nodes/host3/services")));
        match read_leaf(&dir) {
            LeafState::Present { dns, .. } => {
                let doors: Vec<&String> = dns.iter().filter(|d| d.starts_with("noo-")).collect();
                assert_eq!(doors, vec!["noo-stunnel-rhaddon-worker"], "{dns:?}");
                assert!(dns.iter().any(|d| d == "addon-rhaddon-worker") && dns.iter().any(|d| d == "localhost"), "{dns:?}");
            }
            other => panic!("expected a present leaf, got {other:?}"),
        }
        // Renewal logic is the static one: a good leaf is kept.
        assert!(ensure_addon_leaves(&ca, "host3", 90, &doors).unwrap().is_empty());
        // And it packs as the two flat kinds.
        let (p, skipped) = addon_leaf_payloads(&ca, "host3", &doors).unwrap();
        let kinds: Vec<&str> = p.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, vec!["svc-addon-rhaddon-worker.crt", "svc-addon-rhaddon-worker.key"]);
        assert!(skipped.is_empty());
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn an_invalid_addon_pair_is_refused_loudly_naming_the_pair() {
        let ca = scratch("addon-bad");
        let bad = vec![("Bad_Addon".to_string(), "worker".to_string())];
        let e = ensure_addon_leaves(&ca, "n", 90, &bad).unwrap_err();
        assert!(e.contains("Bad_Addon/worker"), "{e}");
        let e = addon_leaf_payloads(&ca, "n", &bad).unwrap_err();
        assert!(e.contains("Bad_Addon/worker"), "{e}");
        assert!(!ca.dir.join("nodes/n").exists(), "nothing may be issued for a refused pair");
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    #[test]
    fn the_seam_returns_no_doors_until_the_parser_lands() {
        assert!(node_workload_doors(Path::new("/nonexistent")).is_empty());
    }

    #[test]
    fn the_addon_floor_withholds_below_and_includes_at_or_above() {
        assert_eq!(APPLIER_ADDON_LEAVES_FLOOR, (0, 6, 18));
        assert!(!applier_knows_addon_leaf_kinds("noo-cli-v0.6.17+abc"));
        assert!(!applier_knows_addon_leaf_kinds("noo-cli-v0.5.99"));
        assert!(applier_knows_addon_leaf_kinds("noo-cli-v0.6.18"));
        assert!(applier_knows_addon_leaf_kinds("noo-cli-v0.6.19+x"));
        assert!(applier_knows_addon_leaf_kinds("noo-cli-v0.7.0"));
        assert!(!applier_knows_addon_leaf_kinds(""), "unknown version: withhold");
        assert!(!applier_knows_addon_leaf_kinds("dev"), "unparseable version: withhold");
        assert!(addon_leaves_withheld_note("host6", "").contains("no CLI version"));
        let note = addon_leaves_withheld_note("host6", "noo-cli-v0.6.17");
        assert!(note.contains("host6") && note.contains("noo upgrade --nodes"), "{note}");
        assert!(!note.contains('\n'));
    }

    #[test]
    fn the_mac_floor_gates_only_macs_and_only_known_old_versions() {
        assert!(applier_knows_leaf_kinds(false, "noo-cli-v0.5.1+abc"));
        assert!(!applier_knows_leaf_kinds(true, "noo-cli-v0.5.62+abc"));
        assert!(applier_knows_leaf_kinds(true, "noo-cli-v0.5.63"));
        assert!(applier_knows_leaf_kinds(true, "noo-cli-v0.6.0+x"));
        assert!(applier_knows_leaf_kinds(true, ""), "unknown version: assume it can");
        assert_eq!(cli_version_triple("noo-cli-v0.5.63+abc"), Some((0, 5, 63)));
        assert_eq!(cli_version_triple("dev"), None);
        assert_eq!(cli_version_triple(""), None);
    }
}
