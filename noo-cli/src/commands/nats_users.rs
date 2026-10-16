// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster nats-users render` and `noo cluster nats-creds rotate` —
//! stage 2 of an earlier release.
//!
//! # What this is for
//!
//! The bus had ONE user/password. The gateway, the workers, trellion and
//! every node presented it. A worker node holding that credential can dispatch
//! jobs to any GPU, subscribe to `worker.>` and read every prompt, answer
//! inference discovery for another node, or purge a stream. Per-principal
//! credentials with subject permissions are the fix; this module mints them
//! and renders the server-side block. Since an earlier release they are the ONLY
//! users: the shared principal is never rendered, and the rendered file
//! references no environment variable at all.
//!
//! # Three rules this module exists to obey
//!
//! 1. **Nodes come from the gateway REGISTRY, never a file.** `noo cluster
//!    reconnect` read the deleted ansible inventory as its only node source
//!    and reported success having done nothing (fixed 2026-09-04). There is
//!    no inventory path in this file, deliberately. [`nodes_from_registry`]
//!    parses `/api/cluster/nodes` and nothing else.
//!
//! 2. **Minting is not delivering.** `security pki issue-node` wrote the
//!    controller's disk, touched no node, and read as if the job were done —
//!    a node ran for hours on a certificate nobody had delivered. So the
//!    default verb here mints AND stages AND waits for the node's own apply
//!    report, and exits non-zero if the node does not confirm. `--mint-only`
//!    is the deliberate exception and prints `delivered: false`.
//!
//! 3. **The rendered config carries no recoverable secret.** Passwords go
//!    into the sops store; `users.conf` gets the bcrypt hash NATS verifies
//!    against (`nats server passwd` parity). That is what makes the rendered
//!    file safe to commit and safe to mount read-only into the container,
//!    and it removes the "who can read the file" question entirely.

use std::collections::BTreeMap;

use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

/// The one account. Isolation comes from per-user permissions, not from
/// separate accounts, because the gateway, the workers and the nodes share
/// the same JetStream streams and KV buckets.
const ACCOUNT: &str = "NOO";

/// Where the rendered block lands, relative to the repo root.
/// `nats-tls.conf` (the only NATS config) `include`s it by this basename.
pub const USERS_CONF: &str = "monitoring/nats/users.conf";

// ── password minting ─────────────────────────────────────────────────────

/// A NATS password: 32 chars, alphanumeric, **leading letter**.
///
/// Alphanumeric-with-a-leading-letter is not cosmetic. The NATS config
/// parser treats an unquoted token specially depending on how it starts —
/// a leading `$` is a variable reference, a leading digit starts a number —
/// and a password that round-trips through an env var, a dotenv line and a
/// config file has three chances to be mangled. Restricting the alphabet
/// costs ~5 bits against a 32-char secret and removes the whole class.
///
/// Entropy comes from the same CSPRNG the secret registry mints with
/// (`security_local::token_urlsafe` → `/dev/urandom`), re-mapped onto the
/// smaller alphabet by rejection rather than by modulo, so the distribution
/// stays flat.
pub fn mint_password() -> String {
    const ALPHA: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    const ALNUM: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(32);
    while out.len() < 32 {
        // token_urlsafe is base64url over urandom: uniform over its own
        // alphabet, so keeping only the characters we want (and discarding
        // '-'/'_') is rejection sampling, not a biased fold.
        for c in crate::commands::security_local::token_urlsafe(48).chars() {
            let set = if out.is_empty() { ALPHA } else { ALNUM };
            if set.contains(&(c as u8)) {
                out.push(c);
                if out.len() == 32 {
                    break;
                }
            }
        }
    }
    out
}

/// The bcrypt hash NATS stores in its config. `nats server passwd` uses
/// cost 11; matching it keeps a hand-generated hash and a rendered one
/// indistinguishable to the server.
pub fn nats_bcrypt(password: &str) -> Result<String, String> {
    bcrypt::hash(password, 11).map_err(|e| format!("bcrypt: {e}"))
}

// ── principals ───────────────────────────────────────────────────────────

/// A NATS user to render. `hash` is its bcrypt digest — every principal has
/// one. (The legacy shared user, whose password was an env reference, was
/// retired by an earlier release; there is no digest-less principal any more.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub user: String,
    pub hash: String,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The only JetStream administrator and the only KV writer.
    Gateway,
    /// noo-worker — and, for ONE release, an add-on whose own principal is
    /// not rendered yet (it falls back to presenting this one).
    Worker,
    /// An add-on's own principal ([`ADDON_PRINCIPALS`]): the user name is the
    /// add-on key, and the grant is exactly the subjects that add-on serves.
    Addon,
    /// One per node. The `&str` is the node id, which appears in every
    /// subject this user may touch.
    Node,
}

/// A node id that is safe to embed in a NATS subject and in a user name.
///
/// `.` `*` `>` and whitespace are subject syntax: an id carrying one would
/// silently widen the permission it appears in, which is the exact opposite
/// of what this file is for. Refuse rather than sanitize — a node whose
/// adopted name cannot be expressed is an operator decision, not something
/// to paper over with a rewritten id that then fails to match the node's
/// own view of its name.
pub fn valid_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Sops key holding this node's password: `NATS_NODE_PASSWORD_<ID>`,
/// upper-cased with `-` folded to `_` (dotenv keys are `[A-Za-z0-9_]`).
pub fn node_secret_key(id: &str) -> String {
    format!(
        "NATS_NODE_PASSWORD_{}",
        id.to_ascii_uppercase().replace('-', "_")
    )
}

/// Node ids already present as principals in a rendered `users.conf`.
///
/// The file is written WHOLE, so whoever renders it must name every node
/// that is currently on the bus or the render is a fleet-wide auth outage
/// dressed up as a smaller file. The registry is the authority for that
/// list — but a render can happen when the gateway is not answering (a
/// re-run of `noo onboard` renders in the SECRETS step, four steps before
/// it touches services), and "the gateway said nothing" is
/// indistinguishable from "there are no nodes" unless somebody reads the
/// file that is already there. This is that reader: the
/// currently-authorised set, used as a floor.
///
/// Pure, so the floor is testable without a controller.
pub fn node_users_in_conf(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("user:") else { continue };
        let Some(id) = rest.trim().trim_matches('"').strip_prefix("node-") else { continue };
        // A rendered id is always a valid node id; anything else is a
        // hand-edit we must not feed back into a permission subject.
        if valid_node_id(id) && !out.iter().any(|x| x == id) {
            out.push(id.to_string());
        }
    }
    out.sort();
    out
}

// ── registry enumeration ─────────────────────────────────────────────────

/// Node ids from `/api/cluster/nodes`. The `id` → `node_id` → `name` fallback
/// is the #78 lesson (the mesh-KV entry uses `id`, the DB row uses `name`).
///
/// Pure so the "registry, never a file" rule is testable without a gateway.
pub fn nodes_from_registry(doc: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = doc["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|n| {
                    n.get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| n.get("node_id").and_then(|v| v.as_str()))
                        .or_else(|| n.get("name").and_then(|v| v.as_str()))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Ask the gateway for the fleet. Hard-fails on an unreachable gateway
/// rather than falling back to anything: a render that silently enumerates
/// zero nodes writes a `users.conf` that locks every node off the bus.
fn registry_nodes(g: &Globals) -> Vec<String> {
    let doc = crate::http::get_json(g, "/api/cluster/nodes", true, 15);
    let nodes = nodes_from_registry(&doc);
    if nodes.is_empty() {
        fail(
            g.json,
            ExitCode::Generic,
            "empty_registry",
            "the gateway registry lists no nodes — refusing to render a users.conf that would \
             lock every node off the bus",
            Some("check `noo cluster status`; this command has no inventory-file fallback by design"),
        );
    }
    nodes
}

// ── rendering ────────────────────────────────────────────────────────────

/// Is this an ENVIRONMENT REFERENCE that NATS would expand?
///
/// In a NATS config a bare `$NAME` token is substituted from the process
/// environment; the same token in quotes is a literal string. The renderer
/// no longer EMITS one
/// one), but the question still has to be answered for two readers: the
/// launcher's pre-`up` check and `noo cluster verify`, which must spot an
/// on-disk users.conf rendered by an older CLI that still names
/// `$NATS_USER` — the file that took host8's bus down on the stack-v0.2.78
/// roll once the compose stopped handing the variable to the server.
///
/// The subtlety that makes a naive `starts_with('$')` wrong: a bcrypt
/// digest also starts with `$` (`$2b$11$...`). It is not an env reference
/// because `2b$11$...` is not an identifier. The test for an identifier — a
/// letter or underscore, then alphanumerics and underscores — is what
/// separates the two.
fn is_env_ref(v: &str) -> bool {
    let Some(name) = v.strip_prefix('$') else { return false };
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Every environment variable a users.conf NAMES (unquoted `$VAR` values),
/// in file order, deduplicated. Comments are ignored. Pure, so the launcher
/// check, `noo cluster verify` and the tests all read one parse.
///
/// A file this renderer wrote returns nothing. A file an older CLI rendered
/// with the legacy principal returns `["NATS_USER", "NATS_PASSWORD"]`.
pub fn env_refs_in_conf(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let Some((_, value)) = line.split_once(':') else { continue };
        let v = value.trim().trim_end_matches(',').trim();
        if is_env_ref(v) {
            let name = v[1..].to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// One value, rendered the way NATS will read it: ALWAYS quoted.
///
/// Quoting is what makes a value a literal. It used to be conditional —
/// bare for an env reference, quoted otherwise — because the legacy
/// principal was `user: $NATS_USER` / `password: $NATS_PASSWORD`, and the
/// two halves once disagreed (stack v0.2.22 quoted the user and not the
/// password, registering a user literally named `$NATS_USER`). With that
/// principal retired nothing the renderer writes may expand,
/// so there is no longer a branch to get wrong: a rendered users.conf
/// cannot depend on the server's environment, and NATS can never refuse it
/// for "variable reference ... can not be found".
fn nats_value(v: &str) -> String {
    format!("\"{v}\"")
}

/// The node id as ONE NATS subject token, matching the agent's
/// `messaging.SubjectToken` byte for byte.
///
/// The agent sets a custom inbox prefix of `_INBOX_node_<token>`
/// (`nats.go NodeInboxPrefix`), and the grant said `_INBOX_node-<id>` — a
/// hyphen where the agent writes an underscore. So every request/reply a node
/// made had its own reply inbox denied. Two spellings of one identifier, in
/// two languages, with nothing comparing them.
fn subject_token(id: &str) -> String {
    let out: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    if out.is_empty() { "unknown".to_string() } else { out }
}

/// How long a worker / add-on / node may take to answer a request it received.
///
/// `allow_responses: true` is NOT unlimited: nats-server reads it as one reply
/// within DEFAULT_ALLOW_RESPONSE_EXPIRATION, **two minutes**. A reply published
/// later is refused as a permissions violation on `_INBOX_gw.…` — the work
/// finished, the caller was told "unreachable". It hit every graph recluster
/// on host8 (3m38s on 2026-10-04, 13 min on 10-03). The longest synchronous
/// requests are `worker.graph.recluster` (RECLUSTER_TIMEOUT, 900 s) and a
/// harness turn (NOO_HARNESS_TURN_TIMEOUT_SECS, default 900 s), so the window
/// is 20 minutes. tests/test_nats_response_expiry_parity.py fails if either
/// timeout outgrows it.
pub(crate) const RESPONSE_EXPIRES: &str = "20m";

/// The WORKER principal's reply inbox, granted to it as a static publish.
///
/// `allow_responses` is not durable. nats-server keeps the "you may answer
/// this one reply subject" entries in a per-connection map, and every
/// config reload re-authorizes each client (`reloadAuthorization` ->
/// `isClientAuthorized` -> `RegisterUser` -> `setPermissions`), which
/// replaces that map with an empty one. So any request in flight across a
/// SIGHUP has its reply refused as a `Publish Violation` on `_INBOX_gw.…`,
/// however short the request — the window above never comes into it. On
/// pop-os 2026-10-14 a 12 s `worker.rag.query` (MCP `noo_rag_query`) was
/// delivered at 20:54:32, NATS reloaded at 20:54:37 (a provision's
/// re-render + HUP), and the reply at 20:54:44 was refused (i69). A slow
/// answer is simply more likely to straddle a reload.
///
/// PER PRINCIPAL, not the gateway's whole inbox (i70). #74 granted the
/// worker `_INBOX_gw.>`, which also covered every reply the gateway awaits
/// from a node. Now the gateway addresses each remote principal's replies
/// to a prefix of its own — `worker_client` uses `_INBOX_gw.worker.<nuid>`
/// for every `worker.>` request, a node's harness requests use
/// `_INBOX_gw.node.<token>.<nuid>` — and each principal holds a static
/// grant on its own prefix only. noo-trellion and noo-trellion-intel
/// present the worker principal, so this is the add-ons' grant too.
///
/// Must equal the gateway's `nats_credentials::WORKER_REPLY_PREFIX` + `.>`
/// — tests/test_nats_principal_reply_grant_parity.py compares the two
/// crates. `allow_responses` stays for the other requesters the worker
/// answers (`agent.msg.direct.*`, `agent.peer.*.task.*`).
pub(crate) const WORKER_REPLY_INBOX: &str = "_INBOX_gw.worker.>";

/// The root of every node principal's reply inbox. A node is granted
/// `<root>.<subject_token(id)>.>` — its own requests' replies and nothing
/// wider; never the root. Must equal the gateway's
/// `nats_credentials::NODE_REPLY_ROOT` (same parity test). Discovery
/// (`mesh.inference.discover`) is a queue request ANY node may answer, so it
/// cannot be addressed to one node's prefix and stays on `allow_responses`.
pub(crate) const NODE_REPLY_ROOT: &str = "_INBOX_gw.node";

/// The gateway's own inbox prefix; every remote principal's reply prefix is
/// one token under it. Must equal `nats_credentials::INBOX_PREFIX`.
pub(crate) const GATEWAY_INBOX: &str = "_INBOX_gw";

/// An add-on that answers its `worker.*` subjects as a NATS principal of its
/// OWN (i70 residue). Until this, noo-trellion and noo-trellion-intel logged
/// in as the worker and so held every grant the worker holds — each other's
/// subjects, the core worker's, and the worker's reply prefix.
#[derive(Debug)]
pub struct AddonPrincipal {
    /// The NATS user, which is also the add-on key (`addons.<name>` in
    /// noomesh.yaml, the `addon:` of its overlay's `x-noo-addon`). One name.
    pub name: &'static str,
    /// The secret-store key that holds its password.
    pub secret_key: &'static str,
    /// The overlay that declares it when the add-on ships in this tree;
    /// `None` = read through the add-on's SIGNED bundle
    /// (`secrets::trusted_addon_overlay`).
    pub core_overlay: Option<&'static str>,
    /// The subjects it SERVES — subscribe, nothing else. These are the
    /// gateway's ownership predicates (`addons::is_trellion_subject`,
    /// `addons::is_trellion_intel_subject`) as NATS wildcards, family for
    /// family: the gateway routes a subject to the add-on by the same
    /// predicate, and tests/test_nats_addon_principal_subjects.py holds the
    /// two, and every `@worker_handler` the add-on's surface registers, together.
    pub subjects: &'static [&'static str],
    /// The containers that present it (recreated on a rotation).
    pub containers: &'static [&'static str],
}

/// Every add-on principal. evolve is absent on purpose: it uses no NATS.
pub const ADDON_PRINCIPALS: &[AddonPrincipal] = &[
    AddonPrincipal {
        name: "trellion",
        secret_key: "NATS_TRELLION_PASSWORD",
        core_overlay: Some("docker-compose.trellion.yml"),
        subjects: &["worker.rag.>", "worker.memory.>", "worker.recall.>", "worker.api.snapshots.>", "worker.autonomy.check_rag"],
        containers: &["noo-trellion"],
    },
    AddonPrincipal {
        name: "trellion_intel",
        secret_key: "NATS_TRELLION_INTEL_PASSWORD",
        core_overlay: None,
        subjects: &["worker.temporal.>", "worker.graph.>", "worker.retrieval.>", "worker.api.heartbeat.run_ml"],
        containers: &["noo-trellion-intel"],
    },
];

/// An add-on principal's reply prefix grant: `_INBOX_gw.<name>.>`. The
/// gateway addresses every request for that add-on's subjects to
/// `_INBOX_gw.<name>.<nuid>` (`nats_credentials::reply_prefix_for`).
pub(crate) fn addon_reply_inbox(name: &str) -> String {
    format!("{GATEWAY_INBOX}.{name}.>")
}

fn quoted_list(items: &[&str]) -> String {
    items.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ")
}

/// Does this overlay text declare `name` as its NATS principal
/// (`x-noo-addon.nats_principal: <name>`)? The name must be the add-on key
/// itself — a block naming another add-on's principal declares nothing.
pub fn overlay_declares_principal(text: &str, name: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Value>(text)
        .ok()
        .and_then(|d| d.get("x-noo-addon")?.get("nats_principal")?.as_str().map(|p| p == name))
        .unwrap_or(false)
}

/// The add-on principals this install's overlays declare, in
/// [`ADDON_PRINCIPALS`] order. Declaration, not config: an add-on's
/// principal is rendered only once the overlay that starts its container
/// delivers the password — otherwise the server would move the add-on's
/// subjects off the worker while the container still presents the worker
/// (an older trellion-intel bundle does).
pub fn declared_addon_principals(root: &std::path::Path) -> Vec<&'static str> {
    ADDON_PRINCIPALS
        .iter()
        .filter(|a| {
            let text = match a.core_overlay {
                Some(f) => std::fs::read_to_string(root.join(f)).ok(),
                None => crate::commands::secrets::trusted_addon_overlay(root, a.name).map(|(_, t)| t),
            };
            text.is_some_and(|t| overlay_declares_principal(&t, a.name))
        })
        .map(|a| a.name)
        .collect()
}

/// Add-on principals a rendered users.conf already names. Pure.
pub fn addon_users_in_conf(text: &str) -> Vec<&'static str> {
    let users: Vec<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("user:").map(|u| u.trim().trim_matches('"').to_string()))
        .collect();
    ADDON_PRINCIPALS.iter().filter(|a| users.iter().any(|u| u == a.name)).map(|a| a.name).collect()
}

fn perms_for(role: Role, id: &str, addons_rendered: &[&str]) -> String {
    let ind = "          ";
    let tok = subject_token(id);
    // The worker serves what no add-on principal serves. An add-on that HAS
    // its own principal takes its subjects with it (denied to the worker);
    // one that does not yet (an older bundle, one release) still presents
    // the worker, so the worker keeps that add-on's reply prefix.
    let worker_addon_replies: String = ADDON_PRINCIPALS
        .iter()
        .filter(|a| !addons_rendered.contains(&a.name))
        .map(|a| format!(", \"{}\"", addon_reply_inbox(a.name)))
        .collect();
    let worker_sub_deny: String = ADDON_PRINCIPALS
        .iter()
        .filter(|a| addons_rendered.contains(&a.name))
        .flat_map(|a| a.subjects.iter())
        .map(|s| format!(", \"{s}\""))
        .collect();
    let addon_subjects = ADDON_PRINCIPALS.iter().find(|a| a.name == id).map(|a| quoted_list(a.subjects)).unwrap_or_default();
    let addon_reply = addon_reply_inbox(id);
    match role {
        Role::Gateway => format!(
            "{ind}publish: {{ allow: [\">\"] }}\n\
             {ind}subscribe: {{ allow: [\">\"] }}\n"
        ),
        Role::Worker => format!(
            "{ind}publish: {{\n\
             {ind}  allow: [\"events.cluster.*\", \"events.job.cancel\", \"agent.collab.>\", \"agent.msg.>\", \"$JS.API.STREAM.INFO.*\", \"{WORKER_REPLY_INBOX}\"{worker_addon_replies}]\n\
             {ind}  deny: [\"$JS.API.STREAM.CREATE.>\", \"$JS.API.STREAM.UPDATE.>\", \"$JS.API.STREAM.DELETE.>\", \"$JS.API.STREAM.PURGE.>\", \"$JS.API.CONSUMER.DELETE.>\", \"$KV.>\", \"tasks.>\"]\n\
             {ind}}}\n\
             {ind}subscribe: {{\n\
             {ind}  allow: [\"worker.>\", \"_INBOX_worker.>\", \"agent.msg.direct.*\", \"agent.peer.*.task.*\"]\n\
             {ind}  deny: [\"$KV.>\", \"tasks.>\"{worker_sub_deny}]\n\
             {ind}}}\n\
             {ind}allow_responses: {{ max: 1, expires: \"{RESPONSE_EXPIRES}\" }}\n"
        ),
        // An add-on: subscribe on exactly the subjects it serves and its own
        // client inbox (`_INBOX_<name>`, nats-py's `inbox_prefix`, where its
        // JetStream `STREAM.INFO` answers land); publish on its own reply
        // prefix and that one JetStream read. Nothing the worker holds beyond
        // that — no agent.*, no events.*, no other add-on's subjects, no
        // worker reply prefix. allow_responses stays, as for the worker, for
        // a requester that is not the gateway.
        Role::Addon => format!(
            "{ind}publish: {{\n\
             {ind}  allow: [\"$JS.API.STREAM.INFO.*\", \"{addon_reply}\"]\n\
             {ind}  deny: [\"$JS.API.STREAM.CREATE.>\", \"$JS.API.STREAM.UPDATE.>\", \"$JS.API.STREAM.DELETE.>\", \"$JS.API.STREAM.PURGE.>\", \"$JS.API.CONSUMER.DELETE.>\", \"$KV.>\", \"tasks.>\", \"worker.>\"]\n\
             {ind}}}\n\
             {ind}subscribe: {{\n\
             {ind}  allow: [{addon_subjects}, \"_INBOX_{id}.>\"]\n\
             {ind}  deny: [\"$KV.>\", \"tasks.>\"]\n\
             {ind}}}\n\
             {ind}allow_responses: {{ max: 1, expires: \"{RESPONSE_EXPIRES}\" }}\n"
        ),
        // The JetStream API subjects a node needs are NOT a matter of taste:
        // they are whatever the nats.go client sends. `js.Subscribe` on a
        // durable does three requests before a single message arrives —
        // `$JS.API.STREAM.NAMES` to find the stream for the subject, then
        // CONSUMER.INFO, then CONSUMER.CREATE — and on a server >= 2.9 with a
        // filter subject set, the create subject carries the filter as extra
        // tokens (`CONSUMER.CREATE.<stream>.<consumer>.<filter…>`,
        // nats.go `apiConsumerCreateWithFilterSubjectT`), so the bare form is
        // not the one sent. The consumer-name token still pins the node, which
        // is what the trailing `>` is safe to widen past.
        //
        // `nc.Publish` returns nil on a DENIED publish — the client is told
        // nothing. So a missing subject here does not fail loudly: the node
        // simply never binds, keeps heartbeating, and silently runs no jobs.
        // That was #1218.
        Role::Node => format!(
            "{ind}publish: {{\n\
             {ind}  allow: [\"mesh.gossip.announce.{id}\", \"events.job.ack.{id}\", \"events.job.complete.{id}\", \"events.job.failed.{id}\", \"events.node.registered.{id}\", \"events.ingest.doc.parsed.{id}\", \"harness.turn.{id}.>\", \"harness.ready.{id}\", \"$JS.API.CONSUMER.CREATE.TASKS.node_{id}_dispatch\", \"$JS.API.CONSUMER.CREATE.TASKS.node_{id}_dispatch.>\", \"$JS.API.CONSUMER.INFO.TASKS.node_{id}_dispatch\", \"$JS.API.CONSUMER.MSG.NEXT.TASKS.node_{id}_dispatch\", \"$JS.API.CONSUMER.CREATE.EVENTS.node_{id}_cancel\", \"$JS.API.CONSUMER.CREATE.EVENTS.node_{id}_cancel.>\", \"$JS.API.CONSUMER.INFO.EVENTS.node_{id}_cancel\", \"$JS.API.CONSUMER.MSG.NEXT.EVENTS.node_{id}_cancel\", \"$JS.ACK.TASKS.node_{id}_dispatch.>\", \"$JS.ACK.EVENTS.node_{id}_cancel.>\", \"$JS.API.STREAM.NAMES\", \"{NODE_REPLY_ROOT}.{tok}.>\"]\n\
             {ind}  deny: [\"tasks.>\", \"worker.>\", \"$KV.>\", \"$JS.API.STREAM.CREATE.>\", \"$JS.API.STREAM.DELETE.>\", \"$JS.API.STREAM.PURGE.>\", \"$JS.API.STREAM.UPDATE.>\", \"$JS.API.CONSUMER.DELETE.>\"]\n\
             {ind}}}\n\
             {ind}subscribe: {{\n\
             {ind}  allow: [\"_INBOX_node_{tok}.>\", \"mesh.inference.discover\", \"harness.run.{id}\", \"harness.task.{id}\"]\n\
             {ind}  deny: [\"tasks.>\", \"worker.>\", \"$KV.>\", \"_INBOX.>\"]\n\
             {ind}}}\n\
             {ind}allow_responses: {{ max: 1, expires: \"{RESPONSE_EXPIRES}\" }}\n"
        ),
    }
}

/// The whole `users.conf` file, as a string. Pure — the test renders it and
/// asserts on the shape, which is the only safe way to check this: applying
/// a wrong permission set to a live fleet is an outage.
///
/// Every principal is rendered with a quoted user and a quoted bcrypt
/// digest; the file names no environment variable. (The legacy shared user
/// used to be rendered here, inside the account, until `--drop-legacy` —
/// An earlier release retired it and the flag.)
pub fn render_users_conf(principals: &[Principal]) -> String {
    let mut s = String::new();
    s.push_str(
        "# GENERATED by `noo cluster nats-users render` — do not hand-edit.\n\
         #\n\
         # One NATS user per principal. Isolation is per-user\n\
         # subject permissions inside ONE account, because the gateway, the\n\
         # workers and the nodes share streams and KV buckets.\n\
         #\n\
         # Passwords are bcrypt digests (`nats server passwd` parity, cost 11):\n\
         # this file holds nothing an attacker can present. The plaintext lives\n\
         # only in secrets/env.sops and on the node that owns it.\n\
         #\n\
         # `include`d by nats-tls.conf. Reload without dropping\n\
         # sessions: docker kill -s HUP noo-nats\n\n",
    );
    s.push_str("accounts {\n");
    s.push_str(&format!("  {ACCOUNT}: {{\n"));
    s.push_str("    jetstream: enabled\n");
    s.push_str("    users: [\n");
    let addons_rendered: Vec<&str> =
        principals.iter().filter(|p| p.role == Role::Addon).map(|p| p.user.as_str()).collect();
    for p in principals {
        let id = match p.role {
            Role::Addon => p.user.as_str(),
            _ => p.user.strip_prefix("node-").unwrap_or(""),
        };
        s.push_str("      {\n");
        s.push_str(&format!("        user: {}\n", nats_value(&p.user)));
        s.push_str(&format!("        password: {}\n", nats_value(&p.hash)));
        s.push_str("        permissions: {\n");
        s.push_str(&perms_for(p.role, id, &addons_rendered));
        s.push_str("        }\n");
        s.push_str("      }\n");
    }
    s.push_str("    ]\n");
    s.push_str("  }\n");
    s.push_str("}\n");
    s
}

// ── `noo cluster nats-users render` ──────────────────────────────────────

/// Passwords for a set of principals, reusing what the store already holds.
///
/// **Idempotence is the requirement here, not an optimisation.** Rendering
/// happens on three occasions — the operator's rollout verb, a fresh
/// onboard, and every node provision — and a render that re-minted would
/// silently rotate the gateway's and every other node's password out from
/// under them. So an existing value is kept and re-hashed; only what is
/// missing is minted. `rotate` is the explicit opt-out.
///
/// The principals to render, plus the (secret key, password) pairs that are
/// NEW and therefore have to reach the store.
pub type RenderPlan = (Vec<Principal>, Vec<(String, String)>);

/// The two principals that live on the controller and can therefore be
/// rotated without a delivery: a re-render + HUP + container recreate is
/// the whole rotation. A NODE's credential is never on this list — minting
/// one without delivering it takes that node off the bus, which is why
/// nodes have their own verb (`nats-creds rotate <node>`) that delivers
/// FIRST and re-renders LAST.
pub const CONTROLLER_PRINCIPALS: &[&str] = &["gateway", "worker"];

/// Every principal whose credential lives on the controller and is rotated
/// by a re-render + HUP + recreate: [`CONTROLLER_PRINCIPALS`] and the add-on
/// principals ([`ADDON_PRINCIPALS`]). `render --rotate` still re-mints only
/// the first two; `nats-creds rotate <name>` takes any of these.
pub fn rotatable_principals() -> Vec<&'static str> {
    CONTROLLER_PRINCIPALS.iter().copied().chain(ADDON_PRINCIPALS.iter().map(|a| a.name)).collect()
}

/// Store keys whose plaintexts are equal — two principals sharing one
/// password are one principal, whatever the users.conf says. Pure.
pub fn shared_passwords(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, (ka, va)) in pairs.iter().enumerate() {
        for (kb, vb) in &pairs[i + 1..] {
            if !va.is_empty() && va == vb {
                out.push((ka.clone(), kb.clone()));
            }
        }
    }
    out
}

/// Bcrypt digests an existing users.conf already carries, by user name.
///
/// A render prefers the store (it re-hashes the stored plaintext), but a
/// principal the server ALREADY authorises whose plaintext is not in the
/// store — an orphaned or mis-keyed node password — must keep the digest it
/// has: minting a fresh password there would take a working node off the
/// bus with nothing delivered to it. Pure.
pub fn digests_in_conf(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut user: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("user:") {
            user = Some(rest.trim().trim_matches('"').to_string());
        } else if let Some(rest) = t.strip_prefix("password:") {
            let v = rest.trim();
            // A quoted bcrypt digest only — never an env reference.
            if let (Some(u), Some(d)) = (user.take(), v.strip_prefix('"').and_then(|x| x.strip_suffix('"'))) {
                if d.starts_with("$2") {
                    out.insert(u, d.to_string());
                }
            }
        }
    }
    out
}

/// The principals to render. `kept` is [`digests_in_conf`] of the file on
/// disk; `mint_missing` says what to do about a principal with neither a
/// stored password nor a kept digest — mint one (the operator's verb, a
/// fresh onboard) or refuse (the upgrade roll, which must change no
/// credential at all).
///
/// `addons` is [`declared_addon_principals`]: each is rendered with its
/// own grant when the store holds its password (or it is minted here). One
/// with neither on a render that mints nothing (the upgrade roll) is left
/// out — its container presents the worker for one more release, and the
/// worker keeps its subjects ([`perms_for`]).
pub fn principals_for(
    store: &crate::commands::secrets::SecretStore,
    nodes: &[String],
    rotate: &[String],
    kept: &BTreeMap<String, String>,
    mint_missing: bool,
    addons: &[&str],
) -> Result<RenderPlan, String> {
    let rotatable = rotatable_principals();
    for r in rotate {
        if !rotatable.contains(&r.as_str()) {
            return Err(format!(
                "'{r}' cannot be rotated by a render: only {} live on the controller. \
                 A node's credential must be DELIVERED — `noo cluster nats-creds rotate <node>`",
                rotatable.join("/")
            ));
        }
        if ADDON_PRINCIPALS.iter().any(|a| a.name == r) && !addons.contains(&r.as_str()) {
            return Err(format!(
                "'{r}' has no principal on this install: its overlay does not declare one \
                 (x-noo-addon.nats_principal), so its container presents the worker — \
                 `noo addons upgrade {r}` brings a bundle that does"
            ));
        }
    }
    let mut fresh: Vec<(String, String)> = Vec::new();
    let mut out: Vec<Principal> = Vec::new();
    let take = |user: String, role: Role, key: String, out: &mut Vec<Principal>, fresh: &mut Vec<(String, String)>| -> Result<(), String> {
        // The plaintext is read here and goes exactly two places: into
        // bcrypt (one-way) and, for a node, into the signed bundle for that
        // node. It is never printed, logged or written to a file.
        let re_mint = rotate.iter().any(|r| r == &user);
        let existing = if re_mint { None } else { store.get(&key).filter(|v| !v.is_empty()) };
        let hash = match existing {
            Some(v) => nats_bcrypt(v)?,
            None => match kept.get(&user).filter(|_| !re_mint) {
                Some(d) => d.clone(),
                None if mint_missing || re_mint => {
                    let v = mint_password();
                    let h = nats_bcrypt(&v)?;
                    fresh.push((key, v));
                    h
                }
                None => {
                    return Err(format!(
                        "{key} is not in the secret store and users.conf has no digest for '{user}' — \
                         this render changes no credential, so it will not mint one. Run \
                         `noo cluster nats-users render` (mints a missing controller pair) or \
                         `noo cluster nats-creds rotate <node>` (mints AND delivers a node's)"
                    ))
                }
            },
        };
        out.push(Principal { user, hash, role });
        Ok(())
    };
    take("gateway".into(), Role::Gateway, "NATS_GATEWAY_PASSWORD".into(), &mut out, &mut fresh)?;
    take("worker".into(), Role::Worker, "NATS_WORKER_PASSWORD".into(), &mut out, &mut fresh)?;
    for a in ADDON_PRINCIPALS.iter().filter(|a| addons.contains(&a.name)) {
        let stored = store.get(a.secret_key).is_some_and(|v| !v.is_empty());
        let re_mint = rotate.iter().any(|r| r == a.name);
        if !stored && !kept.contains_key(a.name) && !mint_missing && !re_mint {
            continue;
        }
        take(a.name.into(), Role::Addon, a.secret_key.into(), &mut out, &mut fresh)?;
    }
    for id in nodes {
        take(format!("node-{id}"), Role::Node, node_secret_key(id), &mut out, &mut fresh)?;
    }
    // No two principals may share a password: a shared one makes the grants
    // above one grant, whichever user name the holder presents.
    let mut plain: Vec<(String, String)> = Vec::new();
    for p in &out {
        let key = match p.role {
            Role::Gateway => "NATS_GATEWAY_PASSWORD".to_string(),
            Role::Worker => "NATS_WORKER_PASSWORD".to_string(),
            Role::Addon => ADDON_PRINCIPALS.iter().find(|a| a.name == p.user).map(|a| a.secret_key.to_string()).unwrap_or_default(),
            Role::Node => node_secret_key(p.user.strip_prefix("node-").unwrap_or("")),
        };
        let v = fresh.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
            .or_else(|| store.get(&key).map(str::to_string))
            .unwrap_or_default();
        plain.push((key, v));
    }
    if let Some((a, b)) = shared_passwords(&plain).first() {
        return Err(format!(
            "{a} and {b} hold the SAME password — two principals sharing one are one principal, so \
             nothing was rendered. Rotate one: `noo cluster nats-creds rotate <principal|node>`"
        ));
    }
    Ok((out, fresh))
}

/// Mint what is missing, write it to the store, render `users.conf`.
///
/// Store FIRST, file second. A failed store write has changed nothing; a
/// failed file write leaves a password no server accepts yet, which a
/// re-run fixes. The reverse order is the unrecoverable one — a server
/// demanding a credential nobody holds.
///
/// `repo` is the tree whose `monitoring/nats/users.conf` is written, so the
/// onboarding wizard can render into the install it is building.
pub fn render_to(
    repo: &std::path::Path,
    nodes: &[String],
    rotate: &[String],
) -> Result<RenderOutcome, String> {
    render_to_mode(repo, nodes, rotate, true)
}

/// [`render_to`] with the mint decision explicit — see [`principals_for`].
pub fn render_to_mode(
    repo: &std::path::Path,
    nodes: &[String],
    rotate: &[String],
    mint_missing: bool,
) -> Result<RenderOutcome, String> {
    for id in nodes {
        if !valid_node_id(id) {
            return Err(format!(
                "node id '{id}' cannot be expressed as a NATS subject token — rename the node; \
                 a sanitized id would not match the node's own view of its name"
            ));
        }
    }
    let sops = repo.join("secrets/env.sops");
    let store = crate::commands::secrets::SecretStore::load_sops(&sops)?;
    let kept = digests_in_conf(&std::fs::read_to_string(repo.join(USERS_CONF)).unwrap_or_default());
    let addons = declared_addon_principals(repo);
    let (principals, fresh) = principals_for(&store, nodes, rotate, &kept, mint_missing, &addons)?;
    // The controller principals need their USER NAMES in the environment as
    // well as their passwords in the store, or the render is only half a
    // migration: the server would demand `gateway`/`worker` while the
    // containers still had nothing but the shared pair to present. The
    // wizard writes these on a fresh install; an install that predates
    // An earlier release has neither, and this is the command its refusal message
    // names — so it has to finish the job. Names, not secrets, so `.env`
    // and not the sops store (`store_move_config_to_env` would relocate
    // them anyway).
    ensure_controller_users_in_env(repo)?;
    let minted: Vec<String> = fresh.iter().map(|(k, _)| k.clone()).collect();
    if !fresh.is_empty() {
        crate::commands::secrets::store_upsert(&fresh)
            .map_err(|e| format!("could not write the minted password(s) to {}: {e} — nothing was rendered", sops.display()))?;
    }
    let target = repo.join(USERS_CONF);
    if let Some(p) = target.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let text = render_users_conf(&principals);
    std::fs::write(&target, &text).map_err(|e| format!(
        "password(s) ARE in the store but {} could not be written: {e} — re-run the render \
         (it is idempotent: it reuses what the store holds)", target.display()))?;
    Ok(RenderOutcome { target, users: principals.len(), minted })
}

/// `NATS_GATEWAY_USER=gateway` / `NATS_WORKER_USER=worker` in `.env`, if
/// they are not already set. Never overwrites: an operator who renamed a
/// principal has said something, and this is not the place to argue.
fn ensure_controller_users_in_env(repo: &std::path::Path) -> Result<(), String> {
    let env_path = repo.join(".env");
    for (key, value) in [("NATS_GATEWAY_USER", "gateway"), ("NATS_WORKER_USER", "worker")] {
        if !crate::onboard::env::read_env_key(&env_path, key).trim().is_empty() {
            continue;
        }
        crate::onboard::env::update_env_key(&env_path, key, value)
            .map_err(|e| format!("could not write {key} to {}: {e}", env_path.display()))?;
    }
    Ok(())
}

pub struct RenderOutcome {
    pub target: std::path::PathBuf,
    pub users: usize,
    /// Secret-store KEYS minted by this render. Names only, never values.
    pub minted: Vec<String>,
}

/// Registry nodes ∪ `extra`, rendered. Used wherever a render happens
/// somewhere other than the operator's own verb — `noo cluster provision`,
/// which must add the node being born WITHOUT dropping the users of every
/// node already on the bus (the file is written whole, so an incomplete
/// node list is a fleet-wide auth outage, not a smaller file).
///
/// A gateway that cannot be reached contributes no nodes rather than
/// failing: on a fresh install there is no gateway yet, and `extra` is the
/// only node there is.
pub fn render_all(g: &Globals, extra: &[String]) -> Result<RenderOutcome, String> {
    let mut nodes = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .map(|doc| nodes_from_registry(&doc))
        .unwrap_or_default();
    for e in extra {
        if !nodes.iter().any(|n| n.eq_ignore_ascii_case(e)) {
            nodes.push(e.clone());
        }
    }
    nodes.sort();
    render_to(&crate::envfile::repo_root(), &nodes, &[])
}

/// The re-render `noo upgrade --stack` runs BEFORE its launcher.
///
/// A live controller's users.conf was rendered by an older CLI and may still
/// name `$NATS_USER`/`$NATS_PASSWORD`; the new compose no longer hands the
/// server either, and NATS refuses to parse a users.conf whose variable it
/// cannot resolve — the stack-v0.2.78 outage. So the file is re-rendered
/// first, the way `noo cluster nats-users render` does it, with two
/// differences that make it safe to run unattended inside a roll:
///
/// * the node list is what users.conf already authorises ∪ the registry
///   (best-effort — the old gateway may be down), never the registry alone;
/// * it MINTS NOTHING: every principal keeps its stored password or, failing
///   that, the digest the server already verifies. A principal with neither
///   is a refusal naming the verb that mints it.
///
/// Returns `None` when the file on disk names no environment variable —
/// nothing to do, and the file is left byte-for-byte alone.
pub fn rerender_for_roll(g: &Globals, repo: &std::path::Path) -> Result<Option<RenderOutcome>, String> {
    let existing = std::fs::read_to_string(repo.join(USERS_CONF)).unwrap_or_default();
    if env_refs_in_conf(&existing).is_empty() {
        return Ok(None);
    }
    let mut nodes = node_users_in_conf(&existing);
    if let Some(doc) = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10) {
        for n in nodes_from_registry(&doc) {
            if !nodes.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                nodes.push(n);
            }
        }
    }
    nodes.sort();
    render_to_mode(repo, &nodes, &[], false).map(Some)
}

/// Give every DECLARED add-on its own principal on an install that predates
/// it — `noo upgrade --stack` (after the new overlays and add-on pins are
/// written, before the launcher) and `noo addons enable` run this.
///
/// Mints each declared add-on's missing password (the same alphabet as every
/// NATS password), then re-renders users.conf the way the upgrade roll does —
/// node list = what the file already authorises ∪ the registry, no node or
/// controller credential minted — so the add-on's principal appears and the
/// worker's grant loses that add-on's subjects. The caller HUPs.
///
/// `Ok(None)`: nothing to do (every declared add-on is already rendered, or
/// there is no users.conf yet — onboarding renders it whole).
pub fn reconcile_addon_principals(g: &Globals, root: &std::path::Path) -> Result<Option<RenderOutcome>, String> {
    let Ok(conf) = std::fs::read_to_string(root.join(USERS_CONF)) else { return Ok(None) };
    let declared = declared_addon_principals(root);
    let rendered = addon_users_in_conf(&conf);
    if declared.iter().all(|d| rendered.contains(d)) {
        return Ok(None);
    }
    let store = crate::commands::secrets::SecretStore::load_sops(&root.join("secrets/env.sops"))?;
    let fresh: Vec<(String, String)> = ADDON_PRINCIPALS
        .iter()
        .filter(|a| declared.contains(&a.name))
        .filter(|a| !store.get(a.secret_key).is_some_and(|v| !v.is_empty()))
        .map(|a| (a.secret_key.to_string(), mint_password()))
        .collect();
    if !fresh.is_empty() {
        crate::commands::secrets::store_upsert(&fresh)
            .map_err(|e| format!("could not write {} to the store: {e} — nothing was rendered",
                fresh.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(", ")))?;
    }
    let mut nodes = node_users_in_conf(&conf);
    if let Some(doc) = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10) {
        for n in nodes_from_registry(&doc) {
            if !nodes.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                nodes.push(n);
            }
        }
    }
    nodes.sort();
    let mut out = render_to_mode(root, &nodes, &[], false)?;
    out.minted = fresh.into_iter().map(|(k, _)| k).collect();
    Ok(Some(out))
}

/// This node's own bus credential, as the `nats-creds` bundle payload.
///
/// Minted at PROVISION time, not at onboard time, for the obvious reason:
/// the node does not exist yet when the controller is built. It rides the
/// provision bundle exactly as the node's certificate does — same rail,
/// same signature, same applier.
///
/// Reuse-or-mint, like every other render path: re-provisioning a node
/// must not silently rotate a credential the running agent is using.
pub fn node_credential_payload(repo: &std::path::Path, node: &str) -> Result<Vec<u8>, String> {
    if !valid_node_id(node) {
        return Err(format!("node id '{node}' cannot be expressed as a NATS subject token"));
    }
    let key = node_secret_key(node);
    let store = crate::commands::secrets::SecretStore::load_sops(&repo.join("secrets/env.sops"))?;
    let pw = match store.get(&key).filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None => {
            let v = mint_password();
            crate::commands::secrets::store_upsert(&[(key, v.clone())])?;
            v
        }
    };
    Ok(creds_payload(node, &pw).into_bytes())
}

/// Ask a running NATS server to re-read its config. A HUP reloads
/// authorization WITHOUT dropping sessions, which is the whole reason the
/// rollout can happen with the fleet up. Best-effort and non-fatal: on a
/// box where the server is not up yet (a fresh onboard) there is nothing to
/// reload, and that is not an error.
pub fn hup_nats() -> bool {
    let prefix = std::env::var("NOO_CONTAINER_PREFIX").unwrap_or_else(|_| "noo".into());
    std::process::Command::new("docker")
        .args(["kill", "-s", "HUP", &format!("{prefix}-nats")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── `noo cluster nats-users render` ──────────────────────────────────────

const RENDER_USAGE: &str =
    "usage: noo cluster nats-users render [--rotate] [--dry-run] [-y|--yes]\n\
     --rotate re-mints the CONTROLLER principals (gateway, worker) only; a node's \
     credential is rotated by `noo cluster nats-creds rotate <node>`, which delivers it.\n\
     --drop-legacy is accepted and ignored for one release: the shared user is never \
     rendered";

pub fn cluster_nats_users_render(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut drop_legacy_given = false;
    let mut dry_run = false;
    let mut rotate = false;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            // Deprecated no-op, accepted for ONE release. The
            // committed baseline users.conf, the isolation runbook and every
            // pre-536 scan finding told operators to run exactly
            // `render --drop-legacy`; a usage error at the moment they follow
            // that advice would be worse than a flag that does nothing.
            "--drop-legacy" => drop_legacy_given = true,
            "--rotate" => rotate = true,
            "--dry-run" => dry_run = true,
            "-y" | "--yes" => yes = true,
            "-h" | "--help" => {
                println!("{RENDER_USAGE}");
                return Ok(0);
            }
            _ => return Err(Unhandled),
        }
    }

    // Registry, never a file. There is no other node source in this command.
    let nodes = registry_nodes(g);
    let repo = crate::envfile::repo_root();

    if dry_run {
        let target = repo.join(USERS_CONF);
        let addons = declared_addon_principals(&repo);
        if g.json {
            println!("{}", serde_json::json!({
                "dry_run": true, "target": target, "nodes": nodes,
                "addon_principals": addons,
                "users": nodes.len() + 2 + addons.len(),
                "legacy_user_kept": false, "rotate": rotate,
            }));
        } else {
            let addon_part: String = addons.iter().map(|a| format!("{a}, ")).collect();
            ui::done(&format!(
                "would render {} — gateway, worker, {addon_part}{} node user(s)",
                target.display(), nodes.len()));
            println!("{}", ui::note("nothing was minted or written"));
        }
        return Ok(0);
    }

    if rotate {
        // Re-minting changes the password the running gateway and worker
        // present; they keep the old one until the stack is recreated.
        super::confirm_destructive(g, yes, "re-mint the NATS passwords of", &CONTROLLER_PRINCIPALS.join(", "));
    }
    let rotate_list: Vec<String> = if rotate {
        CONTROLLER_PRINCIPALS.iter().map(|p| p.to_string()).collect()
    } else {
        Vec::new()
    };
    let out = match render_to(&repo, &nodes, &rotate_list) {
        Ok(o) => o,
        Err(e) => fail(g.json, ExitCode::Generic, "render_failed", &e, None),
    };
    let reloaded = hup_nats();

    if g.json {
        println!("{}", serde_json::json!({
            "target": out.target, "users": out.users, "nodes": nodes,
            "minted_keys": out.minted, "legacy_user_kept": false,
            "reloaded": reloaded,
        }));
    } else {
        ui::done(&format!("{} users rendered to {}", out.users, out.target.display()));
        if out.minted.is_empty() {
            println!("{}", ui::note("every password already existed in the store and was reused — this render changed no credential"));
        } else {
            ui::done(&format!("{} password(s) minted into secrets/env.sops", out.minted.len()));
        }
        if rotate {
            println!("{}", ui::status_line(Glyph::Warn,
                "gateway + worker passwords ROTATED — the server now verifies the new digests; recreate \
                 noo-gateway, noo-worker, noo-trellion (an env change needs a recreate): noo stack restart --force"));
        }
        if reloaded {
            ui::done("noo-nats reloaded (SIGHUP — no session was dropped)");
        } else {
            println!("{}", ui::note("could not signal noo-nats — reload it yourself: docker kill -s HUP noo-nats"));
        }
        if drop_legacy_given {
            println!("{}", ui::note("--drop-legacy is deprecated and does nothing: the shared user is never rendered"));
        }
        ui::guide(&[
            ("curl -s 127.0.0.1:8222/connz?auth=1", "see which user each connection is actually using"),
            ("noo cluster nats-creds rotate <node>", "mint AND deliver one node's credential over the rail"),
        ]);
    }
    Ok(0)
}

// ── `noo cluster nats-creds rotate` ──────────────────────────────────────

/// The payload of the `nats-creds` bundle kind: a dotenv fragment the
/// applier merges into `/etc/noo-node-agent.env`.
///
/// `NODE=` is first and is load-bearing: the applier refuses a bundle whose
/// `NODE` is not the node it resolved, so a signed credential for node A
/// cannot be replayed onto node B. Teardown established that shape.
pub fn creds_payload(node: &str, password: &str) -> String {
    format!("NODE={node}\nNATS_NODE_USER=node-{node}\nNATS_NODE_PASSWORD={password}\n")
}

const ROTATE_USAGE: &str =
    "usage: noo cluster nats-creds rotate <node|gateway|worker|trellion|trellion_intel>... [--mint-only] [--restart] [-y|--yes]\n\
     nodes: mint, deliver over the rail, confirm, then re-render + HUP\n\
     gateway/worker/trellion/trellion_intel: mint, re-render + HUP, then recreate the holders (--restart does it)";

/// Which of the named targets are controller principals. Mixing them with
/// nodes is refused: the two rotations have OPPOSITE orders (a node gets
/// its credential before the server demands it; a controller principal
/// has the server demand it and is then recreated), and one command that
/// did both would have to pick one order and get the other wrong.
pub(crate) fn split_targets(targets: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
    let (principals, nodes): (Vec<String>, Vec<String>) = targets
        .iter()
        .cloned()
        .partition(|t| rotatable_principals().contains(&t.to_ascii_lowercase().as_str()));
    if !principals.is_empty() && !nodes.is_empty() {
        return Err(format!(
            "rotate controller principals ({}) and nodes ({}) in separate runs — their \
             rotations happen in opposite orders",
            principals.join(", "),
            nodes.join(", ")
        ));
    }
    Ok((principals.iter().map(|p| p.to_ascii_lowercase()).collect(), nodes))
}

/// Rotate the controller-side principals: mint, re-render, HUP, recreate.
///
/// Order is the REVERSE of a node's. The server is told the new digest
/// first (render + HUP), and from that instant the running holder loops on
/// `Authorization Violation` until it is recreated with the new env — a
/// window measured in seconds with `--restart`, and an explicit,
/// printed next step without it. A node cannot be done this way because
/// its credential has to travel; these live on the same box as the store.
fn rotate_controller_principals(g: &Globals, principals: &[String], restart: bool, yes: bool) -> Result<i32, Unhandled> {
    super::confirm_destructive(g, yes, "rotate the bus credential of", &principals.join(", "));
    let repo = crate::envfile::repo_root();
    let known = registry_nodes(g);
    let out = match render_to(&repo, &known, principals) {
        Ok(o) => o,
        Err(e) => fail(g.json, ExitCode::Generic, "render_failed", &e, Some("nothing was rotated")),
    };
    let reloaded = hup_nats();
    let holders: Vec<&str> = principals
        .iter()
        .flat_map(|p| match p.as_str() {
            "gateway" => vec!["noo-gateway"],
            // An add-on presents its own principal; for one release an add-on
            // without one still presents the worker, so the worker's holders
            // keep naming them.
            "worker" => vec!["noo-worker", "noo-trellion", "noo-trellion-intel"],
            other => ADDON_PRINCIPALS.iter().find(|a| a.name == other).map(|a| a.containers.to_vec()).unwrap_or_default(),
        })
        .collect();
    if g.json {
        println!("{}", serde_json::json!({
            "principals": principals, "minted_keys": out.minted, "users": out.users,
            "target": out.target, "reloaded": reloaded, "holders_to_recreate": holders,
            "restarted": restart,
        }));
    } else {
        ui::done(&format!("{} password(s) minted into secrets/env.sops: {}", out.minted.len(), out.minted.join(", ")));
        ui::done(&format!("{} users re-rendered to {}", out.users, out.target.display()));
        if reloaded {
            ui::done("noo-nats reloaded (SIGHUP) — the server now verifies the NEW digest");
        } else {
            println!("{}", ui::note("could not signal noo-nats — reload it yourself: docker kill -s HUP noo-nats"));
        }
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "{} hold the OLD password and will loop on 'Authorization Violation' until recreated",
            holders.join(", ")
        )));
    }
    if !restart {
        if !g.json {
            ui::guide(&[("noo stack restart --force", "RECREATES the holders with the new value; a plain restart keeps the old environment, which is what the sentence in brackets has always said")]);
        }
        return Ok(0);
    }
    let script = repo.join("scripts/noomesh-restart.sh");
    // --force: a plain run of this script is `docker compose restart`, which
    // keeps the OLD environment — and the holders are being restarted precisely
    // because their credential changed. Same defect as the secrets rotate path
    // (2026-09-13), where the operator was left on a revoked token.
    // Same binary as this process — see mesh.rs::run_script for why.
    let cli_bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let st = std::process::Command::new("bash")
        .arg(&script)
        .arg("--force")
        .current_dir(&repo)
        .env("NOO_CLI_BIN", &cli_bin)
        .status();
    match st {
        Ok(s) if s.success() => {
            if !g.json {
                ui::done("stack recreated — the holders now present the new credential");
            }
            Ok(0)
        }
        _ => {
            if !g.json {
                println!("{}", ui::status_line(Glyph::Warn, "stack recreate FAILED — the store and server ARE rotated; run: noo stack restart --force"));
            }
            Ok(1)
        }
    }
}

pub fn cluster_nats_creds_rotate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut targets: Vec<String> = Vec::new();
    let mut mint_only = false;
    let mut restart = false;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--mint-only" => mint_only = true,
            "--restart" => restart = true,
            "-y" | "--yes" | "--force" => yes = true,
            "-h" | "--help" => {
                println!("{ROTATE_USAGE}");
                return Ok(0);
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => targets.push(t.to_string()),
        }
    }
    if targets.is_empty() {
        return Err(Unhandled);
    }
    let (principals, nodes) = match split_targets(&targets) {
        Ok(x) => x,
        Err(e) => fail(g.json, ExitCode::Usage, "mixed_targets", &e, None),
    };
    if !principals.is_empty() {
        if mint_only {
            fail(g.json, ExitCode::Usage, "mint_only_is_for_nodes",
                "--mint-only pre-mints for an OFFLINE node; a controller principal is on this box and is rotated in one step",
                None);
        }
        return rotate_controller_principals(g, &principals, restart, yes);
    }

    // Registry, never a file — including for "is this a node at all?".
    let known = registry_nodes(g);
    for n in &nodes {
        if !known.iter().any(|k| k.eq_ignore_ascii_case(n)) {
            fail(g.json, ExitCode::Generic, "unknown_node",
                &format!("'{n}' is not in the gateway registry"),
                Some("`noo cluster status` lists the fleet; this command has no inventory-file fallback"));
        }
        if !valid_node_id(n) {
            fail(g.json, ExitCode::Generic, "bad_node_id",
                &format!("node id '{n}' cannot be expressed as a NATS subject token"), None);
        }
    }
    super::confirm_destructive(g, yes, "rotate the NATS credential on", &nodes.join(", "));

    // Mint + store, for every named node, before touching any of them.
    let mut minted: BTreeMap<String, String> = BTreeMap::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for n in &nodes {
        let pw = mint_password();
        pairs.push((node_secret_key(n), pw.clone()));
        minted.insert(n.clone(), pw);
    }
    if let Err(e) = crate::commands::secrets::store_upsert(&pairs) {
        fail(g.json, ExitCode::Generic, "store_write_failed",
            &format!("could not write the minted password(s) to secrets/env.sops: {e}"),
            Some("nothing was delivered"));
    }

    if mint_only {
        // The deliberate exception: pre-minting for an
        // offline node is legitimate, and saying so plainly is the whole
        // point of the flag existing.
        if g.json {
            println!("{}", serde_json::json!({
                "nodes": nodes, "minted": true, "delivered": false,
                "keys": pairs.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                "next": "noo cluster nats-creds rotate <node>  (without --mint-only) delivers it",
            }));
        } else {
            ui::done(&format!("minted {} credential(s) into secrets/env.sops", pairs.len()));
            println!("{}", ui::status_line(Glyph::Warn, "delivered: false"));
            println!("{}", ui::note(
                "the node still presents its OLD credential. `noo cluster nats-creds rotate <node>` \
                 (no --mint-only) stages the bundle and waits for the node's apply report"));
            println!("{}", ui::note(
                "re-render the server side too — `noo cluster nats-users render` — or the new \
                 password is one nothing accepts"));
        }
        return Ok(0);
    }

    // Deliver. `deliver_kind_to_nodes` is the shared rail skeleton: signed
    // bundle, pull-first staging, gate fallback, per-node honest outcome.
    let payloads = minted.clone();
    let payload = move |node: &str| -> Result<Vec<u8>, String> {
        payloads
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(node))
            .map(|(n, pw)| creds_payload(n, pw).into_bytes())
            .ok_or_else(|| format!("no minted credential for {node}"))
    };
    let rc = crate::commands::cluster_provision::deliver_kind_to_nodes(
        g,
        &nodes,
        "nats-creds",
        &payload,
        "the applier merges it into /etc/noo-node-agent.env and restarts the agent, \
         which reconnects presenting node-<id>",
    )?;
    if rc != 0 {
        // Delivery failed or was SKIPPED, so the node still presents its
        // OLD credential — which the server still accepts, because the
        // render below has not happened. Leaving the server side untouched
        // is what keeps a failed rotation from being an outage.
        if !g.json {
            println!("{}", ui::status_line(Glyph::Warn,
                "server side NOT re-rendered — every node keeps the credential it already has"));
            println!("{}", ui::note(
                "a SKIPPED node had another bundle staged (one slot per node, no queue) — re-run \
                 this command once that bundle collects; nothing was clobbered"));
        }
        return Ok(rc);
    }

    // Server side LAST. The node now holds the new credential and is
    // retrying auth; the render + HUP is what starts accepting it. The
    // other order would have taken the node off the bus for the whole
    // delivery window, and would have stranded it there on a failure.
    let repo = crate::envfile::repo_root();
    match render_to(&repo, &known, &[]) {
        Ok(out) => {
            let reloaded = hup_nats();
            if g.json {
                println!("{}", serde_json::json!({
                    "nodes": nodes, "delivered": true, "users": out.users,
                    "target": out.target, "reloaded": reloaded,
                }));
            } else {
                ui::done(&format!("{} users re-rendered to {}", out.users, out.target.display()));
                if reloaded {
                    ui::done("noo-nats reloaded (SIGHUP) — the new credential is now accepted");
                } else {
                    println!("{}", ui::note("could not signal noo-nats — reload it yourself: docker kill -s HUP noo-nats (the node retries auth until you do)"));
                }
            }
        }
        Err(e) => fail(g.json, ExitCode::Generic, "render_failed",
            &format!("the node HAS the new credential but the server side did not re-render: {e}"),
            Some("run `noo cluster nats-users render` — the node retries auth until you do")),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// i77's NATS half of "a seat can never obtain node credentials": the bus
    /// principals come from the NODE registry (`/api/cluster/nodes`) and the
    /// two controller principals, and nothing else. A kiosk seat lives in its
    /// own registry (`/api/cluster/seats`), which no code here reads, so a
    /// seat cannot have a principal — not by name, not by role. The gateway
    /// half is `auth::tests::seat_cannot_reach_node_routes`.
    #[test]
    fn seat_has_no_bus_principal() {
        // The fleet as the gateway lists it: the nodes, and separately a seat.
        let nodes = serde_json::json!({"nodes": [{"id": "host3"}, {"id": "pop-os"}]});
        let seats = serde_json::json!({"seats": [{"seat_name": "lobby", "role": "seat"}]});
        let ids = nodes_from_registry(&nodes);
        assert_eq!(ids, ["host3", "pop-os"]);
        // The seats document is not a nodes document: read as one, it
        // yields nothing (it has no `nodes` array).
        assert!(nodes_from_registry(&seats).is_empty());
        let mut principals: Vec<Principal> = vec![
            Principal { user: "gateway".into(), hash: "$2b$11$g".into(), role: Role::Gateway },
            Principal { user: "worker".into(), hash: "$2b$11$w".into(), role: Role::Worker },
        ];
        for id in &ids {
            principals.push(Principal { user: format!("node-{id}"), hash: "$2b$11$n".into(), role: Role::Node });
        }
        let conf = render_users_conf(&principals);
        assert!(!conf.contains("lobby"), "a seat must never be a bus principal:\n{conf}");
        assert!(!conf.to_ascii_lowercase().contains("seat"), "{conf}");
        // Structural: the renderer's only fleet source is the node registry.
        let src = include_str!("nats_users.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(!prod.contains("/api/cluster/seats") && !prod.contains("kiosk_seat"),
            "nats_users must never enumerate seats");
        assert!(prod.contains("\"/api/cluster/nodes\""));
        // And the shipped server config has no seat user either.
        let shipped = include_str!("../../../monitoring/nats/nats-tls.conf");
        assert!(!shipped.to_ascii_lowercase().contains("seat"), "nats-tls.conf names a seat");
        let users = include_str!("../../../monitoring/nats/users.conf");
        assert!(!users.to_ascii_lowercase().contains("seat"), "the shipped users.conf names a seat");
    }

    // ── users.conf value quoting (the v0.2.22 outage) ─────────────────

    /// What an older CLI rendered for the legacy principal — the text still
    /// on host8's disk when the shared user was retired.
    const LEGACY_BLOCK: &str = "      {\n        user: $NATS_USER\n        password: $NATS_PASSWORD\n        \
        permissions: {\n          publish: { allow: [\">\"] }\n        }\n      }\n";

    #[test]
    fn the_rendered_file_names_no_environment_variable() {
        // NATS refuses to parse a users.conf whose `$VAR` it
        // cannot resolve, and the compose no longer hands the server any.
        // So a rendered file must reference NOTHING in the environment.
        let conf = render_users_conf(&sample());
        assert_eq!(env_refs_in_conf(&conf), Vec::<String>::new(), "{conf}");
        assert!(!conf.contains("$NATS_USER") && !conf.contains("$NATS_PASSWORD"), "{conf}");
        // ...and the parse can SEE one, or the assertion above is vacuous.
        assert_eq!(env_refs_in_conf(LEGACY_BLOCK), ["NATS_USER", "NATS_PASSWORD"]);
        // A commented-out reference is not one.
        assert!(env_refs_in_conf("# user: $NATS_USER\n").is_empty());
        // Every rendered principal has a bcrypt digest.
        for line in conf.lines().filter(|l| l.trim().starts_with("password:")) {
            assert!(line.trim().starts_with("password: \"$2"), "{line}");
        }
    }

    #[test]
    fn even_a_dollar_user_name_is_rendered_as_a_literal() {
        // The renderer has no bare-value branch left: whatever it is handed
        // is quoted, so it can never emit something NATS would expand.
        let conf = render_users_conf(&[Principal {
            user: "$NATS_USER".into(),
            hash: "$2b$11$x".into(),
            role: Role::Worker,
        }]);
        assert!(conf.contains("user: \"$NATS_USER\"\n"), "{conf}");
        assert!(env_refs_in_conf(&conf).is_empty(), "{conf}");
    }

    #[test]
    fn a_real_principal_is_quoted_on_both_fields() {
        let conf = render_users_conf(&[Principal {
            user: "gateway".into(),
            hash: "$2b$11$abcdefghijklmnopqrstuv".into(),
            role: Role::Gateway,
        }]);
        assert!(conf.contains("user: \"gateway\"\n"), "{conf}");
        assert!(
            conf.contains("password: \"$2b$11$abcdefghijklmnopqrstuv\"\n"),
            "a bcrypt digest starts with `$` but is NOT an env reference — unquoting it \
             would make NATS try to expand it:\n{conf}"
        );
    }

    #[test]
    fn an_env_reference_is_a_dollar_followed_by_an_identifier() {
        assert!(is_env_ref("$NATS_USER"));
        assert!(is_env_ref("$_x9"));
        // A bcrypt digest: `$` then `2b$...`, which is not an identifier.
        assert!(!is_env_ref("$2b$11$abc"));
        assert!(!is_env_ref("$"));
        assert!(!is_env_ref("$NATS-USER"), "a hyphen is not identifier-safe");
        assert!(!is_env_ref("$NATS USER"));
        assert!(!is_env_ref("gateway"));
        assert!(!is_env_ref("node-host3"));
    }

    #[test]
    fn every_node_user_is_quoted() {
        // Node users are literal names and must never be bare — `node-x`
        // is not an identifier, so an unquoted one would not even parse.
        let conf = render_users_conf(&[Principal {
            user: "node-host3".into(),
            hash: "$2b$11$zzz".into(),
            role: Role::Node,
        }]);
        assert!(conf.contains("user: \"node-host3\"\n"), "{conf}");
    }

    #[test]
    fn password_shape_is_parser_safe() {
        for _ in 0..64 {
            let p = mint_password();
            assert_eq!(p.len(), 32);
            assert!(p.chars().next().unwrap().is_ascii_alphabetic(), "leading letter: {p}");
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric()), "alphanumeric only: {p}");
        }
        assert_ne!(mint_password(), mint_password());
    }

    /// The node source is the REGISTRY. `cluster reconnect` read a deleted
    /// inventory file and reported success having done nothing; this pins
    /// that the enumeration here is a pure function of the gateway's answer.
    #[test]
    fn nodes_come_from_the_registry_document() {
        let doc = serde_json::json!({"nodes": [
            {"id": "host9"}, {"node_id": "host8"}, {"name": "host3"},
            {"id": "host9"},
        ]});
        assert_eq!(nodes_from_registry(&doc), vec!["host3", "host8", "host9"]);
        // An empty/absent registry yields nothing to render — the caller
        // turns that into a refusal, never a quiet success.
        assert!(nodes_from_registry(&serde_json::json!({})).is_empty());
        assert!(nodes_from_registry(&serde_json::json!({"nodes": []})).is_empty());
    }

    fn sample() -> Vec<Principal> {
        vec![
            Principal { user: "gateway".into(), hash: "$2b$11$g".into(), role: Role::Gateway },
            Principal { user: "worker".into(), hash: "$2b$11$w".into(), role: Role::Worker },
            Principal { user: "node-host9".into(), hash: "$2b$11$r".into(), role: Role::Node },
            Principal { user: "node-host8".into(), hash: "$2b$11$p".into(), role: Role::Node },
        ]
    }

    #[test]
    fn rendered_config_has_the_expected_shape() {
        let text = render_users_conf(&sample());
        assert!(text.contains("accounts {"));
        assert!(text.contains("NOO: {"));
        assert!(text.contains("jetstream: enabled"));
        assert!(text.contains("users: ["));
        // Braces balance — the cheapest proof the block is includable.
        assert_eq!(text.matches('{').count(), text.matches('}').count());
        assert_eq!(text.matches('[').count(), text.matches(']').count());
        // bcrypt hashes are QUOTED.
        assert!(text.contains("password: \"$2b$11$g\""));
        // Gateway is the only JetStream admin / KV writer: full rights.
        let gw = text.split("user: \"gateway\"").nth(1).unwrap();
        assert!(gw.contains("publish: { allow: [\">\"] }"));
        // Worker is denied the admin surface and the workers' KV.
        let w = text.split("user: \"worker\"").nth(1).unwrap();
        assert!(w.contains("\"worker.>\""));
        assert!(w.contains("\"$KV.>\""));
        assert!(w.contains("$JS.API.STREAM.PURGE.>"));
        assert!(w.contains("allow_responses: { max: 1, expires: \"20m\" }"), "{w}");
        // i69/i70: a reply to the gateway must survive a NATS reload, which
        // wipes allow_responses entries — so each remote principal holds a
        // static publish on ITS OWN reply prefix, and on nobody else's.
        let w_block = w.split("user: \"node-").next().unwrap();
        let w_publish = w_block.split("subscribe:").next().unwrap();
        assert!(w_publish.contains("\"_INBOX_gw.worker.>\""), "{w_block}");
        assert!(!w_publish.contains("\"_INBOX_gw.>\""), "the worker may not answer into every gateway reply:\n{w_block}");
        assert!(!w_publish.contains("_INBOX_gw.node"), "the worker may not answer a node's replies:\n{w_block}");
        for node in text.split("user: \"node-").skip(1) {
            let id = node.split('"').next().unwrap();
            let publish = node.split("subscribe:").next().unwrap();
            let grants: Vec<&str> = publish
                .split('"')
                .filter(|g| g.starts_with("_INBOX"))
                .collect();
            // Exactly one inbox grant: its own prefix. Not the root, not
            // the worker's, not another node's.
            assert_eq!(grants, vec![format!("_INBOX_gw.node.{id}.>")], "node {id}:\n{node}");
        }
        assert!(!text.contains("allow_responses: true"), "a bare `true` is a 2-minute reply window");
    }

    /// The property the whole proposal exists for: node A's user may not
    /// name node B anywhere.
    #[test]
    fn per_node_permissions_name_only_that_node() {
        let text = render_users_conf(&sample());
        let host9 = text
            .split("user: \"node-host9\"")
            .nth(1)
            .unwrap()
            .split("user: \"node-host8\"")
            .next()
            .unwrap();
        assert!(host9.contains("events.job.complete.host9"));
        // The inbox prefix is the agent's, byte for byte: nats.go is given
        // `NodeInboxPrefix(nodeID)` = "_INBOX_node_" + SubjectToken(nodeID).
        // This said "_INBOX_node-host9" — a hyphen where the agent writes an
        // underscore — so every reply the node waited for was denied.
        assert!(host9.contains("_INBOX_node_host9.>"));
        assert!(!host9.contains("_INBOX_node-"), "the inbox prefix is _INBOX_node_<token>, not a hyphen");
        // The three requests js.Subscribe makes before a message can arrive.
        assert!(host9.contains("\"$JS.API.STREAM.NAMES\""));
        assert!(host9.contains("$JS.API.CONSUMER.INFO.TASKS.node_host9_dispatch"));
        assert!(host9.contains("$JS.API.CONSUMER.CREATE.TASKS.node_host9_dispatch.>"));
        // ... and nothing may deny them back. A blanket $JS.API.STREAM.> deny
        // beat the allow above: deny wins, so widening the allow alone did not
        // work. Only the four mutating verbs are denied.
        assert!(!host9.contains("\"$JS.API.STREAM.>\""));
        assert!(host9.contains("node_host9_dispatch"));
        assert!(!host9.contains("host8"), "host9's block names another node:\n{host9}");
        assert!(host9.contains("deny: [\"tasks.>\", \"worker.>\", \"$KV.>\""));
        // The default inbox is nobody's but the gateway's.
        assert!(host9.contains("\"_INBOX.>\""));
    }

    #[test]
    fn node_ids_that_would_widen_a_subject_are_refused() {
        assert!(valid_node_id("host8"));
        assert!(valid_node_id("node_1"));
        assert!(!valid_node_id("a.b"));
        assert!(!valid_node_id("*"));
        assert!(!valid_node_id(">"));
        assert!(!valid_node_id("a b"));
        assert!(!valid_node_id(""));
    }

    #[test]
    fn secret_key_naming_is_dotenv_safe() {
        assert_eq!(node_secret_key("host8"), "NATS_NODE_PASSWORD_HOST8");
        assert!(node_secret_key("host8")
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
    }

    /// The payload names its node, so a signed credential for A cannot be
    /// replayed onto B (the teardown kind's guard, reused).
    #[test]
    fn creds_payload_binds_the_node() {
        let p = creds_payload("host9", "Abc123");
        assert!(p.starts_with("NODE=host9\n"));
        assert!(p.contains("NATS_NODE_USER=node-host9\n"));
        assert!(p.contains("NATS_NODE_PASSWORD=Abc123\n"));
    }

    /// Rendering happens on three occasions (operator verb, fresh onboard,
    /// every node provision). A render that re-minted would rotate the
    /// gateway's and every other node's password out from under them, so
    /// an existing value must be REUSED and only a missing one minted.
    #[test]
    fn a_render_reuses_what_the_store_already_holds() {
        let dir = std::env::temp_dir().join(format!("noo-nats-users-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let envp = dir.join("reuse.env");
        std::fs::write(&envp, "NATS_GATEWAY_PASSWORD=Keepthisone\nNATS_NODE_PASSWORD_HOST9=Alsokeepme\n").unwrap();
        let store = crate::commands::secrets::SecretStore::load_env(&envp);
        let nodes = vec!["host9".to_string(), "host8".to_string()];

        let none = BTreeMap::new();
        let (principals, fresh) = principals_for(&store, &nodes, &[], &none, true, &[]).unwrap();
        // gateway + worker + 2 nodes — and no legacy principal
        assert_eq!(principals.len(), 4);
        // Only what was ABSENT is minted — names only, never values.
        let keys: Vec<&str> = fresh.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["NATS_WORKER_PASSWORD", "NATS_NODE_PASSWORD_HOST8"]);
        // The kept values are the ones the server will now verify against.
        let gw = principals.iter().find(|p| p.user == "gateway").unwrap();
        assert!(bcrypt::verify("Keepthisone", &gw.hash).unwrap());
        let rp = principals.iter().find(|p| p.user == "node-host9").unwrap();
        assert!(bcrypt::verify("Alsokeepme", &rp.hash).unwrap());

        // --rotate re-mints the CONTROLLER principals only. A node's
        // password is never re-minted by a render: minted-but-undelivered
        // is a node off the bus (N10).
        let both: Vec<String> = CONTROLLER_PRINCIPALS.iter().map(|p| p.to_string()).collect();
        let (_, fresh) = principals_for(&store, &nodes, &both, &none, true, &[]).unwrap();
        let keys: Vec<&str> = fresh.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["NATS_GATEWAY_PASSWORD", "NATS_WORKER_PASSWORD", "NATS_NODE_PASSWORD_HOST8"]);
        // One principal at a time is the rotate verb's shape.
        let (_, fresh) = principals_for(&store, &nodes, &["gateway".to_string()], &none, true, &[]).unwrap();
        let keys: Vec<&str> = fresh.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["NATS_GATEWAY_PASSWORD", "NATS_WORKER_PASSWORD", "NATS_NODE_PASSWORD_HOST8"],
            "gateway re-minted, worker minted because ABSENT, host9 kept");
        // Naming a node as a rotate target is refused, not silently honoured.
        assert!(principals_for(&store, &nodes, &["node-host9".to_string()], &none, true, &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_render_leaves_nothing_that_grants_the_whole_bus() {
        // The text, not just the principal list: the DEFAULT render (there
        // is no other since an earlier release) must contain no `$NATS_USER` line
        // in the file the server reads.
        let (principals, _) = principals_for(
            &crate::commands::secrets::SecretStore::load_env(std::path::Path::new("/nonexistent")),
            &["host9".to_string()],
            &[],
            &BTreeMap::new(),
            true,
            &[],
        )
        .unwrap();
        assert_eq!(principals.len(), 3, "gateway + worker + host9, nothing else");
        let text = render_users_conf(&principals);
        assert!(!text.contains("$NATS_USER"), "{text}");
        assert!(!text.contains("$NATS_PASSWORD"), "{text}");

        // Exactly ONE principal may hold `>`: the gateway, which is the
        // JetStream administrator and the KV writer. Count the wide grants
        // and the user lines that precede them.
        let wide = text.matches("allow: [\">\"]").count();
        assert_eq!(wide, 2, "only the gateway's publish+subscribe may be `>`:\n{text}");
        let gw_block = text
            .split("      {\n")
            .find(|b| b.contains("user: \"gateway\""))
            .expect("a gateway principal");
        assert_eq!(gw_block.matches("allow: [\">\"]").count(), 2);
    }

    /// The roll render (`rerender_for_roll`) changes NO credential: a
    /// principal without a stored password keeps the digest the server
    /// already verifies, and one with neither is refused, never minted.
    #[test]
    fn the_roll_render_keeps_digests_and_mints_nothing() {
        let on_disk = format!(
            "{}{}",
            render_users_conf(&[
                Principal { user: "gateway".into(), hash: "$2b$11$GWDIGEST".into(), role: Role::Gateway },
                Principal { user: "worker".into(), hash: "$2b$11$WKDIGEST".into(), role: Role::Worker },
                Principal { user: "node-host3".into(), hash: "$2b$11$AWDIGEST".into(), role: Role::Node },
            ]),
            LEGACY_BLOCK
        );
        let kept = digests_in_conf(&on_disk);
        assert_eq!(kept.get("node-host3").map(String::as_str), Some("$2b$11$AWDIGEST"));
        assert!(!kept.keys().any(|k| k.contains("NATS")), "an env-ref password is not a digest: {kept:?}");
        assert_eq!(node_users_in_conf(&on_disk), ["host3"]);

        let empty = crate::commands::secrets::SecretStore::load_env(std::path::Path::new("/nonexistent"));
        let (p, fresh) = principals_for(&empty, &["host3".to_string()], &[], &kept, false, &[]).unwrap();
        assert!(fresh.is_empty(), "the roll minted {:?}", fresh.iter().map(|(k, _)| k).collect::<Vec<_>>());
        assert_eq!(p.iter().map(|x| x.hash.as_str()).collect::<Vec<_>>(),
            ["$2b$11$GWDIGEST", "$2b$11$WKDIGEST", "$2b$11$AWDIGEST"]);
        let text = render_users_conf(&p);
        assert!(env_refs_in_conf(&text).is_empty(), "{text}");

        // A node the registry knows but neither store nor file does: refused.
        let err = principals_for(&empty, &["host3".to_string(), "newbie".to_string()], &[], &kept, false, &[])
            .unwrap_err();
        assert!(err.contains("NATS_NODE_PASSWORD_NEWBIE") && err.contains("nats-creds rotate"), "{err}");
    }

    #[test]
    fn a_render_writes_the_controller_user_names_into_env() {
        // Half a migration is the failure this closes: the server would
        // demand `gateway`/`worker` while the containers had only the
        // shared pair to present. The refusal messages name this command,
        // so this command has to finish the job.
        let dir = std::env::temp_dir().join(format!("noo-nats-env-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        ensure_controller_users_in_env(&dir).unwrap();
        let env = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(env.contains("NATS_GATEWAY_USER=gateway"), "{env}");
        assert!(env.contains("NATS_WORKER_USER=worker"), "{env}");

        // Idempotent, and never overwrites a rename the operator made.
        std::fs::write(dir.join(".env"), "NATS_GATEWAY_USER=gw-renamed\n").unwrap();
        ensure_controller_users_in_env(&dir).unwrap();
        let env = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(env.contains("NATS_GATEWAY_USER=gw-renamed"), "{env}");
        assert!(env.contains("NATS_WORKER_USER=worker"), "{env}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_targets_split_by_where_the_credential_lives() {
        let (p, n) = split_targets(&["Gateway".into(), "worker".into()]).unwrap();
        assert_eq!(p, ["gateway", "worker"]);
        assert!(n.is_empty());
        let (p, n) = split_targets(&["host9".into(), "host8".into()]).unwrap();
        assert!(p.is_empty());
        assert_eq!(n, ["host9", "host8"]);
        // Opposite orders — never one run.
        assert!(split_targets(&["gateway".into(), "host9".into()]).is_err());
    }

    #[test]
    fn the_rendered_file_names_its_own_node_principals() {
        // The floor `noo onboard` re-renders against. Plant the failure:
        // the parse must FIND the nodes, or the guard reads as "no nodes"
        // and hands the caller the empty list that caused the outage.
        let conf = render_users_conf(&[
            Principal { user: "gateway".into(), hash: "$2a$x".into(), role: Role::Gateway },
            Principal { user: "worker".into(), hash: "$2a$x".into(), role: Role::Worker },
            Principal { user: "node-host8".into(), hash: "$2a$x".into(), role: Role::Node },
            Principal { user: "node-host9".into(), hash: "$2a$x".into(), role: Role::Node },
        ]);
        let found = node_users_in_conf(&conf);
        assert_eq!(found, ["host8", "host9"], "did not re-read its own output:\n{conf}");

        // Round trip: re-rendering with the recovered ids reproduces every
        // node principal. This is the property onboard depends on.
        let again = render_users_conf(
            &[
                Principal { user: "gateway".into(), hash: "$2a$x".into(), role: Role::Gateway },
                Principal { user: "worker".into(), hash: "$2a$x".into(), role: Role::Worker },
            ]
            .into_iter()
            .chain(found.iter().map(|id| Principal {
                user: format!("node-{id}"),
                hash: "$2a$x".into(),
                role: Role::Node,
            }))
            .collect::<Vec<_>>(),
        );
        assert_eq!(node_users_in_conf(&again), ["host8", "host9"]);

        // And the guard fails when it should: a controller-only file has
        // no node principals, which is the genuine fresh-install answer.
        let fresh = render_users_conf(&[Principal {
            user: "gateway".into(),
            hash: "$2a$x".into(),
            role: Role::Gateway,
        }]);
        assert!(node_users_in_conf(&fresh).is_empty(), "{fresh}");
        // A hand-edited id that cannot be a subject token is refused, not
        // sanitized — same rule as `valid_node_id` at render time.
        assert!(node_users_in_conf("        user: \"node-bad.id\"\n").is_empty());
    }

    #[test]
    fn a_render_keeps_every_password_the_store_already_holds() {
        // Onboard re-renders on every run. `principals_for` must be
        // reuse-or-mint for the controller pair AND for each node, or a
        // re-run rotates credentials nobody delivered.
        let dir = std::env::temp_dir().join(format!("noo-nats-reuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let envp = dir.join(".env");
        std::fs::write(
            &envp,
            format!(
                "NATS_GATEWAY_PASSWORD=gw-existing\nNATS_WORKER_PASSWORD=wk-existing\n{}=node-existing\n",
                node_secret_key("host8")
            ),
        )
        .unwrap();
        let store = crate::commands::secrets::SecretStore::load_env(&envp);
        assert!(store.contains("NATS_GATEWAY_PASSWORD"), "the fixture did not load");
        let nodes = vec!["host8".to_string(), "host9".to_string()];
        let (principals, fresh) = principals_for(&store, &nodes, &[], &BTreeMap::new(), true, &[]).unwrap();
        assert_eq!(principals.len(), 4, "gateway + worker + 2 nodes");
        // Only the node with NO stored password is minted.
        assert_eq!(
            fresh.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            [node_secret_key("host9").as_str()],
            "a re-run rotated a credential it should have reused"
        );
        // The kept ones really are the stored ones (verify, don't assume).
        let gw = principals.iter().find(|p| p.user == "gateway").unwrap();
        assert!(bcrypt::verify("gw-existing", &gw.hash).unwrap());
        let node = principals.iter().find(|p| p.user == "node-host8").unwrap();
        assert!(bcrypt::verify("node-existing", &node.hash).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── add-on principals (i70 residue) ───────────────────────────────

    fn with_addons() -> Vec<Principal> {
        let mut p = sample();
        p.insert(2, Principal { user: "trellion".into(), hash: "$2b$11$t".into(), role: Role::Addon });
        p.insert(3, Principal { user: "trellion_intel".into(), hash: "$2b$11$i".into(), role: Role::Addon });
        p
    }

    /// One principal's block of a rendered file.
    fn block<'a>(text: &'a str, user: &str) -> &'a str {
        text.split("      {\n").find(|b| b.contains(&format!("user: \"{user}\""))).unwrap_or_else(|| panic!("no {user} in:\n{text}"))
    }

    fn list_after<'a>(section: &'a str, key: &str) -> Vec<&'a str> {
        let rest = section.split(key).nth(1).unwrap_or("");
        let inner = rest.split('[').nth(1).unwrap_or("").split(']').next().unwrap_or("");
        inner.split(", ").map(|x| x.trim_matches('"')).filter(|x| !x.is_empty()).collect()
    }

    #[test]
    fn an_addon_principal_subscribes_on_its_subjects_and_publishes_on_its_own_prefix() {
        let text = render_users_conf(&with_addons());
        assert_eq!(text.matches('{').count(), text.matches('}').count());
        for a in ADDON_PRINCIPALS {
            let b = block(&text, a.name);
            let (publish, subscribe) = b.split_once("subscribe:").unwrap();
            let pub_allow = list_after(publish, "allow:");
            assert_eq!(pub_allow, ["$JS.API.STREAM.INFO.*", &format!("_INBOX_gw.{}.>", a.name)], "{b}");
            let mut sub_allow = list_after(subscribe, "allow:");
            assert_eq!(sub_allow.pop(), Some(format!("_INBOX_{}.>", a.name).as_str()), "{b}");
            assert_eq!(sub_allow, a.subjects, "{b}");
            assert!(b.contains("allow_responses: { max: 1, expires: \"20m\" }"), "{b}");
            // Nothing of the worker's: not its reply prefix, not its subject tree.
            assert!(!b.contains("_INBOX_gw.worker"), "{b}");
            assert!(!sub_allow.contains(&"worker.>"), "{b}");
            assert!(!b.contains("agent."), "{b}");
        }
        // Neither add-on may serve the other's subjects.
        let t = block(&text, "trellion");
        let i = block(&text, "trellion_intel");
        assert!(!t.contains("worker.graph") && !t.contains("_INBOX_gw.trellion_intel"), "{t}");
        assert!(!i.contains("worker.rag") && !i.contains("\"_INBOX_gw.trellion.>\""), "{i}");
    }

    /// The worker's grant no longer covers an add-on's subjects once that
    /// add-on has a principal of its own — and keeps them (with the add-on's
    /// reply prefix) for one release while it does not.
    #[test]
    fn the_worker_grant_no_longer_covers_addon_subjects() {
        let text = render_users_conf(&with_addons());
        let w = block(&text, "worker");
        let (publish, subscribe) = w.split_once("subscribe:").unwrap();
        let sub_deny: Vec<&str> = {
            let rest = subscribe.split("deny: [").nth(1).unwrap().split(']').next().unwrap();
            rest.split(", ").map(|x| x.trim_matches('"')).collect()
        };
        for a in ADDON_PRINCIPALS {
            for s in a.subjects {
                assert!(sub_deny.contains(s), "the worker may still subscribe {s}:\n{w}");
            }
            assert!(!publish.contains(&format!("_INBOX_gw.{}", a.name)), "the worker answers into {}'s prefix:\n{w}", a.name);
        }
        // Core subjects stay the worker's.
        assert!(!sub_deny.iter().any(|d| d.starts_with("worker.tool") || *d == "worker.>"), "{w}");

        // Fallback: no add-on principal rendered → the worker keeps the
        // subjects AND the add-ons' reply prefixes (they present it).
        let text = render_users_conf(&sample());
        let w = block(&text, "worker");
        let (publish, subscribe) = w.split_once("subscribe:").unwrap();
        for a in ADDON_PRINCIPALS {
            assert!(publish.contains(&format!("\"_INBOX_gw.{}.>\"", a.name)), "{w}");
            for s in a.subjects {
                assert!(!subscribe.contains(&format!("\"{s}\"")), "{w}");
            }
        }
    }

    #[test]
    fn no_two_principals_share_a_password() {
        let dir = std::env::temp_dir().join(format!("noo-nats-dup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let envp = dir.join("dup.env");
        std::fs::write(&envp, "NATS_GATEWAY_PASSWORD=Gwone\nNATS_WORKER_PASSWORD=Same\nNATS_TRELLION_PASSWORD=Same\n").unwrap();
        let store = crate::commands::secrets::SecretStore::load_env(&envp);
        let err = principals_for(&store, &[], &[], &BTreeMap::new(), true, &["trellion"]).unwrap_err();
        assert!(err.contains("NATS_WORKER_PASSWORD") && err.contains("NATS_TRELLION_PASSWORD"), "{err}");
        // Distinct passwords render, each add-on its own principal, and the
        // digests verify only their own plaintext.
        std::fs::write(&envp, "NATS_GATEWAY_PASSWORD=Gwone\nNATS_WORKER_PASSWORD=Wkone\nNATS_TRELLION_PASSWORD=Trone\n").unwrap();
        let store = crate::commands::secrets::SecretStore::load_env(&envp);
        let (p, fresh) = principals_for(&store, &[], &[], &BTreeMap::new(), true, &["trellion", "trellion_intel"]).unwrap();
        assert_eq!(p.iter().map(|x| x.user.as_str()).collect::<Vec<_>>(), ["gateway", "worker", "trellion", "trellion_intel"]);
        assert_eq!(fresh.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["NATS_TRELLION_INTEL_PASSWORD"]);
        let t = p.iter().find(|x| x.user == "trellion").unwrap();
        assert_eq!(t.role, Role::Addon);
        assert!(bcrypt::verify("Trone", &t.hash).unwrap());
        assert!(!bcrypt::verify("Wkone", &t.hash).unwrap());
        assert_eq!(shared_passwords(&[("A".into(), "x".into()), ("B".into(), "y".into()), ("C".into(), "x".into())]),
            [("A".to_string(), "C".to_string())]);
        assert!(shared_passwords(&[("A".into(), String::new()), ("B".into(), String::new())]).is_empty(),
            "an absent password is not a shared one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The roll mints nothing: an add-on with no stored password and no
    /// digest is left out (its container falls back to the worker for one
    /// release), never refused and never minted.
    #[test]
    fn the_roll_leaves_an_unminted_addon_on_the_worker() {
        let empty = crate::commands::secrets::SecretStore::load_env(std::path::Path::new("/nonexistent"));
        let kept: BTreeMap<String, String> =
            [("gateway", "$2b$11$G"), ("worker", "$2b$11$W")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let (p, fresh) = principals_for(&empty, &[], &[], &kept, false, &["trellion"]).unwrap();
        assert!(fresh.is_empty());
        assert_eq!(p.len(), 2, "{p:?}");
        // An undeclared add-on cannot be rotated into existence.
        let err = principals_for(&empty, &[], &["trellion_intel".to_string()], &kept, true, &["trellion"]).unwrap_err();
        assert!(err.contains("nats_principal"), "{err}");
        assert_eq!(split_targets(&["trellion".into(), "Trellion_Intel".into()]).unwrap().0, ["trellion", "trellion_intel"]);
    }

    #[test]
    fn a_principal_is_declared_by_its_overlay_and_only_under_its_own_name() {
        let yes = "x-noo-addon:\n  addon: trellion\n  nats_principal: trellion\n";
        assert!(overlay_declares_principal(yes, "trellion"));
        assert!(!overlay_declares_principal(yes, "trellion_intel"), "a block declares its own add-on's principal only");
        assert!(!overlay_declares_principal("x-noo-addon:\n  addon: trellion\n", "trellion"));
        assert!(!overlay_declares_principal("not: [yaml", "trellion"));
        // The core overlay declares trellion's.
        let core = include_str!("../../../docker-compose.trellion.yml");
        assert!(overlay_declares_principal(core, "trellion"));
        assert_eq!(addon_users_in_conf(&render_users_conf(&with_addons())), ["trellion", "trellion_intel"]);
        assert!(addon_users_in_conf(&render_users_conf(&sample())).is_empty());
    }

    #[test]
    fn bcrypt_hash_verifies() {
        let pw = mint_password();
        let h = nats_bcrypt(&pw).unwrap();
        assert!(h.starts_with("$2"), "{h}");
        assert!(bcrypt::verify(&pw, &h).unwrap());
    }
}
