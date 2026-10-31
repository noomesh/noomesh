// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster provision <node> [tier] [--wait [secs]]` — the controller half
//! of node birth, NATIVE. Reproduces scripts/provision-node.sh + the
//! retired ansible play without ansible, python, Go, or a repo checkout — so a
//! standalone controller can add nodes.
//!
//! Delivery is PULL only. The SSH gate lane it used to fall back to is gone
//! The bundle is encrypted to the node's birth cert and staged
//! at the gateway, and the node's fetch timer collects it. A node with no
//! birth cert is a re-enroll, not a reason to reach in.
//!
//! Flow (identical to the proven script; every deviation is a bug):
//!   1. --wait: poll the bootstrap-token API until the node's name-bound token
//!      shows used_at, then settle 20s (prep runs after redemption).
//!   2. Inventory: if the node has no line, resolve ip+user from the redemption
//!      record and derive the tier from the facts the node REPORTED at
//!      enrollment (SBC→4, GPU→2, arm→4, else 3 — tier 1 never auto), then
//!      append the line. The enrollment IS the registration; the tier probe
//!      that used to ssh for those facts is gone, because the node already
//!      sent them.
//!   3. Certs: `pki issue-node` into the local PKI if missing (NOT push-nodes —
//!      that restarts an agent a fresh node doesn't have).
//!   4. Credentials from secrets/env.sops (sops -d, in memory only).
//!   5. Agent binary: extracted from the multi-arch GHCR node-agent image for
//!      the arch the node REPORTS (docker create+cp — no Go toolchain); falls
//!      back to build-cross.sh when the source tree exists (dev checkouts
//!      testing unreleased agents).
//!   6. Env rendered from the REAL ansible template (single source of truth —
//!      see render_env_template) with the system PKI layout.
//!   7. ONE CA-signed bundle (env+unit+binary+certs), CMS-encrypted to the
//!      node's birth cert and STAGED at the gateway for the node's fetch timer
//!      to collect. No shell on the node, no sudo, no inbound connection.
//!
//! `cluster_provision` is a literal ordered list of phases; read it for the
//! order. In order: `parse_provision_args`, `begin_provision` (lane),
//! `wait_for_enrollment` (1), `load_enrollment` (2), `resolve_identity`,
//! `resolve_machine`, `ensure_node_certs` + door leaves (3), `load_credentials`
//! (4), `obtain_binary` (5), `read_env_template` / `build_env_vars` /
//! `check_data_root` / `render_agent_env` (6), `read_bundle_material`,
//! `prepare_bundle_workspace`, `base_bundle_files`, the `attach_*` phases
//! (applier+fetcher, hostd, CLI, harness, vendor CLIs, backend door leaves,
//! NATS credential; `drop_binaries_the_node_already_runs`), `sign_bundle` (7),
//! `stage_applier_first`, `stage_bundle`, `report_staged_only` (--stage-only),
//! `await_apply`, `report_provisioned`. The source-reading tests read the list
//! for ORDER and the owning phase for CONTENT (`phase_src` at the bottom).

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use crate::ui::Glyph;

/// Per-node rhythm (guide §5): every step of one node's provisioning sits
/// indented under its `ui::item` label, so the node reads as one unit.
fn nstep(msg: &str) {
    if !ui::quiet() {
        println!("{}", ui::sub(&ui::status_line(Glyph::Step, msg)));
    }
}
fn nnote(msg: &str) {
    if !ui::quiet() {
        println!("{}", ui::sub(&ui::note(msg)));
    }
}
/// The loopback publish of the standalone embedder's mTLS door
/// (docker-compose.cluster.yml `stunnel-ollama-embed`).
pub(crate) const OLLAMA_EMBED_LOOPBACK_DOOR: &str = "127.0.0.1:11434:11434";

/// The controller's own agent's OLLAMA_URL — where its "stack" ollama lane
/// looks (node-agent-go backendrt/native.go).
///
/// `https://127.0.0.1:11434` — the `stunnel-ollama-embed` door, dialled
/// with the node leaf — only when this is a standalone install (the only
/// one that runs the sidecar) AND the compose file it runs from declares
/// the sidecar's loopback publish. The second condition is the roll guard:
/// a re-provision on a stack that has not yet been rolled (`noo upgrade
/// --stack`) would otherwise point the agent at a TLS door that is still
/// the raw ollama's plaintext publish, and the lane would find nothing.
/// Otherwise the pre-1245 plaintext loopback URL, which is correct for
/// exactly that stack. An agent too old to dial https is not the concern
/// here: provision delivers the agent binary with this env.
fn self_node_ollama_url(root: &Path) -> String {
    let standalone = root.join(".noo-standalone").is_file();
    let door = standalone
        && std::fs::read_to_string(root.join("docker-compose.cluster.yml"))
            .map(|c| super::cluster_verify::compose_publishes(&c, "stunnel-ollama-embed", OLLAMA_EMBED_LOOPBACK_DOOR))
            .unwrap_or(false);
    if door { "https://127.0.0.1:11434" } else { "http://127.0.0.1:11434" }.to_string()
}

fn human_bytes(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0} kB", n as f64 / 1_000.0)
    } else {
        format!("{n} B")
    }
}
/// A node-level failure with FULL guidance: `✗` on stderr (after a blank
/// line) and a `▸` block naming every command with a why — the JSON path
/// keeps the classic `{error, code, hint}` envelope via `fail`.
fn fail_guided(g: &Globals, code: ExitCode, kind: &str, msg: &str, hint: &str, guide: &[(&str, &str)]) -> ! {
    if g.json {
        fail(g.json, code, kind, msg, Some(hint));
    }
    println!();
    ui::failed(msg, None);
    ui::guide(guide);
    ui::pager_finish();
    std::process::exit(code as i32);
}


/// Record that `node` holds the CURRENT fleet signing key, from the
/// applier's own report of the bundle it just applied (exit 0).
///
/// An earlier release retired the CA-signed apply lane, so a node that has not
/// adopted the signing key receives CA-signed ROLLOVER bundles (they carry
/// `signing-pub`, see `security_local::build_signed_bundle_with_key`) and
/// adopts on that apply. Writing the marker here moves its next bundle onto
/// the signing key without a separate `rotate-signing-key` pass. Positive
/// proof only: every verified-by lane that exists today means the node now
/// holds the key this controller signs with (a rollover installed it; a
/// signing-key verification proved it). An older applier that reports no
/// lane writes nothing.
fn record_signing_adoption(node: &str, msg: &str) {
    let Some(via) = verified_by(msg) else { return };
    if !matches!(via.as_str(), "signing-key" | "ca-rollover" | "ca-rollover-countersigned") {
        return;
    }
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    let Ok(pubkey) = std::fs::read(ca.signing_pub_path()) else { return };
    mark_signing_adopted(&ca, node, &pubkey);
}

/// Write the `signing-adopted` marker for `node`: this controller's record
/// that the node holds the signing key whose public half is `pubkey`. Call
/// it only on proof the key was installed there (an applier's report, or
/// the controller's own root install exiting 0).
fn mark_signing_adopted(ca: &crate::pki::ClusterCa, node: &str, pubkey: &[u8]) {
    let marker = ca.signing_adopted_path(node);
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &marker,
        format!("{}\n", super::security_local::signing_pub_fingerprint(pubkey)),
    );
}

fn read_or_fail_path(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn verified_by(msg: &str) -> Option<String> {
    let at = msg.find("verified-by:")? + "verified-by:".len();
    msg[at..].split_whitespace().next().map(str::to_string).filter(|v| !v.is_empty())
}


/// Run `noo security pki rotate-signing-key <node> --deliver-only --yes` in a
/// child (it reports through `fail`, which exits) and require the adoption
/// marker afterwards. Positive proof only: the child writes the marker when
/// the node REPORTED applying the rollover.
fn deliver_signing_key_first(g: &Globals, node: &str, ca: &crate::pki::ClusterCa) {
    nstep(&format!(
        "{node} has not adopted the fleet signing key — delivering the key alone first \
         (the CA signs nothing else)"));
    let exe = std::env::current_exe().ok().and_then(|p| super::upgrade::reexec_path(&p));
    let ran = match exe {
        Some(exe) => {
            let mut cmd = std::process::Command::new(exe);
            if let Some(u) = &g.gateway_override { cmd.arg("--gateway").arg(u); }
            if let Some(t) = &g.token { cmd.env("NOO_TOKEN", t); }
            cmd.args(["security", "pki", "rotate-signing-key", node, "--deliver-only", "--yes"]);
            cmd.status().map(|s| s.success()).unwrap_or(false)
        }
        None => false,
    };
    if !ran || !ca.signing_adopted(node) {
        let cmd = format!("noo security pki rotate-signing-key {node} --deliver-only");
        fail_guided(g, ExitCode::Generic, "signing_key_not_adopted",
            &format!("{node} did not confirm the fleet signing key, so no bundle can be signed for it \
                      (the CA signs nothing but the key)"),
            &format!("{cmd}   # then re-run `noo cluster provision {node}`"),
            &[(&cmd, "delivers the key alone and reports whether the node applied it"),
              (&format!("noo cluster provision {node} --wait"), "once it has adopted")]);
    }
}

/// How the node verified the bundle it just applied, in the operator's words,
/// from the applier's own report.
///
/// `noo-apply` prints `verified-by: <lane>` and, since the lane became
/// closeable from the controller, `ca-lane: closed|open`. Reading those back
/// is the only honest way to answer "is the CA-signed compatibility lane shut
/// on this node" — the question used to be answered by looking at a file that
/// nothing read.
fn verification_lane(msg: &str) -> Option<String> {
    // The applier prints `verified-by:` and `ca-lane:` on their own LINES, and
    // this read them as lines — but the report that reaches the controller has
    // them collapsed into one, so the field lookup never matched and the check
    // printed nothing. A check that exists and never fires is the failure this
    // whole campaign is about, and it shipped in the PR that added the check
    // (observed on host8, 2026-09-12: the stored report read
    // `applied: … verified-by: signing-key ca-lane: closed` on a single line
    // while `provision --wait` said nothing).
    //
    // So the key is found anywhere in the message and the value is the next
    // whitespace-delimited token, which is what both fields are.
    let field = |k: &str| -> Option<String> {
        let at = msg.find(k)? + k.len();
        msg[at..].split_whitespace().next().map(str::to_string).filter(|v| !v.is_empty())
    };
    let via = field("verified-by:")?;
    let lane = match field("ca-lane:").as_deref() {
        Some("retired") => " · CA-signed lane retired on this node",
        // An applier older than the retirement of the CA-signed lane still reports the arm it had.
        // It is replaced by the applier riding this same bundle (§1b), so
        // this reads only on a report from before the upgrade.
        Some("closed") => " · CA-signed lane closed (applier predates its retirement)",
        Some("open") => " · CA-signed lane OPEN on an applier that predates its retirement — re-stage to replace the applier",
        _ => "",
    };
    Some(match via.as_str() {
        "signing-key" => format!("verified against the fleet signing key{lane}"),
        "ca-rollover" => format!("verified against the cluster CA — a signing-key rollover (first adoption){lane}"),
        "ca-rollover-countersigned" => format!(
            "verified against the cluster CA, countersigned by the node's own signing key — a rollover{lane}"
        ),
        "ca-legacy" => format!(
            "verified against the cluster CA on the RETIRED compatibility lane — this node's \
             applier predates the retirement of the CA-signed lane; re-stage so the bundle's applier replaces it{lane}"
        ),
        other => format!("verified-by: {other}{lane}"),
    })
}


/// Which data root the bundle renders: the operator's declaration, else the
/// birth-time fact, else the built-in default.
///
/// Separated from the lookups so the precedence is testable without a gateway.
/// It is the precedence that was wrong, not the reads.
/// declared > reported (what the node runs on) > birth fact > default. An
/// unusable declaration falls through, as in [`resolve_data_root`].
fn pick_data_root(declared: Option<&str>, reported: Option<&str>, fact: Option<&str>) -> String {
    let usable = |s: &&str| s.trim().starts_with('/') && s.trim().len() > 1;
    resolve_data_root(declared.filter(usable).or(reported.filter(usable)), fact)
}

fn resolve_data_root(declared: Option<&str>, fact: Option<&str>) -> String {
    let usable = |s: &str| {
        let s = s.trim();
        (s.starts_with('/') && s.len() > 1).then(|| s.to_string())
    };
    declared
        .and_then(usable)
        .or_else(|| fact.and_then(usable))
        .unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.to_string())
}

/// The node's data root as the OPERATOR declared it, from the DB row
/// `noo cluster set-config` writes and `noo cluster desired` shows.
///
/// `None` when there is no row, no value, or the gateway cannot be reached —
/// every one of which means "nothing was declared", and the caller falls back
/// to the enrollment fact. A read failure must not silently relocate a node's
/// data, so it is treated as no declaration rather than as an error.
fn declared_data_root(g: &Globals, node: &str) -> Option<String> {
    let body = crate::http::get_json_opt(
        g,
        &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node)),
        true,
        10,
    )?;
    body.get("node")
        .and_then(|n| n.get("data_root"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| s.starts_with('/') && s.len() > 1)
        .map(str::to_string)
}

/// `noo cluster provision <node>` as a LITERAL, ORDERED list of phases. Read
/// this function for the order; each phase owns its behaviour, messages and
/// exit codes (all unchanged from when this was one 1150-line body).
///
/// The invariants the order encodes (the source-reading tests read THIS body
/// for order and the one phase that owns a behaviour for content):
///
/// 1. The rail verb never runs the first-install (sudo) lane: its only sudo
///    is the self node's identity step, inside `begin_provision`.
/// 2. The self node is built from THIS machine (`load_enrollment`), checked
///    against the gateway's view of it, and only then is anything staged
///    (`stage_bundle`). Nothing is staged that the gateway could not verify.
/// 3. hostd is attached for EVERY node before, and outside, the self-node CLI
///    branch (`attach_hostd` precedes `attach_cli`).
/// 4. No bundle leaves without this node's own NATS pair: the credential is
///    attached (`attach_nats_credential`) before the bundle is signed
///    (`sign_bundle`), which itself requires the pair before it signs.
/// 5. A refusal (`no_birth_cert`, `data_root_conflict`, `agent_binary`, ...)
///    happens before the bundle is built; once files are being attached, every
///    failure scrubs the scratch dir first.
/// 6. `--stage-only` returns right after the poke; otherwise `await_apply`
///    judges the node's own apply report, and a self-node success runs
///    `after_self_applied`, which no other path may reimplement.
pub fn cluster_provision(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_provision_args(g, args);

    // Who and where: the lane, the enrollment, the identity, the machine.
    let site = begin_provision(g, &a);
    wait_for_enrollment(g, &a, &site);
    let enrollment = load_enrollment(g, &a, &site);
    let id = resolve_identity(g, &a, &site, &enrollment);
    let machine = resolve_machine(g, &a, &enrollment);

    // The node's PKI, and the agent it will run.
    let pki = ensure_node_certs(g, &a, &site, &id);
    ensure_door_leaves(g, &crate::pki::ClusterCa::new(pki.clone()), &a.node);
    let creds = load_credentials(g, &site);
    let binary = obtain_binary(g, &site, &machine);
    let tmpl = read_env_template(g, &site);
    let vars = build_env_vars(g, &a, &site, &id, &machine, creds);
    check_data_root(g, &a, &enrollment, &machine, &vars);
    let env_body = render_agent_env(g, &a, &enrollment, &machine, &tmpl, &vars);

    // The bundle: every file the node will apply, then one signature.
    let material = read_bundle_material(g, &a, &site, &pki);
    let (ca, work) = prepare_bundle_workspace(g, &a, &pki);
    let mut files = base_bundle_files(&id, &machine, env_body, binary, material);
    attach_applier_and_fetcher(&machine, &mut files);
    attach_hostd(g, &site, &enrollment, &machine, &mut files);
    attach_cli(&a, &site, &enrollment, &id, &machine, &mut files);
    attach_harness(g, &a, &site, &enrollment, &id, &machine, &vars, &mut files);
    attach_vendor_clis(g, &a, &site, &enrollment, &machine, &work, &mut files);
    drop_binaries_the_node_already_runs(g, &a, &machine, &mut files);
    attach_door_leaves(g, &a, &enrollment, &machine, &ca, &work, &mut files);
    attach_nats_credential(g, &a, &site, &work, &mut files);
    let bundle = sign_bundle(g, &a, &ca, &files, &work);

    // Stage it at the gateway, then judge what the node reports.
    let legacy = stage_applier_first(g, &a, &machine, &ca);
    let staged = stage_bundle(g, &a, &enrollment, &machine, &bundle, &work, legacy);
    if a.stage_only {
        report_staged_only(g, &a, &staged);
        return Ok(0);
    }
    await_apply(g, &a, &machine, &staged);
    report_provisioned(g, &a, &id, &machine);
    Ok(0)
}

/// What `noo cluster provision` was asked for (argv, parsed once).
struct ProvisionArgs {
    node: String,
    tier: Option<String>,
    wait: Option<u64>,
    local: bool,
    harness: Option<String>,
    move_data: bool,
    stage_only: bool,
}

/// Where this provision runs: the install root, and whether the node being
/// provisioned is this controller's own.
struct ProvSite {
    root: std::path::PathBuf,
    is_self: bool,
}

/// What the gateway knows about the node: its enrollment record, its live
/// record and the app version it reports.
struct ProvEnrollment {
    record: Option<Redemption>,
    live_node: Option<serde_json::Value>,
    node_app_version: String,
}

/// The node's address, account and tier, resolved from its enrollment.
struct ProvIdentity {
    ip: String,
    user: String,
    tier: String,
}

/// The node's machine facts that decide what the bundle contains.
struct ProvMachine {
    birth_cert: Option<String>,
    goarch: String,
    data_root: String,
    darwin: bool,
}

/// The certificate material the bundle carries (read from the local PKI).
struct BundleMaterial {
    unit: Vec<u8>,
    ca_crt: Vec<u8>,
    node_crt: Vec<u8>,
    node_key: Vec<u8>,
}

/// A bundle staged at the gateway: what the apply wait judges against.
struct ProvStaged {
    sha: String,
    poked: bool,
    legacy: bool,
}

/// Parse `noo cluster provision <node> [tier] [flags]`. Native-only: bad args print usage here.
fn parse_provision_args(g: &Globals, args: &[String]) -> ProvisionArgs {
    let mut node: Option<String> = None;
    let mut tier: Option<String> = None;
    let mut wait: Option<u64> = None;
    // Transport: PULL, and only PULL
    // 2026-09-05) — the bundle is encrypted to the node's birth cert and
    // STAGED at the gateway; the node's noo-fetch timer collects it. No
    // controller→node connection at all.
    // --local is retired as a lane (i67): the controller's own node rides
    // the rail like any node, and the sudo install runs only inside
    // `noo onboard` (provision_local). The flag is still accepted so an old
    // script says what changed instead of dying on an unknown flag.
    let mut local = false;
    // The harness policy this node is born with: `auto` means
    // the loop follows whatever chat backend is later placed here, so the
    // node is ready for one before it has one. Omitted = the cluster
    // default (NOO_HARNESS_DEFAULT_POLICY, else manual).
    let mut harness: Option<String> = None;
    // --move-data: acknowledge that this bundle moves the
    // node's data root off the one it runs on. Moves nothing itself.
    let mut move_data = false;
    // --stage-only: stage + poke, then return without waiting for the node
    // to apply (`noo upgrade --nodes` stages every node this way and waits
    // for them together). It removes ONLY the apply wait: `--wait` still
    // governs the enrollment wait at step 1, exactly as it always has.
    let mut stage_only = false;
    let mut it = args.iter().peekable();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--local" => local = true,
            "--move-data" => move_data = true,
            "--stage-only" => stage_only = true,
            "--harness" => {
                let v = it.next().cloned().unwrap_or_default();
                if !matches!(v.as_str(), "auto" | "manual" | "off") {
                    fail(g.json, ExitCode::Usage, "usage", "--harness must be auto, manual or off",
                        Some("usage: noo cluster provision <node> [tier] [--harness auto|manual|off] [--wait [secs]] [--stage-only] [--move-data]"));
                }
                harness = Some(v);
            }
            "--wait" => {
                // Same rule as the script: consume the next arg only when it
                // is actually a number (bug 2 of the first live onboard).
                wait = Some(match it.peek().and_then(|v| v.parse::<u64>().ok()) {
                    Some(n) => { it.next(); n }
                    None => 1800,
                });
            }
            // Native-only command: bad args must print usage here, never fall
            // through to another implementation.
            t if t.starts_with('-') => fail(g.json, ExitCode::Usage, "usage",
                &format!("unknown flag: {t}"),
                Some("usage: noo cluster provision <node> [tier] [--harness auto|manual|off] [--wait [secs]] [--stage-only] [--move-data]")),
            t if node.is_none() => node = Some(t.to_string()),
            t if tier.is_none() => tier = Some(t.to_string()),
            t => fail(g.json, ExitCode::Usage, "usage",
                &format!("unexpected argument: {t}"),
                Some("usage: noo cluster provision <node> [tier] [--harness auto|manual|off] [--wait [secs]] [--stage-only] [--move-data]")),
        }
    }
    let Some(node) = node else {
        fail(g.json, ExitCode::Usage, "usage", "node name required",
            Some("usage: noo cluster provision <node> [tier] [--harness auto|manual|off] [--wait [secs]] [--stage-only] [--move-data]"));
    };
    ProvisionArgs { node, tier, wait, local, harness, move_data, stage_only }
}

/// Print the node header and settle which lane the node rides.
/// i67: the controller's own node rides the rail, exactly like a remote
/// node, whenever its pull units exist; without them it is refused (never
/// a sudo fallback) and `noo onboard` does the one first install.
///
/// i11a still holds, by construction: the self node is never resolved
/// from an enrollment record (one under its name may belong to another
/// machine that announced the same name). Its address, account, facts
/// and birth cert come from THIS machine (self_node_redemption), and the
/// birth cert is recorded at the gateway by the self-node route.
fn begin_provision(g: &Globals, a: &ProvisionArgs) -> ProvSite {
    let node = a.node.clone();
    let local = a.local;
    if !g.json && !ui::quiet() {
        println!("{}", ui::item(&node));
    }
    let root = crate::envfile::repo_root();

    let is_self = crate::role::is_self_node(&node) && crate::role::detect().controller.is_some();
    if local && !is_self {
        fail(g.json, ExitCode::Usage, "usage",
            &format!("--local is retired: '{node}' is not this controller's own node"),
            Some("a remote node enrolls (`noo enroll` on it) and is provisioned over the rail: noo cluster provision <node>"));
    }
    if local {
        nnote("--local is retired: the controller's own node rides the rail like any node (the sudo install runs only inside `noo onboard`)");
    }
    if is_self {
        let missing = pull_units_missing(&node);
        match self_node_lane(&node, &missing, !missing.is_empty() && can_sudo_here()) {
            SelfLane::Rail => {}
            SelfLane::CreateIdentity => {
                if let Err(e) = ensure_self_identity(&node) {
                    fail(g.json, ExitCode::Generic, "self_identity", &e, Some(SELF_RAIL_REMEDY));
                }
            }
            SelfLane::Refuse(why) => fail(g.json, ExitCode::Generic, "self_node_units", &why, Some(SELF_RAIL_REMEDY)),
        }
    }
    ProvSite { root, is_self }
}

/// Step 1: --wait for the enrollment to land (skipped for the controller's own node).
fn wait_for_enrollment(g: &Globals, a: &ProvisionArgs, site: &ProvSite) {
    let node = a.node.clone();
    let wait = a.wait;
    let is_self = site.is_self;
    if let Some(secs) = wait.filter(|_| !is_self) {
        // One live line (guide §5 "Waiting is one line"); off a TTY a
        // heartbeat per minute (finding #73: a silent multi-minute wait
        // reads as a hang AND lets idle SSH/NAT paths drop the session).
        let mut poll = ui::Poll::start_under(&format!("waiting up to {secs}s for {node}'s enrollment to land"));
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(secs);
        loop {
            if redemption_record(g, &node).is_some() {
                poll.done(&format!("{node} enrolled"));
                break;
            }
            if std::time::Instant::now() >= deadline {
                drop(poll);
                fail_guided(g, ExitCode::Generic, "enroll_timeout",
                    &format!("no redemption for {node} within {secs}s"),
                    "did the paste run on the node? check `noo cluster bootstrap-token list`",
                    &[("noo cluster bootstrap-token list", "shows whether the one-liner was redeemed on the node"),
                      (&format!("noo cluster provision {node} --wait"), "re-run once the paste has run")]);
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
            poll.tick(started.elapsed().as_secs());
        }
        // Prep runs AFTER redemption; the gate must exist before we probe it.
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}

/// Step 2: the enrollment record, the self node's birth cert check, and the node's live record.
/// What the node says it is running: the controller must not stage kinds
/// this version's applier cannot parse (applier_knows_harness_kinds).
/// The node's live record, fetched once: its running version here, and
/// its live-derived tier below.
fn load_enrollment(g: &Globals, a: &ProvisionArgs, site: &ProvSite) -> ProvEnrollment {
    let node = a.node.clone();
    let is_self = site.is_self;
    let record = if is_self {
        match self_node_redemption(&node) {
            Ok(r) => Some(r),
            Err(e) => fail(g.json, ExitCode::Generic, "self_birth_cert_unreadable", &e, Some(SELF_RAIL_REMEDY)),
        }
    } else {
        redemption_record(g, &node)
    };
    // The gateway verifies the fetch receipt and the apply report against
    // the self node's birth cert, read from the PKI's certificate-only view:
    // put THIS cert there (no sudo), then confirm the gateway sees it before
    // staging anything it could not verify.
    if is_self {
        if let Err(e) = sync_self_birth_cert(&crate::pki::pki_dir(), &node, Path::new(SELF_BIRTH_CRT)) {
            fail(g.json, ExitCode::Generic, "self_birth_cert_sync", &e, Some("noo security pki fix-modes"));
        }
        let local_fp = record.as_ref().and_then(|r| r.birth_cert.as_deref())
            .map(|c| crate::commands::node_fetch::cert_der_sha256(c.as_bytes()))
            .unwrap_or_else(|| Err("no birth cert".into()))
            .unwrap_or_else(|e| fail(g.json, ExitCode::Generic, "self_birth_cert_unreadable",
                &format!("{SELF_BIRTH_CRT} cannot be fingerprinted ({e})"), Some(SELF_RAIL_REMEDY)));
        let answer = crate::http::get_raw_opt(g, "/api/cluster/self-node", true, 15);
        match judge_gateway_self_view(&node, &local_fp, answer.as_ref().map(|(s, b)| (*s, b.as_str()))) {
            Ok(()) => nstep(&format!("self node: the gateway verifies against this birth cert ({}…); riding the rail like any node", &local_fp[..12.min(local_fp.len())])),
            Err(p) => fail(g.json, ExitCode::Generic, p.code, &p.msg, Some(&p.remedy)),
        }
    }
    // What the node says it is running: the controller must not stage kinds
    // this version's applier cannot parse (applier_knows_harness_kinds).
    // The node's live record, fetched once: its running version here, and
    // its live-derived tier below.
    let live_node = live_node_record(g, &node);
    let node_app_version = live_app_version(live_node.as_ref());
    ProvEnrollment { record, live_node, node_app_version }
}

/// Resolve the node's address, account and tier from its enrollment record, and record them on its registry row.
///    source. The ansible inventory this verb used to consult and append
///    to went with the playbook tree (3695e129); on a standalone
///    controller it never existed and the first provision after the
///    2026-09-07 walk died on "Cannot read ansible/inventory/hosts".
fn resolve_identity(g: &Globals, a: &ProvisionArgs, site: &ProvSite, enr: &ProvEnrollment) -> ProvIdentity {
    let node = a.node.clone();
    let harness = a.harness.clone();
    let is_self = site.is_self;
    let record = &enr.record;
    let live_node = &enr.live_node;
    let tier = a.tier.clone();
    let (ip, user, tier) = {
        nstep(&format!("resolving {node} from its enrollment record"));
        let Some(rec) = record.as_ref() else {
            fail(g.json, ExitCode::Generic, "no_enrollment",
                &format!("no redeemed name-bound token exists for '{node}'"),
                Some("enroll with a bound token (noo cluster bootstrap-token create --node <n>)"));
        };
        let (ip, user) = (rec.ip.clone(), rec.user.clone());
        if user.is_empty() {
            fail(g.json, ExitCode::Generic, "no_enroll_user",
                &format!("enrollment record for {node} lacks the user"), None);
        }
        let t = match tier {
            Some(t) => t,
            None => {
                // ProvEnrollment facts first (no contact); SSH probe only on the
                // gate lane where facts are absent (pre-pull enrollments).
                // ProvEnrollment facts, or nothing. The SSH probe that used to
                // stand in for a missing record is gone with the gate lane;
                // a node with no facts must be re-enrolled, and guessing a
                // tier here would place work on hardware we cannot see.
                // The LIVE derivation first. A re-provision is not a birth: the
                // node has been heartbeating, and the gateway's canonical
                // ladder (node_tier.rs) has already judged its current
                // hardware. ProvEnrollment facts are a snapshot from the day it
                // joined — host3 enrolled 2026-09-09 with gpu_present:false
                // (WSL2, GPU not yet visible), so every `upgrade --nodes`
                // re-derived tier 3 (CPU) for a 16 GB GPU box and wrote it back
                // to the registry, undoing any correction.
                match resolve_tier(live_node.as_ref(), rec.facts.as_ref()) {
                    Some((t, source)) => {
                        nstep(&format!("tier derived from {source}: {t}"));
                        t
                    }
                    None => fail(g.json, ExitCode::Generic, "no_node_facts",
                        &format!("{node} has no enrollment facts on record and no live tier — its tier cannot be derived"),
                        Some("re-enroll the node (`noo enroll` on the node) so it reports its hardware")),
                }
            }
        };
        // Record what was resolved on the node's DB config row — the same
        // row `noo cluster set-config` edits and `noo cluster desired` shows.
        let mut body = serde_json::json!({"ip_address": ip, "ssh_user": user, "tier": t.parse::<i64>().unwrap_or(0)});
        if let Some(h) = &harness {
            body["harness_policy"] = serde_json::json!(h);
        }
        // Not for the self node: its registry row is the one its agent
        // registered, and this box's LAN address is not necessarily the one
        // the gateway dials it on.
        if !is_self { match crate::http::put_json_try(g, &format!("/api/cluster/nodes/{}/config", super::urlencode(&node)), &body, true, 15) {
            Ok(_) => nstep(&format!("registry row updated: tier {t}, {ip}, user {user}{}",
                harness.as_deref().map(|h| format!(", harness {h}")).unwrap_or_default())),
            Err(e) => nnote(&format!("registry row not updated ({e}) — `noo cluster set-config {node} --tier {t}` records it by hand")),
        } }
        (ip, user, t)
    };
    ProvIdentity { ip, user, tier }
}

/// Transport decision + machine facts: the birth cert, arch, data root and OS of the node.
fn resolve_machine(g: &Globals, a: &ProvisionArgs, enr: &ProvEnrollment) -> ProvMachine {
    let node = a.node.clone();
    let record = &enr.record;
    let live_node = &enr.live_node;
    let birth_cert = record.as_ref().and_then(|r| r.birth_cert.clone());
    // No gate lane. A node with no birth cert cannot collect a staged
    // bundle, and the SSH probe that used to substitute for the record is
    // gone — so this is a re-enroll, not a fallback (2026-09-05).
    if birth_cert.is_none() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_birth_cert",
            &format!(
                "{node} has no birth cert on record — it enrolled before the pull rail and \
                 cannot collect a staged bundle"
            ),
            Some("re-enroll it (`noo enroll` on the node) so it can collect over the rail"),
        );
    }

    let (goarch, data_root) = {
        let f = record.as_ref().and_then(|r| r.facts.clone()).unwrap_or_else(|| serde_json::json!({}));
        let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
        let goarch = if arch.starts_with("aarch64") || arch.starts_with("arm64") {
            "arm64"
        } else {
            "amd64"
        };
        // The OPERATOR's declaration wins over the birth-time observation.
        //
        // This read the enrollment facts only, so `noo cluster set-config
        // <node> --data-root <p>` could not reach the bundle. The shapes
        // disagreed three ways: the verb said "config updated", `noo cluster
        // desired` showed the new path because it reads the DB, the bundle
        // rendered the OLD path from the facts, and the node then REFUSED the
        // new path at reconcile — because a node declares its allowed host
        // roots from the very env vars that bundle renders
        // (`docker/hostroots.go`). So the operator-visible view showed the
        // value that loses, and a verb reported success for a change that
        // could not take effect.
        //
        // host3, 2026-09-12: facts said /mnt/d/noo (inherited from when that
        // box was the controller, a 9P Windows mount vLLM complains about),
        // the operator chose an ext4 path under the node's own filesystem, and the node logged
        // `reconcile.models_dir_refused` naming the old roots.
        //
        // With nothing declared, the root the node REPORTS running on comes
        // next: an undeclared node may sit on an earlier built-in default
        // (/mnt/d/noo, /data/noo), and rendering today's default instead
        // would move it off its own data on the next bundle. The birth-time
        // fact is the fallback after that.
        let declared = declared_data_root(g, &node);
        let reported = live_node
            .as_ref()
            .and_then(|n| n.get("data_roots"))
            .and_then(|d| d.get("noo_data_root"))
            .and_then(|v| v.as_str());
        let data_root = pick_data_root(declared.as_deref(), reported, f.get("data_root").and_then(|v| v.as_str()));
        (goarch.to_string(), data_root)
    };
    let goarch = goarch.as_str();
    // Data-root policy: an existing root that fails the shape rule is
    // rendered as it is (moving data is a separate, explicit decision) but
    // never silently — the node will also report it on every heartbeat.
    if enrolled_os(record.as_ref()) != "macos" {
        if let Some((code, why)) = crate::commands::data_root::shape_problem(&data_root, false, "") {
            ui::warned(&format!(
                "{node}: data root {data_root} does not meet the data-root policy ({code}: {why}); \
                 see `noo cluster verify {node}` for the move"
            ));
        }
    }
    // The target OS, from the same enrollment facts as arch. "arm64"
    // alone cannot tell a Pi from a Mac. Absent (older enroll clients, the
    // controller's own local lane) → linux, exactly the old behaviour —
    // every linux path below is untouched.
    let node_os = enrolled_os(record.as_ref());
    let darwin = node_os == "macos";
    ProvMachine { birth_cert, goarch: goarch.to_string(), data_root, darwin }
}

/// Step 3: the node's cert in the local PKI (issued when absent or when it no longer covers the address). Returns the PKI dir.
///
/// Issue when ABSENT, and re-issue when the existing cert no longer
/// covers the node's current address. Absence alone was the old test,
/// which meant a node that had ever been issued a cert kept it — stale
/// SANs and all — through every restage. Live consequence (2026-09-04):
/// a node's cert named an address it no longer had, the gateway
/// rejected the handshake by name, and every inference to it failed
/// while the node itself reported healthy.
///
/// This matters more the moment the certificate becomes the node's
/// identity: the same drift stops being "one node's inference is down"
/// and becomes "one node cannot authenticate at all".
fn ensure_node_certs(g: &Globals, a: &ProvisionArgs, site: &ProvSite, id: &ProvIdentity) -> std::path::PathBuf {
    let node = a.node.clone();
    let is_self = site.is_self;
    let ip = id.ip.clone();
    let pki = crate::pki::pki_dir();
    let node_crt = pki.join("nodes").join(&node).join("node.crt");
    let node_key = pki.join("nodes").join(&node).join("node.key");
    // The SAN set `pki issue-node` would produce for this node right now.
    let want_dns: Vec<String> = vec![node.clone(), "localhost".into(), "node-agent".into()];
    let mut want_ips: Vec<String> = vec![ip.clone(), "127.0.0.1".into()];
    // The self node: the controller names are what its cert must carry
    // (i11a), and its tailnet address is this device's own, never a lookup
    // of its node name — the same test the onboard install applies.
    let role = crate::pki::NodeRole::of(&node);
    let (want_dns, want_ips) = if is_self {
        (role.required_dns().to_vec(), Vec::new())
    } else {
        want_ips.extend(crate::pki::ClusterCa::tailscale_ip4(&node));
        (want_dns, want_ips)
    };
    let reason = if !node_key.exists() || !node_crt.exists() {
        Some(format!("no certs for {node}"))
    } else if !crate::pki::ClusterCa::cert_covers_sans(&node_crt, &want_dns, &want_ips) {
        Some(format!(
            "{node}'s cert no longer covers its address ({}) — re-issuing",
            want_ips.join(", ")
        ))
    } else {
        None
    };
    if let Some(why) = reason {
        nstep(&format!("{why} — issuing into the local PKI"));
        // --mint-only, deliberately: issue-node DELIVERS by default and exits
        // non-zero when the node does not confirm, which is correct for an
        // operator re-issuing a live node and wrong here. The node is mid-
        // setup: no agent is running to present the cert or report an apply,
        // so "staged but unconfirmed" is the EXPECTED state at this moment,
        // and this call site treats anything but Ok(0) as fatal. Without the
        // flag every fresh provision would hard-stop on its own cert step.
        // The bundle we are about to build is what carries these certs over.
        // Pass the ADDRESS we just resolved: without it the issuer looks the
        // node NAME up in the tailnet, and a machine whose tailnet hostname
        // differs from its node name (host1 enrolled as `host2`,
        // 2026-09-09) failed with "cannot determine an address" although the
        // enrollment record — and the line above — already had it.
        match super::security_local::pki_issue_node(
            g, &[node.clone(), ip.clone(), "--mint-only".to_string()]) {
            Ok(0) => {}
            _ => fail(g.json, ExitCode::Generic, "issue_failed",
                &format!("could not issue a cert for {node}"), None),
        }
    }
    pki
}

/// Step 4: credentials from the secret store (sops -d, in memory only).
fn load_credentials(g: &Globals, site: &ProvSite) -> Creds {
    let root = site.root.clone();
    sops_credentials(&root).unwrap_or_else(|e| {
        fail(g.json, ExitCode::Generic, "secrets", &e, None)
    })
}

/// Step 5: the agent binary for the node's arch.
fn obtain_binary(g: &Globals, site: &ProvSite, m: &ProvMachine) -> Vec<u8> {
    let root = site.root.clone();
    let goarch = m.goarch.as_str();
    let darwin = m.darwin;
    nstep(&format!("obtaining noo-node-agent ({goarch})"));
    if darwin {
        // No darwin binary rides any container image — source build only
        // (build-cross darwin/<arch> is proven to emit valid Mach-O).
        obtain_agent_binary_darwin(g, &root, goarch).unwrap_or_else(|e| {
            fail(g.json, ExitCode::Generic, "agent_binary", &e,
                Some("darwin agents build from source — run provision from a checkout"));
        })
    } else {
        obtain_agent_binary(&root, goarch).unwrap_or_else(|e| {
            fail(g.json, ExitCode::Generic, "agent_binary", &e,
                Some("is docker logged in to the image registry, and NOO_IMAGE_TAG set (noomesh.yaml compose_env / .env)?"));
        })
    }
}

/// Step 6a: the real ansible env template (single source of truth).
fn read_env_template(g: &Globals, site: &ProvSite) -> String {
    let root = site.root.clone();
    let tmpl_path = root.join("node-agent-go/deploy/noo-node-agent.env.tmpl");
    std::fs::read_to_string(&tmpl_path).unwrap_or_else(|e| {
        fail(g.json, ExitCode::Generic, "template",
            &format!("cannot read {} ({e})", tmpl_path.display()), None)
    })
}

/// Step 6b: every var the node env template names.
fn build_env_vars(g: &Globals, a: &ProvisionArgs, site: &ProvSite, id: &ProvIdentity, m: &ProvMachine, creds: Creds) -> BTreeMap<&'static str, String> {
    let node = a.node.clone();
    let root = site.root.clone();
    let tier = id.tier.clone();
    let data_root = m.data_root.clone();
    let darwin = m.darwin;
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("na_node_id", node.clone());
    vars.insert("node_ip", String::new()); // parity with the play (default '')
    vars.insert("node_tier", tier.clone());
    vars.insert("gpu_model", String::new());
    // The name nodes are told to phone home to, in precedence order:
    //
    //  1. NOO_CONTROLLER_DNS — the mesh's FLOATING SERVICE NAME. Failover is
    //     designed as "rename the promoted standby to the service name and
    //     nodes re-home via DNS" (bootstrap-controller.sh); that only works
    //     when nodes were provisioned against the floating name, not a
    //     device name. HA operators set this (noomesh.yaml compose_env /
    //     .env) to their mesh's name — e.g. noo-controller for mesh A,
    //     noo-b for a second mesh on the same tailnet.
    //  2. This controller's ACTUAL MagicDNS device name — the safe default
    //     everywhere: on a SHARED tailnet the literal `noo-controller`
    //     resolves to whichever controller claimed it first, and the other
    //     mesh's nodes would phone the wrong gateway (TLS/auth fail →
    //     UNREACHABLE → you debug the network instead of the name).
    //  3. The host of `services.gateway_url` in noomesh.yaml — what this
    //     controller ADVERTISES. A LAN-only controller (no tailnet) sets it
    //     to reach nodes at all: `bootstrap-token create` refuses to mint
    //     while it still says localhost, so by the time a node enrolls the
    //     value is the name the node just used. Skipping it here sent a
    //     LAN node to the literal below, which nothing resolved: "registered
    //     with controller" only after the operator hand-edited /etc/hosts
    //     (2026-09-28 newcomer rehearsal, blank box on a lab network).
    //  4. The literal `noo-controller` — last resort when tailscale is down,
    //     correct only for the single-controller tailnet install.
    let ctrl_host = std::env::var("NOO_CONTROLLER_DNS").ok()
        .map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
        .or_else(controller_dnsname)
        .or_else(advertised_gateway_host)
        .unwrap_or_else(|| "noo-controller".into());
    vars.insert("controller_url", format!("https://{ctrl_host}:8080"));
    vars.insert("nats_url", format!("tls://{ctrl_host}:4222"));
    vars.insert("noo_node_agent_token", creds.agent_token);
    vars.insert("noo_cluster_secret", creds.cluster_secret);
    vars.insert("noo_pki_dir", String::from("/etc/noo/pki"));
    vars.insert("na_tls_ca", String::from("/etc/noo/pki/ca.crt"));
    vars.insert("na_tls_cert", format!("/etc/noo/pki/nodes/{node}/node.crt"));
    vars.insert("na_tls_key", format!("/etc/noo/pki/nodes/{node}/node.key"));
    vars.insert("noo_mtls_nodes", String::new());
    // The controller's own node adopts the stack's ollama at its loopback
    // publish (NOO_SELF_NODE → the agent's "stack" lane); every other node
    // resolves the compose alias, so empty keeps it. 2026-09-11: this var
    // was added to provision_local's map only, and the template guard
    // refused every node on `noo upgrade --nodes` — the parity test now
    // checks each map on its own.
    let self_node = crate::role::is_self_node(&node);
    vars.insert("noo_self_node", if self_node { "1".to_string() } else { String::new() });
    vars.insert("ollama_url", if self_node { self_node_ollama_url(&root) } else { String::new() });
    vars.insert("noo_data_root", data_root.clone());
    vars.insert("hf_cache_dir", format!("{data_root}/hf-cache"));
    vars.insert("models_dir", format!("{data_root}/models"));
    vars.insert("ollama_data_dir", format!("{data_root}/ollama"));
    vars.insert("noo_model_cache_url", format!("https://{ctrl_host}:8443"));
    // Release identity, so the agent resolves PUBLISHED backend images
    // rather than local build names (see the template comment).
    vars.insert("noo_image_prefix", image_prefix());
    vars.insert("noo_image_tag", image_tag());
    vars.insert("noo_force_gpu", String::new());
    vars.insert("noo_ollama_gpu_count", String::new());
    vars.insert("node_agent_port", String::from("8081"));
    vars.insert("log_level", String::from("info"));
    // Cluster trust: the bind override, owned by the controller (see
    // `cluster_trust_bind`). The v1 cluster-token gate is deleted and no
    // longer rendered: v1 is always refused.
    let agent_bind = cluster_trust_bind().unwrap_or_else(|e| {
        fail(g.json, ExitCode::Generic, "node_agent_bind", &e,
            Some("set NODE_AGENT_BIND in the controller's .env / compose_env to `all`, an IP address, or a comma list of them (or unset it)"))
    });
    vars.insert("node_agent_bind", agent_bind);
    if darwin {
        // Same env contract, darwin homes: everything under ~/noomesh (the
        // enroll binary installs there — no root paths, no systemd). $HOME
        // expands when run-agent.sh `set -a; source`s the file.
        vars.insert("noo_pki_dir", String::from("$HOME/noomesh/pki"));
        vars.insert("na_tls_ca", String::from("$HOME/noomesh/pki/ca.crt"));
        vars.insert("na_tls_cert", String::from("$HOME/noomesh/pki/node.crt"));
        vars.insert("na_tls_key", String::from("$HOME/noomesh/pki/node.key"));
        // The enrollment record carries the Mac's chosen root (enroll asks;
        // an external SSD under /Volumes is typical). Only the legacy
        // Linux default means "not chosen" — then everything stays under
        // ~/noomesh as before.
        let droot = if data_root.starts_with('/') && data_root != crate::commands::data_root::DEFAULT_DATA_ROOT {
            data_root.clone()
        } else {
            "$HOME/noomesh".to_string()
        };
        // The Mac agent env is `source`d by run-agent.sh, so a root with a
        // space or a shell-special character must be quoted (env_quote keeps
        // a leading $HOME expanding). Linux env files are never quoted
        // (systemd and the shell applier read them raw).
        let q = |s: String| super::env_quote::env_quote(&s);
        vars.insert("hf_cache_dir", q(format!("{droot}/hf-cache")));
        vars.insert("models_dir", q(format!("{droot}/models")));
        vars.insert("ollama_data_dir", q(format!("{droot}/ollama")));
        vars.insert("noo_data_root", q(droot));
    }
    vars
}

/// Step 6c: data root, what this bundle renders vs what the node runs on.
/// ── data root: what this bundle renders vs what the node runs on
///    Refuse BEFORE anything is staged. A Mac's roots
///    carry `$HOME` and are not comparable, so it is not checked.
fn check_data_root(g: &Globals, a: &ProvisionArgs, enr: &ProvEnrollment, m: &ProvMachine, vars: &BTreeMap<&str, String>) {
    let node = a.node.clone();
    let move_data = a.move_data;
    let live_node = &enr.live_node;
    let darwin = m.darwin;
    if !darwin {
        let rendered = super::data_root::Rendered {
            noo_data_root: vars["noo_data_root"].clone(),
            hf_cache_dir: vars["hf_cache_dir"].clone(),
            models_dir: vars["models_dir"].clone(),
            ollama_data_dir: vars["ollama_data_dir"].clone(),
        };
        let reported = live_node.as_ref().and_then(|n| n.get("data_roots"));
        match super::data_root::data_root_check(&rendered, reported) {
            super::data_root::RootCheck::Agree => {}
            super::data_root::RootCheck::NotReported(why) => {
                if !g.json && !ui::quiet() {
                    println!("{}", ui::note(&format!("data root check skipped: {why}")));
                }
            }
            super::data_root::RootCheck::Conflict(c) if move_data => {
                if !g.json && !ui::quiet() {
                    println!("{}", ui::note(&format!(
                        "--move-data: {} — staging anyway; moving the files is yours to do",
                        c.headline(&node))));
                }
            }
            super::data_root::RootCheck::Conflict(c) => {
                let set = format!("noo cluster set-config {node} --data-root {}", c.reported_root);
                let mv = format!("noo cluster provision {node} --move-data");
                fail_guided(g, ExitCode::Generic, "data_root_conflict", &c.headline(&node),
                    &format!("{set}   # the declaration follows the node, or: {mv}   # the node follows the declaration"),
                    &[(&set, "the declaration follows the node"),
                      (&mv, "the node follows the declaration (you move the files)")]);
            }
        }
    }
}

/// Step 6d: render the env, withholding keys a Mac applier predating them would refuse.
fn render_agent_env(g: &Globals, a: &ProvisionArgs, enr: &ProvEnrollment, m: &ProvMachine, tmpl: &str, vars: &BTreeMap<&str, String>) -> String {
    let node = a.node.clone();
    let node_app_version = enr.node_app_version.clone();
    let darwin = m.darwin;
    let env_body = render_env_template(tmpl, vars).unwrap_or_else(|e| {
        fail(g.json, ExitCode::Generic, "render", &e, None)
    });
    // A Mac whose CLI predates the cluster-trust key refuses an
    // agent-env that names it (its applier validates every key up front),
    // which would strand the very bundle that carries the newer CLI. Withheld
    // for that node, said, and the next restage carries them.
    if applier_knows_cluster_trust_keys(darwin, &node_app_version) {
        env_body
    } else {
        if !g.json && !ui::quiet() {
            println!("{}", ui::note(&format!(
                "NODE_AGENT_BIND withheld from this bundle: {node} reports \
                 {node_app_version}, whose applier predates it and would refuse the whole agent-env. \
                 The bundle carries the newer CLI; once {node} reports it, re-run \
                 `noo cluster provision {node}` to apply the agent key.")));
        }
        drop_env_keys(&env_body, CLUSTER_TRUST_ENV_KEYS)
    }
}

/// The unit file and the certificate material the bundle carries.
fn read_bundle_material(g: &Globals, a: &ProvisionArgs, site: &ProvSite, pki: &Path) -> BundleMaterial {
    let node = a.node.clone();
    let root = site.root.clone();
    let pki = pki.to_path_buf();
    let unit = std::fs::read(root.join("node-agent-go/deploy/noo-node-agent.service"))
        .unwrap_or_else(|e| fail(g.json, ExitCode::Generic, "unit",
            &format!("cannot read the agent unit file ({e})"), None));
    let read_pki = |rel: &str| -> Vec<u8> {
        std::fs::read(pki.join(rel)).unwrap_or_else(|e| fail(g.json, ExitCode::Generic,
            "pki_read", &format!("cannot read pki/{rel} ({e})"), None))
    };
    let ca_crt = read_pki("ca.crt");
    let node_crt = read_pki(&format!("nodes/{node}/node.crt"));
    let node_key = read_pki(&format!("nodes/{node}/node.key"));
    BundleMaterial { unit, ca_crt, node_crt, node_key }
}

/// Step 7: the CA, the signing key delivered first when the node has not adopted it, and a scratch dir.
fn prepare_bundle_workspace(g: &Globals, a: &ProvisionArgs, pki: &Path) -> (crate::pki::ClusterCa, std::path::PathBuf) {
    let node = a.node.clone();
    let pki = pki.to_path_buf();
    let ca = crate::pki::ClusterCa::new(pki.clone());
    // The CA signs nothing but the signing key itself, so a
    // node that has not adopted it gets the key ALONE first (a CA-signed
    // rollover carrying `signing-pub` and nothing else), and only then this
    // bundle, signed by the signing key. Done before anything is minted, so
    // a node that cannot adopt leaves nothing half-rotated behind.
    if !ca.signing_adopted(&node) {
        deliver_signing_key_first(g, &node, &ca);
    }
    let work = std::env::temp_dir().join(format!("noo-provision-{node}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&work);
    (ca, work)
}

/// The files every bundle carries: env, unit/plist, agent binary, CA and node cert pair.
fn base_bundle_files(id: &ProvIdentity, m: &ProvMachine, env_body: String, binary: Vec<u8>, mat: BundleMaterial) -> Vec<(&'static str, Vec<u8>)> {
    let user = id.user.clone();
    let darwin = m.darwin;
    let BundleMaterial { unit, ca_crt, node_crt, node_key } = mat;
    if darwin {
        vec![
            ("agent-env", env_body.into_bytes()),
            ("agent-plist", DARWIN_AGENT_PLIST.replace("__USER__", &user).into_bytes()),
            ("run-agent", darwin_run_agent().into_bytes()),
            ("agent-binary", binary),
            ("ca.crt", ca_crt),
            ("node.crt", node_crt),
            ("node.key", node_key),
        ]
    } else {
        vec![
            ("agent-env", env_body.into_bytes()),
            ("agent-unit", unit),
            ("agent-binary", binary),
            ("ca.crt", ca_crt),
            ("node.crt", node_crt),
            ("node.key", node_key),
        ]
    }
}

/// The applier and the fetcher ride every Linux bundle.
/// The applier and the fetcher ride every Linux bundle (2026-09-03): a
/// new kind is otherwise refused by the old applier already on the node
/// (exit 76), and the fetcher is what reports apply outcomes back. The
/// applier self-updates FIRST (noo-apply §1b) and re-runs the bundle.
fn attach_applier_and_fetcher(m: &ProvMachine, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let darwin = m.darwin;
    if !darwin {
        let apply = super::enroll::asset_apply();
        let fetch = super::enroll::asset_fetch();
        if !apply.is_empty() { files.push(("applier", apply.as_bytes().to_vec())); }
        if !fetch.is_empty() { files.push(("fetcher", fetch.as_bytes().to_vec())); }
    }
}

/// hostd rides the rail on EVERY node, the controller's own included (it must not sit inside the self-node CLI branch).
/// hostd rides the rail on EVERY node, the controller's own included.
/// It used to sit inside the self-node branch below, which exists for the
/// CLI alone; hostd was swept in with it, so the controller's worker-mode
/// hostd had no upgrade path at all and host8 stayed on 0.5.58 through
/// two releases (2026-09-28). The applier installs it the same way on
/// every node, with a fresh-heartbeat check and an automatic revert.
///
/// The helper the harness lifecycle needs, staged like the harness
/// itself. Without it the agent has nothing to ask
/// the agent cannot sudo, so hostd does the start), and a node with
/// a harness placement and no hostd fails every reconcile tick —
/// which is what every Linux node did on 2026-09-19, because the
/// rail never carried this kind. Absent from an older release is a
/// note, not a failure: the applier simply installs no helper.
fn attach_hostd(g: &Globals, site: &ProvSite, enr: &ProvEnrollment, m: &ProvMachine, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let root = site.root.clone();
    let record = &enr.record;
    let darwin = m.darwin;
    let f = record.as_ref().and_then(|r| r.facts.clone()).unwrap_or_else(|| serde_json::json!({}));
    let os = f.get("os").and_then(|v| v.as_str()).unwrap_or(if darwin { "macos" } else { "linux" });
    let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
    if let Some(asset) = hostd_asset_for(os, arch) {
        match cached_release_asset(g, &root, &asset) {
            Ok(bytes) => {
                nnote(&format!("bundle carries the privileged helper ({asset}, {})", human_bytes(bytes.len())));
                files.push(("hostd-binary", bytes));
            }
            Err(e) => nnote(&format!(
                "no hostd in this bundle: {asset} is not in the controller's asset cache and the \
                 release fetch failed ({e}) — the harness cannot start on this node until it is \
                 (`noo upgrade` refreshes the cache)"
            )),
        }
    }
}

/// The CLI rides the rail too (not for the controller's own node).
/// The CLI rides the rail too: when the controller's cache
/// holds the release asset for this node's platform, the bundle carries
/// it as `cli-binary` (+ `cli-user`, the account that owns ~/.local/bin).
/// `noo upgrade --nodes` fills the cache; a node never needs GitHub.
///
/// Except for the controller's own node: that box's CLI is the one
/// running `noo upgrade`, managed by its CLI stage, and a bundle that
/// installs over it replaces the binary mid-run (2026-09-11: every node
/// after host8 in `--nodes` failed to spawn). Same rail, one file fewer.
fn attach_cli(a: &ProvisionArgs, site: &ProvSite, enr: &ProvEnrollment, id: &ProvIdentity, m: &ProvMachine, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let root = site.root.clone();
    let record = &enr.record;
    let user = id.user.clone();
    let darwin = m.darwin;
    let self_node = crate::role::is_self_node(&node);
    let f = record.as_ref().and_then(|r| r.facts.clone()).unwrap_or_else(|| serde_json::json!({}));
    let os = f.get("os").and_then(|v| v.as_str()).unwrap_or(if darwin { "macos" } else { "linux" });
    let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
    if self_node {
        nnote("this is the controller's own node — the bundle carries no CLI (noo upgrade manages it)");
    } else {
        if let Some(asset) = cli_asset_for(os, arch) {
            let cached = cli_asset_cache_dir(&root).join(&asset);
            if let Ok(bytes) = std::fs::read(&cached) {
                if !bytes.is_empty() && !user.is_empty() {
                    nnote(&format!("bundle carries the CLI for {user} ({asset}, {})", human_bytes(bytes.len())));
                    files.push(("cli-binary", bytes));
                    files.push(("cli-user", user.clone().into_bytes()));
                }
            }
        }
    }
}

/// The harness: the gateway binary for this platform, its env and unit.
/// The gateway binary for this platform, from the controller's release
/// asset cache (`noo upgrade --nodes` fills it), plus its env and unit.
/// A cache without the asset means this release has no harness for the
/// platform yet — said, not silently skipped. The controller's own node
/// gets none: its gateway IS the harness, in process.
fn attach_harness(g: &Globals, a: &ProvisionArgs, site: &ProvSite, enr: &ProvEnrollment, id: &ProvIdentity, m: &ProvMachine, vars: &BTreeMap<&str, String>, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let root = site.root.clone();
    let record = &enr.record;
    let node_app_version = enr.node_app_version.clone();
    let user = id.user.clone();
    let darwin = m.darwin;
    let self_node = crate::role::is_self_node(&node);
    if self_node {
        nnote("this is the controller's own node — no harness in the bundle (the gateway runs turns in process)");
    } else {
        let f = record.as_ref().and_then(|r| r.facts.clone()).unwrap_or_else(|| serde_json::json!({}));
        let os = f.get("os").and_then(|v| v.as_str()).unwrap_or(if darwin { "macos" } else { "linux" });
        let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
        let knows_harness = applier_knows_harness_kinds(darwin, &node_app_version);
        if !knows_harness {
            nnote(&format!(
                "no harness in this bundle: {node} reports {node_app_version}, whose applier \
                 predates the harness kinds and would refuse the whole bundle. It carries the \
                 newer CLI; the next restage carries the harness."
            ));
        }
        match gateway_asset_for(os, arch).filter(|_| knows_harness) {
            Some(asset) => {
                match cached_release_asset(g, &root, &asset) {
                    Ok(bytes) if super::enroll::asset_harness_env_tmpl().is_empty() => {
                        let _ = bytes;
                        nnote("no harness in this bundle: this CLI was built without the repo tree, so it carries no harness unit or env template");
                    }
                    Ok(bytes) => {
                        // Compiled in, NOT read from the controller's
                        // checkout: that tree is any revision at all, and a
                        // 0.5.42 binary on a controller whose checkout
                        // predated the template failed four of five nodes
                        // (2026-09-19). The binary ships what it stages.
                        let htmpl = super::enroll::asset_harness_env_tmpl().to_string();
                        let mut hvars = vars.clone();
                        // Every var the harness template names, supplied
                        // here: the renderer never evaluates a default.
                        // The model endpoint is this node's agent over
                        // loopback; MAX_TURNS caps
                        // concurrent turns the way the container did.
                        hvars.insert("noo_harness_model_url", format!("https://127.0.0.1:{}",
                            vars.get("node_agent_port").cloned().unwrap_or_else(|| "8081".to_string())));
                        hvars.insert("noo_harness_max_turns", String::from("2"));
                        hvars.insert("harness_log", String::from("noo_gateway=info"));
                        // The harness's own copy of the node pair (i119):
                        // the applier installs it root:noo-harness 0640 on
                        // Linux; a Mac runs both as one user, same files.
                        let (hcert, hkey) = harness_tls_paths(darwin, vars);
                        hvars.insert("harness_tls_cert", hcert);
                        hvars.insert("harness_tls_key", hkey);
                        let henv = render_env_template(&htmpl, &hvars)
                            .unwrap_or_else(|e| fail(g.json, ExitCode::Generic, "harness_env", &e, None));
                        nnote(&format!("bundle carries the harness ({asset}, {})", human_bytes(bytes.len())));
                        files.push(("harness-binary", bytes));
                        files.push(("harness-env", henv.into_bytes()));
                        if darwin {
                            files.push(("harness-plist", DARWIN_HARNESS_PLIST.replace("__USER__", &user).into_bytes()));
                            files.push(("run-harness", darwin_run_harness().into_bytes()));
                        } else {
                            files.push(("harness-unit", super::enroll::asset_harness_unit().as_bytes().to_vec()));
                        }
                    }
                    Err(e) => nnote(&format!(
                        "no harness in this bundle: {asset} is not in the controller's asset cache and \
                         the release fetch failed ({e}) — run `noo upgrade --nodes` on a release that carries it")),
                }
            }
            None => nnote(&format!("no harness in this bundle: no gateway asset for {os}/{arch}")),
        }
    }
}

/// The vendor CLIs the node carries (i83 E1e).
/// A harness kind that runs a vendor CLI (Copilot CLI, Claude Code,
/// Codex) needs it on the node's PATH, and the node never fetches it:
/// `noo cluster vendor stage <kind>` fetched and verified it on this
/// controller, and the bundle carries it. The kinds: the harness
/// placement's NOO_HARNESS_KIND (read from the same desired-config the
/// node agent converges to) and the node's `vendor_kinds`
/// (`noo cluster vendor install`), so a node can switch kinds without a
/// restage. Not staged = the restage is refused: a restage never
/// downloads, and a node placed on a CLI it does not have would only be
/// refused by its agent.
fn attach_vendor_clis(g: &Globals, a: &ProvisionArgs, site: &ProvSite, enr: &ProvEnrollment, m: &ProvMachine, work: &Path, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let root = site.root.clone();
    let record = &enr.record;
    let node_app_version = enr.node_app_version.clone();
    let darwin = m.darwin;
    let work = work.to_path_buf();
    let self_node = crate::role::is_self_node(&node);
    if self_node {
        // The controller's gateway runs turns in process; no node harness here.
    } else if !super::cluster_vendor::applier_knows_vendor_kinds(darwin, &node_app_version) {
        nnote(&format!(
            "no vendor CLI in this bundle: {node} reports {node_app_version}, whose applier predates \
             the vendor kinds. It carries the newer CLI; the next restage carries the vendor CLI."
        ));
    } else {
        let desired = crate::http::get_json_opt(
            g, &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(&node)), true, 10);
        let placed = desired.as_ref().and_then(super::cluster_vendor::desired_harness_kind);
        let mut extra = desired.as_ref().map(super::cluster_vendor::node_vendor_kinds).unwrap_or_default();
        // A Mac applier older than the slot floor reads ONE vendor CLI
        // (`vendor-cli`) and refuses a bundle naming `vendor-cli-2`: it gets
        // the placement's CLI alone, the layout it already applies.
        if !extra.is_empty() && !super::cluster_vendor::applier_knows_vendor_slots(darwin, &node_app_version) {
            nnote(&format!(
                "vendor_kinds ({}) not carried: {node} reports {node_app_version}, whose applier takes one vendor CLI \
                 per bundle — only the harness placement's. It carries the newer CLI; the next restage carries them.",
                extra.join(", ")
            ));
            extra.clear();
        }
        let kinds = super::cluster_vendor::bundle_vendor_kinds(placed.as_deref(), &extra);
        let f = record.as_ref().and_then(|r| r.facts.clone()).unwrap_or_else(|| serde_json::json!({}));
        let os = f.get("os").and_then(|v| v.as_str()).unwrap_or(if darwin { "macos" } else { "linux" });
        let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
        let table = crate::harness_kinds::shipped();
        // A kind the table declares with no distribution is a manual
        // install: nothing to carry. An unknown one is judged (refused) below.
        let wants_vendor = kinds.iter().any(|k| {
            table.kinds.iter().find(|r| r.kind == *k).is_none_or(|r| r.distribution.is_some())
        });
        if wants_vendor {
            let Some((os, arch)) = crate::harness_kinds::normalize_platform(os, arch) else {
                scrub(&work);
                fail(g.json, ExitCode::Generic, "vendor_platform",
                    &format!("{node} carries {} but its platform {os}/{arch} is not one vendor CLIs are staged for",
                        kinds.join(", ")), None);
            };
            let dir = super::cluster_vendor::vendor_cache_dir(&root);
            match super::cluster_vendor::vendor_bundle_files(&table, &kinds, os, arch,
                &|n| super::cluster_vendor::read_staged(&dir, n))
            {
                Ok(vf) => {
                    let size: usize = vf.iter().filter(|(k, _)| !k.ends_with("-manifest")).map(|(_, b)| b.len()).sum();
                    nnote(&format!("bundle carries {} vendor CLI(s): {} ({})",
                        vf.len() / 2,
                        kinds.join(", "),
                        human_bytes(size)));
                    files.extend(vf);
                }
                Err(e) => {
                    scrub(&work);
                    let stage = match kinds.as_slice() {
                        [one] => format!("noo cluster vendor stage {one}"),
                        _ => "noo cluster vendor stage".to_string(),
                    };
                    fail_guided(g, ExitCode::Generic, "vendor_not_staged", &e,
                        &stage,
                        &[(&stage,
                           "fetch the pinned CLI (and runtime) on this controller and verify its sha256"),
                          ("noo cluster vendor status", "what is staged and which nodes need it"),
                          (&format!("noo cluster provision {node}"), "restage once it is staged")]);
                }
            }
        }
    }
}

/// Do not carry a binary the node's own last report proves it already runs.
/// A binary the node's own last report proves it already runs is not
/// carried again (bandwidth only: the applier skips identical bytes anyway).
/// The proof is the node's `binary-sha:` statement; see `node_runs_asset`.
/// The status read is one GET; unreachable or unparseable = carry everything.
fn drop_binaries_the_node_already_runs(g: &Globals, a: &ProvisionArgs, m: &ProvMachine, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let darwin = m.darwin;
    let self_node = crate::role::is_self_node(&node);
    let last = crate::http::get_json_opt(g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10);
    for note in drop_proven_binaries(files, last.as_ref(), darwin, self_node) {
        nnote(&note);
    }
}

/// The backend door leaves issued in step 3b, on the same rail and signature.
/// Same rail, same signature. A Mac whose applier predates the kinds
/// would refuse the WHOLE bundle on them (it has no self-updating shell
/// applier), so it gets them on the restage after its CLI moves.
fn attach_door_leaves(g: &Globals, a: &ProvisionArgs, enr: &ProvEnrollment, m: &ProvMachine, ca: &crate::pki::ClusterCa, work: &Path, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let node_app_version = enr.node_app_version.clone();
    let darwin = m.darwin;
    let work = work.to_path_buf();
    if super::node_leaves::applier_knows_leaf_kinds(darwin, &node_app_version) {
        match super::node_leaves::leaf_payloads(ca, &node) {
            Ok((leaves, skipped)) => {
                let n = leaves.len() / 2;
                files.extend(leaves);
                if skipped.is_empty() {
                    nnote(&format!("bundle carries {n} backend door leaves (services/<x>/ on the node)"));
                } else {
                    nnote(&format!("bundle carries {n} backend door leaves; NOT {} (half a pair on disk — \
                        `noo cluster provision {node}` again re-issues it)", skipped.join(", ")));
                }
            }
            Err(e) => { scrub(&work); fail(g.json, ExitCode::Generic, "leaf_read", &e, None); }
        }
    } else {
        nnote(&super::node_leaves::withheld_leaves_note(&node, &node_app_version,
            super::node_leaves::upgrade_restages_leaves()));
    }
}

/// The node's own NATS credential.
/// Rides the provision bundle the way node.crt does: same rail, same CA
/// signature, same applier. Both lanes: the Linux applier merges it into
/// /etc/noo-node-agent.env; the darwin applier merges it into
/// ~/noomesh/agent.env the way it merges fleet-secrets. Until 2026-09-12
/// darwin was skipped ("no env to merge into"), so every Mac kept the
/// shared `noo` user — and the moment the gateway's nats_isolation
/// preflight went critical, one Mac on the legacy user kept the whole
/// controller from starting.
///
/// The server side is re-rendered BEFORE the bundle is staged, and that
/// order is safe here in a way it is not for a rotation: this node is
/// being BORN, so adding its user invalidates nothing anyone is
/// presenting. Every other node's user is re-rendered from the password
/// the store already holds, so nothing else changes either.
///
/// The credential is REQUIRED: since an earlier release retired the shared
/// NATS_USER there is nothing else a node may present, so a bundle
/// without its own pair would provision an agent that refuses to connect.
/// The server-side render stays best-effort — a controller whose gateway
/// is down still stages the bundle, and the node retries auth until
/// `noo cluster nats-users render` accepts its user.
fn attach_nats_credential(g: &Globals, a: &ProvisionArgs, site: &ProvSite, work: &Path, files: &mut Vec<(&'static str, Vec<u8>)>) {
    let node = a.node.clone();
    let root = site.root.clone();
    let work = work.to_path_buf();
    match super::nats_users::node_credential_payload(&root, &node) {
        Ok(payload) => {
            files.push(("nats-creds", payload));
            match super::nats_users::render_all(g, std::slice::from_ref(&node)) {
                Ok(out) => {
                    let reloaded = super::nats_users::hup_nats();
                    nnote(&format!(
                        "bundle carries this node's own NATS credential; {} users rendered{}",
                        out.users,
                        if reloaded { " and noo-nats reloaded" } else { " (reload noo-nats: docker kill -s HUP noo-nats)" }));
                }
                Err(e) => nnote(&format!(
                    "node credential minted but users.conf did not re-render ({e}) — the agent \
                     retries auth until `noo cluster nats-users render` (then \
                     `docker kill -s HUP noo-nats`) accepts node-{node}")),
            }
        }
        Err(e) => {
            scrub(&work);
            fail(g.json, ExitCode::Generic, "nats_credential",
                &format!("could not mint {node}'s own NATS credential ({e}) — a node has no \
                          other bus credential (the shared NATS_USER is retired), so nothing \
                          was staged"),
                Some("check the secret store (`noo security secrets audit`), then re-run \
                      `noo cluster provision <node>`"));
        }
    }
}

/// Sign the bundle. i44 on the rail: no bundle leaves without this node's own NATS pair, the controller's own node included.
/// i44 on the rail: no bundle leaves without this node's own pair —
/// the controller's own node included.
fn sign_bundle(g: &Globals, a: &ProvisionArgs, ca: &crate::pki::ClusterCa, files: &[(&str, Vec<u8>)], work: &Path) -> std::path::PathBuf {
    let node = a.node.clone();
    let work = work.to_path_buf();
    if let Err(e) = require_nats_creds(&node, files) {
        scrub(&work);
        fail(g.json, ExitCode::Generic, "nats_credential", &e, None);
    }
    match super::security_local::build_signed_bundle(ca, &node, files, &work) {
        Ok(b) => b,
        Err(e) => { scrub(&work);
            fail(g.json, ExitCode::Generic, "bundle_failed", &e, None); }
    }
}

/// A node that has never reported an apply runs the legacy fetcher/applier pair: stage an applier-only bundle first, the one kind every applier accepts. Returns whether the node is legacy.
/// A node that has never reported an apply outcome runs the legacy
/// fetcher/applier pair (pre-2026-09-03): its applier refuses every
/// kind it does not know, and its fetcher cannot report. Stage an
/// applier-only bundle first — the one kind every applier accepts —
/// so the full bundle below is applied by the new applier.
fn stage_applier_first(g: &Globals, a: &ProvisionArgs, m: &ProvMachine, ca: &crate::pki::ClusterCa) -> bool {
    let node = a.node.clone();
    let darwin = m.darwin;
    let birth_cert = m.birth_cert.clone();
    let cert = birth_cert.as_deref().expect("pull lane requires a birth cert");
    let legacy = node_never_reported_apply(g, &node);
    if legacy && !darwin {
        let apply = super::enroll::asset_apply();
        if !apply.is_empty() {
            nstep(&format!("{node} has never reported an apply — staging the applier alone first"));
            let w2 = std::env::temp_dir().join(format!("noo-provision-applier-{node}-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&w2);
            let pre: Vec<(&str, Vec<u8>)> = vec![("applier", apply.as_bytes().to_vec())];
            let b2 = match super::security_local::build_signed_bundle(ca, &node, &pre, &w2) {
                Ok(b) => b,
                Err(e) => { scrub(&w2); fail(g.json, ExitCode::Generic, "bundle_failed", &e, None); }
            };
            let blob2 = match encrypt_bundle_cms(&b2, cert, &w2) {
                Ok(b) => b,
                Err(e) => { scrub(&w2); fail(g.json, ExitCode::Generic, "encrypt_failed", &e, None); }
            };
            scrub(&w2);
            let applier_sha = sha256_hex(&blob2);
            if let Err(e) = post_bytes(g, &format!("/api/cluster/provision-bundle/{node}"), &blob2) {
                fail(g.json, ExitCode::Generic, "stage_failed", &e, None);
            }
            poke_fetch(g, &node);
            let staged2 = wait_bundle_fetched(g, &node, 600);
            if !staged2 {
                fail_guided(g, ExitCode::Generic, "not_fetched",
                    &format!("{node}: the applier bundle was staged but never fetched"),
                    "on the node: `systemctl status noo-fetch.timer` and `journalctl -u noo-fetch -n 20`",
                    &[("systemctl status noo-fetch.timer", "on the node — is the poll timer running at all"),
                      ("journalctl -u noo-fetch -n 20", "on the node — TLS and connectivity errors live here"),
                      (&format!("noo cluster provision {node} --wait"), "re-stage once the poll reaches the controller")]);
            }
            // The new applier reports its own apply (that is the point of
            // the handshake), so wait for THAT report instead of a fixed
            // 30 s guess. A node whose report never arrives (a fetcher
            // that cannot report, a gateway that lost the POST) is not
            // stuck: after the cap we proceed exactly as the old fixed
            // sleep did, and say so.
            nstep(&format!("{node} fetched the applier — waiting for it to report the install before the full bundle"));
            match wait_applier_reported(g, &node, &applier_sha, APPLIER_REPORT_CAP_SECS, APPLIER_REPORT_POLL_SECS) {
                Some(0) => nstep(&format!("{node} installed the applier (reported exit 0)")),
                Some(rc) => warn_line(&format!(
                    "{node}: the applier-only bundle reported exit {rc} — staging the full bundle anyway; it will likely be refused the same way")),
                None => warn_line(&format!(
                    "{node}: no apply report for the applier within {APPLIER_REPORT_CAP_SECS}s — proceeding with the full bundle without confirmation")),
            }
        }
    }
    legacy
}

/// Compress (when the node reads gzip), encrypt to the birth cert, stage at the gateway and poke the node.
fn stage_bundle(g: &Globals, a: &ProvisionArgs, enr: &ProvEnrollment, m: &ProvMachine, bundle: &Path, work: &Path, legacy: bool) -> ProvStaged {
    let node = a.node.clone();
    let node_app_version = enr.node_app_version.clone();
    let birth_cert = m.birth_cert.clone();
    let work = work.to_path_buf();
    let bundle = bundle.to_path_buf();
    let cert = birth_cert.as_deref().expect("pull lane requires a birth cert");
    // Compress BEFORE encrypting (AES output does not compress) — but only
    // for a node whose fetcher reads gzip (bundle_gzip_gate).
    let (to_encrypt, gzip_note) = match bundle_gzip_gate(&node_app_version) {
        Err(why) => {
            nstep(&format!("bundle not compressed: {why}"));
            (bundle.clone(), None)
        }
        Ok(()) => match gzip_bundle(&bundle, &work) {
            Ok(gz) => {
                let from = std::fs::metadata(&bundle).map(|m| m.len() as usize).unwrap_or(0);
                (gz, Some(format!(", gzip from {}", human_bytes(from))))
            }
            Err(e) => {
                warn_line(&format!("bundle not compressed: {e} — staging it uncompressed"));
                (bundle.clone(), None)
            }
        },
    };
    nstep(&format!("encrypting the bundle to {node}'s birth cert"));
    let blob = match encrypt_bundle_cms(&to_encrypt, cert, &work) {
        Ok(b) => b,
        Err(e) => { scrub(&work);
            fail(g.json, ExitCode::Generic, "encrypt_failed", &e,
                Some("is openssl installed on the controller?")); }
    };
    scrub(&work);
    nstep(&format!("staging the encrypted bundle at the gateway ({}{})", human_bytes(blob.len()), gzip_note.as_deref().unwrap_or("")));
    if let Err(e) = post_bytes(g, &format!("/api/cluster/provision-bundle/{node}"), &blob) {
        fail(g.json, ExitCode::Generic, "stage_failed", &e, None);
    }
    let poked = poke_fetch(g, &node);
    let staged_sha = sha256_hex(&blob);
    ProvStaged { sha: staged_sha, poked, legacy }
}

/// --stage-only: report the staged bundle and stop. Nothing here has judged the node.
/// Everything up to and including the poke is done; the caller
/// (`noo upgrade --nodes`) waits for the apply, for every node at
/// once. Nothing here has judged the node: "staged" is printed
/// as exactly that, and the verdict is the caller's, from the
/// node's own report.
fn report_staged_only(g: &Globals, a: &ProvisionArgs, staged: &ProvStaged) {
    let node = a.node.clone();
    let staged_sha = staged.sha.clone();
    let poked = staged.poked;
        nstep(&format!("{node} staged (sha {}) — not waiting for the apply (--stage-only)", &staged_sha[..12]));
        if g.json {
            println!("{}", serde_json::json!({
                "status": "staged", "node": node, "staged_sha": staged_sha, "poked": poked,
            }));
        }
}

/// Wait for the node to pull, apply and REPORT, and judge the report ("Agent registered" is not success).
/// Verification (2026-09-03): the node's fetcher REPORTS the applier's
/// exit code (POST /bootstrap/bundle/{node}/applied) and the status
/// route surfaces it. "Agent registered" is no longer success — it
/// was true while HOST3's applier refused the bundle with 76. A
/// legacy node (old fetcher, cannot report) is judged the old way
/// and said so.
fn await_apply(g: &Globals, a: &ProvisionArgs, m: &ProvMachine, staged: &ProvStaged) {
    let node = a.node.clone();
    let darwin = m.darwin;
    let self_node = crate::role::is_self_node(&node);
    let staged_sha = staged.sha.clone();
    let poked = staged.poked;
    let legacy = staged.legacy;
    let mut poll = ui::Poll::start_under(&if poked {
        format!("staged — waiting for {node} to pull, apply and report (poked over the bus; its 5-min timer is the fallback)")
    } else {
        format!("staged — waiting for {node} to pull, apply and report (up to 10 min; an idle node polls about every 5)")
    });
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(600);
    let mut seen_fetch = false;
    let mut outcome: Option<(i64, String)> = None;
    while std::time::Instant::now() < deadline {
        poll.tick(started.elapsed().as_secs());
        if let Some(st) = crate::http::get_json_opt(
            g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        {
            match judge_bundle_status(&st, &staged_sha) {
                BundleVerdict::Applied { rc, msg } => {
                    outcome = Some((rc, msg));
                    break;
                }
                BundleVerdict::Fetched if !seen_fetch => {
                    seen_fetch = true;
                    poll = ui::Poll::start_under(&format!("{node} fetched the bundle — waiting for decrypt + apply"));
                }
                BundleVerdict::Fetched | BundleVerdict::Nothing => {}
            }
        }
        if legacy_fallback_due(legacy, seen_fetch, started.elapsed().as_secs()) && node_is_online(g, &node) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    drop(poll);
    let reprovision = format!("noo cluster provision {node}");
    match outcome {
        Some((0, ref msg)) => {
            nstep(&format!("{node} reported: applied (exit 0)"));
            // One function for every caller (this verb and the combined
            // wait of `noo upgrade --nodes`), so the post-apply steps
            // cannot drift between them. The controller's own node has
            // extra steps; every other node gets the common ones.
            if self_node {
                after_self_applied(g, &node, msg);
            } else {
                after_remote_applied(g, &node, msg);
            }
        }
        Some((rc, msg)) => {
            let tail: String = msg.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
            ui::capture("applier output", tail.trim());
            fail_guided(g, ExitCode::Generic, "apply_failed",
                &format!("{node}: the applier refused the bundle (exit {rc})"),
                "the node kept its previous state; fix the cause and re-run `noo cluster provision <node>`",
                &[(&reprovision, "the node kept its previous state — fix the cause above, then re-stage"),
                  (if darwin { "sudo /usr/local/bin/noo node fetch --user $(id -un)" } else { "journalctl -u noo-fetch -n 20" },
                   "on the node — the applier's own log, if the tail above is not enough")]);
        }
        None if legacy && seen_fetch => {
            println!("{}", ui::sub(&ui::status_line(Glyph::Warn,
                &format!("{node}: applied without confirmation — this node's fetcher predates apply reports; the next restage confirms"))));
        }
        None => {
            let (code, msg, hint, guide): (&str, String, &str, Vec<(&str, &str)>) = if seen_fetch {
                ("not_reported_after_fetch",
                 format!("{node}: fetched the bundle but reported no apply outcome"),
                 if darwin {
                     "on the Mac: `sudo launchctl print system/net.noomesh.fetch | grep -E 'state|last exit'` \
                      and `sudo /usr/local/bin/noo node fetch --user $(id -un)` for the apply error"
                 } else {
                     "on the node: `journalctl -u noo-fetch -n 20` (apply result) then \
                      `journalctl -u noo-node-agent -n 30`"
                 },
                 if darwin {
                     vec![("sudo launchctl print system/net.noomesh.fetch | grep -E 'state|last exit'", "on the Mac — the poller's state and last exit code"),
                          ("sudo /usr/local/bin/noo node fetch --user $(id -un)", "on the Mac — runs one poll by hand and shows the apply error"),
                          (reprovision.as_str(), "re-stage once the apply error is fixed")]
                 } else {
                     vec![("journalctl -u noo-fetch -n 20", "on the node — the apply result"),
                          ("journalctl -u noo-node-agent -n 30", "on the node — the agent's view after the apply"),
                          (reprovision.as_str(), "re-stage once the apply error is fixed")]
                 })
            } else {
                ("not_fetched",
                 format!("{node}: bundle staged but the node never fetched it"),
                 if darwin {
                     "the Mac's poller is not reaching the controller — on the Mac: \
                      `sudo launchctl print system/net.noomesh.fetch | grep -E 'state|last exit'`, \
                      then run one poll by hand to see the error: \
                      `sudo /usr/local/bin/noo node fetch --user $(id -un)` \
                      (needs ~/noomesh/pki/ca.crt — an older enroll never wrote it: re-run `noo enroll`)"
                 } else {
                     "the node's poll is not reaching the controller — on the node: \
                      `systemctl status noo-fetch.timer` and `journalctl -u noo-fetch -n 20` \
                      (TLS/connectivity errors live there)"
                 },
                 if darwin {
                     vec![("sudo launchctl print system/net.noomesh.fetch | grep -E 'state|last exit'", "on the Mac — is the poller loaded, and what did it last exit with"),
                          ("sudo /usr/local/bin/noo node fetch --user $(id -un)", "on the Mac — one poll by hand shows the connectivity or TLS error (needs ~/noomesh/pki/ca.crt; an older enroll never wrote it — re-run noo enroll)"),
                          (reprovision.as_str(), "re-stage once the poll reaches the controller")]
                 } else {
                     vec![("systemctl status noo-fetch.timer", "on the node — the poll is not reaching the controller; is the timer active"),
                          ("journalctl -u noo-fetch -n 20", "on the node — TLS and connectivity errors live here"),
                          (reprovision.as_str(), "re-stage once the poll reaches the controller")]
                 })
            };
            fail_guided(g, ExitCode::Generic, code, &msg, hint, &guide);
        }
    }
}

/// The closing line (and the JSON record) of a provisioned node.
fn report_provisioned(g: &Globals, a: &ProvisionArgs, id: &ProvIdentity, m: &ProvMachine) {
    let node = a.node.clone();
    let tier = id.tier.clone();
    let ip = id.ip.as_str();
    let user = id.user.as_str();
    let goarch = m.goarch.as_str();
    if g.json {
        println!("{}", serde_json::json!({
            "status":"provisioned","node":node,"ip":ip,"user":user,
            "tier":tier,"arch":goarch,
            "transport": "pull",
        }));
    } else {
        let how = "pull";
        ui::close_done(&format!("{node}: provisioned via {how} (tier {tier}, {goarch})"));
        ui::guide(&[
            ("noo cluster status", "the node should show Online within a heartbeat"),
            (&format!("noo cluster place {node} <backend> <model>"), "give it something to run"),
            (&format!("noo cluster logs {node}"), "if it does not register, the agent log names the cause"),
        ]);
    }
}


// ─────────────────────────────────────────────────────────────────────────────

/// Issue or renew `node`'s backend door leaves in the local PKI, saying
/// what was done. Fatal on an issuance failure: a bundle staged without
/// them leaves every placed backend refused on the node, and the operator
/// would learn that from `cluster verify` instead of here.
fn ensure_door_leaves(g: &Globals, ca: &crate::pki::ClusterCa, node: &str) {
    if let Err(e) = ensure_door_leaves_try(ca, node) {
        fail(g.json, ExitCode::Generic, "leaf_issue_failed", &e,
            Some("is the cluster CA readable here? `noo security pki status`"));
    }
}

/// [`ensure_door_leaves`], returning the error instead of exiting.
fn ensure_door_leaves_try(ca: &crate::pki::ClusterCa, node: &str) -> Result<(), String> {
    match super::node_leaves::ensure_node_leaves(ca, node, crate::pki::DEFAULT_DAYS) {
        Ok(issued) if issued.is_empty() => nstep("backend door leaves: current (none re-issued)"),
        Ok(issued) => {
            for (svc, why) in issued {
                nstep(&format!("backend door leaf {svc}: issued ({why})"));
            }
        }
        Err(e) => return Err(format!("could not issue {node}'s backend door leaves: {e}")),
    }
    // The keys this bundle packs are the CLI's alone on this disk (0600,
    // `pki::KeyReader::Cli`). Issuance sets that; a key from before
    // 2026-09-28, or one a `sudo` run left root-owned, is repaired here —
    // the provision that ships a key is the moment to be sure of it.
    for f in ca.fix_node_key_modes(node) {
        match &f.needs {
            Some(cmd) => nnote(&format!("{}: {:04o}, owned by another uid — run: {cmd}", f.rel, f.before)),
            None if f.changed() => nstep(&format!("{}: {:04o} → {:04o}", f.rel, f.before, f.after)),
            None => {}
        }
    }
    Ok(())
}

/// A node's live record from `/api/cluster/nodes` (its heartbeat view), or
/// None when the gateway does not list it. `noo upgrade`'s Mac-leaves pass
/// reads the same record, so both decide on one reading.
pub(crate) fn live_node_record(g: &Globals, node: &str) -> Option<serde_json::Value> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10).and_then(|b| {
        b["nodes"].as_array().and_then(|ns| ns.iter().find(|n| n["id"].as_str() == Some(node)).cloned())
    })
}

/// What the node's agent reports it runs (`noo-cli-v0.5.63+sha`); empty when unknown.
pub(crate) fn live_app_version(live_node: Option<&serde_json::Value>) -> String {
    live_node.and_then(|n| n["app_version"].as_str().map(String::from)).unwrap_or_default()
}

/// The target OS, from the enrollment facts. "arm64" alone cannot
/// tell a Pi from a Mac. Absent (older enroll clients, the controller's own
/// local lane) → linux.
pub(crate) fn enrolled_os(record: Option<&Redemption>) -> String {
    record
        .and_then(|r| r.facts.as_ref())
        .and_then(|f| f.get("os"))
        .and_then(|v| v.as_str())
        .unwrap_or("linux")
        .to_string()
}

// ── i67: the controller's own node rides the rail ─────────────────────────
//
// A controller box holds two roles that update separately: the controller
// (`noo upgrade --stack`) and a node (the rail, like every other node). The
// node role must not depend on the controller role's update path, so the
// self node is staged, poked, fetched, applied and reported exactly like a
// remote node. The one sudo left is the first install inside `noo onboard`,
// which is what puts the pull units below on the box.

/// What host prep installs for the pull lane, as `(path, name)`: without any
/// one of them a staged bundle is never collected or applied.
pub(crate) const PULL_UNITS: &[(&str, &str)] = &[
    ("/usr/local/bin/noo-fetch", "noo-fetch"),
    ("/usr/local/bin/noo-apply", "noo-apply"),
    ("/etc/systemd/system/noo-fetch.timer", "noo-fetch.timer"),
    (SELF_BIRTH_CRT, "the birth cert"),
];
/// The self node's birth cert (0644; the key beside it is root 0600).
const SELF_BIRTH_CRT: &str = "/etc/noo/birth.crt";
/// Where the gateway sees it: `<pki>/nodes/<self>/birth.crt`, mirrored into
/// the certificate-only view it mounts read-only (`public/nodes`), the same
/// path every node cert takes (gateway-rust `bootstrap::self_birth_cert_path`).
pub(crate) const SELF_BIRTH_CRT_PKI_NAME: &str = "birth.crt";
/// The node name noo-fetch asks the controller for.
const SELF_NODE_NAME_FILE: &str = "/etc/noo/node-name";
/// The command that installs the pull units on a controller (its services
/// step runs the first install, the one sudo).
pub(crate) const SELF_RAIL_REMEDY: &str = "noo onboard --only services";

/// The pull units missing for `node`, by name; empty = the rail can reach
/// it. `exists` and the recorded node name are passed in so the rule is
/// testable without a prepped host.
pub(crate) fn missing_pull_units(node: &str, exists: &dyn Fn(&str) -> bool, node_name: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = PULL_UNITS.iter()
        .filter(|(p, _)| !exists(p))
        .map(|(_, n)| (*n).to_string())
        .collect();
    match node_name.map(str::trim).filter(|n| !n.is_empty()) {
        None => out.push(format!("{SELF_NODE_NAME_FILE} (no node name)")),
        // noo-fetch would collect another name's bundle.
        Some(n) if !n.eq_ignore_ascii_case(node) => out.push(format!("{SELF_NODE_NAME_FILE} names '{n}', not '{node}'")),
        Some(_) => {}
    }
    out
}

/// [`missing_pull_units`] on this machine.
pub(crate) fn pull_units_missing(node: &str) -> Vec<String> {
    let name = std::fs::read_to_string(SELF_NODE_NAME_FILE).ok();
    missing_pull_units(node, &|p| Path::new(p).is_file(), name.as_deref())
}

/// Put the host's birth cert where the gateway reads it: copy `host_crt`
/// (the cert host prep installed beside the key it holds) to
/// `<pki>/nodes/<node>/birth.crt` when it differs, then re-sync the PKI's
/// certificate-only view, which the gateway mounts read-only. No sudo (the
/// cert is 0644; the PKI is the operator's), no API, and the gateway cannot
/// write it. Returns whether the copy changed.
pub(crate) fn sync_self_birth_cert(pki: &Path, node: &str, host_crt: &Path) -> Result<bool, String> {
    let pem = std::fs::read(host_crt).map_err(|e| format!("cannot read {} ({e})", host_crt.display()))?;
    if !String::from_utf8_lossy(&pem).trim_start().starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(format!("{} is not a PEM certificate", host_crt.display()));
    }
    let dir = pki.join("nodes").join(node);
    let dst = dir.join(SELF_BIRTH_CRT_PKI_NAME);
    let changed = std::fs::read(&dst).ok().as_deref() != Some(pem.as_slice());
    if changed {
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {} ({e})", dir.display()))?;
        let tmp = dir.join(".birth.crt.next");
        std::fs::write(&tmp, &pem)
            .and_then(|_| {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            })
            .and_then(|_| std::fs::rename(&tmp, &dst))
            .map_err(|e| format!("write {} ({e})", dst.display()))?;
    }
    let sync = crate::pki::ClusterCa::new(pki.to_path_buf()).sync_public_view();
    if let Some(e) = sync.errors.first() {
        return Err(format!("the PKI's public view did not sync ({e})"));
    }
    Ok(changed)
}

/// How the controller's own node is provisioned by the rail verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelfLane {
    /// Staged on the rail, like any node. No sudo.
    Rail,
    /// Its node identity (birth key, pull units) is missing — a
    /// controller installed before i67. Created ONCE,
    /// with the one sudo, by the same prep path onboard uses; then the rail.
    CreateIdentity,
    /// Identity missing and sudo would prompt where nobody can answer:
    /// refused with the remedy, never a silent skip.
    Refuse(String),
}

/// The provisioning plan for the controller's own node. Pure.
pub(crate) fn self_node_lane(node: &str, missing: &[String], can_sudo: bool) -> SelfLane {
    if missing.is_empty() {
        SelfLane::Rail
    } else if can_sudo {
        SelfLane::CreateIdentity
    } else {
        SelfLane::Refuse(format!(
            "'{node}' is this controller's own node and its node identity is missing ({}): creating \
             it takes sudo once, and sudo would prompt in this non-interactive run",
            missing.join(", ")
        ))
    }
}

/// What onboard's self-agent step does (i67). Pure, so every branch is
/// testable: which controller, whether a host agent is installed or
/// running, whether the node identity is in place, and whether sudo can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelfAgentStep {
    /// Nothing to do, and why (always printed).
    Skip(String),
    /// Running, identity in place: upgrades already ride the rail.
    AlreadyOnRail,
    /// Restage over the rail; `cluster provision` creates the identity once
    /// (sudo) first when it is missing.
    Rail,
    /// No agent and no identity: the first install (the one sudo).
    FirstInstall,
}

pub(crate) fn self_agent_step(
    controller: Option<&crate::role::Controller>,
    agent_installed: bool,
    agent_active: bool,
    identity_ok: bool,
    interactive: bool,
    sudo_quiet: bool,
) -> SelfAgentStep {
    use crate::role::Controller;
    match controller {
        None => return SelfAgentStep::Skip("this box is not a controller: no self agent to install".into()),
        Some(Controller::Checkout(_)) if !agent_installed => return SelfAgentStep::Skip(
            "a source-checkout controller with no host agent: nothing to install (a standalone install offers one)".into()),
        Some(_) => {}
    }
    if identity_ok {
        return if agent_active { SelfAgentStep::AlreadyOnRail } else { SelfAgentStep::Rail };
    }
    if !interactive && !sudo_quiet {
        return SelfAgentStep::Skip(
            "the node identity is missing and creating it takes sudo, which would prompt in this \
             non-interactive run — run `noo onboard --only services` at a terminal".into());
    }
    if agent_installed { SelfAgentStep::Rail } else { SelfAgentStep::FirstInstall }
}

/// Can sudo run here without hanging: it is already cached/passwordless, or
/// someone is at a terminal to answer it.
pub(crate) fn can_sudo_here() -> bool {
    let quiet = Command::new("sudo").args(["-n", "true"])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    quiet || std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// The root script that creates (or repairs) the self node's identity: a
/// birth keypair when `etc` holds none, host prep (`prep_line`, which
/// installs it and arms noo-fetch.timer), and the staged keypair removed.
/// `etc` is `/etc/noo` in production. The gateway's view of the cert is the
/// CLI's job afterwards ([`sync_self_birth_cert`], no root).
pub(crate) fn self_identity_script(node: &str, work: &Path, etc: &Path, prep_line: &str) -> String {
    let (w, e) = (work.display(), etc.display());
    format!(
        "if [ ! -s \"{e}/birth.key\" ] || [ ! -s \"{e}/birth.crt\" ]; then\n\
         \x20 openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
         -keyout \"{w}/birth.key\" -out \"{w}/birth.crt\" -subj \"/CN=noo-birth-{node}\" >/dev/null 2>&1 \
         || echo \"birth keypair generation failed — the pull units stay unarmed\" >&2\n\
         fi\n\
         {prep_line}\
         rm -f \"{w}/birth.key\" \"{w}/birth.crt\"\n"
    )
}

/// The host-prep line for the self node, rendered for a root script: the
/// CA pin beside the insecure switch, and the birth keypair the identity
/// script generates into `work`.
fn self_prep_line(node: &str, prep: &Path, data_root: &str, work: &Path) -> Result<String, String> {
    let pki = crate::pki::pki_dir();
    let user = std::env::var("USER").unwrap_or_default();
    let ctrl_host = controller_dnsname().unwrap_or_else(|| "localhost".into());
    let prep_release = format!("{}/{}", env!("CARGO_PKG_VERSION"), image_tag());
    // The gateway's leaf is not in the system trust store, so prep's one
    // first-contact fetch cannot verify the transport — PREP_INSECURE=1.
    // What makes that safe is the PIN: the CA is on THIS disk. Never
    // PREP_INSECURE=1 alone — tests/test_prep_tofu_is_pinned.py.
    let ca_pin = std::fs::read(pki.join("ca.crt"))
        .map_err(|e| e.to_string())
        .and_then(|pem| crate::commands::node_fetch::cert_der_sha256(&pem))
        .map_err(|e| format!(
            "cannot fingerprint {} ({e}) — host prep would fetch the cluster CA unpinned; \
             run `noo onboard --only security` first", pki.join("ca.crt").display()))?;
    let mut c = Command::new("env");
    c.arg(format!("PREP_ENROLL_USER={user}"))
        .arg(format!("PREP_NOO_URL=https://{ctrl_host}:8080"))
        .arg("PREP_INSECURE=1")
        .arg(format!("PREP_CA_SHA256={ca_pin}"))
        .arg(format!("PREP_NODE_NAME={node}"))
        .arg(format!("NOO_DATA_ROOT={data_root}"))
        .arg(format!("PREP_RELEASE={prep_release}"))
        .arg(format!("PREP_BIRTH_KEY={}/birth.key", work.display()))
        .arg(format!("PREP_BIRTH_CRT={}/birth.crt", work.display()))
        .arg("bash").arg(prep);
    Ok(format!("{} || echo \"host prep exited $? — continuing\" >&2\n", command_line(&c)))
}

/// The ONE-TIME creation of this controller's node identity (i67 migration:
/// a controller installed before 0.6.3 has no birth key, pull units or
/// gateway copy). One sudo, said as such; afterwards every install of this
/// node rides the rail. `Err` names what is still missing.
pub(crate) fn ensure_self_identity(node: &str) -> Result<(), String> {
    nstep("creating this controller's node identity — sudo once, never again (later upgrades of this node ride the rail)");
    let root = crate::envfile::repo_root();
    let (prep, _guard) = stage_prep_host(&root)?;
    let work = std::env::temp_dir().join(format!("noo-selfid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("cannot stage {}: {e}", work.display()))?;
    let _ = std::fs::set_permissions(&work, {
        use std::os::unix::fs::PermissionsExt; std::fs::Permissions::from_mode(0o700)
    });
    let line = match self_prep_line(node, &prep, &local_data_root(&root), &work) {
        Ok(l) => l,
        Err(e) => { let _ = std::fs::remove_dir_all(&work); return Err(e); }
    };
    let script = format!("set -e\n{}", self_identity_script(node, &work, Path::new("/etc/noo"), &line));
    let ok = Command::new("sudo").args(["sh", "-c", &script]).status().map(|s| s.success()).unwrap_or(false);
    let _ = std::fs::remove_dir_all(&work);
    if !ok {
        return Err("the identity script did not complete (see output above)".into());
    }
    match pull_units_missing(node) {
        m if m.is_empty() => {
            sync_self_birth_cert(&crate::pki::pki_dir(), node, Path::new(SELF_BIRTH_CRT))?;
            nnote("node identity created — this was the one sudo; upgrades of this node now ride the rail");
            Ok(())
        }
        m => Err(format!("still missing after the identity step: {}", m.join(", "))),
    }
}

/// Which lane last installed the self node, recorded beside its PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfLaneRecord {
    /// `noo onboard`'s first install (the one sudo).
    Onboard,
    /// A rail apply the node reported with exit 0.
    Rail,
}

impl SelfLaneRecord {
    pub(crate) fn word(self) -> &'static str {
        match self {
            SelfLaneRecord::Onboard => "onboard",
            SelfLaneRecord::Rail => "rail",
        }
    }
}

/// `<pki>/nodes/<node>/self-agent.lane`: one word, `onboard` or `rail`.
/// Absent while an older CLI's local lane was the last to install.
pub(crate) const SELF_LANE_RECORD: &str = "self-agent.lane";

fn write_self_lane(node: &str, lane: SelfLaneRecord) {
    let path = crate::pki::pki_dir().join("nodes").join(node).join(SELF_LANE_RECORD);
    if let Err(e) = std::fs::write(&path, format!("{}\n", lane.word())) {
        nnote(&format!("could not record the self-agent lane at {} ({e}) — `noo cluster verify` will read it as unknown", path.display()));
    }
}

/// The recorded lane for `node`, and whether the pre-i67 local lane's
/// install record is present (`local-lane.state`).
pub(crate) fn read_self_lane(node: &str) -> (Option<String>, bool) {
    let dir = crate::pki::pki_dir().join("nodes").join(node);
    let rec = std::fs::read_to_string(dir.join(SELF_LANE_RECORD)).ok()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    (rec, dir.join(LOCAL_LANE_STATE).is_file())
}

/// This controller's own node name: the enrolled name on this box, else the
/// NODE_ID the controller install recorded, else the hostname.
pub(crate) fn self_node_name() -> Option<String> {
    let trimmed = |s: String| { let t = s.trim().to_string(); (!t.is_empty()).then_some(t) };
    std::fs::read_to_string(SELF_NODE_NAME_FILE).ok().and_then(trimmed)
        .or_else(|| trimmed(crate::onboard::env::read_env_key(&crate::envfile::repo_root().join(".env"), "NODE_ID")))
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().and_then(trimmed))
}

/// The self node's data root when nothing else names one: the process env,
/// then the install's `.env`, then the built-in default.
fn local_data_root(root: &Path) -> String {
    std::env::var("NOO_DATA_ROOT").ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let v = crate::onboard::env::read_env_key(&root.join(".env"), "NOO_DATA_ROOT");
            (!v.is_empty()).then_some(v)
        })
        .unwrap_or_else(|| "/data/noo".into())
}

/// The self node's "enrollment record", from THIS machine: its address,
/// operator account, facts and birth cert. Never the gateway's record under
/// its name, which may belong to another machine (i11a).
fn self_node_redemption(node: &str) -> Result<Redemption, String> {
    let cert = std::fs::read_to_string(SELF_BIRTH_CRT)
        .map_err(|e| format!("cannot read {SELF_BIRTH_CRT} ({e}) — '{node}' has no birth identity for the rail"))?;
    if !cert.trim_start().starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(format!("{SELF_BIRTH_CRT} is not a PEM certificate"));
    }
    let root = crate::envfile::repo_root();
    let gpu = Command::new("nvidia-smi").output().map(|o| o.status.success()).unwrap_or(false);
    Ok(Redemption {
        ip: crate::onboard::util::detect_ip(),
        user: std::env::var("USER").unwrap_or_default(),
        birth_cert: Some(cert),
        facts: Some(self_node_facts(std::env::consts::ARCH, &local_data_root(&root), gpu)),
    })
}

/// The facts the self node reports for itself, in the shape `noo enroll`
/// sends. Pure.
pub(crate) fn self_node_facts(arch: &str, data_root: &str, gpu: bool) -> serde_json::Value {
    serde_json::json!({"os": "linux", "arch": arch, "data_root": data_root, "gpu_present": gpu})
}

/// What is wrong with the gateway's view of the self node, and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelfViewProblem {
    pub code: &'static str,
    pub msg: String,
    pub remedy: String,
}

/// Does the gateway see THIS controller's node, with THIS birth cert? Judged
/// from `GET /api/cluster/self-node` (`None` = no HTTP answer). Pure.
pub(crate) fn judge_gateway_self_view(node: &str, local_fp: &str, answer: Option<(u16, &str)>) -> Result<(), SelfViewProblem> {
    let p = |code, msg: String, remedy: &str| Err(SelfViewProblem { code, msg, remedy: remedy.to_string() });
    let Some((status, body)) = answer else {
        return p("gateway_unreachable", "the gateway did not answer, so its view of this node's birth cert is unknown".into(),
            "noo stack status");
    };
    match status {
        200..=299 => {}
        404 => return p("gateway_predates_i67",
            "the gateway does not serve /api/cluster/self-node: it predates the self-node rail".into(), "noo upgrade --stack"),
        401 | 403 => return p("gateway_auth", format!("the gateway refused the self-node read (HTTP {status})"), "noo auth login"),
        s => return p("gateway_error", format!("the gateway answered HTTP {s} to the self-node read"), "noo stack status"),
    }
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let gw_node = v.get("node").and_then(|n| n.as_str()).unwrap_or("");
    if !gw_node.eq_ignore_ascii_case(node) {
        return p("self_id_mismatch", format!(
            "the gateway knows this controller's node as '{}', the CLI as '{node}' — the gateway reads \
             NOO_CONTROLLER_NODE_ID, then NOO_CONTROLLER_HOSTNAME (compose: NODE_ID in .env); \
             set NODE_ID={node} in .env and roll the stack",
            if gw_node.is_empty() { "(unset)" } else { gw_node }), "noo upgrade --stack");
    }
    match v.get("birth_cert_sha256").and_then(|f| f.as_str()) {
        None => p("gateway_no_self_cert", format!(
            "the gateway cannot read this node's birth cert (pki/public/nodes/{node}/birth.crt, its \
             read-only view) — a gateway from before this release reads it elsewhere"),
            "noo upgrade --stack"),
        Some(fp) if !fp.eq_ignore_ascii_case(local_fp) => Err(SelfViewProblem {
            code: "gateway_self_cert_stale",
            msg: format!("the gateway's view of the birth cert ({fp}) is not /etc/noo/birth.crt ({local_fp})"),
            remedy: format!("noo cluster provision {node}"),
        }),
        Some(_) => Ok(()),
    }
}

/// The `nats-creds` member every bundle must carry: present, naming `node`,
/// with a complete `node-<node>` pair. The i44 class (the pair dropped from
/// a bundle) is refused here on the rail, the controller's own node
/// included, before anything is signed.
pub(crate) fn require_nats_creds(node: &str, files: &[(&str, Vec<u8>)]) -> Result<(), String> {
    let Some((_, nc)) = files.iter().find(|(k, _)| *k == "nats-creds") else {
        return Err(format!("the bundle for {node} carries no nats-creds — its agent would have no bus credential"));
    };
    check_nats_creds(node, nc)
}

/// The credential names `node` and carries its own pair.
fn check_nats_creds(node: &str, bytes: &[u8]) -> Result<(), String> {
    let creds = String::from_utf8_lossy(bytes);
    let val = |k: &str| creds.lines().filter_map(|l| l.strip_prefix(k)).next_back().unwrap_or("").trim().to_string();
    if val("NODE=") != node {
        return Err(format!("the NATS credential names '{}', not {node}", val("NODE=")));
    }
    if val("NATS_NODE_USER=") != format!("node-{node}") || val("NATS_NODE_PASSWORD=").is_empty() {
        return Err(format!("the NATS credential for {node} carries no complete pair"));
    }
    Ok(())
}

/// A node's redeemed name-bound token, everything provisioning needs.
pub(crate) struct Redemption {
    ip: String,
    user: String,
    /// PEM the pull lane encrypts the bundle to (migration 053; absent on
    /// nodes enrolled before the pull flow must be re-enrolled).
    birth_cert: Option<String>,
    /// Machine facts gathered at enrollment (arch/model/gpu_present/
    /// data_root) — replaces the push lane's SSH facts probe.
    facts: Option<serde_json::Value>,
}

/// Latest redemption wins, same as the script.
pub(crate) fn redemption_record(g: &Globals, node: &str) -> Option<Redemption> {
    let doc = crate::http::get_json(g, "/api/security/bootstrap-tokens", true, 15);
    let toks = doc.get("tokens")?.as_array()?;
    let mut hits: Vec<&serde_json::Value> = toks.iter()
        .filter(|t| t.get("node_name").and_then(|v| v.as_str()) == Some(node)
            && !t.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false)
            && t.get("used_at").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty())
            && t.get("used_by_ip").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty()))
        .collect();
    hits.sort_by_key(|t| t.get("used_at").and_then(|v| v.as_str()).unwrap_or("").to_string());
    let t = hits.last()?;
    Some(Redemption {
        ip: t.get("used_by_ip").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        user: t.get("enroll_user").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        birth_cert: t.get("birth_cert").and_then(|v| v.as_str()).map(str::to_string),
        facts: t.get("facts").cloned().filter(|f| f.is_object()),
    })
}

/// Tier ladder over the ENROLLMENT facts JSON — same rules as the gate-facts
/// text ladder below: SBC board → 4, GPU → 2, arm → 4, else 3.
/// A node's tier on (re-)provision, and where it came from: the gateway's
/// live `derived_tier` when the node has heartbeated and the ladder decided,
/// else the enrollment facts. The gateway omits `derived_tier` when its
/// ladder returns UNKNOWN, so absence falls through rather than defaulting.
pub(crate) fn resolve_tier(
    live_node: Option<&serde_json::Value>,
    facts: Option<&serde_json::Value>,
) -> Option<(String, &'static str)> {
    if let Some(t) = live_node.and_then(|n| n["derived_tier"].as_u64()).filter(|t| (1..=6).contains(t)) {
        return Some((t.to_string(), "the node's live facts"));
    }
    facts.map(|f| (derive_tier_facts(f), "enrollment facts"))
}

/// Whether the applier's report lists `kind` as applied. The applier ends
/// with `applied: <kind> <kind> …`, and a kind is on that line only after
/// its own verification passed.
///
/// Found by its marker, NOT by line: the report arrives via the node's
/// fetcher, which flattens the log (`tr '\n\r\t' '   '` in noo-fetch.sh)
/// before posting it, so `applied:` sits mid-string. This used to require it
/// at the start of a line, matched nothing on the real wire, and returned
/// false in silence — the controller-mode hostd was never refreshed on the
/// first release that tried (0.5.61 on host8, 2026-09-28).
pub(crate) fn applier_applied(msg: &str, kind: &str) -> bool {
    let Some(at) = msg.rfind("applied:") else { return false };
    // A whole word: `re-applied:` or `unapplied:` would not be the summary.
    if msg[..at].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '-') {
        return false;
    }
    msg[at + "applied:".len()..].split_whitespace().any(|k| k == kind)
}

/// The `<kind>=<sha256>` pairs after the LAST `binary-sha:` in an apply
/// report message (Linux `noo-apply` prints it as its final line; a Mac's
/// fetch appends it). Empty for an applier that predates the line.
fn reported_binary_shas(msg: &str) -> Vec<(String, String)> {
    let Some(at) = msg.rfind("binary-sha:") else { return Vec::new() };
    msg[at + "binary-sha:".len()..].split_whitespace()
        .filter_map(|t| t.split_once('='))
        .filter(|(_, h)| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|(k, h)| (k.to_string(), h.to_ascii_lowercase()))
        .collect()
}

/// Does the node's last apply report PROVE it runs exactly `asset_sha` as
/// `kind`? `status` is `/api/cluster/provision-bundle/<node>/status`. All of:
/// the report is about the bundle currently staged (`applied_sha` equals the
/// staged `sha256`), it was an apply that succeeded (`apply_rc` 0), and the
/// node itself stated `kind=<asset_sha>` in its `binary-sha:` line. Anything
/// else — no status, no report yet, a refused apply, an applier that prints no
/// such line, a different sha — is "not proven", and the caller carries the
/// binary. Never decided from a version string.
fn node_runs_asset(status: Option<&serde_json::Value>, kind: &str, asset_sha: &str) -> bool {
    let Some(st) = status else { return false };
    let staged = st["sha256"].as_str().unwrap_or("");
    let applied = st["applied_sha"].as_str().unwrap_or("");
    if staged.is_empty() || staged != applied || st["apply_rc"].as_i64() != Some(0) {
        return false;
    }
    let msg = st["apply_msg"].as_str().unwrap_or("");
    reported_binary_shas(msg).iter().any(|(k, h)| k == kind && h == &asset_sha.to_ascii_lowercase())
}

/// Remove from the bundle the binary kinds the node has proven it already
/// runs; returns one printed note per omission. Never touches the applier,
/// fetcher, env, unit, certificate or harness-env kinds. Held back on purpose:
/// a Mac's `agent-binary` (its applier requires that payload for a full
/// install) and, on the controller's own node, `hostd-binary` (the controller
/// restarts its user-mode hostd only when this apply installs one).
fn drop_proven_binaries(
    files: &mut Vec<(&str, Vec<u8>)>,
    status: Option<&serde_json::Value>,
    darwin: bool,
    self_node: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    for kind in ["agent-binary", "hostd-binary", "cli-binary", "harness-binary"] {
        if (darwin && kind == "agent-binary") || (self_node && kind == "hostd-binary") {
            continue;
        }
        let Some(sha) = files.iter().find(|(k, _)| *k == kind).map(|(_, b)| sha256_hex(b)) else { continue };
        if !node_runs_asset(status, kind, &sha) {
            continue;
        }
        files.retain(|(k, _)| *k != kind && !(kind == "cli-binary" && *k == "cli-user"));
        notes.push(format!("{kind}: unchanged since last apply, not carried (the node reported running these exact bytes)"));
    }
    // Each vendor CLI goes with its own manifest, slot by slot: the
    // appliers judge every slot on its own, so one proven CLI can stay
    // home while another rides.
    for (cli, manifest) in super::cluster_vendor::VENDOR_SLOTS {
        let Some(sha) = files.iter().find(|(k, _)| *k == cli).map(|(_, b)| sha256_hex(b)) else { continue };
        if !node_runs_asset(status, cli, &sha) {
            continue;
        }
        files.retain(|(k, _)| *k != cli && *k != manifest);
        notes.push(format!("vendor CLI: unchanged since last apply, not carried ({cli}; the node reported running these exact bytes)"));
    }
    notes
}

/// Restart the controller-mode hostd (a user unit on the same binary the
/// applier just upgraded) and wait for a heartbeat from the new process.
/// Reported, never fatal: the worker-mode half is already upgraded.
fn refresh_controller_hostd(root: &std::path::Path) {
    let active = std::process::Command::new("systemctl").args(["--user", "is-active", "--quiet", "noo-hostd"])
        .status().map(|s| s.success()).unwrap_or(false);
    if !active {
        return; // no controller-mode hostd on this box — nothing to refresh
    }
    let hb = root.join(".noo-host-spool").join("hostd.heartbeat.json");
    let before = std::fs::metadata(&hb).and_then(|m| m.modified()).ok();
    let restarted = std::process::Command::new("systemctl").args(["--user", "restart", "noo-hostd"])
        .status().map(|s| s.success()).unwrap_or(false);
    if !restarted {
        ui::warned("controller-mode hostd did not restart — it keeps running the previous build: systemctl --user restart noo-hostd");
        return;
    }
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let now = std::fs::metadata(&hb).and_then(|m| m.modified()).ok();
        if now.is_some() && now != before {
            let version = std::fs::read_to_string(&hb).ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|v| v["version"].as_str().map(String::from))
                .unwrap_or_else(|| "unknown".into());
            nnote(&format!("controller-mode hostd restarted on the new build ({version})"));
            return;
        }
    }
    ui::warned("controller-mode hostd restarted but wrote no fresh heartbeat in 40s — check: journalctl --user -u noo-hostd");
}

pub(crate) fn derive_tier_facts(f: &serde_json::Value) -> String {
    // Unified memory (Apple Silicon, Tegra, GB10): the GPU's usable share of
    // RAM decides the tier — never tier 1 on Metal (no vLLM on macOS), tier 1
    // on CUDA only from 10 GB. An 8 GB Mac mini is tier 2, not an edge box.
    if f.get("unified_memory").and_then(|v| v.as_bool()).unwrap_or(false) {
        let usable = f.get("usable_gpu_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let api = f.get("gpu_api").and_then(|v| v.as_str()).unwrap_or("");
        if usable >= 10.0 && api == "cuda" {
            return "1".into();
        }
        if usable >= 4.0 {
            return "2".into();
        }
        return "4".into();
    }
    let model = f.get("model").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    if ["raspberry", "jetson", "orangepi", "orange pi", "rock"].iter().any(|m| model.contains(m)) {
        return "4".into();
    }
    if f.get("gpu_present").and_then(|v| v.as_i64()).unwrap_or(0) == 1
        || f.get("gpu_present").and_then(|v| v.as_bool()).unwrap_or(false)
    {
        return "2".into();
    }
    let arch = f.get("arch").and_then(|v| v.as_str()).unwrap_or("");
    if arch.starts_with("aarch64") || arch.starts_with("arm") {
        return "4".into();
    }
    "3".into()
}

/// THIS controller's tailnet MagicDNS name (`tailscale status --json` →
/// Self.DNSName, dot-trimmed) — the same resolution the bootstrap-token paste
/// composer uses. None when tailscale is absent/down.
/// The host part of `services.gateway_url` in the repo's noomesh.yaml, when
/// it names something other than this machine (a loopback or bare
/// `localhost` advertises nothing a node can reach). Read straight from the
/// file so an operator's `noo config set services {...}` is honoured on the
/// next provision without a CLI restart.
fn advertised_gateway_host() -> Option<String> {
    let path = crate::envfile::repo_root().join("noomesh.yaml");
    let doc: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let url = doc.get("services")?.get("gateway_url")?.as_str()?.trim();
    let host = url.split("://").nth(1).unwrap_or(url);
    let host = host.split('/').next().unwrap_or(host);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() || host == "localhost" || host.starts_with("127.") || host == "::1" || host.starts_with("0.0.0.0") {
        return None;
    }
    Some(host.to_string())
}

fn controller_dnsname() -> Option<String> {
    let out = Command::new("tailscale").args(["status", "--json"]).output().ok()?;
    if !out.status.success() { return None; }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v["Self"]["DNSName"].as_str()
        .map(|d| d.trim_end_matches('.').to_string())
        .filter(|d| !d.is_empty())
}


/// The fleet-wide credentials a node's env file carries. The bus credential
/// is NOT here: a node presents only its own `NATS_NODE_*` pair, which rides
/// the `nats-creds` bundle kind (the shared `NATS_USER`/`NATS_PASSWORD` pair
/// was retired by an earlier release).
struct Creds {
    agent_token: String,
    cluster_secret: String,
}

/// Decrypt secrets/env.sops in memory and lift exactly the agent's credential
/// set. Values never touch disk unencrypted except inside the signed bundle's
/// staged env (scrubbed after delivery).
fn sops_credentials(root: &Path) -> Result<Creds, String> {
    let path = root.join("secrets/env.sops");
    if !path.exists() {
        return Err(format!("{} not found — is the secret store initialised?", path.display()));
    }
    let mut cmd = crate::commands::secrets::sops_command().map_err(|e| e.to_string())?;
    cmd.args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"]).arg(&path);
    // SOPS_AGE_KEY_FILE, the TPM-sealed runtime key, or the default (i10a).
    let age_key = crate::age_key::path();
    cmd.env("SOPS_AGE_KEY_FILE", &age_key);
    let out = cmd.output().map_err(|e| format!("could not run sops: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sops could not decrypt {} (exit {}) — is the age key at {}?",
            path.display(), out.status.code().unwrap_or(-1), age_key.display()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let get = |k: &str| -> String {
        text.lines().find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or("").trim().trim_matches('"').to_string()
    };
    let creds = Creds {
        agent_token: get("NOO_NODE_AGENT_TOKEN"),
        cluster_secret: get("NOO_CLUSTER_SECRET"),
    };
    let mut missing = Vec::new();
    if creds.agent_token.is_empty() { missing.push("NOO_NODE_AGENT_TOKEN"); }
    if creds.cluster_secret.is_empty() { missing.push("NOO_CLUSTER_SECRET"); }
    if !missing.is_empty() {
        return Err(format!("missing from env.sops: {}", missing.join(", ")));
    }
    Ok(creds)
}

/// Stage the host-prep script from the copy compiled into this binary.
/// Returns the path plus a guard that removes the file on drop. Falls back
/// to the checkout file only when this is a crate-only build with no
/// embedded copy; with neither it is an error, never a silent skip.
fn stage_prep_host(root: &std::path::Path) -> Result<(std::path::PathBuf, PrepGuard), String> {
    let embedded = super::enroll::asset_prep();
    if embedded.is_empty() {
        let on_disk = root.join("scripts/prep-host.sh");
        return if on_disk.is_file() {
            Ok((on_disk, PrepGuard(None)))
        } else {
            Err("this noo binary carries no embedded prep-host.sh and there is no checkout copy".into())
        };
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("noo-prep-host-{}.sh", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&path)
        .and_then(|mut f| f.write_all(embedded.as_bytes()))
        .map_err(|e| format!("cannot stage prep-host.sh at {}: {e}", path.display()))?;
    Ok((path.clone(), PrepGuard(Some(path))))
}

struct PrepGuard(Option<std::path::PathBuf>);
impl Drop for PrepGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.0 { let _ = std::fs::remove_file(p); }
    }
}

/// The FIRST install of THIS machine's own agent (finding #15; i67: called
/// only by `noo onboard`) — the standalone controller's self-node. The same
/// artifacts as the rail (image-extracted binary, canonical env template,
/// embedded unit, local PKI certs), delivered by the one sudo onboard asks
/// for. Host prep runs inside it with a birth keypair, so it leaves the pull
/// units (noo-fetch, noo-apply, the timer, the birth cert) behind, and every
/// later install of this node rides the rail (`SelfLane::Rail`).
/// The applier's `agent_secret_files` block, lifted from
/// between its markers. `noo-apply` runs it at the end of every bundle; the
/// controller's own node is installed by the sudo script below instead, so
/// that script runs the same block — one implementation, and the local node
/// ends with its secrets in files exactly like a rail node. `None` when the
/// applier is not embedded (a crate-only build): the env then stays plain,
/// which the agent reads, and the next rail apply converts it.
pub(crate) fn agent_secret_files_block(applier: &str) -> Option<&str> {
    let start = applier.find("# BEGIN agent_secret_files\n")?;
    let end = start + applier[start..].find("# END agent_secret_files")?;
    Some(&applier[start..end])
}

/// The block plus its call, for onboard's first-install script (empty
/// when the block is unavailable). Same owner rule as the applier: the
/// unit's `User=`, root when that user does not exist.
fn local_agent_secret_files_script(applier: &str) -> String {
    let Some(block) = agent_secret_files_block(applier) else { return String::new() };
    format!(
        "{block}\nASF_OWNER=\"$(sed -n 's/^User=//p' /etc/systemd/system/noo-node-agent.service | tail -1)\"\n\
         {{ [ -n \"$ASF_OWNER\" ] && id -u \"$ASF_OWNER\" >/dev/null 2>&1; }} || ASF_OWNER=root\n\
         agent_secret_files /etc/noo-node-agent.env /etc/noo/agent-secrets /usr/local/bin/noo-node-agent \
         \"$ASF_OWNER\" /etc/noo-node-agent.env.container-backup || exit $?\n"
    )
}

/// The marker prep-host.sh writes (the record of what it decided and, since
/// it records them, the prep digest, inputs and release it ran with).
const LOCAL_PREP_MARKER: &str = "/etc/noo/host-prepped";
/// The installed agent binary (world-readable, so compared directly).
const LOCAL_AGENT_BIN: &str = "/usr/local/bin/noo-node-agent";
/// Per-node record of what the local lane last installed successfully:
/// `<kind> <sha256>` lines, 0600, in the operator's PKI dir beside node.key.
const LOCAL_LANE_STATE: &str = "local-lane.state";
/// The install script's exit when the agent env holds no NATS pair after the
/// install. The agent is NOT restarted on it, so a running agent keeps the
/// pair it already has in its process environment.
const NATS_PAIR_MISSING_EXIT: i32 = 86;

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

/// POSIX single-quoting.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A Command rendered as one shell line (program and arguments quoted).
fn command_line(c: &Command) -> String {
    std::iter::once(c.get_program()).chain(c.get_args())
        .map(|a| shq(&a.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Is the prep marker a record of THIS prep, run with these inputs? Every
/// wanted key must match exactly and the digest must be present: a marker
/// from an older prep (no digest) is not current, which re-runs prep once.
fn prep_marker_current(marker: &str, want: &[(&str, &str)]) -> bool {
    let kv: BTreeMap<&str, &str> = marker.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .collect();
    kv.get("PREPPED_VERSION") == Some(&"1")
        && kv.get("PREP_SHA256").is_some_and(|v| !v.is_empty())
        && want.iter().all(|(k, v)| kv.get(k) == Some(v))
}

/// The inputs of the controller's local "bundle": the same kinds a rail
/// bundle carries for an agent, delivered by one sudo script.
struct LocalInputs {
    signing_pub: Vec<u8>,
    agent_env: Vec<u8>,
    nats_creds: Vec<u8>,
    agent_binary: Vec<u8>,
    agent_unit: Vec<u8>,
    ca_crt: Vec<u8>,
    node_crt: Vec<u8>,
    node_key: Vec<u8>,
    leaves: Vec<(String, Vec<u8>)>,
    secret_files_script: Vec<u8>,
}

/// The staged kinds, in install order. Refuses a `nats-creds` that is not
/// this node's or carries no pair: the lane must never install an agent env
/// that cannot present one.
fn local_bundle(node: &str, i: LocalInputs) -> Result<Vec<(String, Vec<u8>)>, String> {
    check_nats_creds(node, &i.nats_creds)?;
    let mut v: Vec<(String, Vec<u8>)> = vec![
        ("ca.crt".into(), i.ca_crt),
        ("node.crt".into(), i.node_crt),
        ("node.key".into(), i.node_key),
        // The fleet signing PUBLIC key, as a rail bundle's `signing-pub`
        // carries it. Without it the controller's own node never holds the
        // key, `signing-adopted` is never true for it, and a fresh box's
        // `noo cluster verify` asks the operator to provision their own
        // controller (i276).
        ("signing-pub".into(), i.signing_pub),
    ];
    v.extend(i.leaves);
    v.push(("agent-env".into(), i.agent_env));
    v.push(("nats-creds".into(), i.nats_creds));
    v.push(("agent-binary".into(), i.agent_binary));
    v.push(("agent-unit".into(), i.agent_unit));
    v.push(("secret-files".into(), i.secret_files_script));
    Ok(v)
}

fn parse_lane_state(s: &str) -> BTreeMap<String, String> {
    s.lines().filter_map(|l| l.split_once(' '))
        .map(|(k, d)| (k.trim().to_string(), d.trim().to_string()))
        .filter(|(k, d)| !k.is_empty() && !d.is_empty())
        .collect()
}

fn render_lane_state(staged: &[(String, Vec<u8>)]) -> String {
    staged.iter().map(|(k, b)| format!("{k} {}\n", sha256_hex(b))).collect()
}

/// Kinds whose staged digest differs from the recorded (or installed) one.
fn changed_kinds(staged: &[(String, Vec<u8>)], recorded: &BTreeMap<String, String>) -> std::collections::BTreeSet<String> {
    staged.iter()
        .filter(|(k, b)| recorded.get(k) != Some(&sha256_hex(b)))
        .map(|(k, _)| k.clone())
        .collect()
}

/// `nats_pair_ok ENV USER` — the env names USER and a non-empty password,
/// plain or behind a readable `_FILE` pointer (the secret-files layout).
const NATS_PAIR_CHECK: &str = r#"nats_pair_ok() {
    _np_v() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1 | tr -d '\015' | sed -e 's/^"\(.*\)"$/\1/'; }
    [ "$(_np_v "$1" NATS_NODE_USER)" = "$2" ] || return 1
    [ -n "$(_np_v "$1" NATS_NODE_PASSWORD)" ] && return 0
    _np_f="$(_np_v "$1" NATS_NODE_PASSWORD_FILE)"
    [ -n "$_np_f" ] && [ -s "$_np_f" ]
}
"#;

struct LocalScript<'a> {
    node: &'a str,
    work: &'a Path,
    changed: &'a std::collections::BTreeSet<String>,
    prep: Option<&'a str>,
    secret_files: &'a str,
    leaves: &'a [String],
    restart: bool,
}

/// The one root script: host prep when it is not current, then only the
/// pieces that changed, the secret-files conversion, the NATS pair check
/// (fail loud, before any restart), and a restart only when needed.
fn local_install_script(s: &LocalScript) -> String {
    let (node, w) = (s.node, s.work.display());
    let ch = |k: &str| s.changed.contains(k);
    let mut out = String::from("set -e\n");
    if let Some(p) = s.prep {
        // The node identity with prep: a birth keypair when the box has none,
        // prep (installs it, arms the pull timer), the gateway's read-only
        // copy of the cert. Never fatal: without it the pull units stay
        // unarmed and `noo cluster verify` says so.
        out.push_str(&self_identity_script(node, s.work, Path::new("/etc/noo"), p));
    }
    if ch("ca.crt") || ch("node.crt") || ch("node.key") {
        out.push_str(&format!(
            "install -d -m 750 -o root -g noo-agent /etc/noo/pki /etc/noo/pki/nodes \"/etc/noo/pki/nodes/{node}\" 2>/dev/null   || install -d -m 755 /etc/noo/pki \"/etc/noo/pki/nodes/{node}\"\n\
             grp=noo-agent; getent group noo-agent >/dev/null || grp=root\n"));
        if ch("ca.crt") {
            out.push_str(&format!("install -m 640 -o root -g \"$grp\" \"{w}/ca.crt\"   /etc/noo/pki/ca.crt.new && mv /etc/noo/pki/ca.crt.new /etc/noo/pki/ca.crt\n"));
        }
        if ch("node.crt") {
            out.push_str(&format!("install -m 640 -o root -g \"$grp\" \"{w}/node.crt\" \"/etc/noo/pki/nodes/{node}/node.crt\"\n"));
        }
        if ch("node.key") {
            out.push_str(&format!("install -m 640 -o root -g \"$grp\" \"{w}/node.key\" \"/etc/noo/pki/nodes/{node}/node.key\"\n"));
        }
    }
    if ch("signing-pub") {
        // As noo-apply installs it: 0644, root, group noo-agent (root when
        // the account does not exist).
        out.push_str(&format!(
            "grp=noo-agent; getent group noo-agent >/dev/null || grp=root\n\
             [ -d /etc/noo/pki ] || install -d -m 750 -o root -g \"$grp\" /etc/noo/pki\n\
             install -m 644 -o root -g \"$grp\" \"{w}/signing-pub\" /etc/noo/pki/signing.pub\n"));
    }
    // Staged under their bundle kind names; each pair installed the way
    // noo-apply does (root, key 0600, cert 0644, temp + rename).
    for l in super::node_leaves::NODE_DOOR_LEAVES {
        if !s.leaves.iter().any(|k| k == l.crt_kind) || !(ch(l.crt_kind) || ch(l.key_kind)) {
            continue;
        }
        out.push_str(&format!(
            "install -d -m 755 -o root -g root /etc/noo/pki/services /etc/noo/pki/services/{s}\n\
             install -m 600 -o root -g root \"{w}/{k}\" /etc/noo/pki/services/{s}/.service.key.next\n\
             install -m 644 -o root -g root \"{w}/{c}\" /etc/noo/pki/services/{s}/.service.crt.next\n\
             mv -f /etc/noo/pki/services/{s}/.service.key.next /etc/noo/pki/services/{s}/service.key\n\
             mv -f /etc/noo/pki/services/{s}/.service.crt.next /etc/noo/pki/services/{s}/service.crt\n",
            s = l.service, k = l.key_kind, c = l.crt_kind));
    }
    if ch("agent-env") || ch("nats-creds") || ch("secret-files") {
        // agent-env replaces the env whole, then nats-creds is merged in
        // exactly as noo-apply merges it on the rail.
        out.push_str(&format!(
            "install -m 600 -o root -g root \"{w}/agent-env\" /etc/noo-node-agent.env\n\
             nc_tmp=\"$(mktemp)\"; chmod 600 \"$nc_tmp\"\n\
             grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD|NATS_NODE_PASSWORD_FILE)=' /etc/noo-node-agent.env > \"$nc_tmp\" || true\n\
             grep -E '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' \"{w}/nats-creds\" >> \"$nc_tmp\"\n\
             install -m 600 -o root -g root \"$nc_tmp\" /etc/noo-node-agent.env; rm -f \"$nc_tmp\"\n"));
    }
    if ch("agent-binary") {
        out.push_str(&format!("install -m 755 \"{w}/agent-binary\" /usr/local/bin/noo-node-agent\n"));
    }
    if ch("agent-unit") {
        out.push_str(&format!(
            "install -m 644 \"{w}/agent-unit\" /etc/systemd/system/noo-node-agent.service\n\
             getent passwd noo-agent >/dev/null || sed -i 's/^User=noo-agent/User=root/' /etc/systemd/system/noo-node-agent.service\n\
             systemctl daemon-reload\n\
             systemctl enable noo-node-agent\n"));
    }
    out.push_str(s.secret_files);
    out.push_str(NATS_PAIR_CHECK);
    out.push_str(&format!(
        "nats_pair_ok /etc/noo-node-agent.env 'node-{node}' || {{ echo \"first install: /etc/noo-node-agent.env holds no NATS pair for node-{node} — the agent was not restarted\" >&2; exit {NATS_PAIR_MISSING_EXIT}; }}\n"));
    if s.restart {
        // restart, not `enable --now`: `--now` is a NO-OP on an already-running
        // unit, so a surviving agent from a previous install kept its STALE
        // process env (old controller URLs) forever while the rewritten env
        // file sat unread.
        out.push_str("systemctl restart noo-node-agent\n");
    }
    out
}

/// Returns `Err` instead of exiting: its only caller is onboard, which warns
/// and goes on with the rest of the services step (hostd, placement, the
/// embed model, …) rather than stopping at exit 1.
pub fn provision_local(g: &Globals, node: &str, tier: Option<&str>) -> Result<i32, String> {
    provision_local_in(g, node, tier, &crate::envfile::repo_root(), &crate::pki::pki_dir())
}

/// [`provision_local`] over an explicit install root and PKI dir (tests).
fn provision_local_in(g: &Globals, node: &str, tier: Option<&str>, root: &Path, pki: &Path) -> Result<i32, String> {
    let (root, pki) = (root.to_path_buf(), pki.to_path_buf());

    // Facts from the machine itself.
    let goarch = match std::env::consts::ARCH { "aarch64" => "arm64", _ => "amd64" };
    // Process env first (a provisioner may pin it), then the install's own
    // .env (the wizard's storage step wrote it there), and only then the
    // bare default — which on 2026-09-07 sent the controller's self-agent
    // to /data/noo while every volume lived on the chosen drive.
    let data_root = local_data_root(&root);
    let tier = tier.map(str::to_string).unwrap_or_else(|| {
        let gpu = Command::new("nvidia-smi").output().map(|o| o.status.success()).unwrap_or(false);
        if gpu { "2".into() } else { "3".into() }
    });

    // Prep (idempotent): noo-agent account, /etc/noo, gate tooling. The
    // gateway serves the tool downloads, so it should be up; prep tolerates
    // fetch failures with warnings.
    let ctrl_host = controller_dnsname().unwrap_or_else(|| "localhost".into());
    // The embedded copy (enroll::asset_prep), staged to a 0700 temp file — a
    // dist controller has no scripts/ tree, and this used to be an
    // `if prep.exists()` that skipped host prep SILENTLY there, so provision
    // went on to bundle a node whose controller-side prep never ran.
    let (prep, _prep_guard) = stage_prep_host(&root).map_err(|e| format!(
        "{e} — install a released noo binary (it embeds prep-host.sh) or run from a checkout"))?;
    // Host prep runs inside the ONE sudo script below, and only when the
    // marker it last wrote does not name this prep, these inputs and this
    // release — or a pull unit is missing (prep is what installs them).
    let user = std::env::var("USER").unwrap_or_default();
    let prep_release = format!("{}/{}", env!("CARGO_PKG_VERSION"), image_tag());
    let prep_sha = std::fs::read(&prep).map(|b| sha256_hex(&b)).unwrap_or_default();
    let prep_url = format!("https://{ctrl_host}:8080");
    let prep_current = std::fs::read_to_string(LOCAL_PREP_MARKER).map(|m| prep_marker_current(&m, &[
        ("PREP_SHA256", prep_sha.as_str()),
        ("NOO_DATA_ROOT", data_root.as_str()),
        ("ENROLL_USER", user.as_str()),
        ("PREP_NODE_NAME", node),
        ("PREP_NOO_URL", prep_url.as_str()),
        ("PREP_RELEASE", prep_release.as_str()),
    ])).unwrap_or(false);
    let units_missing = pull_units_missing(node);
    // The private staging dir, named up front: prep reads the birth keypair
    // the install script generates into it.
    let work = std::env::temp_dir().join(format!("noo-selfprov-{}", std::process::id()));
    let prep_cmd = if prep_current && units_missing.is_empty() {
        None
    } else {
        Some(self_prep_line(node, &prep, &data_root, &work)?)
    };

    // Certs must exist in the local PKI (the wizard's security step issues
    // the node cert for this hostname; issue-node covers a differing name).
    //
    // i11a: and they must carry the controller names. Absence was the only
    // test, so a cert that had lost them (a re-issue from another path)
    // stayed broken through every `noo upgrade`. Coverage is the test now,
    // which makes this lane, and therefore `noo upgrade`, the repair.
    let node_crt = pki.join("nodes").join(node).join("node.crt");
    let role = crate::pki::NodeRole::of(node);
    let reason = if !pki.join("nodes").join(node).join("node.key").exists() || !node_crt.exists() {
        Some(format!("issuing a cert for {node} into the local PKI"))
    } else if !crate::pki::ClusterCa::cert_covers_sans(&node_crt, role.required_dns(), &[]) {
        Some(format!("{node}'s cert lacks the controller names ({}) — re-issuing", role.required_dns().join(", ")))
    } else {
        None
    };
    if let Some(why) = reason {
        nstep(&why);
        // --mint-only for the same reason as the site above: the bundle
        // delivers these certs, and there is no agent yet to confirm.
        // The address is this box's own LAN address, as onboarding issues
        // it: without one the issuer would look the node NAME up on the
        // tailnet, which for a controller answers with another device.
        // Issued directly (not through the `pki issue-node` verb, which
        // exits on failure): an error here returns to onboard.
        let ca = crate::pki::ClusterCa::new(pki.clone());
        if !ca.ca_exists() {
            return Err("no cluster CA found — run `noo onboard --only security` first".into());
        }
        let ts_ip: Vec<String> = role.tailnet_ip4(node).into_iter().collect();
        ca.issue_node_cert(node, &crate::onboard::util::detect_ip(), crate::pki::DEFAULT_DAYS,
                &["node-agent".to_string()], &ts_ip, &role)
            .map_err(|e| format!("could not issue a cert for {node}: {e}"))?;
    }

    // The self-node's backend doors need their leaves exactly as a remote
    // node's do; the same node-scoped issue, installed by
    // the same sudo script below instead of a bundle.
    let leaf_ca = crate::pki::ClusterCa::new(pki.clone());
    ensure_door_leaves_try(&leaf_ca, node)?;

    leaf_ca.ensure_signing_key().map_err(|e| format!("could not read or mint the fleet signing key: {e}"))?;
    let signing_pub = read_or_fail_path(&leaf_ca.signing_pub_path())?;
    let creds = sops_credentials(&root)?;
    nstep(&format!("obtaining noo-node-agent ({goarch})"));
    let binary = obtain_agent_binary(&root, goarch).map_err(|e| format!(
        "{e} — is docker logged in to the registry, and NOO_IMAGE_TAG set?"))?;

    let tmpl = std::fs::read_to_string(root.join("node-agent-go/deploy/noo-node-agent.env.tmpl"))
        .map_err(|e| format!("cannot read the agent env template ({e})"))?;
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("na_node_id", node.to_string());
    vars.insert("node_ip", String::new());
    vars.insert("node_tier", tier.clone());
    vars.insert("gpu_model", String::new());
    vars.insert("controller_url", format!("https://{ctrl_host}:8080"));
    vars.insert("nats_url", format!("tls://{ctrl_host}:4222"));
    vars.insert("noo_node_agent_token", creds.agent_token);
    vars.insert("noo_cluster_secret", creds.cluster_secret);
    vars.insert("noo_pki_dir", String::from("/etc/noo/pki"));
    vars.insert("na_tls_ca", String::from("/etc/noo/pki/ca.crt"));
    vars.insert("na_tls_cert", format!("/etc/noo/pki/nodes/{node}/node.crt"));
    vars.insert("na_tls_key", format!("/etc/noo/pki/nodes/{node}/node.key"));
    vars.insert("noo_mtls_nodes", String::new());
    // No noo_*_tls vars: the per-backend TLS switches are retired and the
    // template no longer carries them (the agent REFUSES a false value).
    // The controller's own agent has no compose DNS; on a standalone install
    // the embed container is the only ollama and compose publishes its
    // mTLS door (stunnel-ollama-embed, verify = 2) on 127.0.0.1:11434 for
    // exactly this reader (a job dispatched to the controller died on
    // "lookup stunnel-ollama" until the publish moved from the plaintext
    // container to the door).
    // The controller's own node adopts the stack's ollama instead of
    // starting a second one on the same GPU: NOO_SELF_NODE turns on the
    // agent's "stack" lane, and OLLAMA_URL is where that lane looks —
    // https once the stack declares the door (self_node_ollama_url).
    let self_node = crate::role::is_self_node(node);
    vars.insert("noo_self_node", if self_node { "1".to_string() } else { String::new() });
    vars.insert("ollama_url", if self_node || root.join(".noo-standalone").is_file() {
        self_node_ollama_url(&root)
    } else {
        String::new()
    });
    vars.insert("noo_data_root", data_root.clone());
    vars.insert("hf_cache_dir", format!("{data_root}/hf-cache"));
    vars.insert("models_dir", format!("{data_root}/models"));
    vars.insert("ollama_data_dir", format!("{data_root}/ollama"));
    vars.insert("noo_model_cache_url", format!("https://{ctrl_host}:8443"));
    // Release identity, so the agent resolves PUBLISHED backend images
    // rather than local build names (see the template comment).
    vars.insert("noo_image_prefix", image_prefix());
    vars.insert("noo_image_tag", image_tag());
    vars.insert("noo_force_gpu", String::new());
    vars.insert("noo_ollama_gpu_count", String::new());
    vars.insert("node_agent_port", String::from("8081"));
    vars.insert("log_level", String::from("info"));
    let agent_bind = cluster_trust_bind()?;
    vars.insert("node_agent_bind", agent_bind);
    let env_body = render_env_template(&tmpl, &vars)?;

    // ── the controller's own NATS credential ──────────────
    // The same source of truth and the same bundle kind as the rail lane
    // (node_credential_payload): this lane used to install agent-env whole
    // and carry no `nats-creds`, so every `noo upgrade --nodes` dropped the
    // controller agent's bus pair while it still registered over HTTP.
    // REQUIRED, as on the rail: nothing is installed without it.
    let nats_creds = super::nats_users::node_credential_payload(&root, node).map_err(|e| format!(
        "could not mint {node}'s own NATS credential ({e}) — the agent has no other bus credential, \
         so nothing was installed; check the secret store (`noo security secrets audit`), then re-run \
         `noo onboard --only services`"))?;

    let (leaves, _) = super::node_leaves::leaf_payloads(&leaf_ca, node)?;
    let read_or_fail = |p: std::path::PathBuf| std::fs::read(&p)
        .map_err(|e| format!("{}: {e}", p.display()));
    let asf = local_agent_secret_files_script(super::enroll::asset_apply());
    let staged = local_bundle(node, LocalInputs {
        signing_pub: signing_pub.clone(),
        agent_env: env_body.into_bytes(),
        nats_creds,
        agent_binary: binary,
        agent_unit: read_or_fail(root.join("node-agent-go/deploy/noo-node-agent.service"))?,
        ca_crt: read_or_fail(pki.join("ca.crt"))?,
        node_crt: read_or_fail(pki.join(format!("nodes/{node}/node.crt")))?,
        node_key: read_or_fail(pki.join(format!("nodes/{node}/node.key")))?,
        leaves: leaves.iter().map(|(k, b)| (k.to_string(), b.clone())).collect(),
        secret_files_script: asf.clone().into_bytes(),
    })?;

    // What changed since this lane last installed successfully: the state
    // file (kind → sha256, in the operator's own PKI dir beside node.key)
    // for what root keeps unreadable, the installed binary itself for the
    // binary. Nothing changed, prep current and the agent running → no sudo.
    let state_path = pki.join("nodes").join(node).join(LOCAL_LANE_STATE);
    let mut recorded = parse_lane_state(&std::fs::read_to_string(&state_path).unwrap_or_default());
    match std::fs::read(LOCAL_AGENT_BIN) {
        Ok(b) => { recorded.insert("agent-binary".into(), sha256_hex(&b)); }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { recorded.remove("agent-binary"); }
        Err(_) => {}
    }
    let changed = changed_kinds(&staged, &recorded);
    let active = Command::new("systemctl").args(["is-active", "--quiet", "noo-node-agent"])
        .status().map(|s| s.success()).unwrap_or(false);
    let needs_nats_render = changed.contains("nats-creds");

    if prep_cmd.is_none() && changed.is_empty() && active {
        nstep("host agent, certs and credential are current; host prep is current — nothing to install (no sudo)");
    } else {
        if needs_nats_render {
            match super::nats_users::render_all(g, &[node.to_string()]) {
                Ok(out) => {
                    let reloaded = super::nats_users::hup_nats();
                    nnote(&format!("bundle carries this node's own NATS credential; {} users rendered{}",
                        out.users, if reloaded { " and noo-nats reloaded" } else { " (reload noo-nats: docker kill -s HUP noo-nats)" }));
                }
                Err(e) => nnote(&format!(
                    "node credential minted but users.conf did not re-render ({e}) — the agent \
                     retries auth until `noo cluster nats-users render` (then \
                     `docker kill -s HUP noo-nats`) accepts node-{node}")),
            }
        }
        // Stage in a private dir, install what changed with ONE sudo script,
        // scrub the staged secrets either way.
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).map_err(|e| format!("cannot stage {} ({e})", work.display()))?;
        let _ = std::fs::set_permissions(&work, {
            use std::os::unix::fs::PermissionsExt; std::fs::Permissions::from_mode(0o700)
        });
        for (kind, bytes) in &staged {
            if kind == "secret-files" { continue; }
            if let Err(e) = std::fs::write(work.join(kind), bytes) {
                let _ = std::fs::remove_dir_all(&work);
                return Err(format!("cannot stage {kind} ({e})"));
            }
        }
        let what: Vec<&str> = changed.iter().map(String::as_str).collect();
        nstep(&format!("installing the host agent (one sudo, the first install){}{}",
            if prep_cmd.is_some() { "; host prep and the pull units" } else { "" },
            if what.is_empty() { String::new() } else { format!("; changed: {}", what.join(", ")) }));
        let script = local_install_script(&LocalScript {
            node, work: &work, changed: &changed, prep: prep_cmd.as_deref(), secret_files: &asf,
            leaves: &leaves.iter().map(|(k, _)| k.to_string()).collect::<Vec<_>>(),
            restart: !changed.is_empty() || !active,
        });
        let code = Command::new("sudo").args(["sh", "-c", &script])
            .status().ok().and_then(|s| s.code());
        // Scrub the staged secrets regardless of outcome.
        for staged_kind in ["agent-env", "nats-creds", "node.key"].into_iter()
            .chain(leaves.iter().map(|(k, _)| *k).filter(|k| k.ends_with(".key")))
        {
            let p = work.join(staged_kind);
            if let Ok(m) = std::fs::metadata(&p) { let _ = std::fs::write(&p, vec![0u8; m.len() as usize]); }
        }
        let _ = std::fs::remove_dir_all(&work);
        match code {
            Some(0) => {}
            Some(NATS_PAIR_MISSING_EXIT) => return Err(format!(
                "{node}'s agent env holds no NATS pair after the install — the agent would register \
                 over HTTP with no bus connection; it was NOT restarted (`noo cluster nats-creds rotate {node}`)")),
            _ => return Err("local agent install failed (see output above)".into()),
        }
        // Recorded only after a successful install whose env presented a pair.
        let body = render_lane_state(&staged);
        let wrote = {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp = state_path.with_extension("next");
            let _ = std::fs::remove_file(&tmp);
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
                .and_then(|mut f| f.write_all(body.as_bytes()))
                .and_then(|_| std::fs::rename(&tmp, &state_path))
        };
        if let Err(e) = wrote {
            nnote(&format!("could not record {} ({e}) — the next run reinstalls everything", state_path.display()));
        }
    }
    // Reaching here means the root install exited 0 (or a previous run's
    // record says this exact key is already there): this node HOLDS the
    // current signing key, which is what the marker means.
    mark_signing_adopted(&leaf_ca, node, &signing_pub);
    write_self_lane(node, SelfLaneRecord::Onboard);
    // The rail from here on: the gateway reads the birth cert from the
    // PKI's certificate-only view, which the CLI keeps (no sudo).
    match pull_units_missing(node) {
        missing if !missing.is_empty() => nnote(&format!(
            "the pull units are still missing ({}) — upgrades cannot reach this node until `{SELF_RAIL_REMEDY}` installs them",
            missing.join(", "))),
        _ => match sync_self_birth_cert(&pki, node, Path::new(SELF_BIRTH_CRT)) {
            Ok(_) => nnote("node identity and pull units in place — upgrades of this node ride the rail (no sudo)"),
            Err(e) => nnote(&format!("pull units in place; the gateway's view of the birth cert is not ({e}) — the next `noo cluster provision {node}` puts it there")),
        },
    }

    nstep(&format!("waiting for {node} to register on the mesh"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut online = false;
    let mut auth_blind = false;
    while std::time::Instant::now() < deadline {
        // Best-effort (the #48 doctrine): a VERIFICATION poll must not die
        // on a blip — and post-#32b there may be NO credential at all when
        // the auto-login failed (finding #102: this wait exited fatal-401
        // right after a successful agent install). No credential = we
        // cannot VERIFY; that is not the same as "not registered".
        let Some(doc) = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10) else {
            auth_blind = crate::auth::bearer(g).is_none();
            if auth_blind {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            continue;
        };
        // "id" FIRST (finding #78): node_register_body stores the KV entry
        // with "id" — the old node_id/name matchers could NEVER see a
        // freshly-registered node, so every wait this campaign reported
        // "not registered yet" about nodes that had registered in seconds.
        if doc.get("nodes").and_then(|n| n.as_array()).map(|arr| arr.iter().any(|nd| {
            nd.get("id").and_then(|v| v.as_str())
                        .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                .or_else(|| nd.get("name").and_then(|v| v.as_str()))
                .is_some_and(|id| id.eq_ignore_ascii_case(node))
        })).unwrap_or(false) { online = true; break; }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    if g.json {
        println!("{}", serde_json::json!({"status": if online {"provisioned"} else {"installed"},
            "node": node, "transport": "local", "tier": tier, "arch": goarch}));
    } else if online {
        ui::done(&format!("{node}: self-agent installed and registered (tier {tier}, {goarch})"));
    } else if auth_blind {
        ui::warned(&format!("{node}: self-agent installed — registration NOT VERIFIED (no CLI credential; the earlier login failed)"));
        println!("  {}", ui::muted("the agent is likely fine — verify after logging in"));
        ui::guide(&[
            ("noo auth login", "get a CLI credential"),
            ("noo cluster status", "then confirm the node registered"),
        ]);
    } else {
        // Not a success — don't dress it as one (finding #69: the ✓ here
        // buried the one unfinished meter of an otherwise-green onboard).
        ui::warned(&format!("{node}: self-agent installed but NOT yet on the mesh (90s wait elapsed)"));
        println!("  {}", ui::muted("it usually registers moments later"));
        ui::guide(&[
            ("noo cluster status", "re-check in a moment"),
            ("journalctl -u noo-node-agent -n 30", "if it stays absent, the agent log names the cause"),
        ]);
    }
    Ok(0)
}

/// Does this agent binary carry `tag` as its stamped version?
///
/// `internal/version.Version` is injected with -ldflags, so a correctly-built
/// binary contains the tag as a literal byte string. A scan is enough: the
/// question asked is "is this definitely NOT that build", and absence answers
/// it conclusively. A coincidental match cannot make a WRONG binary pass as a
/// right one, because the wrong binary carries a different tag.
///
/// Only meaningful for image-extracted binaries. A source cross-build stamps
/// "dev" by design, and that is a useful signal rather than a failure, so the
/// caller does not apply this to that path.
fn binary_carries_version(bin: &[u8], tag: &str) -> bool {
    if tag.is_empty() {
        return false;
    }
    bin.windows(tag.len()).any(|w| w == tag.as_bytes())
}

/// The agent binary for the node's arch. Primary: extract from the multi-arch
/// GHCR node-agent image (no Go, no repo — the standalone path). Fallback:
/// cross-compile from the source tree when it exists (dev checkouts testing
/// unreleased agents).
fn obtain_agent_binary(root: &Path, goarch: &str) -> Result<Vec<u8>, String> {
    // image_tag(), NOT std::env::var — and this is the whole bug.
    //
    // `ensure_repo_env()` loads .env into the PROCESS environment at CLI
    // startup, NOO_IMAGE_TAG included. Within one `noo upgrade --all` that
    // copy is the tag from BEFORE the upgrade: the stack stage rolls forward
    // and the launcher rewrites .env, but the nodes stage runs in the same
    // process and still holds the old value. So the bundle carried the
    // PREVIOUS release's agent, every time.
    //
    // Live on 2026-09-05: the stack rolled to v0.2.23, .env said v0.2.23, the
    // only node-agent image on the controller was v0.2.22, and all four nodes
    // reported stack-v0.2.22 after applying exit 0. Three node-agent fixes
    // shipped in that release and reached nothing.
    //
    // image_tag() re-reads .env at call time, so it sees what the stack stage
    // just wrote.
    let prefix = image_prefix();
    let tag = image_tag();
    let image_err = if !prefix.is_empty() && !tag.is_empty() {
        let image = format!("{prefix}/node-agent:{tag}");
        match extract_from_image(&image, goarch) {
            Ok(b) => {
                // Compare what came OUT against what was asked for.
                //
                // The rail verified a CA signature, installed this binary and
                // reported exit 0 — all true statements about a binary that
                // was a release out of date. Nothing compared delivered
                // against intended, so three node-agent fixes shipped in
                // stack-v0.2.23 and reached no node (2026-09-05).
                //
                // The version is baked in by -ldflags (internal/version), so
                // the tag is literally present in a correctly-built binary.
                // Absence is conclusive: this is not that build.
                if !binary_carries_version(&b, &tag) {
                    return Err(format!(
                        "{image} yielded an agent binary that does not carry {tag}. \
                         The bundle would install an agent from a different release \
                         and report success — refusing. Check `docker images {prefix}/node-agent` \
                         and re-pull the tag."));
                }
                return Ok(b);
            }
            Err(e) => e, // fall through to the source-tree fallback
        }
    } else {
        "NOO_IMAGE_PREFIX/NOO_IMAGE_TAG unset (no released image to extract from)".to_string()
    };

    let src = root.join("node-agent-go");
    if src.join("build-cross.sh").exists() {
        println!("  {}", ui::muted(&format!("image extract unavailable ({image_err}); cross-compiling from source")));
        let ok = Command::new("bash").arg(src.join("build-cross.sh"))
            .arg(format!("linux/{goarch}"))
            .current_dir(&src)
            .status().map(|s| s.success()).unwrap_or(false);
        if !ok { return Err("build-cross.sh failed".into()); }
        return std::fs::read(src.join(format!("noo-node-agent-{goarch}")))
            .map_err(|e| format!("cross-compiled binary missing: {e}"));
    }
    Err(format!("cannot obtain the agent binary: {image_err}, and no source tree to build from"))
}

/// `docker create --platform linux/<arch>` + `docker cp` of the agent binary.
/// Static Go binary at a fixed path (docker/Dockerfile.node-agent-go); verified
/// live 2026-08-19: the released image yields a static aarch64 ELF (~8.9MB)
/// on an x86 controller.
///
/// LANDMINE (found on that live smoke): a cross-arch `docker pull --platform`
/// REPOINTS the controller's local tag at the foreign-arch variant — a later
/// recreate of the controller's OWN node-agent from that tag would
/// exec-format-error. So when the target arch differs from the host's, the
/// native manifest is re-pulled afterwards, on every exit path.
fn extract_from_image(image: &str, goarch: &str) -> Result<Vec<u8>, String> {
    let host_goarch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let result = extract_from_image_inner(image, goarch);
    if goarch != host_goarch {
        let restored = Command::new("docker")
            .args(["pull", "--platform", &format!("linux/{host_goarch}"), image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false);
        if !restored {
            ui::warned(&format!("could not restore the {host_goarch} manifest for {image} — \
                       the local tag may point at the {goarch} variant"));
            ui::guide(&[(&format!("docker pull --platform linux/{host_goarch} {image}"), "restores the host-arch manifest")]);
        }
    }
    result
}

fn extract_from_image_inner(image: &str, goarch: &str) -> Result<Vec<u8>, String> {
    let platform = format!("linux/{goarch}");
    // Pull (or confirm) the arch-specific manifest. Quiet on success.
    let pull = Command::new("docker")
        .args(["pull", "--platform", &platform, image])
        .output().map_err(|e| format!("docker: {e}"))?;
    if !pull.status.success() {
        return Err(format!("docker pull {image} ({platform}) failed: {}",
            String::from_utf8_lossy(&pull.stderr).lines().last().unwrap_or("")));
    }
    let create = Command::new("docker")
        .args(["create", "--platform", &platform, image])
        .output().map_err(|e| format!("docker: {e}"))?;
    if !create.status.success() {
        return Err(format!("docker create failed: {}",
            String::from_utf8_lossy(&create.stderr).lines().last().unwrap_or("")));
    }
    let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();
    let tmp = std::env::temp_dir().join(format!("noo-agent-extract-{}", std::process::id()));
    // `.output()`, not `.status()`: docker cp chats ("Successfully copied
    // 9.58MB …") on stdout, and subprocess output is ours to frame (§5).
    let cp_ok = Command::new("docker")
        .args(["cp", &format!("{cid}:/usr/local/bin/noo-node-agent")])
        .arg(&tmp)
        .output().map(|o| o.status.success()).unwrap_or(false);
    let _ = Command::new("docker").args(["rm", "-f", &cid])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    if !cp_ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("docker cp of /usr/local/bin/noo-node-agent failed".into());
    }
    let bytes = std::fs::read(&tmp).map_err(|e| format!("read extracted binary: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    if bytes.len() < 1_000_000 {
        return Err(format!("extracted binary suspiciously small ({} bytes)", bytes.len()));
    }
    Ok(bytes)
}

/// Render the REAL agent env template (single source of truth — porting it
/// to a Rust format string is the exact drift class the template itself warns
/// about). Supported subset, verified against noo-node-agent.env.j2:
///   {# … #}            stripped (multi-line)
///   {% if … %}/{% endif %}  kept/stripped by the one known condition
///                            (noo_pki_dir defined+non-empty)
///   {{ var }} / {{ var | default(…) }}  substituted from `vars`
/// Every referenced var MUST be in `vars` — defaults are never evaluated, and
/// an unknown var is an error, so a template edit that adds a value the CLI
/// doesn't supply fails loudly instead of shipping an empty credential.
fn render_env_template(tmpl: &str, vars: &BTreeMap<&str, String>) -> Result<String, String> {
    // Strip {# … #} comments (multi-line).
    let mut s = String::with_capacity(tmpl.len());
    let mut rest = tmpl;
    while let Some(start) = rest.find("{#") {
        s.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("#}") else {
            return Err("unterminated {# comment in template".into());
        };
        rest = &rest[start + end + 2..];
    }
    s.push_str(rest);

    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("{%") {
            // The template's only control flow: `if noo_pki_dir is defined
            // and non-empty` — true here (we always set it) — and its endif.
            if t.contains("endif") { continue; }
            if t.contains("if") && t.contains("noo_pki_dir") {
                let on = vars.get("noo_pki_dir").is_some_and(|v| !v.is_empty());
                if !on {
                    return Err("template if-branch for noo_pki_dir is off — unsupported".into());
                }
                continue;
            }
            return Err(format!("unsupported template tag: {t}"));
        }
        let mut lrest = line;
        while let Some(start) = lrest.find("{{") {
            out.push_str(&lrest[..start]);
            let Some(end_rel) = lrest[start..].find("}}") else {
                return Err(format!("unterminated {{{{ in line: {line}"));
            };
            let expr = &lrest[start + 2..start + end_rel];
            let var = expr.split(['|', ' ']).find(|s| !s.is_empty())
                .ok_or_else(|| format!("empty expression in line: {line}"))?
                .trim();
            let val = vars.get(var).ok_or_else(|| format!(
                "template references '{var}' which `noo cluster provision <node>` does not supply — \
                 add it to the vars map (this guard exists so a template edit cannot \
                 silently ship an empty value)"))?;
            out.push_str(val);
            lrest = &lrest[start + end_rel + 2..];
        }
        out.push_str(lrest);
        out.push('\n');
    }
    Ok(out)
}

/// Encrypt the signed bundle to the node's birth cert (CMS/SMIME, DER) —
/// the format noo-fetch decrypts with `openssl smime -decrypt -inform DER`.
/// CMS handles the hybrid (RSA-wrapped session key + AES) so neither end
/// hand-rolls crypto; integrity/authenticity remain the CA signature INSIDE
/// the plaintext, which noo-apply verifies after decryption.
/// The cert a pulled bundle is encrypted to: for the controller's own node
/// the local `/etc/noo/birth.crt`, and the enrollment record is NOT consulted
/// (i11a: it may belong to another machine); for any other node, its record.
pub(crate) fn pull_target_cert(
    is_self: bool,
    local: impl FnOnce() -> Option<String>,
    record: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if is_self { local() } else { record() }
}

/// PULL delivery for a teardown directive (finding #52): encrypt the
/// signed bundle to the node's birth cert and stage it at the gateway —
/// the node's fetch timer collects and applies it, exactly like birth.
/// None = node has no birth cert on record (pre-pull enrollment; caller
/// falls back to the gate lane). Some(Err) = pull-capable but staging
/// failed.
pub(crate) fn stage_bundle_pull(
    g: &Globals,
    node: &str,
    bundle: &std::path::Path,
    work: &std::path::Path,
) -> Option<Result<(), String>> {
    // The controller's own node: its birth cert is on THIS disk (i67), never
    // taken from an enrollment record under its name (i11a).
    let is_self = crate::role::is_self_node(node) && crate::role::detect().controller.is_some();
    let cert = pull_target_cert(is_self,
        || std::fs::read_to_string(SELF_BIRTH_CRT).ok(),
        || redemption_record(g, node).and_then(|r| r.birth_cert))?;
    Some(
        encrypt_bundle_cms(bundle, &cert, work)
            .and_then(|blob| post_bytes(g, &format!("/api/cluster/provision-bundle/{node}"), &blob)),
    )
}


pub(crate) fn encrypt_bundle_cms(bundle: &Path, cert_pem: &str, work: &Path) -> Result<Vec<u8>, String> {
    let cert_path = work.join("birth.crt");
    std::fs::write(&cert_path, cert_pem).map_err(|e| e.to_string())?;
    let out = work.join("bundle.der");
    let ok = Command::new("openssl")
        .args(["smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER", "-in"])
        .arg(bundle)
        .arg("-out").arg(&out)
        .arg(&cert_path)
        .status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return Err("openssl smime -encrypt failed".into());
    }
    std::fs::read(&out).map_err(|e| e.to_string())
}

/// The first CLI release whose fetcher (`noo-fetch.sh` on Linux, `noo node
/// fetch` on macOS) unwraps a gzip-compressed bundle after decrypting it.
/// A guard test pins it; read that test's comment before changing it.
const GZIP_BUNDLE_MIN_VERSION: (u32, u32, u32) = (0, 6, 5);

/// "noo-cli-v0.6.5+abc1234" -> (0, 6, 5); anything else -> None.
/// The release a node's fetcher came from, from the version its agent
/// reports. Three shapes are live: a Mac reports its CLI
/// (`noo-cli-v0.6.4+ff91728`), a Linux agent reports its stack tag
/// (`stack-v0.6.4+<40-hex>`), and a bare `v0.6.4` is accepted for builds
/// that report the tag alone. The stack tag stands for the fetcher on Linux
/// because the fetcher rides EVERY Linux bundle next to the agent binary, and
/// stack and CLI tags move in lock-step since 0.6.0, so an agent at stack
/// X.Y.Z was installed by a bundle that also installed fetcher X.Y.Z or newer.
/// Anything else (bare digits, a missing patch, a fourth field) is unreadable.
fn parse_cli_version(app_version: &str) -> Option<(u32, u32, u32)> {
    let v = app_version.trim();
    let rest = v.strip_prefix("noo-cli-v")
        .or_else(|| v.strip_prefix("stack-v"))
        .or_else(|| v.strip_prefix('v'))?;
    let nums: Vec<u32> = rest.split(['+', '-']).next()?.split('.').filter_map(|s| s.parse().ok()).collect();
    let [maj, min, pat] = nums[..] else { return None };
    Some((maj, min, pat))
}

/// May this node be sent a gzip-wrapped bundle? Ok(()) yes; Err(reason) no.
///
/// The FETCHER must decompress, and on Linux it runs before the applier can
/// self-update, so the applier's trick does not help. An old fetcher handed
/// gzip bytes passes them to `noo-apply`, which refuses "not a readable tar":
/// a wrong YES bricks the apply. So an unknown or unparseable version is NO
/// (the opposite default from `applier_knows_harness_kinds`).
pub(crate) fn bundle_gzip_gate(app_version: &str) -> Result<(), String> {
    let (a, b, c) = GZIP_BUNDLE_MIN_VERSION;
    match parse_cli_version(app_version) {
        None if app_version.is_empty() => Err("the node reports no CLI version, so its fetcher may predate gzip".into()),
        None => Err(format!("the node's version {app_version:?} is unreadable, so its fetcher may predate gzip")),
        Some(v) if v < GZIP_BUNDLE_MIN_VERSION =>
            Err(format!("{app_version} predates the gzip-aware fetcher (needs >= {a}.{b}.{c})")),
        Some(_) => Ok(()),
    }
}

/// gzip `bundle` (level 6, one member, no filename, mtime 0) into
/// `work/bundle.tar.gz`. The signed tar inside is untouched; the node's
/// fetcher restores it byte for byte. A failure is returned, never fatal:
/// the caller stages the uncompressed tar and says so.
pub(crate) fn gzip_bundle(bundle: &Path, work: &Path) -> Result<std::path::PathBuf, String> {
    use std::io::{Read, Write};
    let out = work.join("bundle.tar.gz");
    let mut src = std::fs::File::open(bundle).map_err(|e| format!("gzip: cannot read the bundle ({e})"))?;
    let dst = std::fs::File::create(&out).map_err(|e| format!("gzip: cannot write {} ({e})", out.display()))?;
    let mut enc = flate2::GzBuilder::new().mtime(0)
        .write(std::io::BufWriter::new(dst), flate2::Compression::new(6));
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = src.read(&mut buf).map_err(|e| format!("gzip: read failed ({e})"))?;
        if n == 0 { break; }
        enc.write_all(&buf[..n]).map_err(|e| format!("gzip: compress failed ({e})"))?;
    }
    enc.finish().and_then(|mut w| w.flush()).map_err(|e| format!("gzip: finish failed ({e})"))?;
    Ok(out)
}

/// POST raw bytes to a gateway path (the encrypted bundle — too large and
/// too binary for the JSON helpers). Same base-url/TLS posture as http.rs;
/// bearer from the standard resolution.
/// The release asset name for a node's platform, from its enrollment facts.
/// The gateway binary asset for a node's platform: what
/// the node runs as its harness.
///
/// Linux is the STATIC musl build. It used to be the glibc one, on the
/// theory that aws-lc-sys needed a toolchain the musl lanes lacked — which
/// made the RELEASE RUNNER's glibc a floor for every node. On 2026-09-19
/// that shipped a binary wanting GLIBC_2.38/2.39 to host3 (Ubuntu 22.04,
/// glibc 2.35): it could not exec, and systemd restarted it 300+ times.
/// aws-lc-sys builds fine under musl given cmake and a C toolchain. The
/// CLI asset beside it has always been static for this reason.
pub(crate) fn gateway_asset_for(os: &str, arch: &str) -> Option<String> {
    let arm = arch.starts_with("aarch64") || arch.starts_with("arm64");
    Some(match (os, arm) {
        ("macos", true) | ("darwin", true) => "noo-gateway-aarch64-apple-darwin".to_string(),
        ("linux", true) => "noo-gateway-aarch64-unknown-linux-musl".to_string(),
        ("linux", false) => "noo-gateway-x86_64-unknown-linux-musl".to_string(),
        _ => return None,
    })
}

/// The confined-root helper a node needs BEFORE it can start a harness.
///
/// The harness lifecycle is a hostd op: the agent runs under
/// `NoNewPrivileges=true` and cannot sudo, so it asks hostd instead. A node
/// with no hostd therefore cannot start a harness at all — and until
/// 2026-09-19 nothing put one there: `provision` never staged the
/// `hostd-binary` kind, the release carried hostd for DARWIN only, and
/// `cluster upgrade-hostd` cross-builds from a checkout that a standalone
/// controller does not have. Three delivery paths, none of them reaching a
/// Linux node.
///
/// darwin needs none: its `hostsvc` drives `launchctl` as the enrolling
/// user, so there is no privileged helper in that path.
/// Does this node's applier understand the harness bundle kinds?
///
/// Only darwin can answer no. On Linux the applier is `noo-apply.sh`,
/// delivered IN the bundle, and it installs a newer applier and re-execs
/// before it validates anything — so a Linux node can always parse the
/// bundle that upgrades it. The Mac's applier is the CLI itself, which
/// validates every kind up front, so a Mac running a CLI older than the
/// kinds refuses the whole bundle — including the `cli-binary` payload
/// that would have taught it the kinds.
///
/// That is a deadlock the node cannot escape on its own, and host6 sat in
/// it for a day (2026-09-19): every restage refused with `unknown kind
/// 'harness-binary'`, and the fix for it shipped inside the CLI it was
/// refusing. Teaching the old applier to self-update (#312) protects every
/// FUTURE node and cannot reach one already stuck.
///
/// So the controller does not send what the node cannot read. It knows the
/// node's version — `app_version` on the node record — and omits the kinds
/// that version predates. The bundle then applies, carrying the newer CLI,
/// and the next restage carries everything.
///
/// Unknown or unparseable version: assume it CAN, because the alternative
/// is silently withholding the harness from every node whose version we
/// failed to read.
pub(crate) fn applier_knows_harness_kinds(darwin: bool, app_version: &str) -> bool {
    if !darwin {
        return true;
    }
    // "noo-cli-v0.5.35+7b00c90" -> (0, 5, 35)
    let Some(rest) = app_version.split("noo-cli-v").nth(1) else {
        return true;
    };
    let nums: Vec<u32> = rest
        .split(['+', '-'])
        .next()
        .unwrap_or("")
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let [maj, min, pat] = nums[..] else { return true };
    // The Mac applier learned the harness kinds in noo-cli-v0.5.40
    (maj, min, pat) >= (0, 5, 40)
}

pub(crate) fn hostd_asset_for(os: &str, arch: &str) -> Option<String> {
    let arm = arch.starts_with("aarch64") || arch.starts_with("arm64");
    Some(match (os, arm) {
        ("linux", true) => "noo-hostd-aarch64-unknown-linux-gnu".to_string(),
        ("linux", false) => "noo-hostd-x86_64-unknown-linux-gnu".to_string(),
        // The release lane has cross-built this since the darwin-agents job
        // existed; only this arm was missing, so every Mac was told "no
        // privileged helper for this platform" and its harness had nothing
        // that could start it (host6, 2026-09-22 — the Darwin twin of the
        // NoNewPrivileges-vs-sudo collision: the agent runs as the user, the
        // harness is a system LaunchDaemon, and nothing in between).
        ("macos", true) | ("darwin", true) => "noo-hostd-aarch64-apple-darwin".to_string(),
        _ => return None,
    })
}

pub(crate) fn cli_asset_for(os: &str, arch: &str) -> Option<String> {
    let arm = arch.starts_with("aarch64") || arch.starts_with("arm64");
    Some(match (os, arm) {
        ("macos", true) | ("darwin", true) => "noo-aarch64-apple-darwin".to_string(),
        ("linux", true) => "noo-aarch64-unknown-linux-musl".to_string(),
        ("linux", false) => "noo-x86_64-unknown-linux-musl".to_string(),
        _ => return None,
    })
}

/// This release's `asset` from the controller's version-keyed cache, or —
/// when the cache lacks it — fetched from the release now and cached
/// Provision used to read the cache only, so one failed
/// fetch during `noo upgrade` left a platform without its harness or helper
/// until the next upgrade. A fetch that fails is not repeated for the same
/// asset within this process: a fleet restage during an outage asks once,
/// not once per node. The bytes ride the CA-signed bundle, as cached bytes
/// always have.
pub(crate) fn cached_release_asset(g: &Globals, root: &Path, asset: &str) -> Result<Vec<u8>, String> {
    static FAILED: std::sync::Mutex<BTreeMap<String, String>> = std::sync::Mutex::new(BTreeMap::new());
    let cached = cli_asset_cache_dir(root).join(asset);
    if let Some(b) = std::fs::read(&cached).ok().filter(|b| !b.is_empty()) {
        return Ok(b);
    }
    if let Some(e) = FAILED.lock().ok().and_then(|m| m.get(asset).cloned()) {
        return Err(e);
    }
    let r = super::upgrade::fetch_release_file(g, env!("CARGO_PKG_VERSION"), asset, None)
        .map_err(|e| e.summary())
        .and_then(|b| if b.is_empty() { Err(format!("{asset} downloaded empty")) } else { Ok(b) });
    match r {
        Ok(b) => {
            if let Some(dir) = cached.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&cached, &b);
            Ok(b)
        }
        Err(e) => {
            if let Ok(mut m) = FAILED.lock() {
                m.insert(asset.to_string(), e.clone());
            }
            Err(e)
        }
    }
}

/// The controller's cache of CLI release assets (also what /bootstrap/cli
/// serves after `noo upgrade --nodes` uploads them).
/// Keyed by THIS CLI's version: the un-keyed `<root>/bin` cache was never
/// refreshed once a file existed, so every upload and every bundle from
/// 0.3.67 to 0.3.75 shipped the first binary ever cached (0.3.68 landed
/// on HOST3 from a 0.3.75 controller, 2026-09-03).
pub(crate) fn cli_asset_cache_dir(root: &Path) -> std::path::PathBuf {
    root.join("bin").join(env!("CARGO_PKG_VERSION"))
}

pub(crate) fn put_bytes(g: &Globals, path: &str, body: &[u8]) -> Result<serde_json::Value, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    let agent = crate::http::agent(g, &base, 120);
    let mut req = agent.put(&url).header("content-type", "application/octet-stream");
    if let Some(b) = crate::auth::bearer(g) {
        req = req.header("Authorization", &b);
    }
    let mut resp = req.send(body).map_err(|e| format!("PUT {path}: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if !(200..=299).contains(&status) {
        return Err(format!("gateway returned HTTP {status} for {path}: {text}"));
    }
    Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
}

pub(crate) fn post_bytes(g: &Globals, path: &str, body: &[u8]) -> Result<(), String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    // 60 s plus a second per MB: a bundle carrying a staged vendor CLI
    // (i83 E1e) is a few hundred MB, which a flat 60 s cut off below ~5 MB/s.
    let agent = crate::http::agent(g, &base, 60 + (body.len() / 1_000_000) as u64);
    let mut req = agent.post(&url).header("content-type", "application/octet-stream");
    if let Some(b) = crate::auth::bearer(g) {
        req = req.header("Authorization", &b);
    }
    let resp = req
        .send(body)
        .map_err(|e| oversize_hint(path, body.len(), &e.to_string()))?;
    let status = resp.status().as_u16();
    if status == 413 {
        return Err(format!(
            "the gateway refused this {} upload as too large for {path} (HTTP 413) —              it is over the rail's body cap; upgrade the stack so the gateway takes it",
            human_bytes(body.len())
        ));
    }
    if !(200..=299).contains(&status) {
        return Err(format!("gateway returned HTTP {status} for {path}"));
    }
    Ok(())
}

/// A transport error part-way through a large upload, said in terms of the
/// thing that actually went wrong.
///
/// A server that refuses an over-cap body answers 413 and closes BEFORE
/// reading the rest, so the client never sees the status — it sees the write
/// fail. Twice now that has reached an operator as `io: Broken pipe (os error
/// 32)`, which names the syscall and nothing else: 2026-09-03 on a ~9 MB CLI
/// asset against a 2 MB cap, and 2026-09-19 on an 82 MB bundle against 64 MB,
/// where it stopped the whole fleet upgrade on four nodes.
fn oversize_hint(path: &str, len: usize, err: &str) -> String {
    let disconnected = ["broken pipe", "connection reset", "os error 32", "connection aborted"]
        .iter()
        .any(|needle| err.to_ascii_lowercase().contains(needle));
    if disconnected && len > 2 * 1024 * 1024 {
        return format!(
            "POST {path}: the gateway closed the connection while receiving {} ({err}).              A body over the gateway's cap is refused this way — the 413 never reaches us              because it stops reading first. Upgrade the stack so the gateway takes it,              or check `noo stack logs gateway` for the refusal.",
            human_bytes(len)
        );
    }
    format!("POST {path}: {err}")
}

/// Overwrite the staged credential file, then remove the workdir — the same
/// shred-no-matter-what posture as the script's trap.
fn scrub(work: &Path) {
    let env = work.join("files/agent-env");
    if let Ok(meta) = std::fs::metadata(&env) {
        let _ = std::fs::write(&env, vec![0u8; meta.len() as usize]);
    }
    let _ = std::fs::remove_dir_all(work);
}

// ── darwin lane pieces (additive — linux paths above untouched) ──────

/// Source-build the darwin agent. No image lane: darwin binaries ride no
/// container.
fn obtain_agent_binary_darwin(g: &Globals, root: &Path, goarch: &str) -> Result<Vec<u8>, String> {
    // 1. The controller's own cache (also the documented drop path).
    //
    // VERSION-KEYED, for the reason cli_asset_cache_dir already documents:
    // the un-keyed `<root>/bin` path was never refreshed once a file existed,
    // so every bundle shipped the first binary ever cached there. That was
    // found and fixed for the CLI assets and left in place here.
    //
    // The cost, live on 2026-09-05: host6 ran a 0.3.60-era agent through
    // every upgrade since. The bundle's CLI updated correctly (it comes from
    // the version-keyed cache) while the agent beside it did not — one bundle,
    // two sources, one of them frozen. So the Mac never received the memory
    // fix, the bus-principal reporting, or the native-backend support merged
    // for it, and reported 8 GB and tier 4 throughout.
    let cache_dir = cli_asset_cache_dir(root);
    let cached = cache_dir.join(format!("noo-node-agent-darwin-{goarch}"));
    if let Ok(b) = std::fs::read(&cached) {
        if !b.is_empty() {
            return Ok(b);
        }
    }
    // 2. The release asset paired with this CLI (private repo → `gh` must be
    //    logged in; public repo → works anywhere). Cached for next time.
    let triple = match goarch {
        "arm64" => "aarch64-apple-darwin",
        other => return Err(format!("no darwin release asset for goarch {other}")),
    };
    let asset = format!("noo-node-agent-{triple}");
    let tag = format!("noo-cli-v{}", env!("CARGO_PKG_VERSION"));
    let _ = std::fs::create_dir_all(&cache_dir);
    // The shared release fetch (gh, then the direct GET where
    // it helps; transient failures retried), and its classified cause kept
    // for the final error instead of a silenced gh.
    let fetch_err = match super::upgrade::fetch_tag_file(g, &tag, &asset) {
        Ok(b) if !b.is_empty() => {
            let _ = std::fs::write(&cached, &b);
            return Ok(b);
        }
        Ok(_) => format!("{asset} in {tag} is empty"),
        Err(e) => e.to_string(),
    };
    // 3. A source checkout with the cross-build script (dev controllers).
    let src = root.join("node-agent-go");
    if src.join("build-cross.sh").exists() {
        let ok = Command::new("bash")
            .arg(src.join("build-cross.sh"))
            .arg(format!("darwin/{goarch}"))
            .env("BINARY", "noo-node-agent")
            .current_dir(&src)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return std::fs::read(src.join(format!("noo-node-agent-darwin-{goarch}")))
                .map_err(|e| format!("built darwin binary missing: {e}"));
        }
        return Err("build-cross.sh darwin build failed".into());
    }
    Err(format!(
        "no darwin agent available: not cached at {}, the release fetch of {asset} from {tag} failed \
         ({fetch_err}), and this is not a source checkout. \
         Drop the binary at that cache path and re-run.",
        cached.display()
    ))
}

/// Rendered per node (`__USER__`): a LaunchDaemon, not a LaunchAgent —
/// runs at boot as the enrolling user with no console login, which is
/// what a headless Mac mini needs and what an SSH session can load.
const DARWIN_AGENT_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>net.noomesh.node-agent</string>
  <key>UserName</key><string>__USER__</string>
  <key>GroupName</key><string>staff</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>/Users/__USER__</string>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>exec "/Users/__USER__/noomesh/run-agent.sh"</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/noomesh-agent.log</string>
  <key>StandardErrorPath</key><string>/tmp/noomesh-agent.log</string>
</dict></plist>
"#;

/// The harness LaunchDaemon. Installed by the darwin applier,
/// loaded/unloaded by the agent per placement — never RunAtLoad: placed =
/// running, and nothing else starts it.
const DARWIN_HARNESS_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>net.noomesh.harness</string>
  <key>UserName</key><string>__USER__</string>
  <key>GroupName</key><string>staff</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>/Users/__USER__</string>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>exec "/Users/__USER__/noomesh/run-harness.sh"</string>
  </array>
  <key>RunAtLoad</key><false/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>150</integer>
  <key>StandardOutPath</key><string>/tmp/noomesh-harness.log</string>
  <key>StandardErrorPath</key><string>/tmp/noomesh-harness.log</string>
</dict></plist>
"#;
fn darwin_run_harness() -> String {
    super::env_quote::run_wrapper(
        "harness.env",
        "rendered into the provision bundle — sources the harness env (launchd has no EnvironmentFile) and execs the gateway binary's harness subcommand.",
        // ~/noomesh/bin first: a staged vendor CLI's wrapper lives there
        // (i83 E1e), and the driver hands the CLI this PATH.
        "export PATH=\"$HOME/noomesh/bin:$PATH\"\nexec \"$HOME/noomesh/bin/noo-gateway\" harness",
    )
}
fn darwin_run_agent() -> String {
    super::env_quote::run_wrapper(
        "agent.env",
        "rendered into the provision bundle — sources the agent env (launchd has no EnvironmentFile) and execs the agent.",
        // ~/noomesh/bin first: the agent's vendor-CLI check (cliOnPath)
        // looks for a staged CLI's wrapper on its own PATH (i83 E1e).
        "export PATH=\"$HOME/noomesh/bin:$PATH\"\nexec \"$HOME/noomesh/bin/noo-node-agent\"",
    )
}

/// Poll the bundle status until `fetched_at` is stamped for the CURRENT
/// staging (fetched_at is reset to NULL on every stage).
/// Ask the node to collect the staged bundle NOW instead of on its next
/// noo-fetch timer tick. A `fetch_bundle` job pinned to the node
/// (`force_node`: that node or nothing, never a fallback) reaches its agent
/// over the bus in seconds; the agent queues a `fetch-bundle` op for its
/// hostd, which runs the same fetch the timer would. Best effort: a node
/// off the bus, or an agent/hostd from before the op existed, waits for
/// the timer as before — the operator watched a 10-minute wait per node
/// on `noo upgrade --nodes` (2026-09-11).
///
/// The poke is worth something only while this command waits for the
/// fetch, so it carries its own deadline (`expire_after_sec`, the longest
/// wait below): a poke for a node that never came back is expired by the
/// scheduler janitor instead of sitting queued for days (2026-10-10: 15 of
/// them, pinned to nodes that were offline or not on the bus). A gateway
/// from before the field ignores it and applies its 24h queued-age bound.
pub(crate) const POKE_EXPIRE_AFTER_SEC: u64 = 600;

/// How long a poke is retried while the gateway says it cannot take one yet
/// (its Redis client reconnecting right after a stack roll — every poke of
/// the 0.6.4 node phase failed that way for several minutes, so every node
/// waited for its timer), and how often.
pub(crate) const POKE_RETRY_WINDOW_SECS: u64 = 60;
pub(crate) const POKE_RETRY_STEP_SECS: u64 = 10;

/// Is this submit failure the gateway's "not yet" rather than a verdict?
/// The gateway answers 503 with `{"error":"redis_reconnecting"}` while its
/// Redis client reconnects (older gateways: a bare 500 naming Redis). Any
/// other status is an answer (bad body, auth, unknown node) and is not
/// retried. The text is what `post_json_try` hands back: the `detail` field
/// when there is one, else `HTTP <status>: <body>`.
pub(crate) fn poke_is_transient(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.starts_with("http 503") || lower.contains("redis")
}

pub(crate) fn poke_fetch(g: &Globals, node: &str) -> bool {
    let body = poke_fetch_body(node);
    let started = std::time::Instant::now();
    loop {
        match crate::http::post_json_try(g, "/api/jobs/submit", &body, true, 10) {
            Ok(v) if v.get("error").is_none() => {
                nstep(&format!("poked {node} over the bus to fetch now (job {})",
                    v.get("job_id").or_else(|| v.get("id")).and_then(|j| j.as_str()).unwrap_or("queued")));
                return true;
            }
            Ok(v) => {
                warn_line(&format!(
                    "poke not accepted ({}) — {node} will only fetch on its own timer, up to about 5 minutes",
                    v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")));
                return false;
            }
            Err(e) if poke_is_transient(&e) && started.elapsed().as_secs() + POKE_RETRY_STEP_SECS <= POKE_RETRY_WINDOW_SECS => {
                nstep(&format!("poke not taken yet ({e}) — retrying in {POKE_RETRY_STEP_SECS}s"));
                std::thread::sleep(std::time::Duration::from_secs(POKE_RETRY_STEP_SECS));
            }
            Err(e) => {
                warn_line(&format!(
                    "poke failed ({e}) — {node} will only fetch on its own timer, up to about 5 minutes"));
                return false;
            }
        }
    }
}

/// The `fetch_bundle` job body `poke_fetch` submits.
pub(crate) fn poke_fetch_body(node: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "fetch_bundle",
        "priority": 1,
        "timeout_sec": 120,
        "force_node": node,
        "expire_after_sec": POKE_EXPIRE_AFTER_SEC,
        "payload": {},
    })
}

/// A redeemed enrollment the fleet still counts: used, carrying a birth
/// cert, and not revoked. `noo cluster forget` revokes a node's enrollments
/// along with its registry row (2026-09-11: a forgotten `host8` kept
/// appearing in `noo upgrade --nodes` and resolving in `provision` because
/// only the row was gone).
pub(crate) fn is_live_enrollment(t: &serde_json::Value) -> bool {
    t.get("used_at").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty())
        && t.get("birth_cert").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty())
        && !t.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// What the status route says about the bundle CURRENTLY staged for a node.
#[derive(Debug, PartialEq)]
pub(crate) enum BundleVerdict {
    /// The node's report names the staged sha: it applied (rc 0) or refused
    /// (rc != 0, -1 when the report carried no code).
    Applied { rc: i64, msg: String },
    /// Fetched (`fetched_at` stamped for this staging) but no report for it yet.
    Fetched,
    /// Not fetched yet, or only an older bundle's report is on the row.
    Nothing,
}

/// The one judgement of `/api/cluster/provision-bundle/<node>/status`,
/// shared by `cluster provision` (one node) and the combined wait of
/// `noo upgrade --nodes`. Success is `applied_sha == staged_sha`, then
/// `apply_rc`; an `applied_sha` for any OTHER bundle is not evidence about
/// this one. An empty `staged_sha` matches nothing (an empty reported sha
/// must never equal an empty staged one).
pub(crate) fn judge_bundle_status(st: &serde_json::Value, staged_sha: &str) -> BundleVerdict {
    let reported = st.get("applied_sha").and_then(|v| v.as_str()).unwrap_or("");
    if !staged_sha.is_empty() && reported == staged_sha {
        return BundleVerdict::Applied {
            rc: st.get("apply_rc").and_then(|v| v.as_i64()).unwrap_or(-1),
            msg: st.get("apply_msg").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };
    }
    if st.get("fetched_at").and_then(|v| v.as_str()).is_some() {
        BundleVerdict::Fetched
    } else {
        BundleVerdict::Nothing
    }
}

/// A node that had never reported an apply (old fetcher, cannot report)
/// gets no report ever; once it fetched and 45 s passed, the caller may
/// fall back to "the agent is online" (see `node_is_online`) and must say
/// the confirmation is missing.
pub(crate) fn legacy_fallback_due(legacy: bool, fetched: bool, elapsed_secs: u64) -> bool {
    legacy && fetched && elapsed_secs > 45
}

/// Is `node` online/busy in the registry? False when the gateway does not
/// answer or does not list it (the fallback then simply does not fire).
pub(crate) fn node_is_online(g: &Globals, node: &str) -> bool {
    let Some(doc) = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10) else { return false };
    doc.get("nodes").and_then(|n| n.as_array()).map(|arr| {
        arr.iter().any(|nd| {
            nd.get("id").and_then(|v| v.as_str())
                .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                .or_else(|| nd.get("name").and_then(|v| v.as_str()))
                .is_some_and(|id| id.eq_ignore_ascii_case(node))
                && nd.get("status").and_then(|v| v.as_str())
                    .is_some_and(|st| st == "online" || st == "busy")
        })
    }).unwrap_or(false)
}

/// True when the node has never reported an apply (no `applied_at` on its
/// status row, or no row / no answer). Read BEFORE a staging replaces the row.
pub(crate) fn node_never_reported_apply(g: &Globals, node: &str) -> bool {
    crate::http::get_json_opt(g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        .map(|st| st.get("applied_at").map(|v| v.is_null()).unwrap_or(true))
        .unwrap_or(true)
}

/// The sha256 of the ciphertext currently staged for `node`, from the
/// status route; None when nothing is staged or the gateway does not answer.
pub(crate) fn staged_sha_of(g: &Globals, node: &str) -> Option<String> {
    crate::http::get_json_opt(g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        .and_then(|st| st.get("sha256").and_then(|v| v.as_str()).map(str::to_string))
        .filter(|s| !s.is_empty())
}

/// An indented warned line under a node's label (the poke and handshake
/// notices; a plain step line reads as routine, these are not).
fn warn_line(msg: &str) {
    if !ui::quiet() {
        println!("{}", ui::sub(&ui::status_line(Glyph::Warn, msg)));
    }
}

/// Longest the applier-first handshake waits for the new applier's own apply
/// report, and how often it looks.
const APPLIER_REPORT_CAP_SECS: u64 = 60;
const APPLIER_REPORT_POLL_SECS: u64 = 5;

/// Poll the status route until it reports an apply of `applier_sha` (the
/// applier-only bundle), returning its rc; None when the cap passes first.
/// ABSENT report / unreachable gateway / old fetcher: None, never an error —
/// the handshake then proceeds as the old fixed sleep did.
fn wait_applier_reported(g: &Globals, node: &str, applier_sha: &str, cap_secs: u64, every_secs: u64) -> Option<i64> {
    let start = std::time::Instant::now();
    let mut poll = ui::Poll::start_under(&format!("waiting for {node}'s applier to report (up to {cap_secs}s)"));
    while start.elapsed().as_secs() < cap_secs {
        if let Some(st) = crate::http::get_json_opt(
            g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        {
            if let BundleVerdict::Applied { rc, .. } = judge_bundle_status(&st, applier_sha) {
                drop(poll);
                return Some(rc);
            }
        }
        poll.tick(start.elapsed().as_secs());
        std::thread::sleep(std::time::Duration::from_secs(every_secs));
    }
    drop(poll);
    None
}

/// One node staged with `--stage-only`, waiting for its apply report.
#[derive(Debug, Clone)]
pub(crate) struct PendingApply {
    pub node: String,
    /// sha256 of the staged ciphertext (the status route's `sha256`).
    pub sha: String,
    /// The node had never reported an apply before this staging (see the
    /// legacy fallback in `cluster_provision`).
    pub legacy: bool,
}

/// How one pending node ended.
#[derive(Debug, PartialEq)]
pub(crate) enum ApplyEnd {
    Applied { rc: i64, msg: String },
    /// Legacy fetcher: fetched, cannot report, agent online. Not a failure,
    /// and not confirmed either.
    LegacyUnconfirmed,
    /// No report for the staged sha within the budget; `fetched` says which
    /// stage it died at.
    NotReported { fetched: bool },
}

/// A fetch that has not happened this long after the staging was poked is
/// on the node's own ~5-minute timer: say so once, early.
pub(crate) const SLOW_TIMER_WARN_SECS: u64 = 150;

/// Wait for EVERY pending node together: one poll of each node's status
/// route per `every_secs`, `budget_secs` overall (measured from the call,
/// i.e. from when the last node was staged), one `ui::Poll` for the group,
/// and a progress line as each node reports. The judgement per node is
/// `judge_bundle_status` + `legacy_fallback_due`, the same as the single
/// node wait. An unreachable status route leaves a node unresolved for that
/// round (it can still resolve in a later one); it is never counted done.
/// Results come back in the order of `pending`.
pub(crate) fn wait_nodes_applied(g: &Globals, pending: &[PendingApply], budget_secs: u64, every_secs: u64) -> Vec<(String, ApplyEnd)> {
    wait_applied_via(g, pending, budget_secs, every_secs, &|n| format!("/api/cluster/provision-bundle/{n}/status"), "node")
}

/// The combined wait over any status route of the provision-bundle SHAPE
/// (`sha256`, `fetched_at`, `applied_sha`, `apply_rc`, `apply_msg`): the
/// nodes' route, or the kiosk seats' (`/api/cluster/seats/<seat>/status`,
/// i77). One wait, one judgement (`judge_bundle_status`), two registries.
pub(crate) fn wait_applied_via(
    g: &Globals,
    pending: &[PendingApply],
    budget_secs: u64,
    every_secs: u64,
    status_path: &dyn Fn(&str) -> String,
    noun: &str,
) -> Vec<(String, ApplyEnd)> {
    let mut ends: Vec<Option<ApplyEnd>> = pending.iter().map(|_| None).collect();
    let mut fetched = vec![false; pending.len()];
    let mut slow_warned = vec![false; pending.len()];
    let started = std::time::Instant::now();
    let names: Vec<&str> = pending.iter().map(|p| p.node.as_str()).collect();
    let mut poll = ui::Poll::start(&format!(
        "waiting for {} {noun}(s) to pull, apply and report (up to {}m): {}",
        pending.len(), budget_secs / 60, names.join(", ")));
    // Printing over a live spinner line would leave its tail behind.
    let say = |line: String| {
        if ui::stderr_is_tty() { ui::clear_line(); }
        if !ui::quiet() { println!("{}", ui::sub(&line)); }
    };
    while started.elapsed().as_secs() < budget_secs && ends.iter().any(|e| e.is_none()) {
        let elapsed = started.elapsed().as_secs();
        for (i, p) in pending.iter().enumerate() {
            if ends[i].is_some() { continue; }
            let st = crate::http::get_json_opt(g, &status_path(&p.node), true, 10);
            if let Some(st) = &st {
                match judge_bundle_status(st, &p.sha) {
                    BundleVerdict::Applied { rc, msg } => {
                        say(if rc == 0 {
                            ui::status_line(Glyph::Ok, &format!("{}: applied (exit 0)", p.node))
                        } else {
                            ui::status_line(Glyph::Err, &format!("{}: the applier refused the bundle (exit {rc})", p.node))
                        });
                        ends[i] = Some(ApplyEnd::Applied { rc, msg });
                        continue;
                    }
                    BundleVerdict::Fetched if !fetched[i] => {
                        fetched[i] = true;
                        say(ui::status_line(Glyph::Step, &format!("{}: fetched the bundle — waiting for decrypt + apply", p.node)));
                    }
                    BundleVerdict::Fetched | BundleVerdict::Nothing => {}
                }
            }
            if legacy_fallback_due(p.legacy, fetched[i], elapsed) && node_is_online(g, &p.node) {
                say(ui::status_line(Glyph::Warn, &format!(
                    "{}: applied without confirmation — this node's fetcher predates apply reports; the next restage confirms", p.node)));
                ends[i] = Some(ApplyEnd::LegacyUnconfirmed);
                continue;
            }
            if !fetched[i] && !slow_warned[i] && elapsed >= SLOW_TIMER_WARN_SECS {
                slow_warned[i] = true;
                say(ui::status_line(Glyph::Warn, &format!(
                    "{}: not fetched after {SLOW_TIMER_WARN_SECS}s — the poke likely did not reach it; it is on its own 5-minute timer", p.node)));
            }
        }
        if ends.iter().all(|e| e.is_some()) { break; }
        poll.tick(started.elapsed().as_secs());
        std::thread::sleep(std::time::Duration::from_secs(every_secs));
    }
    drop(poll);
    pending.iter().zip(ends).zip(fetched).map(|((p, end), f)| {
        (p.node.clone(), end.unwrap_or(ApplyEnd::NotReported { fetched: f }))
    }).collect()
}

/// What `cluster provision` does after a node reports exit 0, for any node
/// but the controller's own: the applier's verification lane note, the
/// signing-key adoption marker, and the invariant check. Called by the single
/// node verb and by the combined wait of `noo upgrade --nodes`.
pub(crate) fn after_remote_applied(g: &Globals, node: &str, msg: &str) {
    after_applied(g, node, msg, false);
}

/// `after_remote_applied` plus the steps only the controller's own node has:
/// the self-agent lane record and the controller-mode hostd restart. The one
/// place those run, whether the node was staged by `cluster provision <me>`
/// or by the combined wait of `noo upgrade --nodes`.
pub(crate) fn after_self_applied(g: &Globals, node: &str, msg: &str) {
    after_applied(g, node, msg, true);
}

fn after_applied(g: &Globals, node: &str, msg: &str, self_steps: bool) {
    // The POSITIVE check for the bundle-verification lane, read off the
    // APPLIER's own account of what it did rather than off a config file's
    // contents. "I edited the file" was exactly the evidence that failed
    // here before: the arm the runbook told operators to close in
    // /etc/noo-node-agent.env never reached the applier at all.
    if let Some(lane) = verification_lane(msg) {
        nnote(&lane);
    }
    record_signing_adoption(node, msg);
    if self_steps {
        // The lane is recorded only for the controller's own node, and only
        // here, after the node reported exit 0.
        if crate::role::is_self_node(node) && crate::role::detect().controller.is_some() {
            write_self_lane(node, SelfLaneRecord::Rail);
        }
        // The controller runs hostd twice from ONE binary: worker mode
        // (a root system unit, which the applier just restarted and
        // verified) and controller mode (this operator's user unit, which a
        // root applier cannot reach). Restart the second only once the
        // applier reports the new binary installed AND proven — its
        // `applied:` list names hostd-binary only after a fresh heartbeat —
        // so a failed upgrade never touches it. An applier that did not
        // name hostd-binary (old, or nothing to install) leaves it alone.
        if applier_applied(msg, "hostd-binary") {
            refresh_controller_hostd(&crate::envfile::repo_root());
        }
    }
    // Applied is not done: the node must now satisfy every invariant.
    // Printed, not fatal — the bundle is on the node; what is left is named
    // beside each row.
    if !crate::commands::cluster_verify::verify_node_after_apply(g, node) {
        nnote(&format!("{node}: applied, and an invariant does not hold yet — `noo cluster verify {node}` re-checks"));
    }
}

fn wait_bundle_fetched(g: &Globals, node: &str, secs: u64) -> bool {
    let start = std::time::Instant::now();
    let mut poll = ui::Poll::start_under(&format!("staged — waiting for {node} to fetch (up to {}m)", secs / 60));
    while start.elapsed().as_secs() < secs {
        if let Some(st) = crate::http::get_json_opt(
            g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        {
            if st.get("fetched_at").and_then(|v| v.as_str()).is_some() {
                poll.done(&format!("{node} fetched the bundle"));
                return true;
            }
        }
        poll.tick(start.elapsed().as_secs());
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    false
}

/// The image prefix and tag this controller deploys from, as the launcher
/// resolves them: env first, then the `.env` bootstrap file. Empty on a
/// source-built install, where the local image names ARE the real ones —
/// so an empty value is a correct answer, not a missing one.
fn image_prefix() -> String {
    release_var("NOO_IMAGE_PREFIX")
}

fn image_tag() -> String {
    release_var("NOO_IMAGE_TAG")
}

/// The agent-env key the controller owns for cluster trust: the bind
/// override. (`NOO_CLUSTER_TOKEN_V1`, the v1 cluster-token gate, was the
/// second; it is deleted and never rendered — a pre-0.6.10 Mac applier would
/// refuse the line anyway.)
pub(crate) const CLUSTER_TRUST_ENV_KEYS: &[&str] = &["NODE_AGENT_BIND"];

/// The first CLI whose Mac applier accepts [`CLUSTER_TRUST_ENV_KEYS`] in an
/// `agent-env` payload (node_fetch.rs `AGENT_ENV_KEYS`). A Linux node is
/// never withheld from: `noo-apply.sh` self-updates before it validates.
///
/// This is the TAG the keys first shipped in, not the version the change was
/// written against: the keys landed on dev while 0.6.8 was in flight and were
/// first released in noo-cli-v0.6.10. With the floor at 0.6.8, a 0.6.9 Mac
/// (mcmini, 2026-10-23) was sent the keys and its applier refused the whole
/// bundle with exit 65 — including the CLI that would have taught it the keys.
/// The applier now self-updates before it validates (node_fetch.rs
/// `verify_bundle_with`), so this floor is belt-and-braces for Macs whose
/// applier predates that too. A future template key joins
/// [`CLUSTER_TRUST_ENV_KEYS`]'s treatment by being added to a table like this
/// one with its own floor (tests/test_apply_env_unit_shape.py fails first).
const CLUSTER_TRUST_KEYS_MAC_FLOOR: (u32, u32, u32) = (0, 6, 10);

/// Does this node's applier accept the cluster-trust keys? On a Mac an
/// unreadable or missing version is assumed OLD: omitting the keys is
/// harmless (the agent defaults both) while sending them to an applier that
/// predates them strands the whole bundle, including the newer CLI that
/// would have taught it. The next restage, once the node reports the new
/// version, carries them.
pub(crate) fn applier_knows_cluster_trust_keys(darwin: bool, app_version: &str) -> bool {
    if !darwin {
        return true;
    }
    super::node_leaves::cli_version_triple(app_version).is_some_and(|v| v >= CLUSTER_TRUST_KEYS_MAC_FLOOR)
}

/// `body` without the lines that set any of `keys`.
pub(crate) fn drop_env_keys(body: &str, keys: &[&str]) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        let k = line.split('=').next().unwrap_or("");
        if keys.contains(&k) {
            continue;
        }
        out.push_str(line);
    }
    out
}

/// What `NODE_AGENT_BIND` may carry: empty (the agent derives it), `all`, or
/// IP addresses separated by commas. Anything else is the agent's own startup
/// refusal (`api.PlanBind`), caught here so a bad value never reaches a
/// node. Spelled narrower than the agent accepts (`0.0.0.0`, `::`, `*`): the
/// Mac sources this file, and `*` is a glob there.
pub(crate) fn agent_bind_value(raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("all") {
        return Ok(v.to_ascii_lowercase());
    }
    let mut parts = Vec::new();
    for h in v.split(',') {
        let h = h.trim();
        match h.parse::<std::net::IpAddr>() {
            Ok(ip) => parts.push(ip.to_string()),
            Err(_) => return Err(format!(
                "NODE_AGENT_BIND={raw:?}: {h:?} is not an IP address — use `all`, an address, or a comma list of addresses"
            )),
        }
    }
    Ok(parts.join(","))
}

/// The `NODE_AGENT_BIND` to render for the agent env: the controller's `.env`
/// / environment value (a fleet setting, like NOO_IMAGE_TAG); an invalid one
/// is an Err naming the fix.
pub(crate) fn cluster_trust_bind() -> Result<String, String> {
    agent_bind_value(&release_var("NODE_AGENT_BIND"))
}

pub(crate) fn release_var(key: &str) -> String {
    if let Ok(v) = std::env::var(key) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    let env_path = crate::onboard::standalone::default_home().join(".env");
    let Ok(body) = std::fs::read_to_string(env_path) else {
        return String::new();
    };
    body.lines()
        .filter_map(|l| l.strip_prefix(&format!("{key}=")))
        .next_back()
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod cluster_trust_tests {
    use super::*;

    /// The v1 gate is deleted: the real template must not carry the line,
    /// and a bundle must not render it for any node.
    #[test]
    fn the_agent_env_no_longer_carries_the_v1_gate() {
        let Some(path) = crate::test_support::repo_file_or_skip("node-agent-go/deploy/noo-node-agent.env.tmpl") else {
            return;
        };
        let tmpl = std::fs::read_to_string(&path).unwrap();
        assert!(tmpl.contains("NODE_AGENT_BIND="), "the guard must be scanning the real template");
        let body = render_env_template(&tmpl, &super::tests::full_vars()).unwrap();
        assert!(!body.contains("NOO_CLUSTER_TOKEN_V1="), "the retired v1 gate is still rendered:\n{body}");
    }

    #[test]
    fn the_bind_override_is_all_or_addresses_and_nothing_a_shell_could_read() {
        assert_eq!(agent_bind_value("").unwrap(), "");
        assert_eq!(agent_bind_value(" ALL ").unwrap(), "all");
        assert_eq!(agent_bind_value("100.64.0.7, 127.0.0.1").unwrap(), "100.64.0.7,127.0.0.1");
        for bad in ["host3.local", "*", "1.2.3.4;id", "$(id)", "0.0.0.0,evil"] {
            let e = agent_bind_value(bad).unwrap_err();
            assert!(e.contains("NODE_AGENT_BIND"), "{e}");
        }
    }

    #[test]
    fn an_old_mac_applier_is_not_sent_keys_it_would_refuse() {
        assert!(applier_knows_cluster_trust_keys(false, "noo-cli-v0.5.1"), "linux self-updates its applier");
        assert!(!applier_knows_cluster_trust_keys(true, "noo-cli-v0.6.7+abc"));
        // 0.6.8 and 0.6.9 shipped WITHOUT the keys in the Mac applier's
        // allow-list; mcmini on noo-cli-v0.6.9 refused the 0.6.10 bundle.
        assert!(!applier_knows_cluster_trust_keys(true, "noo-cli-v0.6.8"));
        assert!(!applier_knows_cluster_trust_keys(true, "noo-cli-v0.6.9+bdf4c07"));
        assert!(applier_knows_cluster_trust_keys(true, "noo-cli-v0.6.10+c6c4814"));
        assert!(applier_knows_cluster_trust_keys(true, "noo-cli-v0.6.11+abc"));
        assert!(!applier_knows_cluster_trust_keys(true, "unknown"), "an unreadable Mac version is assumed old");
        assert!(!applier_knows_cluster_trust_keys(true, ""), "no reported version is assumed old");
        assert!(applier_knows_cluster_trust_keys(false, "noo-cli-v0.6.9"), "linux path unaffected");
        assert!(applier_knows_cluster_trust_keys(false, ""));
    }

    /// The agent-env keys the v0.6.9 Mac applier accepts (node_fetch.rs
    /// `AGENT_ENV_KEYS` at noo-cli-v0.6.9), frozen as a fixture.
    const MAC_0_6_9_AGENT_ENV_KEYS: &[&str] = &[
        "NODE_ID", "NODE_IP", "NODE_TIER", "GPU_MODEL", "CONTROLLER_URL", "NATS_URL",
        "NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NOO_PKI_DIR", "NOO_TLS_CA", "NOO_TLS_CERT",
        "NOO_TLS_KEY", "NOO_MTLS_NODES", "OLLAMA_URL", "NOO_SELF_NODE", "NOO_DATA_ROOT",
        "HF_CACHE_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR", "NOO_MODEL_CACHE_URL", "PATH",
        "NOO_FORCE_GPU", "NOO_OLLAMA_GPU_COUNT", "NOO_IMAGE_PREFIX", "NOO_IMAGE_TAG",
        "NODE_AGENT_PORT", "LOG_LEVEL", "DOCKER_HOST", "NOO_APPLY_ACCEPT_CA_SIGNED",
    ];

    /// Render the REAL template the way provision does for a node reporting
    /// `app_version`, and return the env that would be bundled.
    fn bundled_env(darwin: bool, app_version: &str) -> Option<String> {
        let path = crate::test_support::repo_file_or_skip("node-agent-go/deploy/noo-node-agent.env.tmpl")?;
        let tmpl = std::fs::read_to_string(&path).unwrap();
        let body = render_env_template(&tmpl, &super::tests::full_vars()).unwrap();
        Some(if applier_knows_cluster_trust_keys(darwin, app_version) {
            body
        } else {
            drop_env_keys(&body, CLUSTER_TRUST_ENV_KEYS)
        })
    }

    fn env_keys(body: &str) -> Vec<&str> {
        body.lines().filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect()
    }

    #[test]
    fn a_0_6_9_mac_gets_an_agent_env_its_applier_accepts() {
        for v in ["noo-cli-v0.6.9+abc", "noo-cli-v0.6.8", "", "unknown"] {
            let Some(body) = bundled_env(true, v) else { return };
            let keys = env_keys(&body);
            for k in CLUSTER_TRUST_ENV_KEYS {
                assert!(!keys.contains(k), "{v}: {k} must be withheld:\n{body}");
            }
            for k in &keys {
                assert!(MAC_0_6_9_AGENT_ENV_KEYS.contains(k),
                    "{v}: {k} is not in the 0.6.9 applier's allow-list, so it would refuse the bundle:\n{body}");
            }
        }
    }

    #[test]
    fn a_0_6_10_mac_and_every_linux_node_get_the_trust_keys() {
        for (darwin, v) in [(true, "noo-cli-v0.6.10"), (true, "noo-cli-v0.6.11+x"),
                            (false, "noo-cli-v0.6.9"), (false, "stack-v0.6.9"), (false, "")] {
            let Some(body) = bundled_env(darwin, v) else { return };
            let keys = env_keys(&body);
            for k in CLUSTER_TRUST_ENV_KEYS {
                assert!(keys.contains(k), "darwin={darwin} {v}: {k} missing:\n{body}");
            }
        }
    }

    #[test]
    fn dropping_the_keys_leaves_the_rest_of_the_env_alone() {
        let body = "NODE_ID=h\nNODE_AGENT_BIND=all\n# NODE_AGENT_BIND is a comment\nLOG_LEVEL=info\n";
        assert_eq!(drop_env_keys(body, CLUSTER_TRUST_ENV_KEYS),
            "NODE_ID=h\n# NODE_AGENT_BIND is a comment\nLOG_LEVEL=info\n");
    }
}

#[cfg(test)]
mod poke_fetch_tests {
    use super::{poke_fetch_body, poke_is_transient, POKE_EXPIRE_AFTER_SEC, POKE_RETRY_WINDOW_SECS, POKE_RETRY_STEP_SECS};

    #[test]
    fn only_the_gateways_not_yet_is_retried() {
        assert!(poke_is_transient(r#"HTTP 503: {"error":"redis_reconnecting"}"#));
        assert!(poke_is_transient("Redis not connected"), "an older gateway's bare 500 detail");
        assert!(poke_is_transient("HTTP 500: Redis not connected"));
        assert!(!poke_is_transient("HTTP 400: force_node unknown"));
        assert!(!poke_is_transient("HTTP 401: operator key required"));
        assert!(!poke_is_transient("connection refused (gateway down?)"), "a transport failure is the gateway wait's job");
        const { assert!(POKE_RETRY_WINDOW_SECS >= POKE_RETRY_STEP_SECS && POKE_RETRY_WINDOW_SECS < 600) };
    }

    #[test]
    fn the_poke_is_pinned_and_expires_inside_the_wait_it_serves() {
        let b = poke_fetch_body("host3");
        assert_eq!(b["type"], "fetch_bundle");
        assert_eq!(b["force_node"], "host3");
        assert_eq!(b["expire_after_sec"], POKE_EXPIRE_AFTER_SEC);
        // Longest wait a poker sits through: provision's 600s window and
        // security_local's FETCH_WAIT. A deadline past both is a poke nobody
        // is waiting on.
        const { assert!(POKE_EXPIRE_AFTER_SEC >= crate::commands::security_local::FETCH_WAIT.as_secs()) };
        const { assert!(POKE_EXPIRE_AFTER_SEC <= 600) };
    }
}

#[cfg(test)]
mod data_root_precedence_tests {
    use super::resolve_data_root;

    #[test]
    fn the_operators_declaration_beats_the_birth_time_fact() {
        // The defect: only the fact was read, so `set-config --data-root`
        // could not reach the bundle, and the node then refused the path the
        // operator had chosen because it declares its legal host roots from
        // the env vars that bundle renders.
        assert_eq!(
            resolve_data_root(Some("/srv/chosen"), Some("/mnt/d/noo")),
            "/srv/chosen"
        );
    }

    #[test]
    fn the_fact_is_the_fallback_when_nothing_was_declared() {
        // A node that has never been configured keeps what it was born with.
        assert_eq!(resolve_data_root(None, Some("/mnt/d/noo")), "/mnt/d/noo");
    }

    #[test]
    fn an_unusable_declaration_does_not_relocate_a_nodes_data() {
        // Empty, relative, or bare "/" are not declarations. Treating any of
        // them as one would move a node's whole data tree on a typo, and "/"
        // in particular is the value `hostroots.go` exists to refuse.
        for bad in ["", "   ", "relative/path", "/"] {
            assert_eq!(
                resolve_data_root(Some(bad), Some("/mnt/d/noo")),
                "/mnt/d/noo",
                "{bad:?} must not be taken as a declaration"
            );
        }
    }

    #[test]
    fn with_neither_it_is_the_built_in_default() {
        assert_eq!(resolve_data_root(None, None), "/var/lib/noo");
        assert_eq!(resolve_data_root(Some(""), Some("")), "/var/lib/noo");
    }

    #[test]
    fn an_undeclared_node_keeps_the_root_it_reports() {
        use super::pick_data_root;
        // implicit /data/noo with running mounts, no declaration, no fact:
        // the bundle renders /data/noo, not today's /var/lib/noo.
        assert_eq!(pick_data_root(None, Some("/data/noo"), None), "/data/noo");
        // the reported root beats a stale birth fact (host3, 2026-09-12)
        assert_eq!(pick_data_root(None, Some("/data/noo"), Some("/mnt/d/noo")), "/data/noo");
        // a declaration still wins over what the node reports
        assert_eq!(pick_data_root(Some("/var/lib/noo"), Some("/data/noo"), None), "/var/lib/noo");
        // nothing usable anywhere: the default
        assert_eq!(pick_data_root(Some(""), Some("/"), None), "/var/lib/noo");
    }

    #[test]
    fn a_trailing_space_is_trimmed_rather_than_rendered() {
        assert_eq!(resolve_data_root(Some(" /srv/noo "), None), "/srv/noo");
    }
}

#[cfg(test)]
mod verification_lane_tests {
    use super::verification_lane;

    /// The report EXACTLY as the controller stored it for host8 on
    /// 2026-09-12, newlines already collapsed. Using the real string is the
    /// point: the first version of this parser read the fields as lines, which
    /// is how the applier prints them and not how they arrive, so the check
    /// never fired and no test noticed because there was no test.
    const REAL_CLOSED: &str = "applied: ca.crt node.crt node.key agent-env nats-creds \
agent-binary applier fetcher agent-unit verified-by: signing-key ca-lane: closed active";
    const RETIRED: &str = "applied: ca.crt node.crt node.key agent-env nats-creds \
agent-binary applier fetcher agent-unit verified-by: signing-key ca-lane: retired active";

    #[test]
    fn the_real_collapsed_report_yields_a_line() {
        let out = verification_lane(REAL_CLOSED).expect("the live report must produce a line");
        assert!(out.contains("fleet signing key"), "{out}");
        assert!(out.contains("closed"), "{out}");
    }

    #[test]
    fn a_current_applier_reports_the_lane_retired() {
        let out = verification_lane(RETIRED).expect("line");
        assert!(out.contains("retired"), "{out}");
    }

    #[test]
    fn an_old_applier_on_the_retired_lane_is_named_as_such() {
        let out = verification_lane("applied: agent-env verified-by: ca-legacy ca-lane: open")
            .expect("line");
        assert!(out.contains("RETIRED"), "{out}");
        assert!(out.contains("re-stage"), "{out}");
    }

    #[test]
    fn a_rollover_is_not_mistaken_for_the_retired_lane() {
        for via in ["ca-rollover", "ca-rollover-countersigned"] {
            let out = verification_lane(&format!("applied: signing-pub verified-by: {via}")).expect("line");
            assert!(out.contains("rollover"), "{out}");
            assert!(!out.contains("RETIRED"), "a rollover is the legitimate CA arm: {out}");
        }
    }

    #[test]
    fn adoption_is_read_only_from_a_lane_that_proves_it() {
        assert_eq!(super::verified_by(RETIRED).as_deref(), Some("signing-key"));
        assert_eq!(super::verified_by("applied: ca.crt").as_deref(), None);
    }

    #[test]
    fn a_report_without_the_field_prints_nothing_rather_than_guessing() {
        // An older applier emits no `verified-by:` at all. Silence is correct
        // there; inventing a lane would be worse than saying nothing.
        assert!(verification_lane("applied: ca.crt node.crt").is_none());
        assert!(verification_lane("").is_none());
    }

    #[test]
    fn newline_separated_fields_still_work() {
        // Belt and braces: if the report lane ever stops collapsing them, the
        // parser must not break in the other direction.
        let out = verification_lane("applied: agent-env\nverified-by: signing-key\nca-lane: retired\n")
            .expect("line");
        assert!(out.contains("fleet signing key") && out.contains("retired"), "{out}");
    }
}

/// Where the harness reads its TLS pair (`harness_tls_cert` /
/// `harness_tls_key` in `noo-harness.env.tmpl`): its OWN copy on Linux
/// (`scripts/noo-apply.sh`, harness-pair), the agent's files on a Mac.
pub(crate) fn harness_tls_paths(darwin: bool, vars: &BTreeMap<&str, String>) -> (String, String) {
    if darwin {
        (vars.get("na_tls_cert").cloned().unwrap_or_default(), vars.get("na_tls_key").cloned().unwrap_or_default())
    } else {
        (HARNESS_TLS_CERT.to_string(), HARNESS_TLS_KEY.to_string())
    }
}

/// The harness's own copy of the node pair on a Linux node.
pub(crate) const HARNESS_TLS_CERT: &str = "/etc/noo/pki/harness/node.crt";
pub(crate) const HARNESS_TLS_KEY: &str = "/etc/noo/pki/harness/node.key";

#[cfg(test)]
mod tests {
    // The controller must never stage a bundle the node's applier cannot
    // parse. host6 sat in that deadlock for a day (2026-09-19): every
    // restage refused with `unknown kind 'harness-binary'`, and the fix
    // for it shipped inside the CLI it was refusing.
    #[test]
    fn the_gzip_gate_opens_only_at_or_above_the_fetcher_that_reads_it() {
        for v in ["noo-cli-v0.6.4", "noo-cli-v0.6.4+abc1234", "noo-cli-v0.5.99", "noo-cli-v0.0.1"] {
            assert!(bundle_gzip_gate(v).is_err(), "gzip sent to {v}");
        }
        for v in ["noo-cli-v0.6.5", "noo-cli-v0.6.5+7b00c90", "noo-cli-v0.6.6", "noo-cli-v0.7.0", "noo-cli-v1.0.0"] {
            assert!(bundle_gzip_gate(v).is_ok(), "gzip withheld from {v}");
        }
        // The Linux agents report the stack tag (live, 0.6.5 roll on pop-os):
        // `stack-v<semver>+<40-hex>`. And a bare `v<semver>`.
        let sha = "ff917285b5cb2f43bc2b249393af91dffcf0c298";
        for v in [format!("stack-v0.6.4+{sha}"), "stack-v0.6.4".into(), "v0.6.4".into(), "v0.6.4+abc".into()] {
            assert!(bundle_gzip_gate(&v).is_err(), "gzip sent to {v}");
            assert!(!bundle_gzip_gate(&v).unwrap_err().contains("unreadable"), "{v} must parse: {:?}", bundle_gzip_gate(&v));
        }
        for v in [format!("stack-v0.6.5+{sha}"), "stack-v0.6.5".into(), "stack-v0.7.0".into(), "v0.6.5".into(), "v1.0.0+abc".into()] {
            assert!(bundle_gzip_gate(&v).is_ok(), "gzip withheld from {v}");
        }
        assert_eq!(parse_cli_version(&format!("stack-v0.6.4+{sha}")), Some((0, 6, 4)));
        assert_eq!(parse_cli_version("noo-cli-v0.6.4+ff91728"), Some((0, 6, 4)));
        assert_eq!(parse_cli_version("v0.6.5"), Some((0, 6, 5)));
        // Unknown / unparseable: NO (a wrong yes bricks the apply).
        for v in ["", "garbage", "0.6.9", "noo-cli-v0.6", "noo-cli-vx.y.z", "noo-cli-v0.6.9.1", "stack-v0.6", "stack-vx.y.z", "xstack-v0.6.5", "vv0.6.5"] {
            assert!(bundle_gzip_gate(v).is_err(), "gzip sent to unreadable {v:?}");
        }
    }

    /// The gate names the FIRST release whose fetchers unwrap gzip. It is
    /// pinned here so a later edit can never lower it (a lower value sends
    /// gzip to a fetcher that hands it to `noo-apply`, which refuses it), and
    /// never raise it without reason (a higher value just withholds the
    /// saving from nodes that could take it). The feature was written at CLI
    /// 0.6.4 and ships in the 0.6.5 cut; if that cut is skipped or renumbered,
    /// confirm which release carries the gzip-aware `noo-fetch.sh` and
    /// `node_fetch.rs`, set the constant to it, and update this pin.
    #[test]
    fn the_gzip_gate_is_pinned_to_the_release_that_ships_the_fetcher() {
        assert_eq!(GZIP_BUNDLE_MIN_VERSION, (0, 6, 5), "see the doc comment on this test before changing either");
        let me = env!("CARGO_PKG_VERSION");
        let v: Vec<u32> = me.split(['.', '-', '+']).take(3).map(|s| s.parse().unwrap()).collect();
        assert!((v[0], v[1], v[2]) >= (0, 6, 4), "this tree predates the feature it gates: {me}");
    }

    #[test]
    fn gzip_bundle_is_one_member_gzip_that_inflates_to_the_input() {
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!("noo-gzip-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("bundle.tar");
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let gz = gzip_bundle(&src, &dir).unwrap();
        let raw = std::fs::read(&gz).unwrap();
        assert_eq!(&raw[..2], &[0x1f, 0x8b]);
        assert_eq!(raw[3], 0, "no FNAME/FEXTRA/FCOMMENT header flags");
        assert!(raw.len() < data.len() / 2, "level-6 gzip should shrink a repetitive input");
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mac_older_than_the_harness_kinds_is_not_sent_them() {
        // The version host6 was actually stuck on.
        assert!(!applier_knows_harness_kinds(true, "noo-cli-v0.5.35+7b00c90"));
        // The release that taught the Mac applier those kinds.
        assert!(applier_knows_harness_kinds(true, "noo-cli-v0.5.40+abc1234"));
        assert!(applier_knows_harness_kinds(true, "noo-cli-v0.5.46+b4bdc06"));
        // Boundary: one patch below is still too old.
        assert!(!applier_knows_harness_kinds(true, "noo-cli-v0.5.39"));
        // A later minor/major is fine.
        assert!(applier_knows_harness_kinds(true, "noo-cli-v0.6.0"));
        assert!(applier_knows_harness_kinds(true, "noo-cli-v1.0.0"));
    }

    #[test]
    fn linux_is_never_withheld_because_its_applier_ships_in_the_bundle() {
        // noo-apply.sh self-updates and re-execs BEFORE it validates, so a
        // Linux node can always parse the bundle that upgrades it — even
        // reporting an ancient version.
        for v in ["stack-v0.2.47+7b00c90", "noo-cli-v0.5.35", "", "garbage"] {
            assert!(applier_knows_harness_kinds(false, v), "linux withheld on {v:?}");
        }
    }

    #[test]
    fn an_unreadable_version_is_assumed_capable() {
        // Withholding on a version we failed to parse would silently deny
        // the harness to nodes that can run it — worse than the deadlock,
        // because nothing would say so.
        for v in ["", "unknown", "noo-cli-vX.Y.Z", "stack-v0.2.58+a21a072"] {
            assert!(applier_knows_harness_kinds(true, v), "withheld on {v:?}");
        }
    }

    #[test]
    fn live_enrollment_requires_used_birth_cert_and_not_revoked() {
        use super::is_live_enrollment;
        let live = serde_json::json!({"used_at": "2026-09-11T00:00:00Z", "birth_cert": "PEM", "revoked": false});
        assert!(is_live_enrollment(&live));
        let revoked = serde_json::json!({"used_at": "2026-09-11T00:00:00Z", "birth_cert": "PEM", "revoked": true});
        assert!(!is_live_enrollment(&revoked), "a forgotten node's enrollment must not count");
        let unused = serde_json::json!({"used_at": null, "birth_cert": "", "revoked": false});
        assert!(!is_live_enrollment(&unused));
        let no_cert = serde_json::json!({"used_at": "2026-09-11T00:00:00Z", "birth_cert": "", "revoked": false});
        assert!(!is_live_enrollment(&no_cert), "a v1 enrollment with no birth cert is not pull-capable");
    }


    #[test]
    fn provisioning_has_no_ssh_lane_at_all() {
        // #1184 made the gate lane opt-in; this removes it. The test moved
        // with it: "opt-in" is no longer the property to hold, "absent" is.
        //
        // Pinned as source, not behaviour, because a lane is re-added by
        // writing one — and no behavioural test notices a branch nothing
        // takes yet. The needles are assembled at runtime: a literal spelled
        // out here would match this test's own source and pass no matter
        // what the command does.
        let src = include_str!("provision.rs");
        let fails = format!("{}{}", "\"no_birth", "_cert\"");
        assert!(
            src.contains(&fails),
            "the missing-birth-cert path must fail with a re-enroll instruction"
        );
        for needle in [
            format!("{}{}", "via_", "gate"),
            format!("{}{}", "gate_", "apply"),
            format!("Command::new({}ssh{})", '"', '"'),
        ] {
            assert!(
                !src.contains(&needle),
                "provisioning must not reach a node over ssh — found {needle}"
            );
        }
        // The gate binary's name is a PREFIX of the gateway binary's
        // So this
        // needle is checked by its next character: the prefix followed by
        // anything but the `way` that makes it the gateway is the gate.
        // A plain contains() answered two questions with one string and
        // went red the day the harness arrived (2026-09-18) — and the
        // first fix spelled the prefix out in this comment, which the scan
        // then found in its own source.
        let gate = format!("{}{}", "noo-", "gate");
        for (i, _) in src.match_indices(&gate) {
            let after = &src[i + gate.len()..];
            assert!(
                after.starts_with("way"),
                "provisioning must not reach a node over ssh — found the gate binary at byte {i}"
            );
        }
    }

    use super::*;

    /// Provisioning MUST mint without delivering. `issue-node` delivers by
    /// default and exits non-zero when the node does not confirm — correct
    /// for an operator re-issuing a live node, fatal here: a node being
    /// provisioned has no agent running to present the cert or report an
    /// apply, and both call sites treat anything but Ok(0) as a hard stop.
    /// Drop the flag and every fresh provision fails on its own cert step.
    ///
    /// This reads the source because the call is one branch deep inside a
    /// function that talks to a gateway, a node and sops; the cheap check
    /// that the flag is PRESENT catches the regression that matters.
    /// image_tag() prefers the PROCESS environment over the .env file, and
    /// that preference is why one bug survived two fixes.
    ///
    /// `ensure_repo_env()` loads .env into the process at CLI startup, so
    /// within a single `noo upgrade --all` the process value is the tag from
    /// BEFORE the roll. Fix one used a raw std::env::var (#1181). Fix two moved
    /// to image_tag() — which changed which function was consulted but not
    /// which value won.
    ///
    /// The guard missed it too, and that is the sharper lesson: the extracted
    /// binary was compared against the tag it had ASKED for, and both were
    /// stale. A check that validates an output against a corrupted input cannot
    /// detect the corruption. Live 2026-09-06 — the stack rolled to v0.2.24 and
    /// three linux nodes stayed on v0.2.23, every bundle reporting exit 0.
    ///
    /// So the stack stage now writes the deployed tag into the process on a
    /// successful roll, and this pins the property that makes that work.
    #[test]
    fn the_process_tag_is_what_image_tag_reports() {
        std::env::set_var("NOO_IMAGE_TAG", "v0.2.23");
        assert_eq!(image_tag(), "v0.2.23",
            "the process value wins over .env — this preference IS the trap");

        // What upgrade.rs now does the moment the launcher reports success.
        std::env::set_var("NOO_IMAGE_TAG", "v0.2.24");
        assert_eq!(image_tag(), "v0.2.24",
            "after the roll the process must report the tag actually deployed, \
             because the nodes stage extracts the agent image from it");
        std::env::remove_var("NOO_IMAGE_TAG");
    }

    /// Both agent-binary caches must be version-keyed, or a bundle ships a
    /// frozen binary forever.
    ///
    /// `cli_asset_cache_dir` was already keyed after the un-keyed `<root>/bin`
    /// path shipped the first binary ever cached from 0.3.67 to 0.3.75. The
    /// DARWIN agent kept reading that same un-keyed path, so host6 ran a
    /// 0.3.60-era agent through every upgrade since — while the CLI in the
    /// very same bundle updated correctly, because it came from the keyed
    /// cache. One bundle, two sources, one frozen.
    #[test]
    fn the_darwin_agent_cache_is_version_keyed() {
        let root = std::path::Path::new("/tmp/noo-test-root");
        let dir = cli_asset_cache_dir(root);
        assert!(
            dir.ends_with(env!("CARGO_PKG_VERSION")),
            "cache dir {} is not keyed by this CLI version — a stale binary would be \
             reused forever", dir.display());
        // And it must NOT be the bare `bin` directory that caused the bug.
        assert_ne!(dir, root.join("bin"),
            "the un-keyed <root>/bin path is the one that froze; nothing may return to it");
    }

    /// The guard that would have caught a whole release reaching no node.
    ///
    /// stack-v0.2.23 rolled, every bundle applied exit 0, and all four nodes
    /// kept running a v0.2.22 agent — because `ensure_repo_env` had loaded the
    /// PRE-upgrade NOO_IMAGE_TAG into the process and the nodes stage still
    /// held it. Three node-agent fixes shipped and reached nothing, and the
    /// only signal was a success message.
    #[test]
    fn a_binary_from_the_wrong_release_is_detected() {
        // A binary stamped with the release it actually came from.
        let wrong = b"\x7fELF....internal/version.Version=v0.2.22....".to_vec();
        assert!(!binary_carries_version(&wrong, "v0.2.23"),
            "a v0.2.22 binary must not pass as v0.2.23 — this is the bug");
        assert!(binary_carries_version(&wrong, "v0.2.22"),
            "the binary does carry its own tag");
    }

    /// An empty tag must never pass. `NOO_IMAGE_TAG` unset is exactly the
    /// state that sent the old code down the fallback path, and treating
    /// "" as satisfied would let anything through.
    #[test]
    fn an_empty_tag_never_satisfies_the_check() {
        assert!(!binary_carries_version(b"anything at all", ""));
    }

    /// The scan must not false-negative on a real ELF, where the version sits
    /// among megabytes of other bytes rather than at a boundary.
    #[test]
    fn the_version_is_found_anywhere_in_the_binary() {
        let mut bin = vec![0u8; 4096];
        bin.extend_from_slice(b"v0.2.23");
        bin.extend(std::iter::repeat_n(0u8, 4096));
        assert!(binary_carries_version(&bin, "v0.2.23"));
    }

    /// i11a: the local lane re-issues on missing CONTROLLER NAMES, not only
    /// on a missing cert, and passes this box's own address so the issuer
    /// never looks the controller's node name up on the tailnet.
    #[test]
    fn the_local_lane_reissues_on_missing_controller_names() {
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        let local = &src[src.find("fn provision_local_in(").expect("provision_local_in")..];
        let body = &local[..local.find("ensure_door_leaves_try(").expect("door leaves step")];
        assert!(body.contains("cert_covers_sans(&node_crt, role.required_dns()"), "coverage test missing");
        assert!(body.contains("crate::onboard::util::detect_ip()"), "explicit address missing");
        assert!(body.contains("&ts_ip, &role)"), "the controller role (names, own tailnet address) is issued");
    }

    #[test]
    fn provision_mints_certs_without_delivering() {
        let whole = include_str!("provision.rs");
        // Only the real code: the literals in this test would otherwise
        // match themselves.
        let src = whole.split("#[cfg(test)]").next().unwrap();
        let calls: Vec<&str> = src
            .match_indices("pki_issue_node(")
            .map(|(i, _)| &src[i..(i + 200).min(src.len())])
            .collect();
        assert!(!calls.is_empty(), "no pki_issue_node call sites found — did they move?");
        for c in &calls {
            assert!(
                c.contains("--mint-only"),
                "a provision call site issues certs WITHOUT --mint-only, so it \
                 would deliver and hard-stop on an unconfirmed node: {c}"
            );
        }
    }

    /// Every `PREP_INSECURE=1` this file hands prep-host travels with the
    /// CA's fingerprint in the SAME command: prep-host refuses `-k` without
    /// `PREP_CA_SHA256`, and a paste that omits it would fetch
    /// the trust anchor blind. tests/test_prep_tofu_is_pinned.py is the
    /// repo-wide half; this one reads the crate's own source.
    #[test]
    fn every_prep_insecure_site_carries_the_ca_pin() {
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        let sites: Vec<usize> = src.match_indices("\"PREP_INSECURE=1\"").map(|(i, _)| i).collect();
        assert!(!sites.is_empty(), "no PREP_INSECURE=1 site found — did it move?");
        for i in sites {
            let start = src[..i].rfind("Command::new(").expect("PREP_INSECURE outside a Command chain");
            let end = i + src[i..].find(".status()").expect("Command chain without .status()");
            let chain = &src[start..end];
            assert!(chain.contains("PREP_CA_SHA256="),
                "a PREP_INSECURE=1 site sends no PREP_CA_SHA256 — the CA fetch would be unpinned:\n{chain}");
        }
    }

    /// The retired per-backend TLS switches are neither rendered into the
    /// node env nor carried by its template: the agent REFUSES a
    /// false/0/no/off value, so a line a stale CLI or template could write is
    /// a trap. (`retired_tls_switches_are_in_no_shipped_template` in
    /// tests/test_no_retired_tls_switches.py covers the whole repo.)
    #[test]
    fn retired_backend_tls_switches_are_not_rendered() {
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        for key in ["noo_vllm_tls", "noo_llamacpp_tls", "noo_ollama_tls"] {
            assert!(!src.contains(&format!("vars.insert(\"{key}\"")), "{key} is rendered again");
        }
        let tmpl = std::fs::read_to_string(
            crate::test_support::repo_file("node-agent-go/deploy/noo-node-agent.env.tmpl"),
        ).expect("node env template");
        for line in tmpl.lines().filter(|l| !l.trim_start().starts_with('#')) {
            assert!(!line.contains("_TLS=") || line.starts_with("NOO_TLS_"), "template carries a TLS switch: {line}");
        }
    }

    pub(super) fn full_vars() -> BTreeMap<&'static str, String> {
        let mut v = BTreeMap::new();
        for k in ["na_node_id","node_ip","node_tier","gpu_model","controller_url","nats_url",
                  "noo_node_agent_token","noo_cluster_secret",
                  "noo_pki_dir","na_tls_ca","na_tls_cert","na_tls_key","noo_mtls_nodes",
                  "noo_data_root",
                  "hf_cache_dir","models_dir","ollama_data_dir","noo_model_cache_url",
                  "noo_force_gpu","noo_ollama_gpu_count","node_agent_port","log_level",
                  "noo_image_prefix","noo_image_tag",
                  // The self-node lane and the pull-rail var map put these
                  // in the real vars maps and in the template, but not
                  // here — so this drift guard has been red on dev since.
                  // Fixed in passing rather than left to redden the next
                  // branch that touches this crate.
                  "noo_self_node","ollama_url",
                  "node_agent_bind"] {
            v.insert(k, format!("V_{k}"));
        }
        v
    }

    /// The harness template renders with the pull-rail vars
    /// plus the three harness extras cluster_provision adds — and with NO
    /// default anywhere, because this renderer never evaluates one.
    #[test]
    fn real_harness_template_renders_with_provision_vars() {
        // The EMBEDDED template — the one a bundle actually carries — not
        // the file on disk. Reading the disk copy here would have passed on
        // every machine while the staged bundle failed on a controller
        // whose checkout was older (2026-09-19).
        let tmpl = super::super::enroll::asset_harness_env_tmpl().to_string();
        if tmpl.is_empty() {
            eprintln!("crate-only build (no embedded assets) — harness template drift check skipped");
            return;
        }
        let mut v = full_vars();
        v.insert("noo_harness_model_url", "V_model_url".into());
        v.insert("noo_harness_max_turns", "V_max_turns".into());
        v.insert("harness_log", "V_log".into());
        let (hc, hk) = harness_tls_paths(false, &v);
        v.insert("harness_tls_cert", hc);
        v.insert("harness_tls_key", hk);
        let out = render_env_template(&tmpl, &v).unwrap();
        for line in ["NODE_ID=V_na_node_id", "NOO_GATEWAY_URL=V_controller_url", "NATS_URL=V_nats_url",
                     "NOO_TLS_CA=V_na_tls_ca", "NOO_TLS_CERT=/etc/noo/pki/harness/node.crt", "NOO_TLS_KEY=/etc/noo/pki/harness/node.key",
                     "NOO_HARNESS_MODEL_URL=V_model_url", "NOO_HARNESS_MAX_TURNS=V_max_turns", "RUST_LOG=V_log"] {
            assert!(out.contains(line), "harness env lacks {line}:\n{out}");
        }
        // The NATS pair is the applier's to merge (nats-creds); the template
        // leaves it empty on purpose, never absent.
        assert!(out.contains("NATS_NODE_USER=\n"), "{out}");
        assert!(!out.contains("default("), "a default survived into the rendered env: {out}");
        // i119: never the agent's pair on Linux; the agent's files on a Mac.
        assert!(!out.contains("/pki/nodes/"), "{out}");
        assert_eq!(harness_tls_paths(true, &v), ("V_na_tls_cert".to_string(), "V_na_tls_key".to_string()));
    }

    /// The REAL template must render with the exact vars cluster_provision
    /// supplies — this is the drift guard between the j2 and the Rust caller.
    #[test]
    fn real_template_renders_with_provision_vars() {
        // Outside the harness only: the full-checkout guard is also
        // tests/test_provision_template_vars.py in the python `test` job.
        let Some(path) = crate::test_support::repo_file_or_skip("node-agent-go/deploy/noo-node-agent.env.tmpl") else {
            return;
        };
        let tmpl = std::fs::read_to_string(&path).unwrap();
        let out = render_env_template(&tmpl, &full_vars()).unwrap();
        assert!(out.contains("NODE_ID=V_na_node_id"));
        assert!(out.contains("NOO_NODE_AGENT_TOKEN=V_noo_node_agent_token"));
        assert!(out.contains("NOO_CLUSTER_SECRET=V_noo_cluster_secret"), "the fu52 bug class");
        // The retired shared bus pair is never rendered — a
        // node presents only its own NATS_NODE_* pair (the nats-creds kind).
        assert!(!out.contains("NATS_USER=") && !out.contains("NATS_PASSWORD="), "{out}");
        assert!(out.contains("NOO_TLS_KEY=V_na_tls_key"), "if-branch must be kept");
        assert!(!out.contains("{{") && !out.contains("{%") && !out.contains("{#"));
    }

    #[test]
    fn unknown_var_fails_loud() {
        let mut v = full_vars();
        v.remove("noo_cluster_secret");
        let err = render_env_template("X={{ noo_cluster_secret | default('') }}", &v).unwrap_err();
        assert!(err.contains("noo_cluster_secret"));
    }

    /// The full pull-lane crypto path: a birth keypair exactly as
    /// `noo enroll` generates it, encrypt exactly as provision does,
    /// decrypt exactly as noo-fetch does. Skips when openssl is absent.
    #[test]
    fn cms_round_trips_the_bundle() {
        if Command::new("openssl").arg("version").output().map(|o| !o.status.success()).unwrap_or(true) {
            eprintln!("openssl unavailable — CMS round-trip skipped");
            return;
        }
        let work = std::env::temp_dir().join(format!("noo-cms-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        // Birth keypair, same invocation as `noo enroll`.
        assert!(Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                   "-keyout"]).arg(work.join("birth.key"))
            .arg("-out").arg(work.join("birth.crt"))
            .args(["-subj", "/CN=noo-birth-test"])
            .output().unwrap().status.success());
        let plaintext = b"this stands in for the CA-signed bundle.tar".to_vec();
        let bundle = work.join("bundle.tar");
        std::fs::write(&bundle, &plaintext).unwrap();
        let cert_pem = std::fs::read_to_string(work.join("birth.crt")).unwrap();
        let blob = encrypt_bundle_cms(&bundle, &cert_pem, &work).unwrap();
        assert!(!blob.is_empty());
        assert_ne!(blob, plaintext, "ciphertext must not be the plaintext");
        // Decrypt exactly as noo-fetch does.
        let blob_path = work.join("blob.der");
        std::fs::write(&blob_path, &blob).unwrap();
        let out = Command::new("openssl")
            .args(["smime", "-decrypt", "-binary", "-inform", "DER", "-inkey"])
            .arg(work.join("birth.key"))
            .arg("-in").arg(&blob_path)
            .output().unwrap();
        assert!(out.status.success(), "decrypt failed: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, plaintext, "round trip must be byte-identical");
        // Wrong key must NOT decrypt.
        assert!(Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout"])
            .arg(work.join("other.key"))
            .arg("-out").arg(work.join("other.crt"))
            .args(["-subj", "/CN=other"])
            .output().unwrap().status.success());
        let bad = Command::new("openssl")
            .args(["smime", "-decrypt", "-binary", "-inform", "DER", "-inkey"])
            .arg(work.join("other.key"))
            .arg("-in").arg(&blob_path)
            .output().unwrap();
        // The property is that a foreign key never yields the plaintext.
        // "openssl exits non-zero" is NOT that property on OpenSSL builds
        // with RSA implicit rejection (3.2+, and Ubuntu's 3.0.13 backport of
        // the Marvin-attack fix, which GitHub's hosted runners carry): a
        // wrong key no longer errors, it substitutes a random content key,
        // and the resulting garbage passes the CBC padding check about one
        // run in 256 — which is exactly how this assertion flaked on a
        // hosted runner (2026-09-27, PR #497) after passing twice before.
        assert!(
            !bad.status.success() || bad.stdout != plaintext,
            "a foreign key must not decrypt the bundle"
        );
        assert_ne!(bad.stdout, plaintext, "a foreign key produced the plaintext");
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn tier_ladder_over_enrollment_facts() {
        use serde_json::json;
        assert_eq!(derive_tier_facts(&json!({"model":"Raspberry Pi 5","arch":"aarch64"})), "4");
        assert_eq!(derive_tier_facts(&json!({"gpu_present":1,"arch":"x86_64"})), "2");
        assert_eq!(derive_tier_facts(&json!({"arch":"aarch64","gpu_present":0})), "4");
        assert_eq!(derive_tier_facts(&json!({"arch":"x86_64","gpu_present":0})), "3");
    }

    /// The self-node's OLLAMA_URL is the https door only on a
    /// standalone install whose compose file declares the sidecar's
    /// loopback publish; every other shape keeps the plaintext loopback URL
    /// that is right for the stack it runs.
    #[test]
    fn self_node_ollama_url_follows_the_declared_door() {
        let shipped = std::fs::read_to_string(crate::test_support::repo_file("docker-compose.cluster.yml")).expect("shipped compose");
        let root = std::env::temp_dir().join(format!("noo-ollama-url-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let https = "https://127.0.0.1:11434";
        let http = "http://127.0.0.1:11434";

        // No compose, no marker.
        assert_eq!(self_node_ollama_url(&root), http);
        // The shipped compose (door published) but not standalone: no sidecar runs.
        std::fs::write(root.join("docker-compose.cluster.yml"), &shipped).unwrap();
        assert_eq!(self_node_ollama_url(&root), http);
        // Standalone + the shipped compose: the door.
        std::fs::write(root.join(".noo-standalone"), "standalone\n").unwrap();
        assert_eq!(self_node_ollama_url(&root), https);
        // Standalone on a stack not yet rolled (the publish still on the raw
        // container): plaintext, or the agent would dial TLS at ollama itself.
        let door = format!("    ports:\n      - \"{OLLAMA_EMBED_LOOPBACK_DOOR}\"\n");
        assert_eq!(shipped.matches(&door).count(), 1, "the shipped door publish moved — update this test");
        let unrolled = shipped
            .replacen(&door, "", 1)
            .replacen("  ollama-embed:\n", &format!("  ollama-embed:\n{door}"), 1);
        std::fs::write(root.join("docker-compose.cluster.yml"), &unrolled).unwrap();
        assert_eq!(self_node_ollama_url(&root), http);
        // A sidecar published off loopback is not the door this URL names.
        let lan = shipped.replacen(OLLAMA_EMBED_LOOPBACK_DOOR, "0.0.0.0:11434:11434", 1);
        std::fs::write(root.join("docker-compose.cluster.yml"), &lan).unwrap();
        assert_eq!(self_node_ollama_url(&root), http);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Provision --local runs the applier's own
    /// `agent_secret_files` block, lifted between its markers, so the
    /// controller's node ends with its secrets in files like a rail node.
    #[test]
    fn local_install_runs_the_applier_secret_file_block() {
        let applier = std::fs::read_to_string(crate::test_support::repo_file("scripts/noo-apply.sh")).expect("shipped applier");
        let block = agent_secret_files_block(&applier).expect("markers in noo-apply.sh");
        assert!(block.contains("agent_secret_files() {") && block.contains("AGENT_SECRET_KEYS="), "{block}");
        assert!(!block.contains("# END agent_secret_files"));
        let script = local_agent_secret_files_script(&applier);
        assert!(script.starts_with(block), "the call must follow the definitions");
        assert!(script.contains(
            "agent_secret_files /etc/noo-node-agent.env /etc/noo/agent-secrets /usr/local/bin/noo-node-agent \"$ASF_OWNER\""
        ), "{script}");
        // A crate-only build embeds no applier: no block, no call, and the
        // install script is unchanged.
        assert_eq!(agent_secret_files_block(""), None);
        assert_eq!(local_agent_secret_files_script(""), "");
    }

}

#[cfg(test)]
mod live_tier_tests {
    use super::resolve_tier;
    use serde_json::json;

    /// host3's real enrollment facts (2026-09-09): no GPU seen at birth.
    fn host3_facts() -> serde_json::Value {
        json!({"arch": "amd64", "os": "linux", "gpu_present": false, "gpu_api": "",
               "unified_memory": false, "usable_gpu_gb": 0, "model": ""})
    }

    /// The live defect: a 16 GB GPU box re-derived as tier 3 (CPU) from an
    /// enrollment snapshot taken before its GPU was visible, on every
    /// restage. The gateway's live ladder says 2, and that wins.
    #[test]
    fn a_live_tier_beats_a_stale_enrollment_snapshot() {
        assert_eq!(super::derive_tier_facts(&host3_facts()), "3", "the snapshot alone says CPU");
        let live = json!({"id": "host3", "derived_tier": 2});
        assert_eq!(resolve_tier(Some(&live), Some(&host3_facts())), Some(("2".into(), "the node's live facts")));
    }

    /// The gateway omits derived_tier when its ladder can't decide (UNKNOWN).
    /// Absence falls back to the enrollment facts; it is not a default.
    #[test]
    fn an_undecided_live_ladder_falls_back_to_enrollment_facts() {
        let live = json!({"id": "host3"});
        assert_eq!(resolve_tier(Some(&live), Some(&host3_facts())), Some(("3".into(), "enrollment facts")));
        assert_eq!(resolve_tier(None, Some(&host3_facts())).unwrap().1, "enrollment facts", "a node that never heartbeated");
    }

    /// Only a real tier counts; anything else falls through, it is never used.
    #[test]
    fn an_out_of_range_live_tier_is_ignored() {
        for bad in [json!(0), json!(9), json!("2"), json!(null)] {
            let live = json!({"derived_tier": bad});
            assert_eq!(resolve_tier(Some(&live), Some(&host3_facts())).unwrap().1, "enrollment facts", "{bad}");
        }
    }

    #[test]
    fn nothing_at_all_is_none_not_a_guess() {
        assert_eq!(resolve_tier(None, None), None);
    }
}

#[cfg(test)]
mod controller_hostd_tests {
    use super::applier_applied;

    /// What noo-fetch.sh does to the log before posting it, verbatim:
    /// `tail -c 1500 | tr -d '\000' | … | tr '\n\r\t' '   '`.
    fn as_the_fetcher_sends(log: &str) -> String {
        let tail: String = log.chars().rev().take(1500).collect::<Vec<_>>().into_iter().rev().collect();
        tail.replace('\0', "").replace(['\n', '\r', '\t'], " ")
    }

    /// host8's real applier output from the 0.5.61 roll, as it reached
    /// provision: FLATTENED. The first version of this parser was tested on
    /// the newline-separated log and never on what the fetcher sends.
    #[test]
    fn the_flattened_report_from_the_real_wire_is_read() {
        let log = "noo-apply: verified against the fleet signing key\n\
                   noo-apply: hostd upgraded (fresh heartbeat from the new binary)\n\
                   applied: ca.crt node.crt node.key agent-env nats-creds agent-binary applier fetcher hostd-binary agent-unit\n";
        let wire = as_the_fetcher_sends(log);
        assert!(!wire.contains('\n'), "the fetcher sends one line");
        assert!(applier_applied(&wire, "hostd-binary"));
        assert!(!applier_applied(&wire, "cli-binary"), "a kind that wasn't applied");
    }

    /// The fetcher's transform is what this parser is written against. If
    /// noo-fetch.sh stops flattening, this says so rather than passing on
    /// whichever shape happens to arrive.
    #[test]
    fn the_fetcher_still_flattens_its_report() {
        let fetch = include_str!("../../../scripts/noo-fetch.sh");
        assert!(fetch.contains(r"tr '\n\r\t' '   '"), "noo-fetch.sh no longer flattens apply_msg — revisit applier_applied");
    }

    /// The applier's own report, in its real shape (noo-apply.sh ends with
    /// `echo "applied:$applied"`) — both flattened and not.
    #[test]
    fn a_kind_counts_only_when_the_applier_lists_it_as_applied() {
        let ok = "noo-apply: granted …\napplied: ca.crt node.crt agent-binary hostd-binary nats-creds";
        assert!(applier_applied(ok, "hostd-binary"));
        assert!(!applier_applied("applied: ca.crt node.crt agent-binary", "hostd-binary"));
        // Named in an error is not applied — and a failed hostd install exits
        // 65 before the applied line is ever printed.
        assert!(!applier_applied("noo-apply: hostd-binary is not an ELF executable", "hostd-binary"));
        assert!(!applier_applied("applied: hostd-binary-old", "hostd-binary"), "whole tokens only");
    }

    /// hostd must not slip back inside the self-node branch, which exists for
    /// the CLI alone. That is where it sat, and the controller's hostd had no
    /// upgrade path until someone noticed host8 two releases behind.
    #[test]
    fn hostd_is_staged_for_every_node_including_the_controllers_own() {
        // ORDER: the phase list. CONTENT: the phase that owns hostd.
        let list = super::phase_src::list();
        assert!(list.find("attach_hostd(").expect("hostd is a phase") < list.find("attach_cli(").expect("the CLI is a phase"),
            "hostd staging must precede, not sit inside, the self-node CLI branch");
        let hostd = super::phase_src::body("attach_hostd");
        assert!(hostd.contains(r#"files.push(("hostd-binary""#), "the hostd phase stages hostd");
        assert!(!hostd.contains("self_node"), "hostd is staged for every node, so its phase has no self-node branch");
        assert!(super::phase_src::body("attach_cli").contains("the bundle carries no CLI"), "the self-node CLI branch");
    }
}

#[cfg(test)]
mod self_node_rail_tests {
    //! i67: the controller's own node rides the rail like any node; the
    //! only sudo is creating its node identity, once.
    use super::*;

    fn units<'a>(present: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
        move |p: &str| present.contains(&p)
    }
    const ALL: [&str; 4] = ["/usr/local/bin/noo-fetch", "/usr/local/bin/noo-apply",
        "/etc/systemd/system/noo-fetch.timer", "/etc/noo/birth.crt"];

    #[test]
    fn a_prepped_controller_has_no_missing_units() {
        assert!(missing_pull_units("pop-os", &units(&ALL), Some("pop-os\n")).is_empty());
        assert!(missing_pull_units("pop-os", &units(&ALL), Some("Pop-OS")).is_empty());
    }

    #[test]
    fn each_missing_unit_is_named() {
        let m = missing_pull_units("pop-os", &units(&ALL[..2]), Some("pop-os"));
        assert_eq!(m, vec!["noo-fetch.timer".to_string(), "the birth cert".to_string()]);
        let m = missing_pull_units("pop-os", &units(&ALL), None);
        assert!(m.len() == 1 && m[0].contains("no node name"), "{m:?}");
        let m = missing_pull_units("pop-os", &units(&ALL), Some("host8"));
        assert!(m[0].contains("names 'host8', not 'pop-os'"), "{m:?}");
    }

    /// pop-os before 0.6.3: prepped by the old local lane, no birth key, no
    /// gateway copy. The first `--nodes` creates the identity once.
    #[test]
    fn a_pre_i67_controller_creates_its_identity_once_then_rides_the_rail() {
        let pre = ["/usr/local/bin/noo-fetch", "/usr/local/bin/noo-apply"];
        let missing = missing_pull_units("pop-os", &units(&pre), Some("pop-os"));
        assert_eq!(self_node_lane("pop-os", &missing, true), SelfLane::CreateIdentity);
        // Once created, nothing is missing: the rail, no sudo.
        let after = missing_pull_units("pop-os", &units(&ALL), Some("pop-os"));
        assert_eq!(self_node_lane("pop-os", &after, true), SelfLane::Rail);
        assert_eq!(self_node_lane("pop-os", &after, false), SelfLane::Rail, "the rail never needs sudo");
    }

    #[test]
    fn without_identity_and_without_sudo_the_rail_refuses_with_the_remedy() {
        let missing = vec!["noo-fetch.timer".to_string()];
        let SelfLane::Refuse(why) = self_node_lane("pop-os", &missing, false) else {
            panic!("no identity and no way to sudo must refuse");
        };
        assert!(why.contains("'pop-os' is this controller's own node"), "{why}");
        assert!(why.contains("noo-fetch.timer") && why.contains("sudo once"), "{why}");
        assert_eq!(SELF_RAIL_REMEDY, "noo onboard --only services");
    }

    /// F1 (0.6.3-rc.1): the gateway reads the self node's birth cert from
    /// the PKI's certificate-only view, which the CLI fills without sudo:
    /// `<pki>/nodes/<self>/birth.crt`, mirrored to `public/nodes/<self>/`.
    #[test]
    fn the_birth_cert_reaches_the_gateways_view_without_root() {
        let base = std::env::temp_dir().join(format!("noo-selfcert-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let pki = base.join("pki");
        std::fs::create_dir_all(pki.join("nodes/pop-os")).unwrap();
        let host = base.join("birth.crt");
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        std::fs::write(&host, pem).unwrap();
        assert_eq!(sync_self_birth_cert(&pki, "pop-os", &host), Ok(true));
        assert_eq!(std::fs::read_to_string(pki.join("nodes/pop-os/birth.crt")).unwrap(), pem);
        assert_eq!(std::fs::read_to_string(pki.join("public/nodes/pop-os/birth.crt")).unwrap(), pem,
            "mirrored into the view the gateway mounts at /app/pki/nodes");
        assert_eq!(sync_self_birth_cert(&pki, "pop-os", &host), Ok(false), "idempotent");
        // A new identity replaces the view's copy.
        let pem2 = pem.replace("AAAA", "BBBB");
        std::fs::write(&host, &pem2).unwrap();
        assert_eq!(sync_self_birth_cert(&pki, "pop-os", &host), Ok(true));
        assert_eq!(std::fs::read_to_string(pki.join("public/nodes/pop-os/birth.crt")).unwrap(), pem2);
        // Not a certificate, or no file: an error, nothing written.
        std::fs::write(&host, "garbage").unwrap();
        assert!(sync_self_birth_cert(&pki, "pop-os", &host).unwrap_err().contains("not a PEM"));
        assert!(sync_self_birth_cert(&pki, "pop-os", &base.join("nope")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// F2 (0.6.3-rc.1): the first install RETURNS its errors — onboard warns
    /// and continues with hostd, placement and the rest. A PKI with no CA
    /// fails at the prep line's CA pin; the test process is still here to
    /// see the Err.
    #[test]
    fn the_first_install_returns_its_error_instead_of_exiting() {
        let base = std::env::temp_dir().join(format!("noo-firstinstall-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (root, pki) = (base.join("root"), base.join("pki"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&pki).unwrap();
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let r = provision_local_in(&g, "noo-test-node-i67b", Some("3"), &root, &pki);
        let e = r.expect_err("an install with no CA must fail — by returning");
        assert!(e.contains("ca.crt") || e.contains("prep-host"), "{e}");
        let _ = std::fs::remove_dir_all(&base);
        // And the onboard caller warns and goes on, never `fail`s.
        let steps = include_str!("../onboard/steps.rs");
        let f = &steps[steps.find("fn ensure_self_agent(").unwrap()..];
        let f = &f[..f.find("\n}\n").unwrap()];
        assert!(f.contains("if let Err(e) = crate::commands::provision::provision_local("), "{f}");
        assert!(f.contains("provision_one(ctx.g, &node_id, &[])"), "the rail branch runs in a child");
        assert!(!f.contains("fail("), "{f}");
    }

    /// Behaviour of the identity script itself, run with a temp dir for
    /// /etc/noo and stubs for openssl and prep: keypair generated BEFORE
    /// prep when absent, the staged copy removed after, no root-written
    /// copy for the gateway, and a present keypair left alone.
    #[test]
    fn the_identity_script_creates_the_key_prep_arms_it_and_the_gateway_gets_its_copy() {
        let base = std::env::temp_dir().join(format!("noo-selfid-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (etc, work) = (base.join("etc"), base.join("work"));
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let log = base.join("log");
        // Stubs: openssl writes the pair it was asked for; "prep" installs
        // the staged pair into etc, as prep-host.sh does.
        let stubs = format!(
            "openssl() {{ echo openssl >> '{l}'; k=; c=; while [ $# -gt 0 ]; do case $1 in -keyout) k=$2;; -out) c=$2;; esac; shift; done; echo KEY > \"$k\"; echo CERT > \"$c\"; }}\n",
            l = log.display());
        let prep = format!("echo prep >> '{l}'; [ -f '{w}/birth.key' ] && cp '{w}/birth.key' '{e}/birth.key' && cp '{w}/birth.crt' '{e}/birth.crt'; true\n",
            l = log.display(), w = work.display(), e = etc.display());
        let run = || {
            let script = format!("set -e\n{stubs}{}", self_identity_script("ctrl", &work, &etc, &prep));
            let out = Command::new("sh").arg("-c").arg(&script).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            std::fs::read_to_string(&log).unwrap_or_default()
        };
        let first = run();
        assert_eq!(first.lines().collect::<Vec<_>>(), vec!["openssl", "prep"], "keypair before prep");
        assert_eq!(std::fs::read_to_string(etc.join("birth.crt")).unwrap(), "CERT\n");
        assert!(!etc.join("self-node").exists(), "no root-owned copy for the gateway any more");
        assert!(!work.join("birth.key").exists(), "the staged key is removed");
        // Second run: the pair exists, nothing regenerates; the copy holds.
        std::fs::remove_file(&log).unwrap();
        assert_eq!(run().lines().collect::<Vec<_>>(), vec!["prep"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// stage_bundle_pull's selection: the self node is encrypted to the
    /// LOCAL cert and its enrollment record is never read (i11a); any other
    /// node to its record.
    #[test]
    fn the_self_node_is_staged_to_its_local_cert_never_a_record() {
        assert_eq!(pull_target_cert(true, || Some("LOCAL".into()), || panic!("record read for the self node")),
            Some("LOCAL".into()));
        assert_eq!(pull_target_cert(true, || None, || Some("OTHER MACHINE".into())), None,
            "no local cert: nothing staged, not the record");
        assert_eq!(pull_target_cert(false, || panic!("local read for a remote node"), || Some("REC".into())),
            Some("REC".into()));
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        let f = &src[src.find("pub(crate) fn stage_bundle_pull(").unwrap()..];
        assert!(f[..f.find("\n}\n").unwrap()].contains("pull_target_cert(is_self"));
    }

    #[test]
    fn the_gateways_view_of_the_self_node_is_judged_with_a_remedy_per_cause() {
        let fp = "ab".repeat(32);
        let ok = format!(r#"{{"node":"pop-os","birth_cert_sha256":"{fp}"}}"#);
        assert_eq!(judge_gateway_self_view("pop-os", &fp, Some((200, &ok))), Ok(()));
        let e = |a: Option<(u16, &str)>| judge_gateway_self_view("pop-os", &fp, a).unwrap_err();
        let p = e(None);
        assert_eq!((p.code, p.remedy.as_str()), ("gateway_unreachable", "noo stack status"));
        let p = e(Some((404, "")));
        assert_eq!((p.code, p.remedy.as_str()), ("gateway_predates_i67", "noo upgrade --stack"));
        assert_eq!(e(Some((403, ""))).code, "gateway_auth");
        assert_eq!(e(Some((500, ""))).code, "gateway_error");
        let p = e(Some((200, r#"{"node":"host8","birth_cert_sha256":null}"#)));
        assert_eq!(p.code, "self_id_mismatch");
        assert!(p.msg.contains("'host8'") && p.msg.contains("'pop-os'") && p.msg.contains("NODE_ID"), "{}", p.msg);
        let p = e(Some((200, r#"{"node":"pop-os","birth_cert_sha256":null}"#)));
        assert_eq!((p.code, p.remedy.as_str()), ("gateway_no_self_cert", "noo upgrade --stack"));
        let p = e(Some((200, &format!(r#"{{"node":"pop-os","birth_cert_sha256":"{}"}}"#, "cd".repeat(32)))));
        assert_eq!((p.code, p.remedy.as_str()), ("gateway_self_cert_stale", "noo cluster provision pop-os"));
    }

    /// onboard's self-agent step: standalone/checkout × interactive/--ci.
    #[test]
    fn onboards_self_agent_step_covers_every_controller_shape() {
        use crate::role::Controller;
        let sa = Controller::Standalone(std::path::PathBuf::from("/s"));
        let co = Controller::Checkout(std::path::PathBuf::from("/c"));
        let step = |c: Option<&Controller>, installed, active, identity, interactive, quiet|
            self_agent_step(c, installed, active, identity, interactive, quiet);
        // Not a controller / a checkout with no host agent: said, not silent.
        assert!(matches!(step(None, true, true, true, true, true), SelfAgentStep::Skip(_)));
        assert!(matches!(step(Some(&co), false, false, false, true, true), SelfAgentStep::Skip(_)));
        for c in [&sa, &co] {
            // Identity in place: the rail, interactive or not, no sudo.
            assert_eq!(step(Some(c), true, true, true, false, false), SelfAgentStep::AlreadyOnRail);
            assert_eq!(step(Some(c), true, false, true, false, false), SelfAgentStep::Rail);
            // Agent installed, identity missing (pop-os): the rail, which
            // creates the identity once — at a terminal or with quiet sudo.
            assert_eq!(step(Some(c), true, true, false, true, false), SelfAgentStep::Rail);
            assert_eq!(step(Some(c), true, true, false, false, true), SelfAgentStep::Rail, "--ci with quiet sudo");
            // --ci and sudo would prompt: skipped WITH the reason.
            let SelfAgentStep::Skip(why) = step(Some(c), true, true, false, false, false) else { panic!() };
            assert!(why.contains("noo onboard --only services"), "{why}");
        }
        // A fresh standalone box: the first install, interactive or --ci.
        assert_eq!(step(Some(&sa), false, false, false, true, false), SelfAgentStep::FirstInstall);
        assert_eq!(step(Some(&sa), false, false, false, false, true), SelfAgentStep::FirstInstall);
    }

    /// Source guards (beside the behaviour above): the rail verb never runs
    /// the first-install lane, its sudo is only the identity step, and the
    /// self node is built from this machine, checked against the gateway's
    /// view, then staged.
    #[test]
    fn the_rail_verb_has_no_sudo_lane_and_builds_the_self_node_locally() {
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        // The rail verb is the phase list plus every phase it runs.
        let body = phase_src::verb();
        assert!(!body.contains("provision_local("), "the rail verb must not call the first-install lane");
        assert!(!body.contains(r#"Command::new("sudo")"#), "the rail verb runs no sudo itself");
        assert!(phase_src::body("begin_provision").contains("SelfLane::CreateIdentity => {")
            && phase_src::body("begin_provision").contains("ensure_self_identity(&node)"));
        // Local facts, then the gateway's view (one phase), then the stage (a later phase).
        let enrol = phase_src::body("load_enrollment");
        let local = enrol.find("self_node_redemption(&node)").expect("self node built locally");
        let view = enrol.find("judge_gateway_self_view(").expect("the gateway's view checked");
        assert!(local < view, "local facts, then the gateway's view");
        let list = phase_src::list();
        assert!(list.find("load_enrollment(").expect("the enrollment phase") < list.find("stage_bundle(").expect("the stage phase"),
            "the gateway's view of the self node is checked before anything is staged");
        assert!(phase_src::body("stage_bundle").contains("/api/cluster/provision-bundle/{node}\"), &blob)"), "the stage");
        // The lane record lives in `after_applied`, reached from the applied
        // arm only through `after_self_applied`.
        assert!(!body.contains("write_self_lane("), "the lane is recorded by after_self_applied, not inline");
        let apply = phase_src::body("await_apply");
        let applied = apply.find("reported: applied (exit 0)").expect("the applied arm");
        let call = apply.find("after_self_applied(g, &node, msg)").expect("the self node's post-apply steps");
        assert!(applied < call, "the self steps run only after the node reported exit 0");
        let aa = &src[src.find("fn after_applied(").unwrap()..];
        let aa = &aa[..aa.find("\n}\n").unwrap()];
        let lane = aa.find("write_self_lane(node, SelfLaneRecord::Rail)").expect("the lane record");
        let hostd = aa.find("refresh_controller_hostd(").expect("the hostd restart");
        assert!(aa.find("if self_steps").unwrap() < lane && lane < hostd, "{aa}");
        assert!(aa.contains(r#"applier_applied(msg, "hostd-binary")"#), "{aa}");
        let up = include_str!("upgrade.rs");
        let up = up.split("#[cfg(test)]").next().unwrap();
        let f = &up[up.find("fn upgrade_self_node(").unwrap()..];
        let f = &f[..f.find("\n}\n").unwrap()];
        assert!(f.contains(r#"provision_one(g, me, &["--stage-only"])"#), "{f}");
        assert!(!f.contains("--local"), "{f}");
    }

    #[test]
    fn every_bundle_must_carry_this_nodes_nats_creds() {
        let nc = |n: &str| crate::commands::nats_users::creds_payload(n, "pw").into_bytes();
        for node in ["aserve", "pop-os"] {
            let files: Vec<(&str, Vec<u8>)> = vec![("agent-env", b"x".to_vec()), ("nats-creds", nc(node))];
            assert_eq!(require_nats_creds(node, &files), Ok(()), "{node}");
            let without: Vec<(&str, Vec<u8>)> = vec![("agent-env", b"x".to_vec())];
            assert!(require_nats_creds(node, &without).unwrap_err().contains("carries no nats-creds"), "{node}");
            let other: Vec<(&str, Vec<u8>)> = vec![("nats-creds", nc("someone-else"))];
            assert!(require_nats_creds(node, &other).is_err(), "{node}");
        }
        // The credential is attached, then the signing phase requires the pair
        // before it signs.
        let list = phase_src::list();
        assert!(list.find("attach_nats_credential(").expect("the credential phase") < list.find("sign_bundle(").expect("the signing phase"),
            "the credential is attached before the bundle is signed");
        let body = phase_src::body("sign_bundle");
        let guard = body.find("require_nats_creds(&node, files)").expect("the guard");
        let sign = body.find("build_signed_bundle(ca, &node, files, &work)").expect("the signature");
        assert!(guard < sign, "the pair is required before the bundle is signed");
    }

    #[test]
    fn the_self_nodes_bus_principal_is_not_the_gateways() {
        let payload = crate::commands::nats_users::creds_payload("pop-os", "pw");
        assert_eq!(check_nats_creds("pop-os", payload.as_bytes()), Ok(()));
        let user = payload.lines().find_map(|l| l.strip_prefix("NATS_NODE_USER=")).unwrap();
        assert_eq!(user, "node-pop-os");
        for principal in crate::commands::nats_users::CONTROLLER_PRINCIPALS {
            assert_ne!(user, *principal, "the self node must not present a controller principal");
        }
        let key = crate::commands::nats_users::node_secret_key("pop-os");
        assert_eq!(key, "NATS_NODE_PASSWORD_POP_OS");
        assert_ne!(key, "NATS_GATEWAY_PASSWORD");
        assert_ne!(key, "NATS_WORKER_PASSWORD");
    }

    #[test]
    fn the_self_node_reports_facts_in_the_enroll_shape() {
        let f = self_node_facts("aarch64", "/var/lib/noo", true);
        assert_eq!(f["os"], "linux");
        assert_eq!(f["arch"], "aarch64");
        assert_eq!(f["data_root"], "/var/lib/noo");
        assert_eq!(derive_tier_facts(&f), "2", "a GPU box");
        assert_eq!(derive_tier_facts(&self_node_facts("x86_64", "/d", false)), "3");
    }

    #[test]
    fn the_lane_record_words_are_what_verify_reads() {
        assert_eq!(SelfLaneRecord::Onboard.word(), "onboard");
        assert_eq!(SelfLaneRecord::Rail.word(), "rail");
        assert_eq!(SELF_LANE_RECORD, "self-agent.lane");
    }
}

#[cfg(test)]
mod local_lane_tests {
    use super::*;

    fn creds(node: &str, pw: &str) -> Vec<u8> {
        crate::commands::nats_users::creds_payload(node, pw).into_bytes()
    }

    fn inputs(nats_creds: Vec<u8>) -> LocalInputs {
        LocalInputs {
            signing_pub: b"-----BEGIN PUBLIC KEY-----\nsp\n-----END PUBLIC KEY-----\n".to_vec(),
            agent_env: b"NODE_ID=ctrl\nCONTROLLER_URL=https://ctrl:8080\n".to_vec(),
            nats_creds,
            agent_binary: b"\x7fELF-agent".to_vec(),
            agent_unit: b"[Service]\nUser=noo-agent\n".to_vec(),
            ca_crt: b"ca".to_vec(),
            node_crt: b"crt".to_vec(),
            node_key: b"key".to_vec(),
            leaves: vec![("svc-vllm.crt".into(), b"lc".to_vec()), ("svc-vllm.key".into(), b"lk".to_vec())],
            secret_files_script: b"agent_secret_files ...\n".to_vec(),
        }
    }

    /// The local lane's bundle carries the controller's own NATS pair as
    /// `nats-creds`, the kind the rail lane uses, from the same payload.
    #[test]
    fn the_local_bundle_carries_this_nodes_nats_creds() {
        let b = local_bundle("ctrl", inputs(creds("ctrl", "pw-1"))).expect("bundle");
        let kinds: Vec<&str> = b.iter().map(|(k, _)| k.as_str()).collect();
        let nc = b.iter().find(|(k, _)| k == "nats-creds").expect("nats-creds is staged");
        let text = String::from_utf8_lossy(&nc.1);
        assert!(text.contains("NATS_NODE_USER=node-ctrl\n") && text.contains("NATS_NODE_PASSWORD=pw-1\n"), "{text}");
        // Merged after agent-env, which replaces the env whole.
        let pos = |k: &str| kinds.iter().position(|x| *x == k).unwrap();
        assert!(pos("agent-env") < pos("nats-creds"));
        for k in ["ca.crt", "node.crt", "node.key", "svc-vllm.crt", "svc-vllm.key", "agent-binary", "agent-unit", "secret-files"] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
    }

    /// i276: the controller's own node gets the signing public key from the
    /// local install, installed the way noo-apply installs it, and the
    /// controller then records the adoption it has just proved.
    #[test]
    fn the_local_install_delivers_the_signing_key_and_records_the_adoption() {
        let b = local_bundle("ctrl", inputs(creds("ctrl", "pw-1"))).unwrap();
        assert!(b.iter().any(|(k, body)| k == "signing-pub" && body.starts_with(b"-----BEGIN PUBLIC KEY")), "signing-pub is staged");
        let s = script(&["signing-pub"], false);
        assert!(s.contains("\"/w/signing-pub\" /etc/noo/pki/signing.pub"), "{s}");
        assert!(!script(&["agent-binary"], true).contains("signing.pub"), "unchanged key: not reinstalled");

        let dir = std::env::temp_dir().join(format!("noo-i276-adopt-{}", std::process::id()));
        let ca = crate::pki::ClusterCa::new(dir.clone());
        assert!(!ca.signing_adopted("ctrl"));
        mark_signing_adopted(&ca, "ctrl", b"-----BEGIN PUBLIC KEY-----\nsp\n-----END PUBLIC KEY-----\n");
        assert!(ca.signing_adopted("ctrl"), "the marker `cluster verify` reads is written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_credential_for_another_node_or_without_a_pair_is_refused() {
        assert!(local_bundle("ctrl", inputs(creds("other", "pw"))).unwrap_err().contains("names 'other'"));
        assert!(local_bundle("ctrl", inputs(creds("ctrl", ""))).unwrap_err().contains("no complete pair"));
        assert!(local_bundle("ctrl", inputs(b"NODE=ctrl\n".to_vec())).is_err());
    }

    #[test]
    fn only_what_differs_from_the_last_install_is_changed() {
        let b = local_bundle("ctrl", inputs(creds("ctrl", "pw-1"))).unwrap();
        assert_eq!(changed_kinds(&b, &BTreeMap::new()).len(), b.len(), "no record: everything installs");
        let mut rec = parse_lane_state(&render_lane_state(&b));
        assert!(changed_kinds(&b, &rec).is_empty(), "a faithful record: nothing to install");
        rec.insert("agent-binary".into(), sha256_hex(b"an older agent"));
        let only: Vec<String> = changed_kinds(&b, &rec).into_iter().collect();
        assert_eq!(only, vec!["agent-binary".to_string()]);
    }

    fn script(changed: &[&str], restart: bool) -> String {
        let changed: std::collections::BTreeSet<String> = changed.iter().map(|s| s.to_string()).collect();
        let leaves = vec!["svc-vllm.crt".to_string(), "svc-vllm.key".to_string()];
        local_install_script(&LocalScript {
            node: "ctrl", work: Path::new("/w"), changed: &changed, prep: None,
            secret_files: "", leaves: &leaves, restart,
        })
    }

    #[test]
    fn nothing_changed_installs_nothing_and_does_not_restart() {
        let s = script(&[], false);
        assert!(!s.contains("install -m"), "{s}");
        assert!(!s.contains("systemctl restart"), "{s}");
        assert!(s.contains("nats_pair_ok /etc/noo-node-agent.env 'node-ctrl'"), "the pair is checked every time");
    }

    #[test]
    fn a_new_binary_reinstalls_only_the_binary() {
        let s = script(&["agent-binary"], true);
        assert!(s.contains("/w/agent-binary\" /usr/local/bin/noo-node-agent"));
        for not in ["/w/node.key", "/w/agent-env", "/w/agent-unit", "/w/svc-vllm.key"] {
            assert!(!s.contains(not), "{not} reinstalled for a binary change:\n{s}");
        }
    }

    #[test]
    fn the_env_install_merges_nats_creds_after_agent_env() {
        let s = script(&["agent-env"], true);
        let env = s.find("\"/w/agent-env\" /etc/noo-node-agent.env").expect("env installed");
        let merge = s.find("\"/w/nats-creds\" >>").expect("nats-creds merged");
        let check = s.find("nats_pair_ok /etc/noo-node-agent.env").unwrap();
        let restart = s.find("systemctl restart").unwrap();
        assert!(env < merge && merge < check && check < restart, "{s}");
    }

    /// Fail loud: an env with no pair stops the script with the dedicated
    /// exit BEFORE the restart, so "installed and registered" never prints
    /// and a running agent keeps the pair in its process env.
    #[test]
    fn an_env_without_a_pair_fails_loud_before_the_restart() {
        let dir = std::env::temp_dir().join(format!("noo-local-lane-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join("agent.env");
        let pwfile = dir.join("NATS_NODE_PASSWORD");
        let run = |body: &str| {
            std::fs::write(&env, body).unwrap();
            let s = script(&[], true).replace("/etc/noo-node-agent.env", &env.display().to_string());
            let out = Command::new("sh").arg("-c")
                .arg(format!("systemctl() {{ echo RESTARTED; }}\n{s}")).output().unwrap();
            (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string())
        };
        let (code, out) = run("NODE_ID=ctrl\n");
        assert_eq!(code, Some(NATS_PAIR_MISSING_EXIT));
        assert!(!out.contains("RESTARTED"));
        assert_eq!(run("NODE_ID=ctrl\nNATS_NODE_USER=node-other\nNATS_NODE_PASSWORD=x\n").0, Some(NATS_PAIR_MISSING_EXIT));
        let (code, out) = run("NODE_ID=ctrl\nNATS_NODE_USER=node-ctrl\nNATS_NODE_PASSWORD=pw\n");
        assert_eq!(code, Some(0));
        assert!(out.contains("RESTARTED"));
        // The secret-files layout: a pointer to a non-empty file is a pair,
        // a pointer to an empty one is not.
        std::fs::write(&pwfile, "").unwrap();
        let ptr = format!("NODE_ID=ctrl\nNATS_NODE_USER=node-ctrl\nNATS_NODE_PASSWORD_FILE={}\n", pwfile.display());
        assert_eq!(run(&ptr).0, Some(NATS_PAIR_MISSING_EXIT));
        std::fs::write(&pwfile, "pw").unwrap();
        assert_eq!(run(&ptr).0, Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// i67: the first install carries the node identity: the keypair (when
    /// the box has none) before host prep; no root-written gateway copy.
    #[test]
    fn the_first_install_leaves_the_pull_units_behind() {
        let changed = std::collections::BTreeSet::new();
        let s = local_install_script(&LocalScript {
            node: "ctrl", work: Path::new("/w"), changed: &changed, prep: Some("PREP_LINE\n"),
            secret_files: "", leaves: &[], restart: false,
        });
        assert!(s.contains(&self_identity_script("ctrl", Path::new("/w"), Path::new("/etc/noo"), "PREP_LINE\n")), "{s}");
        let gen = s.find("openssl req -x509 -newkey rsa:4096").expect("keypair generated");
        let prep = s.find("PREP_LINE").expect("prep runs");
        assert!(gen < prep, "{s}");
        assert!(!s.contains("/etc/noo/self-node"), "no root-written copy for the gateway: {s}");
        assert!(!script(&[], false).contains("openssl req"), "no prep: no identity step");
        let whole = include_str!("provision.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap();
        assert!(src.contains(r#".arg(format!("PREP_BIRTH_KEY={}/birth.key", work.display()))"#));
        assert!(src.contains("let prep_cmd = if prep_current && units_missing.is_empty()"),
            "prep re-runs while a pull unit is missing");
    }

    #[test]
    fn the_prep_marker_is_current_only_for_this_prep_and_these_inputs() {
        let m = "# Written by scripts/prep-host.sh\nPREPPED_VERSION=1\nNOO_DATA_ROOT=/d\nENROLL_USER=op\n\
                 PREP_SHA256=abc\nPREP_NODE_NAME=ctrl\nPREP_NOO_URL=https://c:8080\nPREP_RELEASE=0.6.0/v0.6.0\n";
        let want = [("PREP_SHA256", "abc"), ("NOO_DATA_ROOT", "/d"), ("ENROLL_USER", "op"),
                    ("PREP_NODE_NAME", "ctrl"), ("PREP_NOO_URL", "https://c:8080"), ("PREP_RELEASE", "0.6.0/v0.6.0")];
        assert!(prep_marker_current(m, &want));
        assert!(!prep_marker_current(&m.replace("abc", "def"), &want), "a changed prep re-runs");
        assert!(!prep_marker_current(&m.replace("0.6.0/v0.6.0", "0.6.1/v0.6.1"), &want), "a new release re-runs");
        assert!(!prep_marker_current(&m.replace("PREP_SHA256=abc\n", ""), &[("NOO_DATA_ROOT", "/d")]),
            "a marker from an older prep (no digest) is not current");
    }

    #[test]
    fn the_prep_line_carries_the_pin_beside_the_insecure_switch() {
        let mut c = Command::new("env");
        c.arg("PREP_INSECURE=1").arg("PREP_CA_SHA256=ab").arg("NOO_DATA_ROOT=/a b").arg("bash").arg("/tmp/p'q.sh");
        assert_eq!(command_line(&c),
            "'env' 'PREP_INSECURE=1' 'PREP_CA_SHA256=ab' 'NOO_DATA_ROOT=/a b' 'bash' '/tmp/p'\\''q.sh'");
    }

    // ── a binary the node proved it runs is not carried again ──────────

    fn st(rc: i64, staged: &str, applied: &str, msg: &str) -> serde_json::Value {
        serde_json::json!({ "sha256": staged, "applied_sha": applied, "apply_rc": rc, "apply_msg": msg })
    }
    fn report_with(kind: &str, sha: &str) -> String {
        format!("noo-apply: x applied: agent-env {kind}=unchanged verified-by: signing-key ca-lane: retired binary-sha: {kind}={sha}")
    }

    #[test]
    fn omission_needs_the_nodes_own_proof() {
        let bytes = b"\x7fELFgateway".to_vec();
        let sha = sha256_hex(&bytes);
        let ok = st(0, "b1", "b1", &report_with("harness-binary", &sha));
        // No status at all (never staged): carry.
        assert!(!node_runs_asset(None, "harness-binary", &sha));
        // An applier that prints no binary-sha line: carry.
        assert!(!node_runs_asset(Some(&st(0, "b1", "b1", "applied: harness-binary")), "harness-binary", &sha));
        // Proven: the report is about the staged bundle, rc 0, and states this sha.
        assert!(node_runs_asset(Some(&ok), "harness-binary", &sha));
        // The last apply was refused: carry.
        assert!(!node_runs_asset(Some(&st(65, "b1", "b1", &report_with("harness-binary", &sha))), "harness-binary", &sha));
        // The report belongs to an older bundle than the staged one: carry.
        assert!(!node_runs_asset(Some(&st(0, "b2", "b1", &report_with("harness-binary", &sha))), "harness-binary", &sha));
        // Nothing applied yet (null applied_sha): carry.
        assert!(!node_runs_asset(Some(&serde_json::json!({"sha256": "b1", "applied_sha": null, "apply_rc": null, "apply_msg": null})), "harness-binary", &sha));
        // The asset changed since the node's statement: carry.
        assert!(!node_runs_asset(Some(&ok), "harness-binary", &sha256_hex(b"newer")));
        // A statement about another kind proves nothing about this one.
        assert!(!node_runs_asset(Some(&ok), "agent-binary", &sha));
    }

    #[test]
    fn dropping_removes_only_proven_binary_kinds() {
        let hb = b"harness-bytes".to_vec();
        let cb = b"cli-bytes".to_vec();
        let mk = || -> Vec<(&'static str, Vec<u8>)> { vec![
            ("agent-env", b"E".to_vec()), ("agent-binary", b"agent".to_vec()), ("hostd-binary", b"hostd".to_vec()),
            ("cli-binary", cb.clone()), ("cli-user", b"u".to_vec()), ("harness-binary", hb.clone()),
            ("harness-env", b"H".to_vec()), ("applier", b"A".to_vec()), ("fetcher", b"F".to_vec()),
            ("ca.crt", b"C".to_vec()), ("node.crt", b"N".to_vec()), ("node.key", b"K".to_vec()),
        ] };
        let msg = format!("applied: x binary-sha: harness-binary={} cli-binary={} agent-binary={} hostd-binary={}",
            sha256_hex(&hb), sha256_hex(&cb), sha256_hex(b"agent"), sha256_hex(b"hostd"));
        let status = st(0, "s", "s", &msg);
        fn names<'a>(f: &[(&'a str, Vec<u8>)]) -> Vec<&'a str> { f.iter().map(|(k, _)| *k).collect() }

        let mut f = mk();
        let notes = drop_proven_binaries(&mut f, Some(&status), false, false);
        assert_eq!(notes.len(), 4, "{notes:?}");
        assert!(notes.iter().all(|n| n.contains("unchanged since last apply, not carried")));
        assert_eq!(names(&f), ["agent-env", "harness-env", "applier", "fetcher", "ca.crt", "node.crt", "node.key"],
            "env, unit, cert, applier and fetcher kinds are never omitted (cli-user leaves with its binary)");

        // No state: everything rides.
        let mut f = mk();
        assert!(drop_proven_binaries(&mut f, None, false, false).is_empty());
        assert_eq!(f.len(), 12);

        // A Mac keeps agent-binary (its applier demands it); the controller's own node keeps hostd.
        let mut f = mk();
        drop_proven_binaries(&mut f, Some(&status), true, false);
        assert!(names(&f).contains(&"agent-binary") && !names(&f).contains(&"hostd-binary"));
        let mut f = mk();
        drop_proven_binaries(&mut f, Some(&status), false, true);
        assert!(names(&f).contains(&"hostd-binary") && !names(&f).contains(&"agent-binary"));

        // One asset changed: only that one rides.
        let mut f = mk();
        f.iter_mut().find(|(k, _)| *k == "harness-binary").unwrap().1 = b"harness-v2".to_vec();
        drop_proven_binaries(&mut f, Some(&status), false, false);
        assert!(names(&f).contains(&"harness-binary") && !names(&f).contains(&"cli-binary"));
    }

    #[test]
    fn mac_runners_put_noomesh_bin_first_on_path_for_staged_vendor_clis() {
        for (script, exec) in [(darwin_run_agent(), "exec \"$HOME/noomesh/bin/noo-node-agent\""),
                               (darwin_run_harness(), "exec \"$HOME/noomesh/bin/noo-gateway\" harness")] {
            let path_at = script.find("export PATH=\"$HOME/noomesh/bin:$PATH\"\n").expect("PATH export");
            let exec_at = script.find(exec).expect("exec line");
            let env_at = script.find("set -a; . \"$ENV_FILE\"; set +a").expect("env sourced");
            assert!(env_at < path_at && path_at < exec_at, "{script}");
        }
    }

    #[test]
    fn the_vendor_cli_drops_only_with_its_manifest() {
        let mk = || -> Vec<(&'static str, Vec<u8>)> { vec![
            ("agent-env", b"E".to_vec()), ("vendor-cli", b"cli".to_vec()), ("vendor-cli-manifest", b"{}".to_vec()),
        ] };
        fn names<'a>(f: &[(&'a str, Vec<u8>)]) -> Vec<&'a str> { f.iter().map(|(k, _)| *k).collect() }
        let proven = st(0, "s", "s", &format!("applied: vendor-cli=unchanged binary-sha: vendor-cli={}", sha256_hex(b"cli")));
        let mut f = mk();
        let notes = drop_proven_binaries(&mut f, Some(&proven), false, false);
        assert_eq!(names(&f), ["agent-env"], "{notes:?}");
        assert!(notes.iter().any(|n| n.starts_with("vendor CLI: unchanged")));
        // A CLI the node did not report running: the group rides.
        let other = st(0, "s", "s", &format!("applied: x binary-sha: vendor-cli={}", sha256_hex(b"other")));
        let mut f = mk();
        drop_proven_binaries(&mut f, Some(&other), false, false);
        assert_eq!(f.len(), 3);
        // Two slots: only the proven one stays home, with its own manifest.
        let mut f: Vec<(&'static str, Vec<u8>)> = vec![
            ("vendor-cli", b"cli".to_vec()), ("vendor-cli-manifest", b"{}".to_vec()),
            ("vendor-cli-2", b"cli2".to_vec()), ("vendor-cli-2-manifest", b"{}".to_vec()),
        ];
        let one = st(0, "s", "s", &format!("applied: vendor-cli-2=unchanged binary-sha: vendor-cli-2={} vendor-cli={}",
            sha256_hex(b"cli2"), sha256_hex(b"stale")));
        drop_proven_binaries(&mut f, Some(&one), false, false);
        assert_eq!(names(&f), ["vendor-cli", "vendor-cli-manifest"]);
    }

    #[test]
    fn binary_sha_parsing_takes_only_well_formed_pairs_after_the_last_marker() {
        let h = "a".repeat(64);
        let got = reported_binary_shas(&format!("binary-sha: old={} later text binary-sha: agent-binary={h} bad=zz short={}", "b".repeat(64), "c".repeat(63)));
        assert_eq!(got, vec![("agent-binary".to_string(), h)]);
        assert!(reported_binary_shas("applied: agent-binary").is_empty());
    }
}

#[cfg(test)]
mod bundle_status_judgement_tests {
    use super::{judge_bundle_status, legacy_fallback_due, BundleVerdict};
    use serde_json::json;

    const SHA: &str = "aaaa";

    #[test]
    fn applied_ok_is_rc_zero_with_the_appliers_message() {
        let st = json!({"fetched_at":"t","applied_at":"t","applied_sha":SHA,"apply_rc":0,"apply_msg":"applied: agent-env"});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Applied { rc: 0, msg: "applied: agent-env".into() });
    }

    #[test]
    fn applied_refused_carries_the_nonzero_rc() {
        let st = json!({"fetched_at":"t","applied_sha":SHA,"apply_rc":76,"apply_msg":"unknown kind"});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Applied { rc: 76, msg: "unknown kind".into() });
    }

    #[test]
    fn a_report_without_a_code_is_minus_one_not_success() {
        let st = json!({"applied_sha":SHA});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Applied { rc: -1, msg: String::new() });
    }

    #[test]
    fn fetched_but_not_applied_is_fetched() {
        let st = json!({"fetched_at":"t","applied_sha":null,"apply_rc":null});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Fetched);
    }

    #[test]
    fn an_older_bundles_report_is_not_evidence_about_this_one() {
        let st = json!({"fetched_at":null,"applied_sha":"old","apply_rc":0});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Nothing);
        let st = json!({"fetched_at":"t","applied_sha":"old","apply_rc":0});
        assert_eq!(judge_bundle_status(&st, SHA), BundleVerdict::Fetched);
    }

    #[test]
    fn nothing_reported_is_nothing() {
        assert_eq!(judge_bundle_status(&json!({}), SHA), BundleVerdict::Nothing);
        assert_eq!(judge_bundle_status(&json!({"fetched_at":null}), SHA), BundleVerdict::Nothing);
    }

    #[test]
    fn an_empty_staged_sha_never_matches_an_empty_report() {
        let st = json!({"applied_sha":"","apply_rc":0});
        assert_eq!(judge_bundle_status(&st, ""), BundleVerdict::Nothing);
    }

    #[test]
    fn the_legacy_fallback_needs_legacy_a_fetch_and_45_seconds() {
        assert!(legacy_fallback_due(true, true, 46));
        assert!(!legacy_fallback_due(true, true, 45));
        assert!(!legacy_fallback_due(true, false, 600), "never fetched: no fallback");
        assert!(!legacy_fallback_due(false, true, 600), "a node that reports is judged by its report");
    }
}

#[cfg(test)]
mod upgrade_stages_every_node_before_waiting_tests {
    /// `noo upgrade --nodes` must stage+poke every node before it blocks on
    /// any apply, and the self node (staged last) still comes after the
    /// remote nodes have been staged.
    #[test]
    fn the_nodes_phase_stages_all_then_waits_once() {
        let up = include_str!("upgrade.rs");
        let up = up.split("#[cfg(test)]").next().unwrap();
        let f = &up[up.find("fn upgrade_nodes(").unwrap()..];
        let f = &f[..f.find("\n}\n").unwrap()];
        let stage = f.find(r#"provision_one(g, n, &["--stage-only"])"#).expect("remote nodes are staged with --stage-only");
        let me = f.rfind("upgrade_self_node(g, me, &mut failed, &mut pending)").expect("the self node is staged into the same pending list");
        let wait = f.rfind("wait_and_settle_nodes(g, &pending").expect("the combined wait");
        let mac = f.find("mac_leaves_pass(").expect("the mac pass");
        assert!(stage < me && me < wait && wait < mac, "stage remotes, stage self node, one wait, then the Mac pass");
        assert_eq!(f.matches("provision_one(g, n,").count(), 1, "no per-node full provision left in the loop");
        assert_eq!(f.matches("wait_and_settle_nodes(g, &pending").count(), 2, "one wait for the nodes, one for a controller with no other node");
        assert!(!f.contains("provision_one(g, me"), "the self node is staged by upgrade_self_node only");
    }

    /// The self node's post-apply steps have ONE function with two callers:
    /// the single-node verb and the combined wait. Neither may grow its own
    /// copy (the lane record or the hostd restart), or they drift.
    #[test]
    fn the_self_nodes_post_apply_steps_have_one_function_and_two_callers() {
        let prov = include_str!("provision.rs");
        let prov = prov.split("#[cfg(test)]").next().unwrap();
        let up = include_str!("upgrade.rs");
        let up = up.split("#[cfg(test)]").next().unwrap();
        let verb = super::phase_src::body("await_apply");
        assert!(verb.contains("after_self_applied(g, &node, msg)"), "the single-node verb");
        let settle = &up[up.find("fn settle_end(").unwrap()..];
        let settle = &settle[..settle.find("\n}\n").unwrap()];
        assert!(settle.contains("after_self_applied(g, n, &msg)"), "the combined wait");
        for (name, body) in [("provision.rs", prov), ("upgrade.rs", up)] {
            assert_eq!(body.matches("refresh_controller_hostd(").count(), if name == "provision.rs" { 2 } else { 0 },
                "{name}: the hostd restart is called once (plus its definition), inside after_applied");
            assert_eq!(body.matches("write_self_lane(").count(), if name == "provision.rs" { 3 } else { 0 },
                "{name}: Rail lane written once in after_applied; the definition and the onboard lane are the others");
        }
    }

    /// The combined wait polls every 5 s (one cheap SELECT per node).
    #[test]
    fn the_combined_wait_polls_every_five_seconds() {
        let up = include_str!("upgrade.rs");
        assert!(up.contains("const NODES_APPLY_POLL_SECS: u64 = 5;"));
    }
}

/// What a same-uid process on a Mac could read: the environment the run
/// scripts hand to the agent and the harness. After the applier's
/// conversion it holds `NAME_FILE` pointers into `~/noomesh/…` (which the
/// harness jail denies) and no secret value — proved by running the real
/// runner with `env` in place of the binary.
#[cfg(test)]
mod mac_runner_env_tests {
    use super::{darwin_run_agent, darwin_run_harness};
    use crate::commands::agent_secret_files::{
        converge, converge_harness, AGENT_SECRET_CAPABILITY, AGENT_SECRET_KEYS, HARNESS_SECRET_CAPABILITY,
        HARNESS_SECRET_KEYS,
    };

    const VALUES: &[(&str, &str)] = &[
        ("NOO_NODE_AGENT_TOKEN", "tok-mac-1234"),
        ("NOO_CLUSTER_SECRET", "cluster-mac-5678"),
        ("NATS_NODE_PASSWORD", "nats-mac-9012"),
    ];

    fn exported(script: &str, exec_line: &str, home: &std::path::Path) -> String {
        let script = script.replace(exec_line, "exec /usr/bin/env");
        assert!(script.contains("exec /usr/bin/env"), "the exec line moved: {script}");
        let out = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(&script)
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn the_mac_runners_export_pointers_and_no_secret_value() {
        let home = std::env::temp_dir().join(format!("noo-mac-runner-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let base = home.join("noomesh");
        std::fs::create_dir_all(base.join("bin")).unwrap();
        let mut env = String::from("NODE_ID=host6\nNATS_NODE_USER=node-host6\nNOO_TLS_KEY=\"$HOME/noomesh/pki/node.key\"\n");
        for (k, v) in VALUES {
            env.push_str(&format!("{k}={v}\n"));
        }
        std::fs::write(base.join("agent.env"), &env).unwrap();
        std::fs::write(base.join("harness.env"), &env).unwrap();
        std::fs::write(base.join("bin/noo-node-agent"), format!("\u{cf}bin {AGENT_SECRET_CAPABILITY} x")).unwrap();
        std::fs::write(base.join("bin/noo-gateway"), format!("\u{cf}bin {HARNESS_SECRET_CAPABILITY} x")).unwrap();
        assert!(converge(&base.join("agent.env"), &base.join("secrets"), &base.join("bin/noo-node-agent")).unwrap());
        assert!(converge_harness(&base.join("harness.env"), &base.join("harness-secrets"), &base.join("bin/noo-gateway")).unwrap());
        for (script, exec, keys, dir) in [
            (darwin_run_agent(), "exec \"$HOME/noomesh/bin/noo-node-agent\"", AGENT_SECRET_KEYS, "secrets"),
            (darwin_run_harness(), "exec \"$HOME/noomesh/bin/noo-gateway\" harness", HARNESS_SECRET_KEYS, "harness-secrets"),
        ] {
            let got = exported(&script, exec, &home);
            for (k, v) in VALUES {
                assert!(!got.contains(v), "{k}'s value is in the {dir} runner's environment:\n{got}");
            }
            for k in keys {
                let want = format!("{k}_FILE={}", base.join(dir).join(k).display());
                assert!(got.lines().any(|l| l == want), "{want} missing:\n{got}");
                assert!(!got.lines().any(|l| l.starts_with(&format!("{k}="))), "{k} plain:\n{got}");
            }
            assert!(got.lines().any(|l| l == "NODE_ID=host6"));
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// Test support: the non-test source of this file, sliced so a test asserts
/// the ORDER of the phase list (`list`) or the CONTENT of the one phase that
/// owns a behaviour (`body`), or reads the whole verb (`verb`).
#[cfg(test)]
pub(crate) mod phase_src {
    fn code() -> &'static str {
        include_str!("provision.rs").split("#[cfg(test)]").next().expect("non-test source")
    }

    /// `fn <name>(` through the first column-0 closing brace.
    pub(crate) fn body(name: &str) -> &'static str {
        let code = code();
        let start = code.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("fn {name} not found in provision.rs"));
        let rest = &code[start..];
        &rest[..rest.find("\n}\n").unwrap_or_else(|| panic!("end of fn {name}"))]
    }

    /// The ordered phase list of `noo cluster provision`.
    pub(crate) fn list() -> &'static str {
        body("cluster_provision")
    }

    /// The whole rail verb: the phase list through the last phase it runs.
    pub(crate) fn verb() -> &'static str {
        let code = code();
        let start = code.find("pub fn cluster_provision(").expect("cluster_provision");
        let last = body("report_provisioned");
        let end = code.find(last).expect("last phase") + last.len();
        &code[start..end]
    }
}

#[cfg(test)]
mod darwin_harness_plist_tests {
    /// launchd sends SIGKILL `ExitTimeOut` seconds after SIGTERM (default
    /// 20): the harness drains for NOO_HARNESS_DRAIN_SECS (120) on a stop, so
    /// the plist leaves it that plus 30 s, like the unit's TimeoutStopSec.
    #[test]
    fn the_harness_plist_leaves_time_to_drain() {
        assert!(super::DARWIN_HARNESS_PLIST.contains("<key>ExitTimeOut</key><integer>150</integer>"));
    }
}
