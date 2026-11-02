// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster push-secrets` — converge the FLEET-WIDE secrets onto every node.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! Why this exists
//! ─────────────────────────────────────────────────────────────────────────
//!
//! `NOO_CLUSTER_SECRET` and `NOO_NODE_AGENT_TOKEN` are held by EVERY node
//! (the shared `NATS_USER`/`NATS_PASSWORD` pair was too, until an earlier release
//! retired it), in `~/pai-assistant/.env`, written
//! exactly once — at node-provisioning time (historically by the retired
//! `ansible/templates/worker.env.j2`). Nothing else in the tree has ever
//! written one again:
//!
//!   - `noo cluster init-secret` only PRINTS a value.
//!   - `noo cluster upgrade-agents` restages provision bundles
//!     A3 retired its binary swap): it writes the value the controller
//!     already runs, never a new one.
//!
//! So `noo security secrets rotate` refuses these keys (see
//! `secrets::fleet_refusal`) and hands the operator a seven-step manual
//! procedure. This command is the missing half of that procedure: the part
//! that gets a value from the controller's store onto the nodes.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! What it is, precisely: CONVERGENCE, not rotation
//! ─────────────────────────────────────────────────────────────────────────
//!
//! This command has exactly one direction: it moves a NODE toward the value
//! the CONTROLLER is already running. It never mints a value, never writes
//! the store, and never changes the controller. That single property is what
//! makes it safe to run against a live fleet in any order, on any subset:
//!
//!   * A node that already matches is skipped — untouched.
//!   * A node that differs is, by construction, a node that is ALREADY
//!     failing to authenticate against this controller (or is about to, the
//!     next time its container restarts). Moving it onto the controller's
//!     value can only take it from broken to working.
//!
//! There is therefore NO mid-roll ordering hazard *inside this command*. The
//! usual "half the fleet has the new value and half the old" window cannot
//! arise here, because the reference — the controller — is a fixed point for
//! the whole run. Half-converged is strictly better than un-converged, and
//! the un-converged nodes were the broken ones to begin with.
//!
//! The ordering hazard is real, but it lives one step earlier, in the STORE
//! WRITE that a rotation performs. See `ORDERING.md` — reproduced in
//! `rotation_hazard_note()` below — for what the gateway and the node-agent
//! actually accept during that window. Short version, verified against the
//! verifiers rather than assumed:
//!
//!   * `NOO_CLUSTER_SECRET` — symmetric HMAC, read from a SINGLE env var on
//!     both sides (`gateway-rust/src/auth.rs verify_cluster_token`,
//!     `node-agent-go/internal/auth/middleware.go verifyClusterToken`).
//!     Neither verifier has a second/previous-secret slot. There is NO safe
//!     online rotation today. (PR #388's dual-accept is about signature
//!     WIDTH — 32- vs 64-hex — not about two secret VALUES. It does not help.)
//!   * `NOO_NODE_AGENT_TOKEN` — one-directional (controller → node). The
//!     node-agent accepts EITHER this static bearer OR a cluster-HMAC token,
//!     which looks like a free dual-accept window… and is not one. See the
//!     note below; the Python callers' HMAC fallback emits a 32-hex signature
//!     that the Go node-agent explicitly rejects, and Prometheus interpolates
//!     the raw token into its scrape config.
//!   * (`NATS_PASSWORD` is no longer fleet-wide: the shared bus user is
//!     retired; each node's own pair rotates with `nats-creds rotate`,
//!     which delivers before it re-renders.)
//!
//! So this command deliberately does NOT offer a `--rotate`. It converges.
//! Rotation remains: write the store by hand (an outage begins), then run
//! this (the outage ends). That is honest about the outage instead of hiding
//! it inside a flag.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! Secret hygiene
//! ─────────────────────────────────────────────────────────────────────────
//!
//! No secret value is ever placed in an argv, a log line, or a shell — not
//! locally, not on the node. A value leaves this process exactly once: inside
//! a CA-signed bundle, CMS-encrypted to the receiving node's own birth
//! certificate, staged at the gateway for that node to collect. Output
//! carries key names, set/blank/absent states and digests — never a value.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! Why the rail, and not SSH
//! ─────────────────────────────────────────────────────────────────────────
//!
//! This command used to `ssh` to each node, digest-probe `~/pai-assistant/.env`,
//! write the differing keys, and re-probe. Two things were wrong with that,
//! and only the second is about security:
//!
//!   1. It converged a file nothing reads. The node-agent became a HOST
//!      PROCESS reading `/etc/noo-node-agent.env`; `~/pai-assistant/.env` is
//!      the retired container era's compose env. The re-probe read back the
//!      file the write had just made, so the command CONFIRMED ITSELF and
//!      reported `pushed — written and re-verified` while the running agent
//!      kept its old credential.
//!   2. The only key the mesh installs on a node is pinned
//!      `command="/usr/local/bin/noo-gate",restrict` — a forced command that
//!      discards the requested one. `sh -c …` was never a thing a
//!      mesh-provisioned key could carry; this worked only from an operator's
//!      own workstation key, which is out-of-band by design.
//!
//! So delivery is `fleet-secrets`: a bundle kind carrying a dotenv fragment
//! the applier MERGES into `/etc/noo-node-agent.env`, exactly as `nats-creds`
//! does. A merge and not a re-render, because the controller cannot re-render
//! a live node's env without also re-deciding its tier, data root and image
//! tag from the controller's CURRENT defaults — a config change wearing a
//! credential's clothes.
//!
//! What is lost is the per-node probe, and with it the "already matches —
//! skipped" line. Nothing is lost by it: the merge is idempotent, and a node
//! that already holds the value takes a payload identical to what it has. The
//! honest report is now `Queued`, not `Done` — the applier is the judge, and
//! it reports back through the fetch rail.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

use super::secrets::{SecretStore, State};
use crate::args::{ArgError, Args};
use crate::output::{fail, ExitCode};
use crate::{envfile, Globals, Unhandled};
use crate::ui::{self, Glyph};

// ─────────────────────────────────────────────────────────────────────────
// The fleet-wide key registry
// ─────────────────────────────────────────────────────────────────────────

/// One fleet-wide key: the env name the node's `.env` uses, and what breaks
/// on this node while it disagrees with the controller.
pub(crate) struct FleetKey {
    pub key: &'static str,
    /// What a disagreement costs, in the operator's terms.
    pub consequence: &'static str,
}

/// The keys node provisioning hands the agent, and the agent env writes.
/// Kept in the same order and with the same names on purpose — this list and
/// that one are the same fact, and they must not drift apart.
pub(crate) const FLEET_KEYS: &[FleetKey] = &[
    FleetKey {
        key: "NOO_CLUSTER_SECRET",
        consequence: "node-agent → gateway heartbeats and gateway → node-agent calls both fail \
                      HMAC verification; the node goes OFFLINE after 2 minutes and the failure \
                      surfaces as timeouts, not as auth errors",
    },
    FleetKey {
        key: "NOO_NODE_AGENT_TOKEN",
        consequence: "gateway → node-agent calls (start/stop backend, models, sensors) are \
                      rejected 403; heartbeats still work, so the node looks ONLINE while every \
                      command to it fails",
    },
    // NATS_USER / NATS_PASSWORD were fleet keys until an earlier release retired the
    // shared bus user: a node's bus credential is its OWN pair now, minted and
    // delivered by `noo cluster nats-creds rotate <node>` (the `nats-creds`
    // bundle kind), never converged fleet-wide.
];


/// A key name is interpolated into a remote shell script and an `awk -v`
/// assignment, so it is validated rather than trusted. Every name in
/// `FLEET_KEYS` passes; this guards a future edit that adds a careless one.
pub(crate) fn is_safe_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

// ─────────────────────────────────────────────────────────────────────────
// The controller-side interlock
// ─────────────────────────────────────────────────────────────────────────

/// What we established about the CONTROLLER's live value for one key, by
/// reading the running gateway container's own environment.
///
/// This exists because the command's entire safety argument rests on "the
/// controller's store value is what the fleet is authenticating with". If
/// that is false — the store was edited but the gateway was never recreated,
/// which `CLAUDE.md` warns about explicitly ("Env changes need a container
/// RECREATE, not a restart") — then pushing the store value would take every
/// currently-WORKING node and break it. That is the one way this command
/// could do harm, so it is checked first, per key, and it refuses.
///
/// `docker exec … printenv` is used rather than `docker compose config`
/// deliberately: `CLAUDE.md` records that compose reads `.env` and not what
/// the launcher injects, so `compose config` is the misleading answer here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControllerCheck {
    /// The running gateway's env matches the store. The store is the fleet's
    /// live reference and may be pushed.
    Agrees,
    /// The running gateway holds a DIFFERENT value from the store. Pushing
    /// the store would break every node that currently works.
    Disagrees,
    /// The gateway does not carry this variable at all, so the store cannot
    /// be confirmed as the live reference from here.
    NotInGateway,
    /// The gateway container could not be inspected. Not evidence of
    /// anything — emphatically not evidence that the store is correct.
    Unknown,
}

/// What to do about one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PushAction {
    /// Put this key in the bundle.
    Deliver,
    /// Report what would be delivered, stage nothing.
    WouldDeliver,
    /// Declined, with the reason. Counts as a failure for the exit code.
    Refuse(&'static str),
}

/// THE decision table. Pure, so every branch is tested without a fleet, a
/// gateway, or a secret.
///
/// It is now a per-KEY decision rather than a per-(node, key) one, because
/// the rail removed the probe: a merge is idempotent, so "does this node
/// already have it?" stopped being a question worth a round trip. What
/// survives is the half that was doing the real work — the two interlocks
/// that decide whether the store value is a thing the fleet should be
/// converged onto at all. Neither has ever been about the transport.
///
/// Read it as: **the store is delivered only when the RUNNING gateway
/// confirms it is the fleet's live reference.** There is no cell where an
/// unreadable reference is treated as a good one.
pub(crate) fn push_action(
    controller: ControllerCheck,
    store_state: StoreState,
    dry_run: bool,
) -> PushAction {
    // The controller interlock outranks everything. If the store is not
    // demonstrably what the fleet is running on, nothing below is meaningful.
    match controller {
        ControllerCheck::Disagrees => {
            return PushAction::Refuse(
                "the RUNNING gateway holds a different value than the store — the store is not \
                 what this fleet is authenticating with, and delivering it would break every node \
                 that currently works. Recreate the gateway first (env changes need a recreate, \
                 not a restart), then re-run",
            )
        }
        ControllerCheck::NotInGateway => {
            return PushAction::Refuse(
                "the running gateway does not carry this variable, so the store value cannot be \
                 confirmed as the fleet's live reference from here",
            )
        }
        ControllerCheck::Unknown => {
            return PushAction::Refuse(
                "the gateway container could not be inspected — that is not evidence the store \
                 is correct, and converging a fleet on the strength of an unreadable reference \
                 is not a repair",
            )
        }
        ControllerCheck::Agrees => {}
    }

    // Nothing to deliver is not a fault, but it is never a delivery either.
    match store_state {
        StoreState::Missing => PushAction::Refuse(
            "the key is not in the controller's store, so there is no value to converge on",
        ),
        StoreState::Blank => PushAction::Refuse(
            "the stored value is blank; pushing a blank credential to the fleet is a \
             different operation from converging one, and this command does not do it",
        ),
        StoreState::Set if dry_run => PushAction::WouldDeliver,
        StoreState::Set => PushAction::Deliver,
    }
}

/// The store's own three-state view of a key, matching `secrets::State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreState {
    Set,
    Blank,
    Missing,
}

// ─────────────────────────────────────────────────────────────────────────
// Digests — the only representation of a value that ever leaves this process
// ─────────────────────────────────────────────────────────────────────────

/// `sha256(salt || payload || "\n")`, first 16 hex chars.
///
/// The trailing newline is not decoration: the remote side produces the
/// payload with `sed`, whose output is newline-terminated, and pipes it
/// straight into `sha256sum` so the value never becomes an argv element.
/// Matching that byte-for-byte here is what makes the two digests comparable.
pub(crate) fn salted_digest(salt: &str, payload: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(payload.as_bytes());
    h.update(b"\n");
    hex::encode(h.finalize())[..16].to_string()
}

/// A per-run, non-secret salt. Fresh each run so a digest published in a log
/// is not a stable fingerprint that could be matched across runs or hosts.
fn fresh_salt() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(std::process::id().to_le_bytes());
    h.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    // Address-space entropy: cheap, and enough on top of pid+nanos for a
    // value whose only job is to be unpredictable to a log reader.
    let anchor = Box::new(0u8);
    h.update((&*anchor as *const u8 as usize).to_le_bytes());
    hex::encode(h.finalize())[..24].to_string()
}

// ─────────────────────────────────────────────────────────────────────────
// The controller-side reference
// ─────────────────────────────────────────────────────────────────────────

/// `docker exec <container> printenv <KEY>` on the CONTROLLER.
///
/// Deliberately `printenv` inside the running container, not `docker compose
/// config`: `CLAUDE.md` records that compose reads `.env` rather than what
/// the launcher injects, so `compose config` answers a different question.
fn gateway_env_digest(container: &str, key: &str, salt: &str) -> Option<Option<String>> {
    let out = Command::new("docker")
        .args(["exec", container, "printenv", key])
        .output()
        .ok()?;
    if !out.status.success() {
        // `printenv` exits 1 for an unset variable — that is an answer ("not
        // in the gateway"), distinct from docker itself failing. Docker
        // failing writes to stderr; an unset var does not.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.trim().is_empty() {
            return Some(None);
        }
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let v = raw.strip_suffix('\n').unwrap_or(&raw);
    if v.is_empty() {
        return Some(None);
    }
    Some(Some(salted_digest(salt, v)))
}

fn container_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────
// The command
// ─────────────────────────────────────────────────────────────────────────

/// What `noo cluster push-secrets` was asked for.
pub(crate) struct PushSecretsArgs {
    node_args: Vec<String>,
    dry_run: bool,
    yes: bool,
    gateway_container: Option<String>,
    sops_path: Option<PathBuf>,
    explain: bool,
}

pub(crate) fn parse_push_secrets_with(a: &mut Args) -> Result<PushSecretsArgs, ArgError> {
    let dry_run = a.flag(&["--dry-run"]);
    let explain = a.flag(&["--explain"]);
    let yes = a.flag(&["--yes", "-y"]);
    let gateway_container = a.value(&["--gateway-container"])?;
    let sops_path = a.value(&["--sops-file"])?.map(PathBuf::from);
    let node_args = a.positionals()?;
    Ok(PushSecretsArgs { node_args, dry_run, yes, gateway_container, sops_path, explain })
}

/// `noo cluster push-secrets [NODES…] [--dry-run] [--gateway-container C]
///  [--sops-file P] [--explain] [-y|--yes] [--json]`
///
/// `--key` is gone on purpose. The rail's unit of delivery is one signed,
/// node-addressed bundle; a fragment naming one key and a fragment naming
/// every key cost the same round trip, and the applier merges either identically.
/// Keeping the flag would have meant a filter that changes nothing about
/// what happens — a knob that reads like control and is not.
pub fn cluster_push_secrets(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let PushSecretsArgs { node_args, dry_run, yes, gateway_container, sops_path, explain } =
        parse_push_secrets_with(&mut Args::new(args))?;
    let gateway_container = gateway_container.unwrap_or_else(|| crate::envfile::container("gateway"));

    // `--explain` answers the question this command's existence raises —
    // "why can't it just rotate?" — without contacting anything at all.
    if explain {
        if g.json {
            println!("{}", json!({ "ordering": rotation_hazard_note() }));
        } else {
            println!("{}", rotation_hazard_note());
        }
        return Ok(0);
    }

    for fk in FLEET_KEYS {
        if !is_safe_key_name(fk.key) {
            fail(g.json, ExitCode::Generic, "unsafe_key_name", &format!("{} is not a safe env name", fk.key), None);
        }
    }

    // Load the store. Never written, never echoed.
    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    let sops = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "sops_decrypt_failed",
            &e,
            Some("push-secrets decrypts in memory only; it never writes plaintext to disk"),
        ),
    };

    let salt = fresh_salt();

    // ── The controller interlock, per key, BEFORE any bundle is built.
    if !container_running(&gateway_container) {
        fail(
            g.json,
            ExitCode::Generic,
            "gateway_down",
            &format!(
                "{gateway_container} is not running, so the fleet's live reference value cannot \
                 be read"
            ),
            Some(
                "this is a different problem from a drifted node: a stopped gateway means the \
                 store has not been proven to be what the fleet authenticates with. Start it \
                 (`noo stack start`) and re-run.",
            ),
        );
    }

    let mut store_state: BTreeMap<&str, StoreState> = BTreeMap::new();
    let mut controller: BTreeMap<&str, ControllerCheck> = BTreeMap::new();
    for fk in FLEET_KEYS {
        let st = match sops.state(fk.key) {
            State::Missing => StoreState::Missing,
            State::Blank => StoreState::Blank,
            State::Set => StoreState::Set,
        };
        store_state.insert(fk.key, st);
        let sd = sops.salted_digest(fk.key, &salt);
        let check = match (st, gateway_env_digest(&gateway_container, fk.key, &salt)) {
            // Nothing stored: the interlock is moot, the store check refuses
            // first. Report Agrees so the refusal names the real cause.
            (StoreState::Missing | StoreState::Blank, _) => ControllerCheck::Agrees,
            (_, None) => ControllerCheck::Unknown,
            (_, Some(None)) => ControllerCheck::NotInGateway,
            (_, Some(Some(live))) => {
                if Some(&live) == sd.as_ref() {
                    ControllerCheck::Agrees
                } else {
                    ControllerCheck::Disagrees
                }
            }
        };
        controller.insert(fk.key, check);
    }

    // ── Decide the key set ONCE. Same decision for every node: the store and
    // the gateway are the only inputs, and neither varies per node.
    let mut deliver: Vec<&FleetKey> = Vec::new();
    let mut refused: Vec<(&str, &'static str)> = Vec::new();
    let mut would: Vec<&FleetKey> = Vec::new();
    for fk in FLEET_KEYS {
        match push_action(controller[fk.key], store_state[fk.key], dry_run) {
            PushAction::Deliver => deliver.push(fk),
            PushAction::WouldDeliver => would.push(fk),
            PushAction::Refuse(why) => refused.push((fk.key, why)),
        }
    }

    // ── Node list. Same source as `upgrade-agents`: the gateway's registry.
    let body = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let registered: Vec<Value> = body["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|n| n["id"].is_string())
        .cloned()
        .collect();
    let local = Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let target_ids: Vec<String> = if !node_args.is_empty() {
        node_args.clone()
    } else {
        registered
            .iter()
            .filter_map(|n| n["id"].as_str().map(String::from))
            .collect()
    };
    // The controller is never a target: it IS the reference, and it holds
    // these values in the sops store, not in a node env.
    let targets: Vec<String> = target_ids.into_iter().filter(|t| *t != local).collect();
    for t in &targets {
        if !registered.iter().any(|n| n["id"].as_str() == Some(t.as_str())) {
            fail(
                g.json,
                ExitCode::Generic,
                "not_registered",
                &format!("Node '{t}' is not registered with the gateway"),
                None,
            );
        }
    }
    if targets.is_empty() {
        if !g.json {
            println!("{}", ui::muted("no remote nodes to converge"));
        }
        return Ok(0);
    }

    // ── Plan.
    if !g.json {
        println!("{}", ui::phase(if dry_run { "plan (dry run)" } else { "plan" }));
        print!(
            "{}",
            ui::kv(&[
                ("store", sops_path.display().to_string()),
                ("delivery", "fleet-secrets bundle over the pull rail".into()),
            ])
        );
        for fk in FLEET_KEYS {
            let st = match store_state[fk.key] {
                StoreState::Set => ui::ok("set"),
                StoreState::Blank => ui::warn("blank"),
                StoreState::Missing => ui::err("missing"),
            };
            let ck = match controller[fk.key] {
                ControllerCheck::Agrees => ui::ok("gateway agrees"),
                ControllerCheck::Disagrees => ui::err("gateway disagrees"),
                ControllerCheck::NotInGateway => ui::warn("not in gateway env"),
                ControllerCheck::Unknown => ui::warn("gateway unreadable"),
            };
            println!("  {:<22} store {st}  {ck}", fk.key);
            // A refused key is a consequence that STAYS. Naming it here is
            // the difference between "3 of 4 delivered" and knowing which
            // failure mode the fleet is still carrying.
            if let Some((_, why)) = refused.iter().find(|(k, _)| *k == fk.key) {
                println!("    {} {}", ui::glyph_cell(Glyph::Warn), ui::muted(&format!("refused — {why}")));
                println!("    {}", ui::muted(&format!("while it disagrees: {}", fk.consequence)));
            }
        }
        println!("{}", ui::section("nodes"));
        for t in &targets {
            println!("  {t}");
        }
    }

    // Nothing verifiable to send is not a delivery that failed — it is a
    // command that correctly declined. Say which, and stop before staging.
    if deliver.is_empty() && would.is_empty() {
        if g.json {
            println!("{}", json!({
                "dry_run": dry_run,
                "delivered": 0,
                "refused": refused.iter().map(|(k, w)| json!({"key": k, "detail": w})).collect::<Vec<_>>(),
                "nodes": targets,
            }));
        } else {
            ui::close_warned("no key could be confirmed as the fleet's live reference — nothing staged");
            println!("{}", ui::note(
                "refusals are not failures of the fleet — they are states this tool could not \
                 positively verify, and it declines rather than guessing"));
        }
        return Ok(1);
    }

    if dry_run {
        if g.json {
            println!("{}", json!({
                "dry_run": true,
                "would_deliver": would.iter().map(|k| k.key).collect::<Vec<_>>(),
                "refused": refused.iter().map(|(k, w)| json!({"key": k, "detail": w})).collect::<Vec<_>>(),
                "nodes": targets,
            }));
        } else {
            ui::close_done(&format!(
                "{} key(s) would be staged for {} node(s); nothing was written",
                would.len(), targets.len()));
        }
        return Ok(if refused.is_empty() { 0 } else { 1 });
    }

    super::confirm_destructive(
        g,
        yes,
        "Proceed with converging fleet secrets on",
        &format!("{} node(s)", targets.len()),
    );

    // ── Deliver. `deliver_kind_to_nodes` is the shared rail skeleton: signed
    // bundle, encrypted to the node's own birth cert, staged for its fetch
    // timer, per-node honest outcome. The value reaches the bundle here and
    // nowhere else — no argv, no shell, no log line.
    let keys: Vec<(&'static str, String)> = deliver
        .iter()
        .filter_map(|fk| sops.value_for_bundle_payload(fk.key).map(|v| (fk.key, v.to_string())))
        .collect();
    if keys.len() != deliver.len() {
        // Unreachable: StoreState::Set was established above for every key
        // in `deliver`. Refusing beats staging a partial bundle silently.
        fail(g.json, ExitCode::Generic, "store_read_failed",
            "a key the store reported as set could not be read back — nothing was staged", None);
    }
    let payload = move |node: &str| -> Result<Vec<u8>, String> {
        let mut out = format!("NODE={node}\n");
        for (k, v) in &keys {
            // A value with a newline in it would forge extra env lines in the
            // fragment the applier merges. The store should never hold one;
            // refusing costs nothing and closes the injection.
            if v.contains('\n') || v.contains('\r') {
                return Err(format!("{k} contains a newline and cannot be an env line"));
            }
            out.push_str(&format!("{k}={v}\n"));
        }
        Ok(out.into_bytes())
    };
    let rc = crate::commands::cluster_provision::deliver_kind_to_nodes(
        g,
        &targets,
        "fleet-secrets",
        &payload,
        "the applier merges the fragment into /etc/noo-node-agent.env and restarts the agent, \
         which reconnects presenting the controller's value",
    )?;

    if !g.json {
        if !refused.is_empty() {
            println!("{}", ui::note(&format!(
                "{} key(s) were NOT in this bundle — see the refusals above; they are states this \
                 tool could not positively verify, and it declines rather than guessing",
                refused.len())));
        }
        println!("{}", ui::note(
            "this converged nodes onto the value the controller is ALREADY running; it did not \
             rotate anything"));
        ui::guide(&[
            ("noo cluster push-secrets --explain", "why an online rotation is not possible today"),
            ("noo security secrets rotate <name>", "rotate the value on the controller, then push again"),
            ("noo cluster status", "confirm every node is back on the bus after the apply"),
        ]);
    }
    Ok(if rc != 0 || !refused.is_empty() { 1 } else { 0 })
}

/// The ordering answer, kept next to the code it constrains so it cannot rot
/// into a doc nobody reads. Rendered by `noo cluster push-secrets --help`'s
/// long form and quoted by `secrets::fleet_refusal`.
pub(crate) fn rotation_hazard_note() -> &'static str {
    "\
Mid-roll ordering — what the fleet actually accepts while a shared secret changes.

  This command cannot create that window: it only ever moves a node onto the
  value the controller is ALREADY running, so every write takes a node from
  broken toward working and the reference never moves during a run.

  The window belongs to the STORE WRITE that a rotation performs, and for each
  key the answer was read out of the verifier, not assumed:

  NOO_CLUSTER_SECRET — NO safe online path.
    Symmetric HMAC. gateway-rust/src/auth.rs `verify_cluster_token` reads a
    single `NOO_CLUSTER_SECRET`; node-agent-go/internal/auth/middleware.go
    `verifyClusterToken` takes a single secret. Neither has a previous-value
    slot, and it is used in BOTH directions, so any node that disagrees fails
    both its heartbeat and every inbound call. PR #388's dual-accept is about
    signature WIDTH (32- vs 64-hex), not two secret VALUES; it does not help.
    A safe online roll would need a `NOO_CLUSTER_SECRET_PREVIOUS` accepted by
    both verifiers. Because an agent upgrade re-renders only the value the
    controller already runs, the dual-accept node-agent could be rolled out FIRST with no credential
    change at all, and only then would the value push be safe. That is the
    design; it is NOT implemented. Until it is, rotating this key is an
    outage: write the store, recreate the gateway, run this command, and
    expect the fleet down in between.

  NOO_NODE_AGENT_TOKEN — no safe online path either, and the obvious trick
    does not work.
    It is one-directional (controller → node) and the node-agent accepts
    EITHER it or a cluster-HMAC token, which suggests: blank the token on the
    controller so everything falls back to HMAC, push the new token, then set
    it. Two things break that, both checked:
      1. The Python callers' fallback (`cluster_auth.create_cluster_token`)
         truncates to 32 hex, and the Go node-agent verifier accepts ONLY 64
         — see TestVerifyClusterToken_Rejects32HexTruncated. So the fallback
         path is live for the Rust gateway and dead for every Python caller
         (worker_pool, skill_executor, backend_manager, browser_tool).
      2. docker-compose.cluster.yml interpolates the raw token into
         Prometheus' scrape `authorization.credentials`, so blanking it stops
         metrics collection for the window.
    Fix (1) — make Python emit the full 64-hex — and the window becomes real.

  (NATS_USER / NATS_PASSWORD are no longer fleet-wide — the shared bus
  user is retired. A node's own pair rotates online with
  `noo cluster nats-creds rotate <node>`, which delivers first and
  re-renders the server side last.)

  Consequence, stated plainly: there is no online rotation of a fleet-wide
  secret in this tree right now, and this command does not pretend otherwise.
  It refuses to be the thing that opens the window, and it is the thing that
  closes one."
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = "0123456789abcdef01234567";
    /// If any of these ever appears in a rendered surface, a value escaped.
    const V_CLUSTER: &str = "SENTINEL-cluster-secret-aa11";

    // ── the decision table ────────────────────────────────────────────────

    #[test]
    fn only_a_confirmed_reference_is_delivered() {
        assert_eq!(
            push_action(ControllerCheck::Agrees, StoreState::Set, false),
            PushAction::Deliver
        );
    }

    #[test]
    fn controller_disagreement_blocks_every_delivery() {
        // The one way this command could do harm: the store was edited but
        // the gateway was never RECREATED, so the store is not what the fleet
        // authenticates with. Delivering it would break every working node.
        let a = push_action(ControllerCheck::Disagrees, StoreState::Set, false);
        assert!(matches!(a, PushAction::Refuse(_)));
        // …and --dry-run does not soften it into a "would".
        assert!(matches!(
            push_action(ControllerCheck::Disagrees, StoreState::Set, true),
            PushAction::Refuse(_)
        ));
    }

    #[test]
    fn unknown_controller_state_refuses() {
        // Not evidence of anything — emphatically not evidence the store is
        // right. An unreadable reference is the one input this table must
        // never round up to a good one.
        for c in [ControllerCheck::Unknown, ControllerCheck::NotInGateway] {
            assert!(
                matches!(push_action(c, StoreState::Set, false), PushAction::Refuse(_)),
                "{c:?} must refuse"
            );
        }
    }

    #[test]
    fn a_blank_or_missing_store_value_is_never_delivered() {
        for st in [StoreState::Blank, StoreState::Missing] {
            assert!(
                matches!(push_action(ControllerCheck::Agrees, st, false), PushAction::Refuse(_)),
                "{st:?} must refuse"
            );
        }
    }

    #[test]
    fn dry_run_reports_but_never_delivers() {
        assert_eq!(
            push_action(ControllerCheck::Agrees, StoreState::Set, true),
            PushAction::WouldDeliver
        );
    }

    // ── the payload ───────────────────────────────────────────────────────
    //
    // The fragment is the only thing that leaves this process carrying a
    // value, so its shape is the security boundary.

    /// Build a payload the way the command does, without a store or a fleet.
    fn payload_for(node: &str, keys: &[(&'static str, String)]) -> Result<String, String> {
        let mut out = format!("NODE={node}\n");
        for (k, v) in keys {
            if v.contains('\n') || v.contains('\r') {
                return Err(format!("{k} contains a newline and cannot be an env line"));
            }
            out.push_str(&format!("{k}={v}\n"));
        }
        Ok(out)
    }

    #[test]
    fn the_payload_names_its_node_first() {
        // The applier refuses a fragment whose NODE is not the node it
        // resolved, so a signed payload for node A cannot be replayed onto
        // node B. That guard only works if the line is actually there.
        let p = payload_for("host3", &[("NOO_CLUSTER_SECRET", "u".into())]).unwrap();
        assert!(p.starts_with("NODE=host3\n"), "got {p:?}");
    }

    #[test]
    fn a_value_carrying_a_newline_cannot_forge_an_env_line() {
        // Without this, a store value of "x\nPATH=/evil" would become two
        // env lines in a file systemd reads for a ROOT unit.
        let e = payload_for("host3", &[("NOO_CLUSTER_SECRET", "x\nPATH=/evil".into())]).unwrap_err();
        assert!(e.contains("newline"), "got {e}");
        assert!(payload_for("host3", &[("NOO_CLUSTER_SECRET", "x\rY=1".into())]).is_err());
    }

    #[test]
    fn the_payload_carries_only_fleet_keys() {
        let p = payload_for(
            "host3",
            &FLEET_KEYS.iter().map(|k| (k.key, V_CLUSTER.to_string())).collect::<Vec<_>>(),
        )
        .unwrap();
        for line in p.lines().skip(1) {
            let k = line.split('=').next().unwrap();
            assert!(FLEET_KEYS.iter().any(|f| f.key == k), "{k} is not a fleet key");
        }
    }

    // ── the three-site key allowlist ──────────────────────────────────────

    // `every_applier_knows_exactly_these_keys` and
    // `registry_covers_what_the_agent_env_writes` used to live here, along
    // with a block that lifted the applier's fleet-secrets merge out of
    // noo-apply.sh and ran it. They read across the repo, and the `noo-cli`
    // CI job builds this crate in isolation — `scripts/noo-apply.sh` and
    // `node-agent-go/deploy/*` are simply absent there, so all seven failed
    // on a missing file. They moved to tests/test_fleet_secret_declarations.py,
    // which is also where the declaration index can see them. Same lesson as
    // the `include_str!` that reached outside its crate: a test that reads
    // across the repo belongs at the repo level.

    #[test]
    fn every_key_states_its_consequence() {
        for fk in FLEET_KEYS {
            assert!(fk.consequence.len() > 40, "{} needs a real consequence", fk.key);
        }
    }

    #[test]
    fn key_names_are_validated_before_they_reach_a_payload() {
        for bad in ["A B", "A;B", "A=B", "", "A\nB", "a-b"] {
            assert!(!is_safe_key_name(bad), "{bad:?} must be rejected");
        }
        for fk in FLEET_KEYS {
            assert!(is_safe_key_name(fk.key));
        }
    }

    // ── digests ───────────────────────────────────────────────────────────

    #[test]
    fn digests_are_salted_and_truncated() {
        let a = salted_digest(SALT, V_CLUSTER);
        let b = salted_digest("another-salt-entirely-000", V_CLUSTER);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b, "the salt must actually change the digest");
        assert!(!a.contains(V_CLUSTER));
    }

    #[test]
    fn a_fresh_salt_is_fresh() {
        assert_ne!(fresh_salt(), fresh_salt());
    }

    /// The ordering answer must stay honest: it has to name the verifiers it
    /// was read from, and it must not claim a safe online path exists.
    #[test]
    fn the_hazard_note_names_its_evidence() {
        let n = rotation_hazard_note();
        for needle in [
            "verify_cluster_token",
            "verifyClusterToken",
            "TestVerifyClusterToken_Rejects32HexTruncated",
            "PR #388",
        ] {
            assert!(n.contains(needle), "the hazard note must cite {needle}");
        }
        assert!(n.contains("NO safe online path"));
        assert!(n.contains("is NOT implemented"));
        // The shared NATS pair is not a fleet key any more, and
        // the note must not describe a server `authorization` block that no
        // longer exists.
        assert!(n.contains("shared bus") && !n.contains("authorization { user"), "{n}");
    }
}
