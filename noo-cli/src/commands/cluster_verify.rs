// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster verify [<node>...] [--controller] [--wait]` — assert the invariants a
//! node, and the controller, must satisfy to operate under the current
//! constraints.
//!
//! Every constraint added in September has a check somewhere, and none of
//! the checks was run by anything: a feature can ship "not yet live", a token
//! exchange can mint tokens a surface refuses, and a liveness check can verify
//! nothing for weeks. The common shape is a
//! check that exists and a moment nobody points it at the box. This is the
//! moment: one verb, one table per node, one for the controller, exit 1 on
//! the first invariant that does not hold, and the command that fixes it
//! beside it.
//!
//! Invariants, not a diff (the shape `scripts/verify-identity-plane.sh` set):
//! each row is true of every correctly-configured install, so the same
//! output means the same thing on a laptop, on the controller, and in a
//! customer's cluster.
//!
//! The node half reads what the controller already knows — `/api/cluster/
//! nodes` plus the local PKI — so it needs no shell on the node (proposal
//! 22: the controller never reaches in). The controller half composes the
//! verbs that already exist (`posture list`, `service-key list`, `doctor
//! secrets|exposure|strangers`, `secrets audit`, `tailnet policy --merge` (the plan only),
//! `entitlement show`), each run as this binary with `--json` where it
//! speaks it, so there is ONE definition of each check and this verb only
//! decides what "ready" means.

use crate::http::get_json_opt;
use crate::output::ExitCode;
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};
use serde_json::Value;
use std::process::Command;

mod image_family;
mod warmup;
pub(crate) mod restart_loops;

/// One invariant, judged.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
    /// The command that fixes it, when there is one.
    pub remedy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Holds, with a caveat worth reading (never fails the verb).
    Warn,
    Fail,
    /// A readiness miss explained by a container that started moments ago
    /// Neither OK nor FAIL, and not a pass.
    Starting,
}

pub(crate) fn ok(name: &'static str, detail: impl Into<String>) -> Check {
    Check { name, verdict: Verdict::Ok, detail: detail.into(), remedy: None }
}
fn warn(name: &'static str, detail: impl Into<String>, remedy: Option<String>) -> Check {
    Check { name, verdict: Verdict::Warn, detail: detail.into(), remedy }
}
fn fail(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Check {
    Check { name, verdict: Verdict::Fail, detail: detail.into(), remedy: Some(remedy.into()) }
}

/// The `self-agent lane` row (i67): how the controller's own node is
/// updated. It must ride the rail like every node; the sudo lane is
/// onboard's first install only.
///
/// - pull units missing: FAIL, the rail cannot reach it (`noo onboard
///   --only services` installs them, the one sudo);
/// - the gateway does not verify against THIS birth cert (no mount, a
///   stale copy, another self id): FAIL with the cause's remedy;
/// - last install `rail` (or onboard's first install): OK;
/// - anything else while the units exist: FAIL — an older CLI's local lane
///   installed it after onboard (`local-lane.state` without a lane record),
///   which left hostd behind on pop-os after the 0.6.2 roll.
pub(crate) fn self_agent_lane_check(
    node: &str,
    missing_units: &[String],
    gateway: Option<&crate::commands::provision::SelfViewProblem>,
    record: Option<&str>,
    legacy_local: bool,
) -> Check {
    const NAME: &str = "self-agent lane";
    if !missing_units.is_empty() {
        return fail(NAME,
            format!("{node}: node identity incomplete ({}) — the rail cannot reach the controller's own node", missing_units.join(", ")),
            crate::commands::provision::SELF_RAIL_REMEDY);
    }
    if let Some(p) = gateway {
        return fail(NAME, format!("{node}: {}", p.msg), p.remedy.clone());
    }
    match record {
        Some("rail") => ok(NAME, format!("rail — {node} is restaged over the rail like any node (no sudo)")),
        Some("onboard") => ok(NAME, format!("rail — {node} was first installed by onboard; its upgrades ride the rail")),
        other => fail(NAME,
            format!("local — {node} was last installed by the sudo lane{}, not the rail; hostd may be a release behind",
                match (other, legacy_local) {
                    (Some(w), _) => format!(" (record says '{w}')"),
                    (None, true) => " (local-lane.state, no lane record)".to_string(),
                    (None, false) => " (no install record)".to_string(),
                }),
            format!("noo cluster provision {node}")),
    }
}

/// A heartbeat older than this is a node the controller is not hearing.
pub(crate) const HEARTBEAT_MAX_AGE_SECS: i64 = 120;
/// Right after `noo cluster provision <node> --wait`, a field the restarted
/// agent hasn't reported YET (expiry, hostd) reads as absent for exactly
/// one heartbeat — that is not an old agent, and `noo cluster provision <node> --wait`
/// is the wrong remedy for it (2026-09-28 rehearsal). Within this age of the
/// last heartbeat (or no heartbeat recorded at all — freshly provisioned,
/// before its first one), word it as "not reported yet" with no remedy;
/// only beyond it does the field's absence mean a genuinely old agent.
const RECENT_HEARTBEAT_SECS: i64 = 90;
/// A node certificate expiring inside this window fails: the next roll
/// would land on a dead cert.
const CERT_MIN_REMAINING_SECS: i64 = 14 * 86_400;

/// The controller's stack tag: `.env NOO_IMAGE_TAG` (what is deployed), else
/// the tag this binary was paired with at build.
pub(crate) fn controller_stack_tag() -> String {
    let env = crate::envfile::repo_root().join(".env");
    if let Ok(text) = std::fs::read_to_string(&env) {
        if let Some(v) = text.lines().rev().find_map(|l| l.trim().strip_prefix("NOO_IMAGE_TAG=")) {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    crate::onboard::standalone::STANDALONE_STACK_TAG.to_string()
}

/// `stack-v0.2.70+sha` → `v0.2.70`; `noo-cli-v0.5.56+sha` → `cli:v0.5.56`.
pub(crate) fn agent_version_tag(app_version: &str) -> Option<(bool, String)> {
    let base = app_version.split('+').next().unwrap_or(app_version).trim();
    if let Some(v) = base.strip_prefix("stack-") {
        return Some((true, v.to_string()));
    }
    if let Some(v) = base.strip_prefix("noo-cli-") {
        return Some((false, v.to_string()));
    }
    None
}

/// Judge one node record against the invariants. Pure over the record, the
/// controller's tag, the clock and the local PKI marker, so every verdict
/// below is pinned by a test on a canned record.
pub(crate) fn node_checks(n: &Value, controller_tag: &str, cli_version: &str, now_unix: i64, signing_adopted: Option<bool>) -> Vec<Check> {
    let id = n["id"].as_str().unwrap_or("?");
    let mut out = Vec::new();

    // 1. Online, and heard from recently — gossip presence is not a heartbeat.
    let status = n["status"].as_str().unwrap_or("?");
    let hb_age = n["last_heartbeat"].as_str().and_then(parse_rfc3339_unix).map(|t| now_unix - t);
    // A field absent right after the heartbeat that would carry it hasn't
    // landed yet is not evidence of an old agent — no heartbeat at all
    // reads as "freshly provisioned", the same gentle case.
    let hb_recent = hb_age.map(|age| age <= RECENT_HEARTBEAT_SECS).unwrap_or(true);
    match (status, hb_age) {
        ("online", Some(age)) if age <= HEARTBEAT_MAX_AGE_SECS => out.push(ok("online", format!("heartbeat {age}s ago"))),
        ("online", Some(age)) => out.push(fail("online", format!("status says online but the last heartbeat is {age}s old"),
            format!("noo cluster logs {id}"))),
        ("online", None) => out.push(warn("online", "online, no heartbeat timestamp reported", None)),
        (s, _) => out.push(fail("online", format!("status {s}"), format!("noo cluster show {id}"))),
    }

    // 2. Bus: connected on its OWN principal, never the fleet fallback.
    let bus = n["nats_state"].as_str().unwrap_or("?");
    let cred = n["nats_role"].as_str().unwrap_or("?");
    if bus != "connected" {
        out.push(fail("bus", format!("nats {bus}: {}", n["nats_state_detail"].as_str().unwrap_or("no detail")),
            format!("noo cluster provision {id}")));
    } else if cred != "node" {
        out.push(fail("bus", format!("connected as `{cred}` — not this node's own principal (the shared fleet user is retired)"),
            format!("noo cluster nats-creds rotate {id}   # mints AND delivers its own pair; never-provisioned: noo cluster provision {id}")));
    } else {
        out.push(ok("bus", "connected on its own principal"));
    }

    // 3. Agent version pairs with the controller's release.
    match n["app_version"].as_str().and_then(agent_version_tag) {
        Some((true, tag)) if tag == controller_tag => out.push(ok("version", format!("agent {tag} = controller"))),
        Some((true, tag)) => out.push(fail("version", format!("agent {tag}, controller {controller_tag}"),
            format!("noo cluster provision {id} --wait"))),
        Some((false, tag)) if tag == format!("v{cli_version}") => out.push(ok("version", format!("host agent {tag} = this CLI"))),
        Some((false, tag)) => out.push(warn("version", format!("host agent {tag}; this CLI is v{cli_version} (a Mac node upgrades with the CLI)"),
            Some(format!("noo cluster provision {id} --wait")))),
        None => out.push(fail("version", format!("no parsable agent version ({})", n["app_version"].as_str().unwrap_or("-")),
            format!("noo cluster provision {id} --wait"))),
    }

    // 4. Node certificate not about to expire.
    match n["cert_not_after"].as_i64() {
        Some(exp) if exp - now_unix >= CERT_MIN_REMAINING_SECS => out.push(ok("cert", format!("{} days left", (exp - now_unix) / 86_400))),
        Some(exp) if exp > now_unix => out.push(fail("cert", format!("expires in {} days", (exp - now_unix) / 86_400),
            format!("noo security pki issue-node {id} && noo cluster provision {id}"))),
        Some(_) => out.push(fail("cert", "EXPIRED", format!("noo security pki issue-node {id} && noo cluster provision {id}"))),
        None if hb_recent => out.push(warn("cert", "expiry not reported yet — re-run after the next heartbeat", None)),
        None => out.push(warn("cert", "expiry not reported (older agent)", Some(format!("noo cluster provision {id} --wait")))),
    }

    // 4b. The agent requires a client certificate on its control API. The
    //     mTLS-only agent build cannot run without one (it refuses to start
    //     rather than listen in plaintext), so a `false` here is an OLDER
    //     agent still on the plaintext-capable build, or one started without
    //     its PKI material — either way any holder of the fleet secret can
    //     drive its start/stop/pull/clean routes. The gateway alerted on this
    //     at registration and then dropped the field; it is now kept on the
    //     record and refreshed by every heartbeat.
    match n["peer_identity_enforced"].as_bool() {
        Some(true) => out.push(ok("peer identity", "client certificate required on the control API")),
        Some(false) => out.push(fail("peer identity",
            "the agent does not require a client certificate — its control API answers any fleet-secret holder, or plaintext",
            format!("noo cluster provision {id} --wait   # delivers the node's PKI material; the current agent refuses to start without it"))),
        None if hb_recent => out.push(warn("peer identity", "not reported yet — re-run after the next heartbeat", None)),
        None => out.push(warn("peer identity", "not reported (older agent)", Some(format!("noo cluster provision {id} --wait")))),
    }

    // 5. The fleet signing key adopted. The CA-signed bundle lane is retired
    //    So a node that has not adopted takes nothing but a
    //    rollover — which every CA-signed bundle now is, so a provision
    //    adopts it.
    match signing_adopted {
        Some(true) => out.push(ok("signing", "fleet signing key adopted")),
        Some(false) => out.push(fail("signing", "not adopted — the CA-signed lane is retired, so this node applies only a signing-key rollover",
            format!("noo cluster provision {id} --wait   # the bundle carries signing-pub; the node adopts on apply"))),
        None => out.push(warn("signing", "not checked (no local PKI for this node — run on the controller)", None)),
    }

    // 6. hostd alive — the privileged helper every rail op needs.
    let hostd = &n["hostd"];
    match hostd["alive"].as_bool() {
        Some(true) => out.push(ok("hostd", format!("alive, {}s ago", hostd["age_secs"].as_i64().unwrap_or(0)))),
        Some(false) => out.push(fail("hostd", hostd["detail"].as_str().unwrap_or("not alive").to_string(),
            format!("noo cluster provision {id}   # ships the helper"))),
        None if hb_recent => out.push(warn("hostd", "not reported yet — re-run after the next heartbeat", None)),
        None => out.push(warn("hostd", "not reported (older agent)", Some(format!("noo cluster provision {id} --wait")))),
    }

    // 6b. What the node's NEXT BOOT will do, from
    //     the facts noo-hostd reports as root.
    out.extend(host_checks(id, &hostd["host"], hostd["alive"].as_bool() == Some(true)));

    // 6c. Backend doors: every door-backed backend on
    //     the node has a leaf that names its door, and the agent records no
    //     `backend_tls` / `backend_door` refusal. Replaces the old per-refusal
    //     `backend tls` row, whose remedy (unset NOO_<X>_TLS) stopped being
    //     one when every agent-started backend became a TLS door.
    out.push(backend_doors_row(n, now_unix));
    out.extend(stunnel_image_check(n));
    // 6c-rail. Images over the rail (2026-10-10): every image the agent
    //          started came from the controller's artifact rail, and every
    //          placement's image is staged there.
    out.extend(image_sources_check(n));
    out.extend(images_staged_check(n));

    // 6c''. Vendor telemetry (docs/security/telemetry.md): no running
    //       backend container lacks the switches that keep its vendor from
    //       phoning home (vLLM's stats.vllm.ai report above all).
    out.push(vendor_telemetry_check(n));

    // 6c'. The data root: the declaration, the root the
    //      agent resolves, and what its containers mount all say one thing.
    out.push(data_root_row(n));
    if let Some(c) = data_root_policy_row(n) {
        out.push(c);
    }

    // 6d. The log shipper (fleet logging phase 6), from the agent's own
    //     account in its heartbeat.
    out.push(log_shipper_check(id, &n["log_ship"], now_unix, hb_recent));

    // 7. Inbound: the controller can reach the agent.
    match n["inbound"].as_str() {
        Some("ok") => out.push(ok("inbound", "agent reachable from the controller")),
        Some(other) => out.push(fail("inbound", format!("inbound {other}"), format!("noo cluster show {id}   # bind address and tailnet grant"))),
        None => out.push(warn("inbound", "not yet checked", None)),
    }

    // 8. Harness matches the declared policy.
    //
    // An ABSENT policy is not `manual`. It used to resolve to that default
    // here, and `/api/cluster/nodes` did not carry the field at all — so this
    // check reported a green `policy manual` for every node on a fleet whose
    // declared policies it had never seen (live, 2026-09-23). A check that
    // cannot read its input says so; it does not pass itself.
    let state = n["host_services"]["harness"]["state"].as_str().unwrap_or("");
    // The controller's own node runs no harness unit by design — its gateway
    // runs turns in process (provision.rs: "no harness in the bundle"). Read
    // as "absent under policy auto" it failed host8 on every verify and
    // sent the operator to place a harness nothing can deliver.
    if n["self_node"].as_bool() == Some(true) {
        out.push(ok("harness", "in process — the controller's own gateway runs turns; no harness unit here by design"));
    } else { match (n["harness_policy"].as_str(), state) {
        (None, _) => out.push(warn("harness", "policy not reported by the gateway — cannot judge the harness",
            Some(format!("noo cluster show {id}   # the policy is on the node's config row")))),
        (Some("auto"), "running") => out.push(ok("harness", "running (policy auto)")),
        (Some("auto"), "") => out.push(warn("harness", "policy auto, state not reported yet", None)),
        // `auto` places a harness only beside a CHAT backend
        // (apply_harness_policy). host2 and host9 serve only an embedder,
        // so a stopped harness there is the policy working — and this failed
        // them on every verify (2026-09-28). Whether one is wanted is the
        // gateway's answer, read from its policy-applied placements, not a
        // second copy of the rule.
        (Some("auto"), s) => match n["harness_wanted"].as_bool() {
            Some(false) => out.push(ok("harness", format!("{s} — policy auto, and no chat backend here to follow"))),
            Some(true) => out.push(fail("harness", format!("a harness is placed here (policy auto) but it is {s}"),
                format!("noo cluster logs {id} harness"))),
            None => out.push(warn("harness", format!(
                "policy auto, harness {s} — could not read this node's desired placements to tell whether one is wanted"),
                Some(format!("noo cluster desired {id}")))),
        },
        (Some("off"), "running") => out.push(fail("harness", "policy off but the harness is running", format!("noo cluster unplace {id} harness"))),
        (Some(p), s) => out.push(ok("harness", format!("{} (policy {p})", if s.is_empty() { "-" } else { s }))),
    } }
    out
}

/// The `image sources` row: which images the agent started containers from
/// that did NOT come from the controller's artifact rail, from its
/// `image_sources` heartbeat report. `local` = present on the node but not
/// vouched for by the controller's manifest; `registry` = pulled from a
/// public registry under the third-party fallback. No row from an agent that
/// does not report (older, or nothing started yet).
pub(crate) fn image_sources_check(n: &Value) -> Option<Check> {
    let id = n["id"].as_str().unwrap_or("?");
    let entries = n["image_sources"].as_array()?;
    let off: Vec<(String, String)> = entries
        .iter()
        .filter_map(|e| {
            let src = e["source"].as_str().unwrap_or("?");
            (src != "rail").then(|| (e["image"].as_str().unwrap_or("?").to_string(), src.to_string()))
        })
        .collect();
    if off.is_empty() {
        return Some(ok("image sources", format!("{} image(s), all from the artifact rail", entries.len())));
    }
    let list: Vec<String> = off.iter().map(|(i, s)| format!("{i} ({s})")).collect();
    let first = &off[0].0;
    // The rollout switch (NOO_IMAGE_SOURCE): a node still on `legacy` takes
    // images the pre-rail way by design, so this is information for the
    // dry-run, not a warning. An agent that does not report a mode predates it.
    if n["image_source_mode"].as_str() != Some("rail") {
        return Some(ok("image sources", format!(
            "legacy image source (NOO_IMAGE_SOURCE is not `rail` on this node): not from the rail: {}",
            list.join(", "))));
    }
    Some(warn(
        "image sources",
        format!("not from the artifact rail: {}", list.join(", ")),
        Some(format!("noo cluster sync-images {id} -i {first}   # stage it; the agent takes the rail copy on its next start")),
    ))
}

/// The `images staged` row: running placements whose image is not staged on
/// the controller's rail for this node's architecture (`unstaged_images`,
/// injected by `with_harness_wanted` from the local image store). Such a
/// placement cannot start on a node that does not already hold the image:
/// a node has no registry credential.
pub(crate) fn images_staged_check(n: &Value) -> Option<Check> {
    let id = n["id"].as_str().unwrap_or("?");
    let missing = n["unstaged_images"].as_array()?;
    let names: Vec<&str> = missing.iter().filter_map(Value::as_str).collect();
    let first = names.first()?;
    Some(warn(
        "images staged",
        format!("placed but not staged on the artifact rail: {}", names.join(", ")),
        Some(format!("noo cluster sync-images {id} -i {first}   # or `noo upgrade` for the release images")),
    ))
}

/// The `sidecar image` row: which image the node's
/// backend-door stunnel sidecars run on, from the agent's `stunnel_image`.
/// `fallback-alpine` WARNs — the doors work, but every sidecar start
/// installs stunnel from the alpine mirror, so a door start depends on that
/// mirror. No row when the node does not report it (no sidecar started yet,
/// or an agent that predates the report): `backend doors` already speaks
/// for the doors themselves.
pub(crate) fn stunnel_image_check(n: &Value) -> Option<Check> {
    let id = n["id"].as_str().unwrap_or("?");
    match n["stunnel_image"].as_str()? {
        "published" => Some(ok("sidecar image", "backend-door sidecars run on the published stunnel image")),
        "fallback-alpine" => Some(warn(
            "sidecar image",
            "backend-door sidecars run on the alpine fallback: the published stunnel image was missing, and every sidecar start installs stunnel from the alpine mirror",
            Some(format!("noo cluster provision {id} --wait   # a release carrying the published stunnel image")),
        )),
        other => Some(warn("sidecar image", format!("agent reports an unknown stunnel_image {other:?}"), None)),
    }
}

/// The `vendor telemetry` row (docs/security/telemetry.md). The agent reports,
/// per running backend container, the telemetry switches its env LACKS
/// (`backend_containers.<b>.telemetry_missing`, by name — values never leave
/// the node). Any name there FAILs: that container's vendor is phoning home
/// (vLLM posts to stats.vllm.ai every 10 minutes). An entry without the key
/// is an agent that predates the report: WARN, never a claimed pass.
pub(crate) fn vendor_telemetry_check(n: &Value) -> Check {
    const NAME: &str = "vendor telemetry";
    let id = n["id"].as_str().unwrap_or("?");
    let remedy = format!("noo cluster provision {id} --wait   # an agent that stamps the switches recreates each backend once");
    let Some(bc) = n["backend_containers"].as_object() else {
        let running = n["running_backends"].as_object().is_some_and(|m| !m.is_empty());
        if !running {
            return ok(NAME, "no backend container running");
        }
        return warn(NAME, "the agent does not report its backend containers (older agent) — telemetry switches not proven",
            Some(format!("noo cluster provision {id} --wait")));
    };
    if bc.is_empty() {
        return ok(NAME, "no backend container running");
    }
    let mut problems: Vec<String> = Vec::new();
    // Containers the agent flags as orphans beside an adopted backend
    // (self-node: the stack's ollama). Nothing manages them, so a provision
    // never stamps them: the remedy is the operator removing them.
    let mut orphans: Vec<String> = Vec::new();
    let mut orphan_rm: Vec<String> = Vec::new();
    let mut unreported: Vec<&str> = Vec::new();
    let mut proven: Vec<&str> = Vec::new();
    let mut unmanaged: Vec<String> = Vec::new();
    // An unmanaged native ollama judged from its running process: what
    // launched it, and the remedy that goes with that launcher.
    let mut unmanaged_set: Vec<String> = Vec::new();
    let mut unmanaged_missing: Vec<(String, &'static str)> = Vec::new();
    let mut mac_ollama = false;
    for (b, entry) in bc {
        // A Mac's native ollama (node-agent-go backendrt/ollama_telemetry.go):
        // `managed: false` = no brew plist, so nothing here may touch or judge it.
        if entry["managed"].as_bool() == Some(false) {
            // The agent reads the running process's environment whatever
            // launched it: judge by that when it could (older agents omit it).
            let launcher = entry["launcher"].as_str().unwrap_or("");
            match entry["process_env"].as_str() {
                Some("set") => unmanaged_set.push(format!("{b}: not managed by noomesh (launched by {launcher}), but the running process has OLLAMA_NO_CLOUD=1")),
                Some("missing") => unmanaged_missing.push((
                    format!("{b}: launched by {launcher} without OLLAMA_NO_CLOUD — its vendor phones home"), 
                    match launcher {
                        "ollama-app" => "quit Ollama.app and disable its login item, then `HOMEBREW_NO_ANALYTICS=1 brew services start ollama`; the node agent sets the switch within a minute (or keep the app and `launchctl setenv OLLAMA_NO_CLOUD 1` before relaunching it — that lasts until the next login)",
                        _ => "stop the hand-started `ollama serve`; `HOMEBREW_NO_ANALYTICS=1 brew services start ollama` and the agent takes over",
                    })),
                _ if launcher.is_empty() => unmanaged.push(b.to_string()),
                _ => unmanaged.push(format!("{b} (launcher: {launcher})")),
            }
            continue;
        }
        match entry["telemetry_missing"].as_array() {
            None => unreported.push(b),
            Some(a) if a.is_empty() => proven.push(b),
            Some(a) => {
                let names: Vec<&str> = a.iter().filter_map(|v| v.as_str()).collect();
                if entry["orphan"].as_bool() == Some(true) {
                    let ctr = entry["container"].as_str().unwrap_or(b.as_str());
                    orphans.push(format!(
                        "{ctr} is an orphan container beside the stack's adopted {b} — nothing manages it, so it never gets the switches (lacks {})",
                        names.join(", ")));
                    orphan_rm.push(ctr.to_string());
                    if let Some(sc) = entry["sidecars"].as_array() {
                        orphan_rm.extend(sc.iter().filter_map(|v| v.as_str()).map(String::from));
                    }
                } else {
                    problems.push(format!("{b} lacks {}", names.join(", ")));
                    mac_ollama |= entry["runtime"].as_str() == Some("native");
                }
            }
        }
    }
    let remedy = if mac_ollama {
        // Either brew label (sh.brew.ollama is current Homebrew), and the
        // domain launchd actually holds the job in (user/<uid> on a headless
        // Mac over SSH, where gui/<uid> answers 125).
        "on the Mac: L=sh.brew.ollama; [ -f ~/Library/LaunchAgents/$L.plist ] || L=homebrew.mxcl.ollama; \
         P=~/Library/LaunchAgents/$L.plist; D=gui/$(id -u); launchctl print $D/$L >/dev/null 2>&1 || D=user/$(id -u); \
         plutil -insert EnvironmentVariables -dictionary $P 2>/dev/null; \
         plutil -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string 1 $P; \
         launchctl bootout $D $P; launchctl bootstrap $D $P   \
         # a current agent re-applies this itself within a minute".to_string()
    } else {
        remedy
    };
    if !orphans.is_empty() {
        // Still a FAIL: a running container without the switch phones home.
        let mut detail = orphans.join("; ");
        if !problems.is_empty() {
            detail.push_str(&format!("; {} — its vendor phones home", problems.join("; ")));
        }
        let rm = format!("docker rm -f {}   # on {id}: the operator removes the orphan; the adopted backend keeps serving", orphan_rm.join(" "));
        let remedy = if problems.is_empty() { rm } else { format!("{rm}; then {remedy}") };
        return fail(NAME, detail, remedy);
    }
    if !problems.is_empty() {
        return fail(NAME, format!("{} — its vendor phones home", problems.join("; ")), remedy);
    }
    if !unmanaged_missing.is_empty() {
        let detail = unmanaged_missing.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>().join("; ");
        let mut fix: Vec<&str> = unmanaged_missing.iter().map(|(_, r)| *r).collect();
        fix.dedup();
        return fail(NAME, detail, fix.join("; "));
    }
    if !unmanaged.is_empty() {
        return warn(NAME, format!(
            "{}: not managed by noomesh (no brew ollama service: sh.brew.ollama or homebrew.mxcl.ollama) — OLLAMA_NO_CLOUD not proven",
            unmanaged.join(", ")),
            Some("on the Mac: set OLLAMA_NO_CLOUD=1 wherever ollama is launched (Ollama.app: `launchctl setenv OLLAMA_NO_CLOUD 1`, then quit and reopen it)".into()));
    }
    if !unreported.is_empty() {
        return warn(NAME, format!(
            "{}: the agent predates the telemetry report — the switches are not proven",
            unreported.join(", ")), Some(format!("noo cluster provision {id} --wait")));
    }
    if !unmanaged_set.is_empty() {
        let mut parts = unmanaged_set;
        if !proven.is_empty() {
            parts.push(format!("{}: every vendor telemetry switch set", proven.join(", ")));
        }
        return ok(NAME, parts.join("; "));
    }
    ok(NAME, format!("{}: every vendor telemetry switch set", proven.join(", ")))
}

/// A leaf inside this window fails the row: the next backend recreate
/// would serve a dead certificate. Provision renews at 30 days.
const DOOR_LEAF_MIN_REMAINING_SECS: i64 = 14 * 86_400;

/// The `backend doors` row for a node record, reading the controller's
/// copy of each door leaf from its PKI dir.
pub(crate) fn backend_doors_row(n: &Value, now_unix: i64) -> Check {
    let id = n["id"].as_str().unwrap_or("?");
    let leaf_of = |svc: &str| crate::commands::node_leaves::read_leaf(
        &crate::pki::ClusterCa::new(crate::pki::pki_dir()).node_service_dir(id, svc));
    backend_doors_check(n, &leaf_of, now_unix)
}

/// The `backend doors` row. For every door-backed
/// backend on the node — what it runs in Docker (`running_backends`, less
/// any `backend_runtimes` says is native), plus anything the agent refused
/// — three things must hold:
///
/// 1. no `backend_tls` (refused to start: leaf missing / not naming the
///    door) or `backend_door` (running plain, pre-door container) refusal
///    on the record;
/// 2. the controller holds the node's leaf for that door
///    (`nodes/<id>/services/<x>/`, `leaf`), naming the door and outside
///    the expiry window — it is what the next bundle carries;
/// 3. the node reports the leaf it HOLDS (`backend_leaves`), and that one
///    names the door and is not expiring. An agent that does not report
///    it predates the report: the row WARNs instead of
///    claiming a node-side fact it was never told.
///
/// A failure made ONLY of "the node holds no leaf yet" / "refused to start:
/// no leaf yet" on backends whose containers the node reports as started
/// moments ago with health=starting reads `Starting`
/// `warmup::judge_node_doors`). Any other problem on the row — a leaf that
/// does not name its door, an expiring one, a plaintext door, anything the
/// controller holds wrong — keeps the whole row FAIL, however new the
/// container. An agent that does not report `backend_containers` never
/// softens.
///
/// Pure over the record, the leaf reader and the clock. `leaf` is only
/// called for a backend the node actually has, so a record with none
/// reads nothing from disk.
pub(crate) fn backend_doors_check(n: &Value, leaf: &dyn Fn(&str) -> crate::commands::node_leaves::LeafState, now_unix: i64) -> Check {
    use crate::commands::node_leaves::{door_leaf_for_backend, LeafState};
    const NAME: &str = "backend doors";
    let id = n["id"].as_str().unwrap_or("?");
    let remedy = format!("noo cluster provision {id}   # issues/renews the node's door leaves and delivers them on the rail");
    let native = |b: &str| n["backend_runtimes"][b].as_str() == Some("native");
    let mut backends: Vec<String> = n["running_backends"].as_object()
        .map(|m| m.keys().filter(|b| !native(b) && door_leaf_for_backend(b).is_some()).cloned().collect())
        .unwrap_or_default();
    let refusals: Vec<&Value> = n["reconcile_refusals"].as_array()
        .map(|rs| rs.iter().filter(|r| r["scope"] == "backend_tls" || r["scope"] == "backend_door").collect())
        .unwrap_or_default();
    for r in &refusals {
        if let Some(t) = r["target"].as_str() {
            if !backends.iter().any(|b| b == t) {
                backends.push(t.to_string());
            }
        }
    }
    backends.sort();
    if backends.is_empty() {
        return ok(NAME, "no door-backed backend on this node");
    }
    let mut problems: Vec<String> = Vec::new();
    // The backends whose problems warm-up may explain, and
    // whether any problem is one it never may.
    let mut warm: Vec<String> = Vec::new();
    let mut hard = false;
    for r in &refusals {
        let scope = r["scope"].as_str().unwrap_or("?");
        let what = if scope == "backend_door" { "serves plaintext" } else { "refused to start" };
        let reason = r["reason"].as_str().unwrap_or("no reason reported");
        problems.push(format!("{} {what} ({scope}): {reason}", r["target"].as_str().unwrap_or("?")));
        match r["target"].as_str() {
            Some(t) if scope == "backend_tls" && reason.contains(warmup::NO_LEAF_YET_REFUSAL) => warm.push(t.to_string()),
            _ => hard = true,
        }
    }
    let reported = n["backend_leaves"].as_object();
    let mut unreported: Vec<&str> = Vec::new();
    for b in &backends {
        let Some(door) = door_leaf_for_backend(b) else {
            continue; // a refusal target this CLI has no door for (airllm): the refusal line above says it
        };
        let svc = door.service;
        let dial = if door.backends.len() > 1 {
            // vllm and vllm-secondary share the leaf; each is dialled by its own name.
            format!("noo-{b}")
        } else {
            door.doors[0].to_string()
        };
        let before = problems.len();
        match leaf(svc) {
            LeafState::Missing => problems.push(format!(
                "{b}: the controller holds no {svc} leaf for {id} (nodes/{id}/services/{svc}/) — no bundle can carry one")),
            LeafState::Unreadable(e) => problems.push(format!("{b}: the controller's {svc} leaf for {id} is unreadable ({e})")),
            LeafState::Present { dns, not_after, .. } => {
                if !dns.contains(&dial) {
                    problems.push(format!("{b}: the controller's {svc} leaf for {id} does not name {dial}"));
                } else if not_after - now_unix < DOOR_LEAF_MIN_REMAINING_SECS {
                    problems.push(format!("{b}: the controller's {svc} leaf for {id} expires in {} days", (not_after - now_unix).max(0) / 86_400));
                }
            }
        }
        hard |= problems.len() > before; // the controller's copy is never warm-up
        match reported {
            None => unreported.push(b),
            Some(m) => match m.get(svc) {
                None => {
                    problems.push(format!("{b}: the node holds no services/{svc} leaf"));
                    warm.push(b.clone());
                }
                Some(l) => {
                    let before = problems.len();
                    let names = l["dns"].as_array().is_some_and(|a| a.iter().any(|d| d.as_str() == Some(dial.as_str())));
                    if !names {
                        problems.push(format!("{b}: the node's services/{svc} leaf does not name {dial}"));
                    }
                    match l["not_after"].as_i64() {
                        Some(t) if t - now_unix >= DOOR_LEAF_MIN_REMAINING_SECS => {}
                        Some(t) => problems.push(format!("{b}: the node's services/{svc} leaf expires in {} days", (t - now_unix).max(0) / 86_400)),
                        None => problems.push(format!("{b}: the node reports its services/{svc} leaf without an expiry")),
                    }
                    hard |= problems.len() > before; // a leaf that is there and wrong is a security fault
                }
            },
        }
    }
    if !problems.is_empty() {
        let check = fail(NAME, problems.join("; "), remedy);
        if hard {
            return check;
        }
        return warmup::judge_node_doors(check, &warm, n, now_unix);
    }
    let list = backends.join(", ");
    if !unreported.is_empty() {
        return warn(NAME, format!(
            "{list}: the controller's leaves name their doors and no refusal is recorded, but the agent \
             predates backend doors reporting (no `backend_leaves` on its heartbeat) — the leaf ON the node \
             is not proven, only that nothing refused"),
            Some(format!("noo cluster provision {id} --wait")));
    }
    ok(NAME, format!("{list}: leaf present on the node, names its door, not expiring; no refusal"))
}

/// Whether the gateway wants a harness RUNNING on this node, from the body of
/// `/api/cluster/nodes/<id>/desired-config`. Its `placements` are the ones
/// `apply_harness_policy` has already been applied to: under `auto` a
/// harness appears there exactly when the node has a chat backend.
pub(crate) fn harness_wanted_in(desired: &Value) -> Option<bool> {
    let placements = desired["placements"].as_array()?;
    Some(placements.iter().any(|p| p["backend"] == "harness" && p["desired_state"] == "running"))
}

/// The `data root` row, pure over the node record. The
/// record's `declared_data_root` is injected by [`with_harness_wanted`] from
/// the same desired-config read; absent means nothing was declared.
///
/// OK: the declaration (if any), the root the agent resolves and every
/// running backend mount agree. FAIL: they do not, naming both sides.
/// WARN: the agent does not report (older agent).
pub(crate) fn data_root_row(n: &Value) -> Check {
    use crate::commands::data_root::{norm, parse_reported, Placement, Rendered};
    const NAME: &str = "data root";
    let id = n["id"].as_str().unwrap_or("?");
    let rep = match parse_reported(n.get("data_roots")) {
        Ok(r) => r,
        Err(why) => return warn(NAME, format!("not reported (older agent): {why}"),
            Some(format!("noo cluster provision {id} --wait"))),
    };
    let declared = n["declared_data_root"].as_str().map(norm).filter(|d| d.starts_with('/') && d.len() > 1);
    // The node's OS: hostd's fact, else what the declared root's shape says.
    let macos = match n["hostd"]["host"]["os"].as_str() {
        Some(os) => os == "darwin",
        None => declared.as_deref().is_some_and(|d| crate::commands::data_root::infer_os(d).0),
    };
    // "The declaration follows the node" is offered only for a root the node
    // was TOLD (not a built-in fallback) that fits its OS. A fallback root is
    // a symptom (the env did not load), never a decision to adopt.
    let source = n["data_roots"]["noo_data_root_source"].as_str();
    let fell_back = !rep.root_from_env || (source.is_none() && crate::commands::data_root::is_builtin_default_root(&rep.noo_data_root));
    let adoptable = !fell_back && crate::commands::data_root::root_fits_os(&rep.noo_data_root, macos);
    let set = if adoptable {
        format!("noo cluster set-config {id} --data-root {}", rep.noo_data_root)
    } else {
        let env_file = if macos { "~/noomesh/agent.env" } else { "/etc/noo-node-agent.env" };
        format!("on {id}: make {env_file} declare NOO_DATA_ROOT (the node runs on {}, a built-in default it was not told), \
                 then noo cluster restart-agent {id}; noo cluster provision {id} --wait re-renders the env from the declaration once the CLI release quotes values (#776)",
                rep.noo_data_root)
    };
    let mut problems: Vec<String> = Vec::new();
    if let Some(d) = &declared {
        if rep.root_from_env && *d != norm(&rep.noo_data_root) {
            problems.push(format!("declared {d}, but the node runs on {}", rep.noo_data_root));
        } else if !rep.root_from_env {
            problems.push(format!("declared {d}, but the node was never told its root and uses the built-in {}", rep.noo_data_root));
        }
    }
    // The roots the node is meant to use: the declaration's when there is
    // one, else its own.
    let rendered = Rendered::from_root(declared.as_deref().unwrap_or(&rep.noo_data_root));
    let mut roots: Vec<&str> = vec![rendered.noo_data_root.as_str(), rendered.hf_cache_dir.as_str(),
        rendered.models_dir.as_str(), rendered.ollama_data_dir.as_str()];
    // An explicit child dir the node reports (HF_CACHE_DIR etc.) is its own
    // root only when no declaration overrides it.
    if declared.is_none() {
        roots.extend([&rep.hf_cache_dir, &rep.models_dir, &rep.ollama_data_dir].into_iter().flatten().map(String::as_str));
    }
    let root_is_reported = norm(&rep.noo_data_root) == norm(&rendered.noo_data_root);
    for (b, p) in rep.mounts.iter().filter(|(_, p)| rep.place(p, &roots, root_is_reported) == Placement::Outside) {
        problems.push(format!("noo-{b} mounts {p}, outside {}", roots[0]));
    }
    if !problems.is_empty() {
        let remedy = if declared.is_some() { set } else {
            format!("noo cluster desired {id}   # a container mounts a path outside the node's own data root; move the data or recreate the container")
        };
        return fail(NAME, problems.join("; "), remedy);
    }
    let mounts = rep.mounts.len();
    let mut msg = match &declared {
        Some(d) => format!("{d}: declaration, node and {mounts} running mount(s) agree"),
        None => format!("{}: no declaration; node and {mounts} running mount(s) agree", rep.noo_data_root),
    };
    // Inside only through a symlink: healthy, but say it (it moves on the
    // next recreate).
    let notes = rep.link_notes(&roots, root_is_reported);
    if !notes.is_empty() {
        msg.push_str(&format!(" (same data, different path: {} (moves on the next recreate))", notes.join(", ")));
    }
    ok(NAME, msg)
}

/// The `data root policy` row: what the node's own check of its root says
/// (node-agent-go/internal/dataroots/policy.go). None for an agent that
/// predates the policy. A failing root is a WARN while the node only reports
/// (`warn` mode) and a FAIL once it refuses (`enforce`).
pub(crate) fn data_root_policy_row(n: &Value) -> Option<Check> {
    const NAME: &str = "data root policy";
    let pol = n.get("data_roots")?.get("policy")?;
    let id = n["id"].as_str().unwrap_or("?");
    let root = n["data_roots"]["noo_data_root"].as_str().unwrap_or("<root>");
    if pol["ok"].as_bool() == Some(true) {
        return Some(ok(NAME, format!("{root}: dedicated, conventional and owned by the agent")));
    }
    let probs: Vec<&Value> = pol["problems"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let codes: Vec<&str> = probs.iter().filter_map(|p| p["code"].as_str()).collect();
    let detail = probs.iter().filter_map(|p| p["detail"].as_str()).collect::<Vec<_>>().join("; ");
    let only_ownership = !codes.is_empty()
        && codes.iter().all(|c| matches!(*c, "wrong_owner" | "writable_by_others" | "missing"));
    // Kept on an earlier default with an acceptable shape: the fix is to
    // DECLARE where it already is, never to move it.
    let only_undeclared = codes.contains(&"undeclared_root")
        && codes.iter().all(|c| matches!(*c, "undeclared_root" | "wrong_owner" | "writable_by_others"));
    let remedy = if only_undeclared {
        format!("noo cluster set-config {id} --data-root {root} && noo cluster provision {id} --wait")
    } else if only_ownership {
        format!("on {id}: sudo install -d -o noo-agent -g noo-agent {root} && sudo chmod go-w {root}")
    } else {
        let (macos, home) = crate::commands::data_root::infer_os(root);
        let target = if macos && !home.is_empty() {
            format!("'{}'", crate::commands::data_root::default_for_macos(&home))
        } else {
            crate::commands::data_root::DEFAULT_DATA_ROOT.to_string()
        };
        format!("noo cluster set-config {id} --data-root {target} && noo cluster provision {id} --move-data --wait")
    };
    let msg = format!("{root}: {detail}");
    Some(if pol["mode"] == "enforce" { fail(NAME, msg, remedy) } else { warn(NAME, msg, Some(remedy)) })
}

/// The node record plus the gateway's answer on the harness (and the
/// declared data root), for node_checks.
fn with_harness_wanted(g: &Globals, n: &Value) -> Value {
    let mut n = n.clone();
    let id = n["id"].as_str().unwrap_or_default().to_string();
    let desired = get_json_opt(g, &format!("/api/cluster/nodes/{}/desired-config", crate::commands::urlencode(&id)), true, 10);
    let wanted = desired.as_ref().and_then(harness_wanted_in);
    let declared = desired.as_ref()
        .and_then(|d| d["node"]["data_root"].as_str())
        .filter(|s| s.starts_with('/') && s.len() > 1)
        .map(str::to_string);
    // Placements whose image is not staged on the artifact rail for this
    // node's arch (read from the image store on THIS host; empty elsewhere).
    let unstaged = match (desired.as_ref(), crate::commands::image_stage::node_arch(&n)) {
        (Some(d), Some(arch)) => crate::commands::image_stage::unstaged_for(&d["placements"], arch),
        _ => Vec::new(),
    };
    if let Some(obj) = n.as_object_mut() {
        if !unstaged.is_empty() {
            obj.insert("unstaged_images".into(), serde_json::json!(unstaged));
        }
        if let Some(w) = wanted {
            obj.insert("harness_wanted".into(), Value::Bool(w));
        }
        if let Some(d) = declared {
            obj.insert("declared_data_root".into(), Value::String(d));
        }
    }
    n
}

/// The loader's effective default entry and its kernel version, when hostd
/// reported both (`boot_partition.default_entry` + the matching `entries[]`
/// row's `kernel`). `None` means the loader facts are absent.
fn effective_default_entry(host: &Value) -> Option<(String, String)> {
    let bp = &host["boot_partition"];
    let entry = bp["default_entry"].as_str().filter(|e| !e.is_empty())?;
    let kernel = bp["entries"].as_array()?.iter()
        .find(|e| e["name"].as_str() == Some(entry))
        .and_then(|e| e["kernel"].as_str())
        .filter(|k| !k.is_empty())?;
    Some((entry.to_string(), kernel.to_string()))
}

/// A WSL2 node: Windows supplies the kernel and boots the VM, so nothing on
/// the node chooses a kernel and there is no ESP or /boot initrd. One test
/// for the `next boot` and `boot partition` rows.
fn is_wsl2(running_kernel: &str) -> bool {
    running_kernel.contains("microsoft-standard-WSL")
}

/// Judge the host facts. Pure over the `hostd.host` object so each row is
/// pinned on records shaped like the live ones.
///
/// 2026-09-24, the controller: kernel 7.1.5 installed, the next boot hung,
/// and the fallback (6.18.7) had no NVIDIA module. Each of those is a row.
pub(crate) fn host_checks(id: &str, host: &Value, hostd_alive: bool) -> Vec<Check> {
    let mut out = Vec::new();
    if host.is_null() {
        if hostd_alive {
            out.push(warn("next boot", "not reported — this node's noo-hostd predates host facts",
                Some(format!("noo cluster provision {id} --wait"))));
        }
        return out;
    }
    if host["os"].as_str().is_some_and(|os| os != "linux") {
        // A macOS node: no boot or package facts for the mesh to manage, but
        // its brew tailscaled has the same log upload (Linux below).
        if host["telemetry"].is_object() {
            out.push(host_telemetry_check(id, host));
        }
        return out;
    }
    let s = |k: &str| host[k].as_str().unwrap_or("").to_string();
    let (running, installed_default, fallback) = (s("running_kernel"), s("default_kernel"), s("fallback_kernel"));
    let runbook = "docs/operating/runbooks/host-updates.md";
    // The loader's EFFECTIVE default entry beats the /boot/vmlinuz symlink
    // (`default_kernel`): an operator's `bootctl set-default` pin is what the
    // next boot runs (host8, v0.2.95 roll: pinned to 6.18.7 while 7.1.5 was
    // installed). Fall back to `default_kernel` only without loader facts.
    let pinned_entry = effective_default_entry(host);
    let default = pinned_entry.as_ref().map(|(_, k)| k.clone()).unwrap_or_else(|| installed_default.clone());

    // Which kernel the next boot runs.
    match (default.as_str(), running.as_str()) {
        // WSL2: Windows supplies the kernel; there is no boot loader on the
        // node to read and no kernel package an `apt upgrade` could switch.
        ("", _) if is_wsl2(&running) => out.push(ok(
            "next boot",
            format!("WSL2 — Windows supplies the kernel ({running}); nothing on this node chooses it"),
        )),
        ("", _) => out.push(warn("next boot", "could not tell which kernel the next boot runs (boot loader not recognised)", None)),
        (d, r) if d == r => match &pinned_entry {
            Some((entry, _)) if !installed_default.is_empty() && installed_default != r => out.push(ok("next boot",
                format!("pinned to {entry} ({r}, the running kernel) — newer {installed_default} installed but not selected"))),
            _ => out.push(ok("next boot", format!("boots the running kernel ({r})"))),
        },
        (d, r) => out.push(warn("next boot",
            format!("a reboot runs {d}, not the running {r} — boot it on a canary first"),
            Some(format!("see {runbook}")))),
    }

    // The GPU driver for the kernels a reboot can land on.
    if let Some(modules) = host["nvidia_module"].as_object() {
        let has = |k: &str| modules.get(k).and_then(|v| v.as_bool());
        if !default.is_empty() && has(&default) == Some(false) {
            out.push(fail("gpu driver",
                format!("the next boot ({default}) has no NVIDIA module — the GPU backends will not start"),
                format!("sudo dkms autoinstall -k {default}   # or make {running} the default again (see {runbook})")));
        } else if !fallback.is_empty() && has(&fallback) == Some(false) {
            out.push(warn("gpu driver",
                format!("the fallback kernel ({fallback}) has no NVIDIA module — if the next boot fails, the node comes back without its GPU"),
                Some(format!("make the running kernel the fallback before any kernel change (see {runbook})"))));
        } else {
            out.push(ok("gpu driver", "NVIDIA module present for the next boot and its fallback"));
        }
    }

    out.extend(boot_partition_check(id, host, &running, &default));

    // Platform packages held.
    if let Some(platform) = host["platform"].as_object() {
        let held: Vec<&str> = host["held"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
        let mut unheld: Vec<&str> = platform.keys().map(String::as_str).filter(|p| !held.contains(p)).collect();
        unheld.sort_unstable();
        if unheld.is_empty() {
            out.push(ok("holds", format!("{} platform package(s) held", platform.len())));
        } else {
            out.push(warn("holds",
                format!("platform package(s) not held — an ordinary `apt upgrade` moves them: {}", unheld.join(", ")),
                Some(format!("the hold command in {runbook}"))));
        }
    }

    out.push(host_telemetry_check(id, host));

    // Tailscale's control plane, not just its data paths.
    let online = host["tailscale_online"].as_bool();
    let state = s("tailscale_state");
    if online == Some(false) || (!state.is_empty() && state != "Running") {
        // Say how old the reading is. noo-hostd re-reads within a minute
        // while tailscale is not connected, so a reading taken mid-boot
        // ("NoState") clears on its own; on host2, 2026-10-01, a five-minute
        // old boot-time reading read as a stall and tailscaled was restarted
        // for nothing.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let collected = host["collected_at"].as_str().and_then(parse_rfc3339_unix);
        let read = collected
            .map(|t| format!("; read {} ago", age_str(now - t)))
            .unwrap_or_default();
        // Taken while the boot was still bringing tailscaled up: that is a
        // node starting, not a stall. hostd re-reads within a minute.
        let since_boot = collected
            .zip(host["booted_at"].as_str().and_then(parse_rfc3339_unix))
            .map(|(c, b)| c - b);
        if let Some(secs) = since_boot.filter(|s| (0..TAILNET_BOOT_GRACE_SECS).contains(s)) {
            out.push(Check {
                name: "tailnet control",
                verdict: Verdict::Starting,
                detail: format!(
                    "starting — read {secs}s after boot (state {}{read}); noo-hostd re-reads within a minute",
                    if state.is_empty() { "?" } else { &state }
                ),
                remedy: Some(format!("noo cluster verify {id}   # re-run in a minute")),
            });
            return out;
        }
        out.push(fail("tailnet control",
            format!("tailscale is not connected to its control plane (state {}, online {}{read}) — the node stops seeing new devices and policy changes while existing paths keep working",
                if state.is_empty() { "?" } else { &state }, online.map(|b| b.to_string()).unwrap_or_else(|| "?".into())),
            "sudo systemctl restart tailscaled   # only if a re-run a minute later still says this; right after a boot it is still starting"));
    } else if online == Some(true) {
        out.push(ok("tailnet control", "connected to the control plane"));
    }
    out
}

/// The `host telemetry` row (docs/security/telemetry.md, "Host software").
/// A sibling of `vendor telemetry`, not part of it: that row judges backend
/// containers from the node agent's `backend_containers` report and is fixed by
/// `noo cluster provision`; this one judges the HOST (tailscaled and the OS's
/// own reporters) from noo-hostd's facts and is fixed by an operator command
/// on the node. Pure over `hostd.host`.
///
/// - tailscaled running without `--no-logs-no-support` / `TS_NO_LOGS_NO_SUPPORT`
///   FAILs: noomesh installed it, and it uploads client logs to Tailscale. The
///   switch also opts out of Tailscale technical support (Tailscale's words).
/// - an enabled Ubuntu reporter (motd-news, popularity-contest, whoopsie) WARNs:
///   it belongs to the OS, so noomesh reports it and prints the command.
/// - a hostd that does not report the facts WARNs, never a pass.
pub(crate) fn host_telemetry_check(id: &str, host: &Value) -> Check {
    const NAME: &str = "host telemetry";
    let tel = &host["telemetry"];
    if !tel.is_object() {
        return warn(NAME, "this node's noo-hostd predates host telemetry facts — tailscaled's log upload and the OS reporters are not proven",
            Some(format!("noo cluster provision {id} --wait")));
    }
    let mac = host["os"].as_str() == Some("darwin");
    let configured = tel["tailscale_logs_configured"].as_bool() == Some(true);
    let mut bad: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    match tel["tailscale_logs"].as_str().unwrap_or("") {
        "on" => {
            let apply: String = if mac {
                // Either brew label: sh.brew.tailscale is current Homebrew.
                String::from("P=/Library/LaunchDaemons/sh.brew.tailscale.plist; [ -f $P ] || P=/Library/LaunchDaemons/homebrew.mxcl.tailscale.plist; \\
                         sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables dict' $P; \\
                         sudo /usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT' $P; \\
                         sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT string true' $P; \\
                         sudo launchctl bootout system $P; sudo launchctl bootstrap system $P")
            } else if configured {
                "sudo systemctl restart tailscaled".into()
            } else {
                "echo 'TS_NO_LOGS_NO_SUPPORT=true' | sudo tee -a /etc/default/tailscaled && sudo systemctl restart tailscaled".into()
            };
            let drops = "restarting tailscaled drops the tailnet link for a few seconds — on the controller, do it at the console, not over the tailnet";
            // The operator's one command: the same switch, delivered over the
            // pull rail, one node at a time. The by-hand form stays for a node
            // whose applier predates the kind.
            let rail = format!("noo cluster host-telemetry apply {id}");
            if tel["tailscale_logs_operator_choice"].as_bool() == Some(true) {
                // The operator asked for the upload (Tailscale support needs
                // it): not a failure, but not silent either.
                const M: &str = crate::vendor::TAILSCALE_UPLOAD_MARKER;
                warns.push(format!("tailscaled uploads its client logs to Tailscale by operator choice ({M} exists)"));
                fixes.push(format!("when Tailscale support no longer needs them: sudo rm {M} on the node, then `{rail}`   # or by hand: {apply}   # {drops}"));
            } else {
                bad.push("tailscaled uploads its client logs to Tailscale (no --no-logs-no-support; the switch also opts out of Tailscale technical support)".into());
                fixes.push(format!("`{rail}`   # over the pull rail; by hand on the node: {apply}   # {drops}"));
            }
        }
        "unmanaged" => warns.push("tailscale is not the brew formula (the Standalone or App Store app): Tailscale only lets the open-source tailscaled switch off its log upload".into()),
        "unknown" => warns.push("tailscaled's command line or environment could not be read — the log upload switch is not proven".into()),
        _ => {} // off, or tailscaled not running
    }
    let reporters: Vec<&str> = tel["os_reporters"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    for r in &reporters {
        match *r {
            "motd-news" => {
                warns.push("motd-news is enabled (fetches from motd.ubuntu.com)".into());
                fixes.push("sudo sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news && sudo systemctl disable --now motd-news.timer".into());
            }
            "popularity-contest" => {
                warns.push("popularity-contest participates (weekly package report to popcon.ubuntu.com)".into());
                fixes.push("sudo sed -i 's/^PARTICIPATE=.*/PARTICIPATE=\"no\"/' /etc/popularity-contest.conf".into());
            }
            "whoopsie" => {
                warns.push("whoopsie is active (uploads crash reports to daisy.ubuntu.com)".into());
                fixes.push("sudo systemctl disable --now whoopsie".into());
            }
            other => warns.push(format!("{other} is enabled")),
        }
    }
    let mut detail = bad.clone();
    detail.extend(warns.iter().cloned());
    if detail.is_empty() {
        return ok(NAME, "tailscaled's log upload is off or tailscaled is not running here, and no Ubuntu reporter is enabled");
    }
    let remedy = if fixes.is_empty() { None } else { Some(fixes.join("; ")) };
    if !bad.is_empty() {
        return fail(NAME, detail.join("; "), remedy.unwrap_or_default());
    }
    warn(NAME, detail.join("; "), remedy)
}

/// The `boot partition` row (2026-10-01, the controller): the ESP was 100%
/// full, kernel 7.1.5's initramfs was 315 MB (uncompressed DKMS NVIDIA
/// modules; ~140 MB for the others), kernelstub's copy of it to the ESP was
/// truncated, and the reboot looped before any journal. Pure over
/// `host.boot_partition`.
///
/// FAIL: the ESP copy of the next-boot initrd is smaller than /boot's.
/// WARN: the ESP lacks room for the next-boot initrd (or is under 20% free),
/// the next-boot initrd is outsized (>= 1.5x the running kernel's), or its DKMS
/// modules are uncompressed while another kernel's are not. Unread reads as
/// "not checked"; an agent that does not send the object, "older agent".
pub(crate) fn boot_partition_check(id: &str, host: &Value, running: &str, default: &str) -> Option<Check> {
    const NAME: &str = "boot partition";
    // WSL2 has no boot partition for the mesh to read, old agent or new:
    // Windows boots the VM, so there is no ESP and no /boot initrd to judge
    // (host3, 2026-10-09: a new agent's empty object read "not checked").
    // Not applicable, said as a pass, like the `next boot` row.
    if is_wsl2(running) {
        return Some(ok(NAME, format!("WSL2 — Windows boots this node ({running}); there is no ESP or /boot initrd on it to check")));
    }
    let bp = &host["boot_partition"];
    if !bp.is_object() {
        return Some(warn(NAME, "not reported (older agent)", Some(format!("noo cluster provision {id} --wait"))));
    }
    let n = |k: &str| bp[k].as_u64();
    let size_of = |obj: &str, kernel: &str| bp[obj][kernel].as_u64();
    // The kernel a reboot lands on; the running one when the loader is unknown.
    let next = if default.is_empty() { running } else { default };
    let (initrd, esp_copy) = (size_of("initrd_bytes", next), size_of("esp_initrd_bytes", next));
    let mb = |b: u64| format!("{} MB", b / 1_000_000);
    // "full" is a fact hostd now reports (free_bytes: 0); absent is unknown.
    let esp_state = match n("free_bytes") {
        Some(f) if f < 1_000_000 => "full".to_string(),
        Some(f) => format!("{} free", mb(f)),
        None => "of unknown free space".into(),
    };
    // The loader's effective default entry, and where it came from: an EFI
    // variable (LoaderEntryDefault) overrides loader.conf.
    let default_entry = bp["default_entry"].as_str().filter(|e| !e.is_empty());
    let default_note = default_entry.map(|e| {
        let src = bp["default_entry_source"].as_str().unwrap_or("");
        match src {
            "efi-var" => format!("the loader's default entry is {e} (set by the EFI variable LoaderEntryDefault, which overrides loader.conf)"),
            "loader.conf" => format!("the loader's default entry is {e} (from loader.conf)"),
            _ => format!("the loader's default entry is {e}"),
        }
    });
    // The entry to pin: its ESP kernel is the RUNNING one and its ESP initrd is intact.
    let known_good = bp["entries"].as_array().and_then(|es| {
        es.iter().find(|e| e["kernel"].as_str() == Some(running) && e["intact"].as_bool() == Some(true))
            .and_then(|e| e["name"].as_str())
    });
    let pin = match known_good {
        Some(name) => format!("FIRST pin a known-good entry (its ESP kernel is the running {running} and its initrd is intact): `sudo bootctl set-default {name}`; read `bootctl list` for the effective default — an EFI-variable default overrides loader.conf"),
        None => format!("FIRST pin a known-good entry: `bootctl list`, then `sudo bootctl set-default <the entry whose kernel is the running {running} and whose initrd is intact>` — no such entry was found on the ESP, so do not reboot"),
    };
    // Why an initrd is huge, when it is.
    let ratio = match (initrd, size_of("initrd_bytes", running)) {
        (Some(i), Some(r)) if !running.is_empty() && next != running && r > 0 && i * 2 >= r * 3 => Some((i, r)),
        _ => None,
    };
    let bloat = |kernel: &str| format!("list its biggest members with `lsinitramfs -l /boot/initrd.img-{kernel} | sort -k5 -n | tail` (on Pop!_OS /usr/share/initramfs-tools/hooks/framebuffer-nvidia copies the NVIDIA module and GSP firmware in, ~220 MB)");

    // The line that keeps the operator off apt while the ESP is full: removing
    // or installing a kernel re-runs /etc/kernel/postinst.d (kernelstub), which
    // needs ESP room. On host8 (2026-10-06) `apt autoremove --purge` did exactly
    // that, failed with ENOSPC on the initrd copy, and left the new kernel's
    // package half-configured. Tests strip this phrase and assert no other apt.
    const NO_APT: &str = "do NOT run `apt` / `apt autoremove` while this row fails — removing or installing a kernel re-runs kernelstub, which needs ESP room";
    let mount = bp["mount"].as_str().unwrap_or("/boot/efi");
    // Truncated copy: the boot loader cannot load what was cut short.
    if let (Some(boot), Some(esp)) = (initrd, esp_copy) {
        if esp < boot {
            let mut detail = format!("the ESP copy of the next-boot initrd ({next}) is {} but /boot's is {} — truncated, the next boot will not start (the ESP is {esp_state})",
                mb(esp), mb(boot));
            if let Some(d) = &default_note {
                detail.push_str(&format!("; {d}"));
            }
            if let Some((i, r)) = ratio {
                detail.push_str(&format!("; that initrd is {:.1}x the running kernel's ({}) — initramfs bloat", i as f64 / r as f64, mb(r)));
            }
            let mut steps = vec![
                pin,
                format!("do NOT run kernelstub while the ESP lacks room for the {next} initrd ({}): it rotates the ESP's *-previous copies and would overwrite the fallback, and that rotation is likely what truncated this copy", mb(boot)),
                NO_APT.to_string(),
                format!("the ESP holds each kernel's vmlinuz and initrd under {mount}/EFI/<dir>/ (see `bootctl list`); the space problem is the oversized next-boot initrd ({}), not old kernels — freeing space by removing packages is the wrong lever", mb(boot)),
            ];
            if ratio.is_some() {
                steps.push(format!("shrink the initrd first — {}", bloat(next)));
            }
            steps.push(format!("then copy it over the truncated ESP file by hand: `sudo cp /boot/initrd.img-{next} {mount}/EFI/<dir>/initrd.img` (overwriting frees the old file's space first, so it needs only the difference)"));
            steps.push(format!("verify the copy with `cmp /boot/initrd.img-{next} {mount}/EFI/<dir>/initrd.img`"));
            let oneshot = known_good.unwrap_or("<current-entry>");
            steps.push(format!("test with `sudo bootctl set-oneshot {oneshot}` before unpinning, then re-run verify"));
            return Some(fail(NAME, detail, steps.join("; ")));
        }
    }

    let mut problems: Vec<String> = Vec::new();
    let mut remedy = None;
    let mut remedy_kernel = next.to_string();
    // Room on the ESP.
    if let (Some(total), Some(free)) = (n("total_bytes"), n("free_bytes")) {
        let mount = bp["mount"].as_str().unwrap_or("the ESP");
        // The loader's effective entry is intact on the ESP: the next BOOT is
        // safe, and a full ESP only blocks the next kernel INSTALL (kernelstub
        // copies that kernel's initrd there). Name that kernel and its size.
        let entry_intact = default_entry.is_some_and(|d| bp["entries"].as_array()
            .is_some_and(|es| es.iter().any(|e| e["name"].as_str() == Some(d) && e["intact"].as_bool() == Some(true))));
        let installed = host["default_kernel"].as_str().filter(|k| !k.is_empty() && *k != next);
        let upcoming = installed.and_then(|k| size_of("initrd_bytes", k).map(|b| (k, b)));
        let have = if free < 1_000_000 { "is full".to_string() } else { format!("has {} free", mb(free)) };
        match (entry_intact, upcoming) {
            (true, Some((k, b))) if free < b => {
                problems.push(format!("the pinned entry ({next}) is intact; {mount} {have}, so the next kernel install ({k}, {} initrd) cannot be copied — shrink its initrd first (see remedy)", mb(b)));
                remedy_kernel = k.to_string();
            }
            (true, _) => {}
            _ if initrd.is_some_and(|i| free < i) => {
                problems.push(format!("{mount} {have}, less than the next-boot initrd needs ({})", mb(initrd.unwrap_or(0))));
            }
            _ if total > 0 && free * 5 < total => {
                problems.push(format!("{mount} is {}% full ({} free of {})", 100 - free * 100 / total, mb(free), mb(total)));
            }
            _ => {}
        }
        if !problems.is_empty() {
            let k = &remedy_kernel;
            remedy = Some(format!("{NO_APT}; do NOT run kernelstub while the ESP lacks room for the new initrd — it rotates the *-previous copies; shrink the {k} initrd and copy it to the ESP by hand (`sudo cp /boot/initrd.img-{k} {mount}/EFI/<dir>/initrd.img`, then `cmp`)"));
        }
    }
    // An outsized initrd, and the usual reason.
    let uncompressed = bp["dkms_compressed"][next].as_bool() == Some(false)
        && bp["dkms_compressed"].as_object().is_some_and(|m| m.iter().any(|(k, v)| k != next && v.as_bool() == Some(true)));
    let outsized = ratio.is_some();
    if outsized || uncompressed {
        let why = if uncompressed { "its DKMS modules are uncompressed (.ko, not .ko.zst)" } else { "cause unknown" };
        problems.push(format!("the next-boot initrd for {next}{} is outsized — {why}",
            initrd.map(|i| format!(" ({})", mb(i))).unwrap_or_default()));
        let cause = if uncompressed { String::new() } else { format!("; {}", bloat(next)) };
        remedy = Some(format!("{}; sudo zstd --rm /lib/modules/{next}/updates/dkms/*.ko && sudo depmod {next} && sudo update-initramfs -u -k {next}{cause}; do NOT run kernelstub while the ESP lacks room for the new initrd (it rotates *-previous)", pin));
    }
    if !problems.is_empty() {
        return Some(warn(NAME, problems.join("; "), remedy));
    }
    if n("total_bytes").is_none() && initrd.is_none() {
        return Some(warn(NAME, "not checked (the ESP and /boot initrds could not be read)", None));
    }
    let mut seen = Vec::new();
    if let (Some(total), Some(free)) = (n("total_bytes"), n("free_bytes")) {
        seen.push(format!("ESP {} free of {}", mb(free), mb(total)));
    } else {
        seen.push("ESP size not read".into());
    }
    if let Some(d) = default_entry {
        seen.push(format!("default entry {d} ({})", bp["default_entry_source"].as_str().unwrap_or("source unknown")));
    }
    seen.push(if esp_copy.is_some() { format!("ESP copy of {next} initrd matches /boot") } else { "ESP copy not read".into() });
    Some(ok(NAME, seen.join("; ")))
}

/// A tailscale reading taken this soon after boot is "starting", not a
/// stall: tailscaled is still loading its state ("NoState").
const TAILNET_BOOT_GRACE_SECS: i64 = 120;

/// A shipper that has accepted nothing for this long while it still holds
/// lines is stalled, not slow: batches flush every 2 s and the retry
/// backoff tops out at 60 s.
const LOG_SHIP_STALL_SECS: i64 = 15 * 60;

/// `1234s` → `20m`, `2h`, `3d`: the age a row prints.
fn age_str(secs: i64) -> String {
    match secs {
        s if s < 0 => "in the future".into(),
        s if s < 90 => format!("{s}s"),
        s if s < 90 * 60 => format!("{}m", s / 60),
        s if s < 36 * 3600 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// The "log shipper" row (fleet logging phase 6). Pure over the node's
/// `log_ship` heartbeat object — `{enabled, queued, shipped_total,
/// dropped_total, last_accepted_unix, last_error, route_ready,
/// spill_pending, journal}` — so every verdict is pinned on a canned record.
///
/// The journal follower is folded in rather than given a row of its own:
/// it is one input of the same shipper (hostd's `journal-follow` op feeds
/// the agent's journal source), its status string already carries its
/// remedy, and a second row would read "-" on every Mac and on every agent
/// that predates the shipper — two lines to read for one fact.
///
/// Order of judgement: not reported → off by choice → the gateway has no
/// route → stalled → journal not following → OK. The first three say why
/// nothing ships; only "stalled" is a failure, because it is the one state
/// where the operator believes logs arrive and they do not.
pub(crate) fn log_shipper_check(id: &str, ls: &Value, now_unix: i64, hb_recent: bool) -> Check {
    if ls.is_null() {
        // Not a failure: an agent built before the shipper reports nothing,
        // and the `version` row already says whether it is behind.
        return if hb_recent {
            ok("log shipper", "not reported yet — re-run after the next heartbeat; an agent that never reports it predates the shipper")
        } else {
            ok("log shipper", format!("not reported — the agent predates the shipper (noo cluster provision {id} --wait)"))
        };
    }
    let last_error = ls["last_error"].as_str().unwrap_or("").trim().to_string();
    if ls["enabled"].as_bool() != Some(true) {
        let why = if last_error.is_empty() { "no reason reported".to_string() } else { last_error };
        return warn("log shipper", format!("off: {why}"),
            Some(format!("NOO_LOG_SHIP=1 in /etc/noo-node-agent.env on {id} and restart the agent; if it has no TLS material: noo cluster provision {id}")));
    }
    if ls["route_ready"].as_bool() == Some(false) {
        return warn("log shipper",
            "enabled, but the gateway's ingest route is not answering (an older gateway?) — the agent re-probes every 10 minutes",
            Some("noo upgrade --stack   # the gateway image with POST /api/cluster/nodes/{self}/logs".into()));
    }
    let queued = ls["queued"].as_i64().unwrap_or(0);
    // A bool on the wire (`spill.pending()`); a count is accepted too.
    let spill = ls["spill_pending"].as_bool().unwrap_or_else(|| ls["spill_pending"].as_i64().unwrap_or(0) > 0);
    let shipped = ls["shipped_total"].as_i64().unwrap_or(0);
    let dropped = ls["dropped_total"].as_i64().unwrap_or(0);
    let last_accepted = ls["last_accepted_unix"].as_i64().unwrap_or(0);
    let holding = queued > 0 || spill;
    if holding && last_accepted > 0 && now_unix - last_accepted > LOG_SHIP_STALL_SECS {
        let err = if last_error.is_empty() { "no error reported".to_string() } else { last_error };
        return fail("log shipper",
            format!("shipping stalled since {} ago ({queued} queued{}): {err}", age_str(now_unix - last_accepted), if spill { ", more spilled to disk" } else { "" }),
            format!("noo cluster logs {id} agent   # the agent's own account; then noo logs status on the controller"));
    }
    if holding && last_accepted == 0 {
        if !last_error.is_empty() {
            return fail("log shipper",
                format!("nothing accepted yet and the gateway refuses ({queued} queued{}): {last_error}", if spill { ", more spilled to disk" } else { "" }),
                format!("noo cluster logs {id} agent   # then noo logs status on the controller"));
        }
        return warn("log shipper", format!("nothing accepted yet ({queued} queued) — re-run after the next heartbeat"), None);
    }
    // The journal follower, on Linux (a Mac tails files and reports no
    // `journal` key at all). Its string carries the remedy.
    if let Some(j) = ls["journal"].as_str() {
        if j != "running" {
            return warn("log shipper",
                format!("containers ship; the host journal does not: {j}"),
                Some(format!("noo cluster provision {id} --wait   # delivers hostd's journal-follow op with the agent")));
        }
    }
    let dropped_note = if dropped > 0 { format!(", {dropped} dropped past the spill cap") } else { String::new() };
    if last_accepted > 0 {
        ok("log shipper", format!("shipped {shipped}, last accepted {} ago{dropped_note}", age_str(now_unix - last_accepted)))
    } else {
        ok("log shipper", format!("enabled, nothing to ship yet{dropped_note}"))
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` → unix seconds. Hand-rolled: the
/// crate carries no date library, and the heartbeat stamp is one fixed shape
/// the gateway itself writes.
pub(crate) fn parse_rfc3339_unix(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    // Skip fractional seconds; then the offset.
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.chars().take_while(|c| c.is_ascii_digit()).count();
        rest = &r[n..];
    }
    let offset = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let oh = o[1..3].parse::<i64>().ok()?;
            let om = o[4..6].parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

/// Howard Hinnant's days-from-civil; 1970-01-01 → 0.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn signing_adopted_for(node: &str) -> Option<bool> {
    let dir = crate::pki::pki_dir().join("nodes").join(node);
    if !dir.is_dir() {
        return None;
    }
    Some(dir.join("signing-adopted").is_file())
}

// ── the controller half ────────────────────────────────────────────────

/// The `model classes` row: every DECLARED candidate placed or available.
/// Derived classes are what the fleet serves by definition, so they cannot
/// be unplaced. Unplaced → WARN naming class and node, with the placement
/// that would fix it; a declared class with NO routable candidate → FAIL
/// (requests naming it get 503).
pub(crate) fn model_classes_check(classes: Option<&Value>) -> Check {
    let Some(body) = classes else {
        return warn("model classes", "not read", Some("noo cluster class list".into()));
    };
    let empty = Vec::new();
    let declared: Vec<&Value> = body["classes"].as_array().unwrap_or(&empty).iter()
        .filter(|c| c["declared"].as_bool().unwrap_or(false)).collect();
    if declared.is_empty() {
        let derived = body["classes"].as_array().map(|a| a.len()).unwrap_or(0);
        return ok("model classes", format!("none declared; {derived} derived from what the fleet serves"));
    }
    let mut unplaced: Vec<String> = Vec::new();
    let mut dead: Vec<String> = Vec::new();
    let mut remedy: Option<String> = None;
    for c in &declared {
        let name = c["name"].as_str().unwrap_or("?");
        let cands = c["candidates"].as_array().unwrap_or(&empty);
        if c["routable"].as_u64().unwrap_or(0) == 0 {
            dead.push(name.to_string());
        }
        for cand in cands {
            if cand["status"].as_str() == Some("unplaced") {
                let node = cand["node_id"].as_str().unwrap_or("?");
                let backend = cand["backend"].as_str().unwrap_or("?");
                let model = cand["model"].as_str().unwrap_or("?");
                unplaced.push(format!("{name}: {node}/{backend}={model}"));
                remedy.get_or_insert_with(|| format!("noo cluster place {node} {backend} {model}"));
            }
        }
    }
    if !dead.is_empty() {
        return fail("model classes", format!("no routable candidate for {}: requests naming it get 503", dead.join(", ")),
            remedy.unwrap_or_else(|| "noo cluster class list".into()));
    }
    if !unplaced.is_empty() {
        return warn("model classes", format!("{} declared candidate(s) neither running nor pulled, skipped at routing: {}", unplaced.len(), unplaced.join("; ")), remedy);
    }
    let total: usize = declared.iter().map(|c| c["candidates"].as_array().map(|a| a.len()).unwrap_or(0)).sum();
    ok("model classes", format!("{} declared class(es), {total} candidate(s) all placed or available", declared.len()))
}

/// Run this binary with `words` and `--json`; the parsed stdout and the exit
/// code. One definition per check lives in the verb itself.
fn self_json(g: &Globals, words: &[&str]) -> (i32, Value, String) {
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "noo".into());
    let mut cmd = Command::new(exe);
    cmd.args(words).arg("--json");
    if let Some(gw) = &g.gateway_override {
        cmd.arg("-G").arg(gw);
    }
    // The token rides the environment ($NOO_TOKEN), never argv: a command
    // line is readable by every local user.
    if let Some(t) = &g.token {
        cmd.env("NOO_TOKEN", t);
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => return (127, Value::Null, format!("could not run: {e}")),
    };
    let code = out.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let parsed = serde_json::from_str::<Value>(stdout.trim()).unwrap_or(Value::Null);
    (code, parsed, if stderr.trim().is_empty() { stdout } else { stderr })
}

/// The per-consumer keys an install must hold, as `(provision name,
/// consumer)`: every add-on key its overlay declares (`x-noo-addon`, proposal
/// 56 phase B) while that add-on is on, plus every CORE `NOO_SVC_KEY_*` row
/// (the worker) always. Read from the declarations, not guessed from the key's
/// spelling — the old derivation turned `NOO_SVC_KEY_TRELLION_INTEL` back
/// into an add-on name and hoped `addons::row` agreed.
pub(crate) fn required_service_keys(addon_on: &dyn Fn(&str) -> bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for spec in crate::commands::secrets::CORE_REGISTRY {
        let Some(short) = spec.key.strip_prefix("NOO_SVC_KEY_") else { continue };
        let name = short.to_ascii_lowercase().replace('_', "-");
        out.push((name.clone(), format!("svc:{name}")));
    }
    for d in crate::commands::secrets::addon_decls() {
        if addon_on(d.addon) {
            out.push((d.addon.replace('_', "-"), d.consumer.to_string()));
        }
    }
    out
}

/// Does each active key carry everything its declaration now asks for?
///
/// A key is minted once; the overlay can widen its ask in a later release.
/// The key then keeps the grant it was minted with and the new call is
/// refused — the earlier shape, where evolve's key opened one of its six
/// writes. Nothing else makes an upgrade that widens an add-on's ask
/// visible. A WARN, not a failure: the add-on still works on the words it
/// has, and the fix is the operator's grant, one `provision` away.
pub(crate) fn service_key_grants_check(keys: &Value, required: &[(String, String)]) -> Check {
    let empty = Vec::new();
    let mut short: Vec<(String, Vec<String>)> = Vec::new();
    let mut judged = 0usize;
    for (name, consumer) in required {
        let wanted = crate::commands::secrets::provisioned_scopes(consumer, &[]);
        // The newest active, non-superseded row is the key in use.
        let Some(k) = keys["keys"].as_array().unwrap_or(&empty).iter().rev().find(|k| {
            k["consumer"].as_str() == Some(consumer.as_str())
                && k["active"].as_bool().unwrap_or(false)
                && k["superseded_at"].is_null()
        }) else { continue };
        judged += 1;
        let has: Vec<String> = k["scopes"].as_array().unwrap_or(&empty).iter()
            .filter_map(|s| s.as_str().map(str::to_string)).collect();
        let (mut missing, _) = crate::commands::secrets::scope_diff(&has, &wanted);
        // A renamed section's scope is held under either spelling.
        missing.retain(|w| !crate::commands::secrets::scope_held(&has, w));
        if !missing.is_empty() {
            short.push((name.clone(), missing));
        }
    }
    if short.is_empty() {
        return ok("service-key grants", format!("{judged} active key(s) carry what their declaration asks for"));
    }
    let detail = short.iter().map(|(n, m)| format!("{n} lacks {}", m.join(", "))).collect::<Vec<_>>().join("; ");
    warn(
        "service-key grants",
        format!("{detail} — minted before its declaration asked for it; those calls are refused"),
        Some(format!("noo security service-key provision {}", short[0].0)),
    )
}

/// Can Prometheus scrape this controller's `/metrics`? Since an earlier release
/// the page answers an Operator/Admin login or the scraper's service leaf,
/// and the gateway sees that leaf only while mTLS is enforced (the default;
/// `NOO_MTLS_GATEWAY=false` in `.env` is the explicit opt-out). Either
/// missing means empty dashboards, never a public page — so say which.
/// A warning, not a failure: a controller may run no Prometheus at all.
pub(crate) fn metrics_scrape_check(mtls: Option<bool>, missing_leaves: &[&str]) -> Check {
    if mtls != Some(true) {
        return warn(
            "metrics scrape",
            "mTLS enforcement is switched off (NOO_MTLS_GATEWAY=false in .env): the gateway does not read client certificates, so Prometheus cannot scrape /metrics, and a node can present a fleet token naming another node",
            Some("remove NOO_MTLS_GATEWAY=false from .env and recreate the gateway (noo stack restart --force)".into()),
        );
    }
    if let Some(first) = missing_leaves.first() {
        return warn(
            "metrics scrape",
            format!("missing service leaves: {} — the monitoring stack authenticates by these and will not start or scrape without them", missing_leaves.join(", ")),
            Some(format!("noo security pki issue-service {first}")),
        );
    }
    ok("metrics scrape", "Prometheus authenticates by its leaf; people need Operator/Admin")
}

/// The service leaves the monitoring stack authenticates with.
pub(crate) const MONITORING_LEAVES: &[&str] = &["prometheus", "alertmanager", "grafana", "node-exporter", "nvidia-exporter"];

/// The service leaves the DATA plane serves with: the
/// model cache presents `services/model-cache` on its mTLS listener and
/// requires a node or gateway leaf back. Issued by onboard like the
/// monitoring leaves, and pinned to `SVC_LIST` by the same test.
pub(crate) const DATA_PLANE_LEAVES: &[&str] = &["model-cache"];

/// Does the rendered nginx conf carry a plaintext listener? Phase 1 of
/// An earlier release kept `listen 8083;` for one release behind two
/// version floors (`MODEL_CACHE_TLS_AGENT_MIN` v0.2.77 / CLI v0.5.62);
/// phase 2 (2026-09-29) deleted the listener and the floors with it — the
/// row no longer depends on any tag, and a plain listener is a failure.
/// Read from the running checkout (`~/.noo` on a standalone controller);
/// `None` when the file is unreadable, which the row says rather than
/// guessing either way.
fn model_cache_plain_listener_open() -> Option<bool> {
    let conf = std::fs::read_to_string(crate::envfile::repo_root().join("docker").join("model-cache.nginx.conf")).ok()?;
    Some(nginx_has_plain_listener(&conf))
}

/// `listen 8083;` — or any `listen` without `ssl` on a port other than the
/// loopback healthz — in the model-cache nginx conf, comments stripped.
pub(crate) fn nginx_has_plain_listener(conf: &str) -> bool {
    conf.lines().map(|l| l.split('#').next().unwrap_or("").trim()).any(|l| {
        let Some(rest) = l.strip_prefix("listen ") else { return false };
        let rest = rest.trim_end_matches(';');
        let mut parts = rest.split_whitespace();
        let addr = parts.next().unwrap_or("");
        let ssl = parts.any(|p| p == "ssl");
        !ssl && !addr.starts_with("127.0.0.1:")
    })
}

/// Does the compose file the stack runs from still publish the model
/// cache's plaintext port? `None` when unreadable.
fn model_cache_plain_port_published() -> Option<bool> {
    let compose = std::fs::read_to_string(crate::envfile::repo_root().join("docker-compose.cluster.yml")).ok()?;
    Some(compose_publishes_plain_model_cache(&compose))
}

/// The `model-cache` service's `ports:` entries, comments stripped: any
/// entry whose container port is not 8443, or that names the retired
/// `NOO_MODEL_CACHE_PORT`, is the plaintext publish coming back.
pub(crate) fn compose_publishes_plain_model_cache(compose: &str) -> bool {
    let Some(block) = compose.split("\n  model-cache:\n").nth(1) else { return false };
    // The service ends at the next top-level key.
    let block = block.split("\nnetworks:\n").next().unwrap_or(block);
    let mut in_ports = false;
    for raw in block.lines() {
        let l = raw.split('#').next().unwrap_or("").trim_end();
        if l.trim().is_empty() {
            continue;
        }
        // The next service starts at two-space indent; the ports list is
        // the six-space entries under a four-space `ports:`.
        if l.starts_with("  ") && !l.starts_with("    ") {
            break;
        }
        if l.starts_with("    ports:") {
            in_ports = true;
            continue;
        }
        if in_ports && !l.starts_with("      ") {
            in_ports = false;
        }
        if !in_ports {
            continue;
        }
        let entry = l.trim().trim_start_matches("- ").trim_matches('"').trim_matches('\'');
        if entry.contains("NOO_MODEL_CACHE_PORT") || entry.rsplit(':').next() != Some("8443") {
            return true;
        }
    }
    false
}

/// One externally reachable service leaf and what it lacks: `Ok(missing)`
/// (empty = covers the derived names) or `Err` when the file would not parse.
pub(crate) type LeafNames = (String, Result<Vec<String>, String>);

/// Every `EXTERNALLY_REACHABLE` service leaf present under `pki_dir`,
/// compared with `service_cert_sans` for this box. A leaf
/// that is absent is not judged here: the per-service rows name that.
pub(crate) fn externally_reachable_leaf_names(
    pki_dir: &std::path::Path,
    hostname: &str,
    node_ip: &str,
    ts_dnsname: &str,
) -> Vec<LeafNames> {
    let mut out = Vec::new();
    for svc in crate::onboard::steps::EXTERNALLY_REACHABLE {
        let crt = pki_dir.join("services").join(svc).join("service.crt");
        if !crt.is_file() {
            continue;
        }
        let (extra, extra_ips) = crate::onboard::steps::service_cert_sans(svc, hostname, node_ip, ts_dnsname);
        let mut want: Vec<String> = vec![svc.to_string(), "localhost".into()];
        want.extend(extra);
        let r = crate::pki::ClusterCa::cert_names(&crt).map(|have| crate::pki::missing_names(&have, &want, &extra_ips));
        out.push((svc.to_string(), r));
    }
    out
}

/// The "service cert names" row. A leaf that serves remote
/// nodes (`nats`, `redis`, `postgres`, `model-cache`) must carry the names
/// they dial: the tailnet name when the box has one, `noo-controller`, the
/// hostname and the LAN IP. A short one fails every remote handshake by
/// name (`x509: certificate is valid for model-cache, localhost, not <name>`)
/// while the container reports healthy.
pub(crate) fn service_cert_names_check(leaves: &[LeafNames]) -> Check {
    const NAME: &str = "service cert names";
    let bad: Vec<&LeafNames> = leaves.iter().filter(|(_, r)| !matches!(r, Ok(m) if m.is_empty())).collect();
    if bad.is_empty() {
        return ok(NAME, format!("{} externally reachable leaf(s) carry the names remote nodes dial", leaves.len()));
    }
    let detail = bad
        .iter()
        .map(|(svc, r)| match r {
            Ok(m) => format!("{svc} lacks {}", m.join(", ")),
            Err(e) => format!("{svc} could not be read ({e})"),
        })
        .collect::<Vec<_>>()
        .join("; ");
    let remedy = bad
        .iter()
        .map(|(svc, _)| format!("noo security pki issue-service {svc}   # then: noo stack restart --force {svc}"))
        .collect::<Vec<_>>()
        .join(" ; ");
    fail(NAME, format!("{detail} — remote nodes dial these names and fail hostname verification"), remedy)
}

/// Nodes whose agent refused its `NOO_MODEL_CACHE_URL` (preseed.CacheURL
/// records scope `model_cache_url`: a plaintext value, or no leaf), with
/// the agent's own reason — the only way the controller can see what is in
/// a node's env file.
pub(crate) fn nodes_refusing_model_cache_url(fleet: &[Value]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for n in fleet {
        let Some(id) = n["id"].as_str() else { continue };
        if let Some(rs) = n["reconcile_refusals"].as_array() {
            for r in rs.iter().filter(|r| r["scope"] == "model_cache_url") {
                out.push((id.to_string(), r["reason"].as_str().unwrap_or("no reason reported").to_string()));
            }
        }
    }
    out
}

/// The "model cache" row. The leaf is the hard
/// invariant: without `services/model-cache/service.crt` the mTLS listener
/// does not start, and every node preseeds nothing. A plaintext listener in
/// the nginx conf, or a plaintext port in compose, is a FAILURE — the store
/// serves gated weights, and phase 2 closed the one-release exemption. A
/// node whose agent refused its `NOO_MODEL_CACHE_URL` fails the row by
/// name: it cannot preseed until re-provisioned, and nothing else on the
/// controller can tell the operator that.
pub(crate) fn model_cache_check(
    leaf_present: bool,
    plain_open: Option<bool>,
    plain_published: Option<bool>,
    refusing: &[(String, String)],
) -> Check {
    if !leaf_present {
        return fail(
            "model cache",
            "no services/model-cache/service.crt — the mTLS listener (8443) cannot start and no node can preseed",
            "noo security pki issue-service model-cache   # then: noo stack restart --force model-cache",
        );
    }
    if plain_open == Some(true) {
        return fail(
            "model cache",
            "docker/model-cache.nginx.conf carries a plaintext listener — the store serves gated weights and answers mTLS on 8443 only on a current stack",
            "remove the plain `listen` block from docker/model-cache.nginx.conf and recreate: noo stack restart --force",
        );
    }
    if plain_published == Some(true) {
        return fail(
            "model cache",
            "docker-compose.cluster.yml publishes a model-cache port other than 8443 (the retired plaintext 8083 / NOO_MODEL_CACHE_PORT mapping)",
            "keep exactly one `ports:` entry on model-cache (…:8443) and recreate: noo stack restart --force",
        );
    }
    if let Some((first, _)) = refusing.first() {
        let names = refusing.iter().map(|(n, why)| format!("{n} ({why})")).collect::<Vec<_>>().join("; ");
        return fail(
            "model cache",
            format!("leaf present; {} node(s) refuse their NOO_MODEL_CACHE_URL and cannot preseed: {names}", refusing.len()),
            format!("noo cluster provision {first}   # renders https://<controller>:8443 and the node leaf; then restart the agent"),
        );
    }
    match (plain_open, plain_published) {
        (Some(false), Some(false)) => ok("model cache", "leaf present; mTLS on 8443 only, and that is the only published port"),
        _ => warn(
            "model cache",
            "leaf present; could not read docker/model-cache.nginx.conf or docker-compose.cluster.yml to confirm no plaintext listener is open",
            None,
        ),
    }
}

/// Does the compose file the stack runs from give Grafana the SSO public
/// key? Read from the running checkout; `None` when unreadable.
fn grafana_mounts_sso_pub() -> Option<bool> {
    let compose = std::fs::read_to_string(crate::envfile::repo_root().join("docker-compose.cluster.yml")).ok()?;
    Some(compose.lines().map(|l| l.split('#').next().unwrap_or("").trim()).any(|l| {
        l.contains(crate::pki::ClusterCa::GRAFANA_SSO_PUB_REL) && l.contains(":/app/pki/sso/grafana.pub")
    }))
}

/// The "pki key modes" row. Every private key under the PKI dir has one
/// reader (`pki::KeyReader`). A key readable beyond it (0644, a group
/// that is not its reader's) is a FAIL: that is a private key someone
/// else can copy. So is a key owned by another uid that this CLI could not
/// take back: every re-issue and mode repair of it fails until the printed
/// `sudo chown` runs. A uid-read key its container cannot read is a WARN
/// carrying the sudo line (the CLI cannot `chgrp` to a group it is not
/// in, and there is no `setfacl`), and a leaf with no reader row is a
/// WARN naming the table. Issuance, `noo upgrade --stack`, provision and
/// onboard set every mode they can, so a FAIL here that needs no sudo
/// line means one of them has not run since the key changed.
pub(crate) fn pki_key_modes_check(issues: &[crate::pki::KeyIssue], grant_lines: &[String], total_keys: usize) -> Check {
    use crate::pki::KeyIssueKind as K;
    let names = |kind: K| -> Vec<String> {
        issues.iter().filter(|i| i.kind == kind).map(|i| format!("{} {:04o}", i.rel, i.mode)).collect()
    };
    let exposed = names(K::Exposed);
    if !exposed.is_empty() {
        return fail(
            "pki key modes",
            format!("{} private key(s) readable beyond their reader: {}", exposed.len(), exposed.join(", ")),
            if grant_lines.is_empty() {
                "noo security pki fix-modes   # no sudo needed; noo upgrade --stack repairs the same".to_string()
            } else {
                format!("noo security pki fix-modes   # then, as it prints: {}", grant_lines.join(" && "))
            },
        );
    }
    let foreign = names(K::WrongOwner);
    if !foreign.is_empty() {
        return fail(
            "pki key modes",
            format!("{} private key(s) owned by another uid and unreadable to this user — no re-issue or repair can touch them: {}", foreign.len(), foreign.join(", ")),
            if grant_lines.is_empty() { "noo security pki fix-modes --dry-run".to_string() } else { grant_lines.join(" && ") },
        );
    }
    let unreadable = names(K::Unreadable);
    if !unreadable.is_empty() {
        return warn(
            "pki key modes",
            format!("{} key(s) not readable by their container uid — the service fails its TLS start: {}", unreadable.len(), unreadable.join(", ")),
            Some(if grant_lines.is_empty() { "noo security pki fix-modes".to_string() } else { grant_lines.join(" && ") }),
        );
    }
    let unknown = names(K::UnknownReader);
    if !unknown.is_empty() {
        return warn(
            "pki key modes",
            format!("no reader entry for {} (left 0644)", unknown.join(", ")),
            Some("add the container uid to SERVICE_KEY_READERS in noo-cli/src/pki.rs".into()),
        );
    }
    ok("pki key modes", format!("{total_keys} private key(s), each readable only by its reader"))
}

/// `/etc/docker/daemon.json`: `Ok(None)` when there is none.
fn read_daemon_json() -> Result<Option<String>, String> {
    match std::fs::read_to_string("/etc/docker/daemon.json") {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The "docker userns" row. A daemon with
/// `userns-remap` shifts every container uid, root included, so the 0600
/// keys that root-in-container services (redis, nats, grafana, the
/// stunnels…) read through their bind mounts become unreadable and each
/// of them fails its TLS start. Nothing here enables it; this says so
/// before the services do.
pub(crate) fn docker_userns_check(daemon_json: Result<Option<String>, String>) -> Check {
    let text = match daemon_json {
        Ok(None) => return ok("docker userns", "no /etc/docker/daemon.json: container uids are not remapped"),
        Ok(Some(t)) => t,
        Err(e) => return warn("docker userns", format!("could not read /etc/docker/daemon.json ({e}) to confirm userns-remap is off"), None),
    };
    let remap = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) => v.get("userns-remap").and_then(|r| r.as_str()).unwrap_or("").trim().to_string(),
        Err(e) => return warn("docker userns", format!("/etc/docker/daemon.json is not JSON ({e}); cannot confirm userns-remap is off"), None),
    };
    if remap.is_empty() {
        return ok("docker userns", "userns-remap is off: root-in-container services read their 0600 keys");
    }
    fail(
        "docker userns",
        format!("/etc/docker/daemon.json sets userns-remap=\"{remap}\": container root is remapped, so every 0600 service key a root-in-container service reads is unreadable to it and its TLS start fails"),
        "remove \"userns-remap\" from /etc/docker/daemon.json, then: sudo systemctl restart docker",
    )
}

/// Everything the gateway may mount from the PKI dir: the
/// CA certificate, its own leaf, the Grafana SSO pair it signs with, and
/// the certificate-only view of `nodes/` and `services/`. Of these only
/// `gateway/gateway.key` and `sso/grafana.key` are private keys — its own.
/// `tests/test_pki_mounts_are_narrow.py` pins the same set statically.
pub(crate) const GATEWAY_PKI_MOUNTS: &[&str] = &["ca.crt", "gateway", "sso", "public/nodes", "public/services"];

/// The PKI-relative sources the compose `gateway` service mounts (`""` =
/// the PKI root itself), from the compose file as written. `None` when the
/// file has no gateway service.
pub(crate) fn gateway_pki_mounts(compose: &str) -> Option<Vec<String>> {
    let block = compose_service_block(compose, "gateway")?;
    let mut out = Vec::new();
    for line in block.lines() {
        let t = line.trim();
        let Some(t) = t.strip_prefix('-') else { continue };
        let t = t.trim().trim_matches('"').trim_matches('\'');
        if !t.starts_with("${NOO_PKI_DIR") {
            continue;
        }
        let Some(close) = t.find('}') else { continue };
        let rel = t[close + 1..].split(':').next().unwrap_or("").trim_matches('/');
        out.push(rel.to_string());
    }
    Some(out)
}

/// The "gateway pki view" row. The gateway runs as uid
/// 65532, the same uid as loki, prometheus, alertmanager, node-exporter
/// and llamacpp, whose keys are handed to 65532 — so no file mode keeps
/// those keys from a gateway that mounts them. It must mount only
/// `GATEWAY_PKI_MOUNTS`, and `public/` must be a faithful, key-free copy
/// of the certificates under `nodes/` and `services/` (the gateway's cert
/// expiry and `pki status` read the copies). A WARN with the fix, like the
/// other PKI rows: the stack runs either way.
pub(crate) fn gateway_pki_view_check(mounts: Option<&[String]>, drift: &crate::pki::PublicViewDrift) -> Check {
    let Some(mounts) = mounts else {
        return warn(
            "gateway pki view",
            "could not read the gateway's volumes from docker-compose.cluster.yml in the running checkout",
            None,
        );
    };
    let wide: Vec<String> = mounts
        .iter()
        .filter(|m| !GATEWAY_PKI_MOUNTS.contains(&m.as_str()))
        .map(|m| if m.is_empty() { "the whole PKI directory".to_string() } else { m.clone() })
        .collect();
    if !wide.is_empty() {
        return warn(
            "gateway pki view",
            format!(
                "the gateway mounts {} from the PKI dir — as uid 65532 it can read every key handed to that uid (loki, prometheus, alertmanager, node-exporter, llamacpp)",
                wide.join(", ")
            ),
            Some("noo upgrade --stack   # a current stack mounts ca.crt, gateway/, sso/ and pki/public/ only".into()),
        );
    }
    if !drift.keys.is_empty() {
        return warn(
            "gateway pki view",
            format!("private key(s) in pki/public/, which the gateway mounts: {}", drift.keys.join(", ")),
            Some("noo security pki fix-modes   # re-syncs public/ and removes them".into()),
        );
    }
    if !drift.is_clean() {
        let mut parts = Vec::new();
        if !drift.missing_roots.is_empty() {
            parts.push(format!("no public/{}", drift.missing_roots.join(", public/")));
        }
        if !drift.missing.is_empty() {
            parts.push(format!("{} certificate(s) not copied ({})", drift.missing.len(), drift.missing.join(", ")));
        }
        if !drift.stale.is_empty() {
            parts.push(format!("{} stale copy(ies) ({})", drift.stale.len(), drift.stale.join(", ")));
        }
        if !drift.extra.is_empty() {
            parts.push(format!("{} stray entr(ies) ({})", drift.extra.len(), drift.extra.join(", ")));
        }
        return warn(
            "gateway pki view",
            format!(
                "pki/public/ is out of step with nodes/ and services/ — the gateway reports certificate expiry from the copies: {}",
                parts.join("; ")
            ),
            Some("noo security pki fix-modes".into()),
        );
    }
    ok(
        "gateway pki view",
        format!(
            "the gateway mounts ca.crt, gateway/, sso/ and the certificate-only pki/public/ ({} certificate(s)); no other service's key",
            drift.total
        ),
    )
}

/// Cloud provider keys the gateway reads (`coordinator/cloud.rs`). GEMINI is
/// accepted by the gateway as an alias of GOOGLE_API_KEY, so the store may
/// hold either name.
const CLOUD_PROVIDER_KEYS: &[&str] = &["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"];

/// The "cloud gate" row. The router refuses claude-/gpt-/gemini- requests
/// unless `CLOUD_PROVIDERS_ENABLED` is on (default off). An install that
/// upgraded with a provider key already stored would otherwise see its chat
/// start failing with no verify row to say why.
///
/// Inputs, each with its own meaning: `keys` = provider keys SET in the
/// secret store (empty = none configured, nothing to gate); `store_ok` =
/// whether the store could be read (a failed read is NOT "no keys");
/// `flag` = the live flag value from the gateway, `None` when it could not
/// be fetched (a failed fetch is NOT "off").
pub(crate) fn cloud_gate_check(keys: &[&str], store_ok: bool, flag: Option<bool>) -> Check {
    const NAME: &str = "cloud gate";
    if !store_ok {
        return warn(NAME, "the secret store could not be read, so whether a cloud provider key is configured is not proven",
            Some("noo security secrets audit".to_string()));
    }
    if keys.is_empty() {
        return ok(NAME, "no cloud provider key stored; nothing can reach a cloud model");
    }
    match flag {
        Some(true) => ok(NAME, format!("{} stored and CLOUD_PROVIDERS_ENABLED is on", keys.join(", "))),
        Some(false) => fail(
            NAME,
            format!("{} stored but CLOUD_PROVIDERS_ENABLED is off: every claude-/gpt-/gemini- chat request is refused", keys.join(", ")),
            "turn on Settings -> Features -> Cloud model routing in the console (POST /api/settings/flags/set {\"key\":\"CLOUD_PROVIDERS_ENABLED\",\"value\":true}), or leave it off to keep cloud models unused",
        ),
        None => warn(
            NAME,
            format!("{} stored, but the live CLOUD_PROVIDERS_ENABLED value could not be read from the gateway", keys.join(", ")),
            Some("check Settings -> Features -> Cloud model routing in the console".to_string()),
        ),
    }
}

/// The "kiosk labels" row: whether the controller is sending entity names to
/// the kiosk display (`kiosk.graph_labels`). INFORMATIONAL — on is a WARN so
/// it is seen, never a FAIL, because it is a deliberate, audited operator
/// decision rather than a broken invariant. `None` (the gateway did not
/// list it) is a WARN saying so, never "off".
pub(crate) fn kiosk_labels_check(state: Option<&crate::commands::kiosk::LabelsState>) -> Check {
    const NAME: &str = "kiosk labels";
    match state {
        Some(s) if s.on => warn(
            NAME,
            format!(
                "entity names are shown on the kiosk display — {}",
                crate::commands::kiosk::labels_line(s)
            ),
            Some("noo kiosk labels off".to_string()),
        ),
        Some(s) => ok(NAME, format!("off — the kiosk display gets ids, types and degrees, no names ({})",
            crate::commands::kiosk::labels_line(s))),
        None => warn(
            NAME,
            "the kiosk.graph_labels setting could not be read from the gateway (unreachable, or a stack from before the switch)",
            Some("noo kiosk labels status".to_string()),
        ),
    }
}

/// The "grafana sso" row. The gateway signs Grafana
/// session tokens with `sso/grafana.key` and Grafana verifies them with
/// `sso/grafana.pub`; either half missing, the key unreadable by the
/// gateway (uid 65532), or a compose file that does not hand Grafana the
/// public half means "Open Grafana" answers 503 or Grafana refuses the
/// token. A WARN with the fix, never a failure: a controller may run no
/// Grafana at all.
pub(crate) fn grafana_sso_check(key_present: bool, pub_present: bool, readable: Option<bool>, mounted: Option<bool>) -> Check {
    if !key_present || !pub_present {
        return warn(
            "grafana sso",
            format!(
                "missing {} — the console's Open Grafana answers 503 until the pair exists",
                match (key_present, pub_present) {
                    (false, false) => "sso/grafana.key and sso/grafana.pub",
                    (false, true) => "sso/grafana.key",
                    _ => "sso/grafana.pub",
                }
            ),
            Some("noo security pki issue-sso-key   # then: noo stack restart --force".into()),
        );
    }
    if readable == Some(false) {
        let key = crate::pki::ClusterCa::new(crate::pki::pki_dir()).grafana_sso_key_path();
        return warn(
            "grafana sso",
            "sso/grafana.key is not readable by the gateway (uid 65532): it needs 0640 with group 65532, or the mint answers 503",
            Some(format!("sudo chgrp 65532 {} && sudo chmod 640 {}", key.display(), key.display())),
        );
    }
    match mounted {
        Some(false) => warn(
            "grafana sso",
            "the running docker-compose.cluster.yml does not mount sso/grafana.pub into Grafana, so Grafana cannot verify the gateway's session tokens",
            Some("noo upgrade --stack   # a current stack mounts it".into()),
        ),
        None => warn(
            "grafana sso",
            "key pair present; could not read docker-compose.cluster.yml to tell whether Grafana mounts sso/grafana.pub",
            None,
        ),
        Some(true) => ok("grafana sso", "key pair present, readable by the gateway; Grafana mounts the public half"),
    }
}

/// The "loki" row (fleet logging phase 0). Can the gateway reach Loki?
/// Read from `GET /api/logs/status` — the same answer `noo logs status`
/// gives. `loki_configured == false` is a FAILURE, not a caveat: that is
/// the gateway with no `NOO_LOKI_URL`, which is how every install answered
/// "Loki not configured" while the container ran (compose handed it
/// `LOKI_URL`; fixed 2026-09-28). No leaf = the listener cannot start.
pub(crate) fn loki_check(status: Option<&Value>, leaf_present: bool) -> Check {
    if !leaf_present {
        return fail(
            "loki",
            "no services/loki/service.crt — Loki's mTLS listener cannot start and nothing can push or query",
            "noo security pki issue-service loki   # then: noo stack restart --force loki",
        );
    }
    let Some(s) = status else {
        return warn("loki", "not read (the gateway did not answer /api/logs/status)", Some("noo logs status".into()));
    };
    if s["loki_configured"].as_bool() != Some(true) {
        return fail(
            "loki",
            "the gateway has no NOO_LOKI_URL — `noo logs status` answers \"not configured\" whether or not the container runs",
            "noo upgrade --stack   # a stack from 2026-09-28 on hands the gateway NOO_LOKI_URL",
        );
    }
    let url = s["loki_url"].as_str().unwrap_or("?");
    if s["loki_ready"].as_bool() != Some(true) {
        // The gateway names the miss since 2026-10-02 (`loki_ready_detail`:
        // Loki's own "not ready" body, a status, or the transport error); an
        // older gateway does not, and the guess stays.
        let why = s["loki_ready_detail"].as_str().map(str::trim).filter(|d| !d.is_empty())
            .map(|d| format!("/ready {d}"))
            .unwrap_or_else(|| "/ready did not answer — the container is down, or its leaf/CA does not match the gateway's".into());
        return fail(
            "loki",
            format!("configured ({url}) but {why}"),
            "noo stack status   # then: docker logs noo-loki",
        );
    }
    ok("loki", format!("ready at {url}; the gateway queries it with its own leaf over mTLS"))
}

/// One top-level compose service's block, as written (from `  name:` to
/// the next two-space key). Comments stripped so a commented-out `ports:`
/// does not count.
fn compose_service_block(compose: &str, name: &str) -> Option<String> {
    let mut out = String::new();
    let mut inside = false;
    for line in compose.lines() {
        let code = line.split('#').next().unwrap_or("");
        let is_service_key = line.starts_with("  ")
            && !line.starts_with("   ")
            && code.trim_end().ends_with(':')
            && !line.trim().starts_with('#');
        if is_service_key {
            if inside {
                break;
            }
            inside = code.trim() == format!("{name}:");
            continue;
        }
        if inside {
            out.push_str(code);
            out.push('\n');
        }
    }
    if inside { Some(out) } else { None }
}

/// The "loki listener" row: the shipped config requires a client
/// certificate from every caller, and compose publishes no port for it —
/// Loki is reachable only on the compose network, by holders of a cluster
/// leaf. Read from the files the stack runs from (`~/.noo` on a standalone
/// controller); `None` when unreadable, said as such.
pub(crate) fn loki_listener_check(config: Option<&str>, compose: Option<&str>) -> Check {
    let (Some(config), Some(compose)) = (config, compose) else {
        return warn(
            "loki listener",
            "could not read monitoring/loki/loki-config-tls.yml or docker-compose.cluster.yml from the running checkout",
            None,
        );
    };
    let requires_client_cert = config
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .any(|l| l == "client_auth_type: RequireAndVerifyClientCert");
    if !requires_client_cert {
        return fail(
            "loki listener",
            "monitoring/loki/loki-config-tls.yml does not set client_auth_type: RequireAndVerifyClientCert — any process on the compose network could push or read every log",
            "restore the shipped config (noo upgrade --stack re-materialises it)",
        );
    }
    let Some(block) = compose_service_block(compose, "loki") else {
        return warn("loki listener", "docker-compose.cluster.yml has no loki service", None);
    };
    if !block.contains("tls-config.yaml") {
        return fail(
            "loki listener",
            "the loki service's command does not select the mTLS config (tls-config.yaml)",
            "restore the shipped compose file (noo upgrade --stack re-materialises it)",
        );
    }
    if block.lines().any(|l| l.trim() == "ports:") {
        return fail(
            "loki listener",
            "the loki service publishes a host port — Loki is compose-network only by design (a node pushes through the gateway, never to Loki)",
            "remove the ports: block from the loki service and recreate it",
        );
    }
    ok("loki listener", "client certificate required from every caller; no published port")
}

/// The tokens of a compose `command:` as written, in either the block-list
/// or the inline-array form: quotes, list dashes and brackets dropped.
fn command_tokens(block: &str) -> Vec<String> {
    block
        .split(|c: char| c.is_whitespace() || c == ',' || c == '[' || c == ']')
        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
        .filter(|t| !t.is_empty() && *t != "-")
        .map(str::to_string)
        .collect()
}

/// Does this service block run uvicorn with a TLS listener that REQUIRES a
/// client certificate (`--ssl-cert-reqs 2` = ssl.CERT_REQUIRED) and names
/// a certificate, a key and the CA to verify callers against?
fn uvicorn_requires_client_cert(block: &str) -> bool {
    let toks = command_tokens(block);
    let after = |flag: &str| toks.iter().position(|t| t == flag).and_then(|i| toks.get(i + 1)).map(String::as_str);
    after("--ssl-cert-reqs") == Some("2")
        && after("--ssl-certfile").is_some()
        && after("--ssl-keyfile").is_some()
        && after("--ssl-ca-certs").is_some()
}

/// What `sandbox_live_probe` saw from inside the gateway container, each
/// as the probe script printed it: `refused: …`, `answered HTTP/1.1 …`,
/// or `unreachable: …` (no TCP connection at all — the sandbox is down).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct SandboxProbe {
    /// TLS with the cluster CA but NO client certificate.
    pub no_cert: String,
    /// TLS presenting the gateway's own leaf (NOO_TLS_CERT/KEY).
    pub leaf: String,
    /// Plain HTTP to the same port.
    pub plain: String,
}

const SANDBOX_REMEDY_RESTART: &str = "noo stack restart --force sandbox";
const SANDBOX_REMEDY_LEAF: &str = "noo security pki issue-service sandbox   # then: noo stack restart --force sandbox";

/// The "sandbox listener" row (mTLS doors phase 1, i77). The sandbox runs
/// model-written code, so its door must refuse a caller with no cluster
/// leaf in the TLS handshake — not at a bearer, not at a route. Two
/// halves: the compose file the stack runs from (uvicorn with
/// `--ssl-cert-reqs 2` on `sandbox` and `sandbox-extra`, no published
/// port), and a live probe from inside the gateway container — the one
/// that really dials it — that a connection with no client certificate
/// and a plaintext one get no HTTP answer while the gateway's own leaf
/// does. `probe` is `None` when it could not run (container down, no
/// python in the gateway image), which the row says rather than passing.
pub(crate) fn sandbox_listener_check(compose: Option<&str>, probe: Option<&SandboxProbe>) -> Check {
    const ROW: &str = "sandbox listener";
    let Some(compose) = compose else {
        return warn(ROW, "could not read docker-compose.cluster.yml from the running checkout", None);
    };
    let Some(block) = compose_service_block(compose, "sandbox") else {
        return warn(ROW, "docker-compose.cluster.yml has no sandbox service", None);
    };
    let reshipped = "restore the shipped compose file (noo upgrade --stack re-materialises it), then: noo stack restart --force sandbox";
    if !uvicorn_requires_client_cert(&block) {
        return fail(
            ROW,
            "the sandbox's uvicorn does not run with --ssl-cert-reqs 2 and its leaf — any process on noo-sandbox could POST code to /exec",
            reshipped,
        );
    }
    if let Some(extra) = compose_service_block(compose, "sandbox-extra") {
        if !(extra.contains("*sandbox-command") || uvicorn_requires_client_cert(&extra)) {
            return fail(ROW, "sandbox-extra does not run the sandbox's mTLS listener (it answers to the same `sandbox` name)", reshipped);
        }
        if extra.lines().any(|l| l.trim() == "ports:") {
            return fail(ROW, "sandbox-extra publishes a host port — the executor is noo-sandbox only", "remove the ports: block from sandbox-extra and recreate it");
        }
    }
    if block.lines().any(|l| l.trim() == "ports:") {
        return fail(
            ROW,
            "the sandbox service publishes a host port — the executor is reachable on noo-sandbox only by design",
            "remove the ports: block from the sandbox service, then: noo stack restart --force sandbox",
        );
    }
    let Some(p) = probe else {
        return warn(
            ROW,
            "the compose listener requires a client certificate; not probed live (gateway or sandbox container not running)",
            Some("noo stack status".into()),
        );
    };
    let answered = |s: &str| s.starts_with("answered");
    if p.no_cert.starts_with("unreachable") || p.leaf.starts_with("unreachable") {
        return fail(ROW, format!("the gateway cannot reach sandbox:9000 ({})", p.leaf), SANDBOX_REMEDY_RESTART);
    }
    if answered(&p.no_cert) {
        return fail(
            ROW,
            format!("a connection WITHOUT a client certificate was answered ({}) — the listener does not require one", p.no_cert),
            SANDBOX_REMEDY_RESTART,
        );
    }
    if answered(&p.plain) {
        return fail(ROW, format!("a PLAINTEXT request was answered ({})", p.plain), SANDBOX_REMEDY_RESTART);
    }
    if !answered(&p.leaf) {
        return fail(
            ROW,
            format!("the gateway's own leaf was refused ({}) — the sandbox's leaf or CA does not match the gateway's", p.leaf),
            SANDBOX_REMEDY_LEAF,
        );
    }
    ok(ROW, "client certificate required from every caller (none and plaintext refused, the gateway's leaf accepted); no published port")
}

/// Run on the gateway's own interpreter (its runtime image is DHI python,
/// no shell): dial `sandbox:9000` three ways and print one JSON line. TCP
/// is opened BEFORE TLS so a down sandbox reads `unreachable`, never as a
/// refusal that would pass the row.
const SANDBOX_PROBE_PY: &str = r#"import json,os,socket,ssl
def dial(tls,cert):
    try:
        raw=socket.create_connection(('sandbox',9000),timeout=5)
    except OSError as e:
        return 'unreachable: %s'%e
    try:
        s=raw
        if tls:
            c=ssl.create_default_context(cafile=os.environ['NOO_TLS_CA'])
            if cert:
                c.load_cert_chain(os.environ['NOO_TLS_CERT'],os.environ['NOO_TLS_KEY'])
            s=c.wrap_socket(raw,server_hostname='sandbox')
        s.sendall(b'GET /health HTTP/1.1\r\nHost: sandbox\r\nConnection: close\r\n\r\n')
        b=s.recv(64)
        return 'answered '+b.split(b'\r\n')[0].decode('ascii','replace') if b.startswith(b'HTTP/') else 'refused: closed without an answer'
    except (ssl.SSLError,OSError,KeyError) as e:
        return 'refused: %s'%(e,)
    finally:
        raw.close()
print(json.dumps({'no_cert':dial(True,False),'leaf':dial(True,True),'plain':dial(False,False)}))
"#;

fn sandbox_live_probe() -> Option<SandboxProbe> {
    let gateway = crate::envfile::container("gateway");
    let sandbox = crate::envfile::container("sandbox");
    if !crate::commands::secrets::container_running(&gateway) || !crate::commands::secrets::container_running(&sandbox) {
        return None;
    }
    let out = std::process::Command::new("docker")
        .args(["exec", &gateway, "python", "-c", SANDBOX_PROBE_PY])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last()?.trim()).ok()
}

/// What `voice_live_probe` saw at each voice door, from inside the gateway
/// container: the same three dials as the sandbox's ([`SandboxProbe`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct VoiceProbe {
    pub whisper: SandboxProbe,
    pub piper: SandboxProbe,
}

/// The voice doors: compose service name → the leaf it must serve.
const VOICE_DOORS: [&str; 2] = ["whisper", "piper"];

/// The "voice listeners" row (mTLS doors phase 2, i77). noo-whisper and
/// noo-piper take audio and text from the gateway, so each door must
/// refuse a caller with no cluster leaf in the TLS handshake. Voice is an
/// overlay add-on: with `addons.voice` off the containers are never
/// composed, and the row says so instead of failing. With it on, the same
/// two halves as the sandbox row: the overlay file the launcher composes
/// (uvicorn with `--ssl-cert-reqs 2` on both, no published port), and a
/// live probe from inside the gateway — no cert and plaintext get no HTTP
/// answer at either door, the gateway's own leaf does.
pub(crate) fn voice_listeners_check(voice_on: bool, overlay: Option<&str>, probe: Option<&VoiceProbe>) -> Check {
    const ROW: &str = "voice listeners";
    if !voice_on {
        return ok(ROW, "voice off — not checked");
    }
    let Some(overlay) = overlay else {
        return warn(ROW, "voice is on but docker-compose.voice.yml could not be read from the running checkout", None);
    };
    let reshipped = "restore the shipped docker-compose.voice.yml (noo upgrade --stack re-materialises it), then: noo stack restart --force whisper piper";
    for door in VOICE_DOORS {
        let Some(block) = compose_service_block(overlay, door) else {
            return fail(ROW, format!("docker-compose.voice.yml has no {door} service"), reshipped);
        };
        if !uvicorn_requires_client_cert(&block) {
            return fail(
                ROW,
                format!("{door}'s uvicorn does not run with --ssl-cert-reqs 2 and its leaf — any container on noo-cluster could call it"),
                reshipped,
            );
        }
        if block.lines().any(|l| l.trim() == "ports:") {
            return fail(
                ROW,
                format!("{door} publishes a host port — the voice doors are reachable on noo-cluster only by design"),
                format!("remove the ports: block from {door} in docker-compose.voice.yml, then: noo stack restart --force {door}"),
            );
        }
    }
    let Some(p) = probe else {
        return warn(
            ROW,
            "both listeners require a client certificate in compose; not probed live (gateway, whisper or piper container not running)",
            Some("noo stack status".into()),
        );
    };
    let answered = |s: &str| s.starts_with("answered");
    for (door, d) in [("whisper", &p.whisper), ("piper", &p.piper)] {
        let restart = format!("noo stack restart --force {door}");
        if d.no_cert.starts_with("unreachable") || d.leaf.starts_with("unreachable") {
            return fail(ROW, format!("the gateway cannot reach {door}:8000 ({})", d.leaf), restart);
        }
        if answered(&d.no_cert) {
            return fail(
                ROW,
                format!("{door}: a connection WITHOUT a client certificate was answered ({}) — the listener does not require one", d.no_cert),
                restart,
            );
        }
        if answered(&d.plain) {
            return fail(ROW, format!("{door}: a PLAINTEXT request was answered ({})", d.plain), restart);
        }
        if !answered(&d.leaf) {
            return fail(
                ROW,
                format!("{door}: the gateway's own leaf was refused ({}) — {door}'s leaf or CA does not match the gateway's", d.leaf),
                format!("noo security pki issue-service {door}   # then: noo stack restart --force {door}"),
            );
        }
    }
    ok(ROW, "whisper and piper require a client certificate from every caller (none and plaintext refused, the gateway's leaf accepted); no published port")
}

/// The sandbox probe's dial, run against both voice doors by their compose
/// service names (each leaf carries its own). Same rules: TCP before TLS so
/// a down door reads `unreachable`, never a passing refusal.
const VOICE_PROBE_PY: &str = r#"import json,os,socket,ssl
def dial(host,tls,cert):
    try:
        raw=socket.create_connection((host,8000),timeout=5)
    except OSError as e:
        return 'unreachable: %s'%e
    try:
        s=raw
        if tls:
            c=ssl.create_default_context(cafile=os.environ['NOO_TLS_CA'])
            if cert:
                c.load_cert_chain(os.environ['NOO_TLS_CERT'],os.environ['NOO_TLS_KEY'])
            s=c.wrap_socket(raw,server_hostname=host)
        s.sendall(b'GET /health HTTP/1.1\r\nHost: '+host.encode()+b'\r\nConnection: close\r\n\r\n')
        b=s.recv(64)
        return 'answered '+b.split(b'\r\n')[0].decode('ascii','replace') if b.startswith(b'HTTP/') else 'refused: closed without an answer'
    except (ssl.SSLError,OSError,KeyError) as e:
        return 'refused: %s'%(e,)
    finally:
        raw.close()
print(json.dumps({h:{'no_cert':dial(h,True,False),'leaf':dial(h,True,True),'plain':dial(h,False,False)} for h in ('whisper','piper')}))
"#;

fn voice_live_probe() -> Option<VoiceProbe> {
    let gateway = crate::envfile::container("gateway");
    let running = |c: &str| crate::commands::secrets::container_running(c);
    if !running(&gateway) || !VOICE_DOORS.iter().all(|d| running(&crate::envfile::container(d))) {
        return None;
    }
    let out = std::process::Command::new("docker")
        .args(["exec", &gateway, "python", "-c", VOICE_PROBE_PY])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last()?.trim()).ok()
}

/// How each compose-run inference backend on the controller is fronted.
/// `Native`: the server itself terminates TLS and must run with
/// `--ssl-cert-reqs 2` (vLLM). `Stunnel(name)`: the server has no TLS
/// listener and every caller dials `stunnel-<name>` (conf
/// `docker/stunnel-<name>.conf`, `verify = 2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendFront {
    Native,
    Stunnel(&'static str),
}

/// Every compose inference backend and its front. A backend added to the
/// compose file without a row here is caught by
/// `tests/test_backend_listeners_require_client_certs.py`, which pins this
/// list against the file; a row here whose service is absent is skipped
/// (profiles differ per install, the file does not).
pub(crate) const COMPOSE_BACKENDS: &[(&str, BackendFront)] = &[
    ("vllm", BackendFront::Native),
    ("vllm-secondary", BackendFront::Native),
    ("llamacpp", BackendFront::Stunnel("llamacpp")),
    ("ollama", BackendFront::Stunnel("ollama")),
    ("tei", BackendFront::Stunnel("tei")),
    ("tei-gpu", BackendFront::Stunnel("tei-gpu")),
    ("reranker", BackendFront::Stunnel("reranker")),
    ("ollama-embed", BackendFront::Stunnel("ollama-embed")),
    ("ollama-embed-cpu", BackendFront::Stunnel("ollama-embed-cpu")),
];

/// Backends that still serve plaintext, each with why it is named rather
/// than fixed. Not checked (they have no door to read); named in the OK
/// text so the row never reads as "everything is behind a cert". Mirrors
/// `PLAINTEXT_EXCEPTIONS` in `tests/test_backend_listeners_require_client_certs.py`.
pub(crate) const PLAINTEXT_BACKEND_EXCEPTIONS: &[(&str, &str)] =
    &[("airllm", "opt-in experimental backend")];

/// The `- "..."` entries under a compose service block's `ports:` key, up to
/// the next key, quotes stripped. Empty when the block publishes nothing.
pub(crate) fn compose_ports(block: &str) -> Vec<String> {
    block
        .lines()
        .skip_while(|l| l.trim() != "ports:")
        .skip(1)
        .take_while(|l| l.trim().starts_with('-') || l.trim().is_empty())
        .filter_map(|l| l.trim().strip_prefix('-'))
        .map(|e| e.trim().trim_matches('"').trim_matches('\'').to_string())
        .collect()
}

/// Whether the compose file declares `sidecar` publishing exactly `bind`.
/// provision.rs reads this to decide the self-node's OLLAMA_URL: https at
/// the door only once the stack it runs from has moved the publish there
/// So a re-provision never points the agent at a TLS door
/// that is not yet published.
pub(crate) fn compose_publishes(compose: &str, sidecar: &str, bind: &str) -> bool {
    compose_service_block(compose, sidecar).map(|b| compose_ports(&b) == [bind.to_string()]).unwrap_or(false)
}

/// The "backend tls" row: every compose inference backend present in the
/// shipped compose file requires a client certificate at the door a caller
/// reaches — vLLM's own listener (`--ssl-cert-reqs 2`), or a stunnel
/// sidecar with `verify = 2` — and no backend publishes a host port. A
/// sidecar may publish its door on loopback only (stunnel-ollama-embed, for
/// the controller's own host agent). Read from the
/// files the stack runs from (`~/.noo` on a standalone controller).
/// `stunnel_conf(name)` yields `docker/stunnel-<name>.conf` when readable.
///
/// No live probe: the backends resolve only on the compose network, and a
/// TLS connect from the host would need the container's address and a
/// leaf to be a fair test; the shipped command line and conf are what
/// decide the listener's behaviour, and they are what this row reads.
pub(crate) fn backend_listener_check(compose: Option<&str>, stunnel_conf: &dyn Fn(&str) -> Option<String>) -> Check {
    let Some(compose) = compose else {
        return warn("backend tls", "could not read docker-compose.cluster.yml from the running checkout", None);
    };
    let mut problems: Vec<String> = Vec::new();
    let mut checked: Vec<&str> = Vec::new();
    let mut loopback_doors: Vec<String> = Vec::new();
    for (svc, front) in COMPOSE_BACKENDS {
        let Some(block) = compose_service_block(compose, svc) else { continue };
        checked.push(svc);
        // The backend itself never publishes: its own port is plaintext.
        if block.lines().any(|l| l.trim() == "ports:") {
            problems.push(format!("{svc} publishes a host port"));
        }
        match front {
            BackendFront::Native => {
                if !block.contains("--ssl-cert-reqs 2") {
                    problems.push(format!("{svc} does not run with --ssl-cert-reqs 2 — its listener would admit a caller with no client certificate"));
                }
            }
            BackendFront::Stunnel(name) => {
                let sidecar = format!("stunnel-{name}");
                match compose_service_block(compose, &sidecar) {
                    None => problems.push(format!("{svc} has no {sidecar} service in front of it")),
                    Some(sb) => {
                        // A sidecar is an mTLS door (its conf's verify = 2
                        // is checked below), so it MAY be published — on
                        // loopback only, for the controller's own host
                        // agent (stunnel-ollama-embed).
                        // Never a LAN/tailnet bind or a bare port (which
                        // docker binds on every interface).
                        if sb.lines().any(|l| l.trim() == "ports:") {
                            let entries = compose_ports(&sb);
                            if entries.is_empty() || entries.iter().any(|e| !e.starts_with("127.0.0.1:")) {
                                problems.push(format!(
                                    "{sidecar} publishes {} — a sidecar may publish its mTLS door on loopback (127.0.0.1) only",
                                    if entries.is_empty() { "a host port".to_string() } else { entries.join(", ") }
                                ));
                            } else {
                                loopback_doors.push(format!("{sidecar} {}", entries.join(", ")));
                            }
                        }
                        if !sb.contains(&format!("docker/stunnel-{name}.conf")) {
                            problems.push(format!("{sidecar} does not mount docker/stunnel-{name}.conf"));
                        }
                    }
                }
                match stunnel_conf(name) {
                    None => problems.push(format!("docker/stunnel-{name}.conf is unreadable")),
                    Some(conf) => {
                        let verify2 = conf
                            .lines()
                            .map(|l| l.split(';').next().unwrap_or("").trim())
                            .any(|l| l.replace(' ', "") == "verify=2");
                        if !verify2 {
                            problems.push(format!("docker/stunnel-{name}.conf does not set verify = 2 — the sidecar would admit a caller with no client certificate"));
                        }
                    }
                }
            }
        }
    }
    if checked.is_empty() {
        return warn("backend tls", "docker-compose.cluster.yml has none of the compose inference backends", None);
    }
    if !problems.is_empty() {
        return fail(
            "backend tls",
            problems.join("; "),
            "restore the shipped compose file and docker/stunnel-*.conf (noo upgrade --stack re-materialises them)",
        );
    }
    let excepted: Vec<String> = PLAINTEXT_BACKEND_EXCEPTIONS.iter().map(|(s, why)| format!("{s} ({why})")).collect();
    let published = if loopback_doors.is_empty() {
        "no published port".to_string()
    } else {
        format!(
            "no backend publishes a port; mTLS doors published on loopback for the host agent: {}",
            loopback_doors.join(", ")
        )
    };
    ok(
        "backend tls",
        format!(
            "client certificate required at every compose backend door ({}); {published}; still plaintext by exception: {}",
            checked.join(", "),
            excepted.join(", ")
        ),
    )
}

/// The "postgres hba" row: the shipped client-auth policy
/// (`docker/postgres/pg_hba.conf`) accepts no TCP client without TLS and
/// a cluster-CA client certificate, and the compose service actually runs
/// with it (`-c hba_file=…`, `ssl=on` unconditional, no `NOO_PG_TLS`
/// switch). Read from the files the stack runs from; `None` when
/// unreadable, said as such.
pub(crate) fn postgres_hba_check(hba: Option<&str>, compose: Option<&str>) -> Check {
    let (Some(hba), Some(compose)) = (hba, compose) else {
        return warn(
            "postgres hba",
            "could not read docker/postgres/pg_hba.conf or docker-compose.cluster.yml from the running checkout",
            None,
        );
    };
    let rules: Vec<Vec<&str>> = hba
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.split_whitespace().collect())
        .collect();
    if rules.is_empty() {
        return fail("postgres hba", "docker/postgres/pg_hba.conf has no rules", "restore the shipped file (noo upgrade --stack re-materialises it)");
    }
    // Any TCP accept that is not `hostssl` is a plaintext door: `host`
    // matches either transport, `hostnossl` only plaintext. `hostgssenc`
    // is not a transport this stack uses.
    if let Some(r) = rules.iter().find(|r| matches!(r[0], "host" | "hostgssenc") || (r[0] == "hostnossl" && r.get(4) != Some(&"reject"))) {
        return fail(
            "postgres hba",
            format!("docker/postgres/pg_hba.conf accepts a TCP client without TLS: `{}`", r.join(" ")),
            "every TCP rule must be `hostssl … clientcert=verify-ca` or `hostnossl … reject`; restore the shipped file",
        );
    }
    if let Some(r) = rules.iter().find(|r| r[0] == "hostssl" && !(r.iter().any(|f| *f == "clientcert=verify-ca" || *f == "clientcert=verify-full") && r.get(4).is_some_and(|m| *m != "trust"))) {
        return fail(
            "postgres hba",
            format!("docker/postgres/pg_hba.conf has a TLS rule that does not require a cluster-CA client certificate AND a password: `{}`", r.join(" ")),
            "hostssl rules carry `scram-sha-256 clientcert=verify-ca`; restore the shipped file",
        );
    }
    if !rules.iter().any(|r| r[0] == "hostssl" && r[1] == "all" && r[2] == "all") {
        return fail("postgres hba", "docker/postgres/pg_hba.conf has no `hostssl all all …` rule — no client could connect", "restore the shipped file");
    }
    if !rules.iter().any(|r| r[0] == "hostnossl" && r[1] == "all" && r[2] == "all" && r.get(4) == Some(&"reject")) {
        return fail("postgres hba", "docker/postgres/pg_hba.conf does not reject plaintext explicitly (`hostnossl all all all reject`)", "restore the shipped file");
    }
    if let Some(r) = rules.iter().find(|r| r[0] == "local" && r.get(3) != Some(&"trust")) {
        // Not a security finding — a stricter socket is fine — but `secrets
        // rotate` runs ALTER ROLE over the socket with no password, so say it.
        return warn("postgres hba", format!("the unix-socket rule is not `trust` (`{}`): `noo security secrets rotate` cannot ALTER the superuser's own password", r.join(" ")), Some("restore the shipped file".into()));
    }
    let Some(block) = compose_service_block(compose, "postgres") else {
        return warn("postgres hba", "docker-compose.cluster.yml has no postgres service", None);
    };
    if !block.contains("hba_file=/etc/noo/pg_hba.conf") {
        return fail("postgres hba", "the postgres service does not run with `-c hba_file=/etc/noo/pg_hba.conf` — the file initdb wrote (loopback trust, password-only TCP) is what applies", "restore the shipped compose file (noo upgrade --stack re-materialises it)");
    }
    if !block.contains("./docker/postgres/pg_hba.conf:/etc/noo/pg_hba.conf") {
        return fail("postgres hba", "the postgres service does not mount docker/postgres/pg_hba.conf at /etc/noo/pg_hba.conf", "restore the shipped compose file");
    }
    if block.contains("NOO_PG_TLS") || !block.contains("-c ssl=on") {
        return fail("postgres hba", "the postgres service's TLS is conditional (a NOO_PG_TLS switch, or no unconditional `-c ssl=on`)", "restore the shipped compose file — TLS is not a switch");
    }
    ok("postgres hba", "TLS + cluster-CA client certificate + password on every TCP connection; plaintext rejected; socket-only trust")
}

/// What one `psql` probe from inside the postgres container proved.
/// `(exit_ok, stderr)` for a connection that presented NO client
/// certificate over TLS, and for one that offered no TLS at all; `None`
/// when the probe could not run (container down, no routable address).
pub(crate) fn postgres_client_cert_check(no_cert: Option<(bool, &str)>, plaintext: Option<(bool, &str)>) -> Check {
    let (Some((nc_ok, nc_err)), Some((pt_ok, pt_err))) = (no_cert, plaintext) else {
        return warn("postgres tls", "not probed (postgres container not running, or no routable address)", Some("noo stack status".into()));
    };
    if nc_ok {
        return fail("postgres tls", "a TCP connection WITHOUT a client certificate was accepted", "docker/postgres/pg_hba.conf must carry clientcert=verify-ca on every hostssl rule; noo stack restart --force after restoring it");
    }
    if nc_err.contains("password") {
        return fail("postgres tls", "a TCP connection without a client certificate reached password authentication — the certificate is not required", "restore docker/postgres/pg_hba.conf (clientcert=verify-ca) and recreate postgres");
    }
    if !nc_err.contains("requires a valid client certificate") {
        return warn("postgres tls", format!("the no-certificate probe failed for a reason that is not the certificate: {}", nc_err.lines().next().unwrap_or("").trim()), Some("docker logs noo-postgres".into()));
    }
    if pt_ok {
        return fail("postgres tls", "a PLAINTEXT connection was accepted", "docker/postgres/pg_hba.conf must end in `hostnossl all all all reject`; recreate postgres");
    }
    if !(pt_err.contains("no encryption") || pt_err.contains("rejects connection")) {
        return warn("postgres tls", format!("the plaintext probe failed for a reason that is not the transport: {}", pt_err.lines().next().unwrap_or("").trim()), Some("docker logs noo-postgres".into()));
    }
    ok("postgres tls", "a client without a cluster-CA certificate is refused before any password; plaintext is rejected")
}

/// Run one `psql` from inside the postgres container to its own routable
/// address. No password is offered (`-w`): the point is that the server
/// refuses BEFORE asking for one.
fn postgres_probe(container: &str, host: &str, conninfo_extra: &str) -> ProbeResult {
    let db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "noomesh".into());
    let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into());
    let out = std::process::Command::new("docker")
        .args(["exec", container, "sh", "-c"])
        .arg(format!("PGCONNECT_TIMEOUT=5 exec psql -w 'host={host} user={user} dbname={db} {conninfo_extra}' -tAc 'SELECT 1'"))
        .output()
        .ok()?;
    Some((out.status.success() && String::from_utf8_lossy(&out.stdout).trim().starts_with('1'), String::from_utf8_lossy(&out.stderr).into_owned()))
}

/// `(exit_ok, stderr)` of one live probe, or `None` when it could not run.
type ProbeResult = Option<(bool, String)>;

fn postgres_live_probes() -> (ProbeResult, ProbeResult) {
    let container = crate::envfile::container("postgres");
    if !crate::commands::secrets::container_running(&container) {
        return (None, None);
    }
    let Some(host) = crate::commands::secrets::container_routable_host(&container) else {
        return (None, None);
    };
    (
        postgres_probe(&container, &host, "sslmode=verify-ca sslrootcert=/tls/ca.crt"),
        postgres_probe(&container, &host, "sslmode=disable"),
    )
}

/// The mount that holds `path`: the longest mount point that prefixes it,
/// with its source device, from a `/proc/mounts` body. `None` when nothing
/// prefixes it (an unreadable or foreign mounts table).
pub(crate) fn mount_of(proc_mounts: &str, path: &str) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for line in proc_mounts.lines() {
        let mut it = line.split_whitespace();
        let (Some(dev), Some(mp)) = (it.next(), it.next()) else { continue };
        let mp = mp.replace("\\040", " ");
        let covers = mp == "/" || path == mp || path.starts_with(&format!("{}/", mp.trim_end_matches('/')));
        if covers && best.as_ref().is_none_or(|(_, b)| mp.len() > b.len()) {
            best = Some((dev.to_string(), mp));
        }
    }
    best
}

/// Is `dev` (or any device it stacks on) a dm-crypt mapping? `lsblk -s`
/// walks from the device UP to the disk, so a filesystem on LUKS lists a
/// `crypt` row; a plain partition lists none. `None` when lsblk is absent
/// or refuses the device (a bind mount, a network filesystem) — the row
/// says "could not determine" rather than either verdict.
fn block_device_encrypted(dev: &str) -> Option<bool> {
    if !dev.starts_with("/dev/") {
        return None;
    }
    let out = std::process::Command::new("lsblk").args(["-sno", "TYPE", dev]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let types: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if types.is_empty() {
        return None;
    }
    Some(types.contains(&"crypt"))
}

/// One data directory whose at-rest protection `cluster verify` reports:
/// the row's name, what sits there in the clear, and where it is.
pub(crate) struct AtRestDir {
    pub(crate) name: &'static str,
    pub(crate) what: &'static str,
    pub(crate) path: String,
}

const LOKI_WHAT: &str = "the logs (Loki has no chunk encryption for the filesystem store)";

/// The table of directories that hold state in the clear, resolved the way
/// the running stack resolves them (`env` is the process environment, which
/// `ensure_repo_env` loaded from `.env`): the `NOO_DATA_ROOT` binds from
/// `docker-compose.cluster.yml`'s `volumes:`; Postgres by `NOO_PG_DATA`,
/// which onboard's `ensure_pg_data_path` redirects to `$HOME/noo/postgres`
/// when the data root is NTFS; the PKI dir as `pki::pki_dir` resolves it;
/// and the directory of the SOPS age key that decrypts `env.sops`
/// (`SOPS_AGE_KEY_FILE`, else `~/.config/sops/age`). Until 2026-09-29 only
/// Loki had a row; the database, the queue, the metrics, the CA and the key
/// that unlocks every other secret sat on the same disks unreported.
pub(crate) fn at_rest_dirs(env: &dyn Fn(&str) -> Option<String>) -> Vec<AtRestDir> {
    let get = |k: &str| env(k).filter(|v| !v.trim().is_empty()).map(|v| v.trim().trim_end_matches('/').to_string());
    let root = get("NOO_DATA_ROOT").unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.into());
    let home = get("HOME").unwrap_or_else(|| "/root".into());
    let pg = get("NOO_PG_DATA").unwrap_or_else(|| format!("{root}/postgres"));
    let pki = get("NOO_PKI_DIR").unwrap_or_else(|| format!("{home}/.config/mesh/pki"));
    let age = get("SOPS_AGE_KEY_FILE")
        .and_then(|f| std::path::Path::new(&f).parent().map(|p| p.to_string_lossy().into_owned()))
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| format!("{home}/.config/sops/age"));
    vec![
        AtRestDir { name: "loki at rest", what: LOKI_WHAT, path: format!("{root}/loki") },
        AtRestDir { name: "postgres at rest", what: "the database files (every account, session, message and memory)", path: pg },
        AtRestDir { name: "redis at rest", what: "the Redis dumps (RDB/AOF: sessions, rate limits, cached results)", path: format!("{root}/redis") },
        AtRestDir { name: "nats at rest", what: "the JetStream streams (queued tasks, agent mail, KV)", path: format!("{root}/nats") },
        AtRestDir { name: "prometheus at rest", what: "the TSDB blocks (node names, rates, security signals)", path: format!("{root}/prometheus") },
        AtRestDir { name: "grafana at rest", what: "Grafana's own database (users, sessions, dashboards)", path: format!("{root}/grafana") },
        AtRestDir { name: "noo-data at rest", what: "the gateway's data volume (uploads, artifacts, state)", path: format!("{root}/noo-data") },
        AtRestDir { name: "pki at rest", what: "the cluster CA and every service private key", path: pki },
        AtRestDir { name: "age key at rest", what: "the SOPS age key, which decrypts env.sops and so every other secret", path: age },
    ]
}

/// One "<name> at rest" row. Nothing here encrypts its own files (Loki's
/// options exist for S3 only, Postgres has no TDE, the rest write plain
/// files), so what protects them at rest is the host's disk encryption — a
/// fact each row reports and never assumes. A WARN, never a failure: it is
/// the operator's control, and the row exists so the gap is visible.
pub(crate) fn at_rest_check(name: &'static str, what: &str, data_dir: &str, exists: bool, mount: Option<(&str, &str)>, encrypted: Option<bool>) -> Check {
    if !exists {
        return warn(name, format!("{data_dir} does not exist on this host — nothing to judge (not created yet, or the path is set elsewhere)"), None);
    }
    let Some((dev, mp)) = mount else {
        return warn(
            name,
            format!("could not determine which mount holds {data_dir} — in the clear there: {what}; disk encryption is the host's to provide"),
            None,
        );
    };
    match encrypted {
        Some(true) => ok(name, format!("{data_dir} is on {dev} ({mp}), a dm-crypt device")),
        Some(false) => warn(
            name,
            format!("{data_dir} is on {dev} ({mp}), not a dm-crypt device — in the clear on that disk: {what}"),
            Some("encrypt the data root's disk (LUKS) or accept it: access to the files is root on the controller, as for Postgres".into()),
        ),
        None => warn(
            name,
            format!("{data_dir} is on {dev} ({mp}); could not determine whether that device is encrypted (lsblk unavailable, or not a block device)"),
            None,
        ),
    }
}

/// The "loki at rest" row as it was before the table (2026-09-28), kept so
/// the test that pins its text keeps reading the same call; production
/// goes through `at_rest_dirs` + `at_rest_check`, of which this is row one.
#[cfg(test)]
pub(crate) fn loki_at_rest_check(data_dir: &str, mount: Option<(&str, &str)>, encrypted: Option<bool>) -> Check {
    at_rest_check("loki at rest", LOKI_WHAT, data_dir, true, mount, encrypted)
}

/// The "monitoring web config" row (shipped tree, no probe). Every service
/// whose volumes mount a `web-config.yml` must also pass
/// `--web.config.file=<that container path>` in its `command:` — the mount
/// alone does nothing. That is how alertmanager served plain HTTP with no
/// client auth on 127.0.0.1:9093 AND the compose network while Prometheus
/// dialled it as `scheme: https` (found 2026-09-29; the file had been
/// mounted, unread, since the day it was written). The tree guard is
/// `tests/test_monitoring_web_configs_are_loaded.py`; this row says it
/// about the compose file the controller actually runs.
pub(crate) fn monitoring_web_config_check(compose: Option<&str>) -> Check {
    let Some(compose) = compose else {
        return warn("monitoring web config", "docker-compose.cluster.yml is unreadable — cannot judge", None);
    };
    let mut loaded: Vec<&str> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for svc in MONITORING_LEAVES {
        let Some(block) = compose_service_block(compose, svc) else { continue };
        for line in block.lines() {
            let code = line.split('#').next().unwrap_or("").trim().trim_start_matches("- ").trim_matches(|c| c == '\'' || c == '"');
            let Some(idx) = code.find("web-config.yml:") else { continue };
            let target = code[idx + "web-config.yml:".len()..].split(':').next().unwrap_or("").trim();
            if target.is_empty() {
                continue;
            }
            if block.contains(&format!("--web.config.file={target}")) {
                loaded.push(svc);
            } else {
                missing.push(format!("{svc} mounts {target} but its command never names it"));
            }
        }
    }
    if !missing.is_empty() {
        return fail(
            "monitoring web config",
            format!("a mounted web-config is never loaded, so that listener is plain HTTP with no client auth: {}", missing.join("; ")),
            "restore the shipped compose file (noo upgrade --stack re-materialises it): every web-config mount has a matching --web.config.file flag",
        );
    }
    if loaded.is_empty() {
        return warn("monitoring web config", "no monitoring service mounts a web-config.yml — nothing to judge", None);
    }
    ok("monitoring web config", format!("{} load the web-config they mount (TLS + RequireAndVerifyClientCert)", loaded.join(", ")))
}

/// `noo_logs_last_seen_unix{node="…"} <value>` lines of the gateway's
/// `/metrics` text → node → unix seconds. Tolerant of label order and of a
/// float rendering; every other line is skipped.
pub(crate) fn parse_logs_last_seen(metrics: &str) -> std::collections::BTreeMap<String, i64> {
    let mut out = std::collections::BTreeMap::new();
    for line in metrics.lines() {
        let Some(rest) = line.strip_prefix("noo_logs_last_seen_unix{") else { continue };
        let Some((labels, value)) = rest.split_once('}') else { continue };
        let node = labels.split(',').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k.trim() == "node").then(|| v.trim().trim_matches('"').to_string())
        });
        let Some(node) = node.filter(|n| !n.is_empty()) else { continue };
        if let Ok(v) = value.trim().parse::<f64>() {
            if v.is_finite() && v > 0.0 {
                out.insert(node, v as i64);
            }
        }
    }
    out
}

/// The "logs last seen" row (fleet logging phase 6): what the GATEWAY says
/// it has accepted from each node, against the registry. Pure over the
/// metrics text and the `(node, online)` list. A node the controller is
/// not hearing from is skipped and named: its `online` row already fails,
/// and "no logs" from a node that is down is not a logging fault.
///
/// A stale node FAILS — the operator believes its logs arrive and they do
/// not — while a node with no series at all WARNS: nothing has ever
/// arrived, which is the roll not reaching it yet, not a stall.
pub(crate) fn logs_last_seen_check(metrics: Option<&str>, nodes: &[(String, bool)], now_unix: i64) -> Check {
    let Some(text) = metrics else {
        return warn("logs last seen", "not read (GET /metrics did not answer with a credential this row can use — it is Operator/Admin only)",
            Some("noo logs status".into()));
    };
    let seen = parse_logs_last_seen(text);
    let online: Vec<&str> = nodes.iter().filter(|(_, on)| *on).map(|(n, _)| n.as_str()).collect();
    let offline: Vec<&str> = nodes.iter().filter(|(_, on)| !*on).map(|(n, _)| n.as_str()).collect();
    if online.is_empty() {
        return warn("logs last seen", format!("no online node to judge ({} offline: {})", offline.len(), offline.join(", ")), None);
    }
    let mut never = Vec::new();
    let mut stale = Vec::new();
    let mut oldest: i64 = 0;
    for n in &online {
        match seen.get(*n) {
            None => never.push(*n),
            Some(t) if now_unix - t > LOG_SHIP_STALL_SECS => stale.push(format!("{n} ({} ago)", age_str(now_unix - t))),
            Some(t) => oldest = oldest.max(now_unix - t),
        }
    }
    let skipped = if offline.is_empty() { String::new() } else { format!("; skipped offline: {}", offline.join(", ")) };
    if !stale.is_empty() {
        let first = stale[0].split(' ').next().unwrap_or("?").to_string();
        return fail("logs last seen",
            format!("no logs accepted from {} for over {}{skipped}", stale.join(", "), age_str(LOG_SHIP_STALL_SECS)),
            format!("noo cluster verify {first}   # its `log shipper` row says why; then noo cluster logs {first} agent"));
    }
    if !never.is_empty() {
        return warn("logs last seen",
            format!("no logs ever received from {}{skipped}", never.join(", ")),
            Some(format!("noo cluster provision {} --wait   # or NOO_LOG_SHIP on the node; the gateway forgets on restart, so a fresh gateway reads this way for a minute", never[0])));
    }
    ok("logs last seen", format!("{} node(s) shipping, oldest accepted {} ago{skipped}", online.len(), age_str(oldest)))
}

/// The gateway-side legacy credential lanes, as
/// `noo_legacy_lane_uses_total{lane=…}` names them. The comparators
/// (`node_token_with_cert`, `addon_exchanged_token`) are shown beside them
/// but never judged: they are the replacement, not the lane.
///
/// `addon_shared_secret_refused` is judged like a lane although the gateway
/// REFUSES it: a count names an add-on image older than the
/// change, or one with no key, whose gateway calls are all failing.
pub(crate) const GATEWAY_LEGACY_LANES: &[&str] =
    &["self_call_shared_secret", "cluster_hmac_non_inference", "node_token_no_cert", "addon_shared_secret_refused", "cluster_hmac_v1"];
pub(crate) const GATEWAY_LANE_COMPARATORS: &[&str] = &["node_token_with_cert", "addon_exchanged_token", "operator_client_cert", "cluster_hmac_v2"];
/// Counted REFUSALS, not admissions: a `noo` CLI older than the
/// break-glass removal signing with the controller secret. Every count is
/// a binary somewhere that needs `noo upgrade --all`.
pub(crate) const GATEWAY_REFUSED_LANE: &str = "cli_shared_secret_refused";
/// A worker-plane caller still signing with the
/// controller secret after the controller door stopped admitting it. Every
/// count is a container without its own service key, whose gateway calls
/// all fail.
pub(crate) const GATEWAY_REFUSED_CONTROLLER_LANE: &str = "controller_shared_secret_refused";
/// A fleet-secret HMAC that did not come from a
/// node (a controller service still holding the node credential).
pub(crate) const GATEWAY_REFUSED_FLEET_OFF_NODE_LANE: &str = "fleet_secret_off_node_refused";
/// The node-side lanes, as each agent reports them in `legacy_lanes`.
pub(crate) const NODE_LEGACY_LANES: &[&str] = &["static_token", "whois_non_controller", "cluster_hmac_v1"];
/// Below this window a zero is not yet retirement evidence
/// ≥7 days, spanning a weekly heartbeat run).
const LEGACY_LANE_EVIDENCE_SECS: i64 = 7 * 86_400;

/// Parsed `/metrics` text for the `legacy lanes` row: the gateway's start
/// (unix seconds) and, per lane, `(who, count)` where `who` is the
/// `caller` or `node` label of each series.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct GatewayLaneCounts {
    pub start_unix: Option<i64>,
    pub lanes: std::collections::BTreeMap<String, Vec<(String, u64)>>,
}

pub(crate) fn parse_legacy_lane_metrics(metrics: &str) -> GatewayLaneCounts {
    let mut out = GatewayLaneCounts::default();
    for line in metrics.lines() {
        if let Some(v) = line.strip_prefix("noo_gateway_start_time_seconds ") {
            out.start_unix = v.trim().parse::<f64>().ok().filter(|v| v.is_finite() && *v > 0.0).map(|v| v as i64);
            continue;
        }
        let Some(rest) = line.strip_prefix("noo_legacy_lane_uses_total{") else { continue };
        let Some((labels, value)) = rest.split_once('}') else { continue };
        let Ok(n) = value.trim().parse::<f64>() else { continue };
        let mut lane = None;
        let mut who = None;
        for kv in labels.split(',') {
            let Some((k, v)) = kv.split_once('=') else { continue };
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "lane" => lane = Some(v),
                "caller" | "node" if who.is_none() => who = Some(v),
                _ => {}
            }
        }
        let Some(lane) = lane else { continue };
        let who = who.unwrap_or_else(|| "-".into());
        let entry = out.lanes.entry(lane).or_default();
        match entry.iter_mut().find(|(w, _)| *w == who) {
            Some((_, c)) => *c += n as u64,
            None => entry.push((who, n as u64)),
        }
    }
    out
}

/// `12 (trellion 10, worker 2)` — a lane's total and who used it, biggest first.
fn lane_breakdown(series: &[(String, u64)]) -> (u64, String) {
    let total: u64 = series.iter().map(|(_, c)| c).sum();
    let mut by: Vec<&(String, u64)> = series.iter().filter(|(_, c)| *c > 0).collect();
    by.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let who: Vec<String> = by.iter().take(4).map(|(w, c)| format!("{w} {c}")).collect();
    let more = if by.len() > 4 { format!(", +{} more", by.len() - 4) } else { String::new() };
    (total, if who.is_empty() { String::new() } else { format!(" ({}{more})", who.join(", ")) })
}

/// The `legacy lanes` row: how often each legacy credential
/// lane was used since the gateway (and each node agent) started, WITH the
/// window — "0 uses in 15 minutes" is not evidence. Pure over the metrics
/// text and the node records.
///
/// OK when every lane reads 0 (the window is always printed, and a window
/// under seven days says it is not yet evidence); WARN when any lane was
/// used, naming the lane; WARN when the counts cannot be
/// read at all, or an online node does not report its own lanes — a zero
/// that was never measured must not read as a zero.
pub(crate) fn legacy_lanes_check(metrics: Option<&str>, fleet: &[Value], now_unix: i64) -> Check {
    const NAME: &str = "legacy lanes";
    let Some(text) = metrics else {
        return warn(NAME, "not read (GET /metrics did not answer with a credential this row can use — it is Operator/Admin only)", None);
    };
    let g = parse_legacy_lane_metrics(text);
    let Some(start) = g.start_unix else {
        return warn(NAME,
            "the gateway does not publish noo_gateway_start_time_seconds, so its lane counters (if any) have no window — it predates that metric",
            Some("noo upgrade --stack".into()));
    };
    let window = now_unix - start;
    let mut used = Vec::new();
    let mut parts = Vec::new();
    for lane in GATEWAY_LEGACY_LANES {
        let (n, who) = lane_breakdown(g.lanes.get(*lane).map(Vec::as_slice).unwrap_or(&[]));
        if n > 0 {
            used.push(*lane);
        }
        parts.push(format!("{lane} {n}{who}"));
    }
    let comparators: Vec<String> = GATEWAY_LANE_COMPARATORS
        .iter()
        .map(|l| format!("{l} {}", lane_breakdown(g.lanes.get(*l).map(Vec::as_slice).unwrap_or(&[])).0))
        .collect();

    // Node side: sum each lane across the nodes that report, name the ones
    // that used it, and the online ones that do not report at all.
    let mut node_totals: Vec<(String, u64, Vec<String>)> =
        NODE_LEGACY_LANES.iter().map(|l| (l.to_string(), 0, Vec::new())).collect();
    let mut unreported = Vec::new();
    let mut shortest_node_window: Option<i64> = None;
    for n in fleet {
        let id = n["id"].as_str().unwrap_or("?");
        let Some(ll) = n["legacy_lanes"].as_object() else {
            let online = n["status"] == "online"
                && n["last_heartbeat"].as_str().and_then(parse_rfc3339_unix).is_some_and(|t| now_unix - t <= HEARTBEAT_MAX_AGE_SECS);
            if online {
                unreported.push(id.to_string());
            }
            continue;
        };
        if let Some(since) = ll.get("since_unix").and_then(Value::as_i64) {
            let w = now_unix - since;
            shortest_node_window = Some(shortest_node_window.map_or(w, |s: i64| s.min(w)));
        }
        for (lane, total, who) in node_totals.iter_mut() {
            let c = ll.get(lane.as_str()).and_then(Value::as_u64).unwrap_or(0);
            if c > 0 {
                *total += c;
                who.push(format!("{id} {c}"));
            }
        }
    }
    for (lane, total, who) in &node_totals {
        if *total > 0 {
            used.push(NODE_LEGACY_LANES.iter().find(|l| **l == lane).copied().unwrap_or("node lane"));
        }
        let who = if who.is_empty() { String::new() } else { format!(" ({})", who.join(", ")) };
        parts.push(format!("{lane} {total}{who}"));
    }

    let node_window = match shortest_node_window {
        Some(w) => format!("; nodes: shortest agent uptime {}", age_str(w)),
        None => "; nodes: none report yet".into(),
    };
    let young = window.min(shortest_node_window.unwrap_or(window)) < LEGACY_LANE_EVIDENCE_SECS;
    let caveat = if young { " — under 7 days, not yet retirement evidence" } else { "" };
    let unrep = if unreported.is_empty() { String::new() } else { format!("; not reporting: {}", unreported.join(", ")) };
    let detail = format!(
        "uses since gateway start {} ago{node_window}{caveat}: {} [comparators: {}]{unrep}",
        age_str(window), parts.join(", "), comparators.join(", ")
    );
    let (refused, refused_who) = lane_breakdown(g.lanes.get(GATEWAY_REFUSED_LANE).map(Vec::as_slice).unwrap_or(&[]));
    let (c_refused, c_who) = lane_breakdown(g.lanes.get(GATEWAY_REFUSED_CONTROLLER_LANE).map(Vec::as_slice).unwrap_or(&[]));
    let (f_refused, f_who) = lane_breakdown(g.lanes.get(GATEWAY_REFUSED_FLEET_OFF_NODE_LANE).map(Vec::as_slice).unwrap_or(&[]));
    let detail = format!("{detail}; {GATEWAY_REFUSED_LANE} {refused}{refused_who}; {GATEWAY_REFUSED_CONTROLLER_LANE} {c_refused}{c_who}; {GATEWAY_REFUSED_FLEET_OFF_NODE_LANE} {f_refused}{f_who}");
    if f_refused > 0 {
        return warn(NAME,
            format!("a non-node caller signed with the fleet secret and was REFUSED {f_refused} time(s){f_who} — {detail}"),
            Some("noo security service-key provision <consumer>   # a controller service presents its own key, never the node credential".into()));
    }
    if c_refused > 0 {
        return warn(NAME,
            format!("a caller signed with the controller secret and was REFUSED {c_refused} time(s){c_who} — {detail}"),
            Some("noo security service-key provision <consumer>   # the caller named above has no key of its own".into()));
    }
    if refused > 0 {
        return warn(NAME,
            format!("an old `noo` CLI signed with the controller secret and was REFUSED {refused} time(s){refused_who} — {detail}"),
            Some("noo upgrade --all   # on the box running the old CLI; the gateway refuses the CLI's shared-secret HMAC".into()));
    }
    if !used.is_empty() {
        return warn(NAME, format!("in use: {} — {detail}", used.join(", ")),
            Some("the counts name the caller; retire a lane only after 0 over ≥7 days on every node".into()));
    }
    if let Some(first) = unreported.first() {
        return warn(NAME, format!("0 on what reports, but not every online node reports its lanes — {detail}"),
            Some(format!("noo cluster provision {first} --wait   # an agent with the legacy_lanes report")));
    }
    ok(NAME, format!("0 uses — {detail}"))
}

/// The apply lanes a controller may no longer use. The
/// node refuses them; this names where a refusal (or an applier old enough
/// to still have used one) shows in a node's last apply report.
pub(crate) const RETIRED_APPLY_LANES: &str =
    "CA-signed apply lane, CA-only rollover of an adopted signing key";

/// What one node's last apply report says about the retired apply lanes:
/// `Some(reason)` for a refusal by a current applier or a use by an applier
/// that predates the retirement, `None` otherwise. `rc`/`msg` are the
/// `apply_rc`/`apply_msg` of `/api/cluster/provision-bundle/{node}/status`.
pub(crate) fn retired_apply_lane_hit(rc: Option<i64>, msg: &str) -> Option<&'static str> {
    if rc == Some(77) && msg.contains("CA-signed apply lane is retired") {
        return Some("refused a CA-signed bundle (lane retired)");
    }
    if rc == Some(77) && msg.contains("did not countersign") {
        return Some("refused a CA-only rollover (no countersignature)");
    }
    if rc == Some(0) && msg.contains("verified-by: ca-legacy") {
        return Some("applied on the retired CA lane (applier predates the retirement)");
    }
    None
}

/// Fold every node's last apply report into the `legacy lanes` row: OK
/// stays OK only when no node refused (or used) a retired apply lane. Fail
/// loud: a refusal is a node that kept its previous state, so it WARNs with
/// the node named and the command that re-stages it.
#[cfg(test)]
pub(crate) fn with_retired_apply_lanes(c: Check, reports: &[(String, Option<i64>, String)]) -> Check {
    with_retired_apply_lanes_and_adoption(c, reports, &[])
}

/// …and FAIL when any node has not adopted the fleet signing key
/// (`unadopted`, from this controller's markers). Since an earlier release the CA
/// can still deliver a key to such a node, and only a key: that is the one
/// power left to the CA key, so a fleet with a node in that state is not
/// closed.
pub(crate) fn with_retired_apply_lanes_and_adoption(
    c: Check,
    reports: &[(String, Option<i64>, String)],
    unadopted: &[String],
) -> Check {
    let mut c = with_retired_apply_lanes_inner(c, reports);
    if !unadopted.is_empty() {
        c.verdict = Verdict::Fail;
        c.detail = format!(
            "{}; NOT adopted the fleet signing key: {} — the CA key can still install a signing key there",
            c.detail, unadopted.join(", "));
        c.remedy = Some(format!("noo cluster provision {} --wait   # delivers the key alone first", unadopted[0]));
    }
    c
}

/// The anchors a Mac reports in its apply report (`anchors: ca sha256:<DER>
/// signing sha256:<SPKI PEM>`), compared with
/// this controller's CA and fleet signing key. A Mac judging bundles against
/// anything else WARNs, naming it; a match is listed.
pub(crate) fn with_node_anchors(mut c: Check, reports: &[(String, Option<i64>, String)], expected: Option<(&str, &str)>) -> Check {
    let field = |msg: &str, k: &str| -> Option<String> {
        let at = msg.find(k)? + k.len();
        msg[at..].split_whitespace().next().map(str::to_string)
    };
    let mut ok_nodes = Vec::new();
    let mut off = Vec::new();
    for (node, _, msg) in reports {
        let (Some(ca), Some(sp)) = (field(msg, "anchors: ca sha256:"), field(msg, "signing sha256:")) else { continue };
        match expected {
            Some((eca, esp)) if ca.eq_ignore_ascii_case(eca) && sp.eq_ignore_ascii_case(esp) => ok_nodes.push(node.clone()),
            Some(_) => off.push(format!("{node} (ca {}…, signing {}…)", &ca[..ca.len().min(12)], &sp[..sp.len().min(12)])),
            None => ok_nodes.push(format!("{node} (ca {}…)", &ca[..ca.len().min(12)])),
        }
    }
    if !ok_nodes.is_empty() {
        c.detail = format!("{}; node trust anchors match this controller: {}", c.detail, ok_nodes.join(", "));
    }
    if !off.is_empty() {
        c.detail = format!("{}; node trust anchors DIFFER from this controller's: {}", c.detail, off.join(", "));
        if c.verdict == Verdict::Ok {
            c.verdict = Verdict::Warn;
        }
    }
    c
}

/// A Mac whose last apply report says root REFUSED to install its CLI or
/// helper (`… root-refused: noo-cli,noo-hostd`, node_fetch.rs
/// `apply_report_msg`): the directory was not root's alone, typically a
/// Homebrew-owned /usr/local/bin. The rest of that apply landed with rc 0, so
/// without this the node reads as current while running the old binaries.
pub(crate) fn with_node_root_refusals(mut c: Check, reports: &[(String, Option<i64>, String)]) -> Check {
    let tag = crate::commands::node_fetch::ROOT_REFUSED_TAG;
    let hits: Vec<String> = reports
        .iter()
        .filter_map(|(node, _, msg)| {
            let at = msg.find(tag)? + tag.len();
            let what = msg[at..].split_whitespace().next().unwrap_or("").replace(',', ", ");
            Some(format!("{node} ({what})"))
        })
        .collect();
    if hits.is_empty() {
        return c;
    }
    c.detail = format!(
        "{}; root REFUSED to install binaries into a directory that is not root's alone: {}",
        c.detail,
        hits.join("; ")
    );
    if c.verdict == Verdict::Ok {
        c.verdict = Verdict::Warn;
    }
    if c.remedy.is_none() {
        c.remedy = Some("on that Mac: sudo chown root:wheel /usr/local/bin && sudo chmod 755 /usr/local/bin, then re-provision it".into());
    }
    c
}

fn with_retired_apply_lanes_inner(mut c: Check, reports: &[(String, Option<i64>, String)]) -> Check {
    let hits: Vec<String> = reports
        .iter()
        .filter_map(|(node, rc, msg)| retired_apply_lane_hit(*rc, msg).map(|why| format!("{node}: {why}")))
        .collect();
    if hits.is_empty() {
        c.detail = format!("{}; retired apply lanes ({RETIRED_APPLY_LANES}): no node reports using or being refused one", c.detail);
        return c;
    }
    c.detail = format!("{}; retired apply lanes ({RETIRED_APPLY_LANES}): {}", c.detail, hits.join("; "));
    if c.verdict == Verdict::Ok {
        c.verdict = Verdict::Warn;
    }
    if c.remedy.is_none() {
        let first = reports
            .iter()
            .find(|(_, rc, msg)| retired_apply_lane_hit(*rc, msg).is_some())
            .map(|(n, _, _)| n.as_str())
            .unwrap_or("<node>");
        c.remedy = Some(format!("noo cluster provision {first} --wait   # a CA-signed bundle now carries signing-pub, so the node adopts"));
    }
    c
}

/// The `companions` row: a sensor companion (`<node>-sensors`, the compose
/// `sensors` profile) that bind-mounts the host agent binary is restarted by
/// the applier after the rail installs a new one (#899 retired hostd's
/// swap-time restart). It reads the same build as its host or it is stale.
/// `None` when the fleet has no companion beside a host agent.
pub(crate) fn companions_check(fleet: &[Value]) -> Option<Check> {
    const NAME: &str = "companions";
    let version = |id: &str| -> Option<String> {
        fleet.iter().find(|n| n["id"].as_str() == Some(id))
            .and_then(|n| n["app_version"].as_str()).map(str::to_string)
    };
    let mut ok_list = Vec::new();
    let mut stale = Vec::new();
    for n in fleet {
        let Some(id) = n["id"].as_str() else { continue };
        let Some(host) = id.strip_suffix("-sensors") else { continue };
        let Some(hv) = version(host) else { continue };
        let cv = n["app_version"].as_str().unwrap_or("-").to_string();
        if cv == hv {
            ok_list.push(format!("{id} on {hv}"));
        } else {
            stale.push((host.to_string(), format!("{id} runs {cv}, {host} runs {hv}")));
        }
    }
    if ok_list.is_empty() && stale.is_empty() {
        return None;
    }
    if let Some((host, _)) = stale.first() {
        let what: Vec<&str> = stale.iter().map(|(_, w)| w.as_str()).collect();
        return Some(warn(NAME,
            format!("stale: {} — a companion that bind-mounts the host agent is restarted by the applier when the rail installs a new agent binary", what.join("; ")),
            Some(format!("noo cluster provision {host} --wait   # reinstalls the agent and restarts the companion; one without the bind-mount follows the stack image (noo upgrade --stack)"))));
    }
    Some(ok(NAME, format!("running the host agent's build: {}", ok_list.join(", "))))
}

#[cfg(test)]
mod companions_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_companion_on_the_host_build_is_ok_and_a_stale_one_warns() {
        let same = [json!({"id": "host9", "app_version": "stack-v0.2.103+a"}),
                    json!({"id": "host9-sensors", "app_version": "stack-v0.2.103+a"})];
        let c = companions_check(&same).expect("a row");
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        let stale = [json!({"id": "host9", "app_version": "stack-v0.2.103+a"}),
                     json!({"id": "host9-sensors", "app_version": "stack-v0.2.101+b"})];
        let c = companions_check(&stale).expect("a row");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("host9-sensors runs stack-v0.2.101+b"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("noo cluster provision host9 --wait"));
        assert!(companions_check(&[json!({"id": "host3", "app_version": "x"})]).is_none());
    }
}

/// The route the "logs access" row probes: the raw LogQL door, the one a
/// User-tier login could read until 2026-09-28. Its directory is the prefix
/// under which every log READ lives on the gateway and which
/// `auth::scope_allows` refuses below Operator — pinned against
/// `gateway-rust/src/auth.rs::LOGS_READ_PREFIX` by a test in this file.
pub(crate) const LOGS_QUERY_ROUTE: &str = "/api/logs/query";

/// `/api/logs/query` → `/api/logs/`.
pub(crate) fn gateway_logs_read_prefix() -> &'static str {
    &LOGS_QUERY_ROUTE[..=LOGS_QUERY_ROUTE.rfind('/').unwrap_or(0)]
}

/// The "logs access" row (fleet logging phase 6). What it PROVES is
/// narrow, and the detail says so: an anonymous GET under the prefix is
/// refused. What it does not prove is the User-tier refusal — that would
/// need a User credential, and this verb runs as the operator; the
/// controller holds no User token (a kiosk's lives on the kiosk seat, a
/// `noo auth` session is the operator's own), and minting one to probe
/// with is a side effect a verify verb must not have. The User-tier
/// refusal is a source pin in the gateway's own tests
/// (`auth.rs log_reads_are_operator_and_admin_only`) and a runbook step for
/// a live probe (cluster-health.md, "Fleet logs not arriving").
pub(crate) fn logs_access_check(anonymous: Option<u16>) -> Check {
    let prefix = gateway_logs_read_prefix();
    match anonymous {
        Some(401) | Some(403) => ok("logs access",
            format!("anonymous GET {prefix}* refused; the User-tier refusal is pinned in the gateway's tests, not probed here (runbook: log in as a User, `noo logs status` must answer 403)")),
        Some(s) if (200..300).contains(&s) => fail("logs access",
            format!("anonymous GET {LOGS_QUERY_ROUTE} answered {s} — the log doors are open to anyone who can reach the port"),
            "noo upgrade --stack   # a gateway with auth::LOGS_READ_PREFIX; then re-run"),
        Some(s) => warn("logs access", format!("anonymous GET {LOGS_QUERY_ROUTE} answered {s}, neither a refusal nor a body — cannot judge"), None),
        None => warn("logs access", "not probed (the gateway did not answer)", Some("noo health".into())),
    }
}

/// Is mTLS enforced, per the controller's `.env`? None when `.env` is
/// unreadable. Enforcement is the DEFAULT: an unset, empty or unrecognised
/// value is on (the gateway also needs a CA, which a controller always has);
/// only an explicit `false/0/no/off` is off.
fn controller_mtls_on() -> Option<bool> {
    let text = std::fs::read_to_string(crate::envfile::repo_root().join(".env")).ok()?;
    Some(mtls_on_in_dotenv(&text))
}

fn mtls_on_in_dotenv(text: &str) -> bool {
    let v = text
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("NOO_MTLS_GATEWAY="))
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_ascii_lowercase())
        .unwrap_or_default();
    !matches!(v.as_str(), "0" | "false" | "no" | "off")
}

/// One key from the controller's `.env` (last assignment wins, as compose
/// reads it); `None` when the file is unreadable OR the key is absent.
fn dotenv_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(crate::envfile::repo_root().join(".env")).ok()?;
    let prefix = format!("{key}=");
    text.lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(prefix.as_str()))
        .map(|v| v.trim().trim_matches('"').to_string())
}

/// The "nats tls" row: the bus runs ONE shipped config, which requires a
/// client certificate from every connection, and nothing on the box can
/// select something weaker — the plaintext `nats.conf` is gone, the
/// `NOO_NATS_CONFIG` selector is gone from compose, and the controller's
/// own `NATS_URL` (if `.env` sets one) is `tls://`. Read from the files the
/// stack runs from; `plain_conf_present` is whether the retired plaintext
/// config is back on disk.
pub(crate) fn nats_tls_check(tls_conf: Option<&str>, compose: Option<&str>, plain_conf_present: bool, env_nats_url: Option<&str>) -> Check {
    if plain_conf_present {
        return fail(
            "nats tls",
            "monitoring/nats/nats.conf exists — the retired PLAINTEXT bus config is back on disk",
            "noo upgrade --stack   # retires files this release no longer ships (or by hand: rm monitoring/nats/nats.conf)",
        );
    }
    let (Some(tls_conf), Some(compose)) = (tls_conf, compose) else {
        return warn(
            "nats tls",
            "could not read monitoring/nats/nats-tls.conf or docker-compose.cluster.yml from the running checkout",
            None,
        );
    };
    let code = |s: &str| s.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()).collect::<Vec<_>>();
    let conf = code(tls_conf);
    if !conf.iter().any(|l| l.starts_with("tls {")) || !conf.iter().any(|l| l == "verify: true") {
        return fail(
            "nats tls",
            "monitoring/nats/nats-tls.conf has no `tls { … verify: true }` block — the bus would accept a connection with no client certificate",
            "restore the shipped config (noo upgrade --stack re-materialises it)",
        );
    }
    let Some(block) = compose_service_block(compose, "nats") else {
        return warn("nats tls", "docker-compose.cluster.yml has no nats service", None);
    };
    if block.contains("NOO_NATS_CONFIG") {
        return fail(
            "nats tls",
            "the nats service's command still reads NOO_NATS_CONFIG — a config selector is a plaintext escape hatch",
            "restore the shipped compose file (noo upgrade --stack re-materialises it)",
        );
    }
    if !block.lines().any(|l| l.contains("command:") && l.contains("nats-tls.conf")) {
        return fail(
            "nats tls",
            "the nats service's command does not select nats-tls.conf",
            "restore the shipped compose file (noo upgrade --stack re-materialises it)",
        );
    }
    if block.lines().any(|l| l.contains("/nats.conf")) {
        return fail(
            "nats tls",
            "the nats service still mounts a nats.conf — the plaintext config must not be reachable from the container",
            "restore the shipped compose file (noo upgrade --stack re-materialises it)",
        );
    }
    if let Some(u) = env_nats_url {
        if !u.starts_with("tls://") {
            return fail(
                "nats tls",
                format!("NATS_URL={u} in .env is not tls:// — the controller's own services would dial the bus in the clear and be refused"),
                "set NATS_URL=tls://nats:4222 in .env and restart the stack",
            );
        }
    }
    ok("nats tls", "mTLS only: nats-tls.conf with verify: true; no plaintext config, selector or client default")
}

/// The retired bus bridge.
pub(crate) const RETIRED_NATS_BRIDGE: &str = "NOO_NATS_LEGACY_SHARED_CREDS";

/// Where the retired bridge is still set, with its value: `.env`, and a
/// posture DB row the gateway lists under `retired` because the catalog no
/// longer has the key. Pure over its inputs.
pub(crate) fn retired_bridge_sites(env_value: Option<&str>, posture: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(v) = env_value.map(str::trim).filter(|v| !v.is_empty()) {
        out.push((".env".to_string(), v.to_string()));
    }
    if let Some(rows) = posture["retired"].as_array() {
        for r in rows.iter().filter(|r| r["key"].as_str() == Some(RETIRED_NATS_BRIDGE)) {
            out.push(("the posture DB".to_string(), r["value"].as_str().unwrap_or("?").to_string()));
        }
    }
    out
}

/// The "nats principals" row: per-principal credentials are
/// the ONLY way onto the bus. FAILs when the users.conf the server reads
/// names any `$VAR` (the retired shared user, rendered by an older CLI —
/// under the current compose NATS refuses that file), or when the retired
/// bridge is still set ON anywhere. A retired bridge left at a closed value
/// changes nothing and is a WARN with the cleanup.
///
/// `declared_addons` is `nats_users::declared_addon_principals`: an add-on
/// whose overlay declares a principal the file does not render is the
/// one-release fallback (it presents the worker) — a WARN naming the render;
/// one the file renders but no overlay declares is a FAIL: its subjects are
/// off the worker's grant while its container presents the worker, so
/// nothing may serve them.
pub(crate) fn nats_principals_check(users_conf: Option<&str>, bridge_sites: &[(String, String)], declared_addons: &[&str]) -> Check {
    let Some(conf) = users_conf else {
        return warn("nats principals", "could not read monitoring/nats/users.conf from the running checkout", None);
    };
    let refs = crate::commands::nats_users::env_refs_in_conf(conf);
    if !refs.is_empty() {
        return fail(
            "nats principals",
            format!(
                "users.conf names {} — the retired shared bus user, rendered by an older CLI; the compose hands \
                 nats no such variable, so the next nats start refuses the file",
                refs.iter().map(|r| format!("${r}")).collect::<Vec<_>>().join(", ")
            ),
            "noo cluster nats-users render   # re-renders from the store without it, then HUPs noo-nats",
        );
    }
    // Named per site (2026-10-02: the remedy was a raw `psql DELETE`, because
    // no `noo` verb could clear a retired row). A gateway from this release
    // DELETES a retired row at a closed value at boot, audited
    // (`posture::retired_rows_to_clear`), and `posture set` accepts the
    // closing write for a row still held open.
    let in_db = |sites: &[&(String, String)]| sites.iter().any(|(s, _)| s == "the posture DB");
    let in_env = |sites: &[&(String, String)]| sites.iter().any(|(s, _)| s == ".env");
    let cleanup = |sites: &[&(String, String)], open: bool| -> String {
        let mut steps: Vec<String> = Vec::new();
        if in_db(sites) {
            steps.push(if open {
                format!("noo security posture set {RETIRED_NATS_BRIDGE} 0   # then: noo stack restart gateway — boot deletes the closed row")
            } else {
                "noo stack restart gateway   # boot deletes a retired row at its closed value (audited)".to_string()
            });
        }
        if in_env(sites) {
            steps.push(format!("remove the {RETIRED_NATS_BRIDGE} line from .env"));
        }
        steps.join("; then ")
    };
    let where_ = |sites: &[&(String, String)]| {
        sites.iter().map(|(s, v)| format!("{s} (={v})")).collect::<Vec<_>>().join(" and ")
    };
    let on: Vec<&(String, String)> = bridge_sites
        .iter()
        .filter(|(_, v)| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .collect();
    if !on.is_empty() {
        return fail(
            "nats principals",
            format!(
                "{RETIRED_NATS_BRIDGE} is set ON in {} — the bridge is retired: nothing reads it and \
                 the shared user it bridged to no longer exists, so whoever set it expects a door that is gone",
                where_(&on)
            ),
            cleanup(&on, true),
        );
    }
    if !bridge_sites.is_empty() {
        let all: Vec<&(String, String)> = bridge_sites.iter().collect();
        return warn(
            "nats principals",
            format!("{RETIRED_NATS_BRIDGE} is retired but still set in {} — inert, stale", where_(&all)),
            Some(cleanup(&all, false)),
        );
    }
    let rendered = crate::commands::nats_users::addon_users_in_conf(conf);
    let orphaned: Vec<&str> = rendered.iter().copied().filter(|a| !declared_addons.contains(a)).collect();
    if !orphaned.is_empty() {
        return fail(
            "nats principals",
            format!(
                "users.conf renders {} but no overlay on this install declares it (x-noo-addon.nats_principal) — \
                 its subjects are off the worker's grant while its container presents the worker, so nothing may serve them",
                orphaned.join(", ")
            ),
            "noo cluster nats-users render   # renders only the declared add-on principals, then HUPs noo-nats",
        );
    }
    let principals = conf.lines().filter(|l| l.trim().starts_with("user:")).count();
    let nodes = crate::commands::nats_users::node_users_in_conf(conf).len();
    let mut named: Vec<&str> = ["gateway", "worker"].into_iter().filter(|u| conf.contains(&format!("user: \"{u}\""))).collect();
    named.extend(rendered.iter().copied());
    let pending: Vec<&str> = declared_addons.iter().copied().filter(|a| !rendered.contains(a)).collect();
    let detail = format!(
        "{principals} per-principal user(s) ({}{}{nodes} node(s)), each a bcrypt digest; no shared user, no bridge; \
         add-on subjects off the worker's grant: {}",
        named.join(", "),
        if named.is_empty() { "" } else { ", " },
        if rendered.is_empty() { "none".to_string() } else { rendered.join(", ") },
    );
    if !pending.is_empty() {
        return warn(
            "nats principals",
            format!(
                "{detail} — {} present(s) the WORKER principal (the one-release fallback): its overlay declares its own \
                 principal but users.conf does not render it yet",
                pending.join(", ")
            ),
            Some("noo cluster nats-users render   # mints the add-on's password, renders it, HUPs noo-nats; then: noo stack restart --force".into()),
        );
    }
    ok("nats principals", detail)
}

/// Judge the posture, key and doctor outputs. Pure over the JSON so the
/// decisions are pinned; the verb below only collects the inputs.
pub(crate) fn controller_checks(
    posture: &Value,
    keys: &Value,
    required: &[(String, String)],
    secrets: (i32, &Value),
    exposure: &Value,
    strangers: &Value,
    audit_errors: Option<u64>,
    tailnet_missing: Option<Vec<String>>,
    entitlement: Option<Result<(), (String, String)>>,
) -> Vec<Check> {
    let mut out = Vec::new();
    let empty = Vec::new();

    // `posture list --json` answers `{"count", "posture": [{key, running,
    // db_value, pending_restart, …}]}`. The first cut of this read `gates`
    // and `desired` — names from the TABLE, not the JSON — and so reported
    // "no gates read" on the first live run while nine gates were fine.
    let gates = posture["posture"].as_array().unwrap_or(&empty);
    if gates.is_empty() {
        out.push(fail("posture", "no gates read", "noo security posture list"));
    } else {
        let drift: Vec<String> = gates.iter().filter(|g| {
            // db_value null = no DB row, the env/default decides: nothing to be off from.
            match (g["running"].as_str(), g["db_value"].as_str()) {
                (Some(r), Some(d)) => r != d,
                (None, Some(_)) => true,
                _ => false,
            }
        }).map(|g| g["key"].as_str().unwrap_or("?").to_string()).collect();
        let pending = gates.iter().filter(|g| g["pending_restart"].as_bool().unwrap_or(false)).count();
        if !drift.is_empty() || pending > 0 {
            out.push(fail("posture", format!("{} gate(s) not at desired, {pending} pending restart: {}", drift.len(), drift.join(", ")),
                "noo stack restart --force   # then: noo security posture list"));
        } else {
            out.push(ok("posture", format!("{} gates at desired", gates.len())));
        }
    }

    out.extend(node_agent_privilege_check(posture));

    let active: Vec<&str> = keys["keys"].as_array().unwrap_or(&empty).iter()
        .filter(|k| k["active"].as_bool().unwrap_or(false))
        .filter_map(|k| k["consumer"].as_str()).collect();
    let missing: Vec<&(String, String)> = required.iter().filter(|(_, c)| !active.contains(&c.as_str())).collect();
    if missing.is_empty() {
        out.push(ok("service keys", format!("{} consumer(s) hold their own key", required.len())));
    } else {
        let names: Vec<String> = missing.iter().map(|(n, _)| n.clone()).collect();
        out.push(fail("service keys", format!("no active key for {}", names.join(", ")),
            format!("noo security service-key provision {}", names[0])));
    }

    out.push(service_key_grants_check(keys, required));

    match secrets.0 {
        0 => out.push(ok("secrets", secrets.1["summary"].as_str().unwrap_or("every holder agrees").to_string())),
        _ => out.push(fail("secrets", secrets.1["summary"].as_str().unwrap_or("holders disagree").to_string(), "noo doctor secrets")),
    }

    match (exposure["status"].as_str(), exposure["boot_safe"].as_bool()) {
        // A tailnet bind that a reboot can break is worse than an open door:
        // the door is a decision, this is the controller not coming back.
        (_, Some(false)) => out.push(fail("exposure",
            "tailnet-bound ports, and ip_nonlocal_bind is 0 — a reboot where Docker starts before Tailscale leaves the gateway down",
            crate::commands::doctor::nonlocal_bind_fix())),
        (Some("confined"), _) => out.push(ok("exposure", "every published port is tailnet or loopback")),
        (Some("any_interface"), _) => {
            let open: Vec<String> = exposure["published"].as_array().unwrap_or(&empty).iter()
                .filter(|p| p["reach"] == "any-interface")
                .map(|p| format!("{}:{}", p["container"].as_str().unwrap_or("?"), p["host_port"])).collect();
            out.push(warn("exposure", format!("on every interface: {} — a decision, not a default", open.join(", ")),
                Some("NOO_BIND_MODE=tailnet in .env, then noo stack restart --force".into())));
        }
        _ => out.push(warn("exposure", "not read", Some("noo doctor exposure".into()))),
    }

    match strangers["status"].as_str() {
        Some("known") => out.push(ok("callers", "every caller known, none in a refusal storm")),
        Some("storm") => out.push(fail("callers", "a known caller is being refused in a loop", "noo doctor strangers")),
        Some("strangers") => out.push(fail("callers", "a caller the tailnet does not account for", "noo doctor strangers")),
        _ => out.push(warn("callers", "not read", Some("noo doctor strangers".into()))),
    }

    match audit_errors {
        Some(0) => out.push(ok("secrets audit", "no errors")),
        Some(n) => out.push(fail("secrets audit", format!("{n} error(s)"), "noo security secrets audit")),
        None => out.push(warn("secrets audit", "not read", Some("noo security secrets audit".into()))),
    }

    match tailnet_missing {
        Some(m) if m.is_empty() => out.push(ok("tailnet policy",
            "the live policy holds everything noomesh declares (rules of your own beyond it are kept, never judged)")),
        Some(m) => out.push(fail("tailnet policy",
            format!("the live policy lacks {} declared item(s): {}", m.len(), m.join("; ")),
            "noo security tailnet policy --merge   # adds only what is missing; keeps your own rules")),
        None => out.push(warn("tailnet policy", "not read (no tailnet API key?)", Some("noo security tailnet policy".into()))),
    }

    match entitlement {
        Some(Ok(())) => out.push(ok("entitlement", "valid")),
        Some(Err((why, remedy))) => out.push(fail("entitlement", why, remedy)),
        None => out.push(ok("entitlement", "no licensed add-on is on")),
    }
    out
}

/// `erasure archive` — how old the oldest archived erasure is. An erase
/// archives every row it deletes (`noo_user_erasure_staging`) so a mistake can
/// be undone, and the gateway purges that copy 30 days later, daily. An archive
/// older than the window plus one day means the purge is not running: the
/// erased person's data is being kept past the promise made to them. The
/// window comes from the gateway's answer, never from this binary, so the two
/// cannot disagree. `Value::Null` = no answer (unreachable, or an older
/// gateway without the route): a WARN, never a pass.
pub(crate) fn erasure_archive_check(v: &Value) -> Check {
    const NAME: &str = "erasure archive";
    let (Some(window), Some(fail_after)) = (v["retention_days"].as_i64(), v["fail_after_days"].as_i64()) else {
        return warn(
            NAME,
            "not read: the gateway did not answer /api/security/erasure-archive (unreachable, or older than this CLI)",
            None,
        );
    };
    let Some(age_secs) = v["oldest_age_secs"].as_i64() else {
        return ok(NAME, format!("no erased user's copy is held (copies are kept {window} days, then purged)"));
    };
    let days = age_secs / 86_400;
    // Whole days: a copy that turned 30 days old just after yesterday's run is
    // purged by today's, a little over 31 days after it was staged.
    if days > fail_after {
        return fail(
            NAME,
            format!(
                "the oldest archived erasure is {days} days old, past the {window}-day window + 1 day: \
                 the daily purge is not running, so erased users' data is being kept too long"
            ),
            "noo logs search erasure_purge --since 2d",
        );
    }
    ok(
        NAME,
        format!(
            "oldest archived erasure is {days} days old; copies are kept {window} days, then purged daily ({} row(s) held)",
            v["rows"].as_i64().unwrap_or(0)
        ),
    )
}

/// `node-agent privilege` — the container's ACTUAL `HostConfig.Privileged`
/// (added to `posture list --json` by the CLI, since the gateway has no docker
/// access), against the desired posture. "At desired" has to mean the
/// container, not the gateway's own env var. `None` when the posture JSON
/// carries neither field (an older CLI or no such gate): nothing was seen, so
/// no row is better than a green one.
pub(crate) fn node_agent_privilege_check(posture: &Value) -> Option<Check> {
    const NAME: &str = "node-agent privilege";
    const KEY: &str = "NOO_NODE_AGENT_PRIVILEGED";
    let gate = posture["posture"].as_array()?.iter().find(|g| g["key"] == KEY)?;
    let desired = gate["db_value"].as_str();
    let want_off = desired.is_some_and(|d| matches!(d.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"));
    if let Some(why) = gate["actual_error"].as_str() {
        return Some(warn(NAME, format!("not checked: {why}"), Some("noo security posture list".into())));
    }
    let actual = match gate["actual"].as_str() {
        Some("true") => true,
        Some("false") => false,
        _ => return None,
    };
    Some(match (actual, want_off) {
        (true, true) => fail(
            NAME,
            "the node-agent container is PRIVILEGED (docker inspect) but posture says false: the gate is not in effect",
            "noo security posture set NOO_NODE_AGENT_PRIVILEGED false   # mirrors into .env and recreates the node-agent",
        ),
        (true, false) => warn(
            NAME,
            "the node-agent container is privileged (docker inspect); posture does not set it to false",
            Some("noo security posture apply-profile hardened   # or: noo security posture set NOO_NODE_AGENT_PRIVILEGED false".into()),
        ),
        (false, true) => ok(NAME, "unprivileged, as posture says (docker inspect)"),
        (false, false) => ok(NAME, "unprivileged (docker inspect)"),
    })
}

/// `audit key` — is `NOO_AUDIT_HMAC_KEY` in this install's store? Read
/// locally, so it answers even when the gateway cannot (it refuses to boot
/// without the key, which would otherwise surface only as "gateway down").
pub(crate) fn audit_key_check(present: bool, store_unreadable: Option<&str>) -> Check {
    const NAME: &str = "audit key";
    if let Some(why) = store_unreadable {
        return warn(NAME, format!("not checked: the secret store could not be read ({why})"), Some("noo security secrets audit".into()));
    }
    if present {
        return ok(NAME, "NOO_AUDIT_HMAC_KEY is set: audit rows are signed");
    }
    fail(
        NAME,
        "NOO_AUDIT_HMAC_KEY is not set: the gateway refuses to start and no security audit row can be written",
        "noo upgrade --stack   # mints NOO_AUDIT_HMAC_KEY into the encrypted store when absent, then recreates the stack",
    )
}

/// `audit log` — the verdict of `noo security audit verify` (the gateway's
/// `/api/security/audit/verify`). A missing `NOO_AUDIT_HMAC_KEY` fails on its
/// own line, because it is not a verification result: it means every audit
/// row is being refused right now. `Value::Null` = the verb produced no JSON
/// (gateway unreachable, or older than this CLI and without the route).
pub(crate) fn audit_log_check(v: &Value) -> Check {
    const NAME: &str = "audit log";
    if v.is_null() || v.get("verdict").is_none() {
        return warn(
            NAME,
            "no audit verdict: the gateway did not answer /api/security/audit/verify (unreachable, or \
             older than this CLI)",
            Some("noo security audit verify".into()),
        );
    }
    if v["key_present"].as_bool() == Some(false) {
        return fail(
            NAME,
            "NOO_AUDIT_HMAC_KEY is not set: every security audit row is being REFUSED",
            "noo upgrade --stack   # mints NOO_AUDIT_HMAC_KEY when absent, then recreates the stack",
        );
    }
    let n = |k: &str| v[k].as_u64().unwrap_or(0);
    if v["verdict"].as_str() != Some("ok") {
        let first = v["breaks"][0]["reason"]
            .as_str()
            .or_else(|| v["problems"][0].as_str())
            .unwrap_or("see the verb");
        return fail(
            NAME,
            format!(
                "does not verify: {} row(s) fail, {} table-level problem(s) — first: {first}",
                v["breaks"].as_array().map_or(0, |a| a.len()),
                v["problems"].as_array().map_or(0, |a| a.len()),
            ),
            "noo security audit verify",
        );
    }
    let cp = if v["checkpoint"].is_object() {
        format!("checkpoint {}", v["checkpoint"]["timestamp"].as_str().unwrap_or("?"))
    } else {
        "no checkpoint yet".into()
    };
    let verified = format!("{} row(s) verify under the key of their epoch; {cp}", n("ok"));
    // Rows an old-image Python writer signed with the retired
    // key in the minutes after the checkpoint. Not a failure; named.
    let roll: Vec<String> = v["roll_window"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|w| {
                    format!(
                        "{} row(s) written by {} during the roll window, signed with the retired \
                         key (an old-image container still running)",
                        w["rows"].as_u64().unwrap_or(0),
                        w["actor"].as_str().unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    // Rows a v0.2.82 Python writer hashed v1 (time not
    // covered) in the minutes after the hash-v2 marker. Not a failure; named.
    let roll: Vec<String> = roll
        .into_iter()
        .chain(v["v1_roll_window"].as_array().into_iter().flatten().map(|w| {
            format!(
                "{} row(s) written by {} during the roll window, hashed v1 (time not covered) \
                 after the hash-v2 marker (an old-image container still running)",
                w["rows"].as_u64().unwrap_or(0),
                w["actor"].as_str().unwrap_or("?")
            )
        }))
        .collect();
    if !roll.is_empty() {
        return warn(
            NAME,
            format!("{verified}; {}", roll.join("; ")),
            Some("noo security audit verify".into()),
        );
    }
    ok(NAME, verified)
}

/// The `entitlement` row's verdict from `noo security entitlement show
/// --json` (`ec`, `ent`) and whether plaintext `.env` holds a value for the
/// key (`env_copy`). `show` reads the encrypted store only, so "not
/// installed" with a `.env` value is NOT an invalid licence: it is a licence
/// sitting outside the store, which compose may still hand the gateway
/// (host8 2026-10-02: `secrets tidy` had moved it to `.env`; the gateway
/// ran on it, valid to 2027). Say which, so nobody re-installs or hunts a
/// signer for a token that is fine. Names only, never the token.
pub(crate) fn entitlement_verdict(ec: i32, ent: &Value, env_copy: bool) -> Result<(), (String, String)> {
    if ec == 0 && ent["verdict"].as_str().is_some_and(|v| v.starts_with("valid")) {
        return Ok(());
    }
    if ent["installed"].as_bool() == Some(false) {
        return Err(if env_copy {
            (
                "no entitlement in secrets/env.sops — a NOO_ENTITLEMENT value sits in plaintext .env only \
                 (see `secrets at rest`); validity was not judged from there"
                    .into(),
                crate::commands::plaintext_env::REMEDY_ONBOARD.into(),
            )
        } else {
            (
                "no entitlement installed, and a licensed add-on is on".into(),
                "noo security entitlement install <token>".into(),
            )
        });
    }
    let why = ent["verdict"].as_str().map(str::to_string)
        .or_else(|| ent["error"]["message"].as_str().map(str::to_string))
        .or_else(|| ent["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| "not read (`noo security entitlement show` gave no verdict)".into());
    Err((format!("the installed entitlement is not valid: {why}"), "noo security entitlement show".into()))
}

/// What `noo security tailnet policy --merge --json` (no `--yes`: a plan,
/// nothing applied) says the live policy LACKS of the declaration — tags,
/// owners, ACL entries — or `None` when the plan could not be read (no API
/// key). Rules the operator keeps beyond the declaration are not drift: the
/// sanctioned path is the additive merge, never a wholesale `--push`, which
/// would delete them. Until 2026-10-02 the row compared bytes and content
/// both ways, so an operator's own rules failed it forever and its remedy
/// pointed at the push.
pub(crate) fn tailnet_merge_missing(j: &Value) -> Option<Vec<String>> {
    let list = |k: &str| j.get(k).and_then(Value::as_array);
    let (tags, owners, acls) = (list("tags_added")?, list("owners_added")?, list("acls_added")?);
    let mut out: Vec<String> = Vec::new();
    out.extend(tags.iter().filter_map(Value::as_str).map(|t| format!("tag {t}")));
    out.extend(owners.iter().filter_map(|p| {
        let p = p.as_array()?;
        Some(format!("owner {} of {}", p.get(1)?.as_str()?, p.first()?.as_str()?))
    }));
    out.extend(acls.iter().filter_map(Value::as_str).map(|a| format!("grant {a}")));
    Some(out)
}

/// The `add-on pins` row from `noo addons verify --json`: "N verified (key
/// #i)" or the first failing add-on and why.
pub(crate) fn addon_pins_check(ec: i32, v: &Value) -> Check {
    let Some(rows) = v["addons"].as_array() else {
        return warn("add-on pins", "not read (`noo addons verify` gave no verdict)", Some("noo addons verify".into()));
    };
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| r["ok"] != true)
        .map(|r| format!("{}: {}", r["addon"].as_str().unwrap_or("?"), r["problem"].as_str().unwrap_or("not verified")))
        .collect();
    if ec != 0 || !bad.is_empty() {
        let why = if bad.is_empty() { "not verified".to_string() } else { bad.join("; ") };
        return fail("add-on pins", why, "noo addons upgrade");
    }
    let mut keys: Vec<u64> = rows.iter().filter_map(|r| r["key_index"].as_u64()).collect();
    keys.sort_unstable();
    keys.dedup();
    let keys: Vec<String> = keys.iter().map(|k| format!("#{k}")).collect();
    let stack = v["stack"].as_str().unwrap_or("?");
    ok("add-on pins", format!("{} verified for {stack} (key {})", rows.len(), keys.join(", ")))
}

/// An enabled system (evolve, trellion) whose credentials
/// are not in the store. Nothing is broken YET — the running gateway
/// provisioned before the switch flipped — but the next restart is a
/// crash-loop, and the launcher now refuses it. This row catches the state an
/// enable left before a restart makes it an outage.
pub(crate) fn system_credentials_check(missing: Result<Vec<(String, Vec<String>)>, String>) -> Check {
    match missing {
        Ok(m) if m.is_empty() => ok("system credentials", "every enabled system holds its credentials"),
        Ok(m) => fail(
            "system credentials",
            format!(
                "enabled without credentials: {} — the next restart would crash-loop the gateway, and the launcher refuses it",
                m.iter().map(|(n, k)| format!("{n} ({})", k.join(", "))).collect::<Vec<_>>().join("; ")
            ),
            format!("noo systems enable {}", m[0].0),
        ),
        Err(e) => warn("system credentials", format!("not read: {e}"), Some("noo systems status".into())),
    }
}

#[cfg(test)]
mod system_credentials_tests {
    use super::{system_credentials_check, Verdict};

    #[test]
    fn an_enabled_system_without_its_ddl_password_fails_with_the_mint_command() {
        let c = system_credentials_check(Ok(vec![("evolve".into(), vec!["NOO_EVOLVE_DDL_PASSWORD".into()])]));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("evolve (NOO_EVOLVE_DDL_PASSWORD)"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo systems enable evolve"));
    }

    #[test]
    fn complete_credentials_pass_and_an_unreadable_store_only_warns() {
        assert_eq!(system_credentials_check(Ok(vec![])).verdict, Verdict::Ok);
        assert_eq!(system_credentials_check(Err("no age key".into())).verdict, Verdict::Warn);
    }
}

/// `dependencies.redis.state` from an AUTHENTICATED `/health` body
/// (`connected` / `reconnecting` / `unavailable`). `None` when the body is
/// absent or lacks it: the gateway was unreachable, is older than the field,
/// or answered the anonymous body (no credential).
pub(crate) fn gateway_redis_state(health: Option<&Value>) -> Option<&str> {
    health?["dependencies"]["redis"]["state"].as_str()
}

/// The `gateway redis` row. The gateway used to decide Redis ONCE at boot
/// (5 s, no retry): if redis was not accepting connections yet it served
/// without Redis until restarted, and `/api/jobs/*` answered "Redis not
/// connected" on the controller for an hour after the 0.6.4 move
/// (2026-10-15) while `/health` still said healthy. It now redials on its
/// own; a row that stays `reconnecting` means redis is down or the gateway
/// cannot reach it.
pub(crate) fn gateway_redis_check(health: Option<&Value>) -> Check {
    const NAME: &str = "gateway redis";
    match gateway_redis_state(health) {
        Some("connected") => ok(NAME, "connected"),
        Some(state) => fail(
            NAME,
            format!(
                "not connected ({state}) — /api/jobs, rate limiting and the response cache run degraded \
                 (is the redis container up? `noo stack status`)"
            ),
            "noo stack restart gateway",
        ),
        None => warn(
            NAME,
            "not read: no authenticated /health answer with dependencies.redis.state \
             (unreachable, no credential, or a gateway older than this CLI)",
            Some("noo health".into()),
        ),
    }
}

/// When the `restart loops` row names `<prefix>-redis`, a failing `gateway
/// redis` row is the gateway reporting the loop, and `noo stack restart
/// gateway` cannot fix it: the 0.6.5-rc.1 rehearsal's seeded root-owned AOF
/// manifest showed both rows failing with the remedy sending the operator to
/// the one container that was fine. Repoint that remedy at redis.
pub(crate) fn redis_remedy_follows_a_redis_loop(checks: &mut [Check], prefix: &str, data_root: &str) {
    let looping = format!("{prefix}-redis is restart-looping");
    if !checks.iter().any(|c| c.name == restart_loops::NAME && c.verdict == Verdict::Fail && c.detail.contains(&looping)) {
        return;
    }
    let dir = format!("{}/redis", data_root.trim_end_matches('/'));
    for c in checks.iter_mut().filter(|c| c.name == "gateway redis" && c.verdict == Verdict::Fail) {
        c.remedy = Some(format!(
            "noo stack logs redis (redis is restart-looping, see `restart loops`; for 'Permission denied' on its AOF/RDB files (i100): \
             sudo chown -R 65532:65532 {dir}, then noo stack restart redis)"
        ));
    }
}

#[cfg(test)]
mod gateway_redis_tests {
    use super::{gateway_redis_check, gateway_redis_state, redis_remedy_follows_a_redis_loop, restart_loops, Verdict};
    use serde_json::json;

    fn health(state: &str) -> serde_json::Value {
        json!({"status": "healthy", "dependencies": {"redis": {"healthy": state == "connected", "state": state}}})
    }

    #[test]
    fn a_connected_gateway_passes() {
        let c = gateway_redis_check(Some(&health("connected")));
        assert_eq!(c.verdict, Verdict::Ok);
        assert_eq!(c.name, "gateway redis");
        assert_eq!(c.detail, "connected");
    }

    #[test]
    fn a_reconnecting_or_unavailable_gateway_fails_with_the_restart_remedy() {
        for state in ["reconnecting", "unavailable"] {
            let c = gateway_redis_check(Some(&health(state)));
            assert_eq!(c.verdict, Verdict::Fail, "{state}");
            assert!(c.detail.starts_with(&format!("not connected ({state})")), "{}", c.detail);
            assert_eq!(c.remedy.as_deref(), Some("noo stack restart gateway"));
        }
    }

    #[test]
    fn a_redis_restart_loop_repoints_the_gateway_redis_remedy_at_redis() {
        let loop_row = |container: &str| {
            restart_loops::row(
                Ok(vec![restart_loops::Looping {
                    container: container.into(),
                    restarts: 7,
                    last_error: Some("Fatal error: can't open the AOF manifest file appendonly.aof.manifest: Permission denied".into()),
                }]),
                "noo",
            )
        };
        let mut checks = vec![gateway_redis_check(Some(&health("reconnecting"))), loop_row("noo-redis")];
        redis_remedy_follows_a_redis_loop(&mut checks, "noo", "/var/lib/noo/");
        let r = checks[0].remedy.as_deref().unwrap();
        assert!(r.starts_with("noo stack logs redis"), "{r}");
        assert!(r.contains("sudo chown -R 65532:65532 /var/lib/noo/redis"), "{r}");
        assert!(!r.contains("restart gateway"), "{r}");
        // The restart-loops row itself is untouched.
        assert_eq!(checks[1].remedy.as_deref(), Some("noo stack logs redis"));

        // Another container looping: the gateway remedy stands.
        let mut checks = vec![gateway_redis_check(Some(&health("reconnecting"))), loop_row("noo-loki")];
        redis_remedy_follows_a_redis_loop(&mut checks, "noo", "/var/lib/noo");
        assert_eq!(checks[0].remedy.as_deref(), Some("noo stack restart gateway"));

        // No loop: unchanged; a connected gateway row is never given a remedy.
        let mut checks = vec![gateway_redis_check(Some(&health("reconnecting"))), restart_loops::row(Ok(vec![]), "noo")];
        redis_remedy_follows_a_redis_loop(&mut checks, "noo", "/var/lib/noo");
        assert_eq!(checks[0].remedy.as_deref(), Some("noo stack restart gateway"));
        let mut checks = vec![gateway_redis_check(Some(&health("connected"))), loop_row("noo-redis")];
        redis_remedy_follows_a_redis_loop(&mut checks, "noo", "/var/lib/noo");
        assert_eq!(checks[0].remedy, None);
    }

    #[test]
    fn no_state_is_a_warn_never_a_pass() {
        // Unreachable, the anonymous body, and an older gateway's deps map.
        let older = json!({"status": "healthy", "dependencies": {"redis": {"healthy": true, "optional": true}}});
        for body in [None, Some(json!({"status": "healthy"})), Some(older)] {
            assert_eq!(gateway_redis_state(body.as_ref()), None);
            assert_eq!(gateway_redis_check(body.as_ref()).verdict, Verdict::Warn);
        }
    }
}

/// The `(remedy, row name)` pairs a section prints under its table: every
/// FAIL row's, and in the controller section every WARN row's too.
fn remedies_to_print<'a>(title: &str, checks: &'a [Check]) -> Vec<(&'a str, Vec<&'a str>)> {
    // An identical remedy is printed once, with every row it covers (the
    // v0.2.97 roll printed one LUKS remedy nine times, once per `* at rest`).
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for c in checks.iter()
        .filter(|c| c.verdict == Verdict::Fail || (c.verdict == Verdict::Warn && title == "controller"))
    {
        let Some(r) = c.remedy.as_deref() else { continue };
        match out.iter_mut().find(|(x, _)| *x == r) {
            Some((_, names)) => names.push(c.name),
            None => out.push((r, vec![c.name])),
        }
    }
    out
}

fn render(title: &str, checks: &[Check]) -> bool {
    println!("{}", ui::section(title));
    let rows: Vec<Vec<String>> = checks.iter().map(|c| {
        let (glyph, detail) = match c.verdict {
            Verdict::Ok => (Glyph::Ok, ui::muted(&c.detail)),
            Verdict::Warn => (Glyph::Warn, ui::warn(&c.detail)),
            Verdict::Fail => (Glyph::Err, ui::err(&c.detail)),
            Verdict::Starting => (Glyph::Warn, ui::warn(&c.detail)),
        };
        vec![ui::glyph_cell(glyph), c.name.to_string(), detail]
    }).collect();
    print!("{}", ui::table(&[Col::left(""), Col::left("invariant"), Col::left("state")], &rows));
    let failed: Vec<&Check> = checks.iter().filter(|c| c.verdict == Verdict::Fail).collect();
    // FAIL remedies always; WARN remedies too in the controller section (the
    // v0.2.95 roll: `service-key grants` warned with a remedy nobody saw).
    let grouped = remedies_to_print(title, checks);
    let whys: Vec<String> = grouped.iter().map(|(_, names)| names.join(", ")).collect();
    let entries: Vec<(&str, &str)> = grouped.iter().zip(&whys).map(|((r, _), w)| (*r, w.as_str())).collect();
    ui::guide(&entries);
    println!();
    failed.is_empty()
}

/// `noo cluster verify [<node>...] [--controller] [--wait]`
pub fn cluster_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut nodes: Vec<String> = Vec::new();
    let mut controller = false;
    let mut wait = false;
    for a in args {
        match a.as_str() {
            "--controller" => controller = true,
            "--all" => {}
            "--wait" => wait = true,
            s if s.starts_with('-') => return Err(Unhandled),
            s => nodes.push(s.to_string()),
        }
    }
    let want_nodes = !controller || !nodes.is_empty();
    if !controller && nodes.is_empty() {
        controller = true; // no arguments: everything
    }

    let mut all_ok = true;
    let mut any_starting = false;
    let mut json_out = serde_json::Map::new();

    if want_nodes || nodes.is_empty() {
        // Best-effort read: this verb is also run from `onboard`'s last step
        // and from `provision --wait`, and must never exit the process from
        // inside them. An unreachable gateway is a failing invariant here,
        // not a fatal error.
        if wait {
            warmup::wait_for_node_warmup(g, &nodes);
        }
        let Some(body) = get_json_opt(g, "/api/cluster/nodes", true, 10) else {
            if g.json {
                println!("{}", serde_json::json!({ "ok": false, "error": "gateway unreachable" }));
            } else {
                println!("{}", ui::status_line(Glyph::Err, "the gateway did not answer /api/cluster/nodes — nothing can be verified"));
                ui::guide(&[("noo health", "is the controller up"), ("noo stack status", "which container is not")]);
            }
            return Ok(1);
        };
        let empty = Vec::new();
        let records = body["nodes"].as_array().unwrap_or(&empty);
        let selected: Vec<&Value> = records.iter().filter(|n| {
            nodes.is_empty() || nodes.iter().any(|w| n["id"].as_str() == Some(w.as_str()))
        }).collect();
        for w in &nodes {
            if !records.iter().any(|n| n["id"].as_str() == Some(w.as_str())) {
                crate::output::fail(g.json, ExitCode::Generic, "unknown_node", &format!("no node named {w:?}"), Some("noo cluster status"));
            }
        }
        let tag = controller_stack_tag();
        let now = now_unix();
        if !g.json {
            println!("{}", ui::header("cluster verify", Some(&format!("{} node(s) · controller {tag}", selected.len()))));
        }
        let mut node_json = Vec::new();
        for n in selected {
            let id = n["id"].as_str().unwrap_or("?");
            let checks = node_checks(&with_harness_wanted(g, n), &tag, env!("CARGO_PKG_VERSION"), now, signing_adopted_for(id));
            let node_ok = checks.iter().all(|c| c.verdict != Verdict::Fail && c.verdict != Verdict::Starting);
            any_starting |= checks.iter().any(|c| c.verdict == Verdict::Starting);
            all_ok &= node_ok;
            if g.json {
                node_json.push(serde_json::json!({ "node": id, "ok": node_ok, "checks": checks_json(&checks) }));
            } else {
                render(&format!("node {id}"), &checks);
            }
        }
        json_out.insert("nodes".into(), Value::Array(node_json));

        // Kiosk SEATS (i77): their own registry, joined here explicitly — a
        // seat never appears in /api/cluster/nodes, so nothing above judged
        // it. Fleet-wide only (a named-node verify is about those nodes).
        // An older gateway without the registry adds nothing; a registry
        // with no seat says so (the 0.6.6-rc.1 rehearsal read silence as
        // "seats not checked").
        if nodes.is_empty() {
            let listed = crate::commands::kiosk_seat::list_seats(g);
            let seats = listed.clone().unwrap_or_default();
            let mut seat_json = Vec::new();
            if !g.json {
                if let Some((heading, empty_line)) = seats_heading(listed.as_ref().map(Vec::len)) {
                    println!("{}", ui::section(&heading));
                    if let Some(line) = empty_line {
                        println!("{}", ui::note(line));
                    }
                }
            }
            for s in &seats {
                let name = s["seat_name"].as_str().unwrap_or("?");
                let checks = crate::commands::kiosk_seat::seat_checks(s, env!("CARGO_PKG_VERSION"), &tag, now);
                let seat_ok = checks.iter().all(|c| c.verdict != Verdict::Fail && c.verdict != Verdict::Starting);
                all_ok &= seat_ok;
                if g.json {
                    seat_json.push(serde_json::json!({ "seat": name, "ok": seat_ok, "checks": checks_json(&checks) }));
                } else {
                    render(&format!("seat {name}"), &checks);
                }
            }
            json_out.insert("seats".into(), Value::Array(seat_json));
        }
    }

    if controller {
        if wait {
            warmup::wait_for_warmup(g);
        }
        let (_, posture, _) = self_json(g, &["security", "posture", "list"]);
        let (_, keys, _) = self_json(g, &["security", "service-key", "list"]);
        let addon_on = |name: &str| {
            crate::commands::addons::effective(name)
                .unwrap_or_else(|| crate::commands::addons::row(name).map(|r| r.default_on).unwrap_or(false))
        };
        let required = required_service_keys(&addon_on);
        let (sc, secrets, _) = self_json(g, &["doctor", "secrets"]);
        let (_, exposure, _) = self_json(g, &["doctor", "exposure"]);
        let (_, strangers, _) = self_json(g, &["doctor", "strangers"]);
        let (ac, audit, _) = self_json(g, &["security", "secrets", "audit"]);
        let audit_errors = if audit.is_null() { None } else {
            Some(audit["findings"].as_array().map(|f| f.iter().filter(|x| x["severity"] == "error" || x["severity"] == "ERROR").count() as u64)
                .unwrap_or(if ac == 0 { 0 } else { 1 }))
        };
        let (_, tailnet, _) = self_json(g, &["security", "tailnet", "policy", "--merge"]);
        let tailnet_missing = tailnet_merge_missing(&tailnet);
        let licensed_on = ["trellion_intel", "evolve"].iter().any(|a| addon_on(a));
        let entitlement = if !licensed_on { None } else {
            let (ec, ent, _) = self_json(g, &["security", "entitlement", "show"]);
            let env_copy = !crate::onboard::env::read_env_key(
                &crate::envfile::repo_root().join(".env"), crate::entitlement::STORE_KEY).trim().is_empty();
            Some(entitlement_verdict(ec, &ent, env_copy))
        };
        let mut checks = controller_checks(&posture, &keys, &required, (sc, &secrets), &exposure, &strangers, audit_errors, tailnet_missing, entitlement);
        checks.push(system_credentials_check(crate::commands::systems::store_missing_credentials()));
        // i67: the controller's own node (when this box runs one) rides the rail.
        if let Some(me) = crate::commands::provision::self_node_name()
            .filter(|_| std::path::Path::new("/usr/local/bin/noo-node-agent").is_file())
        {
            let (rec, legacy) = crate::commands::provision::read_self_lane(&me);
            let missing = crate::commands::provision::pull_units_missing(&me);
            // The gateway must verify against the cert on this disk.
            let view = if !missing.is_empty() { None } else {
                std::fs::read("/etc/noo/birth.crt").ok()
                    .and_then(|pem| crate::commands::node_fetch::cert_der_sha256(&pem).ok())
                    .and_then(|fp| {
                        let answer = crate::http::get_raw_opt(g, "/api/cluster/self-node", true, 15);
                        crate::commands::provision::judge_gateway_self_view(&me, &fp,
                            answer.as_ref().map(|(st, b)| (*st, b.as_str()))).err()
                    })
            };
            checks.push(self_agent_lane_check(&me, &missing, view.as_ref(), rec.as_deref(), legacy));
        }
        // Licensed add-ons run images pinned by their own signed lock
        // (`noo addons verify`: offline re-verify, local image, what runs).
        // An unreadable noomesh.yaml is a failed row, never "no add-on on".
        match crate::addons::licensed_on(&crate::envfile::repo_root()) {
            Ok(on) if on.is_empty() => {}
            Ok(_) => {
                let (ec, pins, _) = self_json(g, &["addons", "verify"]);
                checks.push(addon_pins_check(ec, &pins));
            }
            Err(e) => checks.push(fail("add-on pins", format!("which add-ons are on is unknown: {e}"), "noo addons list")),
        }
        let missing: Vec<&str> = MONITORING_LEAVES
            .iter()
            .copied()
            .filter(|s| !crate::pki::pki_dir().join("services").join(s).join("service.crt").is_file())
            .collect();
        checks.push(metrics_scrape_check(controller_mtls_on(), &missing));
        // The audit's row counts only errors; a container whose delivered
        // secret files went unchecked is a WARN of its own, so "no errors"
        // is never read as "checked".
        checks.extend(crate::commands::secrets_delivery::unchecked_delivery_check(&audit));
        // The data plane's leaf, no plaintext listener or port, and which
        // nodes refused their cache URL. The fleet is re-read here rather
        // than kept from the node half: `--controller` alone never fetches it.
        let leaf_present = DATA_PLANE_LEAVES
            .iter()
            .all(|s| crate::pki::pki_dir().join("services").join(s).join("service.crt").is_file());
        let fleet: Vec<Value> = get_json_opt(g, "/api/cluster/nodes", true, 10)
            .and_then(|b| b["nodes"].as_array().cloned())
            .unwrap_or_default();
        checks.push(model_cache_check(
            leaf_present,
            model_cache_plain_listener_open(),
            model_cache_plain_port_published(),
            &nodes_refusing_model_cache_url(&fleet),
        ));
        let (id_host, id_ip, id_ts) = crate::onboard::steps::local_cert_identity();
        checks.push(service_cert_names_check(&externally_reachable_leaf_names(
            &crate::pki::pki_dir(), &id_host, &id_ip, &id_ts,
        )));
        let sso = crate::pki::ClusterCa::new(crate::pki::pki_dir());
        checks.push(grafana_sso_check(
            sso.grafana_sso_key_path().is_file(),
            sso.grafana_sso_pub_path().is_file(),
            sso.grafana_sso_key_readable_by_gateway(),
            grafana_mounts_sso_pub(),
        ));
        checks.push(super::grafana_door::door_check(&super::grafana_door::gather(&crate::envfile::repo_root())));
        // Every declared model-class candidate is placed or available
        // An unplaced one is skipped at routing, and a class
        // whose candidates are all unplaced answers nothing.
        checks.push(model_classes_check(get_json_opt(g, "/api/cluster/model-classes", true, 15).as_ref()));
        // The gateway's own Redis connection (authenticated /health: the
        // anonymous body carries no dependency map).
        checks.push(gateway_redis_check(get_json_opt(g, "/health", true, 10).as_ref()));
        {
            let root = crate::envfile::repo_root();
            let store = crate::commands::secrets::SecretStore::load_sops(&root.join("secrets/env.sops"));
            let (store_ok, keys): (bool, Vec<&str>) = match &store {
                Ok(st) => (true, CLOUD_PROVIDER_KEYS.iter().copied()
                    .filter(|k| st.state(k) == crate::commands::secrets::State::Set).collect()),
                Err(_) => (false, Vec::new()),
            };
            // Only ask the gateway when a key makes the answer matter.
            let flag = if keys.is_empty() { None } else {
                get_json_opt(g, "/api/settings/flags", true, 10).and_then(|b| {
                    b["flags"].as_array()?.iter()
                        .find(|f| f["key"] == "CLOUD_PROVIDERS_ENABLED")?["value"].as_bool()
                })
            };
            checks.push(cloud_gate_check(&keys, store_ok, flag));
        }
        checks.push(kiosk_labels_check(
            get_json_opt(g, "/api/settings/flags", true, 10)
                .as_ref()
                .and_then(crate::commands::kiosk::labels_from_flags)
                .as_ref(),
        ));
        let key_issues = sso.audit_key_modes();
        let grant_lines: Vec<String> = sso
            .list_keys()
            .iter()
            .filter_map(|k| sso.key_grant_command(k))
            .collect();
        checks.push(pki_key_modes_check(&key_issues, &grant_lines, sso.list_keys().len()));
        checks.push(docker_userns_check(read_daemon_json()));
        let gw_mounts = std::fs::read_to_string(crate::envfile::repo_root().join("docker-compose.cluster.yml"))
            .ok()
            .and_then(|c| gateway_pki_mounts(&c));
        checks.push(gateway_pki_view_check(gw_mounts.as_deref(), &sso.public_view_drift()));
        // Fleet logging phase 0: the gateway can reach Loki (the row that
        // would have failed for a year), the listener is mTLS-only with no
        // published port, and where the chunks sit at rest.
        let (loki, loki_seen) = warmup::loki_row_seen(g, now_unix());
        checks.push(loki);
        let root = crate::envfile::repo_root();
        let loki_cfg = std::fs::read_to_string(root.join("monitoring/loki/loki-config-tls.yml")).ok();
        let compose = std::fs::read_to_string(root.join("docker-compose.cluster.yml")).ok();
        checks.push(loki_listener_check(loki_cfg.as_deref(), compose.as_deref()));
        // The sandbox executor's door (mTLS doors phase 1): compose runs
        // its uvicorn with a required client certificate, and the gateway
        // container proves it live — no cert and plaintext refused, its own
        // leaf accepted.
        checks.push(sandbox_listener_check(compose.as_deref(), sandbox_live_probe().as_ref()));
        // The voice doors (mTLS doors phase 2): only when the overlay is
        // composed; then the same static + live three-way proof per door.
        let voice_on = addon_on("voice");
        let voice_overlay = if voice_on { std::fs::read_to_string(root.join("docker-compose.voice.yml")).ok() } else { None };
        let voice_probe = if voice_on { voice_live_probe() } else { None };
        checks.push(voice_listeners_check(voice_on, voice_overlay.as_deref(), voice_probe.as_ref()));
        // ... and run as non-root uid 65532, the uid their keys are handed
        // to (i105): the live uid, `docker exec id -u` first.
        checks.push(image_family::voice_images_row(voice_on));
        // ... and load models the controller staged, offline (i105).
        checks.push(image_family::voice_models_row(voice_on));
        // Every compose inference backend requires a client certificate at
        // its door (vLLM --ssl-cert-reqs 2, stunnel verify = 2).
        checks.push(backend_listener_check(compose.as_deref(), &|name| {
            std::fs::read_to_string(root.join("docker").join(format!("stunnel-{name}.conf"))).ok()
        }));
        // The bus: one mTLS config, no plaintext config or selector, and the
        // controller's own NATS_URL (when .env sets one) is tls://.
        let nats_tls_cfg = std::fs::read_to_string(root.join("monitoring/nats/nats-tls.conf")).ok();
        let env_nats_url = dotenv_value("NATS_URL");
        checks.push(nats_tls_check(
            nats_tls_cfg.as_deref(),
            compose.as_deref(),
            root.join("monitoring/nats/nats.conf").is_file(),
            env_nats_url.as_deref(),
        ));
        // Per-principal credentials are the only way onto the bus.
        let users_conf = std::fs::read_to_string(root.join(crate::commands::nats_users::USERS_CONF)).ok();
        checks.push(nats_principals_check(
            users_conf.as_deref(),
            &retired_bridge_sites(dotenv_value(RETIRED_NATS_BRIDGE).as_deref(), &posture),
            &crate::commands::nats_users::declared_addon_principals(&root),
        ));
        // Postgres is TLS-only with a required cluster-CA client certificate
        // (2026-09-28): the shipped policy, and a live refusal of a client
        // that presents none.
        let hba = std::fs::read_to_string(root.join("docker/postgres/pg_hba.conf")).ok();
        checks.push(postgres_hba_check(hba.as_deref(), compose.as_deref()));
        let (no_cert, plaintext) = postgres_live_probes();
        checks.push(postgres_client_cert_check(
            no_cert.as_ref().map(|(ok, e)| (*ok, e.as_str())),
            plaintext.as_ref().map(|(ok, e)| (*ok, e.as_str())),
        ));
        // One "<name> at rest" row per directory that holds state in the
        // clear (`at_rest_dirs`): the process env is what the launcher
        // resolved from `.env`, so the paths are the ones compose bound.
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        for row in at_rest_dirs(&|k| std::env::var(k).ok()) {
            let exists = std::path::Path::new(&row.path).is_dir();
            let mount = if exists { mount_of(&mounts, &row.path) } else { None };
            let encrypted = mount.as_ref().and_then(|(dev, _)| block_device_encrypted(dev));
            checks.push(at_rest_check(row.name, row.what, &row.path, exists, mount.as_ref().map(|(d, m)| (d.as_str(), m.as_str())), encrypted));
        }
        checks.push(monitoring_web_config_check(compose.as_deref()));
        // The runtime images (redis + monitoring) are the family their keys
        // and data are handed to (0.6.1: the upstream family, restart loops).
        checks.push(image_family::image_family_row());
        // A container docker keeps restarting reads "Up" between restarts;
        // judge RestartCount + recency instead (0.6.4 redis AOF, 2026-10-16).
        checks.push(restart_loops::restart_loops_row());
        // A gateway that cannot reach a crash-looping redis is redis's
        // problem: point the `gateway redis` remedy at redis, not a gateway
        // restart (0.6.5-rc.1 rehearsal).
        redis_remedy_follows_a_redis_loop(
            &mut checks,
            &crate::envfile::container_prefix(),
            &std::env::var("NOO_DATA_ROOT").ok().filter(|r| !r.is_empty())
                .unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.into()),
        );
        // Every container that bind-mounts noomesh.yaml still
        // reads the host's file (the gateway checks only its own view).
        checks.extend(config_mount_row());
        checks.push(crate::commands::secrets_delivery::secrets_not_in_env_row());
        // No secret is shared between holders any more — the
        // controller secret reaches the gateway alone, and each bus verifier
        // holds its own key.
        checks.push(crate::commands::secrets_delivery::shared_secrets_row());
        // The audit log signs with its own key and verifies across the
        // checkpoint that retired the NOO_JWT_SECRET derivation.
        checks.push(audit_key_check(
            !std::env::var("NOO_AUDIT_HMAC_KEY").unwrap_or_default().trim().is_empty(),
            match crate::envfile::secret_store_state() {
                crate::envfile::StoreState::Unreadable(e) => Some(e.to_string()),
                _ => None,
            }
            .as_deref(),
        ));
        let (_, audit_verdict, _) = self_json(g, &["security", "audit", "verify"]);
        checks.push(audit_log_check(&audit_verdict));
        // An erase keeps a copy 30 days; a purge that is not running shows as
        // an archive older than the window.
        checks.push(erasure_archive_check(
            &get_json_opt(g, "/api/security/erasure-archive", true, 10).unwrap_or(Value::Null),
        ));
        // .env holds no secret-class value and the store is the backend
        checks.push(crate::commands::plaintext_env::at_rest_row());
        // Fleet logging phase 6: what the gateway has accepted from each
        // online node (its own gauge, read as text — `/metrics` is
        // Operator+ since an earlier release, which is what this verb runs as),
        // and that the read door refuses a caller with no credential.
        let metrics = crate::http::get_raw_opt(g, "/metrics", true, 10)
            .filter(|(status, _)| (200..300).contains(status))
            .map(|(_, text)| text);
        let now = now_unix();
        let roster: Vec<(String, bool)> = fleet
            .iter()
            .filter_map(|n| {
                let id = n["id"].as_str()?.to_string();
                let heard = n["last_heartbeat"].as_str().and_then(parse_rfc3339_unix)
                    .is_some_and(|t| now - t <= HEARTBEAT_MAX_AGE_SECS);
                Some((id, n["status"] == "online" && heard))
            })
            .collect();
        checks.push(logs_last_seen_check(metrics.as_deref(), &roster, now));
        // The legacy credential lanes, gateway counters from
        // the same /metrics text, node counts from each node record.
        // Each node's last apply report, for the
        // retired apply lanes (a refusal is a node that kept its old state).
        let apply_reports: Vec<(String, Option<i64>, String)> = fleet
            .iter()
            .filter_map(|n| n["id"].as_str())
            .filter_map(|id| {
                let st = get_json_opt(g, &format!("/api/cluster/provision-bundle/{id}/status"), true, 10)?;
                Some((id.to_string(), st["apply_rc"].as_i64(), st["apply_msg"].as_str().unwrap_or("").to_string()))
            })
            .collect();
        let unadopted: Vec<String> = fleet
            .iter()
            .filter_map(|n| n["id"].as_str())
            .filter(|id| signing_adopted_for(id) == Some(false))
            .map(str::to_string)
            .collect();
        checks.extend(companions_check(&fleet));
        let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
        let expected_ca = std::fs::read(ca.ca_cert_path()).ok()
            .and_then(|p| crate::commands::node_fetch::cert_der_sha256(&p).ok());
        let expected_sp = std::fs::read(ca.signing_pub_path()).ok()
            .map(|p| crate::commands::security_local::signing_pub_fingerprint(&p));
        let expected = match (&expected_ca, &expected_sp) {
            (Some(a), Some(b)) => Some((a.as_str(), b.as_str())),
            _ => None,
        };
        checks.push(with_node_root_refusals(with_node_anchors(with_retired_apply_lanes_and_adoption(
            legacy_lanes_check(metrics.as_deref(), &fleet, now), &apply_reports, &unadopted), &apply_reports, expected), &apply_reports));
        let anonymous = crate::http::get_raw_opt(g, &format!("{LOGS_QUERY_ROUTE}?query=%7Bnode%3D%22verify%22%7D&limit=1"), false, 10)
            .map(|(status, _)| status);
        checks.push(logs_access_check(anonymous));
        let c_ok = checks.iter().all(|c| c.verdict != Verdict::Fail && c.verdict != Verdict::Starting);
        any_starting |= checks.iter().any(|c| c.verdict == Verdict::Starting);
        all_ok &= c_ok;
        if g.json {
            let mut cj = checks_json(&checks);
            with_warmup_json(&mut cj, "loki", loki_seen.as_ref());
            json_out.insert("controller".into(), serde_json::json!({ "ok": c_ok, "checks": cj }));
        } else {
            if !want_nodes {
                println!("{}", ui::header("cluster verify", Some("controller")));
            }
            render("controller", &checks);
        }
    }

    if g.json {
        json_out.insert("ok".into(), Value::Bool(all_ok));
        json_out.insert("starting".into(), Value::Bool(any_starting));
        println!("{}", Value::Object(json_out));
    } else if all_ok {
        println!("{}", ui::status_line(Glyph::Ok, "every invariant holds"));
    } else if any_starting {
        // Not a pass: a starting row is unproven, and exit 1 says so.
        println!("{}", ui::status_line(Glyph::Warn, "a service is still starting — re-run in a minute, or `noo cluster verify --wait`; any failing row has its remedy beside it"));
    } else {
        println!("{}", ui::status_line(Glyph::Err, "an invariant does not hold — the remedy is beside each failing row"));
    }
    Ok(if all_ok { 0 } else { 1 })
}

fn checks_json(checks: &[Check]) -> Value {
    Value::Array(checks.iter().map(|c| serde_json::json!({
        "name": c.name,
        "verdict": match c.verdict { Verdict::Ok => "ok", Verdict::Warn => "warn", Verdict::Fail => "fail", Verdict::Starting => "starting" },
        "detail": c.detail,
        "remedy": c.remedy,
    })).collect())
}

/// Attach a warm-up row's `[judged …]` fields as `warmup` on its object in
/// `--json` (only when the row printed them: FAIL or Starting).
fn with_warmup_json(checks: &mut Value, name: &str, seen: Option<&warmup::WarmupSeen>) {
    let Some(seen) = seen else { return };
    if let Some(row) = checks.as_array_mut().and_then(|a| a.iter_mut().find(|c| c["name"] == name)) {
        row["warmup"] = seen.json();
    }
}

/// After `provision --wait` reports applied: an enrolment is not done until
/// the node verifies. Prints the table; the caller decides the exit code.
pub(crate) fn verify_node_after_apply(g: &Globals, node: &str) -> bool {
    // "Applied" means the agent RESTARTED on the new build a moment ago; its
    // record still holds nothing the new process has said. Judging that
    // record printed ✗ bus / "older agent" on three healthy nodes and told
    // the operator to re-provision them (2026-09-28, then `noo upgrade --nodes`). So
    // wait for one heartbeat sent after this point — the agent beats every
    // 30s — and judge that.
    let since = now_unix();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(POST_APPLY_WAIT_SECS);
    let mut last: Option<Value> = None;
    loop {
        if let Some(body) = get_json_opt(g, "/api/cluster/nodes", true, 10) {
            let empty = Vec::new();
            last = body["nodes"].as_array().unwrap_or(&empty).iter()
                .find(|n| n["id"].as_str() == Some(node)).cloned();
        }
        if last.as_ref().is_some_and(|n| heard_since(n, since)) || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    let Some(n) = last else {
        println!("{}", ui::status_line(Glyph::Warn, &format!("{node}: not in /api/cluster/nodes yet — verify with `noo cluster verify {node}` once it heartbeats")));
        return true;
    };
    if !heard_since(&n, since) {
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "{node}: no heartbeat from the new build within {POST_APPLY_WAIT_SECS}s — judging the last record it sent; `noo cluster verify {node}` re-checks")));
    }
    let checks = node_checks(&with_harness_wanted(g, &n), &controller_stack_tag(), env!("CARGO_PKG_VERSION"), now_unix(), signing_adopted_for(node));
    // A `starting` row is not a pass: the caller's note
    // says the invariant does not hold YET, and `cluster verify` re-checks.
    render(&format!("verify {node}"), &checks) && !checks.iter().any(|c| c.verdict == Verdict::Starting)
}

/// Two and a half heartbeat intervals: one missed beat is not a verdict.
const POST_APPLY_WAIT_SECS: u64 = 75;

/// Has this node's record heard a heartbeat at or after `since`?
pub(crate) fn heard_since(n: &Value, since: i64) -> bool {
    n["last_heartbeat"].as_str().and_then(parse_rfc3339_unix).is_some_and(|t| t >= since)
}

/// The human Seats section header, by what the seat registry returned:
/// `None` (an older gateway without one) prints nothing; an empty registry
/// prints the section with one line naming the verb that enrols a seat.
pub(crate) fn seats_heading(count: Option<usize>) -> Option<(String, Option<&'static str>)> {
    let n = count?;
    Some((format!("Seats ({n})"), (n == 0).then_some(NO_SEATS_LINE)))
}

pub(crate) const NO_SEATS_LINE: &str = "no seats enrolled (noo kiosk seat-token <seat> mints one)";

#[cfg(test)]
mod tests {
    #[test]
    fn seats_section_prints_when_no_seat_is_enrolled() {
        let (heading, line) = super::seats_heading(Some(0)).expect("an empty registry must still print the section");
        assert_eq!(heading, "Seats (0)");
        assert_eq!(line, Some("no seats enrolled (noo kiosk seat-token <seat> mints one)"));
        let (heading, line) = super::seats_heading(Some(2)).unwrap();
        assert_eq!(heading, "Seats (2)");
        assert_eq!(line, None, "enrolled seats render their own rows");
        assert_eq!(super::seats_heading(None), None, "an older gateway without the registry stays silent");
    }

    /// The `model classes` row: declared candidates must be
    /// placed or available; unplaced → WARN naming class + node with the
    /// placement that fixes it; a class with nothing routable → FAIL.
    #[test]
    fn model_classes_row_warns_on_unplaced_and_fails_on_a_dead_class() {
        use super::model_classes_check;
        let body = serde_json::json!({"classes": [
            {"name": "chat-default", "declared": true, "routable": 2, "candidates": [
                {"node_id": "host3", "backend": "vllm", "model": "HF", "status": "placed", "healthy": true},
                {"node_id": "host6", "backend": "ollama", "model": "gemma4:12b", "status": "available", "healthy": true},
                {"node_id": "host8", "backend": "ollama", "model": "gemma4:12b", "status": "unplaced", "healthy": true},
            ]},
            {"name": "gemma4:26b", "declared": false, "routable": 1, "candidates": [
                {"node_id": "host6", "backend": "ollama", "model": "gemma4:26b", "status": "placed", "healthy": true},
            ]},
        ]});
        let c = model_classes_check(Some(&body));
        assert_eq!(c.verdict, super::Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("chat-default: host8/ollama=gemma4:12b"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo cluster place host8 ollama gemma4:12b"));

        let dead = serde_json::json!({"classes": [
            {"name": "fast", "declared": true, "routable": 0, "candidates": [
                {"node_id": "ghost", "backend": "ollama", "model": "x", "status": "unplaced", "healthy": false},
            ]},
        ]});
        let c = model_classes_check(Some(&dead));
        assert_eq!(c.verdict, super::Verdict::Fail, "{c:?}");
        assert!(c.detail.contains("fast") && c.detail.contains("503"), "{}", c.detail);

        let fine = serde_json::json!({"classes": [
            {"name": "chat-default", "declared": true, "routable": 1, "candidates": [
                {"node_id": "host3", "backend": "vllm", "model": "HF", "status": "placed", "healthy": true},
            ]},
        ]});
        assert_eq!(model_classes_check(Some(&fine)).verdict, super::Verdict::Ok);
        let none = serde_json::json!({"classes": [{"name": "HF", "declared": false, "routable": 1, "candidates": []}]});
        let c = model_classes_check(Some(&none));
        assert_eq!(c.verdict, super::Verdict::Ok);
        assert!(c.detail.contains("1 derived"), "{}", c.detail);
        assert_eq!(model_classes_check(None).verdict, super::Verdict::Warn);
    }

    use super::*;

    /// unix → `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days), for canned records.
    fn stamp(t: i64) -> String {
        let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, (secs % 3600) / 60, secs % 60)
    }

    #[test]
    fn a_record_counts_as_heard_only_after_the_apply() {
        let t0 = 1_800_000_000;
        // The restarted agent has said nothing yet: no timestamp at all.
        assert!(!heard_since(&serde_json::json!({"id": "n"}), t0));
        // The OLD process's last beat, from before the apply.
        assert!(!heard_since(&serde_json::json!({"last_heartbeat": stamp(t0 - 20)}), t0));
        // The new build's first beat.
        assert!(heard_since(&serde_json::json!({"last_heartbeat": stamp(t0 + 4)}), t0));
        assert!(heard_since(&serde_json::json!({"last_heartbeat": stamp(t0)}), t0));
    }

    #[test]
    fn the_stamp_round_trips_through_the_parser() {
        for t in [0, 1_700_000_000, 1_800_000_000, 1_758_650_594] {
            assert_eq!(parse_rfc3339_unix(&stamp(t)), Some(t), "{}", stamp(t));
        }
        // The gateway's own shape, and an offset form, and fractional seconds.
        // The gateway's own shape, checked against an independently computed value.
        assert_eq!(parse_rfc3339_unix("2026-09-23T18:03:14Z"), Some(1790186594));
        assert_eq!(parse_rfc3339_unix("2026-09-23T18:02:55.477530972+00:00"), parse_rfc3339_unix("2026-09-23T18:02:55Z"));
        assert_eq!(parse_rfc3339_unix("2026-09-23T14:02:55-04:00"), parse_rfc3339_unix("2026-09-23T18:02:55Z"));
        assert_eq!(parse_rfc3339_unix("nope"), None);
    }

    /// host3 as the controller reported it on 2026-09-23, trimmed.
    fn healthy(now: i64) -> Value {
        serde_json::json!({
            "id": "host3", "status": "online",
            "app_version": "stack-v0.2.70+c3717a3a",
            "nats_role": "node", "nats_state": "connected",
            "peer_identity_enforced": true,
            "last_heartbeat": stamp(now - 20),
            "cert_not_after": now + 200 * 86_400,
            "hostd": { "alive": true, "age_secs": 3, "host": {
                "os": "linux", "running_kernel": "7.0.11", "default_kernel": "7.0.11", "fallback_kernel": "6.18.7",
                "nvidia_module": { "7.0.11": true, "6.18.7": true },
                "boot_partition": { "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 200_000_000u64, "free_bytes": 311_000_000u64,
                                    "initrd_bytes": { "7.0.11": 140_000_000u64 }, "esp_initrd_bytes": { "7.0.11": 140_000_000u64 } },
                "platform": { "tailscale": "1.102.4" }, "held": ["tailscale"],
                "tailscale_state": "Running", "tailscale_online": true,
                "telemetry": { "tailscale_logs": "off", "tailscale_logs_configured": true, "os_reporters": [] } } },
            "inbound": "ok",
            "harness_policy": "auto",
            "host_services": { "harness": { "state": "running" } },
            "self_node": false,
        })
    }

    fn verdict(checks: &[Check], name: &str) -> Verdict {
        checks.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no check {name}")).verdict
    }

    /// host8 after the 2026-09-24 recovery, as its hostd reports it.
    fn host8_host() -> Value {
        serde_json::json!({
            "os": "linux", "running_kernel": "7.0.11", "boot_loader": "kernelstub",
            "default_kernel": "7.0.11", "fallback_kernel": "6.18.7",
            "nvidia_module": { "7.0.11": true, "6.18.7": false },
            "platform": { "linux-system76": "7.1.5", "tailscale": "1.102.4", "docker-ce": "29.8.1" },
            "held": ["docker-ce", "linux-system76", "tailscale"],
            "tailscale_state": "Running", "tailscale_online": true,
            "telemetry": { "tailscale_logs": "off", "tailscale_logs_configured": true, "os_reporters": [] }
        })
    }

    #[test]
    fn the_controller_after_recovery_warns_about_its_fallback_only() {
        let c = host_checks("host8", &host8_host(), true);
        assert_eq!(verdict(&c, "next boot"), Verdict::Ok);
        assert_eq!(verdict(&c, "gpu driver"), Verdict::Warn, "fallback 6.18.7 has no module");
        assert_eq!(verdict(&c, "holds"), Verdict::Ok);
        assert_eq!(verdict(&c, "tailnet control"), Verdict::Ok);
    }

    #[test]
    fn warn_remedies_print_in_the_controller_section_only() {
        let rows = vec![
            warn("service-key grants", "evolve lacks prompt_skills:write", Some("noo security service-key provision evolve".into())),
            warn("loki", "no remedy", None),
            fail("x", "bad", "noo health"),
        ];
        let c = remedies_to_print("controller", &rows);
        assert_eq!(c, vec![("noo security service-key provision evolve", vec!["service-key grants"]), ("noo health", vec!["x"])]);
        assert_eq!(remedies_to_print("node a", &rows), vec![("noo health", vec!["x"])]);
    }

    #[test]
    fn identical_remedies_print_once_with_every_row_they_cover() {
        let luks = "encrypt the data root's disk (LUKS) or accept it";
        let rows = vec![
            warn("loki at rest", "plaintext", Some(luks.into())),
            warn("loki", "other", Some("noo health".into())),
            warn("postgres at rest", "plaintext", Some(luks.into())),
            warn("age key at rest", "plaintext", Some(luks.into())),
        ];
        let c = remedies_to_print("controller", &rows);
        assert_eq!(c, vec![(luks, vec!["loki at rest", "postgres at rest", "age key at rest"]), ("noo health", vec!["loki"])]);
        // Node sections group identical FAIL remedies the same way.
        let fails = vec![fail("a", "x", "noo fix"), fail("b", "x", "noo fix")];
        assert_eq!(remedies_to_print("node n", &fails), vec![("noo fix", vec!["a", "b"])]);
    }

    /// host8, v0.2.95 roll: 7.1.5 installed (vmlinuz symlink), but the
    /// operator pinned host8-oldkern.conf by EFI variable; running 6.18.7.
    fn pinned_host() -> Value {
        let mut h = host8_host();
        h["running_kernel"] = "6.18.7".into();
        h["default_kernel"] = "7.1.5".into();
        h["nvidia_module"] = serde_json::json!({ "7.1.5": true, "6.18.7": true });
        h["boot_partition"] = serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "free_bytes": 300_000_000u64,
            "initrd_bytes": { "6.18.7": 140_000_000u64, "7.1.5": 150_000_000u64 },
            "esp_initrd_bytes": { "6.18.7": 140_000_000u64, "7.1.5": 150_000_000u64 },
            "default_entry": "host8-oldkern.conf", "default_entry_source": "efi-var",
            "entries": [
                { "name": "host8-current.conf", "kernel": "7.1.5", "intact": true },
                { "name": "host8-oldkern.conf", "kernel": "6.18.7", "intact": true } ] });
        h
    }

    #[test]
    fn next_boot_follows_the_effective_pin_not_the_vmlinuz_symlink() {
        let c = host_checks("host8", &pinned_host(), true);
        let r = c.iter().find(|c| c.name == "next boot").unwrap();
        assert_eq!(r.verdict, Verdict::Ok, "{}", r.detail);
        assert_eq!(r.detail, "pinned to host8-oldkern.conf (6.18.7, the running kernel) — newer 7.1.5 installed but not selected");
    }

    #[test]
    fn next_boot_warns_when_the_effective_entry_is_a_different_kernel() {
        let mut h = pinned_host();
        h["boot_partition"]["default_entry"] = "host8-current.conf".into();
        let r = host_checks("host8", &h, true).into_iter().find(|c| c.name == "next boot").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("a reboot runs 7.1.5, not the running 6.18.7"), "{}", r.detail);
    }

    #[test]
    fn next_boot_falls_back_to_default_kernel_without_loader_facts() {
        let mut h = pinned_host();
        h["boot_partition"].as_object_mut().unwrap().remove("default_entry");
        let r = host_checks("host8", &h, true).into_iter().find(|c| c.name == "next boot").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("a reboot runs 7.1.5"), "{}", r.detail);
    }

    fn bp_host(bp: Value) -> Value {
        let mut h = host8_host();
        h["default_kernel"] = "7.1.5".into();
        h["boot_partition"] = bp;
        h
    }

    /// The 2026-10-01 incident, as hostd now reports it: ESP full, 7.1.5's
    /// initrd 315 MB with uncompressed DKMS, its ESP copy cut short.
    #[test]
    fn a_truncated_esp_copy_of_the_next_boot_initrd_fails() {
        let h = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 511_000_000u64, "free_bytes": 0,
            "initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 315_000_000u64 },
            "esp_initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 170_000_000u64 },
            "dkms_compressed": { "7.0.11": true, "7.1.5": false } }));
        let c = host_checks("host8", &h, true);
        let r = c.iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.detail.contains("truncated") && r.detail.contains("7.1.5"), "{}", r.detail);
        assert!(r.remedy.as_deref().unwrap().contains("bootctl set-default"));
    }

    /// host8, v0.2.93 roll: running 6.18.7, next boot 7.1.5, ESP 100% full,
    /// 7.1.5's copy cut short, EFI-var default. The remedy pins the entry that
    /// matches the RUNNING kernel FIRST and forbids kernelstub.
    #[test]
    fn the_host8_case_pins_first_forbids_kernelstub_and_points_at_the_bloat() {
        let mut h = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 511_000_000u64, "free_bytes": 0,
            "initrd_bytes": { "6.18.7": 120_000_000u64, "7.1.5": 315_000_000u64 },
            "esp_initrd_bytes": { "6.18.7": 120_000_000u64, "7.1.5": 187_000_000u64 },
            "default_entry": "host8-current.conf", "default_entry_source": "efi-var",
            "entries": [
                { "name": "host8-current.conf", "kernel": "7.1.5", "esp_initrd_bytes": 187_000_000u64, "intact": false },
                { "name": "host8-oldkern.conf", "kernel": "6.18.7", "esp_initrd_bytes": 120_000_000u64, "intact": true } ] }));
        h["running_kernel"] = "6.18.7".into();
        let r = host_checks("host8", &h, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.detail.contains("the ESP is full"), "{}", r.detail);
        assert!(!r.detail.contains("unknown free space"), "{}", r.detail);
        assert!(r.detail.contains("EFI variable LoaderEntryDefault") && r.detail.contains("overrides loader.conf"), "{}", r.detail);
        assert!(r.detail.contains("initramfs bloat"), "{}", r.detail);
        let fix = r.remedy.unwrap();
        let at = |w: &str| fix.find(w).unwrap_or_else(|| panic!("{w} missing from {fix}"));
        assert!(at("sudo bootctl set-default host8-oldkern.conf") < at("do NOT run kernelstub"), "{fix}");
        let order = ["do NOT run kernelstub", "do NOT run `apt`", "oversized next-boot initrd", "shrink the initrd first", "sudo cp /boot/initrd.img-7.1.5 /boot/efi/EFI/<dir>/initrd.img", "cmp /boot/initrd.img-7.1.5", "sudo bootctl set-oneshot host8-oldkern.conf"];
        for w in order.windows(2) {
            assert!(at(w[0]) < at(w[1]), "{} must precede {}: {fix}", w[0], w[1]);
        }
        assert!(!fix.contains("sudo kernelstub"), "{fix}");
        let no_apt = fix.replace("do NOT run `apt` / `apt autoremove`", "");
        assert!(!no_apt.contains("apt"), "no apt suggestion in the remedy: {fix}");
        assert!(at("FIRST pin") == 0, "{fix}");
        for w in ["*-previous", "bootctl list", "lsinitramfs -l /boot/initrd.img-7.1.5 | sort -k5 -n | tail", "framebuffer-nvidia"] {
            assert!(fix.contains(w), "{w} missing from {fix}");
        }
    }

    /// host8, v0.2.97 roll: pinned to the running 6.18.7 (intact on the ESP),
    /// ESP full, 7.1.5 installed with a 315 MB initrd.
    #[test]
    fn a_full_esp_with_an_intact_pinned_entry_names_the_next_kernel_install_not_the_boot() {
        let mut h = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 511_000_000u64, "free_bytes": 0,
            "initrd_bytes": { "6.18.7": 139_000_000u64, "7.1.5": 314_926_112u64 },
            "esp_initrd_bytes": { "6.18.7": 139_000_000u64, "7.1.5": 187_973_632u64 },
            "default_entry": "host8-oldkern.conf", "default_entry_source": "efi-var",
            "entries": [
                { "name": "host8-current.conf", "kernel": "7.1.5", "intact": false },
                { "name": "host8-oldkern.conf", "kernel": "6.18.7", "intact": true } ] }));
        h["running_kernel"] = "6.18.7".into();
        let r = host_checks("host8", &h, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert_eq!(r.detail, "the pinned entry (6.18.7) is intact; /boot/efi is full, so the next kernel install (7.1.5, 314 MB initrd) cannot be copied — shrink its initrd first (see remedy)");
        let fix = r.remedy.unwrap();
        assert!(fix.contains("shrink the 7.1.5 initrd") && fix.contains("/boot/initrd.img-7.1.5") && fix.contains("do NOT run kernelstub"), "{fix}");
    }

    #[test]
    fn with_no_intact_entry_for_the_running_kernel_the_remedy_says_do_not_reboot() {
        let h = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "free_bytes": 0,
            "initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 140_000_000u64 },
            "esp_initrd_bytes": { "7.1.5": 100_000_000u64 } }));
        let r = host_checks("host8", &h, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        let fix = r.remedy.unwrap();
        assert!(fix.starts_with("FIRST pin") && fix.contains("do not reboot"), "{fix}");
        assert!(!r.detail.contains("initramfs bloat"), "same-size initrds are not bloat: {}", r.detail);
    }

    #[test]
    fn a_full_esp_and_an_outsized_uncompressed_initrd_warn_with_the_remedy() {
        // Full ESP, copy intact (so not truncated).
        let full = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 500_000_000u64, "free_bytes": 11_000_000u64,
            "initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 140_000_000u64 },
            "esp_initrd_bytes": { "7.1.5": 140_000_000u64 } }));
        let r = host_checks("host8", &full, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("less than the next-boot initrd needs"), "{}", r.detail);
        let fix = r.remedy.clone().unwrap();
        assert!(fix.contains("do NOT run `apt`") && !fix.replace("do NOT run `apt` / `apt autoremove`", "").contains("apt"), "{fix}");

        let big = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 100_000_000u64, "free_bytes": 411_000_000u64,
            "initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 315_000_000u64 },
            "dkms_compressed": { "7.0.11": true, "7.1.5": false } }));
        let r = host_checks("host8", &big, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("uncompressed") && r.detail.contains("outsized"), "{}", r.detail);
        let fix = r.remedy.unwrap();
        assert!(!fix.replace("do NOT run kernelstub", "").contains("apt"), "{fix}");
        for w in ["zstd", "depmod", "update-initramfs -u -k 7.1.5", "bootctl set-default"] {
            assert!(fix.contains(w), "{fix}");
        }
    }

    #[test]
    fn a_healthy_boot_partition_passes_and_unread_is_not_checked_not_ok() {
        let good = bp_host(serde_json::json!({
            "mount": "/boot/efi", "total_bytes": 511_000_000u64, "used_bytes": 300_000_000u64, "free_bytes": 211_000_000u64,
            "initrd_bytes": { "7.0.11": 140_000_000u64, "7.1.5": 142_000_000u64 },
            "esp_initrd_bytes": { "7.1.5": 142_000_000u64 },
            "dkms_compressed": { "7.0.11": true, "7.1.5": true } }));
        assert_eq!(verdict(&host_checks("host8", &good, true), "boot partition"), Verdict::Ok);
        let unread = bp_host(serde_json::json!({}));
        let c = host_checks("host8", &unread, true);
        let r = c.iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.starts_with("not checked"), "{}", r.detail);
    }

    #[test]
    fn an_old_hostd_without_the_boot_fields_is_named() {
        let c = host_checks("host8", &host8_host(), true);
        let r = c.iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("not reported (older agent)"), "{}", r.detail);
    }

    /// Before the recovery: 7.1.5 would boot, and suppose DKMS had not built
    /// for it — that is a FAIL, named with the kernel.
    #[test]
    fn a_next_boot_without_the_gpu_module_fails() {
        let mut h = host8_host();
        h["default_kernel"] = "7.1.5".into();
        h["nvidia_module"]["7.1.5"] = false.into();
        let c = host_checks("host8", &h, true);
        let g = c.iter().find(|c| c.name == "gpu driver").unwrap();
        assert_eq!(g.verdict, Verdict::Fail);
        assert!(g.detail.contains("7.1.5"));
        assert_eq!(verdict(&c, "next boot"), Verdict::Warn, "a pending kernel change is named");
    }

    #[test]
    fn unheld_platform_packages_and_an_offline_control_plane_are_reported() {
        let mut h = host8_host();
        h["held"] = serde_json::json!(["linux-system76"]);
        h["tailscale_online"] = false.into();
        let c = host_checks("host8", &h, true);
        let holds = c.iter().find(|c| c.name == "holds").unwrap();
        assert_eq!(holds.verdict, Verdict::Warn);
        assert!(holds.detail.contains("docker-ce") && holds.detail.contains("tailscale"));
        assert_eq!(verdict(&c, "tailnet control"), Verdict::Fail);
    }

    /// host2, 2026-10-01: a "NoState" reading taken seconds into a boot was
    /// served for five minutes and read as a stall. The row now says how old
    /// the reading is, and its remedy says not to restart on a boot-time one.
    #[test]
    fn a_not_connected_tailnet_row_says_how_old_its_reading_is() {
        let mut h = host8_host();
        h["tailscale_state"] = "NoState".into();
        h["tailscale_online"] = false.into();
        let four_min_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 240;
        h["collected_at"] = stamp(four_min_ago as i64).into();
        let c = host_checks("host2", &h, true);
        let row = c.iter().find(|c| c.name == "tailnet control").unwrap();
        assert_eq!(row.verdict, Verdict::Fail);
        assert!(row.detail.contains("read 4m ago"), "{}", row.detail);
        let remedy = row.remedy.as_deref().unwrap_or("");
        assert!(remedy.starts_with("sudo systemctl restart tailscaled") && remedy.contains("a minute later"), "{remedy}");

        // Read 9s after boot: starting, not failed, and still not a pass.
        let booted = four_min_ago as i64 - 9;
        h["booted_at"] = stamp(booted).into();
        let row = host_checks("host2", &h, true).into_iter().find(|c| c.name == "tailnet control").unwrap();
        assert_eq!(row.verdict, Verdict::Starting, "{}", row.detail);
        assert!(row.detail.contains("9s after boot"), "{}", row.detail);
        assert_eq!(row.remedy.as_deref(), Some("noo cluster verify host2   # re-run in a minute"));
        // Read 10 minutes after boot: a real stall fails as before.
        h["booted_at"] = stamp(four_min_ago as i64 - 600).into();
        let row = host_checks("host2", &h, true).into_iter().find(|c| c.name == "tailnet control").unwrap();
        assert_eq!(row.verdict, Verdict::Fail, "{}", row.detail);
        h["booted_at"] = serde_json::Value::Null;

        // No timestamp: the row still fails and says nothing about age.
        h["collected_at"] = serde_json::Value::Null;
        let row = host_checks("host2", &h, true).into_iter().find(|c| c.name == "tailnet control").unwrap();
        assert!(!row.detail.contains(" ago"), "{}", row.detail);
    }

    #[test]
    fn a_wsl2_node_has_no_boot_loader_to_warn_about() {
        // host3, 2026-10-01: "could not tell which kernel the next boot runs".
        let host = serde_json::json!({"os": "linux", "running_kernel": "6.18.40.1-microsoft-standard-WSL2",
                                      "default_kernel": "", "fallback_kernel": "", "boot_loader": ""});
        let c = host_checks("host3", &host, true);
        assert_eq!(verdict(&c, "next boot"), Verdict::Ok);
        let plain = serde_json::json!({"os": "linux", "running_kernel": "6.8.0-1064-raspi",
                                       "default_kernel": "", "fallback_kernel": "", "boot_loader": ""});
        assert_eq!(verdict(&host_checks("host9", &plain, true), "next boot"), Verdict::Warn,
            "an unrecognised boot loader on real hardware still warns");
    }

    #[test]
    fn a_wsl2_node_has_no_boot_partition_to_check() {
        // host3, 2026-10-09: `! boot partition  not checked (the ESP and /boot
        // initrds could not be read)` beside a `next boot` row that already
        // says Windows supplies the kernel.
        let running = "6.18.40.1-microsoft-standard-WSL2";
        for bp in [serde_json::json!({}), Value::Null,
                   serde_json::json!({"mount": "/boot/efi", "initrd_bytes": {}, "esp_initrd_bytes": {}})] {
            let mut host = serde_json::json!({"os": "linux", "running_kernel": running,
                                              "default_kernel": "", "fallback_kernel": "", "boot_loader": ""});
            if !bp.is_null() {
                host["boot_partition"] = bp.clone();
            }
            let c = host_checks("host3", &host, true);
            let r = c.iter().find(|c| c.name == "boot partition")
                .unwrap_or_else(|| panic!("no boot partition row for {bp}"));
            assert_eq!(r.verdict, Verdict::Ok, "{bp}: {}", r.detail);
            assert!(r.detail.starts_with("WSL2 — Windows boots this node") && r.detail.contains(running), "{}", r.detail);
            assert!(!r.detail.contains("not checked"), "{}", r.detail);
            assert!(r.remedy.is_none());
            assert_eq!(verdict(&c, "next boot"), Verdict::Ok);
        }
        // Real hardware whose ESP could not be read still says so.
        let plain = serde_json::json!({"os": "linux", "running_kernel": "6.8.0-1064-raspi",
                                       "default_kernel": "", "fallback_kernel": "", "boot_loader": "",
                                       "boot_partition": {}});
        let r = host_checks("host9", &plain, true).into_iter().find(|c| c.name == "boot partition").unwrap();
        assert_eq!(r.verdict, Verdict::Warn);
        assert!(r.detail.contains("not checked"), "{}", r.detail);
    }

    fn tel(logs: &str, configured: bool, reporters: &[&str]) -> Value {
        let mut h = host8_host();
        h["telemetry"] = serde_json::json!({"tailscale_logs": logs, "tailscale_logs_configured": configured, "os_reporters": reporters});
        h
    }

    /// The live host3 shape: tailscaled started with no switch.
    #[test]
    fn tailscaled_uploading_its_logs_fails_with_the_exact_remedy() {
        let c = host_checks("host3", &tel("on", false, &[]), true);
        let r = c.iter().find(|c| c.name == "host telemetry").expect("no host telemetry row");
        assert_eq!(r.verdict, Verdict::Fail, "{}", r.detail);
        assert!(r.detail.contains("technical support"), "the cost of the switch must be said: {}", r.detail);
        let fix = r.remedy.as_deref().unwrap();
        assert!(fix.contains("TS_NO_LOGS_NO_SUPPORT=true") && fix.contains("/etc/default/tailscaled") && fix.contains("systemctl restart tailscaled"), "{fix}");
        // The remedy leads with the operator's one command, naming this node, and
        // that command is one the CLI accepts (hint_lint checks the usage row).
        assert!(fix.contains("`noo cluster host-telemetry apply host3`"), "{fix}");
        assert!(crate::usage::lookup(&["cluster", "host-telemetry", "apply"]).is_some(), "the verify remedy points at a verb with no usage row");
        // Already in the file: only the restart is missing.
        let r = host_checks("host3", &tel("on", true, &[]), true).into_iter().find(|c| c.name == "host telemetry").unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(!r.remedy.as_deref().unwrap().contains("tee -a"), "{:?}", r.remedy);
    }

    #[test]
    fn an_operator_opt_in_to_the_upload_is_a_warn_with_the_way_back() {
        let mut h = tel("on", false, &[]);
        h["telemetry"]["tailscale_logs_operator_choice"] = true.into();
        let c = host_checks("host2", &h, true);
        let r = c.iter().find(|c| c.name == "host telemetry").unwrap();
        assert_eq!(r.verdict, Verdict::Warn, "{}", r.detail);
        assert!(r.detail.contains("operator choice"), "{}", r.detail);
        let fix = r.remedy.as_deref().unwrap();
        assert!(fix.contains("sudo rm /etc/noo/allow-tailscale-log-upload") && fix.contains("TS_NO_LOGS_NO_SUPPORT=true"), "{fix}");
        assert!(fix.contains("`noo cluster host-telemetry apply host2`"), "{fix}");
        // The opt-in does not excuse a node that is NOT uploading, nor hide anything else.
        h["telemetry"]["tailscale_logs"] = "off".into();
        assert_eq!(verdict(&host_checks("host2", &h, true), "host telemetry"), Verdict::Ok);
    }

    #[test]
    fn a_node_with_the_switch_passes_and_a_stopped_tailscaled_is_not_a_failure() {
        assert_eq!(verdict(&host_checks("host3", &tel("off", true, &[]), true), "host telemetry"), Verdict::Ok);
        assert_eq!(verdict(&host_checks("host3", &tel("not_running", false, &[]), true), "host telemetry"), Verdict::Ok);
    }

    #[test]
    fn ubuntu_reporters_warn_with_one_command_each_and_are_never_a_fail() {
        let c = host_checks("host2", &tel("off", true, &["motd-news", "popularity-contest", "whoopsie"]), true);
        let r = c.iter().find(|c| c.name == "host telemetry").unwrap();
        assert_eq!(r.verdict, Verdict::Warn, "{}", r.detail);
        let fix = r.remedy.as_deref().unwrap();
        for want in ["/etc/default/motd-news", "motd-news.timer", "/etc/popularity-contest.conf", "disable --now whoopsie"] {
            assert!(fix.contains(want), "{want} missing from {fix}");
        }
    }

    #[test]
    fn an_unproven_host_is_a_warn_never_a_pass() {
        let mut h = host8_host();
        h.as_object_mut().unwrap().remove("telemetry");
        assert_eq!(verdict(&host_checks("host2", &h, true), "host telemetry"), Verdict::Warn);
        assert_eq!(verdict(&host_checks("host3", &tel("unknown", false, &[]), true), "host telemetry"), Verdict::Warn);
    }

    #[test]
    fn a_mac_is_judged_for_its_brew_tailscaled_only() {
        let mac = serde_json::json!({"os": "darwin", "telemetry": {"tailscale_logs": "on", "tailscale_logs_configured": false, "os_reporters": []}});
        let c = host_checks("host6", &mac, true);
        assert_eq!(c.len(), 1, "a Mac has no boot or package rows");
        assert_eq!(c[0].verdict, Verdict::Fail);
        assert!(c[0].remedy.as_deref().unwrap().contains("launchctl bootstrap system"));
        // A Mac whose hostd reports no telemetry stays as before: no rows.
        assert!(host_checks("host6", &serde_json::json!({"os": "darwin"}), true).is_empty());
    }

    #[test]
    fn a_mac_is_skipped_and_an_old_hostd_is_named() {
        assert!(host_checks("host6", &serde_json::json!({"os": "darwin"}), true).is_empty());
        let c = host_checks("host2", &Value::Null, true);
        assert_eq!(verdict(&c, "next boot"), Verdict::Warn);
        assert!(host_checks("host2", &Value::Null, false).is_empty(), "a dead hostd already fails its own row");
    }

    #[test]
    fn a_healthy_node_passes_every_invariant() {
        let now = 1_800_000_000;
        let c = node_checks(&healthy(now), "v0.2.70", "0.5.57", now, Some(true));
        let failed: Vec<_> = c.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| c.name).collect();
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(c.len(), 19, "thirteen node invariants (the log shipper, peer identity, backend doors, vendor telemetry and data root among them) plus six host-fact rows (boot partition and host telemetry among them), each judged");
    }

    /// The door refusals ride the heartbeat as `backend_tls` (refused to
    /// start) and `backend_door` (running plain). Either fails the `backend
    /// doors` row, names the backend, and points at the rail — never at an
    /// env edit on the node. Other refusal scopes are not this row, and the
    /// old `backend tls` row is gone.
    #[test]
    fn a_backend_door_refusal_fails_the_node_and_names_the_rail() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["id"] = "host3".into();
        n["reconcile_refusals"] = serde_json::json!([
            { "scope": "placement_env", "target": "vllm/HF_TOKEN", "reason": "not a tuning key", "since": "2026-09-28T00:00:00Z" },
            { "scope": "backend_tls", "target": "vllm", "reason": "this node's PKI dir has no services/vllm leaf", "since": "2026-09-28T00:00:00Z" },
        ]);
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert!(c.iter().all(|c| c.name != "backend tls"), "the old env-fix row must be gone");
        let rows: Vec<_> = c.iter().filter(|c| c.name == "backend doors").collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, Verdict::Fail);
        assert!(rows[0].detail.contains("vllm") && rows[0].detail.contains("services/vllm"), "{}", rows[0].detail);
        assert!(!rows[0].detail.contains("HF_TOKEN"), "another scope leaked into the row: {}", rows[0].detail);
        let remedy = rows[0].remedy.as_deref().unwrap();
        assert!(remedy.starts_with("noo cluster provision host3"), "{remedy}");
        // A node with no door-backed backend is OK and reads nothing.
        let quiet = node_checks(&healthy(now), "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&quiet, "backend doors"), Verdict::Ok);
    }

    fn door_leaf(dns: &[&str], not_after: i64) -> crate::commands::node_leaves::LeafState {
        crate::commands::node_leaves::LeafState::Present {
            dns: dns.iter().map(|d| d.to_string()).collect(), not_after, aki: None }
    }

    /// The `data root` row: agree, declaration vs node,
    /// a stale mount, and an older agent.
    #[test]
    fn the_data_root_row_judges_each_shape() {
        let now = 1_800_000_000;
        let base = || {
            let mut n = healthy(now);
            n["declared_data_root"] = "/data/noo".into();
            n["data_roots"] = serde_json::json!({
                "noo_data_root": "/data/noo", "noo_data_root_source": "env",
                "hf_cache_dir": "/data/noo/hf-cache", "models_dir": "/data/noo/models",
                "ollama_data_dir": "/data/noo/ollama",
                "running_mounts": {"vllm": ["/data/noo/hf-cache"]}});
            n
        };
        let c = data_root_row(&base());
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);

        // No declaration, node consistent: OK.
        let mut n = base();
        n.as_object_mut().unwrap().remove("declared_data_root");
        assert_eq!(data_root_row(&n).verdict, Verdict::Ok);

        // The host3 shape: declared /opt/noo, node and mounts on /data/noo.
        let mut n = base();
        n["declared_data_root"] = "/opt/noo".into();
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("declared /opt/noo") && c.detail.contains("/data/noo"), "{}", c.detail);
        assert!(c.detail.contains("noo-vllm mounts /data/noo/hf-cache"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo cluster set-config host3 --data-root /data/noo"));

        // Roots agree, a container still mounts the old path.
        let mut n = base();
        n["data_roots"]["running_mounts"] = serde_json::json!({"vllm": ["/mnt/d/noo/hf-cache"]});
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-vllm mounts /mnt/d/noo/hf-cache"), "{}", c.detail);

        // Older agent: WARN, never a verdict about the node.
        let mut n = base();
        n.as_object_mut().unwrap().remove("data_roots");
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("not reported (older agent)"), "{}", c.detail);
    }

    /// A Mac node (2026-10-06) failed to load its env, fell back to the
    /// Linux /mnt/d/noo, and the row offered that as the declaration.
    #[test]
    fn a_built_in_default_root_is_never_offered_as_the_declaration() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["id"] = "a-mac".into();
        n["hostd"]["host"]["os"] = "darwin".into();
        n["declared_data_root"] = "/Users/someone/noomesh".into();
        n["data_roots"] = serde_json::json!({
            "noo_data_root": "/mnt/d/noo", "noo_data_root_source": "default",
            "hf_cache_dir": "/mnt/d/noo/hf-cache", "models_dir": "/mnt/d/noo/models",
            "ollama_data_dir": "/mnt/d/noo/ollama"});
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        let r = c.remedy.unwrap();
        assert!(r.contains("~/noomesh/agent.env") && r.contains("noo cluster restart-agent a-mac"), "{r}");
        assert!(!r.contains("--data-root /mnt/d/noo") && !r.contains("set-config"), "{r}");

        // Same fallback root on a Linux node: still not a declaration.
        let mut l = n.clone();
        l["hostd"]["host"]["os"] = "linux".into();
        l["declared_data_root"] = "/srv/noo".into();
        let r = data_root_row(&l).remedy.unwrap();
        assert!(r.contains("/etc/noo-node-agent.env") && !r.contains("--data-root"), "{r}");

        // A Linux root on a Mac is no candidate even when "told".
        let mut m = n.clone();
        m["data_roots"]["noo_data_root_source"] = "env".into();
        let r = data_root_row(&m).remedy.unwrap();
        assert!(!r.contains("--data-root /mnt/d/noo"), "{r}");

        // A Linux node that genuinely declared /data/noo: the two-way remedy stays.
        let mut g = healthy(now);
        g["declared_data_root"] = "/srv/noo".into();
        g["data_roots"] = serde_json::json!({
            "noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "hf_cache_dir": "/data/noo/hf-cache", "models_dir": "/data/noo/models",
            "ollama_data_dir": "/data/noo/ollama"});
        let c = data_root_row(&g);
        assert_eq!(c.verdict, Verdict::Fail);
        assert_eq!(c.remedy.as_deref(), Some("noo cluster set-config host3 --data-root /data/noo"));
    }

    /// A node's vllm mounts `/opt/noo/hf-cache`, a
    /// symlink to `/data/noo/hf-cache`. Healthy, with the note; an older
    /// agent (no resolution) or a link leading outside still fails.
    #[test]
    fn the_data_root_row_notes_a_mount_that_is_a_symlink_into_the_root() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["declared_data_root"] = "/data/noo".into();
        n["data_roots"] = serde_json::json!({
            "noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "running_mounts": {"vllm": ["/opt/noo/hf-cache"]},
            "running_mounts_resolved": {"/opt/noo/hf-cache": "/data/noo/hf-cache"}});
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("same data, different path: noo-vllm mounts /opt/noo/hf-cache -> /data/noo/hf-cache"), "{}", c.detail);
        assert!(c.detail.contains("moves on the next recreate"), "{}", c.detail);

        n["data_roots"].as_object_mut().unwrap().remove("running_mounts_resolved");
        let c = data_root_row(&n);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);

        n["data_roots"]["running_mounts_resolved"] = serde_json::json!({"/opt/noo/hf-cache": "/mnt/d/noo/hf-cache"});
        assert_eq!(data_root_row(&n).verdict, Verdict::Fail);
    }

    /// Every shape of the `backend doors` row, one plant at a time, on a
    /// node running vLLM and TEI in Docker and a NATIVE ollama (no door —
    /// the operator's loopback process, never judged here).
    #[test]
    fn the_backend_doors_row_judges_each_shape() {
        use crate::commands::node_leaves::LeafState;
        let now = 1_800_000_000;
        let far = now + 80 * 86_400;
        let base = || {
            let mut n = healthy(now);
            n["running_backends"] = serde_json::json!({"vllm": "m", "embedding": "harrier", "ollama": "gemma"});
            n["backend_runtimes"] = serde_json::json!({"vllm": "docker", "embedding": "docker", "ollama": "native"});
            n["backend_leaves"] = serde_json::json!({
                "vllm": {"dns": ["vllm", "noo-vllm", "noo-vllm-secondary"], "not_after": far},
                "tei": {"dns": ["tei", "noo-stunnel-tei"], "not_after": far},
            });
            n
        };
        let good = |svc: &str| match svc {
            "vllm" => door_leaf(&["vllm", "localhost", "noo-vllm", "noo-vllm-secondary"], far),
            "tei" => door_leaf(&["tei", "localhost", "noo-stunnel-tei"], far),
            other => panic!("read a leaf for {other}, which has no docker backend here"),
        };
        let judge = |n: &Value, leaf: &dyn Fn(&str) -> LeafState| backend_doors_check(n, leaf, now);

        let c = judge(&base(), &good);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("embedding") && c.detail.contains("vllm") && !c.detail.contains("ollama"), "{}", c.detail);

        // Agent predates the report: WARN, never OK, never FAIL on that alone.
        let mut n = base();
        n.as_object_mut().unwrap().remove("backend_leaves");
        let c = judge(&n, &good);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("predates"), "{}", c.detail);

        // Refusals: backend_door (plaintext) and backend_tls (refused start).
        for scope in ["backend_door", "backend_tls"] {
            let mut n = base();
            n["reconcile_refusals"] = serde_json::json!([{ "scope": scope, "target": "embedding", "reason": "r" }]);
            let c = judge(&n, &good);
            assert_eq!(c.verdict, Verdict::Fail, "{scope}");
            assert!(c.detail.contains("embedding") && c.detail.contains(scope), "{}", c.detail);
            assert!(c.remedy.as_deref().unwrap().starts_with("noo cluster provision host3"));
        }

        // Controller copy: missing, not naming the door, expiring.
        let fails = |leaf: &dyn Fn(&str) -> LeafState, needle: &str| {
            let c = judge(&base(), leaf);
            assert_eq!(c.verdict, Verdict::Fail, "{needle}: {}", c.detail);
            assert!(c.detail.contains(needle), "{needle}: {}", c.detail);
        };
        fails(&|s: &str| if s == "tei" { LeafState::Missing } else { good(s) }, "holds no tei leaf");
        fails(&|s: &str| if s == "tei" { door_leaf(&["tei", "noo-tei"], far) } else { good(s) }, "does not name noo-stunnel-tei");
        fails(&|s: &str| if s == "vllm" { door_leaf(&["noo-vllm"], now + 3 * 86_400) } else { good(s) }, "expires in 3 days");

        // Node-side report: missing, not naming the door, expiring.
        let mut n = base();
        n["backend_leaves"].as_object_mut().unwrap().remove("tei");
        let c = judge(&n, &good);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("node holds no services/tei leaf"), "{}", c.detail);
        let mut n = base();
        n["backend_leaves"]["vllm"]["dns"] = serde_json::json!(["vllm"]);
        assert!(judge(&n, &good).detail.contains("node's services/vllm leaf does not name noo-vllm"));
        let mut n = base();
        n["backend_leaves"]["tei"]["not_after"] = serde_json::json!(now + 86_400);
        assert_eq!(judge(&n, &good).verdict, Verdict::Fail);

        // vllm-secondary shares the vllm leaf and is dialled by its own name.
        let mut n = base();
        n["running_backends"] = serde_json::json!({"vllm-secondary": "m"});
        let c = judge(&n, &|s: &str| if s == "vllm" { door_leaf(&["noo-vllm"], far) } else { good(s) });
        assert!(c.detail.contains("does not name noo-vllm-secondary"), "{}", c.detail);
    }

    /// A node record whose `backend doors` fails only because the node has
    /// no tei leaf YET, with the node's `backend_containers` report as given
    /// `far`-dated leaves otherwise.
    fn door_warmup_case(now: i64, containers: Option<Value>) -> (Value, impl Fn(&str) -> crate::commands::node_leaves::LeafState) {
        let far = now + 80 * 86_400;
        let mut n = healthy(now);
        n["running_backends"] = serde_json::json!({"vllm": "m", "embedding": "harrier"});
        n["backend_runtimes"] = serde_json::json!({"vllm": "docker", "embedding": "docker"});
        n["backend_leaves"] = serde_json::json!({
            "vllm": {"dns": ["vllm", "noo-vllm", "noo-vllm-secondary"], "not_after": far},
        });
        if let Some(c) = containers {
            n["backend_containers"] = c;
        }
        let good = move |svc: &str| match svc {
            "vllm" => door_leaf(&["vllm", "localhost", "noo-vllm", "noo-vllm-secondary"], far),
            "tei" => door_leaf(&["tei", "localhost", "noo-stunnel-tei"], far),
            other => panic!("read a leaf for {other}"),
        };
        (n, good)
    }
    fn life(now: i64, up: i64, health: Option<&str>) -> Value {
        let mut e = serde_json::json!({"running": true, "started_at": now - up});
        if let Some(h) = health {
            e["health"] = h.into();
        }
        e
    }

    /// The first verify after a bundle apply. The node's tei
    /// door has no leaf yet and its container started 5s ago, health
    /// starting: `starting`, not FAIL, no remedy. Past the window the same
    /// record FAILs and names the backend.
    #[test]
    fn a_node_backend_five_seconds_old_and_starting_reads_starting() {
        let now = 1_800_000_000;
        let (n, leaf) = door_warmup_case(now, Some(serde_json::json!({
            "vllm": life(now, 4000, Some("healthy")), "embedding": life(now, 5, Some("starting")) })));
        let c = backend_doors_check(&n, &leaf, now);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(c.detail.starts_with("starting (embedding 5s since start, health=starting"), "{}", c.detail);
        assert!(c.detail.contains("node holds no services/tei leaf"), "the unproven problem stays visible: {}", c.detail);
        assert!(c.remedy.is_none(), "{:?}", c.remedy);
        assert_eq!(checks_json(&[c])[0]["verdict"], "starting");

        // The agent's own refusal for that missing leaf (the reason text
        // node-agent-go writes) is warm-up too.
        let (mut n, leaf) = door_warmup_case(now, Some(serde_json::json!({ "embedding": life(now, 5, Some("starting")) })));
        n["backend_leaves"]["tei"] = serde_json::json!({"dns": ["tei", "noo-stunnel-tei"], "not_after": now + 80 * 86_400});
        n["reconcile_refusals"] = serde_json::json!([{ "scope": "backend_tls", "target": "embedding",
            "reason": "this node's PKI dir has no services/tei leaf (/etc/noo/pki/services/tei/service.crt: no such file or directory); ..." }]);
        n["backend_containers"]["vllm"] = life(now, 4000, Some("healthy"));
        let c = backend_doors_check(&n, &leaf, now);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);

        // Past the window: FAIL, remedy kept, the backend named.
        let (n, leaf) = door_warmup_case(now, Some(serde_json::json!({
            "embedding": life(now, warmup::WARMUP_WINDOW_SECS, Some("starting")) })));
        let c = backend_doors_check(&n, &leaf, now);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("the embedding container has been up 180s, past the 180s warm-up"), "{}", c.detail);
        assert!(c.remedy.is_some());

        // Inside the window but not warming: unhealthy, healthy, stopped.
        for e in [life(now, 5, Some("unhealthy")), life(now, 5, Some("healthy")),
            serde_json::json!({"running": false, "started_at": now - 5})] {
            let (n, leaf) = door_warmup_case(now, Some(serde_json::json!({ "embedding": e.clone() })));
            let c = backend_doors_check(&n, &leaf, now);
            assert_eq!(c.verdict, Verdict::Fail, "{e}: {}", c.detail);
            assert!(c.detail.contains("the embedding container"), "{}", c.detail);
        }
        // No healthcheck declared: uptime alone explains it, as for Loki.
        let (n, leaf) = door_warmup_case(now, Some(serde_json::json!({ "embedding": life(now, 40, None) })));
        assert_eq!(backend_doors_check(&n, &leaf, now).verdict, Verdict::Starting);
    }

    /// An agent that does not report `backend_containers` (or not for the
    /// backend in question, or without a start time) leaves the row exactly
    /// as it is today: FAIL, never softened.
    #[test]
    fn a_node_without_container_reports_keeps_the_row_as_it_was() {
        let now = 1_800_000_000;
        let (n, leaf) = door_warmup_case(now, None);
        let before = backend_doors_check(&n, &leaf, now);
        assert_eq!(before.verdict, Verdict::Fail, "{}", before.detail);
        assert!(!before.detail.contains("container"), "{}", before.detail);
        for report in [
            serde_json::json!({}),
            serde_json::json!({ "vllm": life(now, 5, Some("starting")) }),
            serde_json::json!({ "embedding": {"running": true, "health": "starting"} }),
            serde_json::json!({ "embedding": {"started_at": now - 5, "health": "starting"} }),
            Value::Null,
        ] {
            let (n, leaf) = door_warmup_case(now, Some(report.clone()));
            assert_eq!(backend_doors_check(&n, &leaf, now), before, "{report}");
        }
    }

    /// Operator rule: a security fault on `backend doors` never softens,
    /// however fresh every container — and one beside a "no leaf yet"
    /// problem keeps the whole row FAIL.
    #[test]
    fn backend_doors_security_faults_never_soften() {
        let now = 1_800_000_000;
        let fresh = serde_json::json!({ "vllm": life(now, 5, Some("starting")), "embedding": life(now, 5, Some("starting")) });
        type Plant = Box<dyn Fn(&mut Value)>;
        let plants: Vec<(&str, Plant)> = vec![
            ("node leaf not naming its door", Box::new(|n: &mut Value| n["backend_leaves"]["vllm"]["dns"] = serde_json::json!(["vllm"]))),
            ("node leaf expiring", Box::new(move |n: &mut Value| n["backend_leaves"]["vllm"]["not_after"] = serde_json::json!(now + 86_400))),
            ("node leaf without expiry", Box::new(|n: &mut Value| { n["backend_leaves"]["vllm"].as_object_mut().unwrap().remove("not_after"); })),
            ("plaintext door", Box::new(|n: &mut Value| n["reconcile_refusals"] = serde_json::json!([{ "scope": "backend_door", "target": "vllm", "reason": "serves PLAINTEXT" }]))),
            ("leaf present, wrong SAN", Box::new(|n: &mut Value| n["reconcile_refusals"] = serde_json::json!([{ "scope": "backend_tls", "target": "vllm",
                "reason": "services/vllm/service.crt does not name noo-vllm (SANs: vllm)" }]))),
            ("no cluster CA", Box::new(|n: &mut Value| n["reconcile_refusals"] = serde_json::json!([{ "scope": "backend_tls", "target": "vllm",
                "reason": "no cluster CA at /etc/noo/pki/ca.crt" }]))),
        ];
        for (what, plant) in &plants {
            let (mut n, leaf) = door_warmup_case(now, Some(fresh.clone()));
            plant(&mut n);
            let c = backend_doors_check(&n, &leaf, now);
            assert_eq!(c.verdict, Verdict::Fail, "{what} was softened: {}", c.detail);
            assert!(c.remedy.is_some(), "{what}");
            assert!(!c.detail.contains("since start"), "{what}: {}", c.detail);
        }
        // The controller's own copy missing or wrong: never warm-up.
        let (n, good) = door_warmup_case(now, Some(fresh.clone()));
        for leaf in [
            Box::new(|s: &str| if s == "vllm" { crate::commands::node_leaves::LeafState::Missing } else { good(s) }) as Box<dyn Fn(&str) -> crate::commands::node_leaves::LeafState>,
            Box::new(|s: &str| if s == "vllm" { door_leaf(&["noo-vllm"], now + 3 * 86_400) } else { good(s) }),
        ] {
            assert_eq!(backend_doors_check(&n, &*leaf, now).verdict, Verdict::Fail);
        }
    }

    /// The one refusal warm-up may explain is the agent's "no leaf yet"
    /// text, pinned against the agent's source; its "leaf does not name the
    /// door" text must not match it.
    #[test]
    fn the_no_leaf_yet_refusal_matches_the_agents_text_and_nothing_else() {
        let src = include_str!("../../../node-agent-go/internal/docker/backends.go");
        let body = src.split("func backendDoorCheck(").nth(1).expect("backendDoorCheck").split("\nfunc ").next().unwrap();
        let reasons: Vec<&str> = body.split("refuse(").skip(1).collect();
        let matching: Vec<&&str> = reasons.iter().filter(|r| r.contains(warmup::NO_LEAF_YET_REFUSAL)).collect();
        assert_eq!(matching.len(), 1, "exactly the missing-leaf refusal: {matching:?}");
        assert!(matching[0].contains("leaf (\" + f"), "{}", matching[0]);
    }

    /// host8 on 2026-09-23: hostd not alive, harness absent, agent on the
    /// controller's tag. hostd is a failure; the harness is NOT — the
    /// controller's own node runs turns in process and gets no unit.
    #[test]
    fn the_controller_node_as_found_fails_hostd_and_its_harness_is_in_process() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["id"] = "host8".into();
        n["self_node"] = true.into();
        n["hostd"] = serde_json::json!({ "alive": false, "detail": "no hostd heartbeat at /var/lib/noo-node-agent/spool" });
        n["host_services"]["harness"]["state"] = "absent".into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&c, "hostd"), Verdict::Fail);
        assert_eq!(verdict(&c, "harness"), Verdict::Ok);
        assert!(c.iter().find(|c| c.name == "harness").unwrap().detail.contains("in process"));
        assert_eq!(verdict(&c, "version"), Verdict::Ok);
    }

    /// An ordinary node whose harness the gateway WANTS but which is absent
    /// is still the failure it always was, with the remedy naming the node.
    /// "Wanted" used to be implicit in `policy auto` — which is exactly what
    /// failed the embedder-only nodes; see an_embedder_only_node_passes_…
    #[test]
    fn an_ordinary_node_with_an_absent_harness_under_auto_fails() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["id"] = "host2".into();
        n["host_services"]["harness"]["state"] = "absent".into();
        n["harness_wanted"] = true.into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&c, "harness"), Verdict::Fail);
        let h = c.iter().find(|c| c.name == "harness").unwrap();
        assert!(h.remedy.as_deref().unwrap().contains("host2"), "the remedy names the node");
    }

    /// The live defect: `/api/cluster/nodes` did not carry `harness_policy`,
    /// and this check resolved the absence to its own `"manual"` default — so
    /// it printed a green `policy manual` for all five nodes of a fleet whose
    /// declared policies it had never read. The fixture above HAD the field,
    /// which is why the tests were happy and the fleet report was not true.
    #[test]
    fn an_unreported_harness_policy_is_not_manual() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n.as_object_mut().unwrap().remove("harness_policy");
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let h = c.iter().find(|c| c.name == "harness").unwrap();
        assert_eq!(h.verdict, Verdict::Warn, "an unread input cannot pass itself");
        assert!(h.detail.contains("not reported"), "and it says so: {}", h.detail);
        // The old behaviour, spelled out so a reintroduction is loud: a
        // running harness under an ABSENT policy must not read as fine.
        assert_ne!(h.verdict, Verdict::Ok);
    }

    /// And the gateway must actually send it, or the check above only ever
    /// warns. This is the seam the fixture hid.
    #[test]
    fn the_nodes_list_route_stamps_the_policy_it_is_judged_on() {
        let src = include_str!("../../../gateway-rust/src/routes/cluster.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert!(
            code.contains("data[\"harness_policy\"]"),
            "collect_cluster_nodes must stamp harness_policy onto every record"
        );
    }

    /// host2 and host9 as found on 2026-09-28: policy auto, harness stopped,
    /// serving only an embedder. `auto` places a harness only beside a chat
    /// backend, so this is the policy working — not a failure.
    #[test]
    fn an_embedder_only_node_passes_with_its_harness_stopped() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["host_services"]["harness"]["state"] = "stopped".into();
        n["harness_wanted"] = false.into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let h = c.iter().find(|c| c.name == "harness").unwrap();
        assert_eq!(h.verdict, Verdict::Ok, "{}", h.detail);
        assert!(h.detail.contains("no chat backend"), "{}", h.detail);
    }

    /// When the gateway DID place a harness here and it isn't running, that
    /// is still a failure, and the remedy points at why it stopped.
    #[test]
    fn a_wanted_harness_that_is_stopped_still_fails() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["host_services"]["harness"]["state"] = "stopped".into();
        n["harness_wanted"] = true.into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let h = c.iter().find(|c| c.name == "harness").unwrap();
        assert_eq!(h.verdict, Verdict::Fail);
        assert!(h.remedy.as_deref().unwrap().contains("logs"), "{:?}", h.remedy);
    }

    /// No answer from the gateway is not a pass and not a failure: it says
    /// it could not tell. (The old behaviour failed here unconditionally.)
    #[test]
    fn an_unknown_want_warns_rather_than_guessing() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["host_services"]["harness"]["state"] = "stopped".into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(c.iter().find(|c| c.name == "harness").unwrap().verdict, Verdict::Warn);
    }

    /// The gateway's answer, read from a desired-config body shaped like the
    /// real one — including the synthesized harness apply_harness_policy adds.
    #[test]
    fn the_want_is_read_from_the_policy_applied_placements() {
        let embed_only = serde_json::json!({"placements": [
            {"backend": "ollama", "model": "harrier", "role": "embed", "desired_state": "running"}]});
        assert_eq!(harness_wanted_in(&embed_only), Some(false));
        let with_chat = serde_json::json!({"placements": [
            {"backend": "vllm", "model": "gemma", "role": "chat", "desired_state": "running"},
            {"backend": "harness", "model": "auto", "role": "harness", "desired_state": "running", "synthesized": true}]});
        assert_eq!(harness_wanted_in(&with_chat), Some(true));
        let off = serde_json::json!({"placements": [
            {"backend": "harness", "model": "auto", "desired_state": "stopped", "synthesized": true}]});
        assert_eq!(harness_wanted_in(&off), Some(false));
        assert_eq!(harness_wanted_in(&serde_json::json!({})), None, "no placements field is unknown, not false");
    }

    #[test]
    fn a_node_behind_the_controllers_release_fails_version_with_the_upgrade_verb() {
        let now = 1_800_000_000;
        let c = node_checks(&healthy(now), "v0.2.72", "0.5.57", now, Some(true));
        let v = c.iter().find(|c| c.name == "version").unwrap();
        assert_eq!(v.verdict, Verdict::Fail);
        assert_eq!(v.remedy.as_deref(), Some("noo cluster provision host3 --wait"));
    }

    /// host6: a Mac node runs the agent out of the CLI binary, so its
    /// version is a CLI version — judged against this CLI, and only warned.
    #[test]
    fn a_host_agent_is_judged_against_the_cli_not_the_stack_tag() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["app_version"] = "noo-cli-v0.5.56+fa0711d".into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&c, "version"), Verdict::Warn);
        let c = node_checks(&n, "v0.2.70", "0.5.56", now, Some(true));
        assert_eq!(verdict(&c, "version"), Verdict::Ok);
    }

    #[test]
    fn a_stale_heartbeat_fails_even_when_status_says_online() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["last_heartbeat"] = stamp(now - 900).into();
        assert_eq!(verdict(&node_checks(&n, "v0.2.70", "0.5.57", now, Some(true)), "online"), Verdict::Fail);
    }

    #[test]
    fn the_nats_principals_row_fails_on_a_legacy_users_conf_or_a_stale_bridge() {
        use crate::commands::nats_users::{render_users_conf, Principal, Role};
        let clean = render_users_conf(&[
            Principal { user: "gateway".into(), hash: "$2b$11$g".into(), role: Role::Gateway },
            Principal { user: "node-host3".into(), hash: "$2b$11$a".into(), role: Role::Node },
        ]);
        let c = nats_principals_check(Some(&clean), &[], &[]);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.starts_with("2 per-principal"), "{}", c.detail);

        let legacy = format!("{clean}      {{\n        user: $NATS_USER\n        password: $NATS_PASSWORD\n      }}\n");
        let c = nats_principals_check(Some(&legacy), &[], &[]);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("$NATS_USER, $NATS_PASSWORD"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").starts_with("noo cluster nats-users render"), "{:?}", c.remedy);

        // The bridge, anywhere: .env or a posture DB row the gateway now
        // lists under `retired`. ON is a FAIL; a stale closed value a WARN.
        let posture = serde_json::json!({"posture": [], "retired": [{"key": RETIRED_NATS_BRIDGE, "value": "1"}]});
        let sites = retired_bridge_sites(Some("0"), &posture);
        assert_eq!(sites.len(), 2, "{sites:?}");
        let c = nats_principals_check(Some(&clean), &sites, &[]);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("the posture DB (=1)") && !c.detail.contains(".env"), "{}", c.detail);
        // Every remedy is a `noo` verb, never SQL (2026-10-02: the WARN's
        // remedy was `docker exec noo-postgres psql … DELETE`).
        let r = c.remedy.clone().unwrap_or_default();
        assert!(r.starts_with("noo security posture set NOO_NATS_LEGACY_SHARED_CREDS 0") && !r.contains("psql"), "{r}");
        let c = nats_principals_check(Some(&clean), &retired_bridge_sites(Some("0"), &serde_json::json!({})), &[]);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains(".env (=0)"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("remove the NOO_NATS_LEGACY_SHARED_CREDS line from .env"));
        // host8: a closed row in the DB only — the gateway deletes it at boot.
        let db_closed = serde_json::json!({"posture": [], "retired": [{"key": RETIRED_NATS_BRIDGE, "value": "0"}]});
        let c = nats_principals_check(Some(&clean), &retired_bridge_sites(None, &db_closed), &[]);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        let r = c.remedy.unwrap_or_default();
        assert!(r.starts_with("noo stack restart gateway") && !r.contains("psql"), "{r}");
        assert!(retired_bridge_sites(None, &serde_json::json!({"posture": []})).is_empty());
        assert!(retired_bridge_sites(Some("  "), &serde_json::json!({"retired": [{"key": "OTHER", "value": "1"}]})).is_empty());
        assert_eq!(nats_principals_check(None, &[], &[]).verdict, Verdict::Warn);
    }

    /// i70 residue: the row counts and names the add-on principals, warns on
    /// the one-release fallback and fails on a principal nothing presents.
    #[test]
    fn the_nats_principals_row_names_each_addon_principal() {
        use crate::commands::nats_users::{render_users_conf, Principal, Role};
        let p = |u: &str, r: Role| Principal { user: u.into(), hash: "$2b$11$x".into(), role: r };
        let both = render_users_conf(&[
            p("gateway", Role::Gateway), p("worker", Role::Worker), p("trellion", Role::Addon),
            p("trellion_intel", Role::Addon), p("node-host3", Role::Node),
        ]);
        let c = nats_principals_check(Some(&both), &[], &["trellion", "trellion_intel"]);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.starts_with("5 per-principal user(s) (gateway, worker, trellion, trellion_intel, 1 node(s))"), "{}", c.detail);
        assert!(c.detail.ends_with("add-on subjects off the worker's grant: trellion, trellion_intel"), "{}", c.detail);

        // Declared but not rendered: the fallback, a WARN naming the render.
        let only_t = render_users_conf(&[p("gateway", Role::Gateway), p("worker", Role::Worker), p("trellion", Role::Addon)]);
        let c = nats_principals_check(Some(&only_t), &[], &["trellion", "trellion_intel"]);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("trellion_intel present(s) the WORKER principal"), "{}", c.detail);
        assert!(c.remedy.unwrap_or_default().starts_with("noo cluster nats-users render"));

        // Rendered but undeclared: nothing serves its subjects.
        let c = nats_principals_check(Some(&both), &[], &["trellion"]);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("renders trellion_intel"), "{}", c.detail);
    }

    #[test]
    fn the_fleet_fallback_credential_fails_the_bus_check() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["nats_role"] = "shared".into();
        assert_eq!(verdict(&node_checks(&n, "v0.2.70", "0.5.57", now, Some(true)), "bus"), Verdict::Fail);
    }

    #[test]
    fn a_cert_inside_the_roll_window_fails_and_an_unadopted_signing_key_fails() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["cert_not_after"] = (now + 3 * 86_400).into();
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(false));
        assert_eq!(verdict(&c, "cert"), Verdict::Fail);
        assert_eq!(verdict(&c, "signing"), Verdict::Fail);
    }

    /// Right after `provision --wait`: the restarted agent's one heartbeat
    /// so far hasn't carried expiry/hostd facts yet. No remedy, and NOT the
    /// "(older agent)" wording — `noo cluster provision <node> --wait` would be wrong
    /// here (2026-09-28 rehearsal).
    #[test]
    fn missing_facts_read_as_not_yet_reported_right_after_a_recent_heartbeat() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["last_heartbeat"] = stamp(now - 20).into();
        n.as_object_mut().unwrap().remove("cert_not_after");
        n.as_object_mut().unwrap().remove("hostd");
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let cert = c.iter().find(|c| c.name == "cert").unwrap();
        assert_eq!(cert.verdict, Verdict::Warn);
        assert_eq!(cert.detail, "expiry not reported yet — re-run after the next heartbeat");
        assert_eq!(cert.remedy, None);
        let hostd = c.iter().find(|c| c.name == "hostd").unwrap();
        assert_eq!(hostd.verdict, Verdict::Warn);
        assert_eq!(hostd.detail, "not reported yet — re-run after the next heartbeat");
        assert_eq!(hostd.remedy, None);
    }

    /// No heartbeat at all yet (freshly provisioned, before its first
    /// beat lands) — the same gentle wording, not "older agent".
    #[test]
    fn missing_facts_read_as_not_yet_reported_with_no_heartbeat_at_all() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n.as_object_mut().unwrap().remove("last_heartbeat");
        n.as_object_mut().unwrap().remove("cert_not_after");
        n.as_object_mut().unwrap().remove("hostd");
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&c, "cert"), Verdict::Warn);
        assert!(c.iter().find(|c| c.name == "cert").unwrap().detail.contains("not reported yet"));
        assert!(c.iter().find(|c| c.name == "hostd").unwrap().detail.contains("not reported yet"));
    }

    /// A node that has been beating for a while and STILL doesn't report
    /// these fields is a genuinely old agent — keep the old wording and
    /// the `noo cluster provision <node> --wait` remedy.
    #[test]
    fn missing_facts_stay_older_agent_when_the_heartbeat_is_stale() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["last_heartbeat"] = stamp(now - 300).into();
        n.as_object_mut().unwrap().remove("cert_not_after");
        n.as_object_mut().unwrap().remove("hostd");
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let cert = c.iter().find(|c| c.name == "cert").unwrap();
        assert_eq!(cert.detail, "expiry not reported (older agent)");
        assert_eq!(cert.remedy.as_deref(), Some("noo cluster provision host3 --wait"));
        let hostd = c.iter().find(|c| c.name == "hostd").unwrap();
        assert_eq!(hostd.detail, "not reported (older agent)");
        assert_eq!(hostd.remedy.as_deref(), Some("noo cluster provision host3 --wait"));
    }

    #[test]
    fn version_tags_parse_both_shapes() {
        assert_eq!(agent_version_tag("stack-v0.2.70+abc"), Some((true, "v0.2.70".into())));
        assert_eq!(agent_version_tag("noo-cli-v0.5.56+fa0711d"), Some((false, "v0.5.56".into())));
        assert_eq!(agent_version_tag("garbage"), None);
    }

    #[test]
    fn the_required_keys_are_the_registrys_and_follow_the_addon_map() {
        let consumers = |on: &dyn Fn(&str) -> bool| -> Vec<String> {
            let mut v: Vec<String> = required_service_keys(on).into_iter().map(|(_, c)| c).collect();
            v.sort();
            v
        };
        assert_eq!(consumers(&|n: &str| matches!(n, "trellion" | "trellion_intel" | "evolve")),
            vec!["svc:evolve", "svc:trellion", "svc:trellion-intel", "svc:worker"],
            "every add-on that is on and has a registry key is required");
        assert_eq!(consumers(&|n: &str| matches!(n, "trellion" | "trellion_intel")),
            vec!["svc:trellion", "svc:trellion-intel", "svc:worker"],
            "evolve off: its key is not required");
        assert_eq!(consumers(&|_: &str| false), vec!["svc:worker"], "worker is not an add-on: always required");
    }

    /// the earlier shape after an upgrade: a key minted before its
    /// overlay asked for `metrics` keeps working for what it has and is
    /// refused for the new word. Verify names the missing word and the verb.
    #[test]
    fn a_key_minted_before_its_declaration_widened_warns_with_the_fix() {
        let required = required_service_keys(&|n: &str| matches!(n, "trellion" | "evolve"));
        let evolve_full: Vec<String> = crate::commands::secrets::provisioned_scopes("svc:evolve", &[]);
        let keys = serde_json::json!({ "keys": [
            // superseded row with the wide grant must not mask the live one
            { "consumer": "svc:trellion", "active": true, "superseded_at": "2026-09-01T00:00:00Z",
              "scopes": ["addon", "chat", "embeddings", "metrics"] },
            { "consumer": "svc:trellion", "active": true, "superseded_at": null,
              "scopes": ["addon", "chat", "embeddings"] },
            { "consumer": "svc:evolve", "active": true, "superseded_at": null, "scopes": evolve_full },
        ]});
        let c = service_key_grants_check(&keys, &required);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("trellion lacks metrics"), "{}", c.detail);
        assert!(!c.detail.contains("evolve"), "evolve holds its whole grant: {}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo security service-key provision trellion"));

        let fixed = serde_json::json!({ "keys": [
            { "consumer": "svc:trellion", "active": true, "superseded_at": null,
              "scopes": ["addon", "chat", "embeddings", "metrics"] },
        ]});
        assert_eq!(service_key_grants_check(&fixed, &required).verdict, Verdict::Ok,
            "a consumer with no key is the `service keys` row's business, not this one's");
    }

    /// During the `video_memory` -> `recall_memory` rename the
    /// two `config:` scopes are one grant. An evolve key minted with the old
    /// word is not short when its declaration asks for the new one, and the
    /// reverse; a key with neither still is.
    #[test]
    fn a_renamed_config_scope_is_satisfied_by_either_spelling() {
        let required = vec![("evolve".to_string(), "svc:evolve".to_string())];
        let declared: Vec<String> = crate::commands::secrets::provisioned_scopes("svc:evolve", &[]);
        let swap = |from: &str, to: &str| -> Vec<String> {
            declared.iter().map(|s| if s == from { to.to_string() } else { s.clone() }).collect()
        };
        let (old, new) = ("config:video_memory", "config:recall_memory");
        let asks_old = declared.iter().any(|s| s == old);
        let asks_new = declared.iter().any(|s| s == new);
        assert!(asks_old || asks_new, "evolve declares a recall-memory config scope: {declared:?}");
        let held = if asks_old { swap(old, new) } else { swap(new, old) };
        let keys = |scopes: Vec<String>| serde_json::json!({ "keys": [
            { "consumer": "svc:evolve", "active": true, "superseded_at": null, "scopes": scopes } ] });
        let c = service_key_grants_check(&keys(held), &required);
        assert_eq!(c.verdict, Verdict::Ok, "either spelling satisfies the declaration: {c:?}");
        let neither: Vec<String> = declared.iter().filter(|s| *s != old && *s != new).cloned().collect();
        let c = service_key_grants_check(&keys(neither), &required);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(crate::commands::secrets::scope_held(&[old.to_string()], new));
        assert!(crate::commands::secrets::scope_held(&[new.to_string()], old));
        assert!(!crate::commands::secrets::scope_held(&["config:memory".to_string()], new));
    }

    #[test]
    fn required_keys_come_from_the_declarations_by_their_provision_names() {
        let names: Vec<String> = required_service_keys(&|_: &str| true).into_iter().map(|(n, _)| n).collect();
        for n in ["worker", "trellion", "trellion-intel", "evolve"] {
            assert!(names.contains(&n.to_string()), "{n} missing from {names:?}");
            assert!(crate::commands::secrets::provision_targets(n).is_some(), "{n} does not resolve");
        }
    }

    /// The controller on 2026-09-23: trellion and worker unprovisioned, a
    /// storm in strangers, the tailnet drifted. Three failures, each with
    /// the verb that fixes it.
    #[test]
    fn the_controller_as_found_fails_keys_callers_and_tailnet() {
        // `posture list --json` as the controller printed it on 2026-09-24.
        let posture = serde_json::json!({ "count": 2, "posture": [
            { "key": "NOO_EXEC_APPROVAL_MODE", "running": "approval", "db_value": "approval", "pending_restart": false, "source": "db" },
            { "key": "NOO_SELF_CALL_SHARED_SECRET", "running": null, "db_value": null, "pending_restart": false, "source": "env" },
        ]});
        let keys = serde_json::json!({ "count": 2, "keys": [
            { "consumer": "svc:trellion-intel", "active": true },
            { "consumer": "svc:trellion-intel", "active": false },
        ]});
        let required = required_service_keys(&|n: &str| matches!(n, "trellion" | "trellion_intel"));
        let secrets = serde_json::json!({ "summary": "12 secret(s) checked; every holder agrees" });
        let exposure = serde_json::json!({ "status": "any_interface", "published": [
            { "container": "noo-gateway", "host_port": 8080, "reach": "any-interface" }
        ]});
        let strangers = serde_json::json!({ "status": "storm" });
        let c = controller_checks(&posture, &keys, &required, (0, &secrets), &exposure, &strangers, Some(0), Some(vec!["grant tag:worker → tag:controller:8443".into()]), Some(Ok(())));
        assert_eq!(verdict(&c, "posture"), Verdict::Ok, "{:?}", c.iter().find(|c| c.name == "posture"));
        let k = c.iter().find(|c| c.name == "service keys").unwrap();
        assert_eq!(k.verdict, Verdict::Fail);
        assert!(k.detail.contains("worker") && k.detail.contains("trellion"), "{}", k.detail);
        assert_eq!(verdict(&c, "callers"), Verdict::Fail);
        assert_eq!(verdict(&c, "tailnet policy"), Verdict::Fail);
        assert_eq!(verdict(&c, "exposure"), Verdict::Warn, "an open door is a decision, not a failure");
        assert_eq!(verdict(&c, "secrets"), Verdict::Ok);
    }

    /// The row reads the ADDITIVE merge plan. An operator's own rules beyond
    /// the declaration are not drift (they failed the row forever, and its
    /// remedy said `--push`, which deletes them); only what the declaration
    /// needs and the live policy lacks fails it, and the remedy is `--merge`.
    #[test]
    fn the_tailnet_row_judges_what_is_missing_and_never_suggests_a_push() {
        let nothing = serde_json::json!({ "tags_added": [], "owners_added": [], "acls_added": [], "applied": false });
        assert_eq!(tailnet_merge_missing(&nothing), Some(vec![]));
        let lacking = serde_json::json!({ "tags_added": ["tag:kiosk"], "owners_added": [["tag:worker", "autogroup:admin"]],
            "acls_added": ["tag:worker → tag:controller:8443"], "applied": false });
        let m = tailnet_merge_missing(&lacking).unwrap();
        assert_eq!(m, vec!["tag tag:kiosk", "owner autogroup:admin of tag:worker", "grant tag:worker → tag:controller:8443"]);
        assert_eq!(tailnet_merge_missing(&Value::Null), None, "unread is not drift");
        // The old shape (`policy` without --merge) is unread, not "in sync".
        assert_eq!(tailnet_merge_missing(&serde_json::json!({"in_sync": false})), None);

        let row = |missing: Option<Vec<String>>| {
            let c = controller_checks(&serde_json::json!({"posture": []}), &serde_json::json!({"keys": []}), &[],
                (0, &Value::Null), &Value::Null, &Value::Null, None, missing, None);
            c.into_iter().find(|c| c.name == "tailnet policy").unwrap()
        };
        assert_eq!(row(Some(vec![])).verdict, Verdict::Ok);
        let f = row(Some(m));
        assert_eq!(f.verdict, Verdict::Fail);
        assert!(f.detail.contains("tag:kiosk"), "{}", f.detail);
        for c in [&f, &row(None), &row(Some(vec![]))] {
            let r = c.remedy.as_deref().unwrap_or("");
            assert!(!r.contains("--push"), "the row suggests a wholesale push: {r}");
        }
        assert!(f.remedy.as_deref().unwrap().starts_with("noo security tailnet policy --merge"));
    }

    #[test]
    fn the_addon_pins_row() {
        let good = serde_json::json!({"stack": "v0.6.0", "verified": 2, "failed": 0, "addons": [
            {"addon": "trellion_intel", "ok": true, "key_index": 0}, {"addon": "evolve", "ok": true, "key_index": 0}]});
        let c = addon_pins_check(0, &good);
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert_eq!(c.detail, "2 verified for v0.6.0 (key #0)");
        let bad = serde_json::json!({"stack": "v0.6.0", "addons": [
            {"addon": "evolve", "ok": false, "problem": "evolve has no pin in addons.lock"}]});
        let c = addon_pins_check(1, &bad);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("evolve has no pin"), "{c:?}");
        assert_eq!(c.remedy.as_deref(), Some("noo addons upgrade"));
        assert_eq!(addon_pins_check(1, &Value::Null).verdict, Verdict::Warn);
    }

    /// host8, 2026-10-02: the licence sat in plaintext `.env` (tidy had
    /// moved it), `show` reads the store, and the row said "no valid
    /// entitlement" of a token valid to 2027. Not installed, invalid, and
    /// outside the store are three different statements.
    #[test]
    fn the_entitlement_row_tells_outside_the_store_from_invalid() {
        let not_installed = serde_json::json!({"installed": false});
        let (why, remedy) = entitlement_verdict(1, &not_installed, true).unwrap_err();
        assert!(why.contains("plaintext .env") && !why.contains("not valid"), "{why}");
        assert_eq!(remedy, crate::commands::plaintext_env::REMEDY_ONBOARD);
        let (why, remedy) = entitlement_verdict(1, &not_installed, false).unwrap_err();
        assert!(why.contains("no entitlement installed"), "{why}");
        assert!(remedy.contains("entitlement install"));
        let invalid = serde_json::json!({"entitlement": {"sub": "x"}, "verdict": "INVALID — entitlement for 'x' expired"});
        let (why, _) = entitlement_verdict(1, &invalid, false).unwrap_err();
        assert!(why.contains("expired"), "{why}");
        let valid = serde_json::json!({"entitlement": {"sub": "x"}, "verdict": "valid (features above are what it unlocks)"});
        assert_eq!(entitlement_verdict(0, &valid, true), Ok(()));
    }

    #[test]
    fn a_tailnet_bind_that_a_reboot_can_break_fails_exposure() {
        let exposure = serde_json::json!({ "status": "confined", "boot_safe": false, "ip_nonlocal_bind": false });
        let c = controller_checks(&serde_json::json!({"posture": [{"key": "K", "running": "1", "db_value": "1"}]}),
            &serde_json::json!({"keys": []}), &[], (0, &Value::Null), &exposure, &Value::Null, None, None, None);
        let e = c.iter().find(|c| c.name == "exposure").unwrap();
        assert_eq!(e.verdict, Verdict::Fail);
        assert!(e.remedy.as_deref().unwrap().contains("ip_nonlocal_bind=1"));
        let safe = serde_json::json!({ "status": "confined", "boot_safe": true });
        let c = controller_checks(&serde_json::json!({"posture": [{"key": "K", "running": "1", "db_value": "1"}]}),
            &serde_json::json!({"keys": []}), &[], (0, &Value::Null), &safe, &Value::Null, None, None, None);
        assert_eq!(verdict(&c, "exposure"), Verdict::Ok);
    }

    /// The privileged flag is judged on the CONTAINER, not the gateway's env.
    #[test]
    fn node_agent_privilege_is_read_from_the_container() {
        let gate = |actual: serde_json::Value, db: &str| serde_json::json!({"posture": [
            {"key": "NOO_NODE_AGENT_PRIVILEGED", "running": db, "db_value": db, "actual": actual}]});
        let v = |p: &serde_json::Value| node_agent_privilege_check(p).map(|c| c.verdict);
        // The bug: posture says false, the gateway's env says false, the container is privileged.
        assert_eq!(v(&gate(serde_json::json!("true"), "false")), Some(Verdict::Fail));
        assert_eq!(v(&gate(serde_json::json!("false"), "false")), Some(Verdict::Ok));
        assert_eq!(v(&gate(serde_json::json!("true"), "true")), Some(Verdict::Warn));
        // Could not inspect: warned as not checked, never ok.
        let unseen = serde_json::json!({"posture": [{"key": "NOO_NODE_AGENT_PRIVILEGED", "db_value": "false", "actual_error": "docker is not runnable"}]});
        let c = node_agent_privilege_check(&unseen).unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.starts_with("not checked"), "{}", c.detail);
        // An older CLI's listing has no container fact: no row, not a green one.
        assert!(v(&serde_json::json!({"posture": [{"key": "NOO_NODE_AGENT_PRIVILEGED", "db_value": "false"}]})).is_none());
        assert!(v(&serde_json::json!({"posture": []})).is_none());
    }

    #[test]
    fn the_audit_key_row_answers_locally() {
        assert_eq!(audit_key_check(true, None).verdict, Verdict::Ok);
        let f = audit_key_check(false, None);
        assert_eq!(f.verdict, Verdict::Fail);
        assert!(f.remedy.unwrap().contains("noo upgrade --stack"));
        // An unreadable store cannot say the key is missing OR present.
        assert_eq!(audit_key_check(false, Some("sops not found")).verdict, Verdict::Warn);
    }

    #[test]
    fn a_posture_gate_off_desired_fails() {
        let posture = serde_json::json!({ "posture": [
            { "key": "NOO_EXEC_APPROVAL_MODE", "running": "strict", "db_value": "approval", "pending_restart": true },
        ]});
        let c = controller_checks(&posture, &serde_json::json!({"keys": []}), &[], (0, &Value::Null), &Value::Null, &Value::Null, None, None, None);
        let p = c.iter().find(|c| c.name == "posture").unwrap();
        assert_eq!(p.verdict, Verdict::Fail);
        assert!(p.detail.contains("NOO_EXEC_APPROVAL_MODE"));
    }

    /// /metrics is no longer public, so a controller the
    /// scraper cannot authenticate to shows empty dashboards. Say which half
    /// is missing; never fail a controller that may run no Prometheus.
    #[test]
    fn the_metrics_scrape_row_names_the_missing_half() {
        assert_eq!(metrics_scrape_check(Some(true), &[]).verdict, Verdict::Ok);
        let no_mtls = metrics_scrape_check(Some(false), &[]);
        assert_eq!(no_mtls.verdict, Verdict::Warn);
        assert!(no_mtls.remedy.unwrap().contains("NOO_MTLS_GATEWAY=false"));
        let no_leaf = metrics_scrape_check(Some(true), &["alertmanager"]);
        assert_eq!(no_leaf.verdict, Verdict::Warn);
        assert!(no_leaf.remedy.unwrap().contains("issue-service alertmanager"));
        assert_eq!(metrics_scrape_check(None, &[]).verdict, Verdict::Warn);
    }

    /// Enforcement is the default: only an explicit off in `.env` is off.
    #[test]
    fn mtls_is_on_unless_the_dotenv_says_off() {
        for on in ["", "FOO=1\n", "NOO_MTLS_GATEWAY=\n", "NOO_MTLS_GATEWAY=true\n", "NOO_MTLS_GATEWAY=maybe\n",
                   "NOO_MTLS_GATEWAY=false\nNOO_MTLS_GATEWAY=true\n"] {
            assert!(mtls_on_in_dotenv(on), "{on:?}");
        }
        for off in ["NOO_MTLS_GATEWAY=false\n", "NOO_MTLS_GATEWAY=\"off\"\n", "NOO_MTLS_GATEWAY=0", "A=1\n NOO_MTLS_GATEWAY=No\n"] {
            assert!(!mtls_on_in_dotenv(off), "{off:?}");
        }
        let w = metrics_scrape_check(Some(false), &[]);
        assert!(w.remedy.unwrap().contains("remove NOO_MTLS_GATEWAY=false from .env and recreate the gateway"));
    }

    /// Every leaf this row checks is one onboard issues — otherwise the row
    /// would send a fresh install to hand-issue what onboard forgot.
    #[test]
    fn every_monitoring_leaf_is_issued_by_onboard() {
        for leaf in MONITORING_LEAVES.iter().chain(DATA_PLANE_LEAVES) {
            assert!(crate::onboard::steps::SVC_LIST.contains(leaf), "{leaf} is not in onboard's SVC_LIST");
        }
        // The data plane is dialled from other hosts by the controller's
        // names, so its leaf needs the SAN treatment nats/redis/postgres get.
        for leaf in DATA_PLANE_LEAVES {
            assert!(crate::onboard::steps::EXTERNALLY_REACHABLE.contains(leaf), "{leaf} is not EXTERNALLY_REACHABLE — nodes would fail hostname verification");
        }
    }

    /// PLANTED: a 0644 node key is a FAIL naming the file and `fix-modes`;
    /// a key owned by another uid is a FAIL carrying the `sudo chown` line;
    /// a uid-read key its container cannot read carries the sudo line; a
    /// leaf without a reader row names the table; a clean tree is OK.
    #[test]
    fn the_pki_key_modes_row_names_the_file_and_the_fix() {
        use crate::pki::{KeyIssue, KeyIssueKind, KeyReader};
        let exposed = KeyIssue { rel: "nodes/host3/node.key".into(), mode: 0o644, reader: KeyReader::Cli, kind: KeyIssueKind::Exposed };
        let c = pki_key_modes_check(std::slice::from_ref(&exposed), &[], 5);
        assert_eq!(c.verdict, Verdict::Fail, "a world-readable private key is a failure, not a warning");
        assert!(c.detail.contains("nodes/host3/node.key 0644"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo security pki fix-modes"), "{:?}", c.remedy);
        // Owned by another uid and unreadable here: only the sudo line helps.
        let foreign = KeyIssue { rel: "services/nats/service.key".into(), mode: 0o600, reader: KeyReader::ContainerRoot, kind: KeyIssueKind::WrongOwner };
        let chown = "sudo chown 1000:1000 /p/services/nats/service.key && sudo chmod 600 /p/services/nats/service.key".to_string();
        let c = pki_key_modes_check(std::slice::from_ref(&foreign), std::slice::from_ref(&chown), 5);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("services/nats/service.key 0600") && c.detail.contains("another uid"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some(chown.as_str()));
        let unreadable = KeyIssue { rel: "services/loki/service.key".into(), mode: 0o640, reader: KeyReader::ContainerUid(65532), kind: KeyIssueKind::Unreadable };
        let line = "sudo chgrp 65532 /p/services/loki/service.key && sudo chmod 640 /p/services/loki/service.key".to_string();
        let c = pki_key_modes_check(&[unreadable], std::slice::from_ref(&line), 5);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("services/loki/service.key"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some(line.as_str()));
        let unknown = KeyIssue { rel: "services/mystery/service.key".into(), mode: 0o644, reader: KeyReader::Unknown, kind: KeyIssueKind::UnknownReader };
        let c = pki_key_modes_check(&[unknown], &[], 5);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.remedy.unwrap().contains("SERVICE_KEY_READERS"));
        // Exposure outranks an unreadable key: the fix for both is the same verb,
        // and the sudo line rides along when the verb alone cannot finish it.
        let c = pki_key_modes_check(&[exposed, KeyIssue { rel: "x".into(), mode: 0o640, reader: KeyReader::ContainerUid(70), kind: KeyIssueKind::Unreadable }], std::slice::from_ref(&line), 5);
        assert!(c.detail.contains("beyond their reader"));
        let remedy = c.remedy.unwrap();
        assert!(remedy.starts_with("noo security pki fix-modes") && remedy.contains(&line), "{remedy}");
        let c = pki_key_modes_check(&[], &[], 19);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("19 private key(s)"));
    }

    /// The live host8 shape (checked with getfacl 2026-09-30): 0640,
    /// owner and group the operator's, and a named ACL entry for the key's
    /// declared reader under an `r--` mask — `user:65532:r--` (gateway,
    /// loki, …) or `user:70:r--` (postgres). The row must call it OK; the
    /// ACL is read through the same `extra_readers` fix-modes grants by.
    /// The negative: 0640 in group `docker`, no ACL — readable by the
    /// docker group, not by the reader — is a FAIL.
    #[test]
    fn the_pki_key_modes_row_reads_the_acl_grant() {
        use crate::pki::{classify_key_access, Access, KeyIssue, KeyReader};
        const OPERATOR_GID: u32 = 1000;
        const DOCKER_GID: u32 = 999;
        let row = |rel: &str, reader: KeyReader, acc: Access| {
            let issues: Vec<KeyIssue> = classify_key_access(reader, &acc)
                .map(|kind| KeyIssue { rel: rel.into(), mode: acc.mode, reader, kind })
                .into_iter()
                .collect();
            pki_key_modes_check(&issues, &[], 1)
        };
        let granted = |uid: u32| Access {
            mode: 0o640,
            gid: OPERATOR_GID,
            acl: Some(format!("user::rw-\nuser:{uid}:r--\ngroup::---\nmask::r--\nother::---\n")),
        };
        for (rel, uid) in [("gateway/gateway.key", 65532), ("sso/grafana.key", 65532), ("services/loki/service.key", 65532), ("services/postgres/service.key", 70)] {
            let c = row(rel, KeyReader::ContainerUid(uid), granted(uid));
            assert_eq!(c.verdict, Verdict::Ok, "{rel}: {}", c.detail);
        }
        // The grant names the WRONG uid: its reader cannot read it.
        let c = row("services/postgres/service.key", KeyReader::ContainerUid(70), granted(65532));
        assert_ne!(c.verdict, Verdict::Ok, "{}", c.detail);
        // Negative: 0640, group docker, no ACL at all.
        let docker = Access { mode: 0o640, gid: DOCKER_GID, acl: None };
        let c = row("services/loki/service.key", KeyReader::ContainerUid(65532), docker);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("services/loki/service.key 0640"), "{}", c.detail);
        // Same with getfacl present but only the base entries.
        let docker_acl = Access { mode: 0o640, gid: DOCKER_GID, acl: Some("user::rw-\ngroup::r--\nother::---\n".into()) };
        assert_eq!(row("services/loki/service.key", KeyReader::ContainerUid(65532), docker_acl).verdict, Verdict::Fail);
    }

    /// A remapping daemon is a FAIL naming the
    /// setting; no file, or the key absent or empty, is OK; unreadable or
    /// garbled is a WARN that says it could not tell.
    #[test]
    fn the_docker_userns_row_fails_a_remapping_daemon() {
        let c = docker_userns_check(Ok(Some(r#"{"data-root":"/data/docker","userns-remap":"default"}"#.into())));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("userns-remap=\"default\""), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("systemctl restart docker"));
        assert_eq!(docker_userns_check(Ok(None)).verdict, Verdict::Ok);
        assert_eq!(docker_userns_check(Ok(Some(r#"{"data-root":"/data/docker"}"#.into()))).verdict, Verdict::Ok);
        assert_eq!(docker_userns_check(Ok(Some(r#"{"userns-remap":""}"#.into()))).verdict, Verdict::Ok);
        assert_eq!(docker_userns_check(Ok(Some("{not json".into()))).verdict, Verdict::Warn);
        assert_eq!(docker_userns_check(Err("permission denied".into())).verdict, Verdict::Warn);
    }

    /// Each half of the SSO story that can be missing is
    /// named with its fix, and only the whole story is OK.
    #[test]
    fn the_grafana_sso_row_names_the_missing_half() {
        let none = grafana_sso_check(false, false, None, Some(true));
        assert_eq!(none.verdict, Verdict::Warn);
        assert!(none.detail.contains("grafana.key and sso/grafana.pub"), "{}", none.detail);
        assert!(none.remedy.unwrap().contains("issue-sso-key"));
        let no_pub = grafana_sso_check(true, false, Some(true), Some(true));
        assert!(no_pub.detail.contains("sso/grafana.pub") && !no_pub.detail.contains("grafana.key and"), "{}", no_pub.detail);
        let unreadable = grafana_sso_check(true, true, Some(false), Some(true));
        assert_eq!(unreadable.verdict, Verdict::Warn);
        assert!(unreadable.remedy.unwrap().contains("chgrp 65532"));
        let unmounted = grafana_sso_check(true, true, Some(true), Some(false));
        assert_eq!(unmounted.verdict, Verdict::Warn);
        assert!(unmounted.detail.contains("sso/grafana.pub"), "{}", unmounted.detail);
        assert_eq!(grafana_sso_check(true, true, Some(true), None).verdict, Verdict::Warn);
        assert_eq!(grafana_sso_check(true, true, Some(true), Some(true)).verdict, Verdict::Ok);
    }

    /// The shipped compose hands the gateway exactly the
    /// certificate-only set, and the row says OK for it; the PKI root, a
    /// second leaf, a planted key or a stale copy each WARN with the fix.
    #[test]
    fn the_gateway_pki_view_row() {
        let compose = include_str!("../../../docker-compose.cluster.yml");
        let mounts = gateway_pki_mounts(compose).expect("a gateway service");
        let mut sorted = mounts.clone();
        sorted.sort();
        let mut want: Vec<String> = GATEWAY_PKI_MOUNTS.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(sorted, want, "the shipped gateway mounts: {mounts:?}");
        let clean = crate::pki::PublicViewDrift { total: 7, ..Default::default() };
        let c = gateway_pki_view_check(Some(&mounts), &clean);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("7 certificate(s)"), "{}", c.detail);

        // The pre-1239 mount: the root.
        let old = "services:\n  gateway:\n    volumes:\n      - ${NOO_PKI_DIR:-./.pki-placeholder}:/app/pki:ro\n  worker:\n";
        let old_mounts = gateway_pki_mounts(old).unwrap();
        assert_eq!(old_mounts, vec![String::new()]);
        let c = gateway_pki_view_check(Some(&old_mounts), &clean);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("the whole PKI directory"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("noo upgrade --stack"));
        let extra = vec!["ca.crt".to_string(), "services/loki".to_string()];
        let c = gateway_pki_view_check(Some(&extra), &clean);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("services/loki"), "{}", c.detail);

        let keyed = crate::pki::PublicViewDrift { keys: vec!["services/loki/service.key".into()], ..Default::default() };
        let c = gateway_pki_view_check(Some(&mounts), &keyed);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("services/loki/service.key"), "{}", c.detail);
        let stale = crate::pki::PublicViewDrift { stale: vec!["nodes/host9/node.crt".into()], ..Default::default() };
        let c = gateway_pki_view_check(Some(&mounts), &stale);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("nodes/host9/node.crt") && c.remedy.unwrap().contains("fix-modes"), "{}", c.detail);
        assert_eq!(gateway_pki_view_check(None, &clean).verdict, Verdict::Warn);
    }

    /// The compose line the row looks for is the one this repo ships.
    #[test]
    fn the_shipped_compose_mounts_the_sso_public_key_into_grafana() {
        let compose = include_str!("../../../docker-compose.cluster.yml");
        let grafana = compose.split("\n  grafana:\n").nth(1).expect("a grafana service");
        let grafana = grafana.split("\n  node-exporter:\n").next().unwrap();
        let code: Vec<&str> = grafana.lines().map(|l| l.split('#').next().unwrap_or("").trim()).collect();
        assert!(code.iter().any(|l| l.contains("/sso/grafana.pub:/app/pki/sso/grafana.pub:ro")), "grafana must mount the SSO public half");
        assert!(!code.iter().any(|l| l.contains("sso/grafana.key") || l.ends_with("/sso:ro") || l.contains("/sso:/")), "grafana must never mount the private half or the sso/ directory");
    }

    /// The leaf is the invariant; a plaintext
    /// listener or port is a failure; a node that refused its URL is named
    /// Informational: labels ON is a WARN carrying the reason, never a FAIL.
    #[test]
    fn the_kiosk_labels_row_warns_when_names_are_on_and_never_fails() {
        use crate::commands::kiosk::LabelsState;
        let on = LabelsState { on: true, source: "db".into(), updated_by: Some("alice".into()), updated_at: Some("2026-10-09T12:00:00Z".into()) };
        let c = kiosk_labels_check(Some(&on));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("entity names are shown on the kiosk display"), "{}", c.detail);
        assert!(c.detail.contains("alice"), "who switched it on is part of the answer: {}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo kiosk labels off"));
        let off = LabelsState { on: false, source: "default".into(), updated_by: None, updated_at: None };
        assert_eq!(kiosk_labels_check(Some(&off)).verdict, Verdict::Ok);
        assert_eq!(kiosk_labels_check(None).verdict, Verdict::Warn);
        for s in [Some(&on), Some(&off), None] {
            assert_ne!(kiosk_labels_check(s).verdict, Verdict::Fail);
        }
    }

    #[test]
    fn the_cloud_gate_row_fails_a_stored_key_with_the_flag_off() {
        let off = cloud_gate_check(&["ANTHROPIC_API_KEY"], true, Some(false));
        assert_eq!(off.verdict, Verdict::Fail);
        assert!(off.detail.contains("CLOUD_PROVIDERS_ENABLED"), "{}", off.detail);
        assert!(off.remedy.unwrap().contains("Settings -> Features"));
        assert_eq!(cloud_gate_check(&["OPENAI_API_KEY"], true, Some(true)).verdict, Verdict::Ok);
        // No key: nothing to gate, whatever the flag. Failed reads are warnings, never "off".
        assert_eq!(cloud_gate_check(&[], true, None).verdict, Verdict::Ok);
        assert_eq!(cloud_gate_check(&["ANTHROPIC_API_KEY"], true, None).verdict, Verdict::Warn);
        assert_eq!(cloud_gate_check(&[], false, None).verdict, Verdict::Warn);
    }

    /// with the provision remedy. No version floor anywhere.
    #[test]
    fn the_model_cache_row_fails_on_any_plaintext_path() {
        let no_leaf = model_cache_check(false, Some(false), Some(false), &[]);
        assert_eq!(no_leaf.verdict, Verdict::Fail);
        assert!(no_leaf.remedy.unwrap().contains("issue-service model-cache"));

        let open = model_cache_check(true, Some(true), Some(false), &[]);
        assert_eq!(open.verdict, Verdict::Fail);
        assert!(open.detail.contains("plaintext listener"), "{}", open.detail);

        let published = model_cache_check(true, Some(false), Some(true), &[]);
        assert_eq!(published.verdict, Verdict::Fail);
        assert!(published.detail.contains("8083"), "{}", published.detail);

        let refusing = model_cache_check(true, Some(false), Some(false), &[
            ("host9".into(), "NOO_MODEL_CACHE_URL=\"http://host8:8083\" is plaintext".into()),
            ("host6".into(), "this node has no client certificate".into()),
        ]);
        assert_eq!(refusing.verdict, Verdict::Fail);
        assert!(refusing.detail.contains("host9 (NOO_MODEL_CACHE_URL=\"http://host8:8083\" is plaintext); host6"), "{}", refusing.detail);
        assert_eq!(refusing.remedy.as_deref().map(|r| r.starts_with("noo cluster provision host9")), Some(true));

        assert_eq!(model_cache_check(true, Some(false), Some(false), &[]).verdict, Verdict::Ok);
        // Unreadable is a warning, never a pass.
        assert_eq!(model_cache_check(true, None, Some(false), &[]).verdict, Verdict::Warn);
        assert_eq!(model_cache_check(true, Some(false), None, &[]).verdict, Verdict::Warn);
    }

    /// The refusal the agent records (preseed.RefusalScope) is read off the
    /// node record by scope, with its reason; other scopes are not it.
    #[test]
    fn the_model_cache_row_reads_the_agents_url_refusal() {
        let fleet = vec![
            serde_json::json!({"id": "host3", "reconcile_refusals": [
                {"scope": "backend_tls", "target": "vllm", "reason": "x"},
            ]}),
            serde_json::json!({"id": "host9", "reconcile_refusals": [
                {"scope": "model_cache_url", "target": "http://host8:8083", "reason": "NOO_MODEL_CACHE_URL=\"http://host8:8083\" is plaintext"},
            ]}),
            serde_json::json!({"id": "host6"}),
        ];
        assert_eq!(
            nodes_refusing_model_cache_url(&fleet),
            vec![("host9".to_string(), "NOO_MODEL_CACHE_URL=\"http://host8:8083\" is plaintext".to_string())]
        );
    }

    /// The shipped tree is what the row reads: no plain listener in the
    /// nginx conf, exactly the 8443 publish in compose — and a planted
    /// `ports:` line or `listen 8083;` is caught.
    #[test]
    fn the_shipped_model_cache_has_no_plaintext_path() {
        let conf = include_str!("../../../docker/model-cache.nginx.conf");
        assert!(!nginx_has_plain_listener(conf), "the shipped nginx conf carries a plaintext listener");
        assert!(conf.lines().any(|l| l.trim() == "listen 8443 ssl;"), "the mTLS listener is gone");
        let planted = format!("{conf}\nserver {{\n    listen 8083;\n    server_name _;\n}}\n");
        assert!(nginx_has_plain_listener(&planted), "a planted `listen 8083;` was not seen");
        // The loopback healthz listener is not a plaintext DATA listener.
        assert!(!nginx_has_plain_listener("server {\n    listen 127.0.0.1:8084;\n}\n"));
        // A comment does not count either way.
        assert!(!nginx_has_plain_listener("# listen 8083;\n"));

        let compose = include_str!("../../../docker-compose.cluster.yml");
        assert!(!compose_publishes_plain_model_cache(compose), "the shipped compose publishes a plaintext model-cache port");
        let tls_line = "${NOO_MODEL_CACHE_TLS_PORT:-8443}:8443\"\n";
        let (head, tail) = compose.split_once(tls_line).expect("the 8443 publish line");
        let planted = format!("{head}{tls_line}      - \"${{NOO_BIND_ADDR:-0.0.0.0}}:${{NOO_MODEL_CACHE_PORT:-8083}}:8083\"\n{tail}");
        assert!(compose_publishes_plain_model_cache(&planted), "a planted 8083 publish was not seen");
        let planted = format!("{head}{tls_line}      - \"8083:8083\"\n{tail}");
        assert!(compose_publishes_plain_model_cache(&planted), "a planted bare 8083 publish was not seen");
        // A commented-out line is not a publish.
        let commented = format!("{head}{tls_line}      # - \"8083:8083\"\n{tail}");
        assert!(!compose_publishes_plain_model_cache(&commented));
    }

    /// Fleet logging phase 0. The "not configured" arm is the one that
    /// matters: it is exactly the live defect (compose said LOKI_URL, the
    /// gateway reads NOO_LOKI_URL), and it must FAIL, not warn.
    #[test]
    fn the_loki_row_fails_on_not_configured_and_on_not_ready() {
        let unconfigured = serde_json::json!({"loki_url": "", "loki_configured": false, "loki_ready": false});
        let c = loki_check(Some(&unconfigured), true);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOO_LOKI_URL"), "{}", c.detail);
        let down = serde_json::json!({"loki_url": "https://loki:3100", "loki_configured": true, "loki_ready": false});
        let c = loki_check(Some(&down), true);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("https://loki:3100"), "{}", c.detail);
        // A gateway that names the miss: the row carries Loki's reason, not the guess.
        let named = serde_json::json!({"loki_url": "https://loki:3100", "loki_configured": true, "loki_ready": false,
            "loki_ready_detail": "answered 503: Ingester not ready: waiting for 15s after being ready"});
        let c = loki_check(Some(&named), true);
        assert!(c.detail.contains("/ready answered 503: Ingester not ready") && !c.detail.contains("leaf/CA"), "{}", c.detail);
        let up = serde_json::json!({"loki_url": "https://loki:3100", "loki_configured": true, "loki_ready": true});
        assert_eq!(loki_check(Some(&up), true).verdict, Verdict::Ok);
        let no_leaf = loki_check(Some(&up), false);
        assert_eq!(no_leaf.verdict, Verdict::Fail);
        assert!(no_leaf.remedy.unwrap().contains("issue-service loki"));
        assert_eq!(loki_check(None, true).verdict, Verdict::Warn);
    }

    const LOKI_TLS_CFG: &str = "server:\n  http_tls_config:\n    client_auth_type: RequireAndVerifyClientCert\n";
    const COMPOSE_OK: &str = "services:\n  gateway:\n    ports:\n      - \"8080:8080\"\n  loki:\n    image: x\n    # ports:\n    command: [\"-config.file=/etc/loki/tls-config.yaml\", \"-config.expand-env=true\"]\n  grafana:\n    ports:\n      - \"3000:3000\"\n";

    #[test]
    fn the_loki_listener_row_reads_the_shipped_config_and_compose() {
        assert_eq!(loki_listener_check(Some(LOKI_TLS_CFG), Some(COMPOSE_OK)).verdict, Verdict::Ok);
        let plain = "server:\n  http_listen_port: 3100\n";
        let c = loki_listener_check(Some(plain), Some(COMPOSE_OK));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("RequireAndVerifyClientCert"));
        let published = COMPOSE_OK.replace("    # ports:\n", "    ports:\n      - \"3100:3100\"\n");
        let c = loki_listener_check(Some(LOKI_TLS_CFG), Some(&published));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("publishes a host port"), "{}", c.detail);
        let plain_cmd = COMPOSE_OK.replace("tls-config.yaml", "local-config.yaml");
        assert_eq!(loki_listener_check(Some(LOKI_TLS_CFG), Some(&plain_cmd)).verdict, Verdict::Fail);
        assert_eq!(loki_listener_check(None, Some(COMPOSE_OK)).verdict, Verdict::Warn);
        // The block parser stops at the next service: grafana's ports are not loki's.
        assert!(compose_service_block(COMPOSE_OK, "loki").unwrap().contains("tls-config.yaml"));
        assert!(!compose_service_block(COMPOSE_OK, "loki").unwrap().contains("3000"));
    }

    const SANDBOX_COMPOSE_OK: &str = "services:\n  sandbox:\n    entrypoint: []\n    command: &sandbox-command\n      - python\n      - -m\n      - uvicorn\n      - noomesh.sandbox.app:app\n      - --port\n      - \"9000\"\n      - --ssl-certfile\n      - /tls/services/sandbox/service.crt\n      - --ssl-keyfile\n      - /tls/services/sandbox/service.key\n      - --ssl-ca-certs\n      - /tls/ca.crt\n      - --ssl-cert-reqs\n      - \"2\"\n    expose:\n      - \"9000\"\n  sandbox-extra:\n    command: *sandbox-command\n  postgres:\n    ports:\n      - \"5432:5432\"\n";

    fn sandbox_probe(no_cert: &str, leaf: &str, plain: &str) -> SandboxProbe {
        SandboxProbe { no_cert: no_cert.into(), leaf: leaf.into(), plain: plain.into() }
    }

    /// The sandbox row: OK only when compose requires a client certificate
    /// AND the live probe saw no-cert and plaintext refused and the
    /// gateway's leaf answered. Every other combination names its remedy.
    #[test]
    fn the_sandbox_listener_row_requires_a_client_cert_and_proves_it_live() {
        let good = sandbox_probe("refused: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED]", "answered HTTP/1.1 200 OK", "refused: closed without an answer");
        let c = sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), Some(&good));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, "client certificate required from every caller (none and plaintext refused, the gateway's leaf accepted); no published port");

        // Compose: optional (1) is not required (2); a plaintext command; a published port.
        let optional = SANDBOX_COMPOSE_OK.replace("      - \"2\"\n", "      - \"1\"\n");
        let c = sandbox_listener_check(Some(&optional), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("--ssl-cert-reqs 2"), "{}", c.detail);
        let inline_plain = "services:\n  sandbox:\n    command: [\"python\", \"-m\", \"uvicorn\", \"noomesh.sandbox.app:app\", \"--port\", \"9000\"]\n";
        assert_eq!(sandbox_listener_check(Some(inline_plain), Some(&good)).verdict, Verdict::Fail);
        let published = SANDBOX_COMPOSE_OK.replace("    expose:\n", "    ports:\n      - \"9000:9000\"\n    expose:\n");
        let c = sandbox_listener_check(Some(&published), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("publishes a host port"), "{}", c.detail);
        let extra_plain = SANDBOX_COMPOSE_OK.replace("    command: *sandbox-command\n", "    command: [\"python\", \"-m\", \"uvicorn\", \"x\"]\n");
        let c = sandbox_listener_check(Some(&extra_plain), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("sandbox-extra"), "{}", c.detail);

        // Live: no-cert answered, plaintext answered, leaf refused, sandbox down.
        let c = sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), Some(&sandbox_probe("answered HTTP/1.1 200 OK", "answered HTTP/1.1 200 OK", "refused: x")));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("WITHOUT a client certificate"));
        assert_eq!(c.remedy.as_deref(), Some("noo stack restart --force sandbox"));
        let c = sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), Some(&sandbox_probe("refused: x", "answered HTTP/1.1 200 OK", "answered HTTP/1.1 200 OK")));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("PLAINTEXT"));
        let c = sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), Some(&sandbox_probe("refused: x", "refused: [SSL: CERTIFICATE_VERIFY_FAILED]", "refused: y")));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.remedy.unwrap().contains("issue-service sandbox"));
        let c = sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), Some(&sandbox_probe("unreachable: [Errno -2]", "unreachable: [Errno -2]", "unreachable: [Errno -2]")));
        assert_eq!(c.verdict, Verdict::Fail, "a down sandbox must not read as a refusal");

        // Not probed / not readable: said, never passed.
        assert_eq!(sandbox_listener_check(Some(SANDBOX_COMPOSE_OK), None).verdict, Verdict::Warn);
        assert_eq!(sandbox_listener_check(None, Some(&good)).verdict, Verdict::Warn);
    }

    /// The shipped compose passes the static half (the row reads the same
    /// file on the running controller), and the probe script's output
    /// parses into the struct the row reads.
    #[test]
    fn the_shipped_compose_passes_the_sandbox_row_and_the_probe_output_parses() {
        let compose = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker-compose.cluster.yml")).unwrap();
        let good = sandbox_probe("refused: x", "answered HTTP/1.1 200 OK", "refused: y");
        let c = sandbox_listener_check(Some(&compose), Some(&good));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        let parsed: SandboxProbe = serde_json::from_str(r#"{"no_cert": "refused: a", "leaf": "answered HTTP/1.1 200 OK", "plain": "refused: b"}"#).unwrap();
        assert_eq!(parsed, sandbox_probe("refused: a", "answered HTTP/1.1 200 OK", "refused: b"));
        assert!(SANDBOX_PROBE_PY.contains("('sandbox',9000)") && SANDBOX_PROBE_PY.contains("NOO_TLS_CERT"));
        assert!(!SANDBOX_PROBE_PY.contains("CERT_NONE") && !SANDBOX_PROBE_PY.contains("check_hostname"));
    }

    fn voice_overlay_ok() -> String {
        let door = |svc: &str| format!(
            "  {svc}:\n    command:\n      - uvicorn\n      - {svc}_server:app\n      - --port\n      - \"8000\"\n      - --ssl-certfile\n      - /tls/services/{svc}/service.crt\n      - --ssl-keyfile\n      - /tls/services/{svc}/service.key\n      - --ssl-ca-certs\n      - /tls/ca.crt\n      - --ssl-cert-reqs\n      - \"2\"\n    expose:\n      - \"8000\"\n"
        );
        format!("services:\n{}{}", door("whisper"), door("piper"))
    }

    /// The voice row: off is said, never failed; on, OK only when both
    /// doors require a client certificate in the overlay AND the live probe
    /// saw no-cert and plaintext refused and the gateway's leaf answered at
    /// each. Every other combination names the door and its remedy.
    #[test]
    fn the_voice_listeners_row_is_off_or_proves_both_doors_live() {
        let good_door = sandbox_probe("refused: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED]", "answered HTTP/1.1 200 OK", "refused: closed without an answer");
        let good = VoiceProbe { whisper: good_door.clone(), piper: good_door.clone() };
        let overlay = voice_overlay_ok();

        // Off: not composed, nothing to probe — said, not failed, whatever the inputs.
        for (o, p) in [(None, None), (Some(overlay.as_str()), Some(&good))] {
            let c = voice_listeners_check(false, o, p);
            assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
            assert_eq!(c.detail, "voice off — not checked");
        }

        let c = voice_listeners_check(true, Some(&overlay), Some(&good));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, "whisper and piper require a client certificate from every caller (none and plaintext refused, the gateway's leaf accepted); no published port");

        // Static half: piper optional (1), whisper plaintext, a published port, a missing door.
        let optional = overlay.replacen("      - \"2\"\n", "      - \"1\"\n", 2).replacen("      - \"1\"\n", "      - \"2\"\n", 1);
        let c = voice_listeners_check(true, Some(&optional), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("piper's uvicorn") && c.detail.contains("--ssl-cert-reqs 2"), "{}", c.detail);
        let plain = overlay.replace("      - --ssl-certfile\n      - /tls/services/whisper/service.crt\n", "");
        let c = voice_listeners_check(true, Some(&plain), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("whisper's uvicorn"), "{}", c.detail);
        let published = overlay.replacen("    expose:\n", "    ports:\n      - \"8000:8000\"\n    expose:\n", 1);
        let c = voice_listeners_check(true, Some(&published), Some(&good));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("whisper publishes a host port"), "{}", c.detail);
        let no_piper = overlay.split("  piper:\n").next().unwrap().to_string();
        assert_eq!(voice_listeners_check(true, Some(&no_piper), Some(&good)).verdict, Verdict::Fail);

        // Live half, per door.
        let with = |w: SandboxProbe, p: SandboxProbe| VoiceProbe { whisper: w, piper: p };
        let c = voice_listeners_check(true, Some(&overlay), Some(&with(good_door.clone(), sandbox_probe("answered HTTP/1.1 200 OK", "answered HTTP/1.1 200 OK", "refused: x"))));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("piper: a connection WITHOUT a client certificate"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo stack restart --force piper"));
        let c = voice_listeners_check(true, Some(&overlay), Some(&with(sandbox_probe("refused: x", "answered HTTP/1.1 200 OK", "answered HTTP/1.1 200 OK"), good_door.clone())));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("whisper: a PLAINTEXT request"), "{}", c.detail);
        let c = voice_listeners_check(true, Some(&overlay), Some(&with(good_door.clone(), sandbox_probe("refused: x", "refused: [SSL: CERTIFICATE_VERIFY_FAILED]", "refused: y"))));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.remedy.unwrap().contains("issue-service piper"));
        let down = sandbox_probe("unreachable: [Errno -2]", "unreachable: [Errno -2]", "unreachable: [Errno -2]");
        let c = voice_listeners_check(true, Some(&overlay), Some(&with(down, good_door.clone())));
        assert_eq!(c.verdict, Verdict::Fail, "a down door must not read as a refusal");
        assert!(c.detail.contains("cannot reach whisper:8000"), "{}", c.detail);

        // On but not probed / not readable: said, never passed.
        assert_eq!(voice_listeners_check(true, Some(&overlay), None).verdict, Verdict::Warn);
        assert_eq!(voice_listeners_check(true, None, Some(&good)).verdict, Verdict::Warn);
    }

    /// The shipped overlay passes the static half (the row reads the same
    /// file on the running controller), and the probe output parses.
    #[test]
    fn the_shipped_voice_overlay_passes_the_row_and_the_probe_output_parses() {
        let overlay = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker-compose.voice.yml")).unwrap();
        let door = sandbox_probe("refused: x", "answered HTTP/1.1 200 OK", "refused: y");
        let good = VoiceProbe { whisper: door.clone(), piper: door.clone() };
        let c = voice_listeners_check(true, Some(&overlay), Some(&good));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        let parsed: VoiceProbe = serde_json::from_str(
            r#"{"whisper": {"no_cert": "refused: a", "leaf": "answered HTTP/1.1 200 OK", "plain": "refused: b"}, "piper": {"no_cert": "refused: a", "leaf": "answered HTTP/1.1 200 OK", "plain": "refused: b"}}"#,
        ).unwrap();
        assert_eq!(parsed.whisper, sandbox_probe("refused: a", "answered HTTP/1.1 200 OK", "refused: b"));
        assert!(VOICE_PROBE_PY.contains("('whisper','piper')") && VOICE_PROBE_PY.contains("NOO_TLS_CERT"));
        assert!(!VOICE_PROBE_PY.contains("CERT_NONE") && !VOICE_PROBE_PY.contains("check_hostname"));
    }

    const NATS_TLS_CFG: &str = "jetstream {\n  store_dir: /data\n}\nhttps_port: 8222\ninclude users.conf\n\ntls {\n  cert_file: /tls/services/nats/service.crt\n  key_file: /tls/services/nats/service.key\n  ca_file: /tls/ca.crt\n  verify: true\n}\n";
    const NATS_COMPOSE_OK: &str = "services:\n  nats:\n    image: nats\n    command: [\"-c\", \"/etc/nats/nats-tls.conf\"]\n    volumes:\n      - nats-data:/data\n      - ./monitoring/nats/nats-tls.conf:/etc/nats/nats-tls.conf:ro\n  gateway:\n    command: [\"-c\", \"/etc/nats/nats.conf\"]\n";

    /// The bus row fails on every plaintext escape hatch it was written to
    /// close: the retired config back on disk, a selector in compose, a
    /// plain mount, a config without client verification, a `nats://`
    /// controller URL. The gateway block below carries a decoy `nats.conf`
    /// so the parser is proven to read the nats block only.
    #[test]
    fn the_nats_tls_row_fails_on_each_plaintext_escape_hatch() {
        let c = nats_tls_check(Some(NATS_TLS_CFG), Some(NATS_COMPOSE_OK), false, Some("tls://nats:4222"));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(nats_tls_check(Some(NATS_TLS_CFG), Some(NATS_COMPOSE_OK), false, None).verdict, Verdict::Ok);

        let c = nats_tls_check(Some(NATS_TLS_CFG), Some(NATS_COMPOSE_OK), true, None);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("nats.conf exists"), "{}", c.detail);

        let selector = NATS_COMPOSE_OK.replace("/etc/nats/nats-tls.conf", "/etc/nats/${NOO_NATS_CONFIG:-nats-tls.conf}");
        let c = nats_tls_check(Some(NATS_TLS_CFG), Some(&selector), false, None);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOO_NATS_CONFIG"), "{}", c.detail);

        let plain_cmd = NATS_COMPOSE_OK.replacen("/etc/nats/nats-tls.conf\"]", "/etc/nats/nats.conf\"]", 1);
        assert_eq!(nats_tls_check(Some(NATS_TLS_CFG), Some(&plain_cmd), false, None).verdict, Verdict::Fail);

        let plain_mount = NATS_COMPOSE_OK.replace("      - nats-data:/data\n", "      - nats-data:/data\n      - ./monitoring/nats/nats.conf:/etc/nats/nats.conf:ro\n");
        let c = nats_tls_check(Some(NATS_TLS_CFG), Some(&plain_mount), false, None);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("mounts a nats.conf"), "{}", c.detail);

        let no_verify = NATS_TLS_CFG.replace("  verify: true\n", "");
        let c = nats_tls_check(Some(&no_verify), Some(NATS_COMPOSE_OK), false, None);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("verify: true"), "{}", c.detail);

        let c = nats_tls_check(Some(NATS_TLS_CFG), Some(NATS_COMPOSE_OK), false, Some("nats://nats:4222"));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not tls://"), "{}", c.detail);

        assert_eq!(nats_tls_check(None, Some(NATS_COMPOSE_OK), false, None).verdict, Verdict::Warn);
    }

    /// The shipped tree passes its own row — and the retired plaintext
    /// config is not in it.
    #[test]
    fn the_shipped_nats_config_and_compose_pass_the_tls_row() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cfg = std::fs::read_to_string(repo.join("monitoring/nats/nats-tls.conf")).expect("shipped nats config");
        let compose = std::fs::read_to_string(repo.join("docker-compose.cluster.yml")).expect("shipped compose");
        let plain = repo.join("monitoring/nats/nats.conf").is_file();
        let c = nats_tls_check(Some(&cfg), Some(&compose), plain, None);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    #[test]
    fn a_node_that_does_not_enforce_peer_identity_fails_with_the_provision_fix() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        assert_eq!(verdict(&node_checks(&n, "v0.2.70", "0.5.57", now, Some(true)), "peer identity"), Verdict::Ok);
        n["peer_identity_enforced"] = false.into();
        let checks = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let c = checks.iter().find(|c| c.name == "peer identity").unwrap();
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.remedy.as_deref().unwrap().contains("noo cluster provision host3"), "{:?}", c.remedy);
        // Not reported: gentle right after a heartbeat, an upgrade hint once the agent is plainly old.
        n.as_object_mut().unwrap().remove("peer_identity_enforced");
        assert_eq!(verdict(&node_checks(&n, "v0.2.70", "0.5.57", now, Some(true)), "peer identity"), Verdict::Warn);
        n["last_heartbeat"] = stamp(now - 3600).into();
        let checks = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        let c = checks.iter().find(|c| c.name == "peer identity").unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.remedy.as_deref().unwrap().contains("noo cluster provision host3 --wait"));
    }

    #[test]
    fn the_shipped_loki_config_and_compose_pass_the_listener_row() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cfg = std::fs::read_to_string(repo.join("monitoring/loki/loki-config-tls.yml")).expect("shipped loki config");
        let compose = std::fs::read_to_string(repo.join("docker-compose.cluster.yml")).expect("shipped compose");
        let c = loki_listener_check(Some(&cfg), Some(&compose));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    const BACKENDS_OK: &str = "services:\n  gateway:\n    ports:\n      - \"8080:8080\"\n  vllm:\n    image: v\n    command:\n      - |\n        ARGS=\"$$ARGS --ssl-certfile /app/pki/services/vllm/service.crt --ssl-cert-reqs 2\"\n  llamacpp:\n    image: l\n  stunnel-llamacpp:\n    image: s\n    volumes:\n      - ./docker/stunnel-llamacpp.conf:/etc/stunnel/stunnel.conf:ro\n  grafana:\n    ports:\n      - \"3000:3000\"\n";

    fn conf_verify2(_: &str) -> Option<String> {
        Some("[x]\naccept = 0.0.0.0:8085\nverify = 2\n".into())
    }

    /// Each way a backend door can admit a caller without a certificate is
    /// named: the vLLM flag missing, the sidecar missing, its conf without
    /// verify = 2, and a published port on either.
    #[test]
    fn the_backend_tls_row_names_each_way_a_door_opens_without_a_cert() {
        let ok_row = backend_listener_check(Some(BACKENDS_OK), &conf_verify2);
        assert_eq!(ok_row.verdict, Verdict::Ok, "{}", ok_row.detail);
        assert!(ok_row.detail.contains("vllm, llamacpp"), "{}", ok_row.detail);
        assert!(ok_row.detail.contains("airllm"), "the exception is named: {}", ok_row.detail);
        assert!(!ok_row.detail.contains("ollama-embed"), "no loopback allowance named for an absent service: {}", ok_row.detail);

        let no_flag = BACKENDS_OK.replace(" --ssl-cert-reqs 2", "");
        let c = backend_listener_check(Some(&no_flag), &conf_verify2);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("vllm does not run with --ssl-cert-reqs 2"), "{}", c.detail);

        let no_sidecar = BACKENDS_OK.replace("  stunnel-llamacpp:\n    image: s\n    volumes:\n      - ./docker/stunnel-llamacpp.conf:/etc/stunnel/stunnel.conf:ro\n", "");
        let c = backend_listener_check(Some(&no_sidecar), &conf_verify2);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("no stunnel-llamacpp service"), "{}", c.detail);

        let c = backend_listener_check(Some(BACKENDS_OK), &|_| Some("[x]\nverify = 0\n".into()));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("verify = 2"), "{}", c.detail);
        // A commented-out verify line does not count.
        let c = backend_listener_check(Some(BACKENDS_OK), &|_| Some("[x]\n; verify = 2\n".into()));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);

        let published = BACKENDS_OK.replace("  llamacpp:\n    image: l\n", "  llamacpp:\n    image: l\n    ports:\n      - \"8085:8085\"\n");
        let c = backend_listener_check(Some(&published), &conf_verify2);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("llamacpp publishes a host port"), "{}", c.detail);

        assert_eq!(backend_listener_check(None, &conf_verify2).verdict, Verdict::Warn);
        assert_eq!(backend_listener_check(Some("services:\n  gateway:\n    image: g\n"), &conf_verify2).verdict, Verdict::Warn);
    }

    /// The shipped compose file and stunnel confs pass the row — and the
    /// parse is not vacuous: every backend in COMPOSE_BACKENDS is present.
    #[test]
    fn the_shipped_compose_and_stunnel_confs_pass_the_backend_tls_row() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let compose = std::fs::read_to_string(repo.join("docker-compose.cluster.yml")).expect("shipped compose");
        for (svc, _) in COMPOSE_BACKENDS {
            assert!(compose_service_block(&compose, svc).is_some(), "{svc} is not in the shipped compose file — drop the row or restore the service");
        }
        let c = backend_listener_check(Some(&compose), &|name| {
            std::fs::read_to_string(repo.join("docker").join(format!("stunnel-{name}.conf"))).ok()
        });
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// `sidecar image`: WARN on the alpine fallback, OK on
    /// the published image, no row when the node does not report it.
    #[test]
    fn image_sources_row_names_every_image_not_from_the_rail() {
        let all_rail = serde_json::json!({"id": "host8-ma", "image_sources": [
            {"image": "reg/acme/llamacpp:v1", "source": "rail"}]});
        assert_eq!(image_sources_check(&all_rail).unwrap().verdict, Verdict::Ok);
        let mixed = serde_json::json!({"id": "host8-ma", "image_source_mode": "rail", "image_sources": [
            {"image": "reg/acme/llamacpp:v1", "source": "local"},
            {"image": "ollama/ollama:latest", "source": "registry"},
            {"image": "reg/acme/stunnel:v1", "source": "rail"}]});
        let c = image_sources_check(&mixed).unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("reg/acme/llamacpp:v1 (local)") && c.detail.contains("ollama/ollama:latest (registry)"), "{}", c.detail);
        assert!(!c.detail.contains("stunnel"), "{}", c.detail);
        assert!(image_sources_check(&serde_json::json!({"id": "old"})).is_none(), "an older agent gets no row");
        // On the legacy source the same facts are reported, not warned on.
        let mut legacy = mixed.clone();
        legacy["image_source_mode"] = "legacy".into();
        let c = image_sources_check(&legacy).unwrap();
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("legacy") && c.detail.contains("ollama/ollama:latest (registry)"), "{}", c.detail);
    }

    #[test]
    fn images_staged_row_names_an_unstaged_placement() {
        let n = serde_json::json!({"id": "host8-ma", "unstaged_images": ["reg/acme/llamacpp:v0.2.103"]});
        let c = images_staged_check(&n).unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("reg/acme/llamacpp:v0.2.103"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("noo cluster sync-images host8-ma -i reg/acme/llamacpp:v0.2.103"));
        assert!(images_staged_check(&serde_json::json!({"id": "x"})).is_none());
    }

    #[test]
    fn the_sidecar_image_row_warns_on_the_alpine_fallback() {
        let c = stunnel_image_check(&serde_json::json!({"id": "host9", "stunnel_image": "fallback-alpine"})).expect("a row");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("alpine mirror"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().contains("noo cluster provision host9 --wait"), "{:?}", c.remedy);
        let c = stunnel_image_check(&serde_json::json!({"id": "host3", "stunnel_image": "published"})).expect("a row");
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(stunnel_image_check(&serde_json::json!({"id": "host3"})).is_none());
        assert_eq!(stunnel_image_check(&serde_json::json!({"id": "x", "stunnel_image": "weird"})).unwrap().verdict, Verdict::Warn);
    }

    // docs/security/telemetry.md: a running backend lacking a switch FAILs,
    // naming it; an agent that does not report is never a pass.
    #[test]
    fn vendor_telemetry_row_fails_on_a_missing_switch() {
        let n = serde_json::json!({"id": "host3", "backend_containers": {
            "vllm": {"running": true, "started_at": 1, "telemetry_missing": ["VLLM_NO_USAGE_STATS", "DO_NOT_TRACK"]},
            "embedding": {"running": true, "started_at": 1, "telemetry_missing": []}}});
        let c = vendor_telemetry_check(&n);
        assert_eq!(c.verdict, Verdict::Fail, "{c:?}");
        assert!(c.detail.contains("vllm lacks VLLM_NO_USAGE_STATS, DO_NOT_TRACK"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").starts_with("noo cluster provision host3 --wait"), "{c:?}");

        let clean = serde_json::json!({"id": "host3", "backend_containers": {
            "vllm": {"running": true, "started_at": 1, "telemetry_missing": []}}});
        let c = vendor_telemetry_check(&clean);
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(c.detail.contains("vllm"), "{}", c.detail);

        let old = serde_json::json!({"id": "host3", "backend_containers": {
            "vllm": {"running": true, "started_at": 1}}});
        assert_eq!(vendor_telemetry_check(&old).verdict, Verdict::Warn);
        let older = serde_json::json!({"id": "host3", "running_backends": {"vllm": "m"}});
        assert_eq!(vendor_telemetry_check(&older).verdict, Verdict::Warn);
        let none = serde_json::json!({"id": "host3", "backend_containers": {}});
        assert_eq!(vendor_telemetry_check(&none).verdict, Verdict::Ok);
    }

    // host8 2026-10-03: an old agent-created noo-ollama beside the stack's
    // adopted ollama. Provision cannot fix it; the row says so and names the
    // exact containers to remove.
    #[test]
    fn vendor_telemetry_row_names_an_orphan_beside_an_adopted_backend() {
        let n = serde_json::json!({"id": "host8", "backend_containers": {
            "ollama": {"running": true, "started_at": 1, "container": "noo-ollama", "orphan": true,
                       "sidecars": ["noo-stunnel-ollama"], "telemetry_missing": ["OLLAMA_NO_CLOUD"]}}});
        let c = vendor_telemetry_check(&n);
        assert_eq!(c.verdict, Verdict::Fail, "{c:?}");
        assert!(c.detail.contains("noo-ollama is an orphan container beside the stack's adopted ollama"), "{}", c.detail);
        assert!(c.detail.contains("nothing manages it"), "{}", c.detail);
        let r = c.remedy.as_deref().unwrap();
        assert!(r.starts_with("docker rm -f noo-ollama noo-stunnel-ollama"), "{r}");
        assert!(!r.contains("noo cluster provision"), "provision cannot fix an orphan: {r}");

        // No sidecar reported: none named.
        let n = serde_json::json!({"id": "host8", "backend_containers": {
            "ollama": {"running": true, "started_at": 1, "container": "noo-ollama", "orphan": true,
                       "telemetry_missing": ["OLLAMA_NO_CLOUD"]}}});
        let r = vendor_telemetry_check(&n).remedy.unwrap();
        assert!(r.starts_with("docker rm -f noo-ollama   #"), "{r}");

        // An orphan that has the switch is not a problem; a non-orphan lacking one keeps the provision remedy.
        let n = serde_json::json!({"id": "host8", "backend_containers": {
            "ollama": {"running": true, "started_at": 1, "container": "noo-ollama", "orphan": true, "telemetry_missing": []},
            "vllm": {"running": true, "started_at": 1, "telemetry_missing": ["DO_NOT_TRACK"]}}});
        let c = vendor_telemetry_check(&n);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(!c.detail.contains("orphan"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo cluster provision host8"));
    }

    // A Mac's native ollama rides `backend_containers.ollama` with
    // `runtime: native`: ok when the plist/process carry the switch, FAIL
    // with the Mac remedy when not, and a "not managed" WARN with no plist.
    #[test]
    fn vendor_telemetry_row_judges_a_mac_native_ollama() {
        let set = serde_json::json!({"id": "host6", "backend_containers": {
            "ollama": {"running": true, "runtime": "native", "managed": true, "telemetry_missing": []}}});
        let c = vendor_telemetry_check(&set);
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(c.detail.contains("ollama"), "{}", c.detail);

        let lacks = serde_json::json!({"id": "host6", "backend_containers": {
            "ollama": {"running": true, "runtime": "native", "managed": true, "telemetry_missing": ["OLLAMA_NO_CLOUD"]}}});
        let c = vendor_telemetry_check(&lacks);
        assert_eq!(c.verdict, Verdict::Fail, "{c:?}");
        assert!(c.detail.contains("ollama lacks OLLAMA_NO_CLOUD"), "{}", c.detail);
        let r = c.remedy.as_deref().unwrap_or("");
        assert!(r.contains("plutil -replace EnvironmentVariables.OLLAMA_NO_CLOUD") && r.contains("launchctl bootstrap"), "{r}");
        assert!(r.contains("sh.brew.ollama") && r.contains("homebrew.mxcl.ollama"), "both brew labels: {r}");
        assert!(r.contains("user/$(id -u)"), "a headless Mac's domain: {r}");
        assert!(!r.contains("provision"), "a Mac's remedy is not a container recreate: {r}");

        let absent = serde_json::json!({"id": "host6", "backend_containers": {
            "ollama": {"running": true, "runtime": "native", "managed": false}}});
        let c = vendor_telemetry_check(&absent);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("not managed by noomesh"), "{}", c.detail);
    }

    fn unmanaged_ollama(launcher: Option<&str>, process_env: Option<&str>) -> Value {
        let mut e = serde_json::json!({"running": true, "runtime": "native", "managed": false});
        if let Some(l) = launcher {
            e["launcher"] = l.into();
        }
        if let Some(p) = process_env {
            e["process_env"] = p.into();
        }
        serde_json::json!({"id": "host6", "backend_containers": {"ollama": e}})
    }

    /// An ollama noomesh did not start is judged from its running process
    /// (the agent reads `process_env` whatever launched it), and the launcher
    /// picks the remedy.
    #[test]
    fn vendor_telemetry_row_proves_an_unmanaged_ollama_from_its_process() {
        let c = vendor_telemetry_check(&unmanaged_ollama(Some("manual"), Some("set")));
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(c.detail.contains("not managed by noomesh (launched by manual), but the running process has OLLAMA_NO_CLOUD=1"), "{}", c.detail);

        let c = vendor_telemetry_check(&unmanaged_ollama(Some("ollama-app"), Some("missing")));
        assert_eq!(c.verdict, Verdict::Fail, "{c:?}");
        assert!(c.detail.contains("launched by ollama-app without OLLAMA_NO_CLOUD — its vendor phones home"), "{}", c.detail);
        let r = c.remedy.as_deref().unwrap_or("");
        assert!(r.contains("quit Ollama.app and disable its login item") && r.contains("brew services start ollama") && r.contains("launchctl setenv OLLAMA_NO_CLOUD 1"), "{r}");

        let c = vendor_telemetry_check(&unmanaged_ollama(Some("manual"), Some("missing")));
        assert_eq!(c.verdict, Verdict::Fail, "{c:?}");
        let r = c.remedy.as_deref().unwrap_or("");
        assert!(r.contains("stop the hand-started `ollama serve`") && r.contains("the agent takes over"), "{r}");
        assert!(!r.contains("Ollama.app"), "{r}");

        // Unreadable process, or an older agent that reports neither field:
        // today's warn, plus the launcher when the agent named one.
        let c = vendor_telemetry_check(&unmanaged_ollama(Some("none"), Some("unknown")));
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("not managed by noomesh") && c.detail.contains("OLLAMA_NO_CLOUD not proven") && c.detail.contains("launcher: none"), "{}", c.detail);
        let c = vendor_telemetry_check(&unmanaged_ollama(None, None));
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(!c.detail.contains("launcher"), "{}", c.detail);
    }

    /// `ollama-embed` publishes nothing; its sidecar
    /// `stunnel-ollama-embed` publishes the mTLS door on loopback for the
    /// host agent. The raw backend publishing again (the pre-1245 plaintext
    /// publish), a LAN or bare bind on the sidecar, or the sidecar's conf
    /// without `verify = 2` each fail the row; the OK text names the door.
    #[test]
    fn the_backend_tls_row_allows_only_a_loopback_mtls_door() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let compose = std::fs::read_to_string(repo.join("docker-compose.cluster.yml")).expect("shipped compose");
        let shipped_conf = |name: &str| std::fs::read_to_string(repo.join("docker").join(format!("stunnel-{name}.conf"))).ok();
        let c = backend_listener_check(Some(&compose), &shipped_conf);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("stunnel-ollama-embed 127.0.0.1:11434:11434"), "{}", c.detail);
        assert!(!c.detail.contains("plaintext ("), "no plaintext publish is named any more: {}", c.detail);
        assert!(c.detail.contains("airllm"), "{}", c.detail);

        let embed = compose_service_block(&compose, "ollama-embed").expect("ollama-embed block");
        assert!(compose_ports(&embed).is_empty(), "ollama-embed publishes {:?}", compose_ports(&embed));
        assert!(compose_publishes(&compose, "stunnel-ollama-embed", "127.0.0.1:11434:11434"));

        let shipped = "      - \"127.0.0.1:11434:11434\"\n";
        assert_eq!(compose.matches(shipped).count(), 1, "the shipped publish moved — update this test");
        // The pre-1245 shape: the raw backend published on loopback, plaintext.
        let old = compose
            .replacen(&format!("    ports:\n{shipped}"), "", 1)
            .replacen("  ollama-embed:\n", &format!("  ollama-embed:\n    ports:\n{shipped}"), 1);
        assert!(!compose_publishes(&old, "stunnel-ollama-embed", "127.0.0.1:11434:11434"));
        let c = backend_listener_check(Some(&old), &shipped_conf);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("ollama-embed publishes a host port"), "{}", c.detail);

        for bad in ["0.0.0.0:11434:11434", "11434:11434", "100.64.0.1:11434:11434"] {
            let lan = compose.replacen(shipped, &format!("      - \"{bad}\"\n"), 1);
            let c = backend_listener_check(Some(&lan), &shipped_conf);
            assert_eq!(c.verdict, Verdict::Fail, "{bad}: {}", c.detail);
            assert!(c.detail.contains("stunnel-ollama-embed publishes"), "{bad}: {}", c.detail);
            assert!(!compose_publishes(&lan, "stunnel-ollama-embed", "127.0.0.1:11434:11434"), "{bad}");
        }
        let second = compose.replacen(shipped, &format!("{shipped}      - \"0.0.0.0:11435:11435\"\n"), 1);
        assert_eq!(backend_listener_check(Some(&second), &shipped_conf).verdict, Verdict::Fail);
        assert!(!compose_publishes(&second, "stunnel-ollama-embed", "127.0.0.1:11434:11434"));

        let c = backend_listener_check(Some(&compose), &|name| {
            let conf = shipped_conf(name)?;
            Some(if name == "ollama-embed" { conf.replace("verify = 2", "verify = 0") } else { conf })
        });
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("docker/stunnel-ollama-embed.conf does not set verify = 2"), "{}", c.detail);
    }

    /// The compose healthcheck, onboard's readiness probe and the row's
    /// flag all name the same leaf paths and the same flag: the compose
    /// file is the declaration, the others must follow it.
    #[test]
    fn the_vllm_self_probe_and_compose_agree_on_the_leaf_paths() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let compose = std::fs::read_to_string(repo.join("docker-compose.cluster.yml")).expect("shipped compose");
        let vllm = compose_service_block(&compose, "vllm").expect("vllm service");
        for needle in ["/app/pki/ca.crt", "/app/pki/services/vllm/service.crt", "/app/pki/services/vllm/service.key"] {
            assert!(vllm.contains(needle), "compose vllm lacks {needle}");
            assert!(crate::onboard::steps::VLLM_SELF_PROBE.contains(needle), "onboard's probe lacks {needle}");
        }
        assert!(vllm.contains("load_cert_chain"), "the compose healthcheck does not present the leaf");
        assert!(crate::onboard::steps::VLLM_SELF_PROBE.contains("load_cert_chain"));
        assert!(!vllm.contains("NOO_VLLM_TLS"), "the compose vllm listener must have no plaintext switch");
    }

    #[test]
    fn the_mount_holding_a_path_is_the_longest_prefix() {
        let mounts = "/dev/nvme1n1p3 / ext4 rw 0 0\n/dev/nvme0n1p1 /media/alice/data ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n";
        assert_eq!(mount_of(mounts, "/media/alice/data/noo/loki"), Some(("/dev/nvme0n1p1".into(), "/media/alice/data".into())));
        assert_eq!(mount_of(mounts, "/home/x/.noo/loki"), Some(("/dev/nvme1n1p3".into(), "/".into())));
        // A sibling path must not match by string prefix alone.
        assert_eq!(mount_of(mounts, "/media/alice/data0/loki").unwrap().1, "/");
        assert_eq!(mount_of("", "/x"), None);
    }

    /// Never claims encrypted: the ok arm needs a positive `crypt` reading.
    #[test]
    fn the_at_rest_row_warns_unless_the_device_is_dm_crypt() {
        let m = Some(("/dev/nvme0n1p1", "/media/alice/data"));
        assert_eq!(loki_at_rest_check("/media/alice/data/noo/loki", m, Some(true)).verdict, Verdict::Ok);
        let clear = loki_at_rest_check("/media/alice/data/noo/loki", m, Some(false));
        assert_eq!(clear.verdict, Verdict::Warn);
        assert!(clear.detail.contains("in the clear"), "{}", clear.detail);
        let unknown = loki_at_rest_check("/x/loki", m, None);
        assert_eq!(unknown.verdict, Verdict::Warn);
        assert!(unknown.detail.contains("could not determine"), "{}", unknown.detail);
        assert_eq!(loki_at_rest_check("/x/loki", None, Some(true)).verdict, Verdict::Warn, "no mount = no claim");
    }

    /// The at-rest table resolves each directory the way the stack does:
    /// compose's `NOO_DATA_ROOT` binds, `NOO_PG_DATA` (onboard's NTFS
    /// redirect) for Postgres, `NOO_PKI_DIR`, and the age key's directory.
    #[test]
    fn the_at_rest_table_resolves_every_data_dir_from_the_env() {
        let env = |k: &str| -> Option<String> {
            match k {
                "NOO_DATA_ROOT" => Some("/media/alice/data/noo/".into()),
                "HOME" => Some("/home/alice".into()),
                _ => None,
            }
        };
        let rows = at_rest_dirs(&env);
        let path = |name: &str| rows.iter().find(|r| r.name == name).map(|r| r.path.clone()).unwrap_or_else(|| panic!("no row {name}"));
        assert_eq!(path("loki at rest"), "/media/alice/data/noo/loki");
        assert_eq!(path("postgres at rest"), "/media/alice/data/noo/postgres", "NOO_PG_DATA unset → under the data root, as compose defaults it");
        assert_eq!(path("redis at rest"), "/media/alice/data/noo/redis");
        assert_eq!(path("nats at rest"), "/media/alice/data/noo/nats");
        assert_eq!(path("prometheus at rest"), "/media/alice/data/noo/prometheus");
        assert_eq!(path("grafana at rest"), "/media/alice/data/noo/grafana");
        assert_eq!(path("noo-data at rest"), "/media/alice/data/noo/noo-data");
        assert_eq!(path("pki at rest"), "/home/alice/.config/mesh/pki", "pki::pki_dir's default");
        assert_eq!(path("age key at rest"), "/home/alice/.config/sops/age");
        assert!(rows.iter().all(|r| r.name.ends_with(" at rest")), "one naming for the whole table");
        assert_eq!(rows.len(), 9);

        // The overrides the wizard writes / the operator exports.
        let env2 = |k: &str| -> Option<String> {
            match k {
                "NOO_PG_DATA" => Some("/home/alice/noo/postgres".into()),
                "NOO_PKI_DIR" => Some("/etc/noo/pki".into()),
                "SOPS_AGE_KEY_FILE" => Some("/etc/noo/age/keys.txt".into()),
                _ => None,
            }
        };
        let rows2 = at_rest_dirs(&env2);
        let path2 = |name: &str| rows2.iter().find(|r| r.name == name).unwrap().path.clone();
        assert_eq!(path2("postgres at rest"), "/home/alice/noo/postgres", "the NTFS redirect wins over the data root");
        assert_eq!(path2("pki at rest"), "/etc/noo/pki");
        assert_eq!(path2("age key at rest"), "/etc/noo/age", "dirname of the key file");
        assert_eq!(path2("loki at rest"), format!("{}/loki", crate::commands::data_root::DEFAULT_DATA_ROOT), "the default data root");
    }

    /// Every row of the table judged over one fake mounts table: the rows
    /// on the LUKS-backed mount are OK, the one on the plain root is a
    /// WARN with the same hint Loki's row has carried, and a directory that
    /// does not exist is a WARN that says so rather than a verdict.
    #[test]
    fn every_at_rest_row_gets_the_same_verdict_logic() {
        let mounts = "/dev/mapper/data / ext4 rw 0 0\n/dev/nvme0n1p2 /home ext4 rw 0 0\n";
        let env = |k: &str| -> Option<String> {
            match k {
                "NOO_DATA_ROOT" => Some("/opt/noo".into()),
                "HOME" => Some("/home/alice".into()),
                _ => None,
            }
        };
        for row in at_rest_dirs(&env) {
            let (dev, mp) = mount_of(mounts, &row.path).unwrap();
            let on_home = mp == "/home";
            // Pretend lsblk said: the root mapper is crypt, the /home partition is not.
            let encrypted = Some(!on_home);
            let c = at_rest_check(row.name, row.what, &row.path, true, Some((&dev, &mp)), encrypted);
            if on_home {
                assert_eq!(c.verdict, Verdict::Warn, "{}: {}", row.name, c.detail);
                assert!(c.detail.contains("in the clear") && c.detail.contains(row.what), "{}: {}", row.name, c.detail);
                assert!(c.remedy.as_deref().unwrap_or("").contains("LUKS"), "{}", row.name);
            } else {
                assert_eq!(c.verdict, Verdict::Ok, "{}: {}", row.name, c.detail);
            }
            let absent = at_rest_check(row.name, row.what, &row.path, false, None, None);
            assert_eq!(absent.verdict, Verdict::Warn);
            assert!(absent.detail.contains("does not exist"), "{}", absent.detail);
        }
        // pki and the age key live under $HOME here, the rest under /opt/noo.
        let names: Vec<&str> = at_rest_dirs(&env).into_iter().filter(|r| mount_of(mounts, &r.path).unwrap().1 == "/home").map(|r| r.name).collect();
        assert_eq!(names, vec!["pki at rest", "age key at rest"]);
    }

    /// A mounted web-config that the command never names is the exact
    /// shape alertmanager shipped in: FAIL, naming the service and path.
    #[test]
    fn the_web_config_row_fails_on_a_mount_without_its_flag() {
        let good = "services:\n  alertmanager:\n    volumes:\n      - ./monitoring/alertmanager/web-config.yml:/etc/alertmanager/web-config.yml:ro\n    command:\n      - '--config.file=/etc/alertmanager/alertmanager.yml'\n      - '--web.config.file=/etc/alertmanager/web-config.yml'\n  prometheus:\n    volumes:\n      - ./monitoring/prometheus/web-config.yml:/etc/prometheus/web-config.yml:ro\n    command:\n      - '--web.config.file=/etc/prometheus/web-config.yml'\n";
        let c = monitoring_web_config_check(Some(good));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("alertmanager") && c.detail.contains("prometheus"), "{}", c.detail);

        let planted = good.replace("      - '--web.config.file=/etc/alertmanager/web-config.yml'\n", "");
        let c = monitoring_web_config_check(Some(&planted));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("alertmanager mounts /etc/alertmanager/web-config.yml"), "{}", c.detail);
        assert!(!c.detail.contains("prometheus mounts"), "prometheus still loads its file: {}", c.detail);

        assert_eq!(monitoring_web_config_check(None).verdict, Verdict::Warn);
        assert_eq!(monitoring_web_config_check(Some("services:\n  redis:\n    image: x\n")).verdict, Verdict::Warn, "nothing mounted = nothing judged");
    }

    /// The log shipper row, one state at a time. Planted 2026-09-28: the
    /// stalled arm returning OK fails the second block here.
    #[test]
    fn the_log_shipper_row_reads_every_state_of_the_heartbeat() {
        let now = 1_800_000_000;
        // Not reported: never a failure; the wording follows the heartbeat age.
        let c = log_shipper_check("host3", &Value::Null, now, true);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("not reported yet"), "{}", c.detail);
        let c = log_shipper_check("host3", &Value::Null, now, false);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("predates the shipper") && c.detail.contains("noo cluster provision host3 --wait"), "{}", c.detail);

        // Stalled: enabled, holding lines, nothing accepted for > 15 min.
        let stalled = serde_json::json!({"enabled": true, "queued": 812, "shipped_total": 4000, "dropped_total": 0,
            "last_accepted_unix": now - 40 * 60, "last_error": "503: Loki away", "route_ready": true, "spill_pending": true, "journal": "running"});
        let c = log_shipper_check("host3", &stalled, now, true);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("stalled since 40m ago") && c.detail.contains("503: Loki away"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("noo cluster logs host3 agent"));
        // The same numbers within the window are a slow gateway, not a stall.
        let mut slow = stalled.clone();
        slow["last_accepted_unix"] = serde_json::json!(now - 5 * 60);
        assert_eq!(log_shipper_check("host3", &slow, now, true).verdict, Verdict::Ok);
        // And an old last_accepted with NOTHING held is idle, not stalled.
        let mut idle = stalled.clone();
        idle["queued"] = serde_json::json!(0);
        idle["spill_pending"] = serde_json::json!(false);
        assert_eq!(log_shipper_check("host3", &idle, now, true).verdict, Verdict::Ok);

        // Off by choice, the reason named.
        let off = serde_json::json!({"enabled": false, "queued": 0, "shipped_total": 0, "last_accepted_unix": 0, "last_error": "NOO_LOG_SHIP=0"});
        let c = log_shipper_check("host9", &off, now, true);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("NOO_LOG_SHIP=0"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("/etc/noo-node-agent.env on host9"));

        // The gateway has no route yet.
        let no_route = serde_json::json!({"enabled": true, "queued": 0, "shipped_total": 0, "last_accepted_unix": 0, "last_error": "", "route_ready": false, "spill_pending": false});
        let c = log_shipper_check("host3", &no_route, now, true);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("ingest route is not answering"), "{}", c.detail);

        // Never accepted: with a refusal it fails, without one it waits.
        let refused = serde_json::json!({"enabled": true, "queued": 300, "shipped_total": 0, "last_accepted_unix": 0, "last_error": "403: node token", "route_ready": true, "spill_pending": false});
        assert_eq!(log_shipper_check("host3", &refused, now, true).verdict, Verdict::Fail);
        let fresh = serde_json::json!({"enabled": true, "queued": 3, "shipped_total": 0, "last_accepted_unix": 0, "last_error": "", "route_ready": true, "spill_pending": false});
        let c = log_shipper_check("host3", &fresh, now, true);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("re-run after the next heartbeat"), "{}", c.detail);

        // Journal follower not running: containers ship, the string carries the remedy.
        let old_hostd = serde_json::json!({"enabled": true, "queued": 0, "shipped_total": 900, "last_accepted_unix": now - 10, "last_error": "", "route_ready": true, "spill_pending": false,
            "journal": "hostd predates journal-follow (serves unit-logs); run `noo upgrade --nodes`"});
        let c = log_shipper_check("host3", &old_hostd, now, true);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("hostd predates journal-follow"), "{}", c.detail);

        // Healthy, and a Mac (no journal key) is judged the same.
        let good = serde_json::json!({"enabled": true, "queued": 0, "shipped_total": 9000, "dropped_total": 7, "last_accepted_unix": now - 3, "last_error": "", "route_ready": true, "spill_pending": false, "journal": "running"});
        let c = log_shipper_check("host3", &good, now, true);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("shipped 9000") && c.detail.contains("3s ago") && c.detail.contains("7 dropped"), "{}", c.detail);
        let mut mac = good.clone();
        mac.as_object_mut().unwrap().remove("journal");
        assert_eq!(log_shipper_check("host6", &mac, now, true).verdict, Verdict::Ok);
    }

    /// The row rides `node_checks`, on the record's `log_ship`.
    #[test]
    fn the_node_table_carries_the_log_shipper_row() {
        let now = 1_800_000_000;
        let mut n = healthy(now);
        n["log_ship"] = serde_json::json!({"enabled": true, "queued": 500, "shipped_total": 1, "last_accepted_unix": now - 3600, "last_error": "503", "route_ready": true, "spill_pending": false});
        let c = node_checks(&n, "v0.2.70", "0.5.57", now, Some(true));
        assert_eq!(verdict(&c, "log shipper"), Verdict::Fail);
    }

    /// And the gateway must carry `log_ship` onto the record, or the row
    /// reads every node as "predates the shipper" (the seam phase 6 found).
    #[test]
    fn the_nodes_route_carries_the_shippers_account() {
        let src = include_str!("../../../gateway-rust/src/routes/cluster.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert!(code.contains("carry_reported(&mut data, &body, \"log_ship\")"), "node_heartbeat must carry log_ship onto the record");
    }

    #[test]
    fn the_last_seen_gauge_is_parsed_whatever_the_label_order_or_number_shape() {
        let text = "# TYPE noo_logs_last_seen_unix gauge\nnoo_logs_last_seen_unix{node=\"host3\"} 1800000000\n\
                    noo_logs_last_seen_unix{zone=\"x\",node=\"host9\"} 1799999000.5\n\
                    noo_logs_ingest_lines_total{node=\"host3\"} 12\nnoo_logs_last_seen_unix{node=\"\"} 5\n";
        let seen = parse_logs_last_seen(text);
        assert_eq!(seen.get("host3"), Some(&1_800_000_000));
        assert_eq!(seen.get("host9"), Some(&1_799_999_000));
        assert_eq!(seen.len(), 2, "{seen:?}");
    }

    /// Online nodes are judged; offline ones are skipped and named. Planted
    /// 2026-09-28: the stale arm returning OK fails the first block.
    #[test]
    fn the_last_seen_row_fails_a_stale_online_node_and_skips_offline_ones() {
        let now = 1_800_000_000;
        let text = format!("noo_logs_last_seen_unix{{node=\"host3\"}} {}\nnoo_logs_last_seen_unix{{node=\"host9\"}} {}\n", now - 30, now - 3 * 3600);
        let roster = vec![("host3".to_string(), true), ("host9".to_string(), true), ("host6".to_string(), false)];
        let c = logs_last_seen_check(Some(&text), &roster, now);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("host9 (3h ago)") && c.detail.contains("skipped offline: host6"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("noo cluster verify host9"));

        // host9 offline: its silence is not a logging fault.
        let roster = vec![("host3".to_string(), true), ("host9".to_string(), false)];
        let c = logs_last_seen_check(Some(&text), &roster, now);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("1 node(s) shipping") && c.detail.contains("skipped offline: host9"), "{}", c.detail);

        // A node with no series at all: never arrived, WARN with the roll verb.
        let roster = vec![("host3".to_string(), true), ("host2".to_string(), true)];
        let c = logs_last_seen_check(Some(&text), &roster, now);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("no logs ever received from host2"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("noo cluster provision host2 --wait"));

        assert_eq!(logs_last_seen_check(None, &roster, now).verdict, Verdict::Warn, "metrics unreadable is a caveat, not a verdict");
        assert_eq!(logs_last_seen_check(Some(""), &[("x".into(), false)], now).verdict, Verdict::Warn, "nothing online to judge");
    }

    #[test]
    fn a_mac_reporting_other_anchors_warns() {
        let ca = "c".repeat(64);
        let sp = "d".repeat(64);
        let msg = |a: &str, b: &str| format!("applied verified-by: signing-key ca-lane: retired anchors: ca sha256:{a} signing sha256:{b}");
        let c = with_node_anchors(ok("legacy lanes", "0 uses"), &[("host6".into(), Some(0), msg(&ca, &sp))], Some((&ca, &sp)));
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("match this controller: host6"), "{}", c.detail);
        let c = with_node_anchors(ok("legacy lanes", "0 uses"), &[("host6".into(), Some(0), msg(&"e".repeat(64), &sp))], Some((&ca, &sp)));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("DIFFER") && c.detail.contains("host6"), "{}", c.detail);
    }

    /// Verification of #970, item 1: a Mac whose root refused its CLI or
    /// helper reported rc 0; the refusal rides the message and WARNs here.
    #[test]
    fn a_mac_whose_root_refused_its_binaries_warns() {
        let clean = "applied verified-by: signing-key ca-lane: retired".to_string();
        let c = with_node_root_refusals(ok("legacy lanes", "0 uses"), &[("host6".into(), Some(0), clean)]);
        assert_eq!(c.verdict, Verdict::Ok);
        let refused = format!("applied verified-by: signing-key ca-lane: retired {} noo-cli,noo-hostd",
            crate::commands::node_fetch::ROOT_REFUSED_TAG);
        let c = with_node_root_refusals(ok("legacy lanes", "0 uses"), &[("host6".into(), Some(0), refused)]);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("host6 (noo-cli, noo-hostd)"), "{}", c.detail);
        assert!(c.remedy.is_some());
    }

    #[test]
    fn a_node_that_has_not_adopted_fails_the_legacy_row() {
        let c = with_retired_apply_lanes_and_adoption(ok("legacy lanes", "0 uses"), &[], &["host2".into()]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOT adopted") && c.detail.contains("host2"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("noo cluster provision host2 --wait"));
    }

    #[test]
    fn a_refused_controller_secret_caller_warns() {
        let start = 1_800_000_000 - 30 * 86_400;
        let text = format!("noo_gateway_start_time_seconds {start}\n\
            noo_legacy_lane_uses_total{{caller=\"trellion\",lane=\"controller_shared_secret_refused\",route_class=\"graph\"}} 3\n");
        let c = legacy_lanes_check(Some(&text), &[], 1_800_000_000);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("controller_shared_secret_refused 3 (trellion 3)"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("service-key provision"));
        let quiet = legacy_lanes_check(Some(&format!("noo_gateway_start_time_seconds {start}\n")), &[], 1_800_000_000);
        assert!(quiet.detail.contains("controller_shared_secret_refused 0"), "{}", quiet.detail);
        assert!(quiet.detail.contains("fleet_secret_off_node_refused 0"), "{}", quiet.detail);
        let fleet = format!("noo_gateway_start_time_seconds {start}\n\
            noo_legacy_lane_uses_total{{caller=\"worker\",lane=\"fleet_secret_off_node_refused\",route_class=\"cluster\"}} 2\n");
        let c = legacy_lanes_check(Some(&fleet), &[], 1_800_000_000);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("fleet_secret_off_node_refused 2 (worker 2)"), "{}", c.detail);
    }

    // ── retired apply lanes in the legacy-lanes row ──
    #[test]
    fn a_node_refusing_a_retired_apply_lane_turns_the_legacy_row_warn() {
        let base = ok("legacy lanes", "0 uses");
        let quiet = with_retired_apply_lanes(base.clone(), &[
            ("host3".into(), Some(0), "applied: agent-env verified-by: signing-key ca-lane: retired".into()),
        ]);
        assert_eq!(quiet.verdict, Verdict::Ok, "{quiet:?}");
        assert!(quiet.detail.contains("retired apply lanes"), "{}", quiet.detail);

        let refused = with_retired_apply_lanes(base.clone(), &[
            ("host3".into(), Some(0), "verified-by: signing-key".into()),
            ("host2".into(), Some(77), "noo-apply: REFUSED — ... The CA-signed apply lane is retired".into()),
        ]);
        assert_eq!(refused.verdict, Verdict::Warn);
        assert!(refused.detail.contains("host2: refused a CA-signed bundle"), "{}", refused.detail);
        assert!(refused.remedy.as_deref().unwrap_or("").contains("noo cluster provision host2 --wait"));

        let old = with_retired_apply_lanes(base, &[
            ("host9".into(), Some(0), "applied: agent-env verified-by: ca-legacy ca-lane: open".into()),
        ]);
        assert_eq!(old.verdict, Verdict::Warn);
        assert!(old.detail.contains("host9: applied on the retired CA lane"), "{}", old.detail);
    }

    // ── the `legacy lanes` row ──────────────────────────

    /// What the gateway's `/metrics` renders (legacy_lanes.rs): labels in
    /// sorted order, the start gauge beside them.
    fn lane_metrics(start: i64, series: &[&str]) -> String {
        let mut t = format!("# TYPE noo_gateway_up gauge\nnoo_gateway_up{{engine=\"rust\"}} 1\n# TYPE noo_gateway_start_time_seconds gauge\nnoo_gateway_start_time_seconds {start}\n# TYPE noo_legacy_lane_uses_total counter\n");
        for s in series {
            t.push_str(s);
            t.push('\n');
        }
        t
    }

    fn lane_node(id: &str, now: i64, lanes: Option<Value>) -> Value {
        let mut n = serde_json::json!({ "id": id, "status": "online", "last_heartbeat": stamp(now - 10) });
        if let Some(l) = lanes {
            n["legacy_lanes"] = l;
        }
        n
    }

    #[test]
    fn the_lane_metrics_parse_per_lane_and_caller() {
        let text = lane_metrics(1_790_000_000, &[
            r#"noo_legacy_lane_uses_total{caller="trellion",door="controller",lane="self_call_shared_secret"} 10"#,
            r#"noo_legacy_lane_uses_total{caller="worker",door="controller",lane="self_call_shared_secret"} 2"#,
            r#"noo_legacy_lane_uses_total{caller="trellion",kind="controller",lane="cluster_hmac_non_inference",route_class="graph"} 3"#,
            r#"noo_legacy_lane_uses_total{caller="trellion",kind="controller",lane="cluster_hmac_non_inference",route_class="rag"} 4"#,
            r#"noo_legacy_lane_uses_total{lane="node_token_no_cert",node="host9",route_class="cluster"} 5"#,
        ]);
        let g = parse_legacy_lane_metrics(&text);
        assert_eq!(g.start_unix, Some(1_790_000_000));
        assert_eq!(g.lanes["self_call_shared_secret"], vec![("trellion".to_string(), 10), ("worker".to_string(), 2)]);
        assert_eq!(g.lanes["cluster_hmac_non_inference"], vec![("trellion".to_string(), 7)], "route classes fold into the caller");
        assert_eq!(g.lanes["node_token_no_cert"], vec![("host9".to_string(), 5)]);
    }

    #[test]
    fn zero_everywhere_is_ok_and_prints_its_window() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 8 * 86_400, &[
            r#"noo_legacy_lane_uses_total{lane="node_token_with_cert",node="host3"} 40"#,
        ]);
        let lanes = serde_json::json!({ "since_unix": now - 9 * 86_400, "static_token": 0, "whois_non_controller": 0 });
        let fleet = vec![lane_node("host3", now, Some(lanes))];
        let c = legacy_lanes_check(Some(&text), &fleet, now);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("since gateway start 8d ago"), "{}", c.detail);
        assert!(c.detail.contains("shortest agent uptime 9d"), "{}", c.detail);
        assert!(c.detail.contains("node_token_with_cert 40"), "the comparator is shown: {}", c.detail);
        assert!(!c.detail.contains("not yet retirement evidence"), "{}", c.detail);
    }

    #[test]
    fn a_short_window_says_it_is_not_evidence_yet() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 900, &[]);
        let lanes = serde_json::json!({ "since_unix": now - 900, "static_token": 0, "whois_non_controller": 0 });
        let c = legacy_lanes_check(Some(&text), &[lane_node("host3", now, Some(lanes))], now);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("15m ago") && c.detail.contains("not yet retirement evidence"), "{}", c.detail);
    }

    #[test]
    fn any_gateway_lane_in_use_warns_naming_it_and_its_caller() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 86_400, &[
            r#"noo_legacy_lane_uses_total{caller="evolve",kind="controller",lane="cluster_hmac_non_inference",route_class="hofstadter"} 12"#,
        ]);
        let lanes = serde_json::json!({ "since_unix": now - 86_400, "static_token": 0, "whois_non_controller": 0 });
        let c = legacy_lanes_check(Some(&text), &[lane_node("host3", now, Some(lanes))], now);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("in use: cluster_hmac_non_inference"), "{}", c.detail);
        assert!(c.detail.contains("cluster_hmac_non_inference 12 (evolve 12)"), "{}", c.detail);
    }

    /// An add-on's shared-secret HMAC is REFUSED by the
    /// gateway, and a count is an add-on whose every gateway call fails —
    /// WARN, naming it.
    #[test]
    fn a_refused_add_on_hmac_warns_naming_the_add_on() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 86_400, &[
            r#"noo_legacy_lane_uses_total{caller="pai-evolve",door="controller",lane="addon_shared_secret_refused",route_class="config"} 4"#,
        ]);
        let lanes = serde_json::json!({ "since_unix": now - 86_400, "static_token": 0, "whois_non_controller": 0 });
        let c = legacy_lanes_check(Some(&text), &[lane_node("host3", now, Some(lanes))], now);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("in use: addon_shared_secret_refused"), "{}", c.detail);
        assert!(c.detail.contains("addon_shared_secret_refused 4 ("), "{}", c.detail);
    }

    /// An old `noo` CLI refused by the gateway is its own warning, naming
    /// the caller and the upgrade — not "in use", because nothing admitted it.
    #[test]
    fn a_refused_old_cli_warns_with_the_upgrade() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 86_400, &[
            r#"noo_legacy_lane_uses_total{caller="cli-posture",lane="cli_shared_secret_refused",route_class="security"} 3"#,
        ]);
        let lanes = serde_json::json!({ "since_unix": now - 86_400, "static_token": 0, "whois_non_controller": 0 });
        let c = legacy_lanes_check(Some(&text), &[lane_node("host3", now, Some(lanes))], now);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("REFUSED 3 time(s) (cli-posture 3)"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("noo upgrade --all"), "{:?}", c.remedy);
    }

    #[test]
    fn a_node_lane_in_use_warns_naming_the_node() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 86_400, &[]);
        let fleet = vec![
            lane_node("host3", now, Some(serde_json::json!({ "since_unix": now - 3600, "static_token": 7, "whois_non_controller": 0 }))),
            lane_node("host9", now, Some(serde_json::json!({ "since_unix": now - 3600, "static_token": 0, "whois_non_controller": 2 }))),
        ];
        let c = legacy_lanes_check(Some(&text), &fleet, now);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("in use: static_token, whois_non_controller"), "{}", c.detail);
        assert!(c.detail.contains("static_token 7 (host3 7)") && c.detail.contains("whois_non_controller 2 (host9 2)"), "{}", c.detail);
    }

    /// A zero nobody measured is not a zero: an online node with no report,
    /// a gateway with no window, or unreadable metrics are all WARN.
    #[test]
    fn an_unmeasured_zero_warns() {
        let now = 1_790_000_000;
        let text = lane_metrics(now - 8 * 86_400, &[]);
        let c = legacy_lanes_check(Some(&text), &[lane_node("oldagent", now, None)], now);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("not reporting: oldagent"), "{}", c.detail);
        // An offline node without the report is skipped, not counted as silent.
        let mut off = lane_node("gone", now, None);
        off["status"] = serde_json::json!("offline");
        assert_eq!(legacy_lanes_check(Some(&text), &[off], now).verdict, Verdict::Ok);
        let no_window = "noo_legacy_lane_uses_total{lane=\"node_token_no_cert\",node=\"x\",route_class=\"cluster\"} 0\n";
        let c = legacy_lanes_check(Some(no_window), &[], now);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("noo_gateway_start_time_seconds"), "{}", c.detail);
        assert_eq!(legacy_lanes_check(None, &[], now).verdict, Verdict::Warn);
    }

    /// The row's lane names are the gateway's and the agent's own: a rename
    /// on either side must fail here, not read as "0 uses" forever.
    #[test]
    fn the_lane_names_match_the_gateway_and_the_agent() {
        let gw = include_str!("../../../gateway-rust/src/legacy_lanes.rs");
        // The add-ons' refused HMAC is declared beside its door.
        let refused = include_str!("../../../gateway-rust/src/addon_hmac_refusal.rs");
        for lane in GATEWAY_LEGACY_LANES.iter().chain(GATEWAY_LANE_COMPARATORS) {
            let needle = format!("= \"{lane}\";");
            assert!(gw.contains(&needle) || refused.contains(&needle), "the gateway declares no lane {lane}");
        }
        assert!(gw.contains("pub const METRIC: &str = \"noo_legacy_lane_uses_total\";"));
        let core = include_str!("../../../gateway-rust/src/routes/core.rs");
        assert!(core.contains("noo_gateway_start_time_seconds {}"), "the start gauge's rendering moved");
        let agent = include_str!("../../../node-agent-go/internal/auth/legacy_lanes.go");
        for lane in NODE_LEGACY_LANES {
            assert!(agent.contains(&format!("= \"{lane}\"")), "node agent legacy_lanes.go has no lane {lane}");
        }
        assert!(agent.contains("\"since_unix\""));
    }

    #[test]
    fn the_logs_access_row_reads_a_refusal_as_closed_and_a_body_as_open() {
        for s in [401u16, 403] {
            let c = logs_access_check(Some(s));
            assert_eq!(c.verdict, Verdict::Ok);
            assert!(c.detail.contains("not probed here"), "the row must say what it did not prove: {}", c.detail);
        }
        let open = logs_access_check(Some(200));
        assert_eq!(open.verdict, Verdict::Fail);
        assert!(open.detail.contains("open to anyone"), "{}", open.detail);
        assert_eq!(logs_access_check(Some(503)).verdict, Verdict::Warn);
        assert_eq!(logs_access_check(None).verdict, Verdict::Warn);
    }

    /// The prefix this verb probes under is the gateway's, by source.
    #[test]
    fn the_logs_read_prefix_is_the_gateways() {
        // auth.rs carries several test modules before the constant, so the
        // whole file is read; a `pub const` is not something a test declares.
        let src = include_str!("../../../gateway-rust/src/auth.rs");
        assert_eq!(gateway_logs_read_prefix(), LOGS_QUERY_ROUTE.trim_end_matches("query"), "the prefix is the route's directory");
        let want = format!("pub const LOGS_READ_PREFIX: &str = \"{}\";", gateway_logs_read_prefix());
        assert!(src.contains(&want), "auth.rs no longer declares {want}");
    }

    #[test]
    fn ages_print_in_the_unit_an_operator_reads() {
        assert_eq!(age_str(45), "45s");
        assert_eq!(age_str(40 * 60), "40m");
        assert_eq!(age_str(3 * 3600), "3h");
        assert_eq!(age_str(3 * 86_400), "3d");
    }

    /// The shipped Postgres policy, and each way it could be weakened.
    #[test]
    fn postgres_hba_row_accepts_the_shipped_file_and_refuses_each_weakening() {
        let hba = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docker/postgres/pg_hba.conf")).unwrap();
        let compose = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docker-compose.cluster.yml")).unwrap();
        assert_eq!(postgres_hba_check(Some(&hba), Some(&compose)).verdict, Verdict::Ok);
        // planted: a plaintext-capable accept line (what initdb writes)
        let bad = format!("{hba}\nhost all all 127.0.0.1/32 trust\n");
        let c = postgres_hba_check(Some(&bad), Some(&compose));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("without TLS"), "{}", c.detail);
        // planted: TLS but no client certificate required
        let bad = hba.replace("clientcert=verify-ca", "");
        let c = postgres_hba_check(Some(&bad), Some(&compose));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("client certificate"), "{}", c.detail);
        // planted: certificate but no password
        let bad = hba.replace("scram-sha-256   clientcert=verify-ca", "trust clientcert=verify-ca");
        assert_eq!(postgres_hba_check(Some(&bad), Some(&compose)).verdict, Verdict::Fail);
        // planted: plaintext not rejected explicitly
        let bad: String = hba.lines().filter(|l| !l.starts_with("hostnossl all")).collect::<Vec<_>>().join("\n");
        assert_eq!(postgres_hba_check(Some(&bad), Some(&compose)).verdict, Verdict::Fail);
        // planted: the compose service no longer selects the file / makes TLS conditional
        let bad_compose = compose.replace("-c hba_file=/etc/noo/pg_hba.conf", "");
        assert_eq!(postgres_hba_check(Some(&hba), Some(&bad_compose)).verdict, Verdict::Fail);
        let bad_compose = compose.replace("ARGS=\"$$ARGS -c ssl=on", "if [ -n \"$$NOO_PG_TLS\" ]; then ARGS=\"$$ARGS -c ssl=on");
        assert_eq!(postgres_hba_check(Some(&hba), Some(&bad_compose)).verdict, Verdict::Fail);
        assert_eq!(postgres_hba_check(None, Some(&compose)).verdict, Verdict::Warn);
    }

    /// The live row, over the exact stderr a Postgres 18 with the shipped
    /// policy printed (2026-09-28), and what each weaker server would print.
    #[test]
    fn postgres_tls_row_reads_the_refusals() {
        const NO_CERT: &str = "psql: error: connection to server at \"172.17.0.3\", port 5432 failed: FATAL:  connection requires a valid client certificate\n";
        const PLAIN: &str = "psql: error: connection to server at \"172.17.0.3\", port 5432 failed: FATAL:  pg_hba.conf rejects connection for host \"172.17.0.1\", user \"noo\", database \"noomesh\", no encryption\n";
        assert_eq!(postgres_client_cert_check(Some((false, NO_CERT)), Some((false, PLAIN))).verdict, Verdict::Ok);
        // planted: no cert accepted outright
        assert_eq!(postgres_client_cert_check(Some((true, "")), Some((false, PLAIN))).verdict, Verdict::Fail);
        // planted: no cert, but the server went on to ask for a password (clientcert not enforced)
        let pw = "psql: error: connection to server at \"172.17.0.3\", port 5432 failed: fe_sendauth: no password supplied\n";
        let c = postgres_client_cert_check(Some((false, pw)), Some((false, PLAIN)));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not required"), "{}", c.detail);
        // planted: plaintext accepted
        assert_eq!(postgres_client_cert_check(Some((false, NO_CERT)), Some((true, ""))).verdict, Verdict::Fail);
        // not probed is a warning, never a pass
        assert_eq!(postgres_client_cert_check(None, None).verdict, Verdict::Warn);
        // the failure that is not about the transport is a warning with the line quoted
        let down = "psql: error: connection to server at \"172.17.0.3\", port 5432 failed: Connection refused\n";
        let c = postgres_client_cert_check(Some((false, down)), Some((false, PLAIN)));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("Connection refused"), "{}", c.detail);
    }

    /// By design, an erased user's archived copy is kept 30
    /// days, then purged. The row fails when the oldest copy outlives the window
    /// by more than a day, which is what a purge that is not running looks like.
    #[test]
    fn erasure_archive_row_fails_when_the_oldest_copy_outlives_the_window_plus_a_day() {
        use serde_json::json;
        let day = 86_400;
        let body = |age_days: Option<i64>| {
            json!({"retention_days": 30, "fail_after_days": 31, "rows": 4, "oldest_age_secs": age_days.map(|d| d * day + 60)})
        };
        assert_eq!(erasure_archive_check(&Value::Null).verdict, Verdict::Warn, "no answer is not a pass");
        assert_eq!(erasure_archive_check(&json!({})).verdict, Verdict::Warn);
        let empty = erasure_archive_check(&body(None));
        assert_eq!(empty.verdict, Verdict::Ok);
        assert!(empty.detail.contains("30 days"), "{}", empty.detail);
        assert_eq!(erasure_archive_check(&body(Some(3))).verdict, Verdict::Ok);
        assert_eq!(erasure_archive_check(&body(Some(30))).verdict, Verdict::Ok, "at the window");
        assert_eq!(erasure_archive_check(&body(Some(31))).verdict, Verdict::Ok, "a day of slack for the daily run");
        let stuck = erasure_archive_check(&body(Some(32)));
        assert_eq!(stuck.verdict, Verdict::Fail);
        assert!(stuck.detail.contains("32 days old") && stuck.detail.contains("30-day window + 1 day"), "{}", stuck.detail);
        assert!(stuck.remedy.as_deref().is_some_and(|r| r.starts_with("noo logs search")), "{:?}", stuck.remedy);
    }

    #[test]
    fn the_audit_log_row_judges_each_shape() {
        use serde_json::json;
        assert_eq!(audit_log_check(&Value::Null).verdict, Verdict::Warn);
        let missing = audit_log_check(&json!({"verdict": "fail", "key_present": false}));
        assert_eq!(missing.verdict, Verdict::Fail);
        assert!(missing.detail.contains("REFUSED"), "{}", missing.detail);
        let broken = audit_log_check(&json!({
            "verdict": "fail", "key_present": true,
            "breaks": [{"id": "r1", "timestamp": "t", "reason": "tampered: entry_hash does not verify"}],
            "problems": []
        }));
        assert_eq!(broken.verdict, Verdict::Fail);
        assert!(broken.detail.contains("tampered"), "{}", broken.detail);
        let good = audit_log_check(&json!({
            "verdict": "ok", "key_present": true, "ok": 12,
            "checkpoint": {"timestamp": "2026-09-30T00:00:00Z"}, "breaks": [], "problems": []
        }));
        assert_eq!(good.verdict, Verdict::Ok);
        assert!(good.detail.contains("12 row(s)"), "{}", good.detail);
        // An old-image writer inside the roll window — the
        // verdict stays ok, the row warns and names the writer and count.
        let roll = audit_log_check(&json!({
            "verdict": "ok", "key_present": true, "ok": 12,
            "checkpoint": {"timestamp": "2026-09-30T00:00:00Z"}, "breaks": [], "problems": [],
            "roll_window_rows": 2, "roll_window": [{"actor": "worker_pool", "rows": 2}]
        }));
        assert_eq!(roll.verdict, Verdict::Warn);
        assert!(
            roll.detail.contains(
                "2 row(s) written by worker_pool during the roll window, signed with the retired key \
                 (an old-image container still running)"
            ),
            "{}",
            roll.detail
        );
        assert!(roll.detail.contains("12 row(s)"), "{}", roll.detail);
        assert_eq!(roll.remedy.as_deref(), Some("noo security audit verify"));
        // A v0.2.82 writer's v1 row just after the hash-v2
        // marker — warns, named, the verdict stays ok.
        let v1 = audit_log_check(&json!({
            "verdict": "ok", "key_present": true, "ok": 12, "breaks": [], "problems": [],
            "roll_window": [], "v1_roll_window": [{"actor": "bus", "rows": 1}]
        }));
        assert_eq!(v1.verdict, Verdict::Warn);
        assert!(
            v1.detail.contains(
                "1 row(s) written by bus during the roll window, hashed v1 (time not covered) \
                 after the hash-v2 marker"
            ),
            "{}",
            v1.detail
        );
        // An empty list is no warning.
        let empty = audit_log_check(&json!({
            "verdict": "ok", "key_present": true, "ok": 12, "breaks": [], "problems": [],
            "roll_window": []
        }));
        assert_eq!(empty.verdict, Verdict::Ok);
    }
}

#[cfg(test)]
mod service_cert_names_row_tests {
    use super::*;

    /// A planted short model-cache leaf (the one found live)
    /// FAILS the row, names what it lacks, and the remedy is the bare
    /// issue-service plus the restart; a regenerated leaf passes.
    #[test]
    fn a_short_externally_reachable_leaf_fails_the_row_with_the_working_remedy() {
        let dir = std::env::temp_dir().join(format!("noo-1342-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ca = crate::pki::ClusterCa::new(dir.clone());
        ca.generate_ca("noo-test-ca", 3650).unwrap();
        ca.issue_service_cert("model-cache", &[], &[], crate::pki::DEFAULT_DAYS).unwrap();
        let leaves = externally_reachable_leaf_names(&dir, "Pop-Host", "10.0.0.5", "pop.ts.net");
        let c = service_cert_names_check(&leaves);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("model-cache lacks") && c.detail.contains("pop.ts.net") && c.detail.contains("noo-controller"), "{}", c.detail);
        let r = c.remedy.unwrap();
        assert!(r.contains("noo security pki issue-service model-cache") && r.contains("noo stack restart --force model-cache"), "{r}");
        // The remedy's own derivation produces a leaf the row accepts.
        let (names, ips) = crate::commands::pki::issue_service_names("model-cache", &[], "Pop-Host", "10.0.0.5", "pop.ts.net");
        ca.issue_service_cert("model-cache", &names, &ips, crate::pki::DEFAULT_DAYS).unwrap();
        let fixed = service_cert_names_check(&externally_reachable_leaf_names(&dir, "Pop-Host", "10.0.0.5", "pop.ts.net"));
        assert_eq!(fixed.verdict, Verdict::Ok, "{}", fixed.detail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_leaf_fails_and_an_absent_one_is_not_judged() {
        let c = service_cert_names_check(&[("nats".into(), Err("parse PEM x".into()))]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("could not be read"));
        assert_eq!(service_cert_names_check(&[]).verdict, Verdict::Ok);
    }
}

// ── config mount ─────────────────────────────────────────────────────────
//
// A rename onto `noomesh.yaml` (a single-file bind mount)
// detaches every container from the host file. The gateway checks its own
// view (`config_mount.rs`); this row checks the OTHER containers that mount
// the same file (worker, trellion, trellion-intel, evolve…).

/// What one container's view of the config mount turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigView {
    /// The container's mount entry names a deleted inode (`//deleted`).
    Deleted,
    /// The mount entry is intact; no inode was read (distroless: no `stat`).
    Intact,
    /// The inode the container reads, from `stat` inside it.
    Inode(u64),
    /// Could not be inspected, and why.
    Unchecked(String),
}

/// The verdict over every container that mounts the config. Pure: the
/// caller gathered `views`, this only decides. An inode that differs from
/// the host's, or a `//deleted` entry, is a split; a container nobody could
/// inspect is "not checked", never a pass.
pub(crate) fn config_mount_check(host_inode: Option<u64>, views: &[(String, ConfigView)]) -> Check {
    const NAME: &str = "config mount";
    let split: Vec<&str> = views
        .iter()
        .filter(|(_, v)| match v {
            ConfigView::Deleted => true,
            ConfigView::Inode(i) => host_inode.is_some_and(|h| h != *i),
            _ => false,
        })
        .map(|(n, _)| n.as_str())
        .collect();
    if !split.is_empty() {
        let services: Vec<&str> = split.iter().map(|n| n.trim_start_matches("noo-")).collect();
        return fail(
            NAME,
            format!(
                "{} read an orphaned noomesh.yaml (host and container views split; a config change is discarded at the next recreate)",
                split.join(", ")
            ),
            format!("noo stack restart --force {}", services.join(" ")),
        );
    }
    let unchecked: Vec<String> = views
        .iter()
        .filter_map(|(n, v)| match v {
            ConfigView::Unchecked(why) => Some(format!("{n} ({why})")),
            // An inode read with no host inode to compare is not a verdict.
            ConfigView::Inode(_) if host_inode.is_none() => Some(format!("{n} (host file unreadable)")),
            _ => None,
        })
        .collect();
    let checked = views.len() - unchecked.len();
    if !unchecked.is_empty() {
        return warn(
            NAME,
            format!("not checked: {}{}", unchecked.join(", "), if checked > 0 { format!("; {checked} other(s) agree with the host file") } else { String::new() }),
            Some("docker inspect each container; its mountinfo is /proc/<pid>/mountinfo".into()),
        );
    }
    ok(NAME, format!("{} container(s) read the host's noomesh.yaml", views.len()))
}

/// The mount entry for `dest` in a mountinfo table: `Some(true)` when its
/// root carries `//deleted`, `None` when `dest` is not a mount target. The
/// last matching line wins (the top of the mount stack).
pub(crate) fn mountinfo_deleted(mountinfo: &str, dest: &str) -> Option<bool> {
    mountinfo
        .lines()
        .rev()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 4 && f[4] == dest).then(|| f[3].ends_with("//deleted"))
        })
}

/// `(container, pid, destination)` for every running container with a bind
/// mount whose source is `host_path`. `None` when docker cannot be asked.
fn config_mounters(host_path: &std::path::Path) -> Option<Vec<(String, u32, String)>> {
    let ids = Command::new("docker").args(["ps", "-q"]).output().ok().filter(|o| o.status.success())?;
    let ids: Vec<String> = String::from_utf8_lossy(&ids.stdout).split_whitespace().map(String::from).collect();
    if ids.is_empty() {
        return Some(Vec::new());
    }
    let out = Command::new("docker")
        .args(["inspect", "-f", "{{.Name}} {{.State.Pid}} {{json .Mounts}}"])
        .args(&ids)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let canon = std::fs::canonicalize(host_path).ok();
    let mut found = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut p = line.splitn(3, ' ');
        let (Some(name), Some(pid), Some(mounts)) = (p.next(), p.next(), p.next()) else { continue };
        let Ok(Value::Array(mounts)) = serde_json::from_str::<Value>(mounts) else { continue };
        for m in &mounts {
            let src = std::path::Path::new(m["Source"].as_str().unwrap_or(""));
            if m["Type"] == "bind" && (src == host_path || canon.as_deref() == Some(src)) {
                if let Some(dest) = m["Destination"].as_str() {
                    found.push((name.trim_start_matches('/').to_string(), pid.parse().unwrap_or(0), dest.to_string()));
                }
            }
        }
    }
    Some(found)
}

/// One container's view. The container's own mount table is read from the
/// host (`/proc/<pid>/mountinfo` is readable by the operator without sudo,
/// where `/proc/<pid>/root` is not), so a distroless nonroot image needs
/// nothing inside it; `stat` inside is the fallback.
fn config_view(name: &str, pid: u32, dest: &str) -> ConfigView {
    if pid != 0 {
        if let Ok(mi) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) {
            match mountinfo_deleted(&mi, dest) {
                Some(true) => return ConfigView::Deleted,
                Some(false) => return ConfigView::Intact,
                None => {}
            }
        }
    }
    let out = Command::new("docker").args(["exec", name, "stat", "-c", "%i", dest]).output();
    match out {
        Ok(o) if o.status.success() => match String::from_utf8_lossy(&o.stdout).trim().parse() {
            Ok(i) => ConfigView::Inode(i),
            Err(_) => ConfigView::Unchecked("stat gave no inode".into()),
        },
        _ => ConfigView::Unchecked("mountinfo unreadable and no stat in the image".into()),
    }
}

/// The "config mount" row, or `None` when docker is unavailable or nothing
/// mounts the config (nothing to judge).
pub(crate) fn config_mount_row() -> Option<Check> {
    use std::os::unix::fs::MetadataExt;
    let host = crate::commands::systems::manifest_path();
    let mounters = config_mounters(&host)?;
    if mounters.is_empty() {
        return None;
    }
    let host_inode = std::fs::metadata(&host).ok().map(|m| m.ino());
    let views: Vec<(String, ConfigView)> =
        mounters.iter().map(|(n, pid, dest)| (n.clone(), config_view(n, *pid, dest))).collect();
    Some(config_mount_check(host_inode, &views))
}

#[cfg(test)]
mod config_mount_tests {
    #[test]
    fn data_root_policy_row_reports_the_nodes_own_check() {
        use serde_json::json;
        assert!(super::data_root_policy_row(&json!({"id": "n", "data_roots": {}})).is_none(), "older agent: no row");
        let good = json!({"id": "n", "data_roots": {"noo_data_root": "/var/lib/noo",
            "policy": {"mode": "warn", "ok": true, "problems": []}}});
        assert_eq!(super::data_root_policy_row(&good).unwrap().verdict, super::Verdict::Ok);
        let owner = json!({"id": "host9", "data_roots": {"noo_data_root": "/data/noo",
            "policy": {"mode": "warn", "ok": false, "problems": [{"code": "wrong_owner", "detail": "owned by uid 1000"}]}}});
        let c = super::data_root_policy_row(&owner).unwrap();
        assert_eq!(c.verdict, super::Verdict::Warn);
        assert!(c.remedy.as_deref().unwrap().contains("install -d -o noo-agent"), "{:?}", c.remedy);
        let shape = json!({"id": "host6", "data_roots": {"noo_data_root": "/Users/x/noomesh/data",
            "policy": {"mode": "enforce", "ok": false, "problems": [{"code": "not_dedicated", "detail": "not noo"}]}}});
        let c = super::data_root_policy_row(&shape).unwrap();
        assert_eq!(c.verdict, super::Verdict::Fail);
        assert!(c.remedy.as_deref().unwrap().contains("--move-data"), "{:?}", c.remedy);
        assert!(c.remedy.as_deref().unwrap().contains("'/Users/x/noomesh'"), "{:?}", c.remedy);
    }

    #[test]
    fn an_undeclared_legacy_root_is_declared_where_it_is_not_moved() {
        use serde_json::json;
        let n = json!({"id": "host9", "data_roots": {"noo_data_root": "/data/noo", "noo_data_root_source": "legacy_default",
            "policy": {"mode": "warn", "ok": false, "problems": [{"code": "undeclared_root", "detail": "kept /data/noo"}]}}});
        let c = super::data_root_policy_row(&n).unwrap();
        let r = c.remedy.as_deref().unwrap();
        assert!(r.contains("set-config host9 --data-root /data/noo") && !r.contains("--move-data"), "{r}");
    }

    use super::*;

    fn v(n: &str, view: ConfigView) -> (String, ConfigView) {
        (n.to_string(), view)
    }

    #[test]
    fn an_orphaned_view_fails_and_names_the_containers_and_the_remedy() {
        let c = config_mount_check(
            Some(10),
            &[v("noo-gateway", ConfigView::Intact), v("noo-worker", ConfigView::Deleted), v("noo-trellion", ConfigView::Inode(9))],
        );
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-worker") && c.detail.contains("noo-trellion") && !c.detail.contains("noo-gateway"));
        assert_eq!(c.remedy.as_deref(), Some("noo stack restart --force worker trellion"));
    }

    #[test]
    fn agreeing_views_pass() {
        let c = config_mount_check(Some(10), &[v("noo-worker", ConfigView::Inode(10)), v("noo-gateway", ConfigView::Intact)]);
        assert_eq!(c.verdict, Verdict::Ok);
    }

    #[test]
    fn a_container_nobody_could_inspect_is_not_a_pass() {
        let c = config_mount_check(Some(10), &[v("noo-worker", ConfigView::Intact), v("noo-x", ConfigView::Unchecked("no stat".into()))]);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("not checked") && c.detail.contains("noo-x"));
        let all = config_mount_check(Some(10), &[v("noo-x", ConfigView::Unchecked("no stat".into()))]);
        assert_eq!(all.verdict, Verdict::Warn);
    }

    #[test]
    fn a_failure_outranks_an_unchecked_neighbour() {
        let c = config_mount_check(Some(10), &[v("noo-a", ConfigView::Unchecked("x".into())), v("noo-b", ConfigView::Deleted)]);
        assert_eq!(c.verdict, Verdict::Fail);
    }

    #[test]
    fn an_inode_with_no_host_inode_is_not_a_verdict() {
        let c = config_mount_check(None, &[v("noo-a", ConfigView::Inode(3))]);
        assert_eq!(c.verdict, Verdict::Warn);
        // ...but a deleted mount entry needs no host inode to be a split.
        assert_eq!(config_mount_check(None, &[v("noo-a", ConfigView::Deleted)]).verdict, Verdict::Fail);
    }

    #[test]
    fn mountinfo_names_the_deleted_root_of_the_right_mount() {
        let mi = "1698 1681 259:3 /home/u/.noo/noomesh.yaml//deleted /app/noomesh.yaml rw,noatime - ext4 /dev/x rw\n\
                  1699 1681 259:3 /home/u/.noo/other.yaml /app/other.yaml rw - ext4 /dev/x rw\n";
        assert_eq!(mountinfo_deleted(mi, "/app/noomesh.yaml"), Some(true));
        assert_eq!(mountinfo_deleted(mi, "/app/other.yaml"), Some(false));
        assert_eq!(mountinfo_deleted(mi, "/app/missing"), None);
        assert_eq!(mountinfo_deleted("garbage", "/app/noomesh.yaml"), None);
    }
}

#[cfg(test)]
mod self_agent_lane_tests {
    use super::*;

    #[test]
    fn a_rail_installed_self_node_passes() {
        let c = self_agent_lane_check("pop-os", &[], None, Some("rail"), true);
        assert_eq!(c.verdict, Verdict::Ok);
        assert_eq!(c.name, "self-agent lane");
        assert!(c.detail.starts_with("rail"), "{}", c.detail);
    }

    #[test]
    fn onboards_first_install_reads_as_the_rail() {
        let c = self_agent_lane_check("pop-os", &[], None, Some("onboard"), true);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.starts_with("rail"), "{}", c.detail);
    }

    /// pop-os after the 0.6.2 roll: units in place, the last install was
    /// the old local lane (its state file, no lane record).
    #[test]
    fn the_local_lane_after_onboard_fails_with_the_rail_as_the_remedy() {
        let c = self_agent_lane_check("pop-os", &[], None, None, true);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("local"), "{}", c.detail);
        assert!(c.detail.contains("local-lane.state"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo cluster provision pop-os"));
        assert_eq!(self_agent_lane_check("pop-os", &[], None, Some("local"), false).verdict, Verdict::Fail);
    }

    #[test]
    fn missing_pull_units_fail_with_onboard_as_the_remedy() {
        let c = self_agent_lane_check("pop-os", &["noo-fetch.timer".to_string()], None, Some("rail"), false);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-fetch.timer"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo onboard --only services"));
    }

    /// The gateway verifying against another cert (or none) fails the row
    /// even when the last install was the rail.
    #[test]
    fn the_gateways_view_must_match_the_local_cert() {
        let p = crate::commands::provision::SelfViewProblem {
            code: "gateway_no_self_cert", msg: "the gateway cannot read this node's birth cert".into(),
            remedy: "noo upgrade --stack".into(),
        };
        let c = self_agent_lane_check("pop-os", &[], Some(&p), Some("rail"), false);
        assert_eq!(c.verdict, Verdict::Fail);
        assert_eq!(c.remedy.as_deref(), Some("noo upgrade --stack"));
    }
}
