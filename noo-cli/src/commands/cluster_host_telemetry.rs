// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster host-telemetry apply` — the operator's one command that
//! switches off tailscaled's client-log upload on existing nodes, over the
//! signed pull rail (docs/security/telemetry.md, "Host software").
//!
//! Why a verb and not part of an upgrade: the applier restarts tailscaled,
//! which drops the node's tailnet link for a few seconds, and on the
//! controller's own node drops every node's path to the controller. That is
//! the operator's call, so nothing sends this bundle unattended. The verb:
//!
//! - confirms first (`-y` to skip),
//! - rolls nodes one at a time and waits for each node's next heartbeat
//!   before touching the next; a node that does not come back stops the roll,
//! - applies the controller's own node LAST and only with
//!   `--include-controller`, after a warning.
//!
//! The node-side half is the `host-telemetry` kind in `scripts/noo-apply.sh`
//! (Linux) and `node_fetch::host_telemetry_darwin` (Mac). An opt-in marker
//! file on the node (`vendor::TAILSCALE_UPLOAD_MARKER`) makes it a no-op there.

use std::time::Duration;

use serde_json::Value;

use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// How long to wait for a node to be heard again after its tailscaled restart.
const COME_BACK_SECS: u64 = 150;

/// Who `plan_targets` selected, in apply order, and who it left out and why.
#[derive(Debug, PartialEq)]
pub(crate) struct Plan {
    /// Remote nodes first (registry order), the controller's own node last.
    pub order: Vec<String>,
    /// The controller's own node, when it is in `order` (always the last entry).
    pub controller: Option<String>,
    /// `(node, why)` for nodes a `--all` left out.
    pub skipped: Vec<(String, String)>,
}

/// Pure target selection over the registry rows. `is_self` says which node is
/// the controller's own device.
pub(crate) fn plan_targets(
    registered: &[Value],
    named: &[String],
    all: bool,
    include_controller: bool,
    is_self: &dyn Fn(&str) -> bool,
) -> Result<Plan, String> {
    let id_of = |n: &Value| n["id"].as_str().map(str::to_string);
    let mut order: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    if !named.is_empty() {
        for want in named {
            let Some(n) = registered.iter().find(|n| id_of(n).is_some_and(|i| i.eq_ignore_ascii_case(want))) else {
                return Err(format!("'{want}' is not a registered node (see `noo cluster status`)"));
            };
            let id = id_of(n).unwrap();
            if !order.contains(&id) {
                order.push(id);
            }
        }
    }
    if all {
        for n in registered {
            let Some(id) = id_of(n) else { continue };
            if order.contains(&id) {
                continue;
            }
            if super::cluster_provision::is_companion(n) {
                skipped.push((id, "a companion: no host agent, no pull rail".into()));
            } else if !matches!(n["status"].as_str(), Some("online") | Some("busy")) {
                skipped.push((id, format!("{} — it could not collect the bundle now", n["status"].as_str().unwrap_or("not online"))));
            } else {
                order.push(id);
            }
        }
    }
    let mut controller = None;
    if let Some(pos) = order.iter().position(|n| is_self(n)) {
        let me = order.remove(pos);
        if !include_controller {
            if !named.is_empty() && named.iter().any(|w| w.eq_ignore_ascii_case(&me)) {
                return Err(format!(
                    "'{me}' is the controller's own node: restarting its tailscaled drops EVERY node's path to the \
                     controller for a few seconds. Add --include-controller to apply it, last, after the others"));
            }
            skipped.push((me, "the controller's own node — pass --include-controller to apply it, last".into()));
        } else {
            order.push(me.clone());
            controller = Some(me);
        }
    } else if include_controller {
        return Err("--include-controller was given but the controller's own node is not among the targets \
                    (name it, or use --all, and make sure it is online)".into());
    }
    if order.is_empty() {
        return Err("no nodes to apply to".into());
    }
    Ok(Plan { order, controller, skipped })
}

/// The `host-telemetry` payload: bound to one node, like fleet-secrets.
pub(crate) fn payload_for(node: &str) -> Vec<u8> {
    format!("NODE={node}\n").into_bytes()
}

/// `noo cluster host-telemetry apply [<node>...] [--all] [--include-controller] [-y]`
pub fn cluster_host_telemetry_apply(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut named: Vec<String> = Vec::new();
    let (mut all, mut include_controller, mut yes) = (false, false, false);
    for tok in args {
        match tok.as_str() {
            "--all" => all = true,
            "--include-controller" => include_controller = true,
            "-y" | "--yes" | "--force" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => named.push(t.to_string()),
        }
    }
    if named.is_empty() && !all {
        return Err(Unhandled);
    }
    let body = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
    let registered: Vec<Value> = body["nodes"].as_array().cloned().unwrap_or_default();
    let plan = match plan_targets(&registered, &named, all, include_controller, &|n| crate::role::is_self_node(n)) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "bad_targets", &e, None),
    };
    if !g.json {
        for (n, why) in &plan.skipped {
            println!("{}", ui::status_line(ui::Glyph::Step, &format!("skipping {n}: {why}")));
        }
        println!("{}", ui::muted(
            "Switches off tailscaled's log upload (Tailscale support will not be able to read this node's logs). \
             A node with /etc/noo/allow-tailscale-log-upload is left alone. tailscaled restarts only where it changed; \
             each node's tailnet link drops for a few seconds."));
        if let Some(c) = &plan.controller {
            ui::warned(&format!(
                "'{c}' is the controller's own node and goes LAST: restarting its tailscaled drops EVERY node's path to the \
                 controller for a few seconds. Run this at the controller's console if you can, not over the tailnet"));
        }
    }
    let mut target = plan.order.join(", ");
    if plan.controller.is_some() {
        target.push_str(" (controller last)");
    }
    super::confirm_destructive(g, yes, "restart tailscaled (log upload off) on", &target);

    let payload = |node: &str| -> Result<Vec<u8>, String> { Ok(payload_for(node)) };
    let wait = |node: &str, d: &super::security_local::CertDelivery| -> Result<String, String> {
        confirm_effect_via_heartbeat(g, node, d)
    };
    super::cluster_provision::deliver_kind_to_nodes_then(
        g, &plan.order, "host-telemetry", &payload,
        "an applier older than this kind refuses it (exit 76) — upgrade it with `noo cluster upgrade-applier`, \
         or run the command `noo cluster verify` prints on the node",
        Some(&wait),
    )
}

/// The gate for one node: did the switch TAKE? The success test is the effect,
/// not the apply report. The report is sent by the applier while tailscaled is
/// restarting and can be lost (the node then reads "fetched, apply NOT
/// confirmed"), but the node's own heartbeat carries the very fact `noo
/// cluster verify` reads for its "host telemetry" row (`hostd.host.telemetry
/// .tailscale_logs`), so a heartbeat heard AFTER the apply that says `off` is
/// proof from the node itself. Runs for `Applied` too: a heartbeat that says
/// `on` after an exit-0 apply is a failure to report, not a success.
fn confirm_effect_via_heartbeat(
    g: &Globals,
    node: &str,
    d: &super::security_local::CertDelivery,
) -> Result<String, String> {
    let applied = matches!(d, super::security_local::CertDelivery::Applied);
    confirm_effect(
        node,
        applied,
        super::cluster_verify::now_unix(),
        &mut || super::security_local::cluster_node_entry(g, node),
        &mut || std::thread::sleep(Duration::from_secs(POLL_SECS)),
        COME_BACK_SECS / POLL_SECS,
    )
}

const POLL_SECS: u64 = 5;

/// Pure over its inputs (node entry source, sleep) so the verdicts are
/// testable against a mocked gateway. `applied`: the apply report arrived, so
/// a node that does not report the fact at all (old hostd) is accepted on its
/// heartbeat alone, as before; without a report the fact is the only proof.
fn confirm_effect(
    node: &str,
    applied: bool,
    since: i64,
    entry: &mut dyn FnMut() -> Option<Value>,
    sleep: &mut dyn FnMut(),
    polls: u64,
) -> Result<String, String> {
    let (mut heard, mut saw_on) = (false, false);
    for _ in 0..polls {
        if let Some(n) = entry() {
            if super::cluster_verify::heard_since(&n, since) {
                heard = true;
                let tel = &n["hostd"]["host"]["telemetry"];
                if tel["tailscale_logs_operator_choice"].as_bool() == Some(true) {
                    return Ok("left on by operator choice (the opt-in marker is present) — nothing to apply".into());
                }
                match tel["tailscale_logs"].as_str() {
                    Some("off") => return Ok("applied — heartbeat confirms log upload off".into()),
                    Some("on") => saw_on = true,
                    _ => {}
                }
            }
        }
        sleep();
    }
    if !heard {
        return Err(format!("no heartbeat within {COME_BACK_SECS}s of the apply — the roll stops here; check `noo cluster verify {node}`"));
    }
    if saw_on {
        return Err(format!("heartbeat still reports tailscaled's log upload ON {COME_BACK_SECS}s after the bundle was collected — it did not take; check `noo cluster verify {node}`"));
    }
    if applied {
        return Ok("heartbeat is back (this node does not report the log-upload fact)".into());
    }
    Err(format!("heartbeat is back but does not report the log-upload fact, so the effect is unproven; check `noo cluster verify {node}`"))
}

/// Group stub: `noo cluster host-telemetry` alone prints the real usage.
pub fn cluster_host_telemetry_usage(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Usage,
        "usage",
        "noo cluster host-telemetry needs a subaction",
        Some("apply [<node>...] [--all] [--include-controller] [-y]   switch off tailscaled's log upload over the pull rail"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn n(id: &str, status: &str) -> Value {
        json!({"id": id, "status": status})
    }
    fn fleet() -> Vec<Value> {
        vec![n("host2", "online"), n("host8", "online"), n("host3", "busy"), n("host6", "offline"),
             json!({"id": "host9-sensors", "status": "online", "tier": 5})]
    }
    fn me(x: &str) -> bool { x == "host8" }

    #[test]
    fn all_takes_the_online_remote_nodes_and_leaves_the_controller_out_by_default() {
        let p = plan_targets(&fleet(), &[], true, false, &me).unwrap();
        assert_eq!(p.order, ["host2", "host3"]);
        assert!(p.controller.is_none());
        let why: Vec<&str> = p.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert!(why.contains(&"host8") && why.contains(&"host6") && why.contains(&"host9-sensors"), "{:?}", p.skipped);
    }

    #[test]
    fn the_controller_goes_last_and_only_with_the_flag() {
        let p = plan_targets(&fleet(), &[], true, true, &me).unwrap();
        assert_eq!(p.order, ["host2", "host3", "host8"], "the controller must be applied last");
        assert_eq!(p.controller.as_deref(), Some("host8"));
        // Named first, still last.
        let p = plan_targets(&fleet(), &["host8".into(), "host2".into()], false, true, &me).unwrap();
        assert_eq!(p.order, ["host2", "host8"]);
    }

    #[test]
    fn naming_the_controller_without_the_flag_is_refused_with_the_reason() {
        let e = plan_targets(&fleet(), &["host8".into()], false, false, &me).unwrap_err();
        assert!(e.contains("--include-controller") && e.contains("EVERY node"), "{e}");
    }

    #[test]
    fn the_flag_without_a_controller_in_the_targets_is_an_error_not_a_silent_no_op() {
        let e = plan_targets(&fleet(), &["host2".into()], false, true, &me).unwrap_err();
        assert!(e.contains("--include-controller"), "{e}");
    }

    #[test]
    fn an_unknown_node_is_refused() {
        let e = plan_targets(&fleet(), &["nope".into()], false, false, &me).unwrap_err();
        assert!(e.contains("not a registered node"), "{e}");
    }

    #[test]
    fn the_payload_names_the_node_the_applier_checks() {
        assert_eq!(payload_for("host2"), b"NODE=host2\n");
        assert!(super::super::node_fetch::host_telemetry_binding(&String::from_utf8(payload_for("host2")).unwrap(), "host2").is_ok());
    }

    /// The verb rolls ONE node at a time and gates each on a heartbeat: the
    /// gate must be handed to the shared skeleton, and the skeleton must stop
    /// the roll when the gate fails. Source pins, because the skeleton talks
    /// to a live gateway.
    #[test]
    fn each_node_is_gated_on_its_heartbeat_before_the_next() {
        let me_src = include_str!("cluster_host_telemetry.rs");
        let code = me_src.split("#[cfg(test)]").next().unwrap();
        assert!(code.contains("deliver_kind_to_nodes_then(") && code.contains("Some(&wait)"), "no per-node gate handed to the skeleton");
        assert!(code.contains("confirm_effect_via_heartbeat"), "the gate is no longer the effect test");
        let sk = include_str!("cluster_provision_subprocess.rs");
        assert!(sk.contains("the roll stopped at"), "the skeleton no longer stops the roll at a node that did not come back");
    }

    const T: i64 = 1_800_000_000;
    /// unix -> `YYYY-MM-DDTHH:MM:SSZ`, for canned heartbeats.
    fn stamp(t: i64) -> String {
        let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, (secs % 3600) / 60, secs % 60)
    }

    fn beat(since: i64, logs: Option<&str>) -> Value {
        let mut n = json!({"id": "host2", "last_heartbeat": stamp(since + 1)});
        if let Some(l) = logs {
            n["hostd"] = json!({"alive": true, "host": {"telemetry": {"tailscale_logs": l}}});
        }
        n
    }
    /// Runs `confirm_effect` against a scripted gateway: the i-th poll returns `script[i]`
    /// (the last repeats).
    fn run(script: Vec<Option<Value>>, applied: bool) -> Result<String, String> {
        let mut i = 0usize;
        confirm_effect("host2", applied, T, &mut || { let v = script[i.min(script.len() - 1)].clone(); i += 1; v }, &mut || {}, 30)
    }

    #[test]
    fn a_fact_that_flips_to_off_is_success_even_with_no_apply_report() {
        let r = run(vec![Some(beat(T, Some("on"))), Some(beat(T, Some("on"))), Some(beat(T, Some("off")))], false);
        assert_eq!(r.unwrap(), "applied — heartbeat confirms log upload off");
    }

    #[test]
    fn a_fact_that_stays_on_fails_with_the_verify_hint() {
        let e = run(vec![Some(beat(T, Some("on")))], false).unwrap_err();
        assert!(e.contains("still reports") && e.contains("ON") && e.contains("noo cluster verify host2"), "{e}");
        // An exit-0 apply report does not excuse a node that still uploads.
        assert!(run(vec![Some(beat(T, Some("on")))], true).is_err());
    }

    #[test]
    fn a_stale_heartbeat_proves_nothing() {
        let stale = json!({"id": "host2", "last_heartbeat": stamp(T - 500),
                           "hostd": {"host": {"telemetry": {"tailscale_logs": "off"}}}});
        assert!(run(vec![Some(stale)], false).unwrap_err().contains("no heartbeat"));
    }

    #[test]
    fn an_unreported_fact_is_unproven_without_a_report_and_fine_with_one() {
        assert!(run(vec![Some(beat(T, None))], false).is_err());
        assert!(run(vec![Some(beat(T, None))], true).is_ok());
    }
}
