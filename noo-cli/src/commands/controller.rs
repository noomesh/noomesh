// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo controller promote|demote` — the warm-standby failover pair
//! (operator doctrine, 2026-09-01): the stable tailnet ROLE NAME is the
//! entire realignment mechanism. Nodes pin CONTROLLER_URL to it, gateway
//! certs already carry it as a SAN (pki.rs bakes "noo-controller" in), so
//! promotion = claim the name + rebind serve/URL; the fleet reconverges
//! with zero per-node edits. The DATA half (postgres replication) is
//! bootstrap-standby.sh's job and is only pointed at here.

use std::process::Command;

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui;

const ROLE_NAME: &str = "noo-controller";

fn ts_set_hostname(name: &str) -> bool {
    Command::new("sudo")
        .args(["tailscale", "set", &format!("--hostname={name}")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `noo controller promote [--name N] [--restage-nodes] [-y|--yes]`
pub fn controller_promote(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name = ROLE_NAME.to_string();
    let mut restage = false;
    let mut yes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = it.next().cloned().unwrap_or_else(|| ROLE_NAME.into()),
            "--restage-nodes" => restage = true,
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    let root = crate::envfile::repo_root();
    if !root.join(".env").exists() {
        fail(g.json, ExitCode::Generic, "no_install",
            "no install found at the resolved root — promote runs ON the standby controller",
            Some("onboard this box first (noo onboard --standalone)"));
    }

    // Renames this box's tailnet device and restarts the gateway.
    super::confirm_prompt(g, yes, &format!(
        "Promote this box: rename its tailnet device to '{name}', rebind serve and restart the gateway?"));

    // Multi-phase mutation (guide §5 Rhythm): Role → Data Plane → Restage.
    if !g.json { println!("{}", ui::phase("Role")); }
    ui::step(&format!("claiming the role name '{name}' on the tailnet (one sudo)"));
    if !ts_set_hostname(&name) {
        fail(g.json, ExitCode::Generic, "rename_failed",
            &format!("could not claim '{name}' — is the OLD controller still holding it?"),
            Some("demote it there first (noo controller demote), or delete its device record in the admin console, then re-run"));
    }
    let (dns, ip) = match crate::onboard::steps::tailscale_identity() {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "no_identity",
            &format!("tailnet identity unavailable after rename: {e}"), None),
    };
    ui::done(&format!("tailnet identity {dns} ({ip})"));

    // Gateway cert with the new identity (role name is ALWAYS a SAN).
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    match ca.issue_gateway_cert(&dns, &ip, crate::pki::DEFAULT_DAYS, &[], &[]) {
        Ok(_) => ui::done(&format!("gateway cert re-issued (SANs: {dns}, {ip}, {ROLE_NAME}, …)")),
        Err(e) => ui::warned(&format!("cert re-issue failed ({e}) — the baked {ROLE_NAME} SAN on the existing cert may suffice")),
    }

    // Advertised URL: env + yaml (the enrollment-blob source).
    let url = format!("https://{dns}:8080");
    let _ = crate::onboard::standalone::upsert_env(&root, "NOO_GATEWAY_URL", &url);
    rewrite_yaml_gateway_url(&root, &url);
    ui::done(&format!("advertised gateway URL {url}"));

    // i545 72: the advertised door is the tailnet, so the stack must listen
    // there. Bind mode local kept the gateway on 127.0.0.1 while serve and
    // the URL above pointed at the tailnet address: "promoted", refused.
    match crate::onboard::standalone::upsert_env(&root, "NOO_BIND_MODE", PROMOTED_BIND_MODE) {
        Ok(()) => ui::done(&format!("bind mode {PROMOTED_BIND_MODE} (NOO_BIND_MODE): the stack listens on the tailnet address")),
        Err(e) => ui::warned(&format!(
            "could not set NOO_BIND_MODE={PROMOTED_BIND_MODE} in .env ({e}) — set it, then: noo stack restart --force"
        )),
    }

    // i545 75/81: the services a remote node reaches (nats, redis, postgres,
    // model-cache) verify by the tailnet name too; only the gateway's leaf
    // was re-issued, so an enrolled node failed TLS on the bus.
    reissue_reachable_service_certs(&ca);

    // Serve mappings — the SAME implementation onboard uses
    // (tailnet_serve.rs). The copy that lived here discarded both exit
    // statuses and printed "rebound" from intent: on the 2026-09-01
    // cutover tailscale refused (no root, no operator grant), nothing was
    // written, and this line still said success.
    let plan = crate::tailnet_serve::Plan { ip: ip.to_string(), gw_port: 8080, instance: String::new() };
    match crate::tailnet_serve::apply(&plan, false) {
        Ok(applied) => {
            if applied.granted_operator {
                println!("{}", ui::note("granted tailscale operator to this user (one-time) — mappings written on retry"));
            }
            ui::done("tailscale serve rebound to the gateway (/, /mcp, /mcp/user, /mcp/operator)");
        }
        Err(f) => {
            ui::warned(&format!("tailscale serve NOT rebound — `{}` failed: {}", f.command, f.detail));
            println!("    apply it manually:");
            for line in plan.manual_lines() {
                println!("      {line}");
            }
        }
    }
    match crate::tailnet_serve::status(8080) {
        crate::tailnet_serve::Status::Mapped { fronts_gateway: true, .. } => {}
        crate::tailnet_serve::Status::Mapped { paths, .. } => ui::warned(&format!(
            "tailscale serve maps {} but none of it reaches the gateway on :8080", paths.join(", "))),
        crate::tailnet_serve::Status::NotMapped => ui::warned(
            "tailscale serve status shows NO mapping — this controller is not fronted on the tailnet"),
        crate::tailnet_serve::Status::Unknown(e) => println!("{}", ui::note(&format!("serve status unreadable: {e}"))),
    }
    // Recreate, not restart: a restart keeps the old port bindings, and the
    // bind mode and every re-issued leaf take effect only on a recreate.
    if restart_stack_force() {
        ui::done("stack recreated on the new bind mode and certificates");
    } else {
        ui::warned("the stack did not recreate — run: noo stack restart --force");
    }
    ui::close_done(&format!("role '{name}' claimed — this box is the controller"));

    // i545 74/89/92: this box's OWN node agent follows the new identity:
    // its env still named localhost and its cert lacked the tailnet address
    // and name, so the enroll line promote printed failed at admission.
    // Restaged over the rail (the same lane `noo upgrade` uses for it),
    // always, not only with --restage-nodes.
    let self_node = self_node_id(&crate::onboard::env::read_env_key(&root.join(".env"), "NODE_ID"));
    if !g.json { println!("{}", ui::phase("Self Node")); }
    let self_failed = if crate::commands::provision::pull_units_missing(&self_node).is_empty() {
        match crate::commands::upgrade::provision_one(g, &self_node, &[]) {
            Ok(0) => false,
            _ => {
                ui::warned(&format!("{self_node}'s agent was not restaged — run: noo cluster provision {self_node}"));
                true
            }
        }
    } else {
        println!("{}", ui::note(&format!("{self_node} has no node agent on this box — install it: noo onboard --only services")));
        false
    };

    // The DATA half is not this command's to run; say where it lives.
    if !g.json { println!("{}", ui::phase("Data Plane")); }
    println!("{}", ui::note("if this standby replicates postgres, scripts/bootstrap-standby.sh has the switchover half"));
    println!("{}", ui::note("nothing to do here otherwise — the database this box already holds is the live one"));

    // Fleet realignment: nodes that pin the ROLE name reconverge on their
    // own; anything pinned to the old machine name needs a bundle restage.
    if !g.json { println!("{}", ui::phase("Restage")); }
    let nodes: Vec<String> = inventory_nodes(g).into_iter().filter(|n| !n.eq_ignore_ascii_case(&self_node)).collect();
    let mut failed: Vec<String> = Vec::new();
    if nodes.is_empty() {
        println!("{}", ui::note("no nodes registered with this controller — nothing to restage"));
    } else if restage {
        for n in &nodes {
            // Each node is an item; cluster provision prints the item label
            // and its indented steps. A blank line separates nodes.
            println!();
            match crate::commands::cluster_provision(g, std::slice::from_ref(n)) {
                Ok(0) => {}
                _ => failed.push(n.clone()),
            }
        }
    } else {
        println!("{}", ui::note(&format!("nodes in inventory not restaged: {}", nodes.join(", "))));
        println!("{}", ui::note("nodes pinned to the role name reconverge on their own; anything pinned to the old machine name needs a bundle restage"));
    }

    if self_failed {
        failed.push(self_node.clone());
    }
    if failed.is_empty() {
        ui::close_done("promoted");
    } else {
        ui::close_warned(&format!("promoted, but restage failed for: {}", failed.join(", ")));
    }
    let mut owned: Vec<String> = Vec::new();
    if !nodes.is_empty() && !restage {
        owned.extend(nodes.iter().map(|n| format!("noo cluster provision {n}")));
    }
    let mut entries: Vec<(&str, &str)> = owned
        .iter()
        .map(|c| (c.as_str(), "restages this node's bundle against the new controller"))
        .collect();
    if !nodes.is_empty() && !restage {
        entries.push(("noo controller promote --restage-nodes", "or re-run promote to restage every node in one go"));
    }
    entries.push(("noo cluster status", "every node should report online against this controller within a few heartbeats"));
    entries.push(("noo health", "the gateway on the new cert answers healthy"));
    entries.push(("noo controller demote", "on the OLD controller, if it is still up: release the role name and serve mappings"));
    ui::guide(&entries);
    Ok(0)
}

/// The bind mode a promoted controller runs in: its door is the tailnet.
pub(crate) const PROMOTED_BIND_MODE: &str = "tailnet";

/// The controller's own node id, as onboarding names it (`NODE_ID` in the
/// install's .env, else `controller`).
pub(crate) fn self_node_id(env_node_id: &str) -> String {
    let n = env_node_id.trim();
    if n.is_empty() { "controller".to_string() } else { n.to_string() }
}

/// Re-issue each externally reachable service's leaf that lacks this box's
/// derived names (now including the tailnet name), one line each, as
/// `noo upgrade --stack` does. Returns the services re-issued.
fn reissue_reachable_service_certs(ca: &crate::pki::ClusterCa) -> Vec<String> {
    use crate::onboard::steps::NamesOutcome;
    let (hostname, node_ip, ts) = crate::onboard::steps::local_cert_identity();
    let mut done = Vec::new();
    for svc in crate::onboard::steps::EXTERNALLY_REACHABLE {
        match crate::onboard::steps::ensure_service_cert_names(ca, svc, &hostname, &node_ip, &ts) {
            Ok(NamesOutcome::Reissued { missing, .. }) => {
                ui::done(&format!("re-issued the {svc} service certificate to add {}", missing.join(", ")));
                done.push((*svc).to_string());
            }
            Ok(NamesOutcome::Covered | NamesOutcome::NoLeaf) => {}
            Err(e) => ui::warned(&format!(
                "{svc} service certificate could not be re-issued ({e}) — then: noo security pki issue-service {svc}, then: noo stack restart --force {svc}"
            )),
        }
    }
    done
}

/// `noo stack restart --force` in a child process: it reports failures by
/// exiting, which must not end promote.
fn restart_stack_force() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    Command::new(exe).args(["stack", "restart", "--force"]).status().map(|s| s.success()).unwrap_or(false)
}

/// `noo controller demote [--name N] [-y|--yes]` — release the role name (defaults the
/// machine hostname back) + serve reset. The stack is left running (warm
/// standby); stop it with `noo stack stop` if this box is retiring.
pub fn controller_demote(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let os_host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let mut name = os_host.clone();
    let mut yes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = it.next().cloned().unwrap_or(os_host.clone()),
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    if name.is_empty() {
        fail(g.json, ExitCode::Generic, "no_name", "could not determine a hostname to demote to", Some("pass --name <hostname>"));
    }
    // Renames the tailnet device and resets `tailscale serve`, which drops
    // the mappings clients reach this controller through.
    super::confirm_prompt(g, yes, &format!(
        "Demote this box: rename its tailnet device to '{name}' and reset tailscale serve?"));
    // Two phases: release the name, then the serve mappings.
    if !g.json { println!("{}", ui::phase("Role")); }
    ui::step(&format!("releasing the role name to '{name}' (one sudo)"));
    if !ts_set_hostname(&name) {
        fail(g.json, ExitCode::Generic, "rename_failed", "tailscale rename failed", None);
    }
    ui::done(&format!("tailnet name is '{name}'"));
    if !g.json { println!("{}", ui::phase("Serve")); }
    ui::step("resetting tailscale serve mappings");
    let _ = Command::new("sudo").args(["tailscale", "serve", "reset"]).status();
    ui::done("serve mappings reset");
    ui::close_done(&format!("demoted to '{name}' — stack left running (warm standby)"));
    ui::guide(&[
        ("noo stack stop", "retire this box's stack if it is not staying as a warm standby"),
        ("noo controller promote", "on the new controller: take the role name and serve mappings"),
    ]);
    Ok(0)
}

fn rewrite_yaml_gateway_url(root: &std::path::Path, url: &str) {
    let path = root.join("noomesh.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(mut v) = serde_yaml::from_str::<serde_yaml::Value>(&text) else { return };
    if let Some(m) = v.as_mapping_mut() {
        let key = serde_yaml::Value::String("services".into());
        let services = m
            .entry(key)
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
        if let Some(sm) = services.as_mapping_mut() {
            sm.insert(
                serde_yaml::Value::String("gateway_url".into()),
                serde_yaml::Value::String(url.into()),
            );
        }
    }
    if let Ok(out) = serde_yaml::to_string(&v) {
        let _ = std::fs::write(&path, out);
    }
}

/// Every node the gateway knows about. This parsed
/// `ansible/inventory/hosts` until 2026-09-04 — a file in the tree deleted
/// in 3695e129 — so it returned an empty list on every install and the
/// restage step reported "no nodes in the inventory" on a fleet that had
/// four. The registry is the only thing that knows what is enrolled.
fn inventory_nodes(g: &Globals) -> Vec<String> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|b| b["nodes"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|n| {
            n["id"].as_str().or_else(|| n["hostname"].as_str()).map(str::to_string)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn promote_body() -> String {
        let own = crate::test_src::own_code(include_str!("controller.rs"));
        crate::test_src::fn_body(&own, "pub fn controller_promote(").to_string()
    }

    fn at(body: &str, needle: &str) -> usize {
        body.find(needle).unwrap_or_else(|| panic!("promote no longer has `{needle}`"))
    }

    #[test]
    fn the_self_node_is_onboardings_name_else_controller() {
        assert_eq!(self_node_id(""), "controller");
        assert_eq!(self_node_id("  "), "controller");
        assert_eq!(self_node_id("Lenovo-P52s"), "Lenovo-P52s");
    }

    /// i545 72: promote moves the stack to the tailnet bind mode, and it
    /// does so before the stack is recreated (a restart keeps old bindings).
    #[test]
    fn promote_sets_bind_mode_tailnet_before_the_recreate() {
        let b = promote_body();
        assert_eq!(PROMOTED_BIND_MODE, "tailnet");
        let set = at(&b, "upsert_env(&root, \"NOO_BIND_MODE\", PROMOTED_BIND_MODE)");
        assert!(set < at(&b, "restart_stack_force()"), "set before the recreate");
    }

    /// i545 75/81: the externally reachable service leaves are reconciled
    /// against the new identity, before the recreate that loads them.
    #[test]
    fn promote_reissues_the_reachable_service_certs_before_the_recreate() {
        let b = promote_body();
        assert!(at(&b, "reissue_reachable_service_certs(&ca)") < at(&b, "restart_stack_force()"));
        let own = crate::test_src::own_code(include_str!("controller.rs"));
        let f = crate::test_src::fn_body(&own, "fn reissue_reachable_service_certs(");
        assert!(f.contains("for svc in crate::onboard::steps::EXTERNALLY_REACHABLE"), "{f}");
        assert!(f.contains("ensure_service_cert_names(ca, svc, &hostname, &node_ip, &ts)"), "{f}");
        assert_eq!(crate::onboard::steps::EXTERNALLY_REACHABLE, &["nats", "redis", "postgres", "model-cache"]);
    }

    /// The bind mode and the leaves take effect on a RECREATE; the old
    /// `docker restart noo-gateway` kept the old bindings.
    #[test]
    fn promote_recreates_the_stack_instead_of_restarting_the_gateway() {
        let b = promote_body();
        assert!(!b.contains("\"restart\", \"noo-gateway\""), "a gateway restart is not enough");
        let own = crate::test_src::own_code(include_str!("controller.rs"));
        let f = crate::test_src::fn_body(&own, "fn restart_stack_force(");
        assert!(f.contains(".args([\"stack\", \"restart\", \"--force\"])"), "{f}");
    }

    /// i545 74/89/92: the controller's own node agent is restaged over the
    /// rail on every promote (not only with --restage-nodes), after the
    /// recreate, and the inventory loop does not restage it twice.
    #[test]
    fn promote_always_restages_the_self_node() {
        let b = promote_body();
        let restage = at(&b, "crate::commands::upgrade::provision_one(g, &self_node, &[])");
        assert!(at(&b, "restart_stack_force()") < restage, "after the recreate");
        let gate = at(&b, "} else if restage {");
        assert!(restage < gate, "not behind --restage-nodes");
        assert!(b.contains(".filter(|n| !n.eq_ignore_ascii_case(&self_node))"), "the loop skips it");
    }
}
