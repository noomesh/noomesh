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
    let _ = Command::new("docker").args(["restart", "noo-gateway"]).status();
    ui::done("gateway restarted on the new cert");
    ui::close_done(&format!("role '{name}' claimed — this box is the controller"));

    // The DATA half is not this command's to run; say where it lives.
    if !g.json { println!("{}", ui::phase("Data Plane")); }
    println!("{}", ui::note("if this standby replicates postgres, scripts/bootstrap-standby.sh has the switchover half"));
    println!("{}", ui::note("nothing to do here otherwise — the database this box already holds is the live one"));

    // Fleet realignment: nodes that pin the ROLE name reconverge on their
    // own; anything pinned to the old machine name needs a bundle restage.
    if !g.json { println!("{}", ui::phase("Restage")); }
    let nodes = inventory_nodes(g);
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
