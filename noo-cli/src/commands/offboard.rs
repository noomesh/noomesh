// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo offboard` — the mirror of `noo onboard`: tear a STANDALONE
//! controller back down to bare machine prep, or audit how fresh it is.
//!
//! Born from the wipe-and-retry onboarding campaign (2026-08-20..23): the
//! wipe card lived in chat messages and HANDOFF docs, which is exactly the
//! smell a CLI verb fixes. Node-side teardown already exists
//! (`noo cluster teardown-node`); this is the controller half.
//!
//! Safety posture:
//! - REFUSES to run against anything that is not a standalone install
//!   (`.noo-standalone` marker) — a repo checkout / reconciler-owned
//!   controller (HOST3) must never be offboardable by one command.
//! - `--check` is read-only anywhere, and is the "is this box fresh?"
//!   audit: prints CLEAN/LEFTOVER per item, exit 1 if anything remains.
//! - Every destructive section is individually confirmed (or `--yes`).
//! - The age key is KEPT by default (`--purge-secrets` to remove): deleting
//!   it orphans every sops store encrypted to it, forever.
//! - Machine prep is deliberately untouched: docker, its data-root, nvidia,
//!   gh auth, git/curl/ffmpeg — offboard returns the box to "prepped",
//!   not to "factory".

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui::{self, Glyph};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Stop the host-watcher + hostd self-heal daemons; with `remove_unit`,
/// also disable and delete the systemd user unit so a login cannot re-arm
/// them (finding #85: stopping is not removing). Shared with `stack clean`
/// (host8, 2026-08-31: `clean --deep` left the watcher alive and it
/// resurrected containers onto a box that believed itself clean — the
/// migrate import fresh-box guard then refused).
pub(crate) fn stop_self_heal_daemons(remove_unit: bool) {
    let quiet = |cmd: &str, args: &[&str]| {
        let _ = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };
    quiet("systemctl", &["--user", "stop", "noo-host-watcher", "noo-hostd"]);
    quiet("pkill", &["-f", "noo-host-watcher.sh"]);
    quiet("pkill", &["-f", "noo-hostd run"]);
    if remove_unit {
        quiet("systemctl", &["--user", "disable", "noo-host-watcher", "noo-hostd"]);
        if let Ok(h) = std::env::var("HOME") {
            remove_self_heal_units(Path::new(&h));
        }
        quiet("systemctl", &["--user", "daemon-reload"]);
        remove_secret_rundir();
    }
}

/// The self-heal daemons' systemd USER units under `home`, by exact path:
/// the host-watcher, and noo-hostd in controller mode (its `--system` unit
/// is `/etc/systemd/system/noo-hostd.service`, removed by the offboard walk).
pub(crate) fn self_heal_user_units(home: &Path) -> [PathBuf; 2] {
    let dir = home.join(".config/systemd/user");
    [dir.join("noo-host-watcher.service"), dir.join("noo-hostd.service")]
}

/// Delete both user units (i677a 3c: the hostd one used to be stopped but
/// left on disk, by `stack clean --deep` and by offboard alike). Exact paths
/// only; a unit that is not there is fine.
pub(crate) fn remove_self_heal_units(home: &Path) {
    for unit in self_heal_user_units(home) {
        let _ = std::fs::remove_file(unit);
    }
}

/// The user units still on disk: what the audit reports as leftovers.
pub(crate) fn self_heal_unit_leftovers(home: &Path) -> Vec<PathBuf> {
    self_heal_user_units(home).into_iter().filter(|u| u.is_file()).collect()
}

/// The RAM directory the launcher writes the containers' secret files to
/// (scripts/lib-secrets.sh `secret_rundir`: `NOO_SECRET_RUNDIR`, else
/// `/run/noo/secrets` as root, else `/dev/shm/noo-secrets-<uid>`). Offboard and
/// `stack clean --deep` leave no plaintext behind, even in RAM. Best effort: a
/// directory that is not there, or not ours, is left alone.
pub(crate) fn remove_secret_rundir() {
    let euid = unsafe { libc::geteuid() };
    let dir = match std::env::var("NOO_SECRET_RUNDIR") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ if euid == 0 => PathBuf::from("/run/noo/secrets"),
        _ => PathBuf::from(format!("/dev/shm/noo-secrets-{euid}")),
    };
    if dir.is_dir() && !dir.is_symlink() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Sub-line under an item label: a bullet for "kept/skipped", a glyph line
/// for outcomes (guide §5 "Rhythm").
fn sub(g: Glyph, msg: &str) {
    if !ui::quiet() {
        println!("{}", ui::sub(&ui::status_line(g, msg)));
    }
}
fn item(label: &str) {
    if !ui::quiet() {
        println!("{}", ui::item(label));
    }
}
fn note(text: &str) {
    if !ui::quiet() {
        println!("{}", ui::note(text));
    }
}

pub fn offboard(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut check = false;
    let mut yes = false;
    let mut keep_tailnet = false;
    let mut purge_secrets = false;
    let mut uninstall = false;
    for tok in args {
        match tok.as_str() {
            "--check" => check = true,
            "-y" | "--yes" => yes = true,
            "--keep-tailnet" => keep_tailnet = true,
            "--purge-secrets" => purge_secrets = true,
            "--uninstall" => uninstall = true,
            t => fail(g.json, ExitCode::Usage, "usage",
                &format!("unknown argument: {t}"),
                Some("usage: noo offboard [--check] [--yes] [--keep-tailnet] [--purge-secrets] [--uninstall]")),
        }
    }

    if check {
        return audit(g);
    }

    // ── Guard: standalone installs only ─────────────────────────────────
    // `home = None` is RESIDUE MODE (first-contact finding #27): the install
    // is already gone but machine-level leftovers remain (volumes, CA trust,
    // tailnet identity) — the audit sees them, so the teardown must be able
    // to clear them. A half-wiped box is the COMMON state mid-testing; the
    // old hard-fail left `--check` pointing at a command that refused to run.
    // Repo checkouts stay non-offboardable: residue mode touches only what
    // this tool's own installs create, never a checkout or its data.
    let home: Option<std::path::PathBuf> = match crate::envfile::standalone_home() {
        Some(h) => Some(h),
        None => {
            // A home dir carrying only the marker (partial install/wipe)
            // still deserves the full path; require the marker itself.
            let fallback = crate::onboard::standalone::default_home();
            if fallback.join(".noo-standalone").is_file() {
                Some(fallback)
            } else {
                None
            }
        }
    };
    if g.json {
        fail(true, ExitCode::Generic, "interactive_only",
            "noo offboard is interactive; use --check for the JSON-safe audit", None);
    }

    match &home {
        Some(h) => println!("{}", ui::header("offboard", Some(&format!("standalone controller at {}", h.display())))),
        None => {
            println!("{}", ui::header("offboard", Some("residue mode")));
            println!("  {}", ui::muted("no standalone install found — clearing machine-level leftovers only (stack containers/volumes, CA trust, tailnet identity)"));
            if let Some(root) = checkout_state_root() {
                println!("  {}", ui::muted(&format!("a source checkout at {} still carries controller state — offered for retirement (moved to a dated backup, never deleted) at the end", root.display())));
            }
        }
    }
    println!("  {}", ui::muted("machine prep (docker, data-root, nvidia, gh auth) is not touched"));

    // Preflight for scripted runs: --yes deletes
    // without prompting, so SAY what it will auto-accept before the first
    // deletion — and what still needs its flag.
    if yes {
        println!();
        ui::warned("--yes: auto-accepting WITHOUT prompts: stack (ALL DATA), stack images, storage root, CA trust, tailnet identity + device record, host node-agent, install home");
        let mut held: Vec<&str> = Vec::new();
        if !purge_secrets { held.push("age key + CLI state (add --purge-secrets)"); }
        // A plaintext credential is a leftover. The audit's exit code is the
        // signal; its table has already printed above it.
        if crate::envfile::sops_backend_active() {
            if let Ok(rc) = crate::commands::secrets::secrets_audit(g, &[]) {
                if rc != 0 { held.push("plaintext credential(s) in .env — `noo security secrets audit` lists them"); }
            }
        }
        if !uninstall { held.push("binary (add --uninstall)"); }
        if held.is_empty() {
            note("nothing held back — this is the complete zero-prompt wipe");
        } else {
            note(&format!("held back: {}", held.join("; ")));
        }
    }

    // ── Gate: docker must ANSWER before anything is removed (i677 #20) ───
    // A stranger's install (matrix run 43157286042): offboard ran as a user
    // whose shell was not yet in the docker group. Every docker call failed,
    // the old docker_lines read that as an EMPTY list, the walk said "no
    // containers or volumes — already clean" while 16 containers ran, and
    // then removed the storage root and the install home from under them.
    // An unanswered docker is never "nothing there": stop before step 0.
    let docker = match docker_gate(&mut LiveGate, "noo offboard") {
        Ok(d) => d,
        Err(code) => return Ok(code),
    };
    if docker == DockerAccess::NotInstalled {
        note("docker is not installed on this box: no stack container, volume or image can exist here");
    }

    // ── 0. Stop the self-heal daemons FIRST (finding #54) ───────────────
    // The host-watcher (systemd-user or nohup fallback) and hostd recreate
    // spool dirs inside ~/.noo moments after removal — the first live
    // offboard "succeeded" and the freshness check then found the home
    // resurrected. Processes die before files.
    println!("{}", ui::phase("Stop"));
    stop_self_heal_daemons(true);
    ui::done("self-heal daemons stopped, watcher unit removed");

    let prefix = crate::envfile::container_prefix();
    // What this walk set out to remove (the user agreed, or -y) and could not.
    let mut removal_failed: Vec<String> = Vec::new();

    // ── 0b. Enrolled workers = future ORPHANS (finding #72) ─────────────
    // This is the LAST moment the controller knows its workers exist. A
    // teardown staged over the pull rail dies with the controller if the
    // node has not collected it yet (60s fetch cadence — host4 hit
    // exactly this live: enrolled forever in a mesh that stopped existing,
    // and the next enroll refused on the CA anchor). Best-effort: a dead
    // gateway just skips the warning.
    {
        let self_node = home.as_ref()
            .map(|h| crate::onboard::env::read_env_key(&h.join(".env"), "NODE_ID"))
            .unwrap_or_default();
        let doc = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 8);
        let workers: Vec<String> = doc
            .as_ref()
            .and_then(|d| d.get("nodes")?.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|n| {
                n.get("id").and_then(|v| v.as_str())
                        .or_else(|| n.get("node_id").and_then(|v| v.as_str()))
                    .or_else(|| n.get("name").and_then(|v| v.as_str()))
                    .map(str::to_string)
            })
            .filter(|n| !n.eq_ignore_ascii_case(&self_node))
            .collect();
        if !workers.is_empty() {
            ui::warned(&format!("{} worker node(s) still enrolled: {}", workers.len(), workers.join(", ", )));
            note("offboarding now ORPHANS them: their staged teardowns die with this controller and the next enroll refuses on the CA anchor");
            ui::guide(&[
                ("noo cluster teardown-node <name> --factory", "dismantle each worker first, then re-run offboard"),
                ("noo cluster forget <name>", "if a worker is already dead hardware, drop its record instead"),
            ]);
            if !(yes || ctx_confirm(g, false,
                // Not `curl … | sudo sh`: that is a script run as root that
                // nobody ever sees, and this string is what an operator will
                // actually paste. Verified against the node's own anchor.
                "Continue anyway and orphan these nodes? (recover later, on each node: curl -fsS --cacert /etc/noo/pki/ca.crt <new-controller>/bootstrap/deenroll -o /tmp/deenroll.sh && sudo sh /tmp/deenroll.sh)",
                false))
            {
                ui::close_failed("offboard stopped — tear down the workers first, then re-run", None);
                return Ok(1);
            }
        }
    }
    println!("{}", ui::phase("Remove"));

    // ── 1. Stack: containers, volumes, networks ─────────────────────────
    let project = crate::envfile::compose_project();
    let cluster_net = crate::envfile::cluster_network();
    let mut walk = LiveWalk { g, yes, project: &project, cluster_net: &cluster_net };
    match stack_step(&mut walk, docker, &prefix) {
        Ok(failed) => removal_failed.extend(failed),
        Err(code) => return Ok(code),
    }

    // ── 1a. Pulled stack images (finding #85) ───────────────────────────
    // Containers and volumes went; the ~dozen ghcr images (gigabytes) did
    // not — the single largest leftover on a "fresh" box. Own prompt:
    // keeping them is legitimate (a re-onboard pulls nothing), deleting
    // them is what "fresh start" means.
    // Addressed by IMAGE ID, not repo:tag: a digest-pinned pull (every
    // --dist image since the signed lock) has no tag, so `repo:<none>` is
    // not a reference docker accepts — seven of nine rmi calls failed with
    // "invalid reference format" while this step reported all nine removed
    // (host8 offboard, 2026-09-07).
    let image_lines = match stack_image_lines(&mut walk, docker) {
        Ok(l) => l,
        Err(code) => return Ok(code),
    };
    let stack_images: Vec<(String, String)> = image_lines
        .into_iter()
        .filter_map(|l| {
            let (repo, id) = l.split_once('\t')?;
            crate::registry::is_our_image(repo)
                .then(|| (repo.to_string(), id.to_string()))
        })
        .collect();
    if !stack_images.is_empty() {
        if yes || ctx_confirm(g, false,
            &format!("Remove the {} pulled stack image(s) ({}/*)? \
                      (keeping them makes the next onboard pull-free)", stack_images.len(), crate::registry::IMAGE_NAMESPACE),
            false)
        {
            let mut ids: Vec<String> = stack_images.iter().map(|(_, id)| id.clone()).collect();
            ids.sort();
            ids.dedup();
            let before = ids.len();
            run("docker", &[vec!["rmi".into(), "-f".into()], ids].concat());
            match docker_list(&["images", "--format", "{{.Repository}}"]) {
                Ok(l) => {
                    let left = l.into_iter().filter(|r| crate::registry::is_our_image(r)).count();
                    if left == 0 {
                        sub(Glyph::Ok, &format!("{before} pulled image(s) removed"));
                    } else {
                        sub(Glyph::Warn, &format!("{left} of {before} pulled image(s) still present — a running container holds them? `docker images | grep noomesh`"));
                    }
                }
                Err(why) => sub(Glyph::Warn, &format!("could not re-list images to confirm the removal ({why})")),
            }
        } else {
            sub(Glyph::Bullet, &format!("{} pulled image(s) kept — the next onboard reuses them", stack_images.len()));
        }
    }

    // ── 1b. The HOST node-agent (self-agent) ────────────────────────────
    // A systemd service outside both the stack and ~/.noo, so the walk
    // used to leave it RUNNING with the old identity baked into its
    // process env — 21h of "nats still disconnected" to a ghost tailnet
    // name after the rebirth, and `enable --now` in the next install
    // could not restart it (finding #71a; the installer side is #71b).
    if Path::new("/etc/systemd/system/noo-node-agent.service").is_file()
        || Path::new("/usr/local/bin/noo-node-agent").is_file()
        || Path::new("/usr/local/bin/noo-hostd").is_file()
    {
        item("host daemons");
        if yes || ctx_confirm(g, false,
            "Remove the host daemons (node-agent + hostd: services, binaries, /etc/noo-node-agent.env, /etc/noo/agent-secrets, /etc/noo/pki)?", false)
        {
            // hostd rides the same sudo: it is the other PAI-authored root
            // daemon and stopping-without-removing left its unit + binary
            // behind on every offboard (finding #85).
            run("sudo", &["sh".into(), "-c".into(),
                "systemctl disable --now noo-node-agent 2>/dev/null; \
                 systemctl disable --now noo-hostd 2>/dev/null; \
                 rm -f /etc/systemd/system/noo-node-agent.service \
                       /etc/systemd/system/noo-hostd.service \
                       /usr/local/bin/noo-node-agent \
                       /usr/local/bin/noo-hostd \
                       /etc/noo-node-agent.env /etc/noo-node-agent.env.container-backup; \
                 rm -rf /etc/noo/pki /etc/noo/agent-secrets /etc/noo/harness-secrets; \
                 systemctl daemon-reload".into()]);
            sub(Glyph::Ok, "node-agent + hostd removed (services, binaries, env, secret files, /etc/noo/pki)");
        } else {
            sub(Glyph::Bullet, "kept (skipped)");
        }
    }

    // The namespace restore unit (#1108): we remove what onboard and the
    // stack stage install.
    if Path::new(crate::netns_unit::UNIT_PATH).is_file() {
        item("namespace restore unit");
        if yes || ctx_confirm(g, false, &format!("Remove {} (it restarts the stack's namespace-joined containers after dockerd starts)?", crate::netns_unit::UNIT_NAME), false) {
            // SAFETY: isatty has no preconditions.
            match crate::netns_unit::remove(unsafe { libc::isatty(0) } == 1) {
                Ok(_) => sub(Glyph::Ok, &format!("{} removed", crate::netns_unit::UNIT_NAME)),
                Err(e) => sub(Glyph::Warn, &format!("{e} — by hand: {}", crate::netns_unit::manual_removal())),
            }
        } else {
            sub(Glyph::Bullet, "kept (skipped)");
        }
    }

    // ── 2. Storage root (bind-mounted data) ─────────────────────────────
    // Only with an install to read it from: the path comes from the
    // install's own .env, NEVER guessed — so residue mode (no .env left)
    // cannot offer this. If a storage root lingers on a home-less box, the
    // audit's job is to name it, the operator's to remove it.
    if let Some(h) = &home {
        if let Some(root) = storage_root(h) {
            if Path::new(&root).is_dir() {
                item(&format!("storage root  {root}"));
                if yes || ctx_confirm(g, false,
                    &format!("DELETE the storage root (postgres/models/data) at {root}?"), false)
                {
                    run("sudo", &["rm".into(), "-rf".into(), root.clone()]);
                    sub(Glyph::Ok, "removed");
                } else {
                    sub(Glyph::Bullet, "kept (skipped)");
                }
            }
        }
    }

    // ── 3. Cluster CA out of the trust store ────────────────────────────
    let ca = "/usr/local/share/ca-certificates/mesh-cluster-ca.crt";
    if Path::new(ca).is_file() {
        item("cluster CA trust");
        if yes || ctx_confirm(g, false,
            "Remove the cluster CA from the trust store on this machine?", false)
        {
            run("sudo", &["rm".into(), "-f".into(), ca.into()]);
            run("sudo", &["update-ca-certificates".into()]);
            sub(Glyph::Ok, "removed from the trust store");
        } else {
            sub(Glyph::Bullet, "kept (skipped)");
        }
    }

    // ── 4. Tailscale: serve mapping, then identity ──────────────────────
    // Skip entirely when there is no identity (running OR cached) — asking
    // an already-logged-out box to log out is noise (residue-mode polish).
    let ts_present = Command::new("tailscale").args(["status", "--json"]).output().ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .map(|j| {
            j["BackendState"].as_str() == Some("Running")
                || !j["Self"]["DNSName"].as_str().unwrap_or("").is_empty()
        })
        .unwrap_or(false);
    item("tailnet");
    if !keep_tailnet && !ts_present {
        sub(Glyph::Ok, "no identity (running or cached) — nothing to clear");
        // A logout (a previous, interrupted offboard — host8 2026-09-01)
        // wipes the local identity but leaves the DEVICE RECORD in the
        // tailnet; the next onboard then re-registers as <host>-1. The
        // OAuth client is still in the home at this point (section 5
        // removes it), so match the record by hostname and offer the delete.
        let host = std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
        if !host.is_empty() && (yes || ctx_confirm(g, false,
            &format!("Check the tailnet for a stale device record named '{host}' and delete it?"), false))
        {
            match crate::commands::cluster_provision::delete_tailnet_device(&[], &host) {
                Ok(name) => sub(Glyph::Ok, &format!("stale device record removed from the tailnet ({name})")),
                Err(e) => sub(Glyph::Bullet, &format!("no stale record removed: {e}")),
            }
        }
    } else if !keep_tailnet
        && !(yes || ctx_confirm(g, false,
            "Reset tailscale serve + LOG OUT of the tailnet on this machine?", false))
    {
        sub(Glyph::Bullet, "identity kept (skipped)");
    } else if !keep_tailnet {
        // Capture who we ARE before logout wipes it — the device record we
        // offer to delete below is matched off these (finding #66).
        let self_identity = Command::new("tailscale")
            .args(["status", "--json"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
            .map(|j| {
                let ips: Vec<String> = j["Self"]["TailscaleIPs"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                (ips, j["Self"]["HostName"].as_str().unwrap_or("").to_string())
            })
            .filter(|(ips, host)| !ips.is_empty() || !host.is_empty());
        // Every call here is BOUNDED (host8 offboard, 2026-09-01: `tailscale
        // logout` hung on the control plane, tailscaled wedged mid-logout so
        // `systemctl stop` and `start` hung too — three Ctrl+Cs, then this
        // step printed ✓). Prime sudo first so its password prompt never
        // eats a timeout budget.
        let _ = Command::new("sudo").arg("-v").status();
        let mut ok = run_bounded(30, "sudo", &["tailscale", "serve", "reset"]);
        // Logout tells the control plane to drop the node key. It is the
        // nice-to-have: the identity RESET is the state-file removal below,
        // and the device record is deleted by API in the next prompt.
        if !run_bounded(45, "sudo", &["tailscale", "logout"]) {
            note("logout did not complete — taking the link down and resetting local state instead");
            let _ = run_bounded(15, "sudo", &["tailscale", "down"]);
        }
        // The state file survives a logout whose account is already gone
        // ("no nodekey" 500) and then serves a DEAD identity to the next
        // onboard (first-contact finding #17) — always reset it.
        if !run_bounded(30, "sudo", &["systemctl", "stop", "tailscaled"]) {
            note("tailscaled did not stop — killing it");
            ok &= run_bounded(15, "sudo", &["systemctl", "kill", "-s", "KILL", "tailscaled"]);
        }
        ok &= run_bounded(10, "sudo", &["rm", "-f", "/var/lib/tailscale/tailscaled.state"]);
        ok &= run_bounded(30, "sudo", &["systemctl", "start", "tailscaled"]);
        if ok {
            sub(Glyph::Ok, "identity cleared (tailscale itself stays installed)");
        } else {
            sub(Glyph::Warn, "identity NOT fully cleared");
            ui::guide(&[
                ("tailscale status", "shows what the daemon still believes it is"),
                ("sudo systemctl kill -s KILL tailscaled && sudo rm -f /var/lib/tailscale/tailscaled.state && sudo systemctl start tailscaled", "the manual reset, in one line"),
            ]);
        }
        // Logout leaves the DEVICE RECORD behind, so every rebirth
        // re-registers as <host>-1, -2, … (finding #66). Offer to delete it
        // while the OAuth client is still on disk (section 5 removes it).
        if let Some((ips, host)) = self_identity {
            if yes || ctx_confirm(g, false,
                "Also DELETE this machine's device record from the tailnet? \
                 (otherwise the next onboard re-registers as <name>-1, -2, …)", false)
            {
                match crate::commands::cluster_provision::delete_tailnet_device(&ips, &host) {
                    Ok(name) => sub(Glyph::Ok, &format!("device record removed from the tailnet ({name})")),
                    Err(e) => sub(Glyph::Warn, &format!("device record not removed: {e}")),
                }
            } else {
                sub(Glyph::Bullet, "device record kept (skipped)");
            }
        }
    } else {
        sub(Glyph::Bullet, "--keep-tailnet: serve mapping + identity left in place");
    }

    // ── 4b. A source checkout's controller state ────────────────────────
    // HOST3 (2026-09-01): the controller moved to host8 by export, the node
    // side was torn down from the new controller, and the CLONE still held
    // .env + noomesh.yaml + secrets/ + pki/ + the override — so `noo whoami`
    // said "controller (source checkout)", the role gate let `noo stack
    // status` stumble through missing secrets, and the MCP servers pointed
    // at the dead controller name. Offboard never touched a checkout, by
    // design (it is source, not this tool's install) — so it MOVES the
    // state files to a dated backup and leaves the source alone.
    if home.is_none() {
        if let Some(root) = checkout_state_root() {
            let present: Vec<&str> = CHECKOUT_STATE
                .iter()
                .copied()
                .filter(|f| root.join(f).exists())
                .collect();
            item(&format!("checkout state  {}", root.display()));
            if yes || ctx_confirm(g, false,
                &format!("Retire the controller state in the checkout at {} ({}) — moved to a dated backup under ~/noo-backups, source untouched?",
                    root.display(), present.join(", ")),
                false)
            {
                match retire_checkout_state(&root, &present) {
                    Ok(dest) => sub(Glyph::Ok, &format!("moved to {}", dest.display())),
                    Err(e) => sub(Glyph::Warn, &format!("NOT retired: {e}")),
                }
            } else {
                sub(Glyph::Bullet, "kept (skipped) — `noo whoami` will keep reporting a checkout controller");
            }
        }
    }

    // ── 5. The standalone home itself ───────────────────────────────────
    if let Some(h) = &home {
        item(&format!("install  {}", h.display()));
        if !(yes || ctx_confirm(g, false,
            &format!("DELETE the standalone install (secrets, PKI, config) at {}?", h.display()),
            false))
        {
            sub(Glyph::Bullet, "kept (skipped)");
            ui::close_done("offboard walk finished");
            ui::guide(&[
                ("noo offboard --check", "lists what is still on this machine"),
                ("noo offboard --yes", "re-run without prompts to remove the rest"),
            ]);
            return Ok(0);
        }
        let _ = std::fs::remove_dir_all(h);
        // Containers (uid 65532) write root-owned files into bind dirs
        // under the home; user-level removal chokes on them SILENTLY
        // (finding #54, live: .noo_noo-data/ingest survived and the
        // freshness check flagged the "removed" home). Escalate only when
        // needed.
        if h.exists() {
            note("root-owned container files inside — removing with sudo");
            let _ = Command::new("sudo").arg("rm").arg("-rf").arg(h).status();
        }
        if h.exists() {
            sub(Glyph::Warn, "could not be fully removed — check ownership manually");
        } else {
            sub(Glyph::Ok, "removed");
        }
    } else {
        // RESIDUE MODE: a marker-less ~/.noo stub (watcher spool debris,
        // partial wipe) is still residue — offer its removal instead of
        // skipping it (finding #54, second half).
        let stub = crate::onboard::standalone::default_home();
        if stub.exists() {
            item(&format!("install stub  {}", stub.display()));
        }
        if stub.exists()
            && (yes || ctx_confirm(g, false,
                &format!("DELETE the leftover install stub at {}?", stub.display()), false))
        {
            let _ = std::fs::remove_dir_all(&stub);
            if stub.exists() {
                let _ = Command::new("sudo").arg("rm").arg("-rf").arg(&stub).status();
            }
            if stub.exists() {
                sub(Glyph::Warn, "could not be removed");
            } else {
                sub(Glyph::Ok, "removed");
            }
        } else if stub.exists() {
            sub(Glyph::Bullet, "kept (skipped)");
        }
    }

    // ── 6-8. The COMPLETE walk (finding #57, operator design 2026-08-26):
    // "it asks for each step, so a flag isn't needed — it would just ask."
    // Every trace gets its own yes/no with the dangerous defaults on N;
    // the flags (--purge-secrets, --uninstall) exist only to pre-answer
    // for scripted runs. A present human is never left with hidden
    // leftovers behind flags they'd have to know about.

    // 6. Age key — irreversible for anything it encrypted; default NO.
    let age = age_dir();
    if age.is_dir() {
        item(&format!("age key  {}", age.display()));
        let do_it = purge_secrets
            || ctx_confirm(g, yes && purge_secrets,
                "PERMANENTLY delete the age key? (irreversible — orphans every sops \
                 store encrypted to it; fine when the stores are gone too)", false);
        if do_it {
            let _ = std::fs::remove_dir_all(&age);
            sub(Glyph::Ok, "removed");
        } else {
            sub(Glyph::Bullet, "kept (add --purge-secrets to remove)");
        }
    }

    // 7. CLI state: per-user credential + model cache (finding #57 gap —
    // a fresh persona otherwise inherits creds pointing at a dead gateway).
    let mesh_cfg = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".config/mesh");
    if mesh_cfg.is_dir() {
        item(&format!("CLI state  {}", mesh_cfg.display()));
        let do_it = purge_secrets
            || ctx_confirm(g, yes && purge_secrets,
                "Delete the CLI state (login credential, model cache) at ~/.config/mesh?",
                false);
        if do_it {
            let _ = std::fs::remove_dir_all(&mesh_cfg);
            sub(Glyph::Ok, "removed (login credential, model cache)");
        } else {
            sub(Glyph::Bullet, "kept (add --purge-secrets to remove)");
        }
    }

    // 8. Full uninstall — the binary + its completion file. LAST, since the
    // running process deletes its own file (fine on Linux: the inode
    // outlives the name for this run).
    let mut binary_removed = false;
    if let Ok(exe) = std::env::current_exe() {
        item(&format!("binary  {}", exe.display()));
        let do_it = uninstall
            || ctx_confirm(g, yes && uninstall,
                "Uninstall the noo binary itself? (reinstall any time with the \
                 one-line installer)", false);
        if do_it {
            let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());
            for comp in [
                std::path::PathBuf::from("/etc/bash_completion.d/noo"),
                std::path::PathBuf::from("/etc/bash_completion.d/pai"),
                home.join(".local/share/bash-completion/completions/noo"),
                home.join(".local/share/bash-completion/completions/pai"),
            ] {
                let _ = std::fs::remove_file(&comp);
            }
            match std::fs::remove_file(&exe) {
                Ok(()) => {
                    binary_removed = true;
                    sub(Glyph::Ok, "uninstalled (with its completion files)");
                    // The way back, printed at the moment of departure —
                    // the channel knob (NOO_CLI_REPO, fu44) keeps this
                    // correct for the public repo too.
                    let repo = std::env::var("NOO_CLI_REPO")
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                        .unwrap_or_else(super::upgrade::repo);
                    // First live test of this hint 404'd (finding #62): the
                    // repo is PRIVATE (raw.githubusercontent rejects
                    // unauthenticated) and the default branch is dev, not
                    // main. The gh form works for private today and public
                    // later; the curl form is the public-channel future.
                    ui::guide(&[
                        (&super::cluster_provision::fetch_then_run(
                            &format!("gh api -H \"Accept: application/vnd.github.raw\" \"repos/{repo}/contents/noo-cli/install.sh?ref=dev\""), ""),
                         "reinstall any time (private repo: the gh form)"),
                        (&super::cluster_provision::fetch_then_run(
                            &format!("curl -fsSL https://raw.githubusercontent.com/{repo}/main/noo-cli/install.sh"), ""),
                         "the public channel, once live"),
                    ]);
                }
                Err(e) => sub(Glyph::Warn, &format!("could not remove: {e}")),
            }
        } else {
            sub(Glyph::Bullet, "kept (add --uninstall to remove)");
        }
    }

    // ◆ Verify: the same audit --check runs, quietly, so the walk ends with
    // what is actually left rather than a hopeful "complete".
    println!("{}", ui::phase("Verify"));
    let left = audit_leftovers(g, false);
    if !removal_failed.is_empty() {
        // Agreed to, attempted, still there: never "complete" (i677a). A
        // clean verdict that cannot see what it was asked to remove is the
        // failure this phase exists to prevent.
        ui::close_failed(
            &format!("offboard did NOT remove what it was asked to: {}", removal_failed.join(", ")),
            Some("noo offboard --check"),
        );
        return Ok(1);
    }
    if left.is_empty() {
        ui::done("nothing left — this box is fresh");
    } else {
        ui::warned(&format!("{} item(s) still present: {}", left.len(), left.join(", ")));
        note("each was kept by choice above, or needs its flag (--purge-secrets, --uninstall)");
    }

    // Don't suggest running a binary we just deleted (finding #67).
    ui::close_done("offboard complete");
    if !binary_removed {
        ui::guide(&[
            ("noo offboard --check", "confirms nothing is left"),
            ("noo onboard", "set this machine up again"),
            ("noo enroll <controller-url>", "or join it to another controller as a worker"),
        ]);
    }
    Ok(0)
}

/// What the docker gate does to the machine; [`docker_gate`] holds the
/// decision, so a test drives it with a fake.
pub(crate) trait GateHost {
    fn access(&mut self) -> Result<DockerAccess, String>;
    /// Run this command again with the docker group when that is what fixes
    /// it (added to the group this session, i677 #10): its exit code.
    fn relaunch(&mut self, why: &str) -> Option<i32>;
    /// Print a refusal: line 0 is the verdict, the rest the ways forward.
    fn refuse(&mut self, lines: &[String]);
}

/// Docker must ANSWER before anything is stopped or removed (i677 #20):
/// `Err(exit code)` when it does not, after the relaunch or the refusal.
pub(crate) fn docker_gate(h: &mut impl GateHost, verb: &str) -> Result<DockerAccess, i32> {
    match h.access() {
        Ok(d) => Ok(d),
        Err(why) => {
            // The one shell that can be fixed here is run again with the
            // group; anything else is refused with nothing removed.
            if let Some(code) = h.relaunch(&why) {
                return Err(code);
            }
            h.refuse(&docker_unreachable_refusal(&why, verb));
            Err(1)
        }
    }
}

pub(crate) struct LiveGate;

impl GateHost for LiveGate {
    fn access(&mut self) -> Result<DockerAccess, String> {
        docker_access()
    }
    fn relaunch(&mut self, why: &str) -> Option<i32> {
        crate::docker_group::relaunch_if_needed(why)
    }
    fn refuse(&mut self, lines: &[String]) {
        for l in &lines[1..] {
            println!("{}", ui::note(l));
        }
        ui::close_failed(&lines[0], Some("docker ps"));
    }
}

/// What the walk's stack and image steps do to the machine; [`stack_step`]
/// and [`stack_image_lines`] hold every decision.
trait StackHost {
    /// One docker listing (`docker_list`).
    fn list(&mut self, args: &[&str]) -> Result<Vec<String>, String>;
    /// This project's volumes (`stack_volumes`).
    fn volumes(&mut self) -> Result<Vec<String>, String>;
    /// This project's networks and the cluster network (`stack_networks`).
    fn networks(&mut self) -> Result<Vec<String>, String>;
    /// `--yes`, or the user's answer to `q` (default no).
    fn confirm(&mut self, q: &str) -> bool;
    fn run(&mut self, cmd: &str, args: &[String]);
    fn item(&mut self, label: &str);
    fn sub(&mut self, g: Glyph, msg: &str);
    /// docker stopped answering mid-walk: say so; the exit code.
    fn stop_walk(&mut self, step: &str, why: &str) -> i32;
}

/// Step 1: list the stack, ask, remove, re-check. `Err(exit code)` when a
/// listing did not answer (nothing from this step on is removed); else what
/// the walk was asked to remove and could not.
fn stack_step(h: &mut impl StackHost, docker: DockerAccess, prefix: &str) -> Result<Vec<String>, i32> {
    let listed = if docker == DockerAccess::Reachable {
        h.list(&["ps", "-aq", "--filter", &format!("name={prefix}-")])
            .and_then(|c| h.volumes().and_then(|v| h.networks().map(|n| (c, v, n))))
    } else {
        Ok((Vec::new(), Vec::new(), Vec::new()))
    };
    let (containers, volumes, networks) = match listed {
        Ok(cvn) => cvn,
        Err(why) => return Err(h.stop_walk("the stack's containers, volumes and networks", &why)),
    };
    h.item("stack");
    let mut removal_failed = Vec::new();
    let anything = !containers.is_empty() || !volumes.is_empty() || !networks.is_empty();
    if anything && !h.confirm("STOP + DELETE the stack (containers, volumes = ALL DATA, networks) on this controller?") {
        h.sub(Glyph::Bullet, "kept (skipped)");
    } else if anything {
        if !containers.is_empty() {
            h.run("docker", &[vec!["rm".into(), "-f".into()], containers.clone()].concat());
        }
        for v in &volumes {
            h.run("docker", &["volume".into(), "rm".into(), "-f".into(), v.clone()]);
        }
        // Networks after the containers: a network with an attached
        // container cannot be removed. This project's, by exact label, and
        // the launcher's external cluster network by exact name (i677a:
        // offboard said "complete" with four noomesh_* networks left).
        for n in &networks {
            h.run("docker", &["network".into(), "rm".into(), n.clone()]);
        }
        // Agreed to and attempted: whatever is still there is a FAILURE of
        // this offboard, not a choice. It fails the walk (i677a).
        removal_failed = recheck_after_removal(h.volumes(), h.networks());
        h.sub(Glyph::Ok, &format!("{} container(s), {} volume(s), {} network(s) removed", containers.len(), volumes.len(), networks.len()));
    } else if docker == DockerAccess::NotInstalled {
        h.sub(Glyph::Ok, "docker is not installed: no stack here");
    } else {
        // docker ANSWERED, and listed nothing: a positive "clean".
        h.sub(Glyph::Ok, "no containers, volumes or networks — already clean");
    }
    Ok(removal_failed)
}

/// The re-check after the stack's removal: what is still there, and a
/// re-check that could not ask docker, are each a removal failure, never
/// "nothing left".
fn recheck_after_removal(vols: Result<Vec<String>, String>, nets: Result<Vec<String>, String>) -> Vec<String> {
    let mut failed = Vec::new();
    match vols {
        Ok(left) => failed.extend(left.into_iter().map(|v| format!("volume {v}"))),
        Err(why) => failed.push(format!("volumes (not re-checked: {why})")),
    }
    match nets {
        Ok(left) => failed.extend(left.into_iter().map(|n| format!("network {n}"))),
        Err(why) => failed.push(format!("networks (not re-checked: {why})")),
    }
    failed
}

/// Step 1a's listing: `Err(exit code)` when docker did not answer.
fn stack_image_lines(h: &mut impl StackHost, docker: DockerAccess) -> Result<Vec<String>, i32> {
    if docker != DockerAccess::Reachable {
        return Ok(Vec::new());
    }
    match h.list(&["images", "--format", "{{.Repository}}\t{{.ID}}"]) {
        Ok(l) => Ok(l),
        Err(why) => Err(h.stop_walk("the stack images", &why)),
    }
}

struct LiveWalk<'a> {
    g: &'a Globals,
    yes: bool,
    project: &'a str,
    cluster_net: &'a str,
}

impl StackHost for LiveWalk<'_> {
    fn list(&mut self, args: &[&str]) -> Result<Vec<String>, String> {
        docker_list(args)
    }
    fn volumes(&mut self) -> Result<Vec<String>, String> {
        stack_volumes(self.project)
    }
    fn networks(&mut self) -> Result<Vec<String>, String> {
        stack_networks(self.project, self.cluster_net)
    }
    fn confirm(&mut self, q: &str) -> bool {
        self.yes || ctx_confirm(self.g, false, q, false)
    }
    fn run(&mut self, cmd: &str, args: &[String]) {
        run(cmd, args);
    }
    fn item(&mut self, label: &str) {
        item(label);
    }
    fn sub(&mut self, g: Glyph, msg: &str) {
        sub(g, msg);
    }
    fn stop_walk(&mut self, step: &str, why: &str) -> i32 {
        stop_walk(step, why)
    }
}

/// Interactive yes/no with a scripted pre-answer: `preset` short-circuits
/// (flag-driven runs), otherwise the operator is asked with `default`.
fn ctx_confirm(g: &Globals, preset: bool, label: &str, default: bool) -> bool {
    if preset {
        return true;
    }
    if unsafe { libc::isatty(0) } != 1 {
        return default;
    }
    let _ = g;
    use std::io::{BufRead as _, Write as _};
    eprint!("{} [{}]: ", label, if default { "Y/n" } else { "y/N" });
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        "" => default,
        _ => default,
    }
}

// ── Checkout controller state ───────────────────────────────────────────

/// The files that make a source checkout a controller in `role.rs` terms
/// (and in the launcher's). Source files are never in this list.
const CHECKOUT_STATE: &[&str] = &[
    ".env",
    "noomesh.yaml",
    "secrets",
    "pki",
    "docker-compose.override.yml",
];

/// The checkout that currently reads as a controller, if any — same test
/// role.rs uses, so offboard and whoami agree.
fn checkout_state_root() -> Option<PathBuf> {
    let root = crate::envfile::repo_root();
    (root.join(".env").is_file() && root.join("noomesh.yaml").is_file()).then_some(root)
}

/// Move the listed state entries out of the checkout into
/// `~/noo-backups/<host>-checkout-state-<epoch>/`. Rename, never delete: a
/// checkout's secrets are the operator's, and the move is reversible.
fn retire_checkout_state(root: &Path, entries: &[&str]) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let host = std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "host".into());
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let dest = PathBuf::from(home).join("noo-backups").join(format!("{host}-checkout-state-{stamp}"));
    std::fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    for f in entries {
        let from = root.join(f);
        let to = dest.join(f);
        if let Err(e) = std::fs::rename(&from, &to) {
            return Err(format!("move {} → {}: {e} (moved so far: see {})", from.display(), to.display(), dest.display()));
        }
    }
    Ok(dest)
}

// ── The freshness audit (`--check`) ─────────────────────────────────────

/// Read-only. Exit 0 = fresh (ready for a virgin `noo onboard`), 1 = leftovers.
fn audit(g: &Globals) -> Result<i32, Unhandled> {
    if !g.json {
        println!("{}", ui::header("offboard check", Some("fresh-box audit")));
        println!();
    }
    let leftovers = audit_leftovers(g, !g.json);
    if g.json {
        println!("{}", serde_json::json!({"fresh": leftovers.is_empty(), "leftovers": leftovers}));
    } else if leftovers.is_empty() {
        ui::close_done("fresh — ready for `noo onboard`");
    } else {
        println!();
        println!("{}", ui::status_line(Glyph::Err, &format!("{} leftover(s)", leftovers.len())));
        ui::guide(&[
            ("noo offboard", "removes them (prompts per item)"),
            ("noo offboard --yes", "removes everything without prompts"),
        ]);
    }
    Ok(if leftovers.is_empty() { 0 } else { 1 })
}

/// The audit's item walk: returns the leftover labels; prints a glyph row
/// per item when `print` (the `--check` view; the offboard walk's Verify
/// phase runs it silently).
fn audit_leftovers(g: &Globals, print: bool) -> Vec<String> {
    let prefix = crate::envfile::container_prefix();
    let mut leftovers: Vec<String> = Vec::new();
    let mut item = |label: &str, dirty: bool, detail: String| {
        if dirty {
            if print {
                println!("  {} {label}  {}", ui::glyph_cell(Glyph::Warn), ui::muted(&detail));
            }
            leftovers.push(label.to_string());
        } else if print {
            println!("  {} {label}", ui::glyph_cell(Glyph::Ok));
        }
    };

    // Each docker item is clean only when docker ANSWERED with nothing.
    // Unreachable is "not checked", a leftover, so --check and the walk's
    // Verify never call this box fresh on a docker that did not answer.
    let access = docker_access();
    let docker_items = |args: &[&str]| -> Result<Vec<String>, String> {
        match &access {
            Ok(DockerAccess::NotInstalled) => Ok(Vec::new()),
            Ok(DockerAccess::Reachable) => docker_list(args),
            Err(why) => Err(why.clone()),
        }
    };
    match docker_items(&["ps", "-aq", "--filter", &format!("name={prefix}-")]) {
        Ok(c) => item("stack containers", !c.is_empty(), format!("{} present", c.len())),
        Err(why) => item("stack containers (not checked)", true, format!("docker did not answer: {why}")),
    }
    match checkout_state_root() {
        Some(root) => item("checkout controller state", true, format!("{} carries .env + noomesh.yaml (noo offboard retires it to a backup)", root.display())),
        None => item("checkout controller state", false, String::new()),
    }
    // The SAME selector the removal uses: this audit once counted `{prefix}_`
    // (default `noo_`) and could not see a `noomesh_*` volume the removal had
    // failed to delete, so a failed removal still read "clean" (i677a).
    let volumes = match &access {
        Ok(DockerAccess::NotInstalled) => Ok(Vec::new()),
        Ok(DockerAccess::Reachable) => stack_volumes(&crate::envfile::compose_project()),
        Err(why) => Err(why.clone()),
    };
    match volumes {
        Ok(v) => item("stack volumes", !v.is_empty(), format!("{} present", v.len())),
        Err(why) => item("stack volumes (not checked)", true, format!("docker did not answer: {why}")),
    }
    let networks = match &access {
        Ok(DockerAccess::NotInstalled) => Ok(Vec::new()),
        Ok(DockerAccess::Reachable) => stack_networks(&crate::envfile::compose_project(), &crate::envfile::cluster_network()),
        Err(why) => Err(why.clone()),
    };
    match networks {
        Ok(n) => item("stack networks", !n.is_empty(), if n.is_empty() { String::new() } else { n.join(", ") }),
        Err(why) => item("stack networks (not checked)", true, format!("docker did not answer: {why}")),
    }

    let home = crate::onboard::standalone::default_home();
    item("standalone home", home.exists(), home.display().to_string());
    if let Some(root) = storage_root(&home) {
        item("storage root", Path::new(&root).is_dir(), root);
    }
    // The self-agent survives everything else by default (finding #71a) —
    // a running one with a stale env poisons the next onboard silently.
    item("host node-agent",
        Path::new("/etc/systemd/system/noo-node-agent.service").is_file()
            || Path::new("/usr/local/bin/noo-node-agent").is_file()
            || Path::new("/etc/noo-node-agent.env").is_file(),
        "service/binary/env still installed".into());
    item("host daemon (noo-hostd)",
        Path::new("/usr/local/bin/noo-hostd").is_file()
            || Path::new("/etc/systemd/system/noo-hostd.service").is_file(),
        "binary/unit still installed".into());
    item("namespace restore unit", Path::new(crate::netns_unit::UNIT_PATH).is_file(), crate::netns_unit::UNIT_PATH.into());
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let left = self_heal_unit_leftovers(&home);
    item("self-heal user units (host-watcher, noo-hostd)", !left.is_empty(),
        left.iter().map(|u| u.display().to_string()).collect::<Vec<_>>().join(", "));
    match docker_items(&["images", "--format", "{{.Repository}}"]) {
        Ok(l) => {
            let image_count = l.into_iter().filter(|i| crate::registry::is_our_image(i)).count();
            item("stack images", image_count > 0,
                format!("{image_count} present (fine to keep — makes the next onboard pull-free)"));
        }
        Err(why) => item("stack images (not checked)", true, format!("docker did not answer: {why}")),
    }

    let age = age_dir();
    item("age key", age.is_dir(), format!("{} (fine to keep across re-onboards)", age.display()));
    item("cluster CA trust",
        Path::new("/usr/local/share/ca-certificates/mesh-cluster-ca.crt").is_file(),
        "still in the trust store".into());

    // Tailscale: a stopped daemon still reporting an identity is the
    // finding-#17 trap — call it out explicitly.
    let ts = Command::new("tailscale").args(["status", "--json"]).output().ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok());
    match ts {
        Some(j) => {
            let state = j["BackendState"].as_str().unwrap_or("unknown").to_string();
            let dns = j["Self"]["DNSName"].as_str().unwrap_or("").trim_end_matches('.').to_string();
            let logged_in = state == "Running";
            item("tailnet identity", logged_in || !dns.is_empty(),
                if logged_in { format!("joined as {dns}") }
                else if !dns.is_empty() {
                    format!("STALE state file (daemon {state}, cached {dns}) — \
                             reset /var/lib/tailscale/tailscaled.state")
                } else { state });
        }
        None => {
            if print {
                println!("  {} tailnet identity  {}", ui::glyph_cell(Glyph::Ok), ui::muted("tailscale not installed/running"));
            }
        }
    }

    // Warn-only: a stale repo clone shadows repo_root() ranking (bit us live
    // 2026-08-23). Not counted as a leftover — a dev box legitimately has one.
    // Both names: a clone of noomesh/noomesh is `noomesh` and the checkout was
    // `pai-assistant` before the monorepo move, and a box mid-migration has
    // BOTH — which is exactly the case that shadows repo_root() ranking.
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let clone = ["noomesh", "pai-assistant"]
        .iter()
        .map(|n| home.join(n))
        .find(|p| p.is_dir())
        .unwrap_or_else(|| home.join("noomesh"));
    if clone.is_dir() && print {
        println!("  {} {}", ui::glyph_cell(Glyph::Bullet), ui::muted(&format!("repo clone at {} — fine on a dev box, but on a test \
                  box it shadows the standalone home (remove it there)", clone.display())));
    }
    let _ = g;
    leftovers
}

// ── helpers ─────────────────────────────────────────────────────────────

/// This install's Docker volumes, by name: the ones offboard deletes and the
/// ones its audit (`--check`, and the walk's own Verify) must not find.
pub(crate) fn stack_volumes(project: &str) -> Result<Vec<String>, String> {
    docker_list(&["volume", "ls", "--format", "{{.Name}}\t{{.Labels}}"]).map(|l| select_stack_volumes(&l, project))
}

/// This install's Docker networks: those whose compose project label IS this
/// project, plus the launcher's external cluster network by its exact name.
pub(crate) fn stack_networks(project: &str, cluster_net: &str) -> Result<Vec<String>, String> {
    docker_list(&["network", "ls", "--format", "{{.Name}}\t{{.Labels}}"]).map(|l| select_stack_networks(&l, project, cluster_net))
}

/// Pure: exact project label, or exactly the cluster network's name. Never a
/// name prefix (a box can run several stacks).
fn select_stack_networks(lines: &[String], project: &str, cluster_net: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let (name, labels) = line.split_once('\t').unwrap_or((line.as_str(), ""));
            (name == cluster_net
                || labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .any(|(k, v)| k == "com.docker.compose.project" && v == project))
            .then(|| name.to_string())
        })
        .collect()
}

/// Pure selection over `docker volume ls --format '{{.Name}}\t{{.Labels}}'`
/// lines: exactly the volumes whose `com.docker.compose.project` label IS
/// this install's project. Never a name glob. A box can run several stacks
/// (`noo-<instance>`, a dev checkout, someone else's compose project), and a
/// prefix match once reached across them. The old `{prefix}_` filter matched
/// nothing after the project rename (2026-09-01), and the `noomesh_*`
/// fallback that replaced it would also take `noomesh_*` volumes of a
/// different project.
fn select_stack_volumes(lines: &[String], project: &str) -> Vec<String> {
    // The one volume the launcher used to create OUTSIDE compose, by an exact
    // name: lib-instance.sh's gateway-dirs prep mounted `<project>_noo-data`
    // before compose made it, so every install from then on has it with no
    // project label (i677). An exact name, not a glob: docker volume names
    // are global, so this name is this project's volume and no other.
    let unlabelled_own = format!("{project}_noo-data");
    lines
        .iter()
        .filter_map(|line| {
            // lines_of trims each line, so an UNLABELLED volume (docker
            // prints "name<TAB>") arrives as "name" with no tab at all.
            let (name, labels) = line.split_once('\t').unwrap_or((line.as_str(), ""));
            (name == unlabelled_own
                || labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .any(|(k, v)| k == "com.docker.compose.project" && v == project))
            .then(|| name.to_string())
        })
        .collect()
}

/// Whether docker ANSWERS on this box. `NotInstalled` (no docker binary) is
/// a positive answer, since no container can exist. Permission denied, a
/// daemon that is down, or any other failure is `Err` with docker's reason:
/// never "nothing there" (i677 #20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DockerAccess {
    Reachable,
    NotInstalled,
}

pub(crate) fn docker_access() -> Result<DockerAccess, String> {
    docker_access_from(Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output())
}

/// [`docker_access`], pure over the spawn result.
fn docker_access_from(out: std::io::Result<std::process::Output>) -> Result<DockerAccess, String> {
    match out {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DockerAccess::NotInstalled),
        Err(e) => Err(format!("could not run docker: {e}")),
        // Reachable means the DAEMON answered with its version. An exit 0
        // with no version is not an answer: the matrix's Docker 28.0.4 shell
        // without the docker group passed this gate, and offboard stopped
        // the self-heal daemons before its first listing hit "permission
        // denied" (rc.2 install matrix, every cell's offboard probe).
        Ok(o) if o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty() => Ok(DockerAccess::Reachable),
        Ok(o) if o.status.success() => Err(match failure_reason(&o) {
            r if o.stderr.iter().any(|b| !b.is_ascii_whitespace()) => r,
            _ => "docker info reported no server version: the daemon did not answer".to_string(),
        }),
        Ok(o) => Err(failure_reason(&o)),
    }
}

fn failure_reason(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    err.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
        .unwrap_or_else(|| format!("docker exited {}", o.status.code().map_or("by a signal".into(), |c| c.to_string())))
}

/// One docker listing: the lines when docker answered, its reason when it
/// did not. There is no "empty on failure".
fn docker_list(args: &[&str]) -> Result<Vec<String>, String> {
    docker_list_from(Command::new("docker").args(args).output())
}

/// [`docker_list`], pure over the spawn result.
fn docker_list_from(out: std::io::Result<std::process::Output>) -> Result<Vec<String>, String> {
    match out {
        Err(e) => Err(format!("could not run docker: {e}")),
        Ok(o) if o.status.success() => Ok(lines_of(&String::from_utf8_lossy(&o.stdout))),
        Ok(o) => Err(failure_reason(&o)),
    }
}

/// The refusal when docker does not answer: line 0 is the verdict, the rest
/// are the two ways forward.
pub(crate) fn docker_unreachable_refusal(why: &str, verb: &str) -> Vec<String> {
    vec![
        format!("cannot reach docker ({why}): nothing was removed"),
        "this shell cannot use docker yet. Either run it from a shell where `docker ps` works".to_string(),
        "(after joining the docker group: a new terminal, or `newgrp docker`),".to_string(),
        format!("or as root: sudo {verb} (with the same flags)"),
    ]
}

/// docker stopped answering mid-walk: stop before the step's removal and say so.
fn stop_walk(step: &str, why: &str) -> i32 {
    ui::close_failed(
        &format!("docker did not answer while listing {step} ({why}): nothing from this step on was removed"),
        Some("docker ps"),
    );
    1
}

/// docker's stdout as trimmed, non-empty lines (what every docker_list caller sees).
fn lines_of(stdout: &str) -> Vec<String> {
    stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

/// The install's data root, read from its own .env (never guessed — deleting
/// a guessed path is how storage accidents happen).
fn storage_root(home: &Path) -> Option<String> {
    let env = std::fs::read_to_string(home.join(".env")).ok()?;
    env.lines().find_map(|l| l.trim().strip_prefix("NOO_DATA_ROOT=").map(str::to_string))
        .filter(|v| !v.is_empty() && v != "/" && v.len() > 4)
}

fn age_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/sops/age")
}

/// Run interactively (inherits the tty — sudo can prompt), report failures.
/// Bounded subprocess: `timeout -k 5 <secs>` around the command. Anything
/// that talks to tailscaled or systemd can wedge indefinitely; an offboard
/// step must never need Ctrl+C. Returns true only on a clean exit.
fn run_bounded(secs: u64, cmd: &str, args: &[&str]) -> bool {
    let mut c = Command::new("timeout");
    c.arg("-k").arg("5").arg(secs.to_string()).arg(cmd).args(args);
    match c.status() {
        Ok(s) if s.success() => true,
        Ok(s) if s.code() == Some(124) => {
            ui::warned(&format!("{cmd} {} timed out after {secs}s", args.join(" ", )));
            false
        }
        Ok(s) => {
            ui::warned(&format!("{cmd} {} exited {}", args.join(" ", ), s.code().unwrap_or(-1)));
            false
        }
        Err(e) => {
            ui::warned(&format!("could not run {cmd}: {e}"));
            false
        }
    }
}

fn run(cmd: &str, args: &[String]) {
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => ui::warned(&format!("{cmd} {} exited {}", args.join(" "), s.code().unwrap_or(-1))),
        Err(e) => ui::warned(&format!("could not run {cmd}: {e}")),
    }
}

#[cfg(test)]
mod volume_selection_tests {
    use super::*;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const LS: &[&str] = &[
        "noomesh_postgres-data\tcom.docker.compose.project=noomesh,com.docker.compose.volume=postgres-data",
        "noomesh_noo-data\tcom.docker.compose.volume=noo-data,com.docker.compose.project=noomesh",
        "renamed_by_hand\tcom.docker.compose.project=noomesh",
        "noo-galaxy_noo-data\tcom.docker.compose.project=noo-galaxy",
        "noomesh-dev_cache\tcom.docker.compose.project=noomesh-dev",
        "noomesh_not_ours\tcom.docker.compose.project=someone-else",
        "noomesh_unlabelled\t",
        "noomesh_noo-data2\t",
        "noo_legacy\t",
        "pai-assistant_hf-cache\t",
        "no-tab-at-all",
    ];

    /// Exactly this install's project, by label. Another instance, a dev
    /// project, another project's `noomesh_*` volume and unlabelled names are
    /// never selected: a box runs several stacks (i677a).
    #[test]
    fn only_this_projects_labelled_volumes_are_selected() {
        assert_eq!(
            select_stack_volumes(&lines(LS), "noomesh"),
            ["noomesh_postgres-data", "noomesh_noo-data", "renamed_by_hand"],
        );
        assert_eq!(select_stack_volumes(&lines(LS), "noo-galaxy"), ["noo-galaxy_noo-data"]);
        assert!(select_stack_volumes(&lines(LS), "noomesh-d").is_empty(), "no prefix match on the label either");
    }

    /// Every existing install has `<project>_noo-data` WITHOUT the project
    /// label (the launcher's prep created it before compose did). It is
    /// selected by its exact name. A longer name, another project's
    /// noo-data, or an unlabelled prefix match is not (i677).
    #[test]
    fn the_unlabelled_noo_data_of_this_project_is_selected_by_its_exact_name() {
        let ls = lines(&[
            // As lines_of hands it over: docker prints "noomesh_noo-data<TAB>"
            // and the trim removes the tab.
            "noomesh_noo-data",
            "noomesh_noo-data2",
            "noo-galaxy_noo-data",
            "noomesh_other",
            "noomesh_postgres-data\tcom.docker.compose.project=noomesh",
        ]);
        assert_eq!(select_stack_volumes(&ls, "noomesh"), ["noomesh_noo-data", "noomesh_postgres-data"]);
        assert_eq!(select_stack_volumes(&ls, "noo-galaxy"), ["noo-galaxy_noo-data"]);
    }

    /// End to end through the same parsing offboard uses: docker's raw
    /// `volume ls --format '{{.Name}}\t{{.Labels}}'` output, where an
    /// unlabelled volume is "name<TAB>" and the trim eats the tab.
    #[test]
    fn docker_raw_output_with_an_unlabelled_noo_data_selects_it() {
        let raw = "noomesh_noo-data\t\nnoomesh_postgres-data\tcom.docker.compose.project=noomesh\ngo-mod-cache\t\nnoomesh_noo-data2\t\n";
        assert_eq!(select_stack_volumes(&lines_of(raw), "noomesh"), ["noomesh_noo-data", "noomesh_postgres-data"]);
    }

    /// The project name mirrors scripts/lib-instance.sh.
    #[test]
    fn the_compose_project_mirrors_the_launcher() {
        use crate::envfile::project_for;
        assert_eq!(project_for("", None), "noomesh");
        assert_eq!(project_for("galaxy", None), "noo-galaxy");
        assert_eq!(project_for("galaxy", Some("custom")), "custom");
        assert_eq!(project_for("", Some(" \"\" ")), "noomesh", "a blank override is no override");
    }

    /// The audit (`noo offboard --check`, and the walk's own Verify) counts
    /// with the SAME selector and project the removal deletes with. It once
    /// counted `{prefix}_` (`noo_`) and could not see a `noomesh_*` volume a
    /// failed removal left, so the leftover read "clean" (i677a).
    #[test]
    fn the_audit_and_the_removal_share_one_selector_and_project() {
        let code = crate::test_src::own_code(include_str!("offboard.rs"));
        let audit = crate::test_src::fn_body(&code, "fn audit_leftovers(");
        assert!(audit.contains("Ok(DockerAccess::Reachable) => stack_volumes(&crate::envfile::compose_project()),"), "{audit}");
        // The removal's listing and its re-check both ask LiveWalk::volumes
        // (stack_step calls it twice: stack_step_tests).
        assert_eq!(code.matches("stack_volumes(self.project)").count(), 1, "the walk's one volume source");
        assert_eq!(code.matches("stack_volumes(&project)").count(), 0, "nothing else lists the volumes");
        assert_eq!(code.matches("\"volume\", \"ls\"").count(), 1, "one volume listing, inside stack_volumes");
    }

    /// What the stack step could not remove fails the walk: exit 1 before
    /// any "complete" line (the step itself: `stack_step_tests`).
    #[test]
    fn what_the_stack_step_could_not_remove_fails_the_walk() {
        let code = crate::test_src::own_code(include_str!("offboard.rs"));
        let walk = crate::test_src::fn_body(&code, "pub fn offboard(");
        let step = walk.find("Ok(failed) => removal_failed.extend(failed),").expect("the step's failures are kept");
        let fail = walk.find("if !removal_failed.is_empty() {").expect("the walk judges it");
        let complete = walk.find("ui::close_done(\"offboard complete\")").expect("the success line");
        assert!(step < fail && fail < complete, "{walk}");
        let judged = &walk[fail..complete];
        assert!(judged.contains("ui::close_failed(") && judged.contains("return Ok(1);"), "{judged}");
    }
}

#[cfg(test)]
mod docker_gate_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn out(code: i32, stdout: &str, stderr: &str) -> std::io::Result<std::process::Output> {
        Ok(std::process::Output { status: std::process::ExitStatus::from_raw(code << 8), stdout: stdout.into(), stderr: stderr.into() })
    }

    /// i677 #20: a docker that does not answer is never "nothing there".
    #[test]
    fn only_an_answer_or_a_missing_binary_is_a_positive_answer() {
        assert_eq!(docker_access_from(out(0, "29.0.1\n", "")), Ok(DockerAccess::Reachable));
        assert_eq!(
            docker_access_from(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            Ok(DockerAccess::NotInstalled),
            "no docker binary: no stack can exist"
        );
        let denied = docker_access_from(out(1, "", "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n"));
        assert_eq!(denied, Err("permission denied while trying to connect to the docker API at unix:///var/run/docker.sock".to_string()));
        let down = docker_access_from(out(1, "", "\nCannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n"));
        assert!(down.as_ref().is_err_and(|e| e.starts_with("Cannot connect to the Docker daemon")), "{down:?}");
        assert_eq!(docker_access_from(out(1, "", "")), Err("docker exited 1".to_string()));
        assert!(docker_access_from(Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).is_err(), "a binary we may not run is not 'not installed'");
    }

    /// An exit 0 with no server version is not an answer (rc.2 matrix: a
    /// shell without the docker group got past the gate on Docker 28.0.4).
    #[test]
    fn exit_zero_with_no_server_version_is_not_an_answer() {
        let denied = docker_access_from(out(0, "", "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock\n"));
        assert_eq!(denied, Err("permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock".to_string()));
        let silent = docker_access_from(out(0, "\n", ""));
        assert!(silent.as_ref().is_err_and(|e| e.contains("no server version")), "{silent:?}");
        assert_eq!(docker_access_from(out(0, "28.0.4\n", "WARNING: bridge-nf-call-iptables is disabled\n")), Ok(DockerAccess::Reachable),
            "a version with a warning on stderr is an answer");
    }

    #[test]
    fn a_failed_listing_is_an_error_never_an_empty_list() {
        assert_eq!(docker_list_from(out(0, "a\n\nb\n", "")), Ok(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(docker_list_from(out(0, "", "")), Ok(vec![]), "docker answered: nothing there");
        assert!(docker_list_from(out(1, "", "permission denied")).is_err());
        assert!(docker_list_from(Err(std::io::Error::from(std::io::ErrorKind::NotFound))).is_err(),
            "a listing never decides 'not installed': only the gate does");
    }

    #[test]
    fn the_refusal_says_nothing_was_removed_and_the_two_ways_forward() {
        let l = docker_unreachable_refusal("permission denied", "noo offboard");
        assert_eq!(l[0], "cannot reach docker (permission denied): nothing was removed");
        let rest = l[1..].join(" ");
        assert!(rest.contains("`docker ps` works") && rest.contains("newgrp docker") && rest.contains("sudo noo offboard"), "{rest}");
    }

    /// The gate runs before step 0 (stopping the daemons) and before the
    /// stack step, and its refusal returns; no call site can read a failed
    /// docker as empty any more. (What the gate decides: `stack_step_tests`.)
    #[test]
    fn the_walk_asks_docker_before_it_stops_or_removes_anything() {
        let code = crate::test_src::own_code(include_str!("offboard.rs"));
        assert!(!code.contains("docker_lines("), "the empty-on-failure helper is gone");
        let walk = crate::test_src::fn_body(&code, "pub fn offboard(");
        let gate = walk.find("let docker = match docker_gate(&mut LiveGate, \"noo offboard\") {").expect("the gate");
        let refuse = walk[gate..].find("Err(code) => return Ok(code),").map(|i| i + gate).expect("it refuses");
        let stop = walk.find("stop_self_heal_daemons(true);").expect("step 0");
        let step = walk.find("match stack_step(&mut walk, docker, &prefix) {").expect("the stack step");
        let images = walk.find("let image_lines = match stack_image_lines(&mut walk, docker) {").expect("the image listing");
        let first_rm = walk.find("run(\"docker\"").expect("a docker removal");
        assert!(gate < refuse && refuse < stop && stop < step && step < images && images < first_rm, "{walk}");
        for at in [step, images] {
            let end = walk[at..].find("\n    }").expect("the match closes");
            let arms = &walk[at..at + end];
            assert!(arms.contains("Err(code) => return Ok(code),"), "each step's refusal returns: {arms}");
        }
    }

    /// The audit marks what it could not read as a leftover ("not checked"),
    /// so --check exits 1 and Verify never says fresh.
    #[test]
    fn the_audit_never_counts_an_unanswered_docker_as_clean() {
        let code = crate::test_src::own_code(include_str!("offboard.rs"));
        let audit = crate::test_src::fn_body(&code, "fn audit_leftovers(");
        for label in ["stack containers (not checked)", "stack volumes (not checked)", "stack images (not checked)"] {
            assert!(audit.contains(&format!("item(\"{label}\", true,")), "{label}: {audit}");
        }
    }
}

#[cfg(test)]
mod network_selection_tests {
    use super::*;

    /// i677a (matrix run 4): offboard said "complete" with noomesh_noo-browser,
    /// noomesh_noo-db, noomesh_noo-pg-host and noomesh_noo-sandbox left. The
    /// old match was `noo-cluster` or a `noo_` prefix. Now: the exact project
    /// label, or the external cluster network by its exact name; never a prefix.
    #[test]
    fn this_projects_networks_and_the_cluster_network_are_selected_and_nothing_else() {
        let ls: Vec<String> = [
            "noomesh_noo-db\tcom.docker.compose.network=noo-db,com.docker.compose.project=noomesh",
            "noomesh_noo-sandbox\tcom.docker.compose.project=noomesh",
            "noo-cluster",
            "noo-cluster-2",
            "noo-galaxy_noo-db\tcom.docker.compose.project=noo-galaxy",
            "noomesh_unlabelled",
            "bridge",
            "host",
        ].iter().map(|s| s.to_string()).collect();
        assert_eq!(select_stack_networks(&ls, "noomesh", "noo-cluster"), ["noomesh_noo-db", "noomesh_noo-sandbox", "noo-cluster"]);
        assert_eq!(select_stack_networks(&ls, "noo-galaxy", "noo-galaxy-cluster"), ["noo-galaxy_noo-db"]);
    }

    #[test]
    fn the_cluster_network_name_mirrors_the_launcher() {
        use crate::envfile::cluster_network_for;
        assert_eq!(cluster_network_for("", None), "noo-cluster");
        assert_eq!(cluster_network_for("", Some("my-net")), "my-net");
        assert_eq!(cluster_network_for("galaxy", Some("ignored")), "noo-galaxy-cluster");
    }

    /// Networks are part of the one stack consent, removed after the
    /// containers, re-checked like the volumes (the order and the survivor:
    /// `stack_step_tests`), selected by label not name prefix, and audited.
    #[test]
    fn networks_are_selected_by_label_and_audited() {
        let code = crate::test_src::own_code(include_str!("offboard.rs"));
        for f in ["pub fn offboard(", "fn stack_step("] {
            let body = crate::test_src::fn_body(&code, f);
            assert!(!body.contains("n.starts_with(&format!(\"{prefix}_\"))"), "no name prefix: {body}");
        }
        let audit = crate::test_src::fn_body(&code, "fn audit_leftovers(");
        assert!(audit.contains("item(\"stack networks (not checked)\", true,"), "{audit}");
    }
}

#[cfg(test)]
mod self_heal_unit_tests {
    use super::*;

    fn scratch_home(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-i677a-3c-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".config/systemd/user")).unwrap();
        d
    }

    /// i677a 3c: both the watcher's AND noo-hostd's user units go, by exact
    /// path; a neighbouring unit is never touched.
    #[test]
    fn both_self_heal_user_units_are_removed_and_nothing_else() {
        let home = scratch_home("rm");
        let dir = home.join(".config/systemd/user");
        for f in ["noo-host-watcher.service", "noo-hostd.service", "someone-else.service"] {
            std::fs::write(dir.join(f), "[Unit]\n").unwrap();
        }
        assert_eq!(self_heal_unit_leftovers(&home).len(), 2, "the audit sees both before removal");
        remove_self_heal_units(&home);
        assert!(!dir.join("noo-hostd.service").exists(), "the hostd user unit was left on disk");
        assert!(!dir.join("noo-host-watcher.service").exists());
        assert!(dir.join("someone-else.service").exists(), "exact paths only");
        assert!(self_heal_unit_leftovers(&home).is_empty());
        remove_self_heal_units(&home); // absent is fine
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The audit lists a surviving hostd unit (not only the watcher's).
    #[test]
    fn the_audit_lists_a_surviving_hostd_unit() {
        let home = scratch_home("audit");
        std::fs::write(home.join(".config/systemd/user/noo-hostd.service"), "[Unit]\n").unwrap();
        assert_eq!(self_heal_unit_leftovers(&home), vec![home.join(".config/systemd/user/noo-hostd.service")]);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The daemon stop (shared with `stack clean --all/--deep`) and the
    /// audit use the tested functions.
    #[test]
    fn the_stop_and_the_audit_use_the_tested_functions() {
        let own = crate::test_src::own_code(include_str!("offboard.rs"));
        let stop = crate::test_src::fn_body(&own, "pub(crate) fn stop_self_heal_daemons(");
        assert!(stop.contains("remove_self_heal_units(Path::new(&h));"), "{stop}");
        let audit = crate::test_src::fn_body(&own, "fn audit_leftovers(");
        assert!(audit.contains("self_heal_unit_leftovers(&home)"), "{audit}");
    }
}

#[cfg(test)]
mod netns_unit_offboard_tests {
    /// We remove what we install: the walk removes noo-netns-restore.service
    /// and the audit lists it if it survives (#1108).
    #[test]
    fn offboard_removes_and_audits_the_namespace_restore_unit() {
        let own = crate::test_src::own_code(include_str!("offboard.rs"));
        let walk = crate::test_src::fn_body(&own, "pub fn offboard(");
        assert!(walk.contains("crate::netns_unit::remove(unsafe { libc::isatty(0) } == 1)"), "{walk}");
        let audit = crate::test_src::fn_body(&own, "fn audit_leftovers(");
        assert!(audit.contains(r#"item("namespace restore unit", Path::new(crate::netns_unit::UNIT_PATH).is_file()"#), "{audit}");
    }
}

#[cfg(test)]
mod stack_step_tests {
    use super::*;

    /// A fake gate: docker's answer, and every effect.
    struct FakeGate {
        access: Result<DockerAccess, String>,
        relaunch: Option<i32>,
        refused: Vec<String>,
        relaunched: u32,
    }

    impl GateHost for FakeGate {
        fn access(&mut self) -> Result<DockerAccess, String> {
            self.access.clone()
        }
        fn relaunch(&mut self, _why: &str) -> Option<i32> {
            self.relaunched += 1;
            self.relaunch
        }
        fn refuse(&mut self, lines: &[String]) {
            self.refused.extend(lines.iter().cloned());
        }
    }

    fn gate(access: Result<DockerAccess, String>, relaunch: Option<i32>) -> FakeGate {
        FakeGate { access, relaunch, refused: Vec::new(), relaunched: 0 }
    }

    /// m1: a docker that does not answer is refused (exit 1, "nothing was
    /// removed"), never read as "not installed".
    #[test]
    fn an_unanswered_docker_is_refused_never_read_as_absent() {
        let mut h = gate(Err("permission denied while trying to connect".into()), None);
        assert_eq!(docker_gate(&mut h, "noo offboard"), Err(1));
        assert_eq!(h.refused[0], "cannot reach docker (permission denied while trying to connect): nothing was removed");
        assert!(h.refused.iter().any(|l| l.contains("sudo noo offboard")), "{:?}", h.refused);
        // The one shell that can be fixed is run again; its exit is the walk's.
        let mut h = gate(Err("permission denied".into()), Some(0));
        assert_eq!((docker_gate(&mut h, "noo offboard"), h.refused.len()), (Err(0), 0));
        // An answer passes, and so does no docker at all.
        for d in [DockerAccess::Reachable, DockerAccess::NotInstalled] {
            let mut h = gate(Ok(d), None);
            assert_eq!((docker_gate(&mut h, "noo offboard"), h.relaunched, h.refused.len()), (Ok(d), 0, 0));
        }
    }

    /// A fake stack: what each docker listing answers (in call order), the
    /// user's answer, and every effect.
    #[derive(Default)]
    struct FakeStack {
        containers: Option<Result<Vec<String>, String>>,
        images: Option<Result<Vec<String>, String>>,
        volumes: Vec<Result<Vec<String>, String>>,
        networks: Vec<Result<Vec<String>, String>>,
        declines: bool,
        asked: u32,
        ran: Vec<Vec<String>>,
        said: Vec<String>,
        stopped: Vec<String>,
    }

    impl StackHost for FakeStack {
        fn list(&mut self, args: &[&str]) -> Result<Vec<String>, String> {
            match args.first() {
                Some(&"ps") => self.containers.clone().unwrap_or(Ok(Vec::new())),
                Some(&"images") => self.images.clone().unwrap_or(Ok(Vec::new())),
                other => panic!("unexpected listing {other:?}"),
            }
        }
        fn volumes(&mut self) -> Result<Vec<String>, String> {
            if self.volumes.is_empty() { Ok(Vec::new()) } else { self.volumes.remove(0) }
        }
        fn networks(&mut self) -> Result<Vec<String>, String> {
            if self.networks.is_empty() { Ok(Vec::new()) } else { self.networks.remove(0) }
        }
        fn confirm(&mut self, _q: &str) -> bool {
            self.asked += 1;
            !self.declines
        }
        fn run(&mut self, cmd: &str, args: &[String]) {
            self.ran.push([vec![cmd.to_string()], args.to_vec()].concat());
        }
        fn item(&mut self, label: &str) {
            self.said.push(format!("item {label}"));
        }
        fn sub(&mut self, _g: Glyph, msg: &str) {
            self.said.push(msg.to_string());
        }
        fn stop_walk(&mut self, step: &str, why: &str) -> i32 {
            self.stopped.push(format!("{step}: {why}"));
            1
        }
    }

    fn names(v: &[&str]) -> Result<Vec<String>, String> {
        Ok(v.iter().map(|s| s.to_string()).collect())
    }

    fn a_stack() -> FakeStack {
        FakeStack {
            containers: Some(names(&["c1"])),
            volumes: vec![names(&["noomesh_noo-data"])],
            networks: vec![names(&["noomesh_default"])],
            ..Default::default()
        }
    }

    /// m2: a listing docker did not answer stops the walk before anything
    /// of this step is asked or removed; it is never read as "nothing there".
    #[test]
    fn an_unanswered_stack_listing_stops_the_walk_before_any_removal() {
        for broken in ["containers", "volumes", "networks"] {
            let mut h = a_stack();
            let err = || Err::<Vec<String>, String>("permission denied".into());
            match broken {
                "containers" => h.containers = Some(err()),
                "volumes" => h.volumes = vec![err()],
                _ => h.networks = vec![err()],
            }
            assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Err(1), "{broken}");
            assert_eq!(h.stopped, ["the stack's containers, volumes and networks: permission denied"], "{broken}");
            assert_eq!((h.asked, h.ran.len(), h.said.len()), (0, 0, 0), "{broken}: nothing asked, run or said");
        }
    }

    /// m3: the same for the image listing.
    #[test]
    fn an_unanswered_image_listing_stops_the_walk() {
        let mut h = FakeStack { images: Some(Err("permission denied".into())), ..Default::default() };
        assert_eq!(stack_image_lines(&mut h, DockerAccess::Reachable), Err(1));
        assert_eq!(h.stopped, ["the stack images: permission denied"]);
        let mut h = FakeStack { images: Some(names(&["ghcr.io/noomesh/gateway\tsha256:1"])), ..Default::default() };
        assert_eq!(stack_image_lines(&mut h, DockerAccess::Reachable), Ok(vec!["ghcr.io/noomesh/gateway\tsha256:1".to_string()]));
        // No docker at all: nothing is listed and nothing stops.
        let mut h = FakeStack { images: Some(Err("unreachable".into())), ..Default::default() };
        assert_eq!((stack_image_lines(&mut h, DockerAccess::NotInstalled), h.stopped.len()), (Ok(Vec::new()), 0));
    }

    /// The agreed removal, then a re-check that finds the stack gone: no
    /// failure. Containers first, then volumes, then networks.
    #[test]
    fn a_removed_stack_rechecks_clean() {
        let mut h = a_stack();
        h.volumes.push(names(&[]));
        h.networks.push(names(&[]));
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec![]));
        assert_eq!(h.asked, 1);
        let ran: Vec<String> = h.ran.iter().map(|r| r.join(" ")).collect();
        assert_eq!(ran, ["docker rm -f c1", "docker volume rm -f noomesh_noo-data", "docker network rm noomesh_default"]);
    }

    /// What is still there after its removal fails the walk.
    #[test]
    fn a_volume_that_survives_its_removal_fails_the_walk() {
        let mut h = a_stack();
        h.volumes.push(names(&["noomesh_noo-data"]));
        h.networks.push(names(&["noomesh_default"]));
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec!["volume noomesh_noo-data".into(), "network noomesh_default".into()]));
    }

    /// m8: a volume re-check that cannot ask docker is a removal FAILURE,
    /// never "nothing left".
    #[test]
    fn a_volume_recheck_that_cannot_ask_docker_fails_the_walk() {
        let mut h = a_stack();
        h.volumes.push(Err("permission denied".into()));
        h.networks.push(names(&[]));
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec!["volumes (not re-checked: permission denied)".into()]));
    }

    /// m9: the same for the network re-check.
    #[test]
    fn a_network_recheck_that_cannot_ask_docker_fails_the_walk() {
        let mut h = a_stack();
        h.volumes.push(names(&[]));
        h.networks.push(Err("permission denied".into()));
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec!["networks (not re-checked: permission denied)".into()]));
    }

    /// A declined prompt removes nothing; an answered empty listing is a
    /// positive "clean"; no docker at all lists nothing.
    #[test]
    fn declined_clean_and_absent_remove_nothing() {
        let mut h = FakeStack { declines: true, ..a_stack() };
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec![]));
        assert_eq!((h.ran.len(), h.said.last().map(String::as_str)), (0, Some("kept (skipped)")));
        let mut h = FakeStack::default();
        assert_eq!(stack_step(&mut h, DockerAccess::Reachable, "noo"), Ok(vec![]));
        assert_eq!((h.asked, h.said.last().map(String::as_str)), (0, Some("no containers, volumes or networks — already clean")));
        let mut h = FakeStack { containers: Some(Err("unreachable".into())), ..Default::default() };
        assert_eq!(stack_step(&mut h, DockerAccess::NotInstalled, "noo"), Ok(vec![]));
        assert_eq!(h.said.last().map(String::as_str), Some("docker is not installed: no stack here"));
    }
}
