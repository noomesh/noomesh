// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo stack …` — Docker service management, the SELF-MANAGEMENT surface.
//!
//! Unlike every other native group these handlers spawn subprocesses
//! (docker, the repo's `scripts/*.sh`) instead of calling the gateway: they
//! must keep working when the Python venv or the gateway itself is broken —
//! that is the point of the static Rust binary. No http.rs/auth usage.
//!
//! JSON contract (mirrors `noomesh/mesh_cli.py`):
//!   - action commands (start/stop/restart/rebuild) redirect the script's
//!     stdout to OUR stderr (stdout stays data-only) and emit
//!     `{"status":"ok","action":…}` on success; a failed script exits with
//!     the child's code (never 0) after `{"error":…,"code":…}` on stderr.
//!   - `status --json` skips the script and emits structured container JSON
//!     straight from `docker ps`.
//!
//! WP-B2 adds the remaining self-management commands: `reset` (spawns
//! scripts/noomesh-reset.sh; destructive → agent-first confirm contract),
//! `ollama` (docker-exec pass-through with inherited stdio), and
//! `install-watcher` — now a retired stub (the bash host watcher is gone;
//! noo-hostd executes the host spool).

use std::io::Write as _;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::envfile::repo_root;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

fn print_json(v: &serde_json::Value) {
    // Python's output_json uses indent=2 — match it.
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
}

/// Run a `scripts/` bash script with cwd = repo root (the scripts reference
/// docker-compose.cluster.yml relatively). Human mode: inherited stdio,
/// return the child's exit code. `--json` mode with `json_action`: child
/// stdout → our stderr, then the `{"status":"ok","action":…}` contract.
fn run_script(g: &Globals, name: &str, args: &[String], json_action: Option<&str>) -> i32 {
    let root = repo_root();
    let script = root.join("scripts").join(name);
    if !script.is_file() {
        fail(
            g.json,
            ExitCode::Generic,
            "error",
            &format!("Script not found: {}", script.display()),
            None,
        );
    }

    // The gateway mounts `pki/public/{nodes,services}` and `pki/sso`, not
    // the PKI root. Re-sync the certificate-only view
    // before every launcher that can (re)create the gateway, so a cert
    // written by anything but this CLI's issuer is current and the bind
    // sources exist as the operator's. Silent when it works; a failure is
    // one stderr line, and the launcher's bind-source check has the final
    // word on a missing directory.
    if ["start", "restart", "rebuild"].iter().any(|verb| name == format!("noomesh-{verb}.sh")) {
        let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
        if ca.ca_cert_path().is_file() {
            for e in ca.sync_public_view().errors {
                let why = super::pki::public_view_hint(&ca, &e).unwrap_or(e);
                eprintln!("warning: gateway certificate view (pki/public/): {why} — then: noo security pki fix-modes");
            }
        }
    }

    // Postgres role leaves (i132). This release's pg_hba requires a client
    // certificate whose CN is the role being asked for, and its compose points
    // each DSN at `gateway/pg/<role>.*` or `<leaf>/pg/<role>.*`. An install
    // started from a checkout that predates them (no `noo upgrade --stack`
    // in between) has none: mint what is absent, as the operator, BEFORE the
    // launcher recreates anything. Idempotent; a leaf that cannot be issued
    // refuses the start here, with the fix, instead of leaving the database
    // unreachable for every container.
    if ["start", "restart", "rebuild"].iter().any(|verb| name == format!("noomesh-{verb}.sh")) {
        let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
        if ca.ca_exists() {
            let failed: Vec<String> = ca
                .ensure_pg_leaves(crate::pki::DEFAULT_DAYS)
                .into_iter()
                .filter_map(|(l, r)| r.err().map(|e| format!("{} ({}): {e}", l.role, l.cert_rel())))
                .collect();
            if !failed.is_empty() {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "pg_role_leaf_failed",
                    &format!(
                        "could not issue the Postgres client certificate(s) this release's pg_hba requires: {} — nothing was started",
                        failed.join("; ")
                    ),
                    Some("noo security pki fix-modes   # then re-run the same command"),
                );
            }
        }
    }

    // The gateway refuses to boot without its audit key. Mint it into the
    // encrypted store when absent, BEFORE the launcher can recreate the
    // gateway; a store that cannot be read is left to the launcher, which
    // fails closed on it with its own explanation.
    if ["start", "restart", "rebuild"].iter().any(|verb| name == format!("noomesh-{verb}.sh")) {
        match super::upgrade::ensure_audit_key_for_launch(&root) {
            Ok(true) => eprintln!("minted NOO_AUDIT_HMAC_KEY into the encrypted store (the gateway will not start without the audit log's signing key)"),
            Ok(false) => {}
            Err(e) => eprintln!("warning: could not check NOO_AUDIT_HMAC_KEY in the encrypted store: {e}"),
        }
    }

    let mut cmd = Command::new("bash");
    cmd.arg(&script).args(args).current_dir(&root);
    // The launcher's lib-ui.sh mirrors the CLI palette; hand it the
    // CLI's resolved mode so `noo --color=never stack start` and a piped
    // stdout render the script's output the same way as ours.
    cmd.env("NOO_COLOR", if crate::ui::styled() { "always" } else { "never" });
    // The launcher's `noo_bin` helper (scripts/lib-config.sh) prefers this
    // over `command -v noo` so it calls the SAME binary that invoked it —
    // not whatever else happens to be on PATH — for its internal
    // `config launch-render` reads of noomesh.yaml (2026-09-29: a
    // newcomer host with neither PATH `noo` nor host PyYAML was silently
    // skipping compose_env/addons/mounts).
    if let Ok(exe) = std::env::current_exe() {
        cmd.env("NOO_CLI_BIN", exe);
    }

    if let (true, Some(action)) = (g.json, json_action) {
        // stdout stays data-only in json mode: route the script's stdout to
        // our stderr (dup(2) so the child owns its copy of the fd).
        let stderr_copy = unsafe { libc::dup(2) };
        if stderr_copy >= 0 {
            cmd.stdout(unsafe { Stdio::from_raw_fd(stderr_copy) });
        }
        let status = match cmd.status() {
            Ok(s) => s,
            Err(e) => fail(
                g.json,
                ExitCode::Generic,
                "subprocess_failed",
                &format!("failed to run {name}: {e}"),
                None,
            ),
        };
        if status.success() {
            print_json(&serde_json::json!({"status": "ok", "action": action}));
            return 0;
        }
        let rc = status.code().unwrap_or(1);
        eprintln!(
            "{}",
            serde_json::json!({"error": format!("{name} exited with {rc}"), "code": "subprocess_failed"})
        );
        return if rc == 0 { 1 } else { rc };
    }

    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "subprocess_failed",
            &format!("failed to run {name}: {e}"),
            None,
        ),
    }
}

/// Recreate ONE compose service (`noomesh-restart.sh --force <service>`) so
/// it re-reads `.env` / the store. For callers that must keep their own
/// stdout clean (posture commands under `--json`): the script's stdout goes to
/// our stderr. `Err` carries the exit status.
pub(crate) fn recreate_service(service: &str) -> Result<(), String> {
    let root = repo_root();
    let script = root.join("scripts/noomesh-restart.sh");
    if !script.is_file() {
        return Err(format!("{} not found: cannot recreate {service}", script.display()));
    }
    // The script's stdout goes to our stderr (see the doc comment); if the
    // dup fails, it inherits ours.
    let stderr_copy = unsafe { libc::dup(2) };
    let stdout = if stderr_copy >= 0 { unsafe { Stdio::from_raw_fd(stderr_copy) } } else { Stdio::inherit() };
    let status = Command::new("bash")
        .arg(&script)
        .arg("--force")
        .arg(service)
        .current_dir(&root)
        .env("NOO_COLOR", "never")
        .envs(std::env::current_exe().ok().map(|exe| ("NOO_CLI_BIN", exe)))
        .stdout(stdout)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("noomesh-restart.sh --force {service} exited {}", s.code().unwrap_or(1))),
        Err(e) => Err(format!("could not run noomesh-restart.sh: {e}")),
    }
}

/// `noo stack status` — every `noo-*` container from `docker ps -a`,
/// rendered natively (human: glyph table; `--json`: `{containers, count}`).
/// `--watch [SECS]` (default 2): redraw on a TTY until Ctrl-C. Rejected
/// under `--json`/`--quiet` and off a terminal, where it makes no sense.
pub fn mesh_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok((rest, watch)) = crate::ui::take_watch(args) else { return Err(Unhandled) };
    let Some(secs) = watch else { return mesh_status_once(g, &rest) };
    if g.json || g.quiet || !crate::ui::styled() {
        crate::output::fail(g.json, crate::output::ExitCode::Usage, "usage",
            "--watch needs an interactive terminal (not --json/--quiet or a pipe)", None);
    }
    Ok(crate::ui::watch_loop(secs, || mesh_status_once(g, &rest).unwrap_or(2)))
}

fn mesh_status_once(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }

    let serve = controller_serve_status();
    let out = Command::new("docker")
        .args(["ps", "-a", "--filter", "name=noo-", "--format", "{{json .}}"])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(_) => fail(g.json, ExitCode::Generic, "subprocess_failed", "docker not found on PATH", None),
    };
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if msg.is_empty() { "docker ps failed".to_string() } else { msg };
        let rc = out.status.code().unwrap_or(1);
        if g.json {
            eprintln!("{}", serde_json::json!({"error": msg, "code": "subprocess_failed"}));
        } else {
            ui::failed(&msg, Some("sudo systemctl start docker"));
        }
        return Ok(if rc == 0 { 1 } else { rc });
    }
    let mut containers = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(c) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        containers.push(serde_json::json!({
            "name": c["Names"].as_str().unwrap_or(""),
            "service": compose_service(c["Labels"].as_str().unwrap_or("")),
            "image": c["Image"].as_str().unwrap_or(""),
            "state": c["State"].as_str().unwrap_or(""),
            "status": c["Status"].as_str().unwrap_or(""),
            "ports": c["Ports"].as_str().unwrap_or(""),
        }));
    }
    let count = containers.len();
    // A container docker keeps restarting is broken, not "up" (i58); so is
    // one that EXITED, unless it is a declared one-shot that exited 0 (i64a):
    // the exit code says so, whatever the table prints.
    let failed = failed_containers(&containers, crate::oneshots::declared());
    let exit = i32::from(!failed.is_empty());
    if g.json {
        print_json(&serde_json::json!({
            "containers": containers, "count": count, "failed": failed, "tailnet_serve": serve_word(&serve),
        }));
        return Ok(exit);
    }

    // Human view: the same container set rendered natively. (Until
    // 2026-09-03 this path ran scripts/noomesh-status.sh — compose ps plus a
    // "spawned backends" tail; the native table shows every noo-* container
    // in one list, compose-managed and node-agent-spawned alike.)
    let right = format!("{} on {}", crate::role::detect().label(), std::env::var("NOO_INSTANCE").unwrap_or_else(|_| "default".into()));
    println!("{}", ui::header("stack", Some(&right)));
    if containers.is_empty() {
        println!("{}", ui::muted("no containers"));
        println!("{}", ui::hint("noo stack start"));
        return Ok(0);
    }
    println!("{}", ui::section("containers"));
    let mut running = 0usize;
    let rows: Vec<Vec<String>> = containers
        .iter()
        .map(|c| {
            let state = c["state"].as_str().unwrap_or("");
            let glyph = match state {
                "running" => {
                    running += 1;
                    Glyph::Ok
                }
                // A declared one-shot that finished cleanly is done, not down.
                "exited" if finished_oneshot(c, crate::oneshots::declared()) => {
                    running += 1;
                    Glyph::Ok
                }
                "exited" | "dead" => Glyph::Err,
                _ => Glyph::Warn,
            };
            // docker's own "Up 3 days (healthy)" is the detail; strip the
            // leading state word it repeats.
            let detail = c["status"].as_str().unwrap_or("").to_string();
            vec![
                ui::glyph_cell(glyph),
                c["name"].as_str().unwrap_or("").trim_start_matches("noo-").to_string(),
                ui::state(state),
                detail,
                c["image"].as_str().unwrap_or("").to_string(),
                c["ports"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("service"), Col::left("state"), Col::left("since"), Col::left("image"), Col::left("ports")],
            &rows,
        )
    );
    if running < count {
        println!();
        println!("{}", ui::status_line(Glyph::Warn, &format!("{} of {count} containers not running", count - running)));
        let looping: Vec<&str> = containers.iter()
            .filter(|c| c["state"].as_str() == Some("restarting"))
            .filter_map(|c| c["name"].as_str())
            .collect();
        if !looping.is_empty() {
            println!("{}", ui::status_line(Glyph::Err, &format!("crash-looping (Restarting): {}", looping.join(", "))));
        }
        let exited: Vec<&str> = failed.iter().map(String::as_str).filter(|n| !looping.contains(n)).collect();
        if !exited.is_empty() {
            println!("{}", ui::status_line(Glyph::Err, &format!("exited and not a finished one-shot: {}", exited.join(", "))));
        }
        println!("{}", ui::hint("noo stack logs <service>"));
    }
    // A controller with no serve mapping is reachable by IP and by nothing
    // else — the dashboard URL and every MCP door are dead while every
    // container is green (host8 after the 2026-09-01 promote).
    match &serve {
        Some(crate::tailnet_serve::Status::NotMapped) => {
            println!();
            println!("{}", ui::status_line(Glyph::Warn, "tailnet serve: no mapping — the dashboard and MCP doors are not fronted on the tailnet"));
            println!("{}", ui::hint("noo controller promote"));
        }
        Some(crate::tailnet_serve::Status::Mapped { fronts_gateway: false, paths }) => {
            println!();
            println!("{}", ui::status_line(Glyph::Warn, &format!("tailnet serve: maps {} but nothing reaches the gateway", paths.join(", "))));
        }
        // Fronted: say WHERE. This was the one healthy case that printed
        // nothing, so the operator's own URL lived only in onboarding's
        // scrollback.
        Some(crate::tailnet_serve::Status::Mapped { fronts_gateway: true, .. }) => {
            crate::tailnet_serve::print_front_door(8080 + crate::envfile::port_offset(), &crate::envfile::instance());
        }
        _ => {}
    }
    Ok(exit)
}

/// The compose service from docker's `Labels` (`k=v,k=v`), or "".
fn compose_service(labels: &str) -> String {
    labels
        .split(',')
        .find_map(|kv| kv.strip_prefix("com.docker.compose.service="))
        .unwrap_or("")
        .to_string()
}

/// A declared one-shot (by its compose service, else its container name)
/// that exited 0.
fn finished_oneshot(c: &serde_json::Value, oneshots: &[String]) -> bool {
    let service = c["service"].as_str().unwrap_or("");
    let name = c["name"].as_str().unwrap_or("");
    let declared = (!service.is_empty() && crate::oneshots::is_oneshot_in(service, oneshots))
        || crate::oneshots::is_oneshot_in(name, oneshots);
    declared && crate::oneshots::exit_code(c["status"].as_str().unwrap_or("")) == Some(0)
}

/// The containers that make `noo stack status` exit 1: `restarting`
/// (crash-looping, i58), `dead`, and `exited` unless a declared one-shot
/// that exited 0 (i64a). Named, in docker's order.
fn failed_containers(containers: &[serde_json::Value], oneshots: &[String]) -> Vec<String> {
    containers
        .iter()
        .filter(|c| match c["state"].as_str().unwrap_or("") {
            "restarting" | "dead" => true,
            "exited" => !finished_oneshot(c, oneshots),
            _ => false,
        })
        .map(|c| c["name"].as_str().unwrap_or("").to_string())
        .collect()
}

/// `tailscale serve status` on a CONTROLLER (a worker fronts nothing);
/// None elsewhere or when tailscale is absent.
fn controller_serve_status() -> Option<crate::tailnet_serve::Status> {
    crate::role::detect().controller.as_ref()?;
    if Command::new("tailscale").arg("--version").output().is_err() {
        return None;
    }
    Some(crate::tailnet_serve::status(8080))
}

fn serve_word(s: &Option<crate::tailnet_serve::Status>) -> serde_json::Value {
    match s {
        None => serde_json::Value::Null,
        Some(crate::tailnet_serve::Status::NotMapped) => "none".into(),
        Some(crate::tailnet_serve::Status::Mapped { fronts_gateway: true, .. }) => "gateway".into(),
        Some(crate::tailnet_serve::Status::Mapped { .. }) => "other".into(),
        Some(crate::tailnet_serve::Status::Unknown(_)) => "unknown".into(),
    }
}

/// `noo stack logs [SERVICES…] [-f/--follow] [-n/--tail LINES]`
/// One service → `docker logs` on the container directly (fast, works with
/// container names like noo-gateway; bare compose names get a `noo-` prefix
/// probe). Zero or many services → scripts/noomesh-logs.sh (compose logs,
/// Python parity). Streaming: inherited stdio so `-f` + Ctrl-C behave.
pub fn mesh_logs(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut follow = false;
    let mut tail: Option<u64> = None;
    let mut services: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-f" | "--follow" => follow = true,
            "-n" | "--tail" => {
                tail = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?)
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => services.push(t.to_string()),
        }
    }

    if services.len() == 1 {
        let container = resolve_container(&services[0]);
        let mut cmd = Command::new("docker");
        cmd.args(["logs", "--tail", &tail.unwrap_or(50).to_string()]);
        if follow {
            cmd.arg("-f");
        }
        cmd.arg(&container);
        return match cmd.status() {
            Ok(s) => Ok(s.code().unwrap_or(1)),
            Err(_) => {
                fail(g.json, ExitCode::Generic, "subprocess_failed", "docker not found on PATH", None)
            }
        };
    }

    // 0 or ≥2 services: the compose script (same as the Python CLI).
    let mut script_args: Vec<String> = Vec::new();
    if follow {
        script_args.push("-f".into());
    }
    if let Some(n) = tail {
        script_args.push(format!("--tail={n}"));
    }
    script_args.extend(services);
    Ok(run_script(g, "noomesh-logs.sh", &script_args, None))
}

/// Resolve a name to a live container: as given, else with a `noo-` prefix
/// (compose service names like `gateway` map to containers `noo-gateway`).
pub(crate) fn resolve_container(name: &str) -> String {
    let exists = |n: &str| {
        Command::new("docker")
            .args(["container", "inspect", "--format", "{{.Name}}", n])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if exists(name) {
        return name.to_string();
    }
    if !name.starts_with("noo-") {
        let prefixed = format!("noo-{name}");
        if exists(&prefixed) {
            return prefixed;
        }
    }
    name.to_string() // let docker report the error
}

/// `noo stack restart [--profile P] [--force] [SERVICES…]` → scripts/noomesh-restart.sh
///
/// `--force` = RECREATE (compose up -d --force-recreate) instead of a plain
/// restart. The difference is load-bearing: a plain restart keeps the OLD
/// container environment, so changed secrets (env.sops) never reach the
/// process — the script always supported --force, the CLI never forwarded
/// it, leaving no first-class way to reload a secret into one service
/// (first-contact finding #42).
pub fn mesh_restart(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut profile: Option<String> = None;
    let mut force = false;
    let mut services: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--profile" => profile = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--force" => force = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => services.push(t.to_string()),
        }
    }
    let mut script_args: Vec<String> = Vec::new();
    if let Some(p) = profile {
        script_args.extend(["--profile".into(), p]);
    }
    if force {
        script_args.push("--force".into());
    }
    script_args.extend(services);
    let rc = run_script(g, "noomesh-restart.sh", &script_args, Some("restart"));
    if rc == 0 {
        front_addon_uis(g);
    }
    Ok(rc)
}

/// Front each add-on UI origin the gateway allocated with `tailscale serve
/// --https=<port>`, and drop our entries for ports it no longer allocates.
/// Called after a successful `noo stack start`, `noo stack restart` and
/// `noo upgrade --stack`
/// (tailnet_serve.rs "Add-on UI origins"). Asks the gateway which ports
/// (`GET /api/addons/ui`); when it cannot be asked, or on a worker, nothing
/// is written or removed. Never fails the start: what could not be written is
/// printed as the exact line to run.
pub(crate) fn front_addon_uis(g: &Globals) {
    if crate::role::detect().controller.is_none() {
        return;
    }
    // Called seconds after a start/restart/roll: the gateway may not be
    // listening yet. Wait, bounded, for it to answer; a timeout falls through
    // to the same "not checked" note below.
    let _ = crate::http::wait_for_gateway_answer(g);
    let listing = match crate::http::get_json_try(g, "/api/addons/ui", true, 15) {
        Ok(v) => v,
        Err(e) => {
            if !g.json {
                println!("{}", ui::note(&format!("add-on UI ports not checked: the gateway did not list them ({e})")));
            }
            return;
        }
    };
    let ports: Vec<u32> = listing["uis"]
        .as_array()
        .map(|a| a.iter().filter_map(|u| u["port"].as_u64()).map(|p| p as u32).collect())
        .unwrap_or_default();
    crate::envfile::ensure_repo_env();
    let range = crate::tailnet_serve::addon_ui_range(std::env::var("NOO_ADDON_UI_PORTS").ok().as_deref());
    let Some(report) = crate::tailnet_serve::ensure_addon_ui_fronted(&ports, range, true) else {
        return; // no tailscale, or it cannot say: not our call
    };
    if g.json {
        return;
    }
    for p in &report.written {
        ui::done(&format!("tailscale serve now fronts the add-on UI origin on :{p}"));
    }
    for p in &report.removed {
        ui::done(&format!("tailscale serve no longer fronts :{p} (no add-on UI is allocated there)"));
    }
    for (p, what) in &report.occupied {
        ui::warned(&format!("add-on UI port :{p} is already served by tailscale ({what}); noo leaves it alone — that add-on's UI is not reachable until the port is free"));
    }
    if !report.failed.is_empty() {
        ui::warned("could not change tailscale serve for the add-on UI ports; run:");
        for (cmd, detail) in &report.failed {
            println!("    {}    # {detail}", crate::tailnet_serve::manual_line(cmd));
        }
    }
}

/// `noo stack start [--profile P] [--pull] [--build]` → scripts/noomesh-start.sh
pub fn mesh_start(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut profile: Option<String> = None;
    let (mut pull, mut build, mut dist, mut dev) = (false, false, false, false);
    let mut tag: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--profile" => profile = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--pull" => pull = true,
            "--build" => build = true,
            // Launcher-script modes: the flags were Python-CLI-only, which
            // made a worker-less controller (no Python CLI) unable to spell
            // `noo stack start --dist --tag vX` at all (host8, 2026-08-31).
            "--dist" => dist = true,
            "--dev" => dev = true,
            "--tag" => tag = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with("--tag=") => tag = Some(t["--tag=".len()..].to_string()),
            _ => return Err(Unhandled),
        }
    }
    let mut script_args: Vec<String> = Vec::new();
    if let Some(p) = profile {
        script_args.extend(["--profile".into(), p]);
    }
    if pull {
        script_args.push("--pull".into());
    }
    if build {
        script_args.push("--build".into());
    }
    if dist {
        script_args.push("--dist".into());
    }
    if dev {
        script_args.push("--dev".into());
    }
    if let Some(t) = tag {
        script_args.extend(["--tag".into(), t]);
    }
    let rc = run_script(g, "noomesh-start.sh", &script_args, Some("start"));
    // The launcher's banner shows the bound IP; the address an operator
    // actually shares is the tailnet name, which the shell can't read
    // without jq. Say it here, where tailscale's JSON is easy.
    if rc == 0 && !g.json {
        crate::tailnet_serve::print_front_door(8080 + crate::envfile::port_offset(), &crate::envfile::instance());
    }
    if rc == 0 {
        front_addon_uis(g);
    }
    Ok(rc)
}

/// `noo stack stop [--volumes]` → scripts/noomesh-stop.sh
///
/// NOTE: Python's `stop -v` means --volumes, but the Rust front door consumes
/// a bare `-v` as the global --verbose flag before handlers run. To avoid
/// silently dropping a volume-removal request we refuse a literal `-v` on the
/// command line with a usage error (use `--volumes`); the old Python
/// semantics were the reference.
pub fn mesh_stop(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    refuse_short_v(g, "stop");
    let (mut volumes, mut yes) = (false, false);
    for tok in args {
        match tok.as_str() {
            "--volumes" => volumes = true,
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    if volumes {
        confirm_stop_volumes(g, yes);
    }
    let script_args: Vec<String> = if volumes { vec!["-v".into()] } else { Vec::new() };
    Ok(run_script(g, "noomesh-stop.sh", &script_args, Some("stop")))
}

/// The front door eats a bare `-v` as the global `--verbose`, so a handler
/// cannot tell `stack stop -v` (Python's `--volumes`) from verbose. Treating
/// it as verbose would silently drop the volume removal, so a `-v`
/// AFTER the verb is refused here: use `--volumes`.
fn short_v_after(argv: &[String], verb: &str) -> bool {
    argv.iter().position(|a| a == verb).is_some_and(|i| argv[i + 1..].iter().any(|a| a == "-v"))
}

fn refuse_short_v(g: &Globals, verb: &str) {
    let argv: Vec<String> = std::env::args().collect();
    if short_v_after(&argv, verb) {
        fail(
            g.json,
            ExitCode::Usage,
            "usage",
            &format!("`-v` after `stack {verb}` is ambiguous (verbose or volumes): use --volumes"),
            None,
        );
    }
}

/// The phrase typed to confirm deleting the database.
const STOP_VOLUMES_PHRASE: &str = "delete database";

/// What `stack stop --volumes` does before it touches anything.
#[derive(Debug, PartialEq, Eq)]
enum VolumesGate {
    /// `-y`: go ahead.
    Proceed,
    /// No terminal to ask on (pipe, agent, `--json`): refuse.
    Refuse,
    /// Ask for the typed phrase.
    Prompt,
}

fn stop_volumes_gate(yes: bool, json: bool, tty: bool) -> VolumesGate {
    if yes {
        VolumesGate::Proceed
    } else if json || !tty {
        VolumesGate::Refuse
    } else {
        VolumesGate::Prompt
    }
}

/// "3h 12m", "2d 4h": how old a backup is, for the prompt.
fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86400, (secs % 86400) / 3600),
    }
}

/// The warning shown before the typed confirmation. States plainly that the
/// database and every stack volume are deleted, and names the backup to take
/// first. `last_backup_age` is `None` when it cannot be read cheaply.
fn stop_volumes_warning(backup_cmd: &str, last_backup_age: Option<u64>) -> String {
    let last = match last_backup_age {
        Some(s) => format!("last backup: {} ago\n", format_age(s)),
        None => String::new(),
    };
    format!(
        "`stack stop --volumes` DELETES THE DATABASE and every other volume of this stack. \
         This cannot be undone.\n\
         Take a fresh backup first:\n  {backup_cmd}\n{last}\
         To proceed, type \"{STOP_VOLUMES_PHRASE}\" (or pass -y to skip this prompt)."
    )
}

fn confirm_stop_volumes(g: &Globals, yes: bool) {
    use std::io::BufRead as _;
    let tty = unsafe { libc::isatty(0) } == 1;
    let backup_cmd = format!("bash {}", repo_root().join("scripts").join("backup-controller.sh").display());
    match stop_volumes_gate(yes, g.json, tty) {
        VolumesGate::Proceed => {}
        VolumesGate::Refuse => fail(
            g.json,
            ExitCode::Generic,
            "confirmation_required",
            "refusing to delete the database and every stack volume without a terminal to confirm on",
            Some("take a backup first, then re-run with -y: noo stack stop --volumes -y"),
        ),
        VolumesGate::Prompt => {
            let age = super::secrets::backup_artifacts("pg_*.sql.gz.enc")
                .first()
                .and_then(|p| std::fs::metadata(p).ok())
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs());
            eprintln!("{}", stop_volumes_warning(&backup_cmd, age));
            eprint!("> ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            if line.trim() != STOP_VOLUMES_PHRASE {
                eprintln!("Aborted. Nothing was stopped.");
                std::process::exit(ExitCode::Generic as i32);
            }
        }
    }
}

/// `noo stack clean [--volumes] [--images] [--all] [--deep] [--cache]
/// [--hf-cache] [-y/--yes]` → scripts/noomesh-clean.sh
///
/// Destructive: with --volumes/--all/--deep it confirms exactly like the
/// Python CLI ("Clean all Docker resources on this host?") unless --yes.
/// Agent-first confirm contract (see `commands::confirm_destructive`):
/// --json never prompts (requires --yes), a non-TTY stdin errors instead
/// of blocking. Script-arg mapping is Python parity: --deep wins, else
/// --all, else the individual -v/--images/--cache/--hf-cache flags.
///
/// NOTE: Python's `-v` short flag means --volumes here but the front door
/// consumes a bare `-v` as the global --verbose before handlers run — a
/// literal `-v` on the command line is refused with a usage error (same
/// pattern as `stack stop`). The `--volumes` long form is native.
pub fn mesh_clean(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    refuse_short_v(g, "clean");
    let (mut volumes, mut images, mut all, mut deep) = (false, false, false, false);
    let (mut cache, mut hf_cache, mut yes) = (false, false, false);
    for tok in args {
        match tok.as_str() {
            "--volumes" => volumes = true,
            "--images" => images = true,
            "--all" => all = true,
            "--deep" => deep = true,
            "--cache" => cache = true,
            "--hf-cache" => hf_cache = true,
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }

    // Every variant that deletes something confirms (unless -y).
    if all || deep || volumes || images || cache || hf_cache {
        super::confirm_destructive(g, yes, "Clean all Docker resources on", "this host");
    }
    if all || deep || volumes {
        // The self-heal watcher would resurrect the stack onto the box we
        // are about to declare clean (host8, 2026-08-31). Full teardown
        // variants remove the unit like offboard does; volumes-only stops
        // the processes but leaves the unit for the next `stack start`.
        super::offboard::stop_self_heal_daemons(all || deep);
        if !g.json {
            ui::done(&format!("self-heal daemons stopped{}", if all || deep { " + watcher unit removed" } else { "" }));
        }
    }

    let script_args = clean_script_args(volumes, images, all, deep, cache, hf_cache, yes);
    Ok(run_script(g, "noomesh-clean.sh", &script_args, Some("clean")))
}

/// Script arguments for `noomesh-clean.sh`. `--deep` wins, else `--all`,
/// else the individual flags; `--yes` is forwarded so the script's own
/// sub-prompts (pg/redis volumes, PKI, secrets) do not ask again.
fn clean_script_args(volumes: bool, images: bool, all: bool, deep: bool, cache: bool, hf_cache: bool, yes: bool) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    if deep {
        a.push("--deep".into());
    } else if all {
        a.push("--all".into());
    } else {
        if volumes {
            a.push("-v".into());
        }
        if images {
            a.push("--images".into());
        }
        if cache {
            a.push("--cache".into());
        }
        if hf_cache {
            a.push("--hf-cache".into());
        }
    }
    if yes {
        a.push("--yes".into());
    }
    a
}

/// `noo stack rebuild [SERVICES…] [-q/--quick] [--no-cache] [--profile P]
/// [--gateway-engine E] [--node-engine E] [-b/--background]`
/// Foreground → scripts/noomesh-rebuild.sh (`--profile` becomes a script
/// arg; the engine flags become GATEWAY_ENGINE/NODE_ENGINE env vars, same
/// as the Python CLI). Background → spool a `stack-rebuild` command for
/// noo-hostd (detached; follow with `noo stack rebuild-status`);
/// profile/engine flags are rejected there because the detached hostd
/// job doesn't inherit this process's environment (Python parity).
pub fn mesh_rebuild(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut quick, mut no_cache, mut background) = (false, false, false);
    let mut profile: Option<String> = None;
    let mut gateway_engine: Option<String> = None;
    let mut node_engine: Option<String> = None;
    let mut services: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-q" | "--quick" => quick = true,
            "--no-cache" => no_cache = true,
            "-b" | "--background" => background = true,
            "--profile" => profile = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--gateway-engine" => gateway_engine = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--node-engine" => node_engine = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => services.push(t.to_string()),
        }
    }

    if background && (profile.is_some() || gateway_engine.is_some() || node_engine.is_some()) {
        // Same refusal (and reason) as the Python CLI: the detached job
        // runs with noo-hostd's environment, so these overrides would
        // silently not apply.
        fail(
            g.json,
            ExitCode::Generic,
            "error",
            "--gateway-engine/--node-engine/--profile need a foreground run \
             (they work via environment variables the detached noo-hostd \
             job doesn't inherit).",
            None,
        );
    }

    // Engine selection travels as env vars the script reads
    // (GATEWAY_ENGINE defaults rust, NODE_ENGINE defaults go) — children
    // inherit our environment, mirroring Python's os.environ mutation.
    if let Some(e) = &gateway_engine {
        std::env::set_var("GATEWAY_ENGINE", e);
    }
    if let Some(e) = &node_engine {
        std::env::set_var("NODE_ENGINE", e);
    }

    let mut script_args: Vec<String> = Vec::new();
    if quick {
        script_args.push("--quick".into());
    }
    if no_cache {
        script_args.push("--no-cache".into());
    }
    if let Some(p) = &profile {
        script_args.extend(["--profile".into(), p.clone()]);
    }
    script_args.extend(services);

    if background {
        return Ok(queue_background_rebuild(g, &script_args));
    }
    Ok(run_script(g, "noomesh-rebuild.sh", &script_args, Some("rebuild")))
}

fn spool_dir() -> PathBuf {
    repo_root().join(".noo-host-spool")
}

/// Write a `stack-rebuild` spool command (same schema as
/// `noomesh/gateway/host_spool.py::write_command`) for the spool executor.
fn queue_background_rebuild(g: &Globals, args: &[String]) -> i32 {
    // A rebuild nobody picks up is worse than an error. The executor is
    // noo-hostd in controller mode (a user unit). The bash host watcher
    // this once checked for is retired and no longer shipped.
    let hostd_up = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "noo-hostd"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !hostd_up {
        fail(
            g.json,
            ExitCode::Generic,
            "error",
            "noo-hostd is not running — nothing would pick the rebuild up. Install or restart it with: noo onboard --only services",
            Some("or rebuild in the foreground: noo stack rebuild"),
        );
    }

    let payload = serde_json::json!({
        "op": "stack-rebuild",
        "service": "stack",
        "health_check": false,
        "rollback": null,
        "args": args,
        "requested_by": "cli:mesh_rebuild",
        "ts": utc_now_iso(),
    });

    // <unix_nanos>-<8 hex>: unique + lexically ordered, same as Python.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("{nanos}-{}", random_hex8());
    let dir = spool_dir();
    let final_name = format!("{name}.cmd.json");

    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        // Temp file in the SAME dir, then atomic rename — the watcher must
        // never observe a half-written command.
        let tmp = dir.join(format!(".{name}.tmp"));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(payload.to_string().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, dir.join(&final_name)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    };
    if let Err(e) = write() {
        fail(
            g.json,
            ExitCode::Generic,
            "error",
            &format!("Could not write the spool command: {e}"),
            None,
        );
    }

    if g.json {
        print_json(&serde_json::json!({
            "status": "ok",
            "action": "rebuild-queued",
            "command": final_name,
        }));
        return 0;
    }
    ui::done(&format!("rebuild queued through noo-hostd ({final_name})"));
    println!("{}", ui::note("the dashboard shows the same job under Self-Regulation → Host Operations"));
    ui::guide(&[
        ("noo stack rebuild-status --follow", "streams the build log until it finishes"),
        ("noo stack status", "afterwards: confirms every service came back on the new image"),
    ]);
    0
}

/// `noo stack rebuild-status [-f/--follow]` — most recent background
/// stack-rebuild result from the spool dir (`*.result.json` + rebuild log).
pub fn mesh_rebuild_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut follow = false;
    for tok in args {
        match tok.as_str() {
            "-f" | "--follow" => follow = true,
            _ => return Err(Unhandled),
        }
    }

    let dir = spool_dir();
    let mut result_files: Vec<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".result.json"))
                .collect()
        })
        .unwrap_or_default();
    result_files.sort_by(|a, b| b.cmp(a)); // newest first (time_ns-prefixed names)

    let mut latest: Option<(String, serde_json::Value)> = None;
    for fname in result_files {
        let Ok(text) = std::fs::read_to_string(dir.join(&fname)) else { continue };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        if data["op"].as_str() == Some("stack-rebuild") {
            latest = Some((fname.trim_end_matches(".result.json").to_string(), data));
            break;
        }
    }

    let Some((name, data)) = latest else {
        if g.json {
            print_json(&serde_json::json!({"rebuild": null}));
        } else {
            println!("{}", ui::muted("no background rebuild"));
            println!("{}", ui::hint("noo stack rebuild -b"));
        }
        return Ok(0);
    };

    let mut status = data["status"].as_str().unwrap_or("done").to_string();
    if status == "done" && data["ok"].as_bool() != Some(true) {
        status = "failed".into();
    }
    let log_path = dir.join(format!("{name}.rebuild.log"));
    let log_tail = || -> Vec<String> {
        std::fs::read(&log_path)
            .map(|b| {
                let text = String::from_utf8_lossy(&b);
                let lines: Vec<&str> = text.lines().collect();
                lines.iter().rev().take(15).rev().map(|s| s.to_string()).collect()
            })
            .unwrap_or_default()
    };

    if g.json {
        let mut payload = data.clone();
        payload["name"] = name.into();
        payload["status"] = status.into();
        if log_path.is_file() {
            payload["log_tail"] = serde_json::json!(log_tail());
        }
        print_json(&payload);
        return Ok(0);
    }

    let glyph = match status.as_str() {
        "running" => Glyph::Step,
        "done" => Glyph::Ok,
        "failed" => Glyph::Err,
        _ => Glyph::Warn,
    };
    println!(
        "{}",
        ui::status_line(
            glyph,
            &format!(
                "stack rebuild {}  {}",
                ui::state(&status),
                ui::muted(&format!("at {} · rc {}", data["ts"].as_str().unwrap_or("?"), data["rc"]))
            )
        )
    );
    if let Some(stderr) = data["stderr"].as_str().filter(|s| !s.is_empty()) {
        println!("  {}", ui::muted(stderr));
    }

    if !log_path.is_file() {
        return Ok(0);
    }
    if follow && status == "running" {
        println!("{}", ui::section(&format!("tailing {} (Ctrl-C to stop)", log_path.display())));
        let _ = Command::new("tail").arg("-f").arg(&log_path).status();
    } else {
        let lines = log_tail();
        if !lines.is_empty() {
            println!("{}", ui::section(&format!("last {} log lines", lines.len())));
            for line in &lines {
                println!("  {line}");
            }
        }
    }
    Ok(0)
}

// ── WP-B2: stack mgmt ───────────────────────────────────────────────────

/// `noo stack reset [--dist] [--tag T] [--ci] [--keep-env] [-y/--yes]` →
/// scripts/noomesh-reset.sh (deep clean → onboard → start; DESTRUCTIVE).
///
/// Python's handler passes the flags straight through and relies on the
/// script's own "Type 'reset' to confirm" prompt. The Rust port keeps that
/// interactive prompt (inherited stdio) but adds the agent-first confirm
/// contract for the non-interactive paths, same as `stack clean`:
/// `--json` without `--yes` errors (never prompts), and a non-TTY stdin
/// errors instead of letting the script block on `read` forever.
pub fn mesh_reset(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut dist, mut ci, mut keep_env, mut yes) = (false, false, false, false);
    let mut tag: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--dist" => dist = true,
            "--tag" => tag = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with("--tag=") => tag = Some(t["--tag=".len()..].to_string()),
            "--ci" => ci = true,
            "--keep-env" => keep_env = true,
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    if tag.is_some() && !dist {
        // Same message + json shape ({"error","code":"error"}) as Python's _err.
        fail(g.json, ExitCode::Generic, "error", "--tag only applies with --dist.", None);
    }

    // Agent-first confirm contract (see commands::confirm_destructive): the
    // json/non-TTY paths must never hang on the script's stdin prompt. A real
    // TTY without --yes proceeds — the script itself asks for the stronger
    // "Type 'reset' to confirm" (Python parity: one prompt, not two).
    if !yes {
        if g.json {
            fail(
                true,
                ExitCode::Generic,
                "confirmation_required",
                "confirmation required: pass --yes",
                Some("refusing to prompt in --json mode; the reset script would ask: Type 'reset' to confirm"),
            );
        }
        if unsafe { libc::isatty(0) } != 1 {
            fail(
                false,
                ExitCode::Generic,
                "confirmation_required",
                "confirmation required: pass --yes (stdin is not a TTY; refusing to block on the reset script's confirmation prompt)",
                Some("agents and pipes must confirm destructive commands explicitly with --yes/-y"),
            );
        }
    }

    // Script-arg order is Python parity: --dist, --tag, --ci, --keep-env, --yes.
    let mut script_args: Vec<String> = Vec::new();
    if dist {
        script_args.push("--dist".into());
    }
    if let Some(t) = &tag {
        script_args.extend(["--tag".into(), t.clone()]);
    }
    if ci {
        script_args.push("--ci".into());
    }
    if keep_env {
        script_args.push("--keep-env".into());
    }
    if yes {
        script_args.push("--yes".into());
    }
    Ok(run_script(g, "noomesh-reset.sh", &script_args, Some("reset")))
}

/// `noo stack ollama [ARGS…] [-c/--container NAME]` — run ollama inside the
/// Docker container (`docker exec NAME ollama ARGS…`, default action `list`)
/// with inherited stdio, propagating the exit code.
///
/// NOTE: bare tokens that collide with our global flags (`-v`, `--verbose`,
/// `--json`, `--gateway`/`-G`, `--timeout`) are consumed by the front door
/// before handlers run and could be MEANT for ollama (`ollama show -v`), so
/// their presence anywhere on the raw command line is a usage error (same
/// pattern as `stack stop`). Other dash tokens are refused too — there is no
/// Python typer surface behind them any more.
pub fn mesh_ollama(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    const GLOBALS: &[&str] = &["-v", "--verbose", "--json", "--gateway", "-G", "--timeout"];
    if std::env::args().any(|a| GLOBALS.contains(&a.as_str())) {
        return Err(Unhandled);
    }
    let mut container = "noo-ollama".to_string();
    let mut ollama_args: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-c" | "--container" => container = iter.next().ok_or(Unhandled)?.clone(),
            t if t.starts_with('-') => return Err(Unhandled),
            t => ollama_args.push(t.to_string()),
        }
    }
    if ollama_args.is_empty() {
        ollama_args.push("list".into()); // default to list (Python parity)
    }
    let mut cmd = Command::new("docker");
    cmd.args(["exec", &container, "ollama"]).args(&ollama_args);
    match cmd.status() {
        Ok(s) => Ok(s.code().unwrap_or(1)),
        Err(_) => {
            fail(g.json, ExitCode::Generic, "subprocess_failed", "docker not found on PATH", None)
        }
    }
}

/// `noo stack sync-assets` — re-materialise the standalone deploy slice
/// (scripts, compose, templates) from THIS binary's embedded assets.
/// No-op on non-standalone installs. `noo upgrade` runs it via the NEW
/// binary so the slice always matches the CLI version (#14).
pub fn mesh_sync_assets(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let home = crate::onboard::standalone::default_home();
    if !home.join(".noo-standalone").is_file() {
        if !g.json {
            ui::done("no change: not a standalone install — nothing to sync");
        }
        return Ok(0);
    }
    match crate::onboard::standalone::materialize(&home) {
        Ok(report) => {
            if g.json {
                println!("{}", serde_json::json!({
                    "status":"ok","action":"sync-assets",
                    "retired":report.retired,"moved_aside":report.moved_aside,"skipped":report.skipped,
                }));
            } else {
                for line in report.retired.iter().chain(&report.moved_aside).chain(&report.skipped) {
                    println!("{}", ui::note(line));
                }
                ui::done(&format!("deploy slice refreshed under {}", home.display()));
                ui::guide(&[
                    ("noo stack restart", "running containers keep the old compose until restarted"),
                    ("noo stack status", "confirms the stack tag the slice now carries"),
                ]);
            }
            Ok(0)
        }
        Err(e) => {
            ui::failed(&format!("sync-assets failed: {e}"), Some("noo upgrade --check"));
            Ok(1)
        }
    }
}

/// `noo stack install-watcher` — RETIRED. It installed the bash host
/// watcher (scripts/noo-host-watcher.sh) as a systemd user unit. noo-hostd
/// took over the host spool on 2026-09-24 and the watcher
/// was removed from the tree on 2026-09-27, `--legacy` rollback included.
/// Kept as a stub for the reason `cluster clean-node` is: an old runbook
/// hitting a missing command gets "unknown command", which explains
/// nothing.
pub fn mesh_install_watcher(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "install-watcher is retired: noo-hostd runs host commands now",
        Some(
            "install or repair it:     noo onboard --only services\n  \
             check it:                 systemctl --user status noo-hostd\n  \
             stop a leftover watcher:  systemctl --user disable --now noo-host-watcher",
        ),
    );
}

/// 4 random bytes as 8 hex chars (spool-name uniqueness; time-derived fallback).
fn random_hex8() -> String {
    use std::io::Read;
    let mut buf = [0u8; 4];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if ok {
        return hex::encode(buf);
    }
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{n:08x}")
}

/// Current UTC time as ISO-8601 (`YYYY-MM-DDTHH:MM:SS+00:00`, matching
/// Python's `datetime.now(timezone.utc).isoformat()` shape, sans micros).
fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}+00:00")
}

/// `noo stack sandbox <up|status|run|rehearse|down> …` — throwaway
/// full-stack Mesh in a docker-in-docker container, fully isolated from
/// the live system. Thin exec of noomesh-sandbox.sh; the
/// subcommand surface is validated there (unknown → usage, exit 2).
pub fn mesh_sandbox(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    Ok(run_script(g, "noomesh-sandbox.sh", args, None))
}

#[cfg(test)]
mod stop_clean_tests {
    #[test]
    fn stack_exit_is_nonzero_when_a_container_is_restarting() {
        let c = |state: &str| serde_json::json!({"name": "noo-x", "state": state});
        let none: Vec<String> = Vec::new();
        assert!(failed_containers(&[c("running"), c("running")], &none).is_empty());
        assert_eq!(failed_containers(&[c("running"), c("restarting")], &none).len(), 1);
        assert!(failed_containers(&[], &none).is_empty());
    }

    /// i64a: an Exited container fails `noo stack status` unless it is a
    /// declared one-shot that exited 0; the failure names the container.
    #[test]
    fn an_exited_container_fails_unless_it_is_a_finished_declared_one_shot() {
        let ex = |name: &str, service: &str, status: &str| {
            serde_json::json!({"name": name, "service": service, "state": "exited", "status": status})
        };
        let list = crate::oneshots::parse(include_str!("../../../config/oneshot-services.txt"));
        // A long-running service that exited, cleanly or not: a failure.
        assert_eq!(failed_containers(&[ex("noo-worker", "worker", "Exited (1) 2 minutes ago")], &list), ["noo-worker"]);
        assert_eq!(failed_containers(&[ex("noo-redis", "redis", "Exited (0) 2 minutes ago")], &list), ["noo-redis"]);
        // The evolve route one-shot that finished: done (by label or by name).
        assert!(failed_containers(&[ex("noo-evolve-routes", "noo-evolve-routes", "Exited (0) 3 hours ago")], &list).is_empty());
        assert!(failed_containers(&[ex("noo-evolve-routes", "", "Exited (0) 3 hours ago")], &list).is_empty());
        // A declared one-shot that FAILED is still a failure.
        assert_eq!(
            failed_containers(&[ex("noo-evolve-routes", "noo-evolve-routes", "Exited (2) 3 hours ago")], &list),
            ["noo-evolve-routes"]
        );
        // dead is never fine.
        let dead = serde_json::json!({"name": "noo-nats", "state": "dead", "status": "Dead"});
        assert_eq!(failed_containers(&[dead], &list), ["noo-nats"]);
    }

    #[test]
    fn the_compose_service_is_read_from_the_labels() {
        assert_eq!(compose_service("com.docker.compose.project=noomesh,com.docker.compose.service=gateway,x=y"), "gateway");
        assert_eq!(compose_service("a=b"), "");
        assert_eq!(compose_service(""), "");
    }

    use super::*;

    #[test]
    fn volumes_gate_refuses_without_a_terminal_or_in_json() {
        assert_eq!(stop_volumes_gate(false, false, false), VolumesGate::Refuse);
        assert_eq!(stop_volumes_gate(false, true, true), VolumesGate::Refuse);
        assert_eq!(stop_volumes_gate(false, false, true), VolumesGate::Prompt);
        assert_eq!(stop_volumes_gate(true, false, false), VolumesGate::Proceed);
        assert_eq!(stop_volumes_gate(true, true, false), VolumesGate::Proceed);
    }

    #[test]
    fn volumes_warning_names_the_deletion_and_the_backup() {
        let w = stop_volumes_warning("bash /srv/noo/scripts/backup-controller.sh", Some(3 * 3600 + 120));
        assert!(w.contains("DELETES THE DATABASE"), "{w}");
        assert!(w.contains("bash /srv/noo/scripts/backup-controller.sh"), "{w}");
        assert!(w.contains("last backup: 3h 2m ago"), "{w}");
        assert!(w.contains(STOP_VOLUMES_PHRASE), "{w}");
        // Unreadable age is skipped, not guessed.
        assert!(!stop_volumes_warning("x", None).contains("last backup"));
    }

    #[test]
    fn short_v_after_the_verb_is_detected_only_there() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(short_v_after(&a(&["noo", "stack", "stop", "-v"]), "stop"));
        assert!(!short_v_after(&a(&["noo", "-v", "stack", "stop"]), "stop"));
        assert!(!short_v_after(&a(&["noo", "stack", "stop", "--volumes"]), "stop"));
    }

    #[test]
    fn clean_forwards_yes_to_the_script() {
        let a = clean_script_args(false, false, false, true, false, false, true);
        assert_eq!(a, ["--deep", "--yes"]);
        let a = clean_script_args(true, true, false, false, false, false, false);
        assert_eq!(a, ["-v", "--images"]);
        let a = clean_script_args(false, false, true, false, false, false, true);
        assert_eq!(a, ["--all", "--yes"]);
    }
}
