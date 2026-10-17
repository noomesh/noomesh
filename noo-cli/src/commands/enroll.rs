// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo enroll` — the binary is the enroller.
//!
//! Compiled port of scripts/bootstrap-enroll.sh plus the tailscale join the
//! unified paste used to inline. The operator's paste shrinks to
//! `noo enroll noo1.<blob>`; every step the shell rail fetched over
//! unverified TLS either moves into this binary (which arrived over an
//! authenticated channel) or is verified against material carried in the
//! out-of-band blob:
//!
//!   1. tailscale install + `tailscale up` (skippable)
//!   2. foreign-mesh guard (exit 78 BEFORE burning the token)
//!   3. birth keypair (openssl, parity with the script's RSA-4096)
//!   4. POST /api/cluster/bootstrap — redeem the single-use token
//!   5. no controller key and no sudoers grant — the mesh is the only lane
//!   6. root prep from EMBEDDED assets (PREP_TOOLS_DIR) — the CA anchor is
//!      still fetched but hard-verified against the blob's pin
//!
//! The shell paste remains a fully supported fallback
//! CLIs); prep-host.sh serves both lanes.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::{Globals, Unhandled};
use crate::ui::{self, Glyph};

/// Narration line (guide rev 2: stdout, silenced by --quiet/--json).
fn say(s: &str) {
    if !crate::ui::quiet() {
        println!("{s}");
    }
}

/// `◆ Phase` (guide §5 "Rhythm"): every enroll lane is multi-phase —
/// tailnet, identity, registration, access, host prep — so each gets a
/// section. Fast-fail preflight (usage, --resume checks) prints none.
fn phase(label: &str) {
    say(&ui::phase(label));
}

// ── Embedded node tooling ──────────────────────────────────────────────────
// Compiled in via build.rs (enroll_assets.rs) so no executable crosses the
// unverified first-contact transport — the SAME files the gateway serves
// for the shell lane. build.rs, not raw include_str!: a crate-only build
// (CI's noo-cli job builds outside the repo tree) gets EMPTY consts and
// enroll degrades to prep's fetch lane instead of failing to compile.
include!(concat!(env!("OUT_DIR"), "/enroll_assets.rs"));

/// The embedded applier / fetcher scripts, for provision to put into every
/// Linux bundle (`applier` + `fetcher` kinds) so both ride the rail.
pub(crate) fn asset_prep() -> &'static str { ASSET_PREP }
pub(crate) fn asset_apply() -> &'static str { ASSET_APPLY }
pub(crate) fn asset_fetch() -> &'static str { ASSET_FETCH }

/// The harness's unit and env template, compiled in so a
/// bundle carries the release's own copies rather than whatever revision
/// the controller's checkout happens to be at. Empty on a crate-only
/// build; provision says so and stages no harness instead of an empty file.
pub(crate) fn asset_harness_unit() -> &'static str { ASSET_HARNESS_UNIT }
pub(crate) fn asset_harness_env_tmpl() -> &'static str { ASSET_HARNESS_ENV_TMPL }

const USAGE: &str = "usage: noo enroll <noo1.blob> | --url <https://…> --token <t> \
[--ca-sha256 <hex>] [--ts-authkey <k>] [--node <name>] [--skip-tailscale] [--skip-prep] [--data-root <dir>]\n\
       noo enroll --via-tailnet <https://controller.ts.net> [--ts-authkey <k>] [--skip-prep]\n  --resume            macOS: finish the arm step (root CLI + fetch daemon) after a failure, no new token";

#[derive(Debug)]
struct EnrollCred {
    url: String,
    token: String,
    ca_sha256: Option<String>,
    ts_authkey: Option<String>,
    node: Option<String>,
}

/// `noo1.` + base64url(JSON {v,url,token,ca?,tsk?,node?}) — minted by
/// `noo cluster bootstrap-token create`. Accepts padded or
/// unpadded encoding so a hand-relayed blob survives copy mangling.
fn parse_blob(blob: &str) -> Result<EnrollCred, String> {
    if blob.trim().starts_with("noo-seat1.") {
        return Err("this is a kiosk SEAT enrolment paste — run it as `noo kiosk enroll noo-seat1.…`; \
                    a seat never enrols as a node".into());
    }
    let b64 = blob
        .strip_prefix("noo1.")
        .ok_or("not a noo1. credential blob")?
        .trim_end_matches('=');
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("blob is not valid base64url: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("blob is not valid JSON: {e}"))?;
    if v["v"].as_i64() != Some(1) {
        return Err(format!(
            "blob version {} is newer than this CLI understands — run `noo upgrade` first",
            v["v"]
        ));
    }
    // A node blob carries no role claim (or `node`). Anything else — a seat
    // claim smuggled into a node-shaped blob — is refused: the node lane
    // never redeems a token minted for something that is not a node.
    if let Some(role) = v.get("role").filter(|r| !r.is_null()) {
        if role.as_str() != Some("node") {
            return Err(format!("this enrolment blob claims role {role}, not a node — refusing"));
        }
    }
    let field = |k: &str| v[k].as_str().map(str::to_string).filter(|s| !s.is_empty());
    Ok(EnrollCred {
        url: field("url").ok_or("blob is missing the controller url")?,
        token: field("token").ok_or("blob is missing the token")?,
        ca_sha256: field("ca"),
        ts_authkey: field("tsk"),
        node: field("node"),
    })
}

/// The ONE unverified-transport request in the whole enrollment, and it
/// fetches exactly one thing: `/bootstrap/ca.crt`, whose DER-sha256 must then
/// match the pin carried in the enroll blob ([`fetch_ca_pem`], which is the
/// only caller and enforces the pin). There is no chicken-and-egg escape from
/// this: a machine that has never met the mesh has nothing to verify a mesh
/// certificate against. What CAN be removed — and was, on 2026-09-11 — is
/// everything that used to ride the same unverified agent afterwards: the
/// foreign-mesh probe, the token redemption, and, worst, `GET /bootstrap/prep`
/// whose body is handed straight to `sudo bash`. Once the pinned CA
/// is in hand every later request verifies against it via [`ca_agent`].
///
/// Trust here is CONTENT trust, not transport trust: the bytes are accepted
/// only if they hash to the fingerprint the operator pasted.
fn first_contact_agent(timeout: u64) -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .disable_verification(true)
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(timeout)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// An agent that verifies the controller against the pin-verified cluster CA.
/// Everything after the CA fetch uses this. The gateway cert carries the
/// controller's tailnet DNS name AND its tailnet IP as SANs (see
/// `pki::issue_gateway_cert` + the onboard Tailscale step), which are exactly
/// the two spellings `noo cluster provision` can put in the blob URL, so a
/// verifying agent works for both.
pub(crate) fn ca_agent(ca_pem: &[u8], timeout: u64) -> Result<ureq::Agent, String> {
    let cert = ureq::tls::Certificate::from_pem(ca_pem)
        .map_err(|e| format!("the controller's CA is not a usable certificate: {e}"))?;
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]))
        .build();
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(timeout)))
        .http_status_as_error(false)
        .build()
        .into())
}

fn run(cmd: &mut Command) -> (i32, String) {
    match cmd.output() {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
        ),
        Err(_) => (-1, String::new()),
    }
}

/// Stop, disable and delete the pre-rename `pai-hostd` / `pai-host-watcher`
/// USER units. A box enrolled before the noomesh rename kept them enabled
/// next to the new set; on HOST3 (2026-09-01) `pai-hostd run --root <clone>`
/// was still active on a host that had just become a worker. Idempotent,
/// silent when there is nothing to retire.
fn retire_legacy_user_units() {
    let Ok(home) = std::env::var("HOME") else { return };
    let unit_dir = std::path::PathBuf::from(home).join(".config/systemd/user");
    let mut retired: Vec<&str> = Vec::new();
    for unit in ["pai-hostd", "pai-host-watcher"] {
        let file = unit_dir.join(format!("{unit}.service"));
        let dropin = unit_dir.join(format!("{unit}.service.d"));
        if !file.exists() && !dropin.exists() {
            continue;
        }
        let _ = run(Command::new("systemctl").args(["--user", "disable", "--now", unit]));
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&dropin);
        retired.push(unit);
    }
    let _ = run(Command::new("pkill").args(["-f", "pai-hostd run"]));
    let _ = run(Command::new("pkill").args(["-f", "pai-host-watcher.sh"]));
    if !retired.is_empty() {
        let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
        ui::step(&format!("Retired pre-rename user units: {}", retired.join(", ")));
    }
}

/// Can a TCP connection be opened to `<host>:<port>` of an http(s) URL?
/// Default ports: 443 for https, 80 for http.
fn tcp_reachable(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .map(|r| (r, 443u16))
        .or_else(|| url.strip_prefix("http://").map(|r| (r, 80u16)));
    let Some((rest, default_port)) = rest else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = match authority.rsplit_once(':') {
        // An IPv6 literal's colons belong to the address, not a port.
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => {
            (h, p.parse::<u16>().unwrap_or(default_port))
        }
        _ => (authority, default_port),
    };
    let host = host.trim_matches(['[', ']']);
    let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)) else {
        return false;
    };
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok() {
            return true;
        }
    }
    false
}

/// Wait until the controller's port ACCEPTS a connection, or ~60 s pass.
/// This absorbs tunnel/DNS settle time after `tailscale up`; it is a
/// reachability probe and nothing more, so it opens a TCP socket rather than
/// speaking TLS at all. (It used to make an unverified HTTPS request, which
/// answered the same question and needed a verification-disabled agent to do
/// it.) One live line (`ui::Poll`), started only once the first probe fails.
fn wait_for_controller(noo_url: &str) {
    let started = std::time::Instant::now();
    let mut poll: Option<ui::Poll> = None;
    for _attempt in 0..12 {
        if tcp_reachable(noo_url) {
            if let Some(p) = poll.take() {
                p.done("controller reachable");
            }
            return;
        }
        poll.get_or_insert_with(|| ui::Poll::start("waiting for the tailnet tunnel to settle (up to 60s)"))
            .tick(started.elapsed().as_secs());
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    if let Some(p) = poll.take() {
        p.warned("controller still not answering — continuing; enrollment will report the real error");
    }
}

/// prep-host's data-root pick, mirrored for the prompt default: the largest
/// writable non-root ext4/xfs/btrfs mount over 10 GB, plus "/noo", when the
/// data-root policy accepts it; else the standard /var/lib/noo. Writability is proven with a touch, as in prep-host.sh.
fn suggest_data_root() -> String {
    if cfg!(target_os = "macos") {
        return suggest_data_root_darwin();
    }
    let out = Command::new("findmnt")
        .args(["-bnro", "AVAIL,TARGET,OPTIONS", "-t", "ext4,ext3,xfs,btrfs"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let mut cands: Vec<(u64, String)> = out
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let avail: u64 = it.next()?.parse().ok()?;
            let target = it.next()?.to_string();
            let opts = it.next().unwrap_or("");
            let ro = opts.split(',').any(|o| o == "ro");
            if target == "/" || target.contains("boot") || target.contains("recovery") || target.contains("wslg") || ro || avail <= 10_737_418_240 {
                return None;
            }
            Some((avail, target))
        })
        .collect();
    cands.sort_by_key(|c| std::cmp::Reverse(c.0));
    for (_, t) in cands {
        let probe = std::path::Path::new(&t).join(".noo-writable-probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            let root = format!("{}/noo", t.trim_end_matches('/'));
            // A mount the policy refuses (/home, a Windows drive, …) is
            // never suggested; the standard location is.
            if crate::commands::data_root::shape_problem(&root, false, "").is_none() {
                return root;
            }
        }
    }
    crate::commands::data_root::DEFAULT_DATA_ROOT.to_string()
}

/// macOS: the largest writable volume under /Volumes (external SSDs live
/// there), else ~/noomesh. `df -k` is the portable source; writability is
/// proven with a touch, like the Linux picker.
fn suggest_data_root_darwin() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let out = Command::new("df")
        .args(["-k"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let mut cands: Vec<(u64, String)> = out
        .lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let target = *cols.last()?;
            if !target.starts_with("/Volumes/") || target.contains("Recovery") || target.contains("Preboot") {
                return None;
            }
            let avail_k: u64 = cols.get(3)?.parse().ok()?;
            Some((avail_k, target.to_string()))
        })
        .collect();
    cands.sort_by_key(|c| std::cmp::Reverse(c.0));
    for (avail_k, t) in cands {
        if avail_k < 10 * 1024 * 1024 {
            continue;
        }
        let probe = std::path::Path::new(&t).join(".noo-writable-probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            return format!("{t}/noo");
        }
    }
    crate::commands::data_root::default_for_macos(&home)
}

/// (unified_memory, usable_gpu_gb, gpu_api) for the enrollment record — the
/// controller derives the tier from these. Mirrors the agent's
/// detectUnifiedMemory: Apple Silicon (Metal, usable = iogpu wired limit or
/// ¾ RAM); Linux Tegra/Jetson/GB10 by device tree (CUDA, ¾ RAM).
/// A stable, non-reversible id for THIS machine (i11a): sha256 over a
/// domain prefix and the OS machine id (`/etc/machine-id`, or the platform
/// UUID on macOS). The raw id never leaves the box. `None` when the OS
/// gives none; the controller then judges a name claim by address.
fn machine_fingerprint() -> Option<String> {
    let raw = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .or_else(|| {
            let out = Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .and_then(|l| l.split('"').nth(3).map(str::to_string))
        })?;
    Some(fingerprint_of(&raw))
}

fn fingerprint_of(raw_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("noomesh-machine:{}", raw_id.trim()).as_bytes()))
}

/// The controller's 409 body (`{"error": "..."}`) as the line to show.
fn conflict_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("this node name is held by a different machine: {body}"))
}

fn unified_memory_facts() -> (bool, f64, &'static str) {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        let ram_gb = run(Command::new("sysctl").args(["-n", "hw.memsize"])).1
            .parse::<f64>().map(|b| b / 1_073_741_824.0).unwrap_or(0.0);
        let wired_mb = run(Command::new("sysctl").args(["-n", "iogpu.wired_limit_mb"])).1
            .parse::<f64>().unwrap_or(0.0);
        let usable = if wired_mb > 0.0 { wired_mb / 1024.0 } else { ram_gb * 0.75 };
        return (true, (usable * 10.0).round() / 10.0, "metal");
    }
    if cfg!(target_os = "linux") {
        if let Ok(b) = std::fs::read("/proc/device-tree/compatible") {
            let c = String::from_utf8_lossy(&b).to_lowercase();
            if c.contains("nvidia,tegra") || c.contains("nvidia,p3") || c.contains("gb10") {
                let ram_gb = std::fs::read_to_string("/proc/meminfo").ok()
                    .and_then(|m| m.lines().find(|l| l.starts_with("MemTotal:")).map(str::to_string))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|k| k.parse::<f64>().ok()))
                    .map(|kb| kb / 1_048_576.0)
                    .unwrap_or(0.0);
                return (true, ((ram_gb * 0.75) * 10.0).round() / 10.0, "cuda");
            }
        }
    }
    (false, 0.0, "none")
}

/// The data-root shape rule for THIS machine
/// policy): a dedicated, conventional `noo` directory.
fn data_root_acceptable(root: &str) -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    match crate::commands::data_root::shape_problem(root, cfg!(target_os = "macos"), &home) {
        None => Ok(()),
        Some((code, why)) => Err(format!("data root refused ({code}): {why} — use /var/lib/noo, or a dedicated <data disk>/noo (macOS: ~/noomesh or /Volumes/<disk>/noo)")),
    }
}

/// Interactive subprocess (sudo prompts, installer output) — inherits stdio.
fn run_visible(cmd: &mut Command) -> i32 {
    cmd.status().ok().and_then(|s| s.code()).unwrap_or(-1)
}

/// What the pre-redeem host check's exit status means for the enrollment.
#[derive(Debug, PartialEq, Eq)]
enum PreflightVerdict {
    /// Exit 1: prep-host's `PREP_CHECK` found a blocker. Stop before the
    /// single-use token is spent.
    Stop,
    /// Exit 0: nothing blocks prep.
    Clear,
    /// Any other status, a signal, or a spawn failure (`None`): an older
    /// prep without a check mode, or a broken environment. Never blocks.
    Unavailable,
}

fn preflight_verdict(code: Option<i32>) -> PreflightVerdict {
    match code {
        Some(0) => PreflightVerdict::Clear,
        Some(1) => PreflightVerdict::Stop,
        _ => PreflightVerdict::Unavailable,
    }
}

/// Run the embedded prep in check mode (unprivileged, no changes) and map
/// its status. Output is inherited: the `prep-check:` lines are the
/// operator's. 2026-10-10: a Pop!_OS box redeemed its token, THEN prep died
/// on a wrong docker repo; the check runs first so that cannot spend a token.
fn prep_preflight(data_root: &str) -> PreflightVerdict {
    let path = std::env::temp_dir().join(format!("noo-enroll-precheck-{}.sh", std::process::id()));
    if std::fs::write(&path, ASSET_PREP).is_err() {
        return PreflightVerdict::Unavailable;
    }
    let code = Command::new("bash")
        .arg(&path)
        .env("PREP_CHECK", "1")
        .env("NOO_DATA_ROOT", data_root)
        .status()
        .ok()
        .and_then(|s| s.code());
    let _ = std::fs::remove_file(&path);
    preflight_verdict(code)
}

pub fn enroll(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let _ = g;
    let mut cred: Option<EnrollCred> = None;
    let mut url = String::new();
    let mut token = String::new();
    let mut ca_sha256: Option<String> = None;
    let mut ts_authkey: Option<String> = None;
    let mut node: Option<String> = None;
    let mut skip_tailscale = false;
    let mut data_root: Option<String> = None;
    let mut skip_prep = false;
    let mut via_tailnet: Option<String> = None;
    let mut resume = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--url" => url = it.next().cloned().unwrap_or_default(),
            "--token" => token = it.next().cloned().unwrap_or_default(),
            "--ca-sha256" => ca_sha256 = it.next().cloned(),
            "--ts-authkey" => ts_authkey = it.next().cloned(),
            "--node" => node = it.next().cloned(),
            "--via-tailnet" => via_tailnet = it.next().cloned(),
            "--skip-tailscale" => skip_tailscale = true,
            "--data-root" => data_root = it.next().cloned(),
            "--skip-prep" => skip_prep = true,
            "--resume" => resume = true,
            "--help" | "-h" => {
                say(USAGE);
                return Ok(0);
            }
            // A kiosk seat's paste is not a node's (i77): name the right verb
            // instead of a usage error.
            b if b.starts_with("noo-seat1.") => {
                ui::failed(&parse_blob(b).err().unwrap_or_default(), Some("noo kiosk enroll noo-seat1.…"));
                return Ok(2);
            }
            b if b.starts_with("noo1.") => match parse_blob(b) {
                Ok(c) => cred = Some(c),
                Err(e) => {
                    ui::failed(&e.to_string(), None);
                    return Ok(2);
                }
            },
            _ => return Err(Unhandled),
        }
    }

    // `noo enroll --resume` (macOS): the registration already landed but the
    // arm step (root CLI / fetch daemon — the sudo part) failed, e.g. no
    // /usr/local/bin on a fresh Apple Silicon box (host6, 2026-09-03). The
    // token is spent, the birth key and CA anchor are persisted: finish
    // arming from what is on disk instead of minting a new token.
    if resume {
        if !cfg!(target_os = "macos") {
            ui::failed("--resume is the macOS arm-step resume; Linux nodes re-run prep with a fresh token", None);
            return Ok(2);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let base = std::path::PathBuf::from(format!("{home}/noomesh"));
        let need = ["birth.key", "node-name", "controller-url", "pki/ca.crt"];
        if let Some(missing) = need.iter().find(|f| !base.join(f).is_file()) {
            ui::failed(&format!("nothing to resume — {}/{missing} is missing; enroll with a fresh token", base.display()), None);
            return Ok(1);
        }
        let node = std::fs::read_to_string(base.join("node-name")).unwrap_or_default().trim().to_string();
        let noo_url = std::fs::read_to_string(base.join("controller-url")).unwrap_or_default().trim().to_string();
        ui::step(&format!("Resuming the arm step for {node} against {noo_url} (registration already landed)"));
        return darwin_arm_daemon(&home, &noo_url, &node, data_root.as_deref());
    }
    // Self-awareness (role.rs): enrolling the controller as a node is a
    // legitimate shape (onboard's self-agent step does exactly that), but
    // it should be a CHOICE, not a surprise.
    let here = crate::role::detect();
    if let Some(c) = &here.controller {
        say(&format!("note: this box is already the controller ({}) — onboard installs its own agent \
                   (`noo onboard --only services`); continuing enrolls it as a node explicitly.",
            match c { crate::role::Controller::Standalone(p) | crate::role::Controller::Checkout(p) => p.display() }));
        // The controller is on the tailnet as tag:controller, and the ACL
        // routes every worker→controller port by that tag. The tailnet step
        // below would `tailscale up --reset --advertise-tags=tag:worker` —
        // which REPLACES the tag and takes the whole fleet offline (host8,
        // 2026-09-09: all four remote nodes Offline until the tag was
        // re-claimed by hand). Enrolling the controller as its own node
        // never needs the tailnet touched: it reaches its gateway locally.
        if !skip_tailscale {
            say(&ui::muted("tailnet step skipped: this box already holds tag:controller, and \
                            re-tagging it as a worker would cut every remote node off"));
            skip_tailscale = true;
        }
    }
    if let Some(n) = &here.node {
        say(&ui::muted(&format!("this box is already enrolled as node '{}' — re-enrolling adapts in place.", n.name)));
    }
    // A token bound to some OTHER name than the one this host already carries
    // is a typo or a rename, and neither should spend the token: the applier
    // refuses a bundle addressed to a name the agent env disagrees with
    // (`noo-apply` exit 77), so the enrollment would land and then wedge at
    // provision — host8 enrolled as `host8` on 2026-09-09 did exactly that.
    //
    // The identity that matters is the AGENT's (`NODE_ID` in the root-only
    // agent env) — that is what the applier compares against. The 644
    // node-name file is only prep-host's copy of it, and a 0.5.17 enrollment
    // that never applied left the two disagreeing (node-name `host8`, agent
    // `host8`), so a guard reading node-name refused the CORRECT token
    // (2026-09-10). Read the agent env, with the one sudo enroll takes
    // anyway (host prep reuses the cached credential); node-name is the
    // fallback where there is no agent env to read.
    let bound = cred.as_ref().and_then(|c| c.node.as_deref()).or(node.as_deref()).map(str::to_string);
    if bound.is_some() {
        let existing = installed_agent_node_id().or_else(|| here.node.as_ref().map(|n| n.name.clone()));
        if let Some(problem) = bound_name_conflict(existing.as_deref(), bound.as_deref()) {
            ui::failed(&problem, None);
            return Ok(2);
        }
    }
    let cred = match cred {
        Some(c) => c,
        // Tailnet-native: no token, no pins — the
        // serve URL's WebPKI cert verifies transport, whois + dialback on
        // the controller verify identity.
        None if via_tailnet.is_some() => EnrollCred {
            url: via_tailnet.clone().unwrap_or_default(),
            token: String::new(),
            ca_sha256,
            ts_authkey,
            node,
        },
        None if !url.is_empty() && !token.is_empty() => EnrollCred {
            url,
            token,
            ca_sha256,
            ts_authkey,
            node,
        },
        None => {
            eprintln!("{USAGE}");
            eprintln!("(the blob comes from `noo cluster bootstrap-token create --node <name>` on the controller)");
            return Ok(2);
        }
    };
    let noo_url = cred.url.trim_end_matches('/').to_string();

    // ── 1. Tailnet join ────────────────────────────────────────────────────
    if !skip_tailscale {
        if let Some(tsk) = &cred.ts_authkey {
            phase("Tailnet");
            if run(Command::new("sh").args([
                "-c",
                "command -v tailscale || test -x /opt/homebrew/bin/tailscale",
            ]))
            .0 != 0
            {
                // Install.sh is linux-only; darwin uses the brew
                // FORMULA (headless tailscaled) — never the cask/App Store
                // app on an SSH-driven box.
                let ts_install =
                    crate::vendor::install_script_cmd(crate::vendor::TAILSCALE_INSTALL_URL);
                let brew_install = format!(
                    "{off}; {b} brew install tailscale && sudo {b} brew services start tailscale && sleep 3",
                    off = crate::vendor::brew_analytics_off_cmd(),
                    b = crate::vendor::BREW_ENV
                );
                let (msg, cmd) = if cfg!(target_os = "macos") {
                    (
                        "Installing tailscale (brew formula, headless) ...",
                        brew_install.as_str(),
                    )
                } else {
                    (
                        "Installing tailscale (tailscale.com, WebPKI-verified, digest logged) ...",
                        // Downloaded to a file, checked, digest printed,
                        // then run — never piped into a shell (crate::vendor).
                        ts_install.as_str(),
                    )
                };
                // Interactive installer: inherits the tty (sudo, brew) —
                // its output is the operator's to watch, under our step.
                ui::step(msg);
                if run_visible(Command::new("sh").args(["-c", cmd])) != 0 {
                    ui::close_failed("tailscale install failed", None);
                    ui::guide(&[
                        ("https://tailscale.com/download", "install tailscale manually, then re-run this enroll line"),
                    ]);
                    return Ok(1);
                }
            } else if cfg!(target_os = "macos") {
                // Installed but the daemon may not be running (fresh boot).
                let _ = run(Command::new("sh").args([
                    "-c",
                    &format!("pgrep -x tailscaled >/dev/null || sudo {} brew services start tailscale", crate::vendor::BREW_ENV),
                ]));
            }
            // Zero vendor phone-home: tailscaled uploads its client logs to
            // Tailscale unless told not to (docs/security/telemetry.md).
            tailscale_logs_off();
            // Already on the tailnet? ADAPT instead of failing: re-auth
            // with the blob's key, asserting tag:worker and keeping the
            // current hostname (bare `up` on a box with non-default flags
            // errors with "mentioning all non-default flags", which the
            // old path misread as an expired key — HOST3 demotion,
            // 2026-09-01). A fresh box takes the plain join, ALSO with
            // tag:worker asserted so the ACL matches from packet one.
            let (st, ts_json) = run(Command::new(ts_bin()).args(["status", "--json"]));
            let already_joined = st == 0 && ts_json.contains("\"BackendState\": \"Running\"");
            let hostname_arg = if already_joined {
                ts_json
                    .split("\"HostName\":")
                    .nth(1)
                    .and_then(|s| s.split('"').nth(1))
                    .map(|h| format!("--hostname={h}"))
            } else {
                None
            };
            if already_joined {
                ui::step("Already on the tailnet — re-asserting tag:worker (one sudo) ...");
            } else {
                ui::step("Joining the tailnet (one sudo) ...");
            }
            let mut up = Command::new("sudo");
            up.args([ts_bin(), "up", &format!("--auth-key={tsk}"), "--advertise-tags=tag:worker"]);
            if let Some(h) = &hostname_arg {
                up.arg(h);
            }
            if run_visible(&mut up) != 0 {
                // Third state (2026-09-01): logged OUT but with stale prefs —
                // tailscale demands "mentioning all non-default flags" even
                // for a fresh auth-key join. --reset clears the stale prefs
                // and applies exactly what the blob declares; keep the
                // machine's previous tailnet hostname when one is visible.
                ui::step("Join refused (stale tailscale prefs?) — retrying with --reset ...");
                let (_, stat) = run(Command::new(ts_bin()).args(["status", "--json"]));
                let prev_host = stat
                    .split("\"HostName\":")
                    .nth(1)
                    .and_then(|s| s.split('"').nth(1))
                    .map(str::to_string);
                let mut retry = Command::new("sudo");
                retry.args([ts_bin(), "up", "--reset", &format!("--auth-key={tsk}"), "--advertise-tags=tag:worker"]);
                if let Some(h) = &prev_host {
                    if !h.is_empty() {
                        retry.arg(format!("--hostname={h}"));
                    }
                }
                if run_visible(&mut retry) != 0 {
                    ui::close_failed("tailscale up failed even with --reset", None);
                    say(&ui::note("the auth key may be expired or not authorized for tag:worker"));
                    ui::guide(&[
                        ("noo cluster bootstrap-token create --node <name>", "on the controller: mints a fresh blob with a fresh tailnet key"),
                    ]);
                    return Ok(1);
                }
            }
            // Verify the tag actually landed — a wrong self-tag turns into
            // silent ACL timeouts later; five seconds here names it now.
            let (_, after) = run(Command::new(ts_bin()).args(["status", "--json"]));
            if !after.contains("tag:worker") {
                ui::warned("this machine does not advertise tag:worker after the join");
                say(&ui::note("the tailnet ACL will drop its traffic to the controller"));
                say(&ui::note("fix the tags in the admin console (Machines → this device)"));
            } else {
                ui::done("on the tailnet as tag:worker");
            }
        }
    }

    // ── 1b. The trust anchor, BEFORE anything else touches the network ─────
    //
    // Every remaining request in this enrollment — the foreign-mesh
    // comparison, the token redemption, and `GET /bootstrap/prep`, whose body
    // is fed to `sudo bash` — used to ride an agent with TLS verification
    // switched off. They now verify against THIS certificate, fetched once
    // over the single sanctioned unverified request and accepted only when
    // its DER-sha256 equals the fingerprint the operator pasted.
    //
    // The tailnet-native lane (`--via-tailnet`) skips this: its serve URL
    // carries a real WebPKI certificate and it never redeems a blob, so
    // there is no pin and none is needed.
    let ca_pem: Vec<u8> = if via_tailnet.is_some() {
        // Verified by WebPKI, so no pin is needed and none exists — but the
        // anchor is still fetched, because the foreign-mesh guard below has
        // to compare against something and an absent CA would silently
        // disable it.
        wait_for_controller(&noo_url);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .into();
        agent
            .get(format!("{noo_url}/bootstrap/ca.crt"))
            .call()
            .ok()
            .filter(|r| r.status().as_u16() == 200)
            .and_then(|mut r| r.body_mut().read_to_string().ok())
            .filter(|t| t.starts_with("-----BEGIN CERTIFICATE-----"))
            .map(String::into_bytes)
            .unwrap_or_default()
    } else {
        phase("Trust");
        wait_for_controller(&noo_url);
        ui::step("fetching and pinning the controller's CA");
        match fetch_ca_pem(&noo_url, cred.ca_sha256.as_deref().unwrap_or("")) {
            Ok(pem) => pem,
            Err(e) => {
                ui::close_failed(&e, None);
                return Ok(1);
            }
        }
    };

    // ── 2. Foreign-mesh guard (second-controller hardening) ────────────────
    // A node belongs to ONE mesh, anchored by the birth-TOFU CA. Refuse
    // BEFORE burning the token when this machine's anchor differs from the
    // enrolling controller's. Same semantics and exit code (78) as the
    // shell rail; sudo because the anchor is root-readable only.
    //
    // The comparison is against the PIN-VERIFIED CA above, not a second
    // unverified download: bytes an unverified transport supplied could be
    // made to say "same mesh" by anyone on the path.
    if Path::new("/usr/local/bin/noo-apply").exists()
        && run(Command::new("sudo").args(["test", "-f", "/etc/noo/pki/ca.crt"])).0 == 0
    {
        let new_ca = String::from_utf8_lossy(&ca_pem).to_string();
        if new_ca.contains("BEGIN CERTIFICATE") {
            let tmp = std::env::temp_dir().join("noo-enroll-ca-probe.crt");
            if std::fs::write(&tmp, &new_ca).is_ok()
                && run(Command::new("sudo").args([
                    "cmp",
                    "-s",
                    "/etc/noo/pki/ca.crt",
                    &tmp.to_string_lossy(),
                ]))
                .0 != 0
            {
                let _ = std::fs::remove_file(&tmp);
                ui::close_failed(&format!("this machine is already enrolled in a DIFFERENT mesh (its CA anchor does not match {noo_url}'s)"), None);
                ui::guide(&[
                    ("noo cluster teardown-node <name> --factory", "on ITS controller: tear this node down first, then re-run this enroll"),
                    ("sudo noo-deenroll", "if that controller no longer exists: clear the anchor here, then re-run"),
                ]);
                return Ok(78);
            }
            let _ = std::fs::remove_file(&tmp);
        }
    }

    // ── 3. Birth keypair + machine facts ───────────────────────────────────
    // openssl subprocess (not rcgen) for exact parity with what noo-fetch's
    // bundle decryption expects; the private key never leaves this machine —
    // prep installs the root copy and we shred the original below.
    // Data root, resolved BEFORE registration for every lane — flag, then
    // the prompt, then the same picker prep-host uses — because the
    // enrollment record carries it and the controller's bundle (the
    // authoritative agent env) is rendered from that record. Until now the
    // record said /data/noo whatever prep chose: HOST3's agent ran with
    // /data/noo while prep had put its data at /mnt/d/noo (2026-09-02).
    phase("Identity");
    if data_root.is_none() {
        let suggested = suggest_data_root();
        if !skip_prep && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            if cfg!(target_os = "macos") {
                say(&ui::note("data root: where this Mac keeps the agent's data and Ollama's models (an external SSD under /Volumes is typical)"));
            } else {
                say(&ui::note("data root: where this node keeps models and data (largest writable disk)"));
            }
            // Line editor (arrows, delete, tab-completes paths). None means
            // rustyline could not start: take the suggested default, which is
            // what an empty line means anyway.
            let a = crate::onboard::prompt::read_line_edited(&format!("  Data root [{suggested}]: ")).unwrap_or_default();
            let a = a.trim();
            data_root = Some(if a.is_empty() { suggested } else { a.to_string() });
        } else {
            data_root = Some(suggested);
        }
    }
    if let Some(root) = data_root.as_deref() {
        if let Err(msg) = data_root_acceptable(root) {
            ui::failed(&msg, Some("noo enroll … --data-root /var/lib/noo"));
            return Ok(1);
        }
    }
    say(&ui::kv(&[
        ("controller", noo_url.clone()),
        ("data root", format!("{}  {}", data_root.as_deref().unwrap_or(""), ui::muted("change later: re-run enroll with --data-root"))),
    ]));
    // Right after `tailscale up` the tunnel and MagicDNS need a few seconds
    // (HOST3 2026-09-02: "the controller is unreachable: timeout" one
    // second after the join; a retry a minute later answered in 85 ms).
    // Wait, bounded, for the controller to answer before enrolling.
    wait_for_controller(&noo_url);
    let hostname = run(&mut Command::new("hostname")).1;
    let enroll_user = run(Command::new("id").arg("-un")).1;
    let birth_dir = std::env::temp_dir().join(format!("noo-birth-{}", std::process::id()));
    let mut birth_cert_pem = String::new();
    if run(Command::new("sh").args(["-c", "command -v openssl"])).0 == 0 {
        ui::step("generating the birth keypair (RSA-4096)");
        let _ = std::fs::create_dir_all(&birth_dir);
        let _ = run(Command::new("chmod").arg("700").arg(&birth_dir));
        let key = birth_dir.join("birth.key");
        let crt = birth_dir.join("birth.crt");
        let (code, _) = run(Command::new("openssl").args([
            "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-sha256", "-days", "3650",
            "-keyout", &key.to_string_lossy(),
            "-out", &crt.to_string_lossy(),
            "-subj", &format!("/CN=noo-birth-{hostname}"),
        ]));
        if code == 0 {
            birth_cert_pem = std::fs::read_to_string(&crt).unwrap_or_default();
        } else {
            let _ = std::fs::remove_dir_all(&birth_dir);
            ui::warned("birth keypair generation failed — pull provisioning unavailable");
        }
    } else {
        ui::warned("openssl not found — pull provisioning unavailable");
    }
    let model = std::fs::read_to_string("/proc/device-tree/model")
        .map(|s| s.trim_end_matches('\0').to_string())
        .or_else(|_| std::fs::read_to_string("/sys/class/dmi/id/product_name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let gpu_present = Path::new("/dev/nvidia0").exists()
        || run(Command::new("sh").args(["-c", "lspci 2>/dev/null | grep -qi nvidia"])).0 == 0;
    let tailnet_ip = run(Command::new("sh").args(["-c", "tailscale ip -4 2>/dev/null | head -1"])).1;

    // ── 3b. Preflight: can host prep succeed here? ─────────────────────────
    // Before the token is spent. Exit 1 stops; anything else (an older prep
    // with no check mode, no bash, unwritable tmp) warns and carries on.
    if cfg!(target_os = "linux") && !skip_prep {
        if ASSET_PREP.is_empty() {
            say(&ui::note(&ui::muted("no embedded prep in this build — skipping the host preflight")));
        } else {
            phase("Preflight");
            match prep_preflight(data_root.as_deref().unwrap_or("")) {
                PreflightVerdict::Clear => ui::done("this host can be prepped"),
                PreflightVerdict::Stop => {
                    // The birth keypair was generated above; nothing will
                    // install it, so shred it rather than leave it in /tmp.
                    let key = birth_dir.join("birth.key");
                    if run(Command::new("shred").arg("-u").arg(&key)).0 != 0 {
                        let _ = std::fs::remove_file(&key);
                    }
                    let _ = std::fs::remove_dir_all(&birth_dir);
                    ui::close_failed("this host cannot be prepped yet — see the prep-check lines above. The token was NOT spent.", None);
                    say(&ui::note("fix the FAIL lines, then run the same `noo enroll …` paste again"));
                    return Ok(1);
                }
                PreflightVerdict::Unavailable => {
                    say(&ui::note(&ui::muted("the host preflight could not run (older prep or restricted environment) — continuing")));
                }
            }
        }
    }

    // ── 4. Redeem the single-use token ─────────────────────────────────────
    phase("Registration");
    let unified = unified_memory_facts();
    let mut body = serde_json::json!({
        "token": cred.token,
        "hostname": hostname,
        "enroll_user": enroll_user,
        "facts": {
            "os": std::env::consts::OS,
            "arch": run(Command::new("uname").arg("-m")).1,
            "model": model,
            "gpu_present": gpu_present,
            "data_root": data_root.clone().unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.into()),
            "unified_memory": unified.0,
            "usable_gpu_gb": unified.1,
            "gpu_api": unified.2,
        },
    });
    // i11a: what tells this machine apart from another one with the same
    // hostname. The controller refuses a name held by a different machine.
    if let Some(fp) = machine_fingerprint() {
        body["facts"]["machine_fp"] = serde_json::Value::String(fp);
    }
    if !tailnet_ip.is_empty() {
        body["tailnet_ip"] = serde_json::Value::String(tailnet_ip.clone());
    }
    if !birth_cert_pem.is_empty() {
        body["birth_cert"] = serde_json::Value::String(birth_cert_pem.trim_end().to_string());
    }
    // Two admission lanes, one response shape. Tailnet-native uses a
    // VERIFYING agent (the serve URL carries a real ts.net WebPKI cert) and
    // proves identity by whois + dialback: we publish a nonce on our own
    // tailnet address, the controller's self-agent fetches it, and WireGuard
    // routing means only this machine can answer for this address.
    let verified_transport = via_tailnet.is_some();
    let resp = if via_tailnet.is_some() {
        if tailnet_ip.is_empty() {
            ui::failed("--via-tailnet needs this machine on the tailnet first (tailscale up)", None);
            let _ = std::fs::remove_dir_all(&birth_dir);
            return Ok(1);
        }
        let nonce: String = {
            // process-unique, time-salted, alphanumeric — carried only over
            // authenticated channels, single enrollment lifetime.
            use std::time::{SystemTime, UNIX_EPOCH};
            let seed = format!(
                "{}-{}-{}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
                hostname
            );
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(seed.as_bytes()))
        };
        let listener = match std::net::TcpListener::bind((tailnet_ip.as_str(), 0)) {
            Ok(l) => l,
            Err(e) => {
                ui::failed(&format!("could not bind the proof listener on {tailnet_ip}: {e}"), None);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
        };
        let proof_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let served = nonce.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    served.len(), served
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        body["proof_port"] = serde_json::json!(proof_port);
        body["proof_nonce"] = serde_json::Value::String(nonce);
        body.as_object_mut().map(|o| o.remove("token"));
        ui::step(&format!("requesting tailnet-native admission (whois + dialback on {tailnet_ip}:{proof_port})"));
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .into();
        match agent
            .post(format!("{noo_url}/api/cluster/enroll-tailnet"))
            .send_json(&body)
        {
            Ok(mut r) if r.status().as_u16() < 300 => {
                let text = r.body_mut().read_to_string().unwrap_or_default();
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
            }
            Ok(mut r) if r.status().as_u16() == 409 => {
                let text = r.body_mut().read_to_string().unwrap_or_default();
                ui::close_failed(&conflict_message(&text), None);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
            Ok(mut r) => {
                let code = r.status().as_u16();
                let text = r.body_mut().read_to_string().unwrap_or_default();
                ui::close_failed(&format!("tailnet enrollment was refused ({code}): {text}"), None);
                say(&ui::note(&format!("this device must carry the fleet's worker tag, and the controller must reach {tailnet_ip}:{proof_port}")));
                ui::guide(&[
                    ("noo cluster invite", "on the controller: mints an invite whose key carries tag:worker"),
                ]);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
            Err(e) => {
                ui::close_failed(&format!("the controller is unreachable over verified TLS: {e}"), None);
                say(&ui::note("--via-tailnet needs the controller's tailscale-serve URL, e.g. https://noo-controller.<tailnet>.ts.net"));
                ui::guide(&[
                    ("noo cluster bootstrap-token create --node <name>", "for a fleet without tailscale serve: use the blob flow instead"),
                ]);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
        }
    } else {
        ui::step("redeeming the single-use token");
        let agent = match ca_agent(&ca_pem, 30) {
            Ok(a) => a,
            Err(e) => {
                ui::close_failed(&e, None);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
        };
        match agent
            .post(format!("{noo_url}/api/cluster/bootstrap"))
            .send_json(&body)
        {
            Ok(mut r) if r.status().as_u16() < 300 => {
                let text = r.body_mut().read_to_string().unwrap_or_default();
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
            }
            Ok(mut r) if r.status().as_u16() == 409 => {
                // i11a: the name is held by a different machine. The message
                // says what to do; the token is still good.
                let text = r.body_mut().read_to_string().unwrap_or_default();
                ui::close_failed(&conflict_message(&text), None);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
            Ok(mut r) => {
                let code = r.status().as_u16();
                let text = r.body_mut().read_to_string().unwrap_or_default();
                ui::close_failed(&format!("enrollment was rejected ({code}): {text}"), None);
                say(&ui::note("tokens are single-use and expire"));
                ui::guide(&[
                    ("noo cluster bootstrap-token create --node <name>", "on the controller: mint a fresh blob, then re-run its enroll line here"),
                ]);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
            Err(e) => {
                ui::close_failed(&format!("the controller is unreachable: {e}"), None);
                ui::guide(&[
                    ("tailscale status", "is this machine on the tailnet and can it see the controller?"),
                    // Not `curl -k`: this is a REACHABILITY question, and a
                    // hint the operator pastes teaches a habit. s_client
                    // answers it without asserting trust in anything.
                    (&format!("openssl s_client -connect {} </dev/null", noo_url.trim_start_matches("https://").trim_start_matches("http://")), "does the controller answer at all from here?"),
                ]);
                let _ = std::fs::remove_dir_all(&birth_dir);
                return Ok(1);
            }
        }
    };
    ui::done(&format!("registered as {}", resp["node_name"].as_str().or(cred.node.as_deref()).unwrap_or(&hostname)));
    // The controller may still advertise a key (an older one always does).
    // Read and ignore it: enrollment installs no key any more, and failing
    // on a field we simply stopped using would be a pointless break.
    let _ssh_key = resp["ssh_public_key"].as_str().unwrap_or("").to_string();
    let bound_node = resp["node_name"]
        .as_str()
        .map(str::to_string)
        .or(cred.node.clone())
        .unwrap_or_else(|| hostname.clone());

    // ── darwin lane: no gate, no sudoers, no root prep ─────────────
    // macOS nodes have no executor-revive lane and no systemd; the bundle
    // the controller stages is applied HERE, by this binary, into
    // ~/noomesh + a LaunchAgent. Everything below this block is the linux
    // lane, unchanged.
    if cfg!(target_os = "macos") {
        return darwin_arm(&noo_url, &bound_node, &birth_dir, data_root.as_deref(), cred.ca_sha256.as_deref());
    }

    retire_legacy_user_units();

    // ── 5a. No controller SSH key ──────────────────────────────────────────
    // This pinned the controller's key to `command="/usr/local/bin/noo-gate"`
    // — verbs, never a shell, which was the right shape for a lane that
    // existed. The lane is retired and noo-gate is no longer installed, so a
    // pinned line would now authorize a forced command that is not there,
    // turning every login by that key into "No such file or directory"
    // (host9, 2026-09-02).
    //
    // The controller reaches a node over the mesh instead: the node-agent's
    // mTLS API and the NATS dispatch rail, with content arriving as CA-signed
    // bundles the node collects itself.
    phase("Access");
    {
        // Converge a box enrolled under the old lane. Only gate-pinned lines
        // go — a personal key in this file is the operator's own access and
        // is none of enrollment's business.
        let home = std::env::var("HOME").unwrap_or_default();
        let ak_path = Path::new(&home).join(".ssh/authorized_keys");
        if let Ok(existing) = std::fs::read_to_string(&ak_path) {
            let kept: Vec<&str> = existing
                .lines()
                .filter(|l| !(l.contains("/usr/local/bin/pai-gate") || l.contains("/usr/local/bin/noo-gate")))
                .collect();
            let dropped = existing.lines().count() - kept.len();
            if dropped > 0 {
                let content = kept.join("\n") + if kept.is_empty() { "" } else { "\n" };
                if std::fs::write(&ak_path, content).is_ok() {
                    ui::done(&format!(
                        "removed {dropped} gate-pinned key line(s) from {} (the SSH gate is retired)",
                        ak_path.display()
                    ));
                }
            }
        }
        say(&ui::note("pull-only enrollment: the controller gets no key on this node"));
    }

    // ── 5b. No sudoers drop-in ─────────────────────────────────────────────
    // This installed /etc/sudoers.d/noo-cluster, whose only unattended
    // consumer was named in its own comment: "the cluster executor's
    // node-agent revive" — an SSH path, and SSH is retired (2026-09-05).
    // noo-hostd's fixed worker table already has `restart-agent`, reachable
    // by writing a spool file rather than by holding a standing grant.
    //
    // A node ends with ZERO drop-ins in /etc/sudoers.d. Converge one left by
    // an earlier enrollment; prep-host removes the rest on every run.
    for stale in ["/etc/sudoers.d/noo-cluster", "/etc/sudoers.d/noo-apply"] {
        if std::path::Path::new(stale).exists() {
            let _ = run(Command::new("sudo").args(["rm", "-f", stale]));
            ui::done(&format!("retired the SSH-lane sudoers drop-in: {stale}"));
        }
    }

    // ── 6. Root prep from embedded assets ──────────────────────────────────
    if !skip_prep {
        phase("Host Prep");
    }
    // A failed prep leaves a registered node with no agent: that is a failed
    // enrollment, not a "complete" one (2026-10-10). Cleanup below still runs.
    let mut prep_failed: Option<String> = None;
    if !skip_prep && ASSET_PREP.is_empty() {
        // crate-only build: no embedded tooling. Prep still runs — fetched
        // from the controller like the shell lane (CA verified against the
        // blob's pin inside prep), just without the embedded-assets upgrade.
        say(&ui::note("this noo build has no embedded enroll assets — prep is fetched from the controller (shell-lane posture)"));
        let prep_tmp = std::env::temp_dir().join(format!("noo-enroll-prep-{}", std::process::id()));
        // this script is executed by `sudo bash` a few lines down.
        // It used to arrive over `insecure_agent(30)` — an unverified
        // transport handing root a shell script. It now verifies against the
        // pin-verified cluster CA like every other post-first-contact fetch.
        let prep_agent = ca_agent(&ca_pem, 30);
        if let Err(e) = &prep_agent {
            ui::close_failed(&format!("cannot verify the controller for the prep fetch: {e}"), None);
        }
        let fetched = prep_agent
            .ok()
            .and_then(|a| a.get(format!("{noo_url}/bootstrap/prep")).call().ok())
            .filter(|r| r.status().as_u16() == 200)
            .and_then(|mut r| r.body_mut().read_to_string().ok())
            .filter(|t| t.starts_with("#!"))
            .is_some_and(|t| std::fs::write(&prep_tmp, t).is_ok());
        if fetched {
            let ctl_host = noo_url
                .trim_start_matches("https://").trim_start_matches("http://")
                .split([':', '/']).next().unwrap_or("").to_string();
            // prep-host.sh is interactive (sudo) and long; it inherits the
            // tty under this step — its own output is the operator's.
            ui::step("running root host prep (one sudo, fetched)");
            let mut cmd = Command::new("sudo");
            cmd.arg("env")
                .arg(format!("PREP_ENROLL_USER={enroll_user}"))
                .arg("PREP_GATE_LANE=0")
                .arg(format!("NOO_DATA_ROOT={}", data_root.clone().unwrap_or_default()))
                .arg(format!("PREP_CONTROLLER_IP={ctl_host}"))
                .arg(format!("PREP_NOO_URL={noo_url}"))
                .arg(if verified_transport { "PREP_INSECURE=0" } else { "PREP_INSECURE=1" })
                .arg(format!("PREP_CA_SHA256={}", cred.ca_sha256.clone().unwrap_or_default()))
                .arg(format!("PREP_NODE_NAME={bound_node}"));
            if birth_dir.join("birth.key").exists() {
                cmd.arg(format!("PREP_BIRTH_KEY={}", birth_dir.join("birth.key").to_string_lossy()))
                    .arg(format!("PREP_BIRTH_CRT={}", birth_dir.join("birth.crt").to_string_lossy()));
            }
            cmd.arg("bash").arg(&prep_tmp);
            if run_visible(&mut cmd) != 0 {
                prep_failed = Some("host prep failed — the enrollment is registered, but the node has no agent yet".to_string());
            } else {
                ui::done("host prep finished");
            }
            let _ = std::fs::remove_file(&prep_tmp);
        } else {
            prep_failed = Some(format!("could not fetch {noo_url}/bootstrap/prep — the node has no agent yet"));
        }
    }
    if !skip_prep && !ASSET_PREP.is_empty() {
        let stage = std::env::temp_dir().join(format!("noo-enroll-stage-{}", std::process::id()));
        let tools = stage.join("tools");
        let _ = std::fs::create_dir_all(&tools);
        let mut staged_ok = true;
        // No noo-gate: the SSH gate lane is retired and the script is no
        // longer compiled in. prep-host.sh removes a copy an earlier
        // enrollment left behind.
        for (name, content) in [
            ("noo-apply", ASSET_APPLY),
            ("noo-fetch", ASSET_FETCH),
            ("noo-deenroll", ASSET_DEENROLL),
        ] {
            staged_ok &= std::fs::write(tools.join(name), content).is_ok();
        }
        let prep_path = stage.join("prep-host.sh");
        staged_ok &= std::fs::File::create(&prep_path)
            .and_then(|mut f| f.write_all(ASSET_PREP.as_bytes()))
            .is_ok();
        if !staged_ok {
            prep_failed = Some("could not stage embedded prep assets — the node has no agent yet".to_string());
        } else {
            let ctl_host = noo_url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split([':', '/'])
                .next()
                .unwrap_or("")
                .to_string();
            // prep-host.sh is interactive (sudo) and long; it inherits the
            // tty under this step — its own output is the operator's.
            ui::step("running root host prep (one sudo, embedded assets)");
            let mut cmd = Command::new("sudo");
            cmd.arg("env")
                .arg(format!("PREP_ENROLL_USER={enroll_user}"))
                .arg("PREP_GATE_LANE=0")
                .arg(format!("NOO_DATA_ROOT={}", data_root.clone().unwrap_or_default()))
                .arg(format!("PREP_CONTROLLER_IP={ctl_host}"))
                .arg(format!("PREP_NOO_URL={noo_url}"))
                .arg(if verified_transport { "PREP_INSECURE=0" } else { "PREP_INSECURE=1" })
                .arg(format!("PREP_CA_SHA256={}", cred.ca_sha256.clone().unwrap_or_default()))
                .arg(format!("PREP_NODE_NAME={bound_node}"))
                .arg(format!("PREP_TOOLS_DIR={}", tools.to_string_lossy()));
            if birth_dir.join("birth.key").exists() {
                cmd.arg(format!("PREP_BIRTH_KEY={}", birth_dir.join("birth.key").to_string_lossy()))
                    .arg(format!("PREP_BIRTH_CRT={}", birth_dir.join("birth.crt").to_string_lossy()));
            }
            cmd.arg("bash").arg(&prep_path);
            if run_visible(&mut cmd) != 0 {
                prep_failed = Some("host prep failed — the enrollment is registered, but the node has no agent yet".to_string());
            } else {
                ui::done("host prep finished (agent, fetch timer, CA anchor in place)");
            }
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    // Shred the user-owned birth key originals; the root copies live at
    // /etc/noo/birth.{key,crt} (installed by prep).
    if birth_dir.exists() {
        let key = birth_dir.join("birth.key").to_string_lossy().to_string();
        if run(Command::new("shred").args(["-u", &key])).0 != 0 {
            let _ = std::fs::remove_file(&key);
        }
        let _ = std::fs::remove_dir_all(&birth_dir);
    }

    if let Some(msg) = prep_failed {
        ui::close_failed(&msg, None);
        say(&ui::note("fix the error above first; the used token is spent, so mint a fresh one"));
        ui::guide(&[
            (&format!("noo cluster bootstrap-token create --node {bound_node}"), "on the controller: mints a fresh single-use token bound to this node"),
            ("noo enroll <paste>", "run its enroll line here again — re-enrolling the same node is safe"),
        ]);
        return Ok(1);
    }

    let completion = crate::shell_completion::ensure_installed(false).is_some();
    ui::close_done("enrollment complete");
    if completion {
        say(&ui::note("shell completion installed: new shells tab-complete noo"));
    }
    if let Some(r) = resp["role_hint"].as_str() {
        say(&ui::note(&format!("suggested role: {r}")));
    }
    say(&ui::note(&format!("controller: {noo_url}")));
    ui::guide(&[
        (&format!("noo cluster provision {bound_node} --wait"), "on the controller: stages this node's bundle and waits for the agent to come up"),
        ("noo whoami", "here: confirms this box now reads as a node of that controller"),
        ("noo health", "here: probes the controller's gateway over the pinned CA"),
    ]);
    Ok(0)
}

/// Turn off tailscaled's client log upload on this machine. Enroll-time only:
/// a node that is already running is changed by its operator, per the remedy
/// `noo cluster verify` prints (a restart drops the tailnet link). A failure
/// warns with the manual command and never stops the enrollment.
fn tailscale_logs_off() {
    let (script, manual) = if cfg!(target_os = "macos") {
        (
            crate::vendor::tailscale_nologs_mac_script(crate::vendor::tailscale_brew_plist()),
            "see docs/security/telemetry.md, Host software",
        )
    } else {
        (
            crate::vendor::tailscale_nologs_linux_script(),
            "echo 'TS_NO_LOGS_NO_SUPPORT=true' | sudo tee -a /etc/default/tailscaled && sudo systemctl restart tailscaled",
        )
    };
    ui::step("tailscale: client log upload off (this also opts out of Tailscale technical support)");
    if run_visible(Command::new("sh").args(["-c", &script])) != 0 {
        ui::warned("could not switch off tailscaled's log upload");
        say(&ui::note(&format!("do it by hand: {manual}")));
    }
}

/// tailscale binary path: brew installs outside the default non-login PATH.
fn ts_bin() -> &'static str {
    if std::path::Path::new("/opt/homebrew/bin/tailscale").exists() {
        "/opt/homebrew/bin/tailscale"
    } else {
        "tailscale"
    }
}

/// macOS enrollment tail: persist the birth key + identity under
/// ~/noomesh, set Ollama's model store, install the CLI root-owned for the
/// daemon, arm the `net.noomesh.fetch` LaunchDaemon, and EXIT — the daemon
/// pulls the bundle (and every later restage) exactly like Linux's
/// noo-fetch.timer. Before this the pull was inline: a 15-minute wait for
/// the first bundle and nothing ever after (host6, 2026-09-02).
fn darwin_arm(noo_url: &str, node: &str, birth_dir: &std::path::Path, data_root: Option<&str>, ca_sha256: Option<&str>) -> Result<i32, Unhandled> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let base = std::path::PathBuf::from(format!("{home}/noomesh"));
    let _ = std::fs::create_dir_all(&base);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o750));
    }
    // Identity for the poller.
    let key = birth_dir.join("birth.key");
    if !key.is_file() {
        ui::failed("birth key missing — cannot arm the pull lane; re-run enroll", None);
        return Ok(1);
    }
    if std::fs::copy(&key, base.join("birth.key")).is_err() {
        ui::failed(&format!("could not persist the birth key under {}", base.display()), None);
        return Ok(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(base.join("birth.key"), std::fs::Permissions::from_mode(0o600));
    }
    let _ = run(Command::new("sh").args(["-c", &format!("rm -P '{0}' 2>/dev/null || rm -f '{0}'", key.to_string_lossy())]));
    let _ = std::fs::remove_dir_all(birth_dir);
    let _ = std::fs::write(base.join("node-name"), format!("{node}\n"));
    let _ = std::fs::write(base.join("controller-url"), format!("{noo_url}\n"));

    phase("Trust");
    // Trust anchor: the Mac lane mirrors prep-host —
    // fetch the cluster CA over the token-authenticated first contact,
    // verify its DER sha256 against the blob's pin, and refuse to arm the
    // poller without it. Every later fetch pins TLS to this CA and every
    // bundle's manifest signature is checked against it; an unpinned Mac
    // used to install whatever decrypted.
    ui::step("installing the cluster CA trust anchor");
    let _ = std::fs::create_dir_all(base.join("pki"));
    match fetch_ca_pem(noo_url, ca_sha256.unwrap_or("")) {
        Ok(pem) => {
            if std::fs::write(base.join("pki/ca.crt"), &pem).is_err() {
                ui::close_failed(&format!("could not write {}/pki/ca.crt", base.display()), None);
                return Ok(1);
            }
            // The pin this CA was checked against, so the root applier can
            // re-check it when it takes its own copy.
            if let Ok(fp) = crate::commands::node_fetch::cert_der_sha256(&pem) {
                let _ = std::fs::write(base.join("ca.sha256"), format!("{fp}\n"));
            }
            ui::done(&format!("CA anchor installed at {}/pki/ca.crt", base.display()));
        }
        Err(e) => {
            ui::close_failed(&e.to_string(), None);
            say(&ui::note("the pull lane is not armed: a node without the CA anchor would refuse every signed bundle"));
            return Ok(1);
        }
    }
    let _ = std::fs::write(base.join("expect-bundle"), "10\n");
    darwin_arm_daemon(&home, noo_url, node, data_root)
}

/// launchd labels (and plist basenames) Homebrew has given the ollama
/// service, newest first: current Homebrew says `sh.brew.ollama`, older
/// releases `homebrew.mxcl.ollama` (host6, 2026-10-05, had only the first).
pub(crate) const OLLAMA_PLIST_LABELS: [&str; 2] = ["sh.brew.ollama", "homebrew.mxcl.ollama"];

/// Single-quote a value for `sh`.
pub(crate) fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// The shell that puts noomesh's environment into the brew ollama plist and
/// restarts the job. `OLLAMA_NO_CLOUD=1` is always set (docs/security/
/// telemetry.md: it stops cloud models and web search handing prompts to
/// ollama.com); `OLLAMA_MODELS` too when a data root was chosen — unless that
/// would hide models: it is set only when the new store already holds models
/// or ~/.ollama/models holds none (otherwise the script says where to move
/// them, and the node agent switches once they are there).
///
/// What Homebrew does (Library/Homebrew/services/cli.rb, read 2026-10-03):
/// `brew services start` on a service that is not already running or loaded
/// ALWAYS calls `install_service_file`, which `remove_service_files`s the
/// plist in ~/Library/LaunchAgents and re-copies one generated from the
/// formula's `service` block. `brew services stop` removes that plist too
/// (unless `--keep`), and `restart` is stop+start. So the edit must come
/// AFTER the plist is generated, and the job must be restarted with launchctl
/// (`bootout` + `bootstrap`: launchd caches the definition at bootstrap),
/// never with `brew services`. A later `brew services restart|start` or a
/// formula upgrade can still regenerate the plist; the node agent notices
/// (node-agent-go backendrt OllamaGuard.Converge) and re-applies.
///
/// The domain is ASKED, not assumed: a Mac at its screen runs LaunchAgents in
/// gui/<uid>, a headless Mac reached over SSH in user/<uid> (gui/<uid>
/// answers "125: Domain does not support specified action" there). Values go
/// through plutil, which takes each as its own argument — PlistBuddy parses
/// its command text, and "Application Support" has a space.
///
/// Exit codes: 0 applied; 3 no brew ollama plist (Ollama.app or something
/// else runs it — nothing touched); 4 a key could not be written; 5 the job
/// could not be restarted. Every non-zero exit says why on stderr.
pub(crate) fn ollama_env_script(home: &str, models: Option<&str>, uid: &str) -> String {
    let agents = format!("{}/Library/LaunchAgents", home.trim_end_matches('/'));
    let mut s = String::from("P=; L=; ");
    for l in OLLAMA_PLIST_LABELS {
        s.push_str(&format!(
            "[ -z \"$P\" ] && [ -f {f} ] && P={f} && L={l}; ",
            f = sh_quote(&format!("{agents}/{l}.plist"))
        ));
    }
    s.push_str(
        "[ -n \"$P\" ] || { echo \"no Homebrew ollama service under ~/Library/LaunchAgents (looked for sh.brew.ollama and homebrew.mxcl.ollama) — nothing changed\" >&2; exit 3; }; \
         plutil -insert EnvironmentVariables -dictionary \"$P\" >/dev/null 2>&1; \
         plutil -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string 1 \"$P\" || { echo \"could not set OLLAMA_NO_CLOUD in $P\" >&2; exit 4; }; ",
    );
    if let Some(m) = models {
        let old = sh_quote(&format!("{}/.ollama/models/manifests", home.trim_end_matches('/')));
        s.push_str(&format!(
            "M={m}; if [ -n \"$(ls -A \"$M/manifests\" 2>/dev/null)\" ] || [ -z \"$(ls -A {old} 2>/dev/null)\" ]; then \
             plutil -replace EnvironmentVariables.OLLAMA_MODELS -string \"$M\" \"$P\" || {{ echo \"could not set OLLAMA_MODELS in $P\" >&2; exit 4; }}; \
             else echo \"kept OLLAMA_MODELS: models are in ~/.ollama/models — move them to $M and the node agent switches to it\" >&2; fi; ",
            m = sh_quote(m)
        ));
    }
    s.push_str(&format!(
        "D=; for d in gui/{uid} user/{uid}; do launchctl print \"$d/$L\" >/dev/null 2>&1 && D=$d && break; done; \
         [ -n \"$D\" ] || {{ launchctl print gui/{uid} >/dev/null 2>&1 && D=gui/{uid} || D=user/{uid}; }}; \
         launchctl bootout \"$D\" \"$P\" >/dev/null 2>&1; \
         launchctl bootstrap \"$D\" \"$P\" || {{ echo \"launchctl bootstrap $D $P failed\" >&2; exit 5; }}"
    ));
    s
}

/// The sudo half of the Mac lane: Ollama, the root-owned CLI, the fetch
/// LaunchDaemon. Separate from identity persistence so `--resume` can
/// re-run it after a failure without a new token.
fn darwin_arm_daemon(home: &str, noo_url: &str, node: &str, data_root: Option<&str>) -> Result<i32, Unhandled> {
    let user = run(Command::new("id").arg("-un")).1;
    let _ = noo_url;
    phase("Service");
    // Metal-native backend — the whole reason a Mac joins. Quiet brew.
    ui::step("ensuring ollama (brew, Metal-native)");
    let _ = run_visible(Command::new("sh").args([
        "-c",
        &format!(
            "{off}; {b} brew list ollama >/dev/null 2>&1 || {b} brew install ollama; {b} brew services start ollama >/dev/null 2>&1 || true",
            off = crate::vendor::brew_analytics_off_cmd(),
            b = crate::vendor::BREW_ENV
        ),
    ]));
    // `brew services start` has run once above, so the plist exists. Now set
    // the environment the launchd job needs and restart it (see
    // `ollama_env_script` for why this is NOT stop/edit/start).
    let models = data_root.filter(|r| !r.is_empty()).map(|root| format!("{root}/ollama"));
    if let Some(m) = &models {
        let _ = std::fs::create_dir_all(m);
    }
    let uid = run(Command::new("id").arg("-u")).1;
    // Say what happened, never what was meant to: until 2026-10-05 this line
    // claimed "cloud features off" while the script had found no plist.
    match Command::new("sh").args(["-c", &ollama_env_script(home, models.as_deref(), uid.trim())]).output() {
        Ok(o) if o.status.success() => {
            let note = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !note.is_empty() {
                say(&ui::note(&note));
            } else if let Some(m) = &models {
                say(&ui::note(&format!("ollama model store: {m}")));
            }
            say(&ui::note("ollama cloud features off (OLLAMA_NO_CLOUD=1): prompts never go to ollama.com"));
        }
        Ok(o) => {
            let why = String::from_utf8_lossy(&o.stderr).trim().to_string();
            ui::warned(&format!("ollama environment NOT applied: {why} — OLLAMA_NO_CLOUD is not proven; `noo cluster verify` on the controller shows it, and the node agent retries"));
        }
        Err(e) => ui::warned(&format!("ollama environment NOT applied: could not run sh: {e}")),
    }

    // The daemon runs as root: give it a root-owned copy of the CLI rather
    // than executing a user-writable file.
    let me = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "noo".into());
    let noo_bin = "/usr/local/bin/noo";
    ui::step(&format!("installing the CLI for the daemon at {noo_bin} (one sudo)"));
    // A fresh Apple Silicon Mac has no /usr/local/bin at all (Homebrew lives
    // under /opt/homebrew): `install` does not create parents, and this is
    // exactly where host6's enroll died after the token was spent.
    let _ = run(Command::new("sudo").args(["install", "-d", "-m", "755", "-o", "root", "-g", "wheel", "/usr/local/bin"]));
    let (c, o) = run(Command::new("sudo").args(["install", "-m", "755", "-o", "root", "-g", "wheel", &me, noo_bin]));
    if c != 0 {
        ui::close_failed(&format!("could not install {noo_bin}: {}", o.trim()), None);
        say(&ui::note("the registration already landed — the token is not lost"));
        ui::guide(&[("noo enroll --resume", "fix the cause above, then finish the arm step without a new token")]);
        return Ok(1);
    }
    let plist_body = crate::commands::node_fetch::fetch_daemon_plist(&user, noo_bin);
    let tmp = std::env::temp_dir().join(format!("noo-fetch-plist-{}", std::process::id()));
    if std::fs::write(&tmp, plist_body).is_err() {
        ui::failed("could not stage the fetch daemon plist", None);
        return Ok(1);
    }
    let label = crate::commands::node_fetch::FETCH_LABEL;
    let dst = format!("/Library/LaunchDaemons/{label}.plist");
    let armed = run(Command::new("sudo").args(["install", "-m", "644", "-o", "root", "-g", "wheel", &tmp.to_string_lossy(), &dst])).0 == 0
        && {
            let _ = run(Command::new("sudo").args(["launchctl", "bootout", &format!("system/{label}")]));
            run(Command::new("sudo").args(["launchctl", "bootstrap", "system", &dst])).0 == 0
        };
    let _ = std::fs::remove_file(&tmp);
    if !armed {
        ui::close_failed(&format!("could not arm the fetch daemon ({label})"), None);
        say(&ui::note("the registration already landed — the token is not lost"));
        ui::guide(&[
            (&format!("sudo launchctl print system/{label}"), "shows why launchd refused the daemon"),
            ("noo enroll --resume", "fix the cause, then finish the arm step without a new token"),
        ]);
        return Ok(1);
    }
    let _ = run(Command::new("sudo").args(["launchctl", "kickstart", "-k", &format!("system/{label}")]));
    ui::done(&format!("fetch daemon armed: {label}"));
    say(&ui::note(&format!("polls every 60s while a bundle is expected, then every 5 min; log: {}", crate::commands::node_fetch::FETCH_LOG)));
    ui::close_done("enrollment complete");
    say(&ui::note("the Mac collects the bundle itself and loads the agent as a LaunchDaemon (runs at boot, no login needed)"));
    ui::guide(&[
        (&format!("noo cluster provision {node} --wait"), "on the controller: stages this Mac's bundle and waits for the agent to come up"),
        ("noo whoami", "here: confirms this Mac now reads as a node of that controller"),
    ]);
    Ok(0)
}

/// GET `<url>/bootstrap/ca.crt` at first contact and verify it against the
/// enroll blob's DER-sha256 pin (finding #80: the pin makes first contact
/// token-bound rather than blind TOFU). Returns the PEM.
pub(crate) fn fetch_ca_pem(noo_url: &str, pin: &str) -> Result<Vec<u8>, String> {
    if pin.trim().is_empty() {
        return Err(format!(
            "this enrollment carries no cluster-CA fingerprint, so there is nothing to verify \
             {noo_url}/bootstrap/ca.crt against — first contact would be blind trust-on-first-use \
             and this CLI refuses it. Re-mint the paste on the controller \
             (`noo cluster provision <node>`, or `noo cluster bootstrap-token create --node <name>`); \
             a current controller always includes the pin. To pass it by hand: \
             `openssl x509 -outform DER -in <pki>/ca.crt | sha256sum` on the controller, then \
             `noo enroll --url … --token … --ca-sha256 <hex>`"
        ));
    }
    let agent = first_contact_agent(20);
    let mut resp = agent.get(&format!("{noo_url}/bootstrap/ca.crt")).call()
        .map_err(|e| format!("could not fetch the cluster CA from {noo_url}/bootstrap/ca.crt: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("{noo_url}/bootstrap/ca.crt answered HTTP {}", resp.status().as_u16()));
    }
    let mut pem = Vec::new();
    use std::io::Read as _;
    resp.body_mut().as_reader().read_to_end(&mut pem)
        .map_err(|e| format!("reading the cluster CA: {e}"))?;
    if !pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err("the controller did not serve a PEM certificate at /bootstrap/ca.crt".into());
    }
    {
        let pin = pin.trim();
        let got = crate::commands::node_fetch::cert_der_sha256(&pem)?;
        if !got.eq_ignore_ascii_case(pin) {
            return Err(format!(
                "cluster CA fingerprint MISMATCH (expected {pin}, got {got}) — possible transport tamper; enrollment must not proceed"));
        }
        say(&ui::sub(&ui::status_line(Glyph::Ok, &format!("cluster CA fingerprint verified against the token's pin ({got})"))));
    }
    Ok(pem)
}

/// `NODE_ID` from the installed agent env — the identity the applier checks a
/// bundle against. Root-only on Linux, so this takes the interactive sudo
/// enroll needs for host prep anyway (the credential stays cached for that
/// step). `None` when there is no agent env (first install), on macOS (the
/// darwin lane keeps identity under ~/noomesh), or when sudo is declined —
/// the caller then falls back to the node-name file.
fn installed_agent_node_id() -> Option<String> {
    const AGENT_ENV: &str = "/etc/noo-node-agent.env";
    if cfg!(target_os = "macos") || !std::path::Path::new(AGENT_ENV).exists() {
        return None;
    }
    let text = match std::fs::read_to_string(AGENT_ENV) {
        Ok(t) => t,
        Err(_) => {
            say(&ui::muted("reading the installed agent's identity (one sudo — host prep reuses it)"));
            let out = Command::new("sudo")
                .args(["grep", "-E", "^NODE_ID=", AGENT_ENV])
                .stdin(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            String::from_utf8_lossy(&out.stdout).to_string()
        }
    };
    parse_node_id(&text)
}

/// The last `NODE_ID=` line of an agent env (the launcher's `tail -1` rule).
fn parse_node_id(env_text: &str) -> Option<String> {
    env_text
        .lines()
        .filter_map(|l| l.strip_prefix("NODE_ID="))
        .next_back()
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// The refusal when a bound token names a different node than this host
/// already is. `None` when there is nothing to disagree with: a first
/// enrollment, an unbound token, or the same name (re-enroll in place).
fn bound_name_conflict(existing: Option<&str>, bound: Option<&str>) -> Option<String> {
    let (existing, bound) = (existing?.trim(), bound?.trim());
    if existing.is_empty() || bound.is_empty() || existing.eq_ignore_ascii_case(bound) {
        return None;
    }
    Some(format!(
        "this host is already node '{existing}' but the token is bound to '{bound}' — refusing before the \
         token is spent. The applier would reject every bundle addressed to '{bound}' (it must match the \
         identity the agent already holds). Mint the token for the name this host has: \
         `noo cluster bootstrap-token create --node {existing}`; to genuinely rename it, dismantle first \
         (`noo cluster teardown-node {existing}` on the controller), then enroll under the new name."
    ))
}

#[cfg(test)]
mod tests {
    /// i11a: the fingerprint the controller compares is the shape it
    /// accepts (64 hex), stable for one machine id, different for another,
    /// and never the raw id.
    #[test]
    fn the_machine_fingerprint_is_stable_hashed_hex() {
        use super::fingerprint_of;
        let a = fingerprint_of("0123456789abcdef0123456789abcdef");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, fingerprint_of(" 0123456789abcdef0123456789abcdef\n"));
        assert_ne!(a, fingerprint_of("fedcba9876543210fedcba9876543210"));
        assert!(!a.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn a_name_conflict_shows_the_controllers_message() {
        use super::conflict_message;
        let body = r#"{"error":"the node name 'host8' is this controller's own node; rename"}"#;
        assert_eq!(conflict_message(body), "the node name 'host8' is this controller's own node; rename");
        assert!(conflict_message("<html>").contains("held by a different machine"));
    }

    #[test]
    fn bound_name_conflict_only_fires_on_a_real_disagreement() {
        use super::bound_name_conflict;
        assert!(bound_name_conflict(None, Some("alpha1")).is_none(), "first enrollment");
        assert!(bound_name_conflict(Some("alpha-1"), None).is_none(), "unbound token");
        assert!(bound_name_conflict(Some("alpha-1"), Some("alpha-1")).is_none(), "re-enroll in place");
        assert!(bound_name_conflict(Some("alpha-1"), Some("ALPHA-1")).is_none(), "case-insensitive");
        assert!(bound_name_conflict(Some(" "), Some("alpha1")).is_none(), "blank existing");
        let msg = bound_name_conflict(Some("alpha-1"), Some("alpha1")).expect("conflict");
        assert!(msg.contains("bootstrap-token create --node alpha-1"), "{msg}");
        assert!(msg.contains("teardown-node alpha-1"), "{msg}");
    }

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-ollama-script-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs the script for real against stub `plutil` / `launchctl` that log
    /// their argv, so the test checks behaviour, not spelling.
    fn run_script(home: &std::path::Path, labels: &[&str], loaded: &str, models: Option<&str>) -> (i32, String, String) {
        use std::os::unix::fs::PermissionsExt;
        let agents = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        for l in labels {
            std::fs::write(agents.join(format!("{l}.plist")), "<plist/>").unwrap();
        }
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let log = home.join("log");
        let stub = |name: &str, body: &str| {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}\n", log.display())).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        stub("plutil", "exit 0");
        // launchctl print succeeds only for the loaded domain's job.
        stub("launchctl", &format!("[ \"$1\" = print ] && {{ case \"$2\" in {loaded}/*) exit 0;; *) exit 113;; esac; }}; exit 0"));
        let out = std::process::Command::new("sh")
            .args(["-c", &super::ollama_env_script(home.to_str().unwrap(), models, "501")])
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .unwrap();
        (out.status.code().unwrap_or(-1), std::fs::read_to_string(&log).unwrap_or_default(),
         String::from_utf8_lossy(&out.stderr).to_string())
    }

    #[test]
    fn ollama_script_finds_current_brew_label_and_the_user_domain_over_ssh() {
        let home = tmp_home("ssh");
        let (rc, log, _) = run_script(&home, &["sh.brew.ollama"], "user/501", None);
        assert_eq!(rc, 0, "{log}");
        let plist = format!("{}/Library/LaunchAgents/sh.brew.ollama.plist", &home.display());
        assert!(log.contains(&format!("plutil -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string 1 {plist}")), "{log}");
        assert!(log.contains(&format!("launchctl bootstrap user/501 {plist}")), "{log}");
        assert!(!log.contains("bootstrap gui/") && !log.contains("OLLAMA_MODELS") && !log.contains("brew services"), "{log}");
    }

    #[test]
    fn ollama_script_keeps_the_old_label_working() {
        let home = tmp_home("old");
        let (rc, log, _) = run_script(&home, &["homebrew.mxcl.ollama"], "gui/501", None);
        assert_eq!(rc, 0, "{log}");
        assert!(log.contains("launchctl bootstrap gui/501 ") && log.contains("homebrew.mxcl.ollama.plist"), "{log}");
    }

    #[test]
    fn ollama_script_fails_loudly_without_a_brew_plist() {
        let home = tmp_home("none");
        let (rc, log, err) = run_script(&home, &[], "gui/501", None);
        assert_eq!(rc, 3, "{err}");
        assert!(err.contains("no Homebrew ollama service") && log.is_empty(), "{err} / {log}");
    }

    #[test]
    fn ollama_script_sets_a_models_dir_with_a_space_but_never_hides_models() {
        let home = tmp_home("space");
        let m = format!("{}/Library/Application Support/noo/ollama", &home.display());
        // ~/.ollama/models holds models and the new store does not: kept.
        std::fs::create_dir_all(home.join(".ollama/models/manifests/registry")).unwrap();
        let (rc, log, err) = run_script(&home, &["sh.brew.ollama"], "user/501", Some(&m));
        assert_eq!(rc, 0, "{err}");
        assert!(!log.contains("OLLAMA_MODELS") && err.contains("move them to"), "{log} / {err}");
        // Once the models are moved, the space-carrying path is set whole.
        std::fs::create_dir_all(format!("{m}/manifests/registry")).unwrap();
        let (rc, log, _) = run_script(&home, &["sh.brew.ollama"], "user/501", Some(&m));
        assert_eq!(rc, 0);
        assert!(log.contains(&format!("plutil -replace EnvironmentVariables.OLLAMA_MODELS -string {m} ")), "{log}");
    }

    #[test]
    fn parse_node_id_takes_the_last_line_and_strips_quotes() {
        use super::parse_node_id;
        assert_eq!(parse_node_id("NODE_ID=alpha1\nNOO_DATA_ROOT=/x\nNODE_ID=\"alpha-1\"\n").as_deref(), Some("alpha-1"));
        assert_eq!(parse_node_id("NOO_DATA_ROOT=/x\n"), None);
        assert_eq!(parse_node_id("NODE_ID=\n"), None);
    }

    use super::*;

    fn make_blob(v: serde_json::Value) -> String {
        use base64::Engine as _;
        format!(
            "noo1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        )
    }

    #[test]
    fn blob_round_trip() {
        let blob = make_blob(serde_json::json!({
            "v": 1, "url": "https://100.64.0.16:8080", "token": "tok",
            "ca": "abcd", "tsk": "tskey-auth-x", "node": "host5"
        }));
        let c = parse_blob(&blob).unwrap();
        assert_eq!(c.url, "https://100.64.0.16:8080");
        assert_eq!(c.token, "tok");
        assert_eq!(c.ca_sha256.as_deref(), Some("abcd"));
        assert_eq!(c.ts_authkey.as_deref(), Some("tskey-auth-x"));
        assert_eq!(c.node.as_deref(), Some("host5"));
    }

    #[test]
    fn blob_optional_fields_absent() {
        let blob = make_blob(serde_json::json!({"v":1,"url":"https://c:8080","token":"t"}));
        let c = parse_blob(&blob).unwrap();
        assert!(c.ca_sha256.is_none() && c.ts_authkey.is_none() && c.node.is_none());
    }

    #[test]
    fn blob_padded_base64_accepted() {
        use base64::Engine as _;
        let json = serde_json::json!({"v":1,"url":"https://c:8080","token":"t"}).to_string();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(&json);
        assert!(parse_blob(&format!("noo1.{padded}")).is_ok());
    }

    #[test]
    fn blob_future_version_refused_with_upgrade_hint() {
        let blob = make_blob(serde_json::json!({"v":2,"url":"https://c:8080","token":"t"}));
        let err = parse_blob(&blob).unwrap_err();
        assert!(err.contains("noo upgrade"), "err was: {err}");
    }

    /// A seat's paste never enrols a node (i77), in either spelling: the
    /// `noo-seat1.` blob, or a `noo1.` blob carrying a non-node role claim.
    #[test]
    fn a_seat_blob_is_refused_by_the_node_enrolment() {
        let seat = crate::commands::kiosk_seat::compose_seat_blob(&crate::commands::kiosk_seat::SeatBlob {
            url: "https://c:8080".into(), token: "noo-st-x".into(), ca: "ab".into(), seat: "lobby".into(),
            sigpub: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n".into(),
        });
        assert!(parse_blob(&seat).unwrap_err().contains("noo kiosk enroll"));
        let smuggled = make_blob(serde_json::json!({"v":1,"url":"https://c:8080","token":"t","role":"seat"}));
        assert!(parse_blob(&smuggled).unwrap_err().contains("not a node"));
        let node = make_blob(serde_json::json!({"v":1,"url":"https://c:8080","token":"t","role":"node"}));
        assert!(parse_blob(&node).is_ok());
    }

    #[test]
    fn blob_missing_required_fields_refused() {
        assert!(parse_blob(&make_blob(serde_json::json!({"v":1,"token":"t"}))).is_err());
        assert!(parse_blob(&make_blob(serde_json::json!({"v":1,"url":"https://c"}))).is_err());
        assert!(parse_blob("nonsense").is_err());
    }

    #[test]
    fn preflight_verdict_maps_exit_codes() {
        assert_eq!(preflight_verdict(Some(0)), PreflightVerdict::Clear);
        assert_eq!(preflight_verdict(Some(1)), PreflightVerdict::Stop);
        // Only a clean 1 blocks; other codes, signals and spawn failures
        // must never stop an enrollment.
        assert_eq!(preflight_verdict(Some(2)), PreflightVerdict::Unavailable);
        assert_eq!(preflight_verdict(Some(127)), PreflightVerdict::Unavailable);
        assert_eq!(preflight_verdict(None), PreflightVerdict::Unavailable);
    }

    #[test]
    fn prep_handles_check_mode_before_the_root_guard() {
        if ASSET_PREP.is_empty() {
            return; // crate-only build
        }
        let check = ASSET_PREP.find("PREP_CHECK");
        let guard = ASSET_PREP.find("\"$(id -u)\" = 0");
        assert!(check.is_some(), "prep-host.sh has no PREP_CHECK mode");
        assert!(guard.is_some(), "prep-host.sh has no root guard");
        assert!(check < guard, "PREP_CHECK must be handled before the root guard");
    }

    #[test]
    fn embedded_assets_are_scripts() {
        if ASSET_PREP.is_empty() {
            eprintln!("crate-only build (no repo tree) — enroll asset check skipped");
            return;
        }
        for a in [ASSET_PREP, ASSET_APPLY, ASSET_FETCH, ASSET_DEENROLL] {
            assert!(a.starts_with("#!"), "embedded asset lost its shebang");
        }
        // prep must know the embedded lane or staged tools are dead weight
        assert!(ASSET_PREP.contains("PREP_TOOLS_DIR"));
    }
}
