// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo enroll` — the binary is the enroller.
//!
//! Compiled port of the shell enroller (scripts/bootstrap-enroll.sh, served
//! at `GET /bootstrap`, retired) plus the tailscale join the
//! unified paste used to inline. The operator's paste shrinks to
//! `noo enroll noo1.<blob>`; every step the shell rail fetched over
//! unverified TLS either moves into this binary (which arrived over an
//! authenticated channel) or is verified against material carried in the
//! out-of-band blob:
//!
//!   0. checks before anything is spent: sudo (terminal, root or
//!      --root-ok), free disk, then (after the join) a controller that answers
//!   1. tailscale install + `tailscale up` (skippable)
//!   2. foreign-mesh guard (exit 78 BEFORE burning the token)
//!   3. birth keypair (openssl, parity with the script's RSA-4096)
//!   4. POST /api/cluster/bootstrap — redeem the single-use token
//!   5. no controller key and no sudoers grant — the mesh is the only lane
//!   6. root prep from EMBEDDED assets (PREP_TOOLS_DIR) — the CA anchor is
//!      still fetched but hard-verified against the blob's pin
//!
//! The shell lane is gone (the script and `GET /bootstrap` are retired);
//! prep-host.sh, still served at `/bootstrap/prep`, is the root prep this
//! command runs.

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
[--ca-sha256 <hex>] [--ts-authkey <k>] [--node <name>] [--skip-tailscale] [--skip-prep] [--data-root <dir>] [--controller-approvals] [--root-ok]\n\
       noo enroll --via-tailnet <https://controller.ts.net> [--ts-authkey <k>] [--skip-prep] [--controller-approvals] [--root-ok]\n  --resume            macOS: re-run the arm step (Ollama boot service, root CLI, fetch daemon), no new token: after a failure, or once on a Mac enrolled before Ollama became a boot service\n  --controller-approvals  Linux: let the controller approve add-on workloads on this node (asked when interactive; default no)\n  --root-ok           no terminal here, and sudo needs no password: run the root steps unattended";

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
        return Err("this is a kiosk SEAT enrollment paste — run it as `noo kiosk enroll noo-seat1.…`; \
                    a seat never enrolls as a node".into());
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
            return Err(format!("this enrollment blob claims role {role}, not a node — refusing"));
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

/// The answer to enroll's controller-approvals question: only an explicit
/// yes opts in; empty, no, or anything else does not.
fn optin_answer(a: &str) -> bool {
    matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `noo enroll --controller-approvals` (i596): the owner's opt-in, written
/// during this one setup run as root by the same writer the owner uses later,
/// `noo node workloads controller allow`, run with this noo by its full path
/// (root's PATH often lacks the directory it is in).
fn opt_in_controller_approvals() {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "noo".to_string());
    let argv = crate::commands::node_workloads::controller_allow_argv(&exe);
    ui::step("opting this node in to controller approvals (as root)");
    if run_visible(Command::new(&argv[0]).args(&argv[1..])) != 0 {
        ui::warned("this node was not opted in to controller approvals; the enrollment itself is done");
        say(&ui::note(&format!("to opt in later, on this node: {}", crate::commands::node_workloads::ALLOW_AS_ROOT)));
    }
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
    // i689: the script `bash` runs sits in a fresh 0700 dir, not a
    // predictable `<tmp>/noo-enroll-precheck-<pid>.sh` another user could swap.
    let Ok(dir) = crate::private_tmp::Dir::new("noo-enroll-precheck") else {
        return PreflightVerdict::Unavailable;
    };
    let path = dir.path().join("prep-host.sh");
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

// ── Checks before anything is spent ────────────────────────────────────────
// A run that cannot finish spends nothing. Before the tailnet join (whose
// auth key may itself be single-use) and before the token is redeemed,
// enroll checks what its later steps refuse on: a way to run sudo, free
// disk for the install, and a controller that answers. Sudo is decided as
// the rest of noo decides it (i907): a terminal to ask at, root, or the
// owner's `--root-ok`; never by running sudo to see whether it could.

/// Free space, in GB, `noo enroll` asks for on `/var/lib` and on the data
/// root's disk before it spends the token: a disk that is plainly full.
/// Measured (the rehearsal's B-workers disk record, 0.6.29-rc.1, two
/// workers): enroll and provision themselves write almost nothing there
/// (/var/lib/docker 316 KB, /var/lib/noo 20 KB, no images; the ~104 MB agent
/// bundle lives elsewhere). The disk is spent at PLACEMENT, when images are
/// pulled, and is checked there (the agent's pre-pull check, #1373; the
/// image-store refusal for the CUDA image, #1397). Do not raise this to an
/// image's size: a node enrolls fine and is refused at the placement that
/// would not fit, with the size it needs.
pub(crate) const NODE_MIN_FREE_GB: u64 = 2;

/// Free bytes on the filesystem holding a path; `None` when it cannot be read.
pub(crate) type FreeBytes = Box<dyn Fn(&str) -> Option<u64>>;

/// What the checks ask this machine. Injectable, so the tests fake them.
pub(crate) struct Probes {
    pub is_root: Box<dyn Fn() -> bool>,
    pub has_tty: Box<dyn Fn() -> bool>,
    pub sudo_present: Box<dyn Fn() -> bool>,
    /// `sudo -v` at the terminal: the one password prompt, up front. Asked
    /// only when there is a terminal and the run is not root.
    pub sudo_validate: Box<dyn Fn() -> bool>,
    pub controller_reachable: Box<dyn Fn(&str) -> bool>,
    pub free_bytes: FreeBytes,
}

impl Probes {
    fn live() -> Self {
        Probes {
            is_root: Box::new(crate::onboard::steps::running_as_root),
            has_tty: Box::new(crate::onboard::steps::stdin_at_terminal),
            sudo_present: Box::new(|| run(Command::new("sh").args(["-c", "command -v sudo"])).0 == 0),
            sudo_validate: Box::new(|| run_visible(Command::new("sudo").arg("-v")) == 0),
            // Bounded wait first: right after `tailscale up` the tunnel needs
            // a few seconds before the controller answers.
            controller_reachable: Box::new(|url: &str| {
                wait_for_controller(url);
                tcp_reachable(url)
            }),
            free_bytes: Box::new(crate::commands::at_rest_volume::free_bytes),
        }
    }
}

/// The real token redemption (`POST /api/cluster/bootstrap`), a parameter so
/// the tests can count that a refused run never reaches it.
type Redeem<'a> = &'a mut dyn FnMut(&ureq::Agent, &str, &serde_json::Value) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>;

/// What this run's later steps need from the host.
#[derive(Debug, PartialEq)]
struct HostNeeds {
    sudo: bool,
    disk_paths: Vec<String>,
}

/// macOS arms its fetch daemon with sudo on every run; Linux needs sudo for
/// host prep and for `tailscale up`. Disk is checked where prep installs.
fn host_needs(macos: bool, skip_prep: bool, joins_tailnet: bool, data_root: Option<&str>) -> HostNeeds {
    let sudo = macos || !skip_prep || joins_tailnet;
    let mut disk_paths = Vec::new();
    if !macos && !skip_prep {
        disk_paths.push("/var/lib".to_string());
        if let Some(root) = data_root.filter(|r| r.starts_with('/')) {
            // The nearest directory that exists: statvfs needs a real path.
            let mut p = Path::new(root);
            while !p.exists() {
                match p.parent() {
                    Some(up) => p = up,
                    None => break,
                }
            }
            let p = p.display().to_string();
            if !disk_paths.contains(&p) {
                disk_paths.push(p);
            }
        }
    }
    HostNeeds { sudo, disk_paths }
}

/// Why this run would stop part-way, said before anything is spent.
#[derive(Debug, PartialEq)]
enum Refusal {
    NoSudo,
    SudoNeedsTerminal,
    SudoRefused,
    ControllerUnreachable(String),
    LowDisk { path: String, free: u64, need_gb: u64 },
}

const PASTE_AGAIN: &str = "noo enroll <the same paste>";

impl Refusal {
    fn code(&self) -> &'static str {
        match self {
            Refusal::NoSudo | Refusal::SudoNeedsTerminal | Refusal::SudoRefused => "enroll_needs_sudo",
            Refusal::ControllerUnreachable(_) => "enroll_controller_unreachable",
            Refusal::LowDisk { .. } => "enroll_low_disk",
        }
    }

    /// Exit codes from the agent contract: a missing controller is 3; a
    /// step only the person can take (sudo, disk) is 6.
    fn exit(&self) -> crate::output::ExitCode {
        match self {
            Refusal::ControllerUnreachable(_) => crate::output::ExitCode::GatewayUnreachable,
            _ => crate::output::ExitCode::NeedsDecision,
        }
    }

    fn message(&self) -> String {
        let what = match self {
            Refusal::NoSudo => "sudo is not installed here, and enroll runs its root steps through it".to_string(),
            Refusal::SudoNeedsTerminal => {
                "this run has no terminal to ask for the sudo password, and nothing says sudo needs none here".to_string()
            }
            Refusal::SudoRefused => "sudo did not accept a password for this user".to_string(),
            Refusal::ControllerUnreachable(url) => format!("the controller at {url} does not answer from this machine"),
            Refusal::LowDisk { path, free, need_gb } => format!(
                "only {:.1} GB free on the filesystem holding {path}; the node install needs {need_gb} GB \
                 (Docker's packages and the node agent's image, plus headroom)",
                *free as f64 / 1e9
            ),
        };
        format!("{what}. The token was NOT used")
    }

    /// The next step, one line, for the JSON `hint`.
    fn hint(&self) -> String {
        match self {
            Refusal::NoSudo => "install sudo, then run the same paste again".to_string(),
            Refusal::SudoNeedsTerminal => "run this at the machine with a terminal; or give this user passwordless sudo \
                                           for noo's install and add --root-ok; or run as root"
                .to_string(),
            Refusal::SudoRefused => "give this user sudo for noo's install, or run as root".to_string(),
            Refusal::ControllerUnreachable(_) => {
                "check that this machine reaches the controller (tailscale status), then run the same paste again".to_string()
            }
            Refusal::LowDisk { path, free, need_gb } => {
                let short = (*need_gb as f64 - *free as f64 / 1e9).ceil().max(1.0) as u64;
                format!("free {short} GB on the filesystem holding {path}, then run the same paste again")
            }
        }
    }

    fn guide(&self) -> Vec<(String, String)> {
        let again = (PASTE_AGAIN.to_string(), format!("{}; the token is still good", self.hint()));
        match self {
            Refusal::ControllerUnreachable(_) => vec![
                ("tailscale status".to_string(), "is this machine on the tailnet, and does it see the controller?".to_string()),
                again,
            ],
            Refusal::LowDisk { path, .. } => vec![(format!("df -h {path}"), "what is using the space".to_string()), again],
            _ => vec![again],
        }
    }
}

/// Sudo and disk: everything this host must have before the tailnet join.
fn host_preflight(needs: &HostNeeds, root_ok: bool, p: &Probes) -> Result<(), Refusal> {
    if needs.sudo {
        if !(p.sudo_present)() {
            return Err(Refusal::NoSudo);
        }
        let passwordless = root_ok || (p.is_root)();
        let can_prompt = (p.has_tty)();
        if !passwordless && !can_prompt {
            return Err(Refusal::SudoNeedsTerminal);
        }
        if !passwordless && !(p.sudo_validate)() {
            return Err(Refusal::SudoRefused);
        }
    }
    let need = NODE_MIN_FREE_GB.saturating_mul(1_000_000_000);
    for path in &needs.disk_paths {
        // Unknown free space is never a refusal: no guessing.
        if let Some(free) = (p.free_bytes)(path) {
            if free < need {
                return Err(Refusal::LowDisk { path: path.clone(), free, need_gb: NODE_MIN_FREE_GB });
            }
        }
    }
    Ok(())
}

/// The controller answers (a TCP connect: nothing is sent, nothing spent).
/// After the tailnet join, which is what makes it reachable.
fn controller_preflight(noo_url: &str, p: &Probes) -> Result<(), Refusal> {
    if (p.controller_reachable)(noo_url) {
        Ok(())
    } else {
        Err(Refusal::ControllerUnreachable(noo_url.to_string()))
    }
}

/// Say the refusal (`✗`, then the guide; JSON: the `{error, code, hint}`
/// envelope) and hand back its exit code.
fn report_refusal(g: &Globals, r: &Refusal) -> i32 {
    if g.json {
        crate::output::fail(true, r.exit(), r.code(), &r.message(), Some(&r.hint()));
    }
    ui::close_failed(&r.message(), None);
    let guide = r.guide();
    let lines: Vec<(&str, &str)> = guide.iter().map(|(c, w)| (c.as_str(), w.as_str())).collect();
    ui::guide(&lines);
    r.exit() as i32
}

pub fn enroll(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut redeem = |agent: &ureq::Agent, url: &str, body: &serde_json::Value| agent.post(url).send_json(body);
    enroll_with(g, args, &Probes::live(), &mut redeem)
}

fn enroll_with(g: &Globals, args: &[String], probes: &Probes, redeem: Redeem<'_>) -> Result<i32, Unhandled> {
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
    // i596: the owner's opt-in to approvals the controller signs. Only this
    // run, as the node's own root, writes it; nothing the controller sends
    // (a bundle, provision) ever does.
    let mut controller_approvals = false;
    // i907: the owner's word that sudo needs no password here, for a run
    // with no terminal to ask at. Never learned by running sudo.
    let mut root_ok = false;

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
            "--controller-approvals" => controller_approvals = true,
            "--root-ok" => root_ok = true,
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

    // ── 0. Checks before anything is spent (sudo, disk) ────────────────────
    let joins_tailnet = !skip_tailscale && cred.ts_authkey.is_some();
    let needs = host_needs(cfg!(target_os = "macos"), skip_prep, joins_tailnet, data_root.as_deref());
    if let Err(refusal) = host_preflight(&needs, root_ok, probes) {
        return Ok(report_refusal(g, &refusal));
    }

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
            // `--ssh=false`: noomesh never uses Tailscale SSH (the controller
            // reaches nodes over mTLS), so a node joins with it explicitly off.
            up.args([ts_bin(), "up", &format!("--auth-key={tsk}"), "--advertise-tags=tag:worker", "--ssh=false"]);
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
                retry.args([ts_bin(), "up", "--reset", &format!("--auth-key={tsk}"), "--advertise-tags=tag:worker", "--ssh=false"]);
                if let Some(h) = &prev_host {
                    if !h.is_empty() {
                        retry.arg(format!("--hostname={h}"));
                    }
                }
                if run_visible(&mut retry) != 0 {
                    ui::close_failed("tailscale up failed even with --reset. The token was NOT used", None);
                    // The checks above settled sudo at a terminal (`sudo -v`)
                    // and as root. Unattended, only --root-ok vouched for it:
                    // a sudo that wanted a password fails here too, and that
                    // is not the key's fault.
                    if !(probes.is_root)() && !(probes.has_tty)() {
                        say(&ui::note("if sudo printed \"a terminal is required\" or \"a password is required\" above, sudo stopped it, not the key: --root-ok needs passwordless sudo; run at a terminal instead"));
                        say(&ui::note("otherwise the auth key may be expired or not authorized for tag:worker"));
                    } else {
                        say(&ui::note("the auth key may be expired or not authorized for tag:worker"));
                    }
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

    // ── 1a. The controller answers, before anything is spent ──────────────
    if let Err(refusal) = controller_preflight(&noo_url, probes) {
        return Ok(report_refusal(g, &refusal));
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
            // i689: a fresh 0700 dir, not the fixed `<tmp>/noo-enroll-ca-probe.crt`
            // (whose planted symlink `write` would follow).
            let probe = crate::private_tmp::Dir::new("noo-enroll-ca-probe");
            let tmp = probe.as_ref().map(|d| d.path().join("ca.crt")).unwrap_or_default();
            if probe.is_ok()
                && std::fs::write(&tmp, &new_ca).is_ok()
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
    // i596: the owner's opt-in to controller approvals, asked once here
    // (before the token is spent) when nobody passed the flag. Default no; a
    // run nobody can answer is never opted in.
    if !controller_approvals && cfg!(target_os = "linux") && !skip_prep && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        say(&ui::note("the controller can approve add-on workloads on this node, with sets signed by the fleet key; no keeps approvals local (sudo on this node each time)"));
        let a = crate::onboard::prompt::read_line_edited("  Let the controller approve add-on workloads here? [y/N]: ").unwrap_or_default();
        controller_approvals = optin_answer(&a);
    }
    let mut identity = vec![
        ("controller", noo_url.clone()),
        ("data root", format!("{}  {}", data_root.as_deref().unwrap_or(""), ui::muted("change later: re-run enroll with --data-root"))),
    ];
    if cfg!(target_os = "linux") {
        let words = if controller_approvals { "yes" } else { "no (approvals stay local)" };
        identity.push(("controller approvals", format!("{words}  {}", ui::muted("change later on this node: noo node workloads controller allow|deny, as root"))));
    }
    say(&ui::kv(&identity));
    // Right after `tailscale up` the tunnel and MagicDNS need a few seconds
    // (HOST3 2026-09-02: "the controller is unreachable: timeout" one
    // second after the join; a retry a minute later answered in 85 ms).
    // Wait, bounded, for the controller to answer before enrolling.
    wait_for_controller(&noo_url);
    let hostname = run(&mut Command::new("hostname")).1;
    let enroll_user = run(Command::new("id").arg("-un")).1;
    // i689: the birth key lives in a fresh 0700 dir (removed when enroll
    // returns), not a predictable `<tmp>/noo-birth-<pid>` another user could
    // pre-create and read the key from.
    let birth_guard = crate::private_tmp::Dir::new("noo-birth");
    let birth_dir = birth_guard.as_ref().map(|d| d.path().to_path_buf()).unwrap_or_default();
    let mut birth_cert_pem = String::new();
    if let Err(e) = &birth_guard {
        ui::warned(&format!("no private dir for the birth keypair ({e}) — pull provisioning unavailable"));
    } else if run(Command::new("sh").args(["-c", "command -v openssl"])).0 == 0 {
        ui::step("generating the birth keypair (RSA-4096)");
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
        match redeem(&agent, &format!("{noo_url}/api/cluster/bootstrap"), &body) {
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
    // "admitted", not "registered": the controller has stored this
    // enrollment, and the registry row appears only when the agent first
    // heartbeats, which needs the first bundle (`noo cluster provision`).
    // "registered" sent an outside tester looking for a row that, by
    // design, was not there yet (i545 findings 98 and 102).
    let admitted_as = resp["node_name"].as_str().or(cred.node.as_deref()).unwrap_or(&hostname);
    ui::done(&format!(
        "admitted as {admitted_as}: no agent yet, it starts when the controller runs `noo cluster provision {admitted_as}`"
    ));
    // An older controller still advertises `ssh_public_key`; it is ignored:
    // enrollment installs no key (the `noo-gate` lane is retired).
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
        if controller_approvals {
            say(&ui::note("--controller-approvals is for Linux nodes (an add-on's node workload needs Linux); nothing was opted in here"));
        }
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
        // i689: the script `sudo bash` runs, in a fresh 0700 dir.
        let prep_dir = crate::private_tmp::Dir::new("noo-enroll-prep");
        let prep_tmp = prep_dir.as_ref().map(|d| d.path().join("prep-host.sh")).unwrap_or_default();
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
        // i689: root runs what is staged here; a fresh 0700 dir, not a
        // predictable `<tmp>/noo-enroll-stage-<pid>`.
        let stage_dir = crate::private_tmp::Dir::new("noo-enroll-stage");
        let stage = stage_dir.as_ref().map(|d| d.path().to_path_buf()).unwrap_or_default();
        let tools = stage.join("tools");
        let mut staged_ok = stage_dir.is_ok() && std::fs::create_dir(&tools).is_ok();
        // No noo-gate: the SSH gate lane is retired and the script is no
        // longer compiled in. prep-host.sh removes a copy an earlier
        // enrollment left behind.
        for (name, content) in [
            ("noo-apply", ASSET_APPLY),
            ("noo-fetch", ASSET_FETCH),
            ("noo-deenroll", ASSET_DEENROLL),
        ] {
            staged_ok = staged_ok && std::fs::write(tools.join(name), content).is_ok();
        }
        let prep_path = stage.join("prep-host.sh");
        staged_ok = staged_ok && std::fs::File::create(&prep_path)
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

    // After prep: the agent's state directory exists now. A failure here is
    // said, not fatal: the node is enrolled, and stays local-only.
    if controller_approvals {
        opt_in_controller_approvals();
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
pub(crate) fn ts_bin() -> &'static str {
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

/// The placement tuning keys the node agent's `ollama_env` check requires in a
/// boot-service plist (node-agent-go `OllamaTuningKeys`, same order; a Python
/// guard keeps the two lists equal).
pub(crate) const OLLAMA_TUNING_KEYS: [&str; 6] = [
    "OLLAMA_NUM_PARALLEL",
    "OLLAMA_MAX_LOADED_MODELS",
    "OLLAMA_KEEP_ALIVE",
    "OLLAMA_CONTEXT_LENGTH",
    "OLLAMA_FLASH_ATTENTION",
    "OLLAMA_KV_CACHE_TYPE",
];

/// The file under `~/noomesh` where the agent records the tuning values it
/// wants in the boot-service plist (node-agent-go `OllamaWantedEnvFile`). The
/// values come from the node's placements, which enroll cannot know, so enroll
/// reads what the agent asked for rather than inventing defaults.
pub(crate) const OLLAMA_WANTED_ENV_FILE: &str = "ollama-env.json";

/// The tuning pairs in the agent's wanted-env file (a JSON object of strings),
/// in `OLLAMA_TUNING_KEYS` order. Anything else is dropped: an unknown key, a
/// non-string or empty value, or one with a control character.
pub(crate) fn ollama_wanted_env(json: &str) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    OLLAMA_TUNING_KEYS
        .iter()
        .filter_map(|k| {
            let v = m.get(*k)?.as_str()?.trim();
            (!v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control)).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Single-quote a value for `sh`.
pub(crate) fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Where a Mac's boot-time (system) LaunchDaemons live.
const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";

/// The model store the boot service must keep: the store Ollama uses TODAY.
/// `current` is the `OLLAMA_MODELS` an existing plist carries (the boot
/// service's on a re-run, else the user LaunchAgent's), else `~/.ollama/models`.
/// A data root's store (`wanted`) replaces it only when that cannot hide
/// models: it already holds them, or the current store holds none. A root
/// LaunchDaemon without `OLLAMA_MODELS` and HOME would read root's home and
/// find an empty store.
pub(crate) fn ollama_boot_store(home: &str, current: Option<&str>, wanted: Option<&str>, has_models: &dyn Fn(&str) -> bool) -> String {
    let current = current
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("{}/.ollama/models", home.trim_end_matches('/')));
    match wanted.map(str::trim).filter(|w| !w.is_empty()) {
        Some(w) if w != current && (has_models(w) || !has_models(&current)) => w.to_string(),
        _ => current,
    }
}

/// The shell prefix that finds the boot-service plist Homebrew wrote, as `$P`
/// and its label as `$L` (current Homebrew names it `sh.brew.ollama`, older
/// releases `homebrew.mxcl.ollama`). Exits 3 when there is none.
fn system_ollama_plist_sh() -> String {
    let mut s = String::from("P=; L=; ");
    for l in OLLAMA_PLIST_LABELS {
        s.push_str(&format!(
            "[ -z \"$P\" ] && [ -f {f} ] && P={f} && L={l}; ",
            f = sh_quote(&format!("{LAUNCH_DAEMONS}/{l}.plist"))
        ));
    }
    s.push_str(&format!(
        "[ -n \"$P\" ] || {{ echo \"no Homebrew ollama boot service under {LAUNCH_DAEMONS} (looked for sh.brew.ollama and homebrew.mxcl.ollama)\" >&2; exit 3; }}; "
    ));
    s
}

/// One step of a Mac's Ollama boot-service plan: what the step says, and the
/// shell it runs (`sh -c`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OllamaBootStep {
    pub what: &'static str,
    pub sh: String,
}

/// The plan that makes a Mac's native Ollama a SYSTEM boot service run as the
/// node's user, in order. Pure: it builds the commands, it runs nothing.
///
/// Why a system LaunchDaemon (operator, 2026-11-21, followup i1156): the node
/// agent is one and comes back after a power cut; a per-user LaunchAgent
/// (`brew services start` without sudo) starts only at that user's login, so
/// a rebooted headless Mac had an agent and no Ollama.
///
/// Why Homebrew's own plist, edited (Library/Homebrew/services/cli.rb and
/// service.rb, read 2026-11-21): `sudo brew services start` writes
/// /Library/LaunchDaemons/<label>.plist from the formula's `service` block
/// (`run [opt_bin/"ollama", "serve"]`, `keep_alive true`, `working_dir var`,
/// its log paths and environment); `--sudo-service-user <user>` makes
/// `install_service_file` add `UserName`, so Ollama runs unprivileged at
/// boot. Homebrew writes no HOME and skips its per-user env-override file for
/// root services, so `HOME`, `OLLAMA_MODELS` and `OLLAMA_NO_CLOUD` are set
/// with plutil afterwards (plutil takes each value as its own argument;
/// "Application Support" has a space), and the job is restarted with
/// launchctl bootout/bootstrap: launchd caches a job's definition at
/// bootstrap. Never `brew services restart`: every `start` re-copies the plist
/// from the formula and drops the edits (`brew services start` of a loaded
/// service is a no-op, so a re-run of this plan is safe). `UserName` is set
/// with plutil too, for a boot service an older run registered without it.
/// `tuning` is the placement env the agent asked for (`ollama_wanted_env`),
/// written with the rest so the agent's `ollama_env` check passes at once.
///
/// A per-user LaunchAgent of the same service is unloaded and removed FIRST:
/// two jobs would fight over 127.0.0.1:11434, and the agent's OllamaGuard
/// would read the wrong plist. Both domains are tried (gui/<uid> at the
/// screen, user/<uid> over SSH); a job that is not loaded is not an error.
pub(crate) fn darwin_ollama_boot_plan(home: &str, user: &str, uid: &str, store: &str, tuning: &[(String, String)]) -> Vec<OllamaBootStep> {
    let b = crate::vendor::BREW_ENV;
    let agents = format!("{}/Library/LaunchAgents", home.trim_end_matches('/'));
    let mut unload = String::new();
    for l in OLLAMA_PLIST_LABELS {
        unload.push_str(&format!(
            "launchctl bootout gui/{uid}/{l} >/dev/null 2>&1; launchctl bootout user/{uid}/{l} >/dev/null 2>&1; rm -f {f}; ",
            f = sh_quote(&format!("{agents}/{l}.plist"))
        ));
    }
    unload.push_str("true");
    let find = system_ollama_plist_sh();
    let set = |key: &str, val: &str| {
        format!(
            "sudo /usr/bin/plutil -replace {key} -string {v} \"$P\" || {{ echo \"could not set {key} in $P\" >&2; exit 4; }}; ",
            v = sh_quote(val)
        )
    };
    let mut env = find.clone();
    env.push_str(&set("UserName", user));
    env.push_str("sudo /usr/bin/plutil -insert EnvironmentVariables -dictionary \"$P\" >/dev/null 2>&1; ");
    env.push_str(&set("EnvironmentVariables.HOME", home.trim_end_matches('/')));
    env.push_str(&set("EnvironmentVariables.OLLAMA_MODELS", store));
    env.push_str(&set("EnvironmentVariables.OLLAMA_NO_CLOUD", "1"));
    for (k, v) in tuning {
        env.push_str(&set(&format!("EnvironmentVariables.{k}"), v));
    }
    env.push_str("true");
    let restart = format!(
        "{find}sudo launchctl bootout \"system/$L\" >/dev/null 2>&1; \
         sudo launchctl bootstrap system \"$P\" || {{ sleep 2; sudo launchctl bootstrap system \"$P\"; }} || \
         {{ echo \"launchctl bootstrap system $P failed\" >&2; exit 5; }}"
    );
    vec![
        OllamaBootStep { what: "Homebrew analytics off", sh: crate::vendor::brew_analytics_off_cmd() },
        OllamaBootStep { what: "install ollama if absent", sh: format!("{b} brew list ollama >/dev/null 2>&1 || {b} brew install ollama") },
        OllamaBootStep { what: "unload the per-user ollama LaunchAgent", sh: unload },
        OllamaBootStep {
            what: "register ollama as a boot service",
            sh: format!("sudo {b} brew services start --sudo-service-user {u} ollama", u = sh_quote(user)),
        },
        OllamaBootStep { what: "run it as the node user, with its model store and OLLAMA_NO_CLOUD=1", sh: env },
        OllamaBootStep { what: "restart it with that environment", sh: restart },
    ]
}

/// `OLLAMA_MODELS` in a plist, if it exists and carries one.
fn plist_ollama_models(path: &str) -> Option<String> {
    if !Path::new(path).exists() {
        return None;
    }
    let (c, out) = run(Command::new("/usr/bin/plutil").args(["-extract", "EnvironmentVariables.OLLAMA_MODELS", "raw", "-o", "-", path]));
    (c == 0).then(|| out.trim().to_string()).filter(|v| !v.is_empty())
}

/// The store Ollama uses today, read from the boot service's plist (a re-run)
/// or the user LaunchAgent's, before the plan removes the latter.
fn ollama_current_store(home: &str) -> Option<String> {
    let agents = format!("{}/Library/LaunchAgents", home.trim_end_matches('/'));
    OLLAMA_PLIST_LABELS
        .iter()
        .find_map(|l| plist_ollama_models(&format!("{LAUNCH_DAEMONS}/{l}.plist")))
        .or_else(|| OLLAMA_PLIST_LABELS.iter().find_map(|l| plist_ollama_models(&format!("{agents}/{l}.plist"))))
}

/// Runs the boot-service plan. Install and the sudo step inherit the terminal
/// (brew's and sudo's output are the operator's to watch). A failed step
/// stops the plan with a warning; enrollment goes on (the agent's `native
/// ollama` verify row and its start refusal say what is left).
fn darwin_ollama_boot_service(home: &str, user: &str, data_root: Option<&str>) {
    let wanted = data_root.filter(|r| !r.is_empty()).map(|root| format!("{root}/ollama"));
    if let Some(m) = &wanted {
        let _ = std::fs::create_dir_all(m);
    }
    let has_models = |d: &str| std::fs::read_dir(Path::new(d).join("manifests")).is_ok_and(|mut e| e.next().is_some());
    let current = ollama_current_store(home);
    let store = ollama_boot_store(home, current.as_deref(), wanted.as_deref(), &has_models);
    if wanted.as_deref().is_some_and(|w| w != store) {
        say(&ui::note(&format!(
            "kept the ollama model store at {store}: it holds models and {} does not — move them there and the node agent switches",
            wanted.as_deref().unwrap_or_default()
        )));
    }
    let uid = run(Command::new("id").arg("-u")).1;
    let tuning = std::fs::read_to_string(format!("{}/noomesh/{OLLAMA_WANTED_ENV_FILE}", home.trim_end_matches('/')))
        .map(|j| ollama_wanted_env(&j))
        .unwrap_or_default();
    for step in darwin_ollama_boot_plan(home, user, uid.trim(), &store, &tuning) {
        ui::step(step.what);
        let (code, why) = if step.what == "install ollama if absent" || step.what == "register ollama as a boot service" {
            (run_visible(Command::new("sh").args(["-c", &step.sh])), String::new())
        } else {
            match Command::new("sh").args(["-c", &step.sh]).output() {
                Ok(o) => (o.status.code().unwrap_or(1), String::from_utf8_lossy(&o.stderr).trim().to_string()),
                Err(e) => (1, format!("could not run sh: {e}")),
            }
        };
        if code != 0 {
            ui::warned(&format!(
                "ollama boot service NOT set up ({}{}): run `{}` on this Mac, or run `noo enroll --resume`; `noo cluster verify` on the controller shows the native ollama row",
                step.what,
                if why.is_empty() { String::new() } else { format!(": {why}") },
                crate::commands::cluster_verify::MAC_OLLAMA_START
            ));
            return;
        }
    }
    say(&ui::note(&format!("ollama runs at boot as {user} (a system LaunchDaemon); model store: {store}")));
    say(&ui::note("ollama cloud features off (OLLAMA_NO_CLOUD=1): prompts never go to ollama.com"));
}

/// The sudo half of the Mac lane: Ollama, the root-owned CLI, the fetch
/// LaunchDaemon. Separate from identity persistence so `--resume` can
/// re-run it after a failure without a new token.
fn darwin_arm_daemon(home: &str, noo_url: &str, node: &str, data_root: Option<&str>) -> Result<i32, Unhandled> {
    let user = run(Command::new("id").arg("-un")).1;
    let _ = noo_url;
    phase("Service");
    // Metal-native backend — the whole reason a Mac joins: installed, and
    // registered to start at boot as this user (darwin_ollama_boot_plan).
    darwin_ollama_boot_service(home, user.trim(), data_root);

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
    // i689: `sudo install`s this as a root LaunchDaemon; a fresh 0700 dir.
    let plist_dir = crate::private_tmp::Dir::new("noo-fetch-plist");
    let tmp = plist_dir.as_ref().map(|d| d.path().join("fetch.plist")).unwrap_or_default();
    if plist_dir.is_err() || std::fs::write(&tmp, plist_body).is_err() {
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

    // Followup i1156: a Mac's Ollama becomes a SYSTEM boot service run as the
    // node user. The plan is pure: the commands, in order.
    #[test]
    fn the_mac_ollama_plan_installs_unloads_registers_and_pins_the_store() {
        let plan = super::darwin_ollama_boot_plan("/Users/nodeuser", "nodeuser", "501", "/Users/nodeuser/.ollama/models", &[]);
        let whats: Vec<&str> = plan.iter().map(|s| s.what).collect();
        assert_eq!(
            whats,
            [
                "Homebrew analytics off",
                "install ollama if absent",
                "unload the per-user ollama LaunchAgent",
                "register ollama as a boot service",
                "run it as the node user, with its model store and OLLAMA_NO_CLOUD=1",
                "restart it with that environment",
            ]
        );
        let sh = |i: usize| plan[i].sh.as_str();
        assert!(sh(0).contains("brew analytics off"), "{}", sh(0));
        assert!(sh(1).contains("brew list ollama >/dev/null 2>&1 || ") && sh(1).contains(" brew install ollama"), "{}", sh(1));
        assert!(sh(1).contains("HOMEBREW_NO_ANALYTICS=1") && !sh(1).starts_with("sudo"), "brew never runs as root: {}", sh(1));
        // The user agent, both labels, both domains, then its file.
        for l in super::OLLAMA_PLIST_LABELS {
            assert!(sh(2).contains(&format!("launchctl bootout gui/501/{l} ")), "{}", sh(2));
            assert!(sh(2).contains(&format!("launchctl bootout user/501/{l} ")), "{}", sh(2));
            assert!(sh(2).contains(&format!("rm -f '/Users/nodeuser/Library/LaunchAgents/{l}.plist'")), "{}", sh(2));
        }
        assert!(!sh(2).contains("sudo"), "the user agent is the user's: {}", sh(2));
        assert_eq!(
            sh(3),
            format!("sudo {} brew services start --sudo-service-user 'nodeuser' ollama", crate::vendor::BREW_ENV)
        );
        // The system plist: UserName, HOME, the store that stays, the switch.
        for want in [
            "/Library/LaunchDaemons/sh.brew.ollama.plist",
            "/Library/LaunchDaemons/homebrew.mxcl.ollama.plist",
            "sudo /usr/bin/plutil -replace UserName -string 'nodeuser' \"$P\"",
            "sudo /usr/bin/plutil -replace EnvironmentVariables.HOME -string '/Users/nodeuser' \"$P\"",
            "sudo /usr/bin/plutil -replace EnvironmentVariables.OLLAMA_MODELS -string '/Users/nodeuser/.ollama/models' \"$P\"",
            "sudo /usr/bin/plutil -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string '1' \"$P\"",
        ] {
            assert!(sh(4).contains(want), "missing {want}: {}", sh(4));
        }
        assert!(!sh(4).contains("LaunchAgents"), "{}", sh(4));
        assert!(sh(5).contains("sudo launchctl bootout \"system/$L\"") && sh(5).contains("sudo launchctl bootstrap system \"$P\""), "{}", sh(5));
        // Never `brew services restart`: it regenerates the plist and drops the edits.
        assert!(plan.iter().all(|s| !s.sh.contains("brew services restart")), "{plan:?}");
    }

    // The agent records the env it requires of a boot-service plist; enroll
    // writes exactly those values with the rest, in the agent's key order.
    #[test]
    fn the_mac_ollama_plan_writes_the_tuning_the_agent_asked_for() {
        let json = r#"{"OLLAMA_NUM_PARALLEL":"2","OLLAMA_HOST":"0.0.0.0","OLLAMA_KEEP_ALIVE":"-1","OLLAMA_CONTEXT_LENGTH":"8192","OLLAMA_KV_CACHE_TYPE":"","OLLAMA_MAX_LOADED_MODELS":3}"#;
        let t = super::ollama_wanted_env(json);
        assert_eq!(
            t,
            [("OLLAMA_NUM_PARALLEL", "2"), ("OLLAMA_KEEP_ALIVE", "-1"), ("OLLAMA_CONTEXT_LENGTH", "8192")]
                .map(|(k, v)| (k.to_string(), v.to_string())),
            "unknown keys, empty and non-string values are dropped"
        );
        assert!(super::ollama_wanted_env("not json").is_empty() && super::ollama_wanted_env("[]").is_empty());
        assert!(super::ollama_wanted_env(r#"{"OLLAMA_KEEP_ALIVE":"a\nb"}"#).is_empty(), "control characters");
        let plan = super::darwin_ollama_boot_plan("/Users/nodeuser", "nodeuser", "501", "/Users/nodeuser/.ollama/models", &t);
        let env = &plan[4].sh;
        for want in [
            "sudo /usr/bin/plutil -replace EnvironmentVariables.OLLAMA_NUM_PARALLEL -string '2' \"$P\"",
            "sudo /usr/bin/plutil -replace EnvironmentVariables.OLLAMA_KEEP_ALIVE -string '-1' \"$P\"",
            "sudo /usr/bin/plutil -replace EnvironmentVariables.OLLAMA_CONTEXT_LENGTH -string '8192' \"$P\"",
        ] {
            assert!(env.contains(want), "missing {want}: {env}");
        }
        assert!(!env.contains("OLLAMA_HOST"), "{env}");
        // Idempotent: plutil -replace sets the same value again, and the job is re-bootstrapped.
        let again = super::darwin_ollama_boot_plan("/Users/nodeuser", "nodeuser", "501", "/Users/nodeuser/.ollama/models", &t);
        assert_eq!(plan, again);
    }

    // The store stays where Ollama keeps it today; a data root's store takes
    // over only when that cannot hide models.
    #[test]
    fn the_mac_ollama_store_never_hides_models() {
        let home = "/Users/nodeuser";
        let default = "/Users/nodeuser/.ollama/models";
        let root = "/Users/nodeuser/Library/Application Support/noo/ollama";
        let none = |_: &str| false;
        assert_eq!(super::ollama_boot_store(home, None, None, &none), default);
        assert_eq!(super::ollama_boot_store(home, Some("/data/ollama"), None, &none), "/data/ollama");
        // default holds models, the root does not: kept.
        let only_default = |d: &str| d == default;
        assert_eq!(super::ollama_boot_store(home, None, Some(root), &only_default), default);
        // the root holds them (moved), or nothing does: the root.
        let only_root = |d: &str| d == root;
        assert_eq!(super::ollama_boot_store(home, None, Some(root), &only_root), root);
        assert_eq!(super::ollama_boot_store(home, None, Some(root), &none), root);
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

    /// A seat's paste never enrolls a node (i77), in either spelling: the
    /// `noo-seat1.` blob, or a `noo1.` blob carrying a non-node role claim.
    #[test]
    fn a_seat_blob_is_refused_by_the_node_enrollment() {
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

    #[test]
    fn only_an_explicit_yes_opts_in_to_controller_approvals() {
        for yes in ["y", "Y", "yes", " YES "] {
            assert!(optin_answer(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "maybe", "yep", "1", "true"] {
            assert!(!optin_answer(no), "{no:?} opted in; the default is no");
        }
    }

    // ── checks before anything is spent ──────────────────────────────────
    use crate::output::ExitCode;
    use std::cell::Cell;
    use std::rc::Rc;

    const PLENTY: Option<u64> = Some(500_000_000_000);

    /// A machine as the checks see it. `prompts` counts `sudo -v` runs.
    fn machine(root: bool, tty: bool, sudo_present: bool, reachable: bool, free: Option<u64>, prompts: Rc<Cell<u32>>) -> Probes {
        Probes {
            is_root: Box::new(move || root),
            has_tty: Box::new(move || tty),
            sudo_present: Box::new(move || sudo_present),
            sudo_validate: Box::new(move || {
                prompts.set(prompts.get() + 1);
                true
            }),
            controller_reachable: Box::new(move |_: &str| reachable),
            free_bytes: Box::new(move |_: &str| free),
        }
    }

    /// The whole enroll flow on a fake machine; the redeemer counts calls.
    /// (exit code, redeem calls)
    fn enroll_on(probes: &Probes, extra: &[&str]) -> (i32, u32) {
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let mut args: Vec<String> = ["--url", "https://ctl.invalid:8080", "--token", "t0k", "--skip-tailscale"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        args.extend(extra.iter().map(|s| s.to_string()));
        let calls = Cell::new(0u32);
        let mut redeem = |_: &ureq::Agent, _: &str, _: &serde_json::Value| -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
            calls.set(calls.get() + 1);
            Err(ureq::Error::ConnectionFailed)
        };
        let code = enroll_with(&g, &args, probes, &mut redeem).unwrap_or(-99);
        (code, calls.get())
    }

    #[test]
    fn a_run_without_terminal_or_passwordless_sudo_is_refused_before_the_redeem() {
        // The controller probe answers "unreachable" too: a run that got
        // past the sudo check would exit 3, not 6.
        let prompts = Rc::new(Cell::new(0));
        let m = machine(false, false, true, false, PLENTY, prompts.clone());
        let (code, redeemed) = enroll_on(&m, &[]);
        assert_eq!(code, ExitCode::NeedsDecision as i32, "enroll_needs_sudo exits 6");
        assert_eq!(redeemed, 0, "the token must not be redeemed");
        assert_eq!(prompts.get(), 0, "no terminal: sudo is never run to ask");
    }

    #[test]
    fn an_unreachable_controller_is_refused_before_the_redeem() {
        let m = machine(true, false, true, false, PLENTY, Rc::new(Cell::new(0)));
        let (code, redeemed) = enroll_on(&m, &[]);
        assert_eq!(code, ExitCode::GatewayUnreachable as i32, "enroll_controller_unreachable exits 3");
        assert_eq!(redeemed, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn low_disk_is_refused_before_the_redeem() {
        let m = machine(true, false, true, false, Some(1_000_000_000), Rc::new(Cell::new(0)));
        let (code, redeemed) = enroll_on(&m, &[]);
        assert_eq!(code, ExitCode::NeedsDecision as i32, "enroll_low_disk exits 6");
        assert_eq!(redeemed, 0);
    }

    #[test]
    fn a_run_that_needs_no_sudo_is_not_refused_for_it() {
        // --skip-prep and no tailnet join: nothing runs sudo on Linux, so a
        // run with no terminal goes on to the controller check (exit 3).
        if cfg!(target_os = "linux") {
            let m = machine(false, false, false, false, Some(0), Rc::new(Cell::new(0)));
            let (code, redeemed) = enroll_on(&m, &["--skip-prep"]);
            assert_eq!(code, ExitCode::GatewayUnreachable as i32);
            assert_eq!(redeemed, 0);
        }
    }

    #[test]
    fn no_terminal_and_no_passwordless_sudo_refuses_and_root_root_ok_or_a_terminal_pass() {
        let needs = HostNeeds { sudo: true, disk_paths: vec!["/var/lib".into()] };
        let p = Rc::new(Cell::new(0));
        let none = machine(false, false, true, true, PLENTY, p.clone());
        assert_eq!(host_preflight(&needs, false, &none), Err(Refusal::SudoNeedsTerminal));
        assert_eq!(p.get(), 0);
        // root
        let root = machine(true, false, true, true, PLENTY, p.clone());
        assert_eq!(host_preflight(&needs, false, &root), Ok(()));
        // the owner's --root-ok (passwordless sudo, unattended)
        assert_eq!(host_preflight(&needs, true, &none), Ok(()));
        assert_eq!(p.get(), 0, "root and --root-ok never prompt");
        // a terminal: sudo asks once, up front
        let tty = machine(false, true, true, true, PLENTY, p.clone());
        assert_eq!(host_preflight(&needs, false, &tty), Ok(()));
        assert_eq!(p.get(), 1);
        // no sudo at all, even as root: every root step runs through it
        let bare = machine(true, true, false, true, PLENTY, p.clone());
        assert_eq!(host_preflight(&needs, false, &bare), Err(Refusal::NoSudo));
        // sudo not needed: nothing is asked
        let quiet = HostNeeds { sudo: false, disk_paths: vec![] };
        assert_eq!(host_preflight(&quiet, false, &none), Ok(()));
    }

    #[test]
    fn a_terminal_whose_sudo_refuses_the_password_is_refused() {
        let needs = HostNeeds { sudo: true, disk_paths: vec![] };
        let mut m = machine(false, true, true, true, PLENTY, Rc::new(Cell::new(0)));
        m.sudo_validate = Box::new(|| false);
        assert_eq!(host_preflight(&needs, false, &m), Err(Refusal::SudoRefused));
    }

    #[test]
    fn disk_below_the_floor_is_refused_and_unknown_free_space_is_not() {
        let needs = HostNeeds { sudo: false, disk_paths: vec!["/var/lib".into()] };
        let floor = NODE_MIN_FREE_GB * 1_000_000_000;
        let low = machine(true, false, true, true, Some(floor - 1), Rc::new(Cell::new(0)));
        assert!(matches!(host_preflight(&needs, false, &low), Err(Refusal::LowDisk { .. })));
        let exact = machine(true, false, true, true, Some(floor), Rc::new(Cell::new(0)));
        assert_eq!(host_preflight(&needs, false, &exact), Ok(()));
        let unknown = machine(true, false, true, true, None, Rc::new(Cell::new(0)));
        assert_eq!(host_preflight(&needs, false, &unknown), Ok(()));
    }

    #[test]
    fn the_controller_check_reads_the_probe() {
        let up = machine(true, false, true, true, PLENTY, Rc::new(Cell::new(0)));
        assert_eq!(controller_preflight("https://ctl.invalid:8080", &up), Ok(()));
        let down = machine(true, false, true, false, PLENTY, Rc::new(Cell::new(0)));
        assert_eq!(
            controller_preflight("https://ctl.invalid:8080", &down),
            Err(Refusal::ControllerUnreachable("https://ctl.invalid:8080".into()))
        );
    }

    #[test]
    fn host_needs_follow_the_lanes() {
        // Linux with prep: sudo, and /var/lib checked
        let n = host_needs(false, false, false, None);
        assert!(n.sudo);
        assert_eq!(n.disk_paths, vec!["/var/lib".to_string()]);
        // Linux, --skip-prep, no tailnet join: no sudo, no disk
        assert_eq!(host_needs(false, true, false, None), HostNeeds { sudo: false, disk_paths: vec![] });
        // the tailnet join alone needs sudo
        assert!(host_needs(false, true, true, None).sudo);
        // macOS arms its daemon with sudo every time; no Docker install
        assert_eq!(host_needs(true, true, false, None), HostNeeds { sudo: true, disk_paths: vec![] });
        // a data root that does not exist yet is checked at its nearest parent
        let n = host_needs(false, false, false, Some("/nonexistent-noo-test/a/b/noo"));
        assert_eq!(n.disk_paths, vec!["/var/lib".to_string(), "/".to_string()]);
    }

    #[test]
    fn every_refusal_has_a_stable_code_an_exit_and_says_the_token_was_not_used() {
        let all = [
            (Refusal::NoSudo, "enroll_needs_sudo", 6),
            (Refusal::SudoNeedsTerminal, "enroll_needs_sudo", 6),
            (Refusal::SudoRefused, "enroll_needs_sudo", 6),
            (Refusal::ControllerUnreachable("https://ctl.invalid:8080".into()), "enroll_controller_unreachable", 3),
            (Refusal::LowDisk { path: "/var/lib".into(), free: 2_500_000_000, need_gb: 5 }, "enroll_low_disk", 6),
        ];
        for (r, code, exit) in all {
            assert_eq!(r.code(), code);
            assert_eq!(r.exit() as i32, exit, "{r:?}");
            assert!(r.message().ends_with("The token was NOT used"), "{}", r.message());
            assert!(!r.hint().is_empty());
            assert!(r.guide().iter().any(|(c, _)| c == super::PASTE_AGAIN), "{r:?}");
        }
        let low = Refusal::LowDisk { path: "/var/lib".into(), free: 2_500_000_000, need_gb: 5 };
        assert!(low.hint().starts_with("free 3 GB on the filesystem holding /var/lib"), "{}", low.hint());
        assert!(Refusal::SudoNeedsTerminal.hint().contains("run this at the machine with a terminal"));
    }
}
