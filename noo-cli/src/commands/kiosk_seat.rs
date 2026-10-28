// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Kiosk SEATS (proposal i77, followup i66): a kiosk display enrolled with
//! the controller so its `noo` CLI and kiosk assets ride the artifact rail
//! like a node's — and `noo upgrade --all` reaches it.
//!
//! # A seat is never a node
//!
//! A seat holds ONE credential: its own birth key, generated at
//! `noo kiosk enroll <blob>` and recorded at the controller in `noo_seats` (a table
//! no node query reads). It never holds the fleet secret, a NATS principal, a
//! backend door leaf, the node-agent control API or a harness. Its bundle can
//! carry only the kinds in [`SEAT_KINDS`] — the CLI, the four kiosk scripts,
//! the four kiosk units and the signing anchor — and the seat applier writes
//! only the paths in [`seat_targets`]; anything else refuses the WHOLE
//! bundle before a byte is written.
//!
//! # The flow
//!
//! 1. controller: `noo kiosk seat-token <seat>` mints a one-time `role=seat`
//!    token and prints `noo kiosk enroll noo-seat1.<blob>` (the blob carries
//!    the controller URL, the token, the cluster CA pin and the fleet signing
//!    PUBLIC key — the bundle trust anchor). The URL is the controller's
//!    HTTPS front door when `tailscale serve` fronts the gateway (a seat may
//!    reach nothing else), else `services.gateway_url`; `--controller`
//!    overrides. The seat trusts public roots AND the pinned cluster CA, so
//!    either door works.
//! 2. seat: `noo kiosk enroll <blob>` pins the CA, generates the birth key,
//!    redeems the token at `/api/cluster/seat-enroll`, then asks for sudo
//!    ONCE to install what truly needs root and is STATIC: `/etc/noo-seat` (trust
//!    anchors + config; the birth key readable by the seat user),
//!    `noo-seat-sync.{service,timer}` (the service runs as the seat user),
//!    the display's shared dir [`SEAT_KIOSK_DIR`] (seat user : display
//!    group, so the seat writes it and the display user runs it — never a
//!    home directory, which the display user cannot traverse), the kiosk
//!    units pointed there, and one polkit rule letting that user restart the
//!    kiosk units. The seat's own copy of the CLI lives in
//!    `~/.local/libexec/noo-seat/`. Nothing after this needs sudo, and
//!    nothing recurring runs as root.
//! 3. controller: `noo upgrade --nodes` / `--all` (or `--seats`) stages each
//!    seat's bundle — signed with the fleet signing key exactly like a node
//!    bundle, gzipped, CMS-encrypted to the seat's birth cert — then waits
//!    for every seat together and prints a verify block per seat.
//! 4. seat: `noo-seat-sync.timer` (the seat user, every minute) runs
//!    `noo kiosk seat-sync`: a signed heartbeat, a signed fetch, decrypt,
//!    verify, apply inside the allow-list, restart `kiosk-serve` / reload the
//!    display as needed, a signed apply report, and a closing heartbeat.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::host_exec::now_unix;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

/// The seat's root-owned home: birth key + cert, CA, signing anchor, config.
pub(crate) const SEAT_DIR: &str = "/etc/noo-seat";
/// The pre-0.6.10 layout, kept ONLY so `seat-sync --migrate` can move a seat
/// off it: a root timer ran a root copy of `noo` here, with its state below.
pub(crate) const LEGACY_STATE_DIR: &str = "/var/lib/noo-seat";
pub(crate) const LEGACY_APPLIER_BIN: &str = "/usr/local/libexec/noo-seat/noo";
const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/49-noo-seat.rules";
/// Where a seat's display scripts (`noo-kiosk-{launch,cdp,serve}`) live and
/// where kiosk.service / kiosk-serve.service exec them from. Root creates it
/// once (enroll, `kiosk setup` on a seat, or `seat-sync --migrate`) as
/// `<seat user>:<display group>` mode 2750: the seat's user-run sync writes
/// it, the display user (`User=` of kiosk.service, `kiosk` by default) can
/// read and execute it, nobody else can. setgid so a file the seat writes
/// keeps the display group. NOT under a home directory: 0.6.10 put these
/// in `~/.local/libexec/noo-seat/kiosk` and the display user, which cannot
/// traverse a 0750 home, died with status=203/EXEC.
pub(crate) const SEAT_KIOSK_DIR: &str = "/opt/noo-seat/kiosk";
/// Its root-owned parent.
pub(crate) const SEAT_OPT_DIR: &str = "/opt/noo-seat";
/// The system units a seat's sync may restart (polkit grants exactly these).
const SEAT_RESTARTABLE_UNITS: [&str; 4] = ["kiosk.service", "kiosk-serve.service", "kiosk-watchdog.service", "kiosk-watchdog.timer"];
pub(crate) const SEAT_SYNC_SERVICE: &str = "/etc/systemd/system/noo-seat-sync.service";
pub(crate) const SEAT_SYNC_TIMER: &str = "/etc/systemd/system/noo-seat-sync.timer";
const BLOB_PREFIX: &str = "noo-seat1.";
/// A seat bundle older than this is a replay (a node bundle's window).
const SEAT_BUNDLE_MAX_AGE_SECS: i64 = 86_400;
/// A seat heard from within this is online (the timer ticks every 60 s).
pub(crate) const SEAT_HEARTBEAT_MAX_AGE_SECS: i64 = 180;

/// Every kind a seat bundle may carry. Nothing a node bundle carries for its
/// credentials (`agent-env`, `nats-creds`, `fleet-secrets`, `svc-*` leaves,
/// `harness-*`, `hostd-binary`, `agent-binary`) is here, and the builder and
/// the applier both refuse a kind that is not.
pub(crate) const SEAT_KINDS: &[&str] = &[
    "cli-binary",
    "kiosk-launch",
    "kiosk-cdp",
    "kiosk-watchdog",
    "kiosk-serve",
    "unit-kiosk",
    "unit-kiosk-serve",
    "unit-kiosk-watchdog",
    "unit-kiosk-watchdog-timer",
    "signing-pub",
    "seat-meta",
];

// ═══ the enrollment blob ═══════════════════════════════════════════════

/// What `noo kiosk enroll <blob>` needs, in one paste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatBlob {
    pub url: String,
    pub token: String,
    /// The cluster CA's DER sha256 (the pin for first contact).
    pub ca: String,
    pub seat: String,
    /// The fleet signing PUBLIC key (PEM): what every seat bundle verifies
    /// against. Rides the same out-of-band paste as the CA pin.
    pub sigpub: String,
}

pub(crate) fn compose_seat_blob(b: &SeatBlob) -> String {
    use base64::Engine as _;
    let v = json!({"v": 1, "role": "seat", "url": b.url, "token": b.token, "ca": b.ca, "seat": b.seat, "sigpub": b.sigpub});
    format!("{BLOB_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string()))
}

/// Parse a seat blob. Refuses a node's `noo1.` blob and any blob whose claim
/// is not `role: seat` — the two pastes are not interchangeable in either
/// direction (`noo enroll` refuses this one).
pub(crate) fn parse_seat_blob(s: &str) -> Result<SeatBlob, String> {
    let s = s.trim();
    if s.starts_with("noo1.") {
        return Err("this is a NODE enrollment paste (`noo enroll noo1.…`); a seat enrolls with \
                    `noo kiosk enroll noo-seat1.…` from `noo kiosk seat-token <seat>` on the controller".into());
    }
    let b64 = s.strip_prefix(BLOB_PREFIX).ok_or("not a noo-seat1. enrollment blob")?.trim_end_matches('=');
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("blob is not valid base64url: {e}"))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("blob is not valid JSON: {e}"))?;
    if v["v"].as_i64() != Some(1) {
        return Err(format!("blob version {} is newer than this CLI understands — run `noo upgrade` first", v["v"]));
    }
    if v["role"].as_str() != Some("seat") {
        return Err("this blob does not carry the role=seat claim — refusing".into());
    }
    let field = |k: &str| v[k].as_str().map(str::to_string).filter(|s| !s.is_empty());
    let seat = field("seat").ok_or("blob is missing the seat name")?;
    if !valid_seat_name(&seat) {
        return Err(format!("blob seat name {seat:?} is not a valid name"));
    }
    let sigpub = field("sigpub").ok_or("blob is missing the fleet signing key")?;
    if !sigpub.contains("BEGIN PUBLIC KEY") {
        return Err("blob's signing key is not a PEM public key".into());
    }
    Ok(SeatBlob {
        url: field("url").ok_or("blob is missing the controller url")?,
        token: field("token").ok_or("blob is missing the token")?,
        ca: field("ca").ok_or("blob is missing the cluster CA pin")?,
        seat,
        sigpub,
    })
}

pub(crate) fn valid_seat_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ═══ seat configuration (written at enroll, root-owned) ════════════════

/// `/etc/noo-seat/seat.json`. Root-owned and written once by the enroll step,
/// so nothing the seat user can change decides where the root applier writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeatConfig {
    pub seat: String,
    pub controller_url: String,
    /// The account whose `noo` the seat keeps current.
    pub cli_user: String,
    pub cli_home: String,
    /// Tests only: where [`SeatConfig::kiosk_dir`] points instead of
    /// [`SEAT_KIOSK_DIR`]. Never read from or written to seat.json.
    #[serde(skip)]
    pub kiosk_dir_at: Option<String>,
}

impl SeatConfig {
    /// `~/.local/bin/noo` for the seat user — the ONE path under a home
    /// directory the applier writes, and it writes it AS that user.
    pub(crate) fn cli_path(&self) -> PathBuf {
        Path::new(&self.cli_home).join(".local/bin/noo")
    }

    /// The seat's own copy of `noo` — what the timer runs. USER-owned: the
    /// sync runs as the seat user, so nothing root executes is user-writable
    /// and nothing user-run needs root to be replaced.
    pub(crate) fn applier_path(&self) -> PathBuf {
        Path::new(&self.cli_home).join(".local/libexec/noo-seat/noo")
    }

    /// Where the display's scripts (`launch`, `cdp`, `serve`) live: the
    /// seat-owned shared dir [`SEAT_KIOSK_DIR`]. The units exec them from
    /// here; `/usr/local/bin/noo-kiosk-*` are symlinks here for the callers
    /// that find them on PATH (the proxy's mint, the watchdog, `kiosk status`).
    pub(crate) fn kiosk_dir(&self) -> PathBuf {
        PathBuf::from(self.kiosk_dir_at.as_deref().unwrap_or(SEAT_KIOSK_DIR))
    }

    /// The 0.6.10 location of those scripts, under the seat user's home —
    /// unreachable for the display user. Only the migration reads it (to
    /// clean it up); verify flags a seat whose units still lead here.
    pub(crate) fn home_kiosk_dir(&self) -> PathBuf {
        Path::new(&self.cli_home).join(".local/libexec/noo-seat/kiosk")
    }

    /// Applier state (last applied sha, last console build) and staging.
    pub(crate) fn state_dir(&self) -> PathBuf {
        Path::new(&self.cli_home).join(".local/state/noo-seat")
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if !valid_seat_name(&self.seat) {
            return Err(format!("seat name {:?} is invalid", self.seat));
        }
        let user_ok = !self.cli_user.is_empty()
            && self.cli_user.len() <= 32
            && self.cli_user != "root"
            && self.cli_user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !user_ok {
            return Err(format!("seat user {:?} is not a plain non-root account name", self.cli_user));
        }
        let home = Path::new(&self.cli_home);
        if !home.is_absolute()
            || self.cli_home == "/"
            || home.components().any(|c| !matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_)))
        {
            return Err(format!("seat user home {:?} is not a plain absolute path", self.cli_home));
        }
        Ok(())
    }
}

/// The seat user of an enrolled seat on THIS box (`/etc/noo-seat/seat.json`,
/// root-owned), or None when this box is not a seat. `noo kiosk setup` uses
/// it to put the display's scripts in the seat's shared dir.
pub(crate) fn enrolled_seat_user() -> Option<String> {
    let b = std::fs::read(Path::new(SEAT_DIR).join("seat.json")).ok()?;
    let cfg: SeatConfig = serde_json::from_slice(&b).ok()?;
    cfg.validate().ok()?;
    Some(cfg.cli_user)
}

// ═══ the allow-list ═══════════════════════════════════════════════════

/// Where `noo-kiosk-*` are found on PATH (root-installed symlinks into
/// [`SEAT_KIOSK_DIR`] for launch/cdp/serve; the root-owned watchdog itself);
/// never written by the seat.
const KIOSK_BIN: &str = "/usr/local/bin";

/// Where one kind lands on the seat. `Err` for any kind outside
/// [`SEAT_KINDS`] — the applier refuses the whole bundle on it.
pub(crate) fn seat_targets(kind: &str, cfg: &SeatConfig) -> Result<Vec<PathBuf>, String> {
    Ok(match kind {
        // The user's CLI, and the seat's own user-owned copy the timer runs.
        "cli-binary" => vec![cfg.cli_path(), cfg.applier_path()],
        "kiosk-launch" | "kiosk-cdp" | "kiosk-serve" => vec![cfg.kiosk_dir().join(format!("noo-{kind}"))],
        // ROOT-installed at enroll/setup and never written by the seat: the
        // watchdog runs as root (executing a user-writable script as root
        // would be an escalation), the units are static system units whose
        // text a user-run sync cannot — and must not — rewrite, and the
        // signing anchor is root-owned so a compromised seat user cannot
        // re-point what the seat trusts. Carried in the bundle, verified,
        // not applied.
        "kiosk-watchdog" | "unit-kiosk" | "unit-kiosk-serve" | "unit-kiosk-watchdog" | "unit-kiosk-watchdog-timer"
        | "signing-pub" => vec![],
        // Read, never written.
        "seat-meta" => vec![],
        other => return Err(format!(
            "REFUSED — kind '{other}' is not a seat kind; a seat bundle carries only {} (65)",
            SEAT_KINDS.join(", ")
        )),
    })
}

/// The second guard: is `p` one of the exact paths a seat may write? Checked
/// immediately before every write, independently of the kind mapping, so a
/// mapping bug cannot widen the applier's reach.
pub(crate) fn seat_path_allowed(p: &Path, cfg: &SeatConfig) -> bool {
    if !p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir)) {
        return false;
    }
    let s = p.to_string_lossy();
    let mut allowed: Vec<String> = vec![
        cfg.cli_path().to_string_lossy().into_owned(),
        cfg.applier_path().to_string_lossy().into_owned(),
    ];
    for n in ["launch", "cdp", "serve"] {
        allowed.push(cfg.kiosk_dir().join(format!("noo-kiosk-{n}")).to_string_lossy().into_owned());
    }
    allowed.iter().any(|a| a == s.as_ref())
}

/// The whole write plan for a bundle's kinds, or the refusal. Duplicate
/// kinds and any target outside the allow-list refuse everything.
pub(crate) fn plan_seat_apply(kinds: &[String], cfg: &SeatConfig) -> Result<Vec<(String, PathBuf)>, String> {
    cfg.validate()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut plan = Vec::new();
    for k in kinds {
        if !seen.insert(k.clone()) {
            return Err(format!("REFUSED — kind '{k}' appears twice (65)"));
        }
        for dst in seat_targets(k, cfg)? {
            if !seat_path_allowed(&dst, cfg) {
                return Err(format!("REFUSED — {} is outside the seat applier's allow-list (65)", dst.display()));
            }
            plan.push((k.clone(), dst));
        }
    }
    Ok(plan)
}

// ═══ the bundle (controller side) ═════════════════════════════════════

/// `#noo-seat-bundle 1` — a header no node applier accepts (`#noo-bundle 2`)
/// and the seat applier requires, so a node bundle cannot be applied to a
/// seat nor a seat bundle to a node.
pub(crate) fn seat_manifest_header(seat: &str, issued: i64) -> String {
    format!("#noo-seat-bundle 1\n#seat {seat}\n#issued {issued}\n")
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// Build the signed seat bundle tar in `work`: `manifest` (sha256 per kind),
/// `manifest.sig` (the CURRENT fleet signing key), `manifest.xsig.<n>` (each
/// retained signing key, current first — so a seat still holding the key
/// from before a rotation verifies, and then adopts the new `signing-pub`),
/// `files/<kind>`. Refuses any kind outside [`SEAT_KINDS`]: this is where a
/// node credential could otherwise slip into a seat bundle, so it is checked
/// at the one door every seat bundle goes through.
pub(crate) fn build_seat_bundle(
    ca: &crate::pki::ClusterCa,
    seat: &str,
    files: &[(&str, Vec<u8>)],
    work: &Path,
) -> Result<PathBuf, String> {
    for (kind, _) in files {
        if !SEAT_KINDS.contains(kind) {
            return Err(format!("a seat bundle may not carry '{kind}' (seat kinds: {})", SEAT_KINDS.join(", ")));
        }
    }
    ca.ensure_signing_key()?;
    let files_dir = work.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| e.to_string())?;
    let mut manifest = seat_manifest_header(seat, now_unix());
    for (kind, bytes) in files {
        std::fs::write(files_dir.join(kind), bytes).map_err(|e| e.to_string())?;
        manifest.push_str(&format!("{}  {kind}\n", sha256_hex(bytes)));
    }
    let manifest_path = work.join("manifest");
    std::fs::write(&manifest_path, &manifest).map_err(|e| e.to_string())?;
    let sign = |k: &Path, out: &str| -> bool {
        Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"]).arg(k)
            .arg("-out").arg(work.join(out))
            .arg(&manifest_path)
            .status().map(|s| s.success()).unwrap_or(false)
    };
    if !sign(&ca.signing_key_path(), "manifest.sig") {
        return Err("openssl signing failed (is openssl installed?)".into());
    }
    let mut members: Vec<String> = vec!["manifest".into(), "manifest.sig".into()];
    for (n, k) in ca.retained_signing_keys().iter().enumerate() {
        let name = format!("manifest.xsig.{n}");
        if !sign(k, &name) {
            return Err(format!("openssl could not countersign with {}", k.display()));
        }
        members.push(name);
    }
    members.push("files".into());
    let bundle = work.join("bundle.tar");
    let ok = Command::new("tar").arg("-cf").arg(&bundle).arg("-C").arg(work).args(&members)
        .status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return Err("tar failed".into());
    }
    Ok(bundle)
}

/// The kiosk parameters a seat reported (from its `/etc/default/kiosk`),
/// which the units are rendered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KioskParams {
    pub user: String,
    pub mode: super::kiosk::Mode,
    pub vt: u8,
}

pub(crate) fn kiosk_params_from(hb: &Value) -> Option<KioskParams> {
    let k = hb.get("kiosk")?;
    let user = k.get("user")?.as_str()?.to_string();
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return None;
    }
    let mode = match k.get("mode")?.as_str()? {
        "dedicated" => super::kiosk::Mode::Dedicated,
        "shared" => super::kiosk::Mode::Shared,
        _ => return None,
    };
    let vt: u8 = k.get("vt").and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64().map(|n| n as u8)))
        .filter(|v| (1..=63).contains(v))?;
    Some(KioskParams { user, mode, vt })
}

/// Everything a seat bundle carries, as (kind, bytes). Pure: the CLI bytes,
/// the signing anchor and the meta come in, so the contents are testable
/// without a release asset. Units only when the seat has reported its kiosk
/// parameters (a seat whose kiosk is not set up gets scripts and the CLI).
pub(crate) fn seat_bundle_files(
    cli: Vec<u8>,
    kiosk: Option<&KioskParams>,
    signing_pub: Vec<u8>,
    meta: &Value,
) -> Vec<(&'static str, Vec<u8>)> {
    use super::kiosk as k;
    let mut files: Vec<(&'static str, Vec<u8>)> = vec![
        ("cli-binary", cli),
        ("kiosk-launch", k::LAUNCH.as_bytes().to_vec()),
        ("kiosk-cdp", k::CDP.as_bytes().to_vec()),
        ("kiosk-watchdog", k::WATCHDOG.as_bytes().to_vec()),
        ("kiosk-serve", k::SERVE.as_bytes().to_vec()),
    ];
    if let Some(p) = kiosk {
        files.push(("unit-kiosk", k::render_kiosk_service_in(&p.user, p.mode, p.vt, SEAT_KIOSK_DIR).into_bytes()));
        files.push(("unit-kiosk-serve", k::render_serve_service_in(&p.user, SEAT_KIOSK_DIR).into_bytes()));
        files.push(("unit-kiosk-watchdog", k::render_watchdog_service().into_bytes()));
        files.push(("unit-kiosk-watchdog-timer", k::render_watchdog_timer().as_bytes().to_vec()));
    }
    files.push(("signing-pub", signing_pub));
    files.push(("seat-meta", meta.to_string().into_bytes()));
    files
}

/// Stage one seat's bundle. Returns the staged sha256 (the status route's
/// `sha256`, what the combined wait judges against).
pub(crate) fn stage_seat(g: &Globals, seat: &Value) -> Result<String, String> {
    let name = seat["seat_name"].as_str().ok_or("seat record has no name")?;
    let cert = seat["birth_cert"].as_str().filter(|c| !c.is_empty()).ok_or("seat record has no birth cert")?;
    let facts = &seat["facts"];
    let os = facts["os"].as_str().unwrap_or("linux");
    let arch = facts["arch"].as_str().unwrap_or("x86_64");
    let asset = super::provision::cli_asset_for(os, arch)
        .ok_or_else(|| format!("no CLI release asset for {os}/{arch}"))?;
    let root = crate::envfile::repo_root();
    let cli = super::provision::cached_release_asset(g, &root, &asset)?;
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    ca.ensure_signing_key()?;
    let signing_pub = std::fs::read(ca.signing_pub_path()).map_err(|e| format!("signing.pub: {e}"))?;
    let meta = json!({
        "console_build": super::cluster_verify::controller_stack_tag(),
        "cli_version": env!("CARGO_PKG_VERSION"),
        "staged_at": now_unix(),
    });
    let kiosk = kiosk_params_from(&seat["heartbeat"]);
    let files = seat_bundle_files(cli, kiosk.as_ref(), signing_pub, &meta);
    let work = private_dir(&std::env::temp_dir(), "noo-seat-stage")?;
    let r = (|| {
        let refs: Vec<(&str, Vec<u8>)> = files.iter().map(|(k, b)| (*k, b.clone())).collect();
        let bundle = build_seat_bundle(&ca, name, &refs, &work)?;
        // Seats run a fetcher from this release or later: always gzip.
        let gz = super::provision::gzip_bundle(&bundle, &work)?;
        let blob = super::provision::encrypt_bundle_cms(&gz, cert, &work)?;
        let sha = sha256_hex(&blob);
        super::provision::post_bytes(g, &format!("/api/cluster/seats/{name}/bundle"), &blob)?;
        Ok(sha)
    })();
    let _ = std::fs::remove_dir_all(&work);
    r
}

/// A fresh 0700 directory under `under` (never one that already existed).
fn private_dir(under: &Path, prefix: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = under.join(format!("{prefix}-{}-{nanos:x}-{}", std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    std::fs::DirBuilder::new().mode(0o700).recursive(false).create(&dir)
        .map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    Ok(dir)
}

// ═══ the bundle (seat side): verify ═══════════════════════════════════

/// The seat twin of the node manifest shape check: header lines exactly as
/// built, payload lines exactly `<64 hex><two spaces><kind>`.
pub(crate) fn seat_manifest_shape_ok(m: &str) -> Result<(), String> {
    let bad = || Err("REFUSED — the manifest has a line that is not a seat header or '<sha256>  <kind>' (65)".to_string());
    if m.contains('\r') || m.contains('\0') {
        return bad();
    }
    for line in m.lines() {
        let ok = if line == "#noo-seat-bundle 1" {
            true
        } else if let Some(n) = line.strip_prefix("#seat ") {
            valid_seat_name(n)
        } else if let Some(t) = line.strip_prefix("#issued ") {
            !t.is_empty() && t.len() <= 12 && t.bytes().all(|c| c.is_ascii_digit())
        } else if line.len() > 66 && &line[64..66] == "  " {
            let (sum, kind) = (&line[..64], &line[66..]);
            sum.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && kind.len() <= 64
                && kind.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        } else {
            false
        };
        if !ok {
            return bad();
        }
    }
    Ok(())
}

/// The header binding, judged AFTER the signature verifies: this seat, and
/// signed recently.
pub(crate) fn verify_seat_header(manifest: &str, seat: &str, now: i64) -> Result<(), String> {
    let field = |name: &str| manifest.lines().find_map(|l| l.strip_prefix(name)).map(|v| v.trim().to_string());
    if !manifest.lines().any(|l| l == "#noo-seat-bundle 1") {
        return Err("REFUSED — not a seat bundle (no #noo-seat-bundle 1 header); a node bundle is never applied to a seat (77)".into());
    }
    match field("#seat ") {
        Some(s) if s == seat => {}
        Some(s) => return Err(format!("REFUSED — this bundle is addressed to seat '{s}', this seat is '{seat}' (77)")),
        None => return Err("REFUSED — the bundle names no seat (77)".into()),
    }
    let issued: i64 = field("#issued ").and_then(|v| v.parse().ok()).ok_or("REFUSED — no #issued stamp (77)")?;
    let age = now - issued;
    if age > SEAT_BUNDLE_MAX_AGE_SECS {
        return Err(format!("REFUSED — signed {age}s ago, past the {SEAT_BUNDLE_MAX_AGE_SECS}s window: a replay (77)"));
    }
    if age < -300 {
        return Err("REFUSED — the bundle claims to be signed in the future; a clock is wrong (77)".into());
    }
    Ok(())
}

/// The kinds the manifest names, in order.
fn manifest_kinds(manifest: &str) -> Vec<(String, String)> {
    manifest
        .lines()
        .filter(|l| !l.starts_with('#') && l.len() > 66)
        .map(|l| (l[..64].to_string(), l[66..].to_string()))
        .collect()
}

/// Verify an extracted seat bundle in `stage` against the seat's signing
/// anchor: signature (the current key, or a countersignature by it after a
/// rotation), header, then every file's sha. Returns the plan.
pub(crate) fn verify_seat_stage(
    stage: &Path,
    signing_pub: &Path,
    cfg: &SeatConfig,
    now: i64,
) -> Result<Vec<(String, PathBuf)>, String> {
    let manifest_path = stage.join("manifest");
    let manifest = std::fs::read_to_string(&manifest_path).map_err(|_| "REFUSED — the bundle has no manifest (65)".to_string())?;
    seat_manifest_shape_ok(&manifest)?;
    let mut sigs = vec![stage.join("manifest.sig")];
    for n in 0..100 {
        let p = stage.join(format!("manifest.xsig.{n}"));
        if !p.is_file() {
            break;
        }
        sigs.push(p);
    }
    let verified = sigs.iter().filter(|s| s.is_file()).any(|sig| {
        Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"]).arg(signing_pub)
            .arg("-signature").arg(sig).arg(&manifest_path)
            .output().map(|o| o.status.success()).unwrap_or(false)
    });
    if !verified {
        return Err("REFUSED — the manifest signature does not verify against this seat's fleet signing key (77)".into());
    }
    verify_seat_header(&manifest, &cfg.seat, now)?;
    let entries = manifest_kinds(&manifest);
    for (sum, kind) in &entries {
        let bytes = std::fs::read(stage.join("files").join(kind)).map_err(|_| format!("REFUSED — '{kind}' is in the manifest but not the bundle (65)"))?;
        if &sha256_hex(&bytes) != sum {
            return Err(format!("REFUSED — '{kind}' does not match its manifest sha (65)"));
        }
    }
    let kinds: Vec<String> = entries.into_iter().map(|(_, k)| k).collect();
    plan_seat_apply(&kinds, cfg)
}

/// `noo-kiosk-launch` carries one per-box line (`setup` rewrites BROWSER=
/// when the box's browser is not `chromium`). Keep the installed line.
pub(crate) fn carry_browser_line(new: &str, installed: Option<&str>) -> String {
    let Some(old) = installed.and_then(|t| t.lines().find(|l| l.trim_start().starts_with("BROWSER=")).map(str::to_string)) else {
        return new.to_string();
    };
    let mut out: Vec<String> = Vec::new();
    for l in new.lines() {
        out.push(if l.trim_start().starts_with("BROWSER=") { old.clone() } else { l.to_string() });
    }
    let mut s = out.join("\n");
    if new.ends_with('\n') {
        s.push('\n');
    }
    s
}

// ═══ the seat's transport: which URL, which roots ═══════════════════════

/// The URL a seat token carries. The operator's `--controller` wins; then
/// the controller's HTTPS front door (the `tailscale serve` URL `noo` prints
/// as "Dashboard" — what a kiosk already shows, and the only address a seat
/// that can reach the tailnet but not the gateway's own port can use); then
/// the gateway's `services.gateway_url` the mint answered with.
pub(crate) fn seat_token_url(explicit: Option<&str>, front_door: Option<&str>, gateway: &str) -> (String, &'static str) {
    let clean = |u: &str| u.trim().trim_end_matches('/').to_string();
    if let Some(u) = explicit.map(clean).filter(|u| !u.is_empty()) {
        return (u, "--controller");
    }
    if let Some(u) = front_door.map(clean).filter(|u| !u.is_empty()) {
        return (u, "the controller's HTTPS front door (tailscale serve)");
    }
    (clean(gateway), "services.gateway_url (no HTTPS front door is serving the gateway)")
}

/// A `--controller` the seat can use: https, with a host.
pub(crate) fn validate_seat_controller(url: &str) -> Result<(), String> {
    let host = url.strip_prefix("https://").map(|r| r.split('/').next().unwrap_or("")).unwrap_or("");
    if host.is_empty() {
        return Err(format!("--controller must be an https:// URL with a host (got {url:?})"));
    }
    Ok(())
}

/// This controller's HTTPS front door, when `tailscale serve` fronts the
/// gateway (the same check `noo stack status` makes before printing it).
fn controller_front_door() -> Option<String> {
    let urls = crate::tailnet_serve::front_door_urls(8080 + crate::envfile::port_offset(), &crate::envfile::instance())?;
    urls.into_iter().find(|(label, _)| *label == "Dashboard").map(|(_, u)| u)
}

/// The public roots a seat trusts beside the cluster CA: the platform's
/// store, or Mozilla's set when the box has none (a minimal image without
/// `ca-certificates`).
fn public_roots() -> Vec<ureq::tls::Certificate<'static>> {
    let native = rustls_native_certs::load_native_certs().certs;
    if !native.is_empty() {
        return native.iter().map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned()).collect();
    }
    webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect()
}

/// The roots a seat client trusts: the pinned cluster CA AND `public`. The
/// union is what lets one seat use either door — the `tailscale serve`
/// front door (a public ts.net certificate) or the gateway's own port (a
/// cluster-CA leaf). A certificate from any other private CA is refused.
///
/// The CA pin is not weakened by this: the pinned CA still came from the
/// paste-bound fetch (`fetch_ca_pem`), and nothing a seat sends is a bearer
/// a different server could replay — enrollment spends a single-use token
/// bound to this seat's name, and every later call carries a proof signed by
/// the seat's birth key over (purpose, seat, sha, ts).
pub(crate) fn seat_agent_with(
    ca_pem: &[u8],
    public: Vec<ureq::tls::Certificate<'static>>,
    timeout: u64,
) -> Result<ureq::Agent, String> {
    let ca = ureq::tls::Certificate::from_pem(ca_pem)
        .map_err(|e| format!("the controller's CA is not a usable certificate: {e}"))?;
    let mut roots = public;
    roots.push(ca);
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
        .build();
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(std::time::Duration::from_secs(timeout)))
        .http_status_as_error(false)
        .build()
        .into())
}

/// [`seat_agent_with`] over this box's public roots: the client for the
/// seat-token redeem and every seat rail call.
pub(crate) fn seat_agent(ca_pem: &[u8], timeout: u64) -> Result<ureq::Agent, String> {
    seat_agent_with(ca_pem, public_roots(), timeout)
}

// ═══ commands ═════════════════════════════════════════════════════════

/// `noo kiosk seat-token <seat> [--ttl <1h|30m|secs>] [--controller <url>]` —
/// on the controller. The paste's URL is chosen by [`seat_token_url`].
pub fn kiosk_seat_token(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut seat: Option<String> = None;
    let mut ttl: Option<i64> = None;
    let mut controller: Option<String> = None;
    let mut it = args.iter();
    while let Some(t) = it.next() {
        match t.as_str() {
            "--controller" => controller = Some(it.next().ok_or(Unhandled)?.trim().trim_end_matches('/').to_string()),
            "--ttl" => ttl = Some(super::cluster_provision::parse_ttl_seconds(it.next().ok_or(Unhandled)?).ok_or(Unhandled)?),
            s if s.starts_with('-') => return Err(Unhandled),
            s if seat.is_none() => seat = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(seat) = seat.filter(|s| valid_seat_name(s)) else {
        fail(g.json, ExitCode::Usage, "usage", "a seat name is required ([a-zA-Z0-9._-], <= 64)",
            Some("noo kiosk seat-token <seat-name> [--ttl 1h] [--controller https://<controller>.<tailnet>.ts.net]"));
    };
    if let Some(Err(e)) = controller.as_deref().map(validate_seat_controller) {
        fail(g.json, ExitCode::Usage, "usage", &e,
            Some("noo kiosk seat-token <seat-name> --controller https://<controller>.<tailnet>.ts.net"));
    }
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    if let Err(e) = ca.ensure_signing_key() {
        fail(g.json, ExitCode::Generic, "signing_key", &e, Some("noo security pki status"));
    }
    let sigpub = match std::fs::read_to_string(ca.signing_pub_path()) {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "signing_key",
            &format!("cannot read the fleet signing public key: {e}"), Some("noo security pki status")),
    };
    let mut body = json!({"seat_name": seat});
    if let Some(t) = ttl {
        body["ttl_seconds"] = json!(t);
    }
    let resp = match crate::http::post_json_try(g, "/api/cluster/seat-tokens", &body, true, 15) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "mint_failed", &e, None),
    };
    let front_door = if controller.is_none() { controller_front_door() } else { None };
    let (url, url_from) = seat_token_url(controller.as_deref(), front_door.as_deref(),
        resp["controller_url"].as_str().unwrap_or_default());
    let blob = SeatBlob {
        url,
        token: resp["token"].as_str().unwrap_or_default().to_string(),
        ca: resp["ca_sha256"].as_str().unwrap_or_default().to_string(),
        seat: seat.clone(),
        sigpub,
    };
    if blob.url.is_empty() || blob.token.is_empty() || blob.ca.is_empty() {
        fail(g.json, ExitCode::Generic, "mint_failed", "the gateway's answer lacks the url, token or CA pin", None);
    }
    let enroll = format!("noo kiosk enroll {}", compose_seat_blob(&blob));
    if g.json {
        println!("{}", json!({"id": resp["id"], "seat_name": seat, "role": "seat", "expires_at": resp["expires_at"],
            "controller_url": blob.url, "controller_url_from": url_from, "enroll_command": enroll}));
        return Ok(0);
    }
    println!("{}", ui::header("kiosk seat token", Some(&seat)));
    println!("{}", ui::note(&format!("the seat reaches the controller at {} — from {url_from}", blob.url)));
    println!("{}", ui::note("on the seat, as the account that runs `noo` (not root):"));
    ui::value(&enroll);
    println!("{}", ui::note(&format!(
        "single-use; enrolls a SEAT, never a node; expires {} — if the paste leaks, revoke it: \
         POST /api/cluster/seat-tokens/{}/revoke",
        resp["expires_at"].as_str().unwrap_or("?"), resp["id"].as_str().unwrap_or("?"))));
    Ok(0)
}

/// What `/etc/default/kiosk` says about this display, when it is readable.
fn read_kiosk_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.trim().split_once('='))
        .filter(|(k, _)| k.starts_with("NOO_KIOSK_"))
        .map(|(k, v)| (k.to_string(), v.trim().trim_matches('"').to_string()))
        .collect()
}

fn kiosk_json(env: &BTreeMap<String, String>) -> Value {
    let get = |k: &str| env.get(k).cloned().unwrap_or_default();
    json!({
        "user": get("NOO_KIOSK_USER"),
        "mode": get("NOO_KIOSK_MODE"),
        "vt": get("NOO_KIOSK_VT"),
        "view": get("NOO_KIOSK_VIEW"),
        "quality": get("NOO_KIOSK_QUALITY"),
    })
}

/// The systemd units the enroll step installs. Runs AS the seat user,
/// oneshot, every minute: nothing recurring holds root.
pub(crate) fn render_sync_service(cfg: &SeatConfig) -> String {
    format!(
        "# Written by `noo kiosk enroll <blob>`. The seat's rail: a signed heartbeat,\n\
         # a signed fetch, and an apply that runs as {user}, never root, and may\n\
         # write ONLY {cli}, {applier}\n\
         # and {kdir}/noo-kiosk-{{launch,cdp,serve}}.\n\
         # It holds no fleet credential and never will.\n\
         [Unit]\n\
         Description=noomesh kiosk seat sync (CLI + kiosk assets over the rail; seat-scoped)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         User={user}\n\
         ExecStart={applier} kiosk seat-sync\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         TimeoutStartSec=15min\n",
        user = cfg.cli_user, cli = cfg.cli_path().display(), applier = cfg.applier_path().display(),
        kdir = cfg.kiosk_dir().display(),
    )
}

/// The polkit rule that lets the seat user restart exactly the kiosk units
/// (no sudo in the sync). Nothing else: not other units, not other users.
pub(crate) fn render_polkit_rule(user: &str) -> String {
    let units = SEAT_RESTARTABLE_UNITS.iter().map(|u| format!("\"{u}\"")).collect::<Vec<_>>().join(", ");
    format!(
        "// Written by noo kiosk enroll. The seat user's sync may start/stop/restart the\n\
         // kiosk units, and nothing else.\n\
         polkit.addRule(function(action, subject) {{\n\
         \x20   if (action.id == \"org.freedesktop.systemd1.manage-units\" &&\n\
         \x20       subject.user == \"{user}\" &&\n\
         \x20       [{units}].indexOf(action.lookup(\"unit\")) >= 0) {{\n\
         \x20       return polkit.Result.YES;\n\
         \x20   }}\n\
         }});\n",
    )
}

pub(crate) fn render_sync_timer() -> &'static str {
    "# Written by `noo kiosk enroll <blob>`.\n\
     [Unit]\n\
     Description=noomesh kiosk seat sync, every minute\n\
     \n\
     [Timer]\n\
     OnBootSec=45s\n\
     OnUnitActiveSec=60s\n\
     AccuracySec=5s\n\
     \n\
     [Install]\n\
     WantedBy=timers.target\n"
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Which root script [`seat_install_script`] renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeatScript {
    /// `noo kiosk enroll`: a fresh seat.
    Enroll,
    /// `seat-sync --migrate` on a pre-0.6.10 root-layout seat.
    Migrate,
    /// `seat-sync --migrate` on a seat already on the user layout: ONLY the
    /// display move (shared dir + units + self-check). Repairs a 0.6.10
    /// migration that left the display's scripts under a home directory.
    Repair,
}

/// The ONE root step of enrollment (and of migrating an old seat), as a
/// script: printed in full before it runs, so the operator sees exactly what
/// sudo is asked to do. `work` holds the files it installs; `exe` is this
/// `noo`. Everything root does here is STATIC: root-owned trust anchors and
/// config, two systemd units, the display's shared dir and its units,
/// symlinks, one polkit rule. The user-owned pieces are made by `runuser`,
/// so no directory above them is root-owned with a user-writable child.
pub(crate) fn seat_install_script(work: &Path, exe: &Path, cfg: &SeatConfig, group: &str, kind: SeatScript) -> String {
    seat_install_script_at("", work, exe, cfg, group, kind)
}

/// [`seat_install_script`] with every system path under `root` (tests run
/// it against a fake root; production passes ""). Paths the box REFERS to
/// (ExecStart=, symlink targets) are written as the real box sees them.
pub(crate) fn seat_install_script_at(root: &str, work: &Path, exe: &Path, cfg: &SeatConfig, group: &str, kind: SeatScript) -> String {
    let w = |f: &str| shq(&work.join(f).to_string_lossy());
    let (user, grp) = (shq(&cfg.cli_user), shq(group));
    let applier_dir = cfg.applier_path().parent().map(Path::to_path_buf).unwrap_or_default();
    let (applier, adir, state) = (shq(&cfg.applier_path().to_string_lossy()), shq(&applier_dir.to_string_lossy()), shq(&cfg.state_dir().to_string_lossy()));
    let mut out = format!(
        "set -eu\n\
         as_user() {{ runuser -u {user} -- \"$@\"; }}\n"
    );
    if kind != SeatScript::Repair {
        if kind == SeatScript::Migrate {
            // Stop the old root timer first so no root tick runs while the layout moves.
            out.push_str("systemctl disable --now noo-seat-sync.timer || true\nsystemctl stop noo-seat-sync.service || true\n");
        }
        out.push_str(&format!(
            "install -d -m 0755 -o root -g root {dir}\n\
             install -m 0640 -o root -g {grp} {key} {dir}/birth.key\n\
             install -m 0644 -o root -g root {crt} {dir}/birth.crt\n\
             install -m 0644 -o root -g root {ca} {dir}/ca.crt\n\
             install -m 0644 -o root -g root {sp} {dir}/signing.pub\n\
             install -m 0644 -o root -g root {cfgf} {dir}/seat.json\n\
             as_user mkdir -p {adir} {state}\n\
             as_user chmod 0700 {state}\n\
             as_user sh -c 'install -m 0755 \"$1\" \"$2.new\" && mv -f \"$2.new\" \"$2\"' sh {exe} {applier}\n\
             if [ -d {root}/etc/polkit-1/rules.d ]; then install -m 0644 -o root -g root {rule} {root}{polkit}; fi\n",
            dir = format!("{root}{SEAT_DIR}"), key = w("birth.key"), crt = w("birth.crt"), ca = w("ca.crt"), sp = w("signing.pub"), cfgf = w("seat.json"),
            exe = shq(&exe.to_string_lossy()), rule = w("49-noo-seat.rules"), polkit = POLKIT_RULE,
        ));
        if kind == SeatScript::Migrate {
            out.push_str(&format!(
                "if [ -f {root}{legacy}/state.json ]; then install -m 0600 -o {user} -g {grp} {root}{legacy}/state.json {state}/state.json; fi\n",
                legacy = LEGACY_STATE_DIR,
            ));
        }
        out.push_str(&format!(
            "install -m 0644 -o root -g root {svc} {root}{svc_dst}\n\
             install -m 0644 -o root -g root {tmr} {root}{tmr_dst}\n",
            svc = w("noo-seat-sync.service"), svc_dst = SEAT_SYNC_SERVICE,
            tmr = w("noo-seat-sync.timer"), tmr_dst = SEAT_SYNC_TIMER,
        ));
        if kind == SeatScript::Migrate {
            out.push_str(&format!(
                "rm -f {root}{LEGACY_APPLIER_BIN}\nrmdir {root}/usr/local/libexec/noo-seat 2>/dev/null || true\nrm -rf {root}{LEGACY_STATE_DIR}\n"
            ));
        }
        out.push_str("systemctl daemon-reload\nsystemctl enable --now noo-seat-sync.timer\n");
    }
    // LAST, after the seat's own timer is back: the display. Its self-check
    // can fail the script, and must never leave the seat's sync stopped.
    out.push_str(&display_dir_script(root, work, cfg, kind != SeatScript::Enroll));
    out
}

/// How long the self-check waits for the display to be running (seconds).
const DISPLAY_SELF_CHECK_SECS: u32 = 20;

/// The display half of the root step: create [`SEAT_KIOSK_DIR`]
/// (`<seat user>:<display group>`, 2750), install `noo-kiosk-{launch,cdp,
/// serve}` there from `work` (0750), point `/usr/local/bin/noo-kiosk-*` and
/// the ExecStart= of kiosk.service / kiosk-serve.service at it, restart both
/// and SELF-CHECK: both must be active for 3 consecutive seconds within
/// [`DISPLAY_SELF_CHECK_SECS`], else the script exits non-zero naming the
/// journal. The display user is whoever kiosk.service runs as (`User=`),
/// read at run time by root. Nothing at all when no kiosk.service is
/// installed (`noo kiosk setup` on a seat creates the same dir).
/// `clean_home`: remove the 0.6.10 copies under the seat user's home.
fn display_dir_script(root: &str, work: &Path, cfg: &SeatConfig, clean_home: bool) -> String {
    let homek = shq(&cfg.home_kiosk_dir().to_string_lossy());
    let clean = if clean_home {
        "  # The 0.6.10 copies under the seat user's home: unreachable for the display, now unused.\n\
         \x20 as_user rm -f @HOMEK@/noo-kiosk-launch @HOMEK@/noo-kiosk-cdp @HOMEK@/noo-kiosk-serve\n\
         \x20 as_user rmdir @HOMEK@ 2>/dev/null || true\n"
    } else {
        ""
    };
    let t = r#"# The display's scripts: a seat-owned shared dir the display user can run.
# Never under a home directory: the display user cannot traverse one.
if [ -f @R@/etc/systemd/system/kiosk.service ]; then
  kuser=$(sed -n 's/^User=//p' @R@/etc/systemd/system/kiosk.service | tail -n 1)
  kuser=${kuser:-kiosk}
  kgrp=$(id -gn "$kuser") || { echo "noo-seat: ERROR - kiosk.service runs as '$kuser', an account this box does not have" >&2; exit 1; }
  install -d -m 0755 -o root -g root @R@@OPT@
  install -d -m 2750 -o @USER@ -g "$kgrp" @R@@DIR@
  for n in launch cdp serve; do
    install -m 0750 -o @USER@ -g "$kgrp" @WORK@/noo-kiosk-$n @R@@DIR@/noo-kiosk-$n
    ln -sfn @DIR@/noo-kiosk-$n @R@@BIN@/noo-kiosk-$n
  done
  for u in kiosk:launch kiosk-serve:serve; do
    f=@R@/etc/systemd/system/${u%%:*}.service
    n=${u#*:}
    [ -f "$f" ] || continue
    sed -i "s|^ExecStart=.*/noo-kiosk-$n\$|ExecStart=@DIR@/noo-kiosk-$n|" "$f"
    grep -qx "ExecStart=@DIR@/noo-kiosk-$n" "$f" || { echo "noo-seat: ERROR - could not point $f at @DIR@/noo-kiosk-$n" >&2; exit 1; }
  done
@CLEAN@  systemctl daemon-reload
  systemctl restart kiosk-serve.service || true
  systemctl restart kiosk.service || true
  # Self-check: never report success with a dead display.
  ok=0; i=0; a=unknown; s=unknown
  while [ "$i" -lt @WAIT@ ]; do
    i=$((i + 1))
    a=$(systemctl is-active kiosk.service 2>/dev/null || true)
    s=$(systemctl is-active kiosk-serve.service 2>/dev/null || true)
    if [ "$a" = active ] && [ "$s" = active ]; then
      ok=$((ok + 1))
      if [ "$ok" -ge 3 ]; then break; fi
    else
      ok=0
    fi
    sleep 1
  done
  if [ "$ok" -lt 3 ]; then
    echo "" >&2
    echo "noo-seat: ERROR - THE DISPLAY IS NOT RUNNING: kiosk.service is '$a', kiosk-serve.service is '$s' after @WAIT@ s" >&2
    echo "noo-seat: why: journalctl -u kiosk.service -n 50 --no-pager   (and: journalctl -u kiosk-serve.service -n 50 --no-pager)" >&2
    exit 1
  fi
  echo "noo-seat: display running from @DIR@ (kiosk.service and kiosk-serve.service active)"
else
  echo "noo-seat: no kiosk.service on this box yet; kiosk setup puts the display in @DIR@"
fi
"#;
    t.replace("@CLEAN@", clean)
        .replace("@HOMEK@", &homek)
        .replace("@R@", root)
        .replace("@OPT@", SEAT_OPT_DIR)
        .replace("@DIR@", SEAT_KIOSK_DIR)
        .replace("@BIN@", KIOSK_BIN)
        .replace("@USER@", &shq(&cfg.cli_user))
        .replace("@WORK@", &shq(&work.to_string_lossy()))
        .replace("@WAIT@", &DISPLAY_SELF_CHECK_SECS.to_string())
}

/// Stage the display scripts the root step installs into the shared dir:
/// the ones THIS `noo` carries (the same bytes its seat bundle carries),
/// with the box's own `BROWSER=` line carried over from `installed_launch`.
pub(crate) fn stage_display_scripts(work: &Path, installed_launch: Option<&str>) -> Result<(), String> {
    use super::kiosk as k;
    for (n, body) in [
        ("noo-kiosk-launch", carry_browser_line(k::LAUNCH, installed_launch)),
        ("noo-kiosk-cdp", k::CDP.to_string()),
        ("noo-kiosk-serve", k::SERVE.to_string()),
    ] {
        std::fs::write(work.join(n), body).map_err(|e| format!("{n}: {e}"))?;
    }
    Ok(())
}

/// Where the display's scripts are, as the seat sees it — the heartbeat's
/// `kiosk_bins`, judged by verify:
/// - `home`: a unit or a `/usr/local/bin/noo-kiosk-*` name leads under a
///   home directory (the 0.6.10 migration): the display user cannot reach
///   it, kiosk.service dies with 203/EXEC;
/// - `shared`: the units exec from [`SEAT_KIOSK_DIR`];
/// - `root`: root-installed copies (`kiosk setup` before the seat existed):
///   they run, but seat updates never reach them;
/// - `absent`: no kiosk.service.
pub(crate) fn kiosk_bins_layout(root: &Path, home: &str) -> &'static str {
    let at = |abs: &str| root.join(abs.trim_start_matches('/'));
    let h = home.trim_end_matches('/');
    let under_home = |p: &str| {
        (!h.is_empty() && (p == h || p.starts_with(&format!("{h}/")))) || p.starts_with("/home/") || p.starts_with("/root/")
    };
    // A name and where it leads: setup and migrate only ever make one hop.
    let lead = |abs: &str| std::fs::read_link(at(abs)).map(|t| t.to_string_lossy().into_owned()).unwrap_or_else(|_| abs.to_string());
    let Ok(kiosk) = std::fs::read_to_string(at("/etc/systemd/system/kiosk.service")) else {
        return "absent";
    };
    let serve = std::fs::read_to_string(at("/etc/systemd/system/kiosk-serve.service")).unwrap_or_default();
    let exec_of = |unit: &str| -> Vec<String> {
        unit.lines().filter_map(|l| l.strip_prefix("ExecStart=")).map(|e| e.split_whitespace().next().unwrap_or("").to_string()).collect()
    };
    let (kx, sx) = (exec_of(&kiosk), exec_of(&serve));
    let mut seen: Vec<String> = Vec::new();
    for e in kx.iter().chain(sx.iter()) {
        seen.push(e.clone());
        seen.push(lead(e));
    }
    for n in ["launch", "cdp", "serve"] {
        seen.push(lead(&format!("{KIOSK_BIN}/noo-kiosk-{n}")));
    }
    if seen.iter().any(|p| under_home(p)) {
        return "home";
    }
    let shared = |n: &str| format!("{SEAT_KIOSK_DIR}/noo-kiosk-{n}");
    if kx.iter().any(|e| *e == shared("launch")) && (serve.is_empty() || sx.iter().any(|e| *e == shared("serve"))) {
        "shared"
    } else {
        "root"
    }
}

fn user_group(user: &str) -> String {
    Command::new("id").args(["-gn", user]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|g| !g.is_empty())
        .unwrap_or_else(|| user.to_string())
}

fn user_home(user: &str) -> Option<String> {
    let out = Command::new("getent").args(["passwd", user]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().split(':').nth(5).map(str::to_string).filter(|h| !h.is_empty())
}

/// `noo kiosk enroll <noo-seat1.blob> [--controller <url>] [--dry-run] [-y]`
pub fn kiosk_enroll(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut blob: Option<String> = None;
    let mut controller: Option<String> = None;
    let mut dry_run = false;
    let mut it = args.iter();
    while let Some(t) = it.next() {
        match t.as_str() {
            "--controller" => controller = Some(it.next().ok_or(Unhandled)?.trim_end_matches('/').to_string()),
            "--dry-run" => dry_run = true,
            "-y" | "--yes" => {}
            s if s.starts_with('-') => return Err(Unhandled),
            s if blob.is_none() => blob = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let usage = "noo kiosk enroll noo-seat1.<blob> [--controller <https://…>]   (the blob comes from `noo kiosk seat-token <seat>` on the controller)";
    let Some(blob) = blob else {
        fail(g.json, ExitCode::Usage, "usage", "the seat enrollment blob is required", Some(usage));
    };
    let b = match parse_seat_blob(&blob) {
        Ok(b) => b,
        Err(e) => fail(g.json, ExitCode::Usage, "seat_blob", &e, Some(usage)),
    };
    if !cfg!(target_os = "linux") {
        fail(g.json, ExitCode::Generic, "platform", "a kiosk seat is Linux-only (systemd)", None);
    }
    let me = std::env::var("USER").ok().filter(|u| !u.is_empty())
        .or_else(|| Command::new("id").arg("-un").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()))
        .unwrap_or_default();
    if me.is_empty() || me == "root" {
        fail(g.json, ExitCode::Usage, "run_as_user",
            "run `noo kiosk enroll <blob>` as the account whose `noo` this seat keeps current, not as root \
             (it asks for sudo once, for the install step)", Some(usage));
    }
    let home = user_home(&me).or_else(|| std::env::var("HOME").ok()).unwrap_or_default();
    let url = controller.clone().unwrap_or_else(|| b.url.clone());
    let cfg = SeatConfig { seat: b.seat.clone(), controller_url: url.clone(), cli_user: me.clone(), cli_home: home, kiosk_dir_at: None };
    if let Err(e) = cfg.validate() {
        fail(g.json, ExitCode::Generic, "seat_config", &e, None);
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| cfg.cli_path());

    println!("{}", ui::header("kiosk enroll", Some(&format!("seat {} → {url}", b.seat))));
    // 1. the CA, by its pin
    ui::step("fetching the cluster CA and checking it against the paste's pin");
    let ca_pem = match super::enroll::fetch_ca_pem(&url, &b.ca) {
        Ok(p) => p,
        Err(e) if controller.is_none() && !e.contains("MISMATCH") => fail(g.json, ExitCode::Generic, "ca_pin",
            &format!("{e} — if this seat reaches the controller only through its HTTPS front door, name it"),
            Some("noo kiosk enroll <blob> --controller https://<controller>.<tailnet>.ts.net")),
        Err(e) => fail(g.json, ExitCode::Generic, "ca_pin", &e, None),
    };
    // 2. the birth keypair, in a private dir that is shredded on every exit
    let work = match private_dir(&std::env::temp_dir(), "noo-seat-enroll") {
        Ok(w) => w,
        Err(e) => fail(g.json, ExitCode::Generic, "workdir", &e, None),
    };
    let cleanup = |w: &Path| {
        let k = w.join("birth.key");
        if let Ok(m) = std::fs::metadata(&k) {
            let _ = std::fs::write(&k, vec![0u8; m.len() as usize]);
        }
        let _ = std::fs::remove_dir_all(w);
    };
    ui::step("generating the seat's birth keypair (RSA-4096)");
    let ok = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:4096", "-nodes", "-days", "3650", "-subj"])
        .arg(format!("/CN=noo-seat-{}", b.seat))
        .arg("-keyout").arg(work.join("birth.key"))
        .arg("-out").arg(work.join("birth.crt"))
        .output().map(|o| o.status.success()).unwrap_or(false);
    let cert = std::fs::read_to_string(work.join("birth.crt")).unwrap_or_default();
    if !ok || cert.is_empty() {
        cleanup(&work);
        fail(g.json, ExitCode::Generic, "birth_key", "openssl could not generate the birth keypair", Some("sudo apt install openssl"));
    }
    let kiosk_env = std::fs::read_to_string(super::kiosk::ENV_FILE).ok().map(|t| read_kiosk_env(&t)).unwrap_or_default();
    let facts = json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cli_user": cfg.cli_user,
        "cli_path": cfg.cli_path(),
        "kiosk": kiosk_json(&kiosk_env),
    });
    if dry_run {
        cleanup(&work);
        println!("{}", ui::note("dry run: would redeem the token, then run this once under sudo:"));
        for l in seat_install_script(Path::new("<workdir>"), &exe, &cfg, &user_group(&me), SeatScript::Enroll).lines() {
            println!("  {l}");
        }
        return Ok(0);
    }
    // 3. redeem
    ui::step("redeeming the seat token");
    let agent = match seat_agent(&ca_pem, 30) {
        Ok(a) => a,
        Err(e) => { cleanup(&work); fail(g.json, ExitCode::Generic, "ca_agent", &e, None) }
    };
    let body = json!({"token": b.token, "seat_name": b.seat, "birth_cert": cert, "facts": facts, "enroll_user": me});
    let resp = agent.post(&format!("{url}/api/cluster/seat-enroll")).send_json(&body);
    match resp {
        Ok(mut r) if r.status().as_u16() == 200 => {
            let _ = r.body_mut().read_to_string();
        }
        Ok(mut r) => {
            let st = r.status().as_u16();
            let text = r.body_mut().read_to_string().unwrap_or_default();
            cleanup(&work);
            fail(g.json, ExitCode::Generic, "seat_enroll", &format!("the controller refused the seat token (HTTP {st}): {}",
                crate::http::detail_of(st, &text)), Some("mint a fresh one on the controller: noo kiosk seat-token <seat>"));
        }
        Err(e) => {
            cleanup(&work);
            fail(g.json, ExitCode::Generic, "seat_enroll", &format!("could not reach {url}: {e}"), None);
        }
    }
    ui::done(&format!("enrolled as seat {} (no node credential was issued, and none can be)", b.seat));
    // 4. the one root step
    let writes = [
        ("ca.crt", ca_pem.clone()),
        ("signing.pub", b.sigpub.clone().into_bytes()),
        ("seat.json", serde_json::to_vec_pretty(&cfg).unwrap_or_default()),
        ("noo-seat-sync.service", render_sync_service(&cfg).into_bytes()),
        ("noo-seat-sync.timer", render_sync_timer().as_bytes().to_vec()),
        ("49-noo-seat.rules", render_polkit_rule(&cfg.cli_user).into_bytes()),
    ];
    for (f, bytes) in writes {
        if let Err(e) = std::fs::write(work.join(f), bytes) {
            cleanup(&work);
            fail(g.json, ExitCode::Generic, "workdir", &format!("{f}: {e}"), None);
        }
    }
    // The display's scripts for the shared dir (installed there only when a
    // kiosk.service exists; `noo kiosk setup` on a seat does the same later).
    let installed_launch = std::fs::read_to_string(format!("{KIOSK_BIN}/noo-kiosk-launch")).ok();
    if let Err(e) = stage_display_scripts(&work, installed_launch.as_deref()) {
        cleanup(&work);
        fail(g.json, ExitCode::Generic, "workdir", &e, None);
    }
    let script = seat_install_script(&work, &exe, &cfg, &user_group(&me), SeatScript::Enroll);
    println!();
    println!("{}", ui::warn("one sudo, now, to install the seat's rail (nothing after this needs sudo):"));
    for l in script.lines() {
        println!("  {}", ui::muted(l));
    }
    let script_path = work.join("install.sh");
    let _ = std::fs::write(&script_path, &script);
    let st = Command::new("sudo").arg("sh").arg(&script_path).status();
    cleanup(&work);
    if !st.map(|s| s.success()).unwrap_or(false) {
        fail(g.json, ExitCode::Generic, "install",
            "the install step did not complete; the seat is enrolled at the controller but its timer is not installed",
            Some("re-run `noo kiosk enroll <blob>` with a fresh token (`noo kiosk seat-token <seat>` on the controller)"));
    }
    if exe != cfg.cli_path() {
        ui::warned(&format!(
            "this `noo` runs from {}, but the seat keeps {} current — put that first on PATH (install.sh's default)",
            exe.display(), cfg.cli_path().display()));
    }
    ui::done("seat rail installed: noo-seat-sync.timer runs every minute");
    ui::guide(&[
        ("noo upgrade --seats", "on the controller: stage this seat's bundle now (`--nodes`/`--all` include seats)"),
        ("journalctl -u noo-seat-sync -n 30", "here: what the seat's last sync did"),
    ]);
    Ok(0)
}

// ═══ the seat's timer: `noo kiosk seat-sync` (root) ═══════════════════

/// `<ts>.<base64 sig>` over `noo-seat-<tag>:<seat>:<sha>:<ts>` with the birth
/// key — the gateway's `birth_proof::signed_message` for the seat purposes.
pub(crate) fn seat_proof_message(tag: &str, seat: &str, sha: &str, ts: i64) -> String {
    format!("noo-seat-{tag}:{seat}:{sha}:{ts}")
}

fn sign_proof(key: &Path, tag: &str, seat: &str, sha: &str) -> Result<String, String> {
    let ts = now_unix();
    let work = private_dir(&std::env::temp_dir(), "noo-seat-proof")?;
    let msg = work.join("msg");
    let sig = work.join("sig");
    let r = (|| {
        std::fs::write(&msg, seat_proof_message(tag, seat, sha, ts)).map_err(|e| e.to_string())?;
        let out = Command::new("openssl").args(["dgst", "-sha256", "-sign"]).arg(key)
            .arg("-out").arg(&sig).arg(&msg).output().map_err(|e| format!("openssl: {e}"))?;
        if !out.status.success() {
            return Err(format!("openssl could not sign with {}: {}", key.display(), String::from_utf8_lossy(&out.stderr).trim()));
        }
        let bytes = std::fs::read(&sig).map_err(|e| e.to_string())?;
        use base64::Engine as _;
        Ok(format!("{ts}.{}", base64::engine::general_purpose::STANDARD.encode(bytes)))
    })();
    let _ = std::fs::remove_dir_all(&work);
    r
}

/// stdout of `cmd` REGARDLESS of exit status (`systemctl is-active` prints
/// `inactive` and exits non-zero; the word is the answer), with a fixed PATH.
/// None only when the command could not be run at all. The opposite rule
/// from the clean-run-only helper in kiosk.rs, on purpose: see
/// `host_exec::Outcome`.
fn sh_out(cmd: &mut Command) -> Option<String> {
    crate::host_exec::run_cmd(cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))
        .any_stdout()
        .map(str::to_string)
}

fn unit_state(unit: &str) -> String {
    sh_out(Command::new("systemctl").args(["is-active", unit])).filter(|s| !s.is_empty()).unwrap_or_else(|| "unknown".into())
}

fn unit_exists(unit: &str) -> bool {
    Command::new("systemctl").args(["cat", unit]).output().map(|o| o.status.success()).unwrap_or(false)
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SeatState {
    last_applied_sha: Option<String>,
    console_build: Option<String>,
    display: Option<String>,
}

/// Where applier state lives for a layout: the pre-0.6.10 root applier kept
/// it in `LEGACY_STATE_DIR`, the user layout under the seat user's home.
fn state_dir_for(cfg: &SeatConfig, layout: &str) -> PathBuf {
    if layout == "legacy-root" { PathBuf::from(LEGACY_STATE_DIR) } else { cfg.state_dir() }
}

fn read_state(cfg: &SeatConfig) -> SeatState {
    std::fs::read(state_dir_for(cfg, layout_word()).join("state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn write_state(cfg: &SeatConfig, s: &SeatState) {
    use std::os::unix::fs::DirBuilderExt as _;
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(cfg.state_dir());
    let _ = std::fs::write(cfg.state_dir().join("state.json"), serde_json::to_vec_pretty(s).unwrap_or_default());
}

/// `"user"` once the sync runs as the seat user; `"legacy-root"` while the
/// old root timer is still in charge (needs the one-time migration).
fn layout_word() -> &'static str {
    if unsafe { libc::geteuid() } == 0 { "legacy-root" } else { "user" }
}

/// The heartbeat body. What `noo upgrade` and `noo cluster verify` judge.
fn heartbeat_body(cfg: &SeatConfig, state: &SeatState) -> Value {
    heartbeat_body_for(cfg, state, layout_word())
}

fn heartbeat_body_for(cfg: &SeatConfig, state: &SeatState, layout: &str) -> Value {
    let applier_sha = std::fs::read(cfg.applier_path()).or_else(|_| std::fs::read(LEGACY_APPLIER_BIN)).ok().map(|b| sha256_hex(&b));
    let user_sha = std::fs::read(cfg.cli_path()).ok().map(|b| sha256_hex(&b));
    let console = sh_out(Command::new(format!("{KIOSK_BIN}/noo-kiosk-cdp")).arg("build"))
        .filter(|b| !b.is_empty() && b != "null");
    let kiosk_env = std::fs::read_to_string(super::kiosk::ENV_FILE).ok().map(|t| read_kiosk_env(&t)).unwrap_or_default();
    json!({
        "cli_version": env!("CARGO_PKG_VERSION"),
        "layout": layout,
        "user_cli_current": applier_sha.is_some() && applier_sha == user_sha,
        "kiosk_serve": unit_state("kiosk-serve.service"),
        "kiosk_display": unit_state("kiosk.service"),
        "kiosk_bins": kiosk_bins_layout(Path::new("/"), &cfg.cli_home),
        "console_build": console,
        "kiosk": kiosk_json(&kiosk_env),
        "last_applied_sha": state.last_applied_sha,
        "display": state.display,
        "ts": now_unix(),
    })
}

/// Atomic write as the current user (the sync runs as the seat user): temp
/// file in the same directory (same owner, same filesystem), fsync, mode,
/// rename. Never unlinks the target first, so on any failure the old file
/// stays; a running binary is replaced, not overwritten.
pub(crate) fn install_atomic(dst: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let dir = dst.parent().ok_or("no parent")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o755).create(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.noo-seat-{}", dst.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let r = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.write_all(bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, dst).map_err(|e| format!("rename onto {}: {e}", dst.display()))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Write one planned file (production wiring of [`apply_plan`]). The
/// display's scripts are 0750 in the shared dir (the setgid dir gives them
/// the display group); the seat never creates that dir — root does.
fn install_file(dst: &Path, bytes: &[u8], cfg: &SeatConfig) -> Result<(), String> {
    if !seat_path_allowed(dst, cfg) {
        return Err(format!("REFUSED — {} is outside the seat applier's allow-list", dst.display()));
    }
    if dst.starts_with(cfg.kiosk_dir()) {
        if !cfg.kiosk_dir().is_dir() {
            return Err(format!("{} does not exist (root creates it: sudo {} kiosk seat-sync --migrate)",
                cfg.kiosk_dir().display(), cfg.applier_path().display()));
        }
        return install_atomic(dst, bytes, 0o750);
    }
    install_atomic(dst, bytes, 0o755)
}

/// The kiosk scripts wait for the shared dir: until root has created it
/// (an enroll before `kiosk setup`, or a 0.6.10 seat not yet repaired) they
/// are left out of the plan instead of failing the CLI's update with them.
/// Returns the plan to apply and whether anything was deferred.
pub(crate) fn defer_kiosk_until_shared_dir(plan: Vec<(String, PathBuf)>, shared_dir_exists: bool) -> (Vec<(String, PathBuf)>, bool) {
    if shared_dir_exists {
        return (plan, false);
    }
    let before = plan.len();
    let kept: Vec<(String, PathBuf)> = plan.into_iter().filter(|(k, _)| !k.starts_with("kiosk-")).collect();
    let deferred = kept.len() != before;
    (kept, deferred)
}

/// An injected file writer: `(destination, bytes)`.
pub(crate) type Writer<'a> = &'a dyn Fn(&Path, &[u8]) -> Result<(), String>;

/// Apply a verified plan. The seat's own copy and the kiosk scripts first,
/// the user's CLI LAST: it is written only after the seat copy it mirrors.
/// `allowed` is the second allow-list guard; the writer is injected so tests
/// can run on a temp tree.
/// Returns the kinds that changed; an error names what already changed.
pub(crate) fn apply_plan(
    plan: &[(String, PathBuf)],
    cli_path: &Path,
    read_bytes: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    allowed: &dyn Fn(&Path) -> bool,
    install: Writer,
) -> Result<Vec<String>, String> {
    let mut ordered: Vec<&(String, PathBuf)> = plan.iter().filter(|(_, d)| d != cli_path).collect();
    ordered.extend(plan.iter().filter(|(_, d)| d == cli_path));
    let mut changed: Vec<String> = Vec::new();
    for (kind, dst) in ordered {
        if !allowed(dst) {
            return Err(format!("REFUSED — {} is outside the seat applier's allow-list", dst.display()));
        }
        let mut bytes = read_bytes(kind)?;
        if kind == "kiosk-launch" {
            let installed = std::fs::read_to_string(dst).ok();
            bytes = carry_browser_line(&String::from_utf8_lossy(&bytes), installed.as_deref()).into_bytes();
        }
        if std::fs::read(dst).ok().as_deref() == Some(&bytes[..]) {
            continue;
        }
        install(dst, &bytes).map_err(|e| format!("{e} (already changed: {})", changed.join(",")))?;
        if !changed.contains(kind) {
            changed.push(kind.clone());
        }
    }
    Ok(changed)
}

/// Recovery: the user's CLI is missing (a 0.6.7 seat deleted it) but the
/// seat copy exists — restore it from that copy, atomically.
/// Returns whether it restored. Never removes anything.
pub(crate) fn restore_user_cli(
    cli_path: &Path,
    seat_copy: &Path,
    install: Writer,
) -> Result<bool, String> {
    // `exists()` follows links, so a dangling link at the path counts as missing.
    if cli_path.exists() {
        return Ok(false);
    }
    let bytes = match std::fs::read(seat_copy) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(false),
    };
    install(cli_path, &bytes).map_err(|e| format!("restoring {}: {e}", cli_path.display()))?;
    Ok(true)
}

/// What changed, and what the applier did about it — the apply report's
/// words, parsed back by the controller's verify block.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ApplyOutcome {
    pub cli: &'static str,
    pub scripts: usize,
    pub units: usize,
    pub serve: &'static str,
    pub display: &'static str,
    pub console: String,
    /// The kiosk scripts were not applied: the shared dir does not exist yet.
    pub kiosk_deferred: bool,
}

impl ApplyOutcome {
    pub(crate) fn line(&self) -> String {
        format!(
            "seat-apply cli={} scripts={} units={} serve={} display={} console={}",
            self.cli, self.scripts, self.units, self.serve, self.display,
            if self.console.is_empty() { "-" } else { &self.console }
        ) + if self.kiosk_deferred { " kiosk=deferred-no-shared-dir" } else { "" }
    }
}

/// The display action an apply calls for: restart the session when its
/// launcher, CDP helper or unit changed; else reload the page when the
/// console build moved; else nothing.
pub(crate) fn display_action(changed: &[String], console_moved: bool) -> &'static str {
    if changed.iter().any(|k| matches!(k.as_str(), "kiosk-launch" | "kiosk-cdp" | "unit-kiosk")) {
        "restart"
    } else if console_moved {
        "reload"
    } else {
        "unchanged"
    }
}

/// Decrypt, unwrap, extract, verify and apply one blob. Returns the outcome.
fn apply_blob(blob: &[u8], cfg: &SeatConfig, state: &mut SeatState) -> Result<ApplyOutcome, String> {
    let stage = {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(cfg.state_dir()).map_err(|e| format!("state dir: {e}"))?;
        private_dir(&cfg.state_dir(), "stage")?
    };
    let r = (|| {
        let enc = stage.join("bundle.der");
        std::fs::write(&enc, blob).map_err(|e| e.to_string())?;
        let tarp = stage.join("bundle.tar");
        let out = Command::new("openssl")
            .args(["smime", "-decrypt", "-binary", "-inform", "DER", "-inkey"])
            .arg(Path::new(SEAT_DIR).join("birth.key"))
            .arg("-in").arg(&enc).arg("-out").arg(&tarp)
            .output().map_err(|e| format!("openssl: {e}"))?;
        if !out.status.success() {
            return Err(format!("decrypt failed — is this bundle for this seat's birth key? re-enroll if the key changed: {}",
                String::from_utf8_lossy(&out.stderr).trim()));
        }
        let mut tar = std::fs::read(&tarp).map_err(|e| e.to_string())?;
        if tar.starts_with(&[0x1f, 0x8b]) {
            use std::io::Read as _;
            let mut d = Vec::new();
            flate2::read::GzDecoder::new(&tar[..]).read_to_end(&mut d).map_err(|e| format!("gunzip: {e}"))?;
            tar = d;
        }
        let ex = stage.join("x");
        std::fs::create_dir(&ex).map_err(|e| e.to_string())?;
        super::node_fetch::extract_bundle(&tar, &ex)?;
        let plan = verify_seat_stage(&ex, &Path::new(SEAT_DIR).join("signing.pub"), cfg, now_unix())?;
        let (plan, kiosk_deferred) = defer_kiosk_until_shared_dir(plan, cfg.kiosk_dir().is_dir());
        // Apply. Everything verified; any write failure stops here and is
        // reported, with what was already written named in the message.
        let cli_path = cfg.cli_path();
        let mut changed = apply_plan(
            &plan, &cli_path,
            &|kind| std::fs::read(ex.join("files").join(kind)).map_err(|e| e.to_string()),
            &|p| seat_path_allowed(p, cfg),
            &|d, b| install_file(d, b, cfg),
        )?;
        // A seat whose CLI was removed by the old applier: put it back from
        // the seat copy that was just applied (or was already current).
        if restore_user_cli(&cli_path, &cfg.applier_path(), &|d, b| install_file(d, b, cfg))?
            && !changed.iter().any(|k| k == "cli-binary")
        {
            changed.push("cli-binary".into());
        }
        let meta: Value = std::fs::read(ex.join("files/seat-meta")).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        let console = meta["console_build"].as_str().unwrap_or("").to_string();
        let console_moved = !console.is_empty() && state.console_build.as_deref() != Some(console.as_str());
        // Units are root-installed and static: the seat never writes one, so
        // there is never a daemon-reload to do.
        let units_changed = 0usize;
        let mut o = ApplyOutcome {
            cli: if changed.iter().any(|k| k == "cli-binary") { "updated" } else { "unchanged" },
            scripts: changed.iter().filter(|k| k.starts_with("kiosk-")).count(),
            units: units_changed,
            serve: "unchanged",
            display: "unchanged",
            console: console.clone(),
            kiosk_deferred,
        };
        if changed.iter().any(|k| k == "kiosk-serve" || k == "unit-kiosk-serve") && unit_exists("kiosk-serve.service") {
            o.serve = if Command::new("systemctl").args(["restart", "kiosk-serve.service"]).status().map(|s| s.success()).unwrap_or(false) {
                "restarted"
            } else {
                "restart-failed"
            };
        }
        if changed.iter().any(|k| k == "unit-kiosk-watchdog-timer") && unit_exists("kiosk-watchdog.timer") {
            let _ = Command::new("systemctl").args(["restart", "kiosk-watchdog.timer"]).status();
        }
        o.display = match display_action(&changed, console_moved) {
            "restart" if unit_exists("kiosk.service") => {
                if Command::new("systemctl").args(["restart", "kiosk.service"]).status().map(|s| s.success()).unwrap_or(false) { "restarted" } else { "restart-failed" }
            }
            "reload" => {
                if Command::new(format!("{KIOSK_BIN}/noo-kiosk-cdp")).arg("reload").status().map(|s| s.success()).unwrap_or(false) { "reloaded" } else { "reload-failed" }
            }
            _ => "unchanged",
        };
        if !console.is_empty() {
            state.console_build = Some(console);
        }
        state.display = Some(o.display.to_string());
        Ok(o)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    r
}

/// `noo kiosk seat-sync` — the seat timer's one tick (root; hidden).
pub fn kiosk_seat_sync(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let migrate = match args {
        [] => None,
        [a] if a == "--migrate" => Some(false),
        [a, b] if a == "--migrate" && b == "--print" => Some(true),
        _ => return Err(Unhandled),
    };
    let say = |m: &str| eprintln!("noo-seat-sync: {m}");
    let cfg: SeatConfig = match std::fs::read(Path::new(SEAT_DIR).join("seat.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(c) => c,
        None => { say("no /etc/noo-seat/seat.json — this box is not an enrolled seat (`noo kiosk enroll <blob>`)"); return Ok(78); }
    };
    if let Err(e) = cfg.validate() {
        say(&e);
        return Ok(78);
    }
    if let Some(print_only) = migrate {
        return Ok(seat_migrate(&cfg, print_only));
    }
    let key = Path::new(SEAT_DIR).join("birth.key");
    let ca = match std::fs::read(Path::new(SEAT_DIR).join("ca.crt")) {
        Ok(c) => c,
        Err(e) => { say(&format!("no CA anchor: {e}")); return Ok(78); }
    };
    let agent = match seat_agent(&ca, 900) {
        Ok(a) => a,
        Err(e) => { say(&e); return Ok(1); }
    };
    let base = cfg.controller_url.trim_end_matches('/').to_string();
    let seat = cfg.seat.clone();
    let mut state = read_state(&cfg);
    let post_signed = |path: &str, tag: &str, sha: &str, body: Vec<u8>| -> Result<u16, String> {
        let proof = sign_proof(&key, tag, &seat, sha)?;
        let r = agent.post(&format!("{base}{path}"))
            .header("content-type", "application/json")
            .header("x-noo-birth-proof", &proof)
            .send(&body[..]);
        match r {
            Ok(r) => Ok(r.status().as_u16()),
            Err(e) => Err(e.to_string()),
        }
    };
    let heartbeat = |state: &SeatState| {
        let body = heartbeat_body(&cfg, state).to_string().into_bytes();
        let sha = sha256_hex(&body);
        match post_signed(&format!("/bootstrap/seat/{seat}/heartbeat"), "heartbeat", &sha, body) {
            Ok(200) => {}
            Ok(st) => say(&format!("heartbeat answered HTTP {st}")),
            Err(e) => say(&format!("heartbeat: {e}")),
        }
    };
    // An old seat's root timer runs the new binary here after a rail update:
    // it only reports (a heartbeat carrying layout=legacy-root and the running
    // version, sent HERE: this branch returns before the one below) and
    // tells the operator the ONE migration command. It never applies as root.
    if layout_word() == "legacy-root" {
        heartbeat(&state);
        say(&format!(
            "this seat still runs the pre-0.6.10 root layout; migrate it once, on this box: \
             sudo {LEGACY_APPLIER_BIN} kiosk seat-sync --migrate"));
        return Ok(0);
    }
    // Recovery first: a missing user CLI is restored from the seat copy even
    // when no new bundle is waiting.
    match restore_user_cli(&cfg.cli_path(), &cfg.applier_path(), &|d, b| install_file(d, b, &cfg)) {
        Ok(true) => say(&format!("restored {} from {}", cfg.cli_path().display(), cfg.applier_path().display())),
        Ok(false) => {}
        Err(e) => say(&e),
    }
    heartbeat(&state);
    // Fetch (signed GET).
    let proof = match sign_proof(&key, "get", &seat, "-") {
        Ok(p) => p,
        Err(e) => { say(&e); return Ok(1); }
    };
    let blob = match agent.get(&format!("{base}/bootstrap/seat/{seat}/bundle")).header("x-noo-birth-proof", &proof).call() {
        Ok(mut r) if r.status().as_u16() == 200 => {
            use std::io::Read as _;
            let mut b = Vec::new();
            if let Err(e) = r.body_mut().as_reader().read_to_end(&mut b) {
                say(&format!("reading the bundle: {e}"));
                return Ok(1);
            }
            b
        }
        Ok(r) if r.status().as_u16() == 404 => return Ok(0),
        Ok(r) => { say(&format!("bundle fetch answered HTTP {}", r.status().as_u16())); return Ok(1); }
        Err(e) => { say(&format!("bundle fetch: {e}")); return Ok(1); }
    };
    let sha = sha256_hex(&blob);
    if state.last_applied_sha.as_deref() == Some(sha.as_str()) {
        return Ok(0);
    }
    let _ = post_signed(&format!("/bootstrap/seat/{seat}/fetched"), "fetch", &sha, json!({"sha": sha}).to_string().into_bytes());
    let (rc, msg) = match apply_blob(&blob, &cfg, &mut state) {
        Ok(o) => (0, o.line()),
        Err(e) => (65, if e.starts_with("apply failed") { e } else { format!("apply failed: {e}") }),
    };
    say(&format!("apply rc={rc}: {msg}"));
    match post_signed(&format!("/bootstrap/seat/{seat}/applied"), "apply", &sha,
        json!({"sha": sha, "rc": rc, "msg": msg}).to_string().into_bytes()) {
        Ok(200) => {
            // Recorded only once the controller has the report: a lost report
            // means the next tick applies (idempotently) and reports again.
            // A FAILED apply is not recorded: the next tick retries it (the
            // root side is already current, so only what failed re-runs).
            if rc == 0 {
                state.last_applied_sha = Some(sha);
                write_state(&cfg, &state);
            }
        }
        Ok(st) => say(&format!("apply report answered HTTP {st}")),
        Err(e) => say(&format!("apply report: {e}")),
    }
    heartbeat(&state);
    Ok(if rc == 0 { 0 } else { 1 })
}

/// `noo kiosk seat-sync --migrate [--print]` — move an already-enrolled seat
/// from the root layout (root timer, root copy under /usr/local/libexec) to
/// the user layout. ONE explicit command, run by the operator under sudo on
/// the box. Root, offline: no network, no bundle.
///
/// Idempotent and REPAIRING: on a seat already on the user layout (no root
/// copy left, the sync unit runs as the seat user) it does ONLY the display
/// move — the shared dir, the units, the self-check. That is the repair for
/// a 0.6.10 migration, which left the display's scripts under the seat
/// user's home where the display user cannot reach them (203/EXEC).
///
/// Why a command and not an automatic last root tick: that tick would be a
/// root process, fed by the network, rewriting its own unit, the polkit
/// policy and `/usr/local/bin` symlinks on its own authority. The command
/// prints exactly what it runs, is run by a person who typed `sudo`, and
/// until it runs the old layout keeps working (the root timer keeps
/// reporting; nothing is applied as root by the new binary).
fn seat_migrate(cfg: &SeatConfig, print_only: bool) -> i32 {
    let say = |m: &str| eprintln!("noo-seat-sync: {m}");
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(LEGACY_APPLIER_BIN));
    let group = user_group(&cfg.cli_user);
    let kind = migrate_kind(
        Path::new(LEGACY_APPLIER_BIN).exists(),
        std::fs::read_to_string(SEAT_SYNC_SERVICE).ok().as_deref(),
        &cfg.cli_user,
    );
    let work = Path::new("<workdir>");
    if print_only {
        for l in seat_install_script(work, &exe, cfg, &group, kind).lines() {
            println!("{l}");
        }
        return 0;
    }
    if unsafe { libc::geteuid() } != 0 {
        say(&format!("run it as root: sudo {} kiosk seat-sync --migrate   (--print shows the script)", exe.display()));
        return 1;
    }
    let work = match private_dir(&std::env::temp_dir(), "noo-seat-migrate") {
        Ok(w) => w,
        Err(e) => { say(&e); return 1; }
    };
    let mut ok = true;
    if kind == SeatScript::Migrate {
        let files: [(&str, Vec<u8>); 7] = [
            ("birth.key", std::fs::read(Path::new(SEAT_DIR).join("birth.key")).unwrap_or_default()),
            ("birth.crt", std::fs::read(Path::new(SEAT_DIR).join("birth.crt")).unwrap_or_default()),
            ("ca.crt", std::fs::read(Path::new(SEAT_DIR).join("ca.crt")).unwrap_or_default()),
            ("signing.pub", std::fs::read(Path::new(SEAT_DIR).join("signing.pub")).unwrap_or_default()),
            ("seat.json", serde_json::to_vec_pretty(cfg).unwrap_or_default()),
            ("noo-seat-sync.service", render_sync_service(cfg).into_bytes()),
            ("noo-seat-sync.timer", render_sync_timer().as_bytes().to_vec()),
        ];
        ok &= files.iter().take(5).all(|(_, b)| !b.is_empty());
        for (f, b) in files.iter() {
            ok &= std::fs::write(work.join(f), b).is_ok();
        }
        ok &= std::fs::write(work.join("49-noo-seat.rules"), render_polkit_rule(&cfg.cli_user)).is_ok();
    }
    // Root reads the box's current launcher only for its BROWSER= line.
    let installed_launch = std::fs::read_to_string(format!("{KIOSK_BIN}/noo-kiosk-launch")).ok();
    if let Err(e) = stage_display_scripts(&work, installed_launch.as_deref()) {
        say(&e);
        ok = false;
    }
    let rc = if ok {
        let script = seat_install_script(&work, &exe, cfg, &group, kind);
        println!("{script}");
        let sp = work.join("migrate.sh");
        let _ = std::fs::write(&sp, &script);
        let st = Command::new("sh").arg(&sp).status();
        if st.map(|s| s.success()).unwrap_or(false) {
            0
        } else {
            say("the migration script did NOT complete; read its ERROR line above (journalctl -u kiosk.service -n 50 when the display is down)");
            1
        }
    } else {
        say("the seat's /etc/noo-seat files could not be read; re-enroll instead (noo kiosk enroll <blob>)");
        1
    };
    let _ = std::fs::remove_dir_all(&work);
    if rc == 0 {
        match kind {
            SeatScript::Repair => println!("seat repaired: the display runs from {SEAT_KIOSK_DIR}; seat updates land there"),
            _ => println!("seat migrated: noo-seat-sync now runs as {}; nothing recurring holds root; the display runs from {SEAT_KIOSK_DIR}", cfg.cli_user),
        }
    }
    rc
}

/// Full migration, or only the display repair? Repair when the root copy
/// is gone AND the installed sync unit already runs as the seat user.
pub(crate) fn migrate_kind(legacy_applier_present: bool, sync_unit: Option<&str>, user: &str) -> SeatScript {
    let user_unit = sync_unit.is_some_and(|t| t.lines().any(|l| l.trim() == format!("User={user}")));
    if !legacy_applier_present && user_unit { SeatScript::Repair } else { SeatScript::Migrate }
}

// ═══ the controller's view: upgrade + verify ══════════════════════════

/// Every enrolled seat, or `None` when the gateway does not answer (an older
/// gateway has no seat routes: that is "no seats", said once by the caller).
pub(crate) fn list_seats(g: &Globals) -> Option<Vec<Value>> {
    crate::http::get_json_opt(g, "/api/cluster/seats", true, 15)
        .and_then(|d| d["seats"].as_array().cloned())
}

fn check(name: &'static str, verdict: super::cluster_verify::Verdict, detail: String, remedy: Option<String>) -> super::cluster_verify::Check {
    super::cluster_verify::Check { name, verdict, detail, remedy }
}

fn norm_tag(t: &str) -> String {
    let t = t.trim().split('+').next().unwrap_or("").trim_start_matches("stack-");
    if t.is_empty() || t.starts_with('v') { t.to_string() } else { format!("v{t}") }
}

/// The token after `key=` in a `seat-apply …` report line.
pub(crate) fn report_word<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    msg.split_whitespace().find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

/// One seat, judged: online, CLI current, kiosk-serve active, display on the
/// controller's console build, last apply ok. Pure over the record (the
/// `/api/cluster/seats` row or the `/status` answer), so every verdict is
/// pinned by a test. Shared by `noo upgrade` and `noo cluster verify`.
fn hb_layout(seat: &Value) -> Option<&str> {
    seat["heartbeat"]["layout"].as_str()
}

/// The seat's own copy of `noo`, as a command the operator can paste on the
/// seat: `~<user>/.local/libexec/noo-seat/noo` (the 0.6.10 root copy is gone
/// once a seat is on the user layout). The user name comes from the seat
/// row, so only a plain account name is used; anything else is a placeholder.
pub(crate) fn seat_applier_for_remedy(seat: &Value) -> String {
    let user = seat["enroll_user"].as_str().or_else(|| seat["facts"]["cli_user"].as_str()).unwrap_or("");
    let plain = !user.is_empty() && user.len() <= 32 && user != "root"
        && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    format!("~{}/.local/libexec/noo-seat/noo", if plain { user } else { "<seat user>" })
}

pub(crate) fn seat_checks(seat: &Value, controller_cli: &str, controller_tag: &str, now: i64) -> Vec<super::cluster_verify::Check> {
    use super::cluster_verify::Verdict;
    let name = seat["seat_name"].as_str().or_else(|| seat["seat"].as_str()).unwrap_or("?");
    let hb = &seat["heartbeat"];
    let mut out = Vec::new();
    let seen = seat["last_seen"].as_str().and_then(super::cluster_verify::parse_rfc3339_unix);
    out.push(match seen {
        Some(t) if now - t <= SEAT_HEARTBEAT_MAX_AGE_SECS => check("seat online", Verdict::Ok, format!("heard {}s ago", now - t), None),
        Some(t) => check("seat online", Verdict::Fail, format!("last heard {}s ago — the seat's sync timer is not reaching the controller", now - t),
            Some(format!("on {name}: systemctl status noo-seat-sync.timer"))),
        None => check("seat online", Verdict::Fail, "never heard from since it enrolled".into(),
            Some(format!("on {name}: journalctl -u noo-seat-sync -n 30"))),
    });
    let cli = hb["cli_version"].as_str().unwrap_or("");
    let user_current = hb["user_cli_current"].as_bool().unwrap_or(false);
    out.push(if cli.is_empty() {
        check("seat cli", Verdict::Fail, "no CLI version reported".into(), Some("noo upgrade --seats".into()))
    } else if cli != controller_cli {
        check("seat cli", Verdict::Fail, format!("{cli}, controller {controller_cli}"), Some("noo upgrade --seats".into()))
    } else if !user_current {
        check("seat cli", Verdict::Warn, format!("{cli} (the seat's applier); the user's ~/.local/bin/noo differs"),
            Some("noo upgrade --seats".into()))
    } else {
        check("seat cli", Verdict::Ok, format!("{cli} = controller"), None)
    });
    let serve = hb["kiosk_serve"].as_str().unwrap_or("unknown");
    out.push(match serve {
        "active" => check("kiosk-serve", Verdict::Ok, "active".into(), None),
        "inactive" | "unknown" if hb["kiosk"]["user"].as_str().unwrap_or("").is_empty() =>
            check("kiosk-serve", Verdict::Warn, "no kiosk set up on this seat".into(),
                Some(format!("on {name}: noo kiosk setup --mode dedicated --url https://<controller>.<tailnet>.ts.net"))),
        other => check("kiosk-serve", Verdict::Fail, other.to_string(), Some(format!("on {name}: journalctl -u kiosk-serve -n 50"))),
    });
    let build = hb["console_build"].as_str().unwrap_or("");
    let display = report_word(seat["apply_msg"].as_str().unwrap_or(""), "display").unwrap_or("");
    let quality = hb["kiosk"]["quality"].as_str().filter(|q| !q.is_empty()).map(|q| format!(", quality {q}")).unwrap_or_default();
    out.push(if build.is_empty() {
        check("display", Verdict::Warn, format!("console build not stated (the browser is not answering on CDP){quality}"),
            Some(format!("on {name}: noo kiosk status")))
    } else if norm_tag(build) != norm_tag(controller_tag) {
        check("display", Verdict::Fail, format!("console {build}, controller {controller_tag}{quality}"),
            Some(format!("on {name}: noo kiosk reload")))
    } else {
        check("display", Verdict::Ok, format!("console {build} = controller{}{quality}",
            if display.is_empty() { String::new() } else { format!(" (last apply: display {display})") }), None)
    });
    if hb_layout(seat) == Some("legacy-root") {
        out.push(check("seat layout", Verdict::Warn, "still on the root layout (root timer, root-owned copy): no updates apply until migrated".into(),
            Some(format!("on {name}: sudo {LEGACY_APPLIER_BIN} kiosk seat-sync --migrate"))));
    }
    // Where the display execs its scripts from (a 0.6.11+ seat reports it).
    let repair = || Some(format!("on {name}: sudo {} kiosk seat-sync --migrate", seat_applier_for_remedy(seat)));
    match hb["kiosk_bins"].as_str() {
        Some("home") => {
            let display = hb["kiosk_display"].as_str().unwrap_or("unknown");
            out.push(check("display binaries",
                if display == "active" { Verdict::Warn } else { Verdict::Fail },
                format!("display binaries under a home directory the display user cannot reach (kiosk.service {display}); \
                         they belong in {SEAT_KIOSK_DIR}"),
                repair()));
        }
        Some("root") if hb_layout(seat) == Some("user") => out.push(check("display binaries", Verdict::Warn,
            "the display runs root-installed copies in /usr/local/bin: seat updates never reach it".into(), repair())),
        _ => {}
    }
    let staged = seat["staged_sha"].as_str().or_else(|| seat["sha256"].as_str());
    if let Some(staged) = staged {
        let applied = seat["applied_sha"].as_str();
        let rc = seat["apply_rc"].as_i64();
        out.push(match (applied == Some(staged), rc) {
            (true, Some(0)) => check("seat bundle", Verdict::Ok, "the staged bundle applied (exit 0)".into(), None),
            (true, Some(_)) => check("seat bundle", Verdict::Fail,
                format!("apply failed: {}", seat["apply_msg"].as_str().unwrap_or("").trim_start_matches("apply failed: ")),
                Some("noo upgrade --seats".into())),
            _ => check("seat bundle", Verdict::Warn, "staged, not applied yet".into(), Some(format!("on {name}: journalctl -u noo-seat-sync -n 30"))),
        });
    }
    out
}

/// True when the seat's last heartbeat was sent before the apply finished:
/// it still reports the old CLI, or the old applied sha. The seat's closing
/// heartbeat comes from the OLD applier process, and the next one follows a
/// sync tick (60s) later, so right after an apply the record can be stale.
fn heartbeat_predates_apply(seat: &Value, controller_cli: &str) -> bool {
    let hb = &seat["heartbeat"];
    hb["cli_version"].as_str() != Some(controller_cli) || hb["last_applied_sha"] != seat["sha256"]
}

/// `seat_checks` for a seat whose apply just reported exit 0. Judges the seat
/// only on evidence newer than the apply: when the last heartbeat predates it,
/// the CLI and display verdicts must not be read off that heartbeat (it names
/// the version the seat HAD). The apply's own report line stands in, and the
/// row says plainly that no heartbeat has arrived since.
pub(crate) fn seat_checks_after_apply(seat: &Value, controller_cli: &str, controller_tag: &str, now: i64) -> Vec<super::cluster_verify::Check> {
    use super::cluster_verify::Verdict;
    let mut out = seat_checks(seat, controller_cli, controller_tag, now);
    if !heartbeat_predates_apply(seat, controller_cli) { return out; }
    let msg = seat["apply_msg"].as_str().unwrap_or("");
    let installed = matches!(report_word(msg, "cli"), Some("updated" | "unchanged"));
    for c in out.iter_mut() {
        let name: &str = c.name;
        match name {
            "seat cli" if c.verdict == Verdict::Fail || c.verdict == Verdict::Warn => {
                *c = if installed {
                    check("seat cli", Verdict::Warn, format!(
                        "no heartbeat since the apply; the apply reported cli={} (the last heartbeat, from before it, said {})",
                        report_word(msg, "cli").unwrap_or("?"),
                        seat["heartbeat"]["cli_version"].as_str().filter(|v| !v.is_empty()).unwrap_or("nothing")),
                        Some("noo cluster verify".into()))
                } else {
                    check("seat cli", Verdict::Fail, "no heartbeat since the apply, and the apply report does not state the CLI".into(),
                        Some("noo upgrade --seats".into()))
                };
            }
            "display" if c.verdict == Verdict::Fail => {
                let reported = report_word(msg, "console").unwrap_or("");
                if !reported.is_empty() && reported != "-" && norm_tag(reported) == norm_tag(controller_tag) {
                    *c = check("display", Verdict::Warn, format!(
                        "no heartbeat since the apply; the apply reported console {reported} = controller"),
                        Some("noo cluster verify".into()));
                }
            }
            _ => {}
        }
    }
    out
}

/// The seats stage of `noo upgrade` (after the nodes, or alone with
/// `--seats`): stage every enrolled seat, wait for all of them together with
/// the nodes' combined wait, then one verify block per seat. No enrolled
/// seat: nothing is staged and nothing is printed beyond one line.
pub(crate) fn upgrade_seats(g: &Globals) -> i32 {
    let Some(seats) = list_seats(g) else {
        if !g.json { println!("{}", ui::note("seats: this gateway has no seat registry (an older stack) — skipped")); }
        return 0;
    };
    if seats.is_empty() {
        if !g.json { println!("{}", ui::note("seats: none enrolled (`noo kiosk seat-token <seat>` mints one)")); }
        return 0;
    }
    if !g.json { println!("{}", ui::phase("Seats")); }
    let mut pending: Vec<super::provision::PendingApply> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for s in &seats {
        let name = s["seat_name"].as_str().unwrap_or("?").to_string();
        println!();
        println!("{}", ui::item(&format!("seat {name}")));
        match stage_seat(g, s) {
            Ok(sha) => {
                println!("{}", ui::sub(&ui::status_line(Glyph::Ok, "staged (CLI + kiosk assets, signed, encrypted to the seat's birth cert)")));
                pending.push(super::provision::PendingApply { node: name, sha, legacy: false });
            }
            Err(e) => {
                println!("{}", ui::sub(&ui::status_line(Glyph::Err, &format!("not staged: {e}"))));
                failed.push(name);
            }
        }
    }
    if !pending.is_empty() {
        println!();
        let ends = super::provision::wait_applied_via(g, &pending, 600, 5,
            &|n| format!("/api/cluster/seats/{n}/status"), "seat");
        let tag = super::cluster_verify::controller_stack_tag();
        let mut rows = Vec::new();
        for (n, end) in ends {
            let ok_apply = matches!(end, super::provision::ApplyEnd::Applied { rc: 0, .. });
            // The closing heartbeat follows the apply report by a second or
            // two, and the heartbeat that shows the new CLI one sync tick (60s)
            // after that; wait for it, bounded. If it never comes the block
            // says so (`seat_checks_after_apply`) instead of naming the old CLI.
            let mut st = crate::http::get_json_opt(g, &format!("/api/cluster/seats/{n}/status"), true, 10);
            if ok_apply {
                for _ in 0..30 {
                    let fresh = st.as_ref().is_some_and(|s| s["heartbeat"]["cli_version"].as_str() == Some(env!("CARGO_PKG_VERSION"))
                        && s["heartbeat"]["last_applied_sha"] == s["sha256"]);
                    if fresh { break; }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    st = crate::http::get_json_opt(g, &format!("/api/cluster/seats/{n}/status"), true, 10);
                }
            }
            let st = st.unwrap_or(Value::Null);
            let checks = if ok_apply { seat_checks_after_apply(&st, env!("CARGO_PKG_VERSION"), &tag, now_unix()) }
                else { seat_checks(&st, env!("CARGO_PKG_VERSION"), &tag, now_unix()) };
            let seat_ok = ok_apply && checks.iter().all(|c| c.verdict != super::cluster_verify::Verdict::Fail);
            if !seat_ok { failed.push(n.clone()); }
            if g.json {
                rows.push(json!({"seat": n, "ok": seat_ok, "outcome": format!("{end:?}"),
                    "checks": checks.iter().map(|c| json!({"name": c.name, "verdict": format!("{:?}", c.verdict), "detail": c.detail})).collect::<Vec<_>>()}));
            } else {
                println!();
                println!("{}", ui::item(&format!("seat {n}")));
                match &end {
                    super::provision::ApplyEnd::Applied { rc: 0, .. } => {}
                    super::provision::ApplyEnd::Applied { rc: _, msg } => println!("{}", ui::sub(&ui::status_line(Glyph::Err,
                        &format!("apply failed: {}", msg.trim_start_matches("apply failed: ").chars().take(300).collect::<String>())))),
                    other => println!("{}", ui::sub(&ui::status_line(Glyph::Err, &format!("{other:?} within 10m")))),
                }
                for c in &checks {
                    let glyph = match c.verdict {
                        super::cluster_verify::Verdict::Ok => Glyph::Ok,
                        super::cluster_verify::Verdict::Fail => Glyph::Err,
                        _ => Glyph::Warn,
                    };
                    println!("{}", ui::sub(&ui::status_line(glyph, &format!("{}: {}", c.name, c.detail))));
                }
            }
        }
        if g.json { println!("{}", json!({"seats_apply": rows})); }
    }
    if failed.is_empty() {
        if !g.json { ui::close_done(&format!("{} seat(s) current", seats.len())); }
        0
    } else {
        if !g.json {
            ui::close_failed(&format!("{} of {} seat(s) not current: {}", failed.len(), seats.len(), failed.join(", ")),
                Some("noo upgrade --seats"));
        }
        1
    }
}

// ═══ tests ════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SeatConfig {
        SeatConfig { seat: "lobby".into(), controller_url: "https://ctl.example.ts.net:8080".into(),
            cli_user: "alex".into(), cli_home: "/home/alex".into(), kiosk_dir_at: None }
    }

    #[test]
    fn a_legacy_root_heartbeat_names_the_layout_and_the_running_version() {
        let st = SeatState { last_applied_sha: Some("abc".into()), ..Default::default() };
        let b = heartbeat_body_for(&cfg(), &st, "legacy-root");
        assert_eq!(b["layout"], "legacy-root");
        assert_eq!(b["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(b["last_applied_sha"], "abc");
        assert_eq!(heartbeat_body_for(&cfg(), &st, "user")["layout"], "user");
    }

    #[test]
    fn the_legacy_layout_reads_state_from_the_legacy_dir() {
        assert_eq!(state_dir_for(&cfg(), "legacy-root"), PathBuf::from("/var/lib/noo-seat"));
        assert_eq!(state_dir_for(&cfg(), "user"), PathBuf::from("/home/alex/.local/state/noo-seat"));
    }

    const SIGPUB: &str = "-----BEGIN PUBLIC KEY-----\nMHYw\n-----END PUBLIC KEY-----\n";

    fn blob() -> SeatBlob {
        SeatBlob { url: "https://ctl.example.ts.net:8080".into(), token: "noo-st-abc".into(), ca: "ab".repeat(32),
            seat: "lobby".into(), sigpub: SIGPUB.into() }
    }

    #[test]
    fn the_seat_blob_round_trips_and_carries_the_seat_claim() {
        let s = compose_seat_blob(&blob());
        assert!(s.starts_with("noo-seat1."));
        assert_eq!(parse_seat_blob(&s).unwrap(), blob());
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_start_matches("noo-seat1.")).unwrap();
        let v: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["role"], "seat");
    }

    #[test]
    fn a_blob_without_the_seat_claim_or_a_node_blob_is_refused() {
        use base64::Engine as _;
        let enc = |v: Value| format!("noo-seat1.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string()));
        let base = json!({"v": 1, "url": "https://x", "token": "t", "ca": "c", "seat": "s", "sigpub": SIGPUB});
        for role in [json!("node"), json!(null), json!("SEAT")] {
            let mut v = base.clone();
            v["role"] = role.clone();
            assert!(parse_seat_blob(&enc(v)).is_err(), "role {role}");
        }
        assert!(parse_seat_blob("noo1.eyJ2IjoxfQ").unwrap_err().contains("NODE enrollment"));
        let mut v = base.clone();
        v["role"] = json!("seat");
        v["seat"] = json!("../etc");
        assert!(parse_seat_blob(&enc(v)).is_err());
    }

    #[test]
    fn every_seat_kind_lands_inside_the_allow_list() {
        let c = cfg();
        let kinds: Vec<String> = SEAT_KINDS.iter().map(|k| k.to_string()).collect();
        let plan = plan_seat_apply(&kinds, &c).expect("every seat kind plans");
        for (_, dst) in &plan {
            assert!(seat_path_allowed(dst, &c), "{}", dst.display());
        }
        let paths: Vec<String> = plan.iter().map(|(_, p)| p.to_string_lossy().into_owned()).collect();
        assert!(paths.contains(&"/home/alex/.local/bin/noo".to_string()));
        assert!(paths.contains(&"/home/alex/.local/libexec/noo-seat/noo".to_string()));
        assert!(paths.contains(&"/opt/noo-seat/kiosk/noo-kiosk-serve".to_string()), "the display's scripts land in the shared dir: {paths:?}");
        assert!(!paths.iter().any(|p| p.starts_with("/home/alex/.local/libexec/noo-seat/kiosk")), "never under the home dir: {paths:?}");
    }

    /// The applier's scope: node kinds and any path outside the list refuse
    /// the whole bundle.
    #[test]
    fn the_seat_applier_refuses_anything_outside_its_allow_list() {
        let c = cfg();
        for kind in ["agent-env", "nats-creds", "fleet-secrets", "svc-gateway.crt", "svc-gateway.key", "agent-binary",
                     "hostd-binary", "harness-binary", "harness-env", "signing-key", "node-cert", "teardown", "sudoers"] {
            let kinds = vec!["cli-binary".to_string(), kind.to_string()];
            let e = plan_seat_apply(&kinds, &c).unwrap_err();
            assert!(e.contains("not a seat kind"), "{kind}: {e}");
        }
        assert!(plan_seat_apply(&["cli-binary".into(), "cli-binary".into()], &c).is_err(), "a duplicate kind refuses");
        for p in [
            "/etc/noo-node-agent.env", "/usr/local/bin/noo-node-agent", "/usr/local/bin/noo-hostd", "/usr/local/bin/noo",
            "/etc/sudoers.d/noo", "/etc/noo/birth.key", "/etc/noo-seat/birth.key", "/etc/noo-seat/seat.json",
            "/home/alex/.bashrc", "/home/other/.local/bin/noo", "/root/.local/bin/noo",
            "/usr/local/bin/noo-kiosk-serve/../../sbin/x", "/usr/local/bin/../bin/noo-kiosk-serve",
            "/etc/systemd/system/noo-node-agent.service", "/etc/systemd/system/noo-seat-sync.service",
            "usr/local/bin/noo-kiosk-serve", "/etc/default/kiosk",
        ] {
            assert!(!seat_path_allowed(Path::new(p), &c), "{p} must be outside the seat allow-list");
        }
        // install_file re-checks at the write itself.
        assert!(install_file(Path::new("/etc/sudoers.d/noo"), b"x", &c).unwrap_err().contains("allow-list"));
    }

    #[test]
    fn a_seat_config_must_name_a_plain_user_and_home() {
        let mut c = cfg();
        assert!(c.validate().is_ok());
        c.cli_user = "root".into();
        assert!(c.validate().is_err(), "the seat CLI is never root's");
        let mut c = cfg();
        c.cli_home = "/home/alex/../root".into();
        assert!(c.validate().is_err());
        c.cli_home = "/".into();
        assert!(c.validate().is_err());
        c.cli_home = "home/alex".into();
        assert!(c.validate().is_err());
    }

    /// Bundle contents: the seat kinds and nothing that is a node credential.
    #[test]
    fn a_seat_bundle_carries_no_node_credentials() {
        let params = KioskParams { user: "alex".into(), mode: super::super::kiosk::Mode::Dedicated, vt: 1 };
        let files = seat_bundle_files(b"\x7fELF-cli".to_vec(), Some(&params), SIGPUB.as_bytes().to_vec(),
            &json!({"console_build": "stack-v0.6.5", "cli_version": "0.6.5"}));
        for (k, bytes) in &files {
            assert!(SEAT_KINDS.contains(k), "{k} is not a seat kind");
            let text = String::from_utf8_lossy(bytes);
            for needle in ["NOO_CLUSTER_SECRET", "NOO_CONTROLLER_SECRET", "NATS_PASSWORD", "NATS_USER", "BEGIN PRIVATE KEY",
                           "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "NOO_NODE_ID", "noo-node-agent"] {
                assert!(!text.contains(needle), "{k} carries {needle}");
            }
        }
        let kinds: Vec<&str> = files.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&"cli-binary") && kinds.contains(&"unit-kiosk-serve") && kinds.contains(&"signing-pub"));
        // A seat that has not set up its kiosk gets no units.
        let bare = seat_bundle_files(vec![1], None, vec![2], &json!({}));
        assert!(!bare.iter().any(|(k, _)| k.starts_with("unit-")));
    }

    #[test]
    fn the_builder_refuses_a_node_kind() {
        let dir = private_dir(&std::env::temp_dir(), "noo-seat-test").unwrap();
        let ca = crate::pki::ClusterCa::new(dir.join("pki"));
        for kind in ["agent-env", "nats-creds", "svc-gateway.key", "fleet-secrets"] {
            let e = build_seat_bundle(&ca, "lobby", &[("cli-binary", vec![1]), (kind, b"NOO_CLUSTER_SECRET=x".to_vec())], &dir.join("w")).unwrap_err();
            assert!(e.contains("may not carry"), "{kind}: {e}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End to end on this host (openssl + tar): build, extract with the node
    /// extractor, verify with the seat's anchor; a wrong seat, a tampered
    /// file and a foreign key all refuse.
    #[test]
    fn a_built_seat_bundle_verifies_and_tampering_refuses() {
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("openssl absent; skipping");
            return;
        }
        let dir = private_dir(&std::env::temp_dir(), "noo-seat-e2e").unwrap();
        let ca = crate::pki::ClusterCa::new(dir.join("pki"));
        ca.ensure_signing_key().unwrap();
        let files = seat_bundle_files(b"cli-bytes".to_vec(), None, std::fs::read(ca.signing_pub_path()).unwrap(),
            &json!({"console_build": "stack-v0.6.5"}));
        let refs: Vec<(&str, Vec<u8>)> = files.iter().map(|(k, b)| (*k, b.clone())).collect();
        std::fs::create_dir_all(dir.join("w")).unwrap();
        let tar = build_seat_bundle(&ca, "lobby", &refs, &dir.join("w")).expect("build");
        let bytes = std::fs::read(&tar).unwrap();
        let ex = dir.join("x");
        std::fs::create_dir_all(&ex).unwrap();
        super::super::node_fetch::extract_bundle(&bytes, &ex).expect("the node extractor's member rules hold");
        let c = cfg();
        let plan = verify_seat_stage(&ex, &ca.signing_pub_path(), &c, now_unix()).expect("verifies");
        assert!(plan.iter().all(|(_, p)| seat_path_allowed(p, &c)));
        let mut other = cfg();
        other.seat = "hall".into();
        assert!(verify_seat_stage(&ex, &ca.signing_pub_path(), &other, now_unix()).unwrap_err().contains("addressed to seat"));
        assert!(verify_seat_stage(&ex, &ca.signing_pub_path(), &c, now_unix() + 2 * 86_400).unwrap_err().contains("replay"));
        // A foreign key does not verify.
        let foreign = crate::pki::ClusterCa::new(dir.join("pki2"));
        foreign.ensure_signing_key().unwrap();
        assert!(verify_seat_stage(&ex, &foreign.signing_pub_path(), &c, now_unix()).unwrap_err().contains("signature"));
        // A tampered payload does not match its manifest sha.
        std::fs::write(ex.join("files/cli-binary"), b"evil").unwrap();
        assert!(verify_seat_stage(&ex, &ca.signing_pub_path(), &c, now_unix()).unwrap_err().contains("manifest sha"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_node_manifest_is_not_a_seat_manifest() {
        let node = "#noo-bundle 2\n#node lobby\n#issued 1757000000\n";
        assert!(seat_manifest_shape_ok(node).is_err());
        assert!(verify_seat_header(node, "lobby", 1_757_000_000).unwrap_err().contains("not a seat bundle"));
        assert!(seat_manifest_shape_ok(&seat_manifest_header("lobby", 1_757_000_000)).is_ok());
    }

    #[test]
    fn the_browser_line_survives_an_update() {
        let new = "#!/bin/sh\nBROWSER=\"${NOO_KIOSK_BROWSER:-chromium}\"\nexec x\n";
        let old = "#!/bin/sh\nBROWSER=\"${NOO_KIOSK_BROWSER:-google-chrome-stable}\"\nexec old\n";
        let out = carry_browser_line(new, Some(old));
        assert!(out.contains("google-chrome-stable") && out.contains("exec x") && !out.contains("exec old"));
        assert_eq!(carry_browser_line(new, None), new);
    }

    #[test]
    fn the_display_reloads_only_when_it_has_to() {
        assert_eq!(display_action(&["kiosk-launch".into()], false), "restart");
        assert_eq!(display_action(&["unit-kiosk".into()], true), "restart");
        assert_eq!(display_action(&["cli-binary".into(), "kiosk-serve".into()], true), "reload");
        assert_eq!(display_action(&["cli-binary".into()], false), "unchanged");
    }

    #[test]
    fn the_seat_proof_message_matches_the_gateway() {
        assert_eq!(seat_proof_message("heartbeat", "lobby", "deadbeef", 1_757_000_000),
            "noo-seat-heartbeat:lobby:deadbeef:1757000000");
        assert_eq!(seat_proof_message("fetch", "lobby", "deadbeef", 1_757_000_000),
            "noo-seat-fetch:lobby:deadbeef:1757000000");
    }

    #[test]
    fn the_verify_block_judges_a_seat() {
        use super::super::cluster_verify::Verdict;
        let seen = "2025-10-09T08:53:10Z";
        let t = super::super::cluster_verify::parse_rfc3339_unix(seen).unwrap();
        let now = t + 10;
        let good = json!({"seat_name": "lobby", "last_seen": seen,
            "heartbeat": {"cli_version": "0.6.5", "user_cli_current": true, "kiosk_serve": "active",
                          "console_build": "stack-v0.6.5", "kiosk": {"user": "alex", "quality": "lean"}},
            "staged_sha": "a", "applied_sha": "a", "apply_rc": 0,
            "apply_msg": "seat-apply cli=updated scripts=0 units=0 serve=unchanged display=reloaded console=stack-v0.6.5"});
        let c = seat_checks(&good, "0.6.5", "stack-v0.6.5", now);
        assert!(c.iter().all(|c| c.verdict == Verdict::Ok), "{c:?}");
        assert!(c.iter().any(|c| c.detail.contains("display reloaded")));
        let mut old = good.clone();
        old["heartbeat"]["cli_version"] = json!("0.5.56");
        assert!(seat_checks(&old, "0.6.5", "stack-v0.6.5", now).iter().any(|c| c.name == "seat cli" && c.verdict == Verdict::Fail));
        let mut down = good.clone();
        down["heartbeat"]["kiosk_serve"] = json!("failed");
        assert!(seat_checks(&down, "0.6.5", "stack-v0.6.5", now).iter().any(|c| c.name == "kiosk-serve" && c.verdict == Verdict::Fail));
        assert!(seat_checks(&good, "0.6.5", "stack-v0.6.5", now + 600).iter().any(|c| c.name == "seat online" && c.verdict == Verdict::Fail));
        assert!(seat_checks(&good, "0.6.5", "v0.6.6", now).iter().any(|c| c.name == "display" && c.verdict == Verdict::Fail));
        assert_eq!(report_word(good["apply_msg"].as_str().unwrap(), "display"), Some("reloaded"));
    }

    #[test]
    fn a_seat_is_not_judged_on_a_heartbeat_older_than_its_apply() {
        use super::super::cluster_verify::Verdict;
        let seen = "2025-10-09T08:53:10Z";
        let now = super::super::cluster_verify::parse_rfc3339_unix(seen).unwrap() + 10;
        // The apply landed 0.6.13; the last heartbeat predates it (old CLI,
        // old applied sha, old console build).
        let mut seat = json!({"seat_name": "lobby", "last_seen": seen,
            "heartbeat": {"cli_version": "0.6.12", "last_applied_sha": "old", "user_cli_current": true, "kiosk_serve": "active",
                          "console_build": "stack-v0.6.12", "kiosk": {"user": "alex"}},
            "sha256": "new", "applied_sha": "new", "apply_rc": 0,
            "apply_msg": "seat-apply cli=updated scripts=0 units=0 serve=unchanged display=reloaded console=stack-v0.6.13"});
        // Today's judge reads the stale heartbeat as the seat's version.
        assert!(seat_checks(&seat, "0.6.13", "stack-v0.6.13", now).iter().any(|c| c.name == "seat cli" && c.verdict == Verdict::Fail));
        let c = seat_checks_after_apply(&seat, "0.6.13", "stack-v0.6.13", now);
        assert!(c.iter().all(|c| c.verdict != Verdict::Fail), "{c:?}");
        let cli = c.iter().find(|c| c.name == "seat cli").unwrap();
        assert_eq!(cli.verdict, Verdict::Warn);
        assert!(cli.detail.contains("no heartbeat since the apply"), "{}", cli.detail);
        assert!(cli.detail.contains("cli=updated"), "{}", cli.detail);
        // Without any statement of the CLI in the apply report, it still fails.
        let mut mute = seat.clone();
        mute["apply_msg"] = json!("");
        assert!(seat_checks_after_apply(&mute, "0.6.13", "stack-v0.6.13", now).iter().any(|c| c.name == "seat cli" && c.verdict == Verdict::Fail));
        // A newer heartbeat settles it: judged as before, a plain Ok.
        seat["heartbeat"] = json!({"cli_version": "0.6.13", "last_applied_sha": "new", "user_cli_current": true, "kiosk_serve": "active",
                                   "console_build": "stack-v0.6.13", "kiosk": {"user": "alex"}});
        let c = seat_checks_after_apply(&seat, "0.6.13", "stack-v0.6.13", now);
        assert!(c.iter().all(|c| c.verdict == Verdict::Ok), "{c:?}");
    }

    #[test]
    fn kiosk_params_come_from_the_heartbeat() {
        let hb = json!({"kiosk": {"user": "alex", "mode": "dedicated", "vt": "1"}});
        assert_eq!(kiosk_params_from(&hb), Some(KioskParams { user: "alex".into(), mode: super::super::kiosk::Mode::Dedicated, vt: 1 }));
        assert_eq!(kiosk_params_from(&json!({"kiosk": {"user": "", "mode": "dedicated", "vt": "1"}})), None);
        assert_eq!(kiosk_params_from(&json!({"kiosk": {"user": "a b", "mode": "dedicated", "vt": "1"}})), None);
        assert_eq!(kiosk_params_from(&json!({"kiosk": {"user": "k", "mode": "weird", "vt": "1"}})), None);
        assert_eq!(kiosk_params_from(&json!({})), None);
    }

    #[test]
    fn the_install_script_is_the_one_root_step() {
        let c = cfg();
        let s = seat_install_script(Path::new("/tmp/w"), Path::new("/home/alex/.local/bin/noo"), &c, "alex", SeatScript::Enroll);
        assert!(s.contains("install -m 0640 -o root -g 'alex' '/tmp/w/birth.key' /etc/noo-seat/birth.key"));
        assert!(s.contains("install -m 0644 -o root -g root '/tmp/w/signing.pub' /etc/noo-seat/signing.pub"));
        // The seat's copy and kiosk scripts are made AS the user, never by root.
        assert!(s.contains("as_user sh -c 'install -m 0755") && s.contains("/home/alex/.local/libexec/noo-seat/noo"));
        assert!(s.contains("systemctl enable --now noo-seat-sync.timer"));
        assert!(s.contains("/etc/polkit-1/rules.d"));
        // Nothing node-shaped is installed by a seat's enrollment, and no root copy of the CLI.
        for n in ["noo-node-agent", "noo-hostd", "noo-apply", "noo-fetch", "sudoers", "/etc/noo/", "/usr/local/libexec"] {
            assert!(!s.contains(n), "{n}");
        }
    }

    // ── safe apply: atomic, ordered, allow-listed, recoverable ─────────

    /// A scratch tree shaped like a seat's user layout, all under one temp
    /// root: `~/.local/bin`, `~/.local/libexec/noo-seat`, and the shared
    /// display dir (`opt/noo-seat/kiosk`).
    struct Tree { root: PathBuf, cfg: SeatConfig }
    impl Tree {
        fn new(tag: &str) -> Tree {
            let root = std::env::temp_dir().join(format!("noo-seat-apply-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let home = root.join("home/alex");
            for d in [".local/bin", ".local/libexec/noo-seat"] {
                std::fs::create_dir_all(home.join(d)).unwrap();
            }
            let shared = root.join("opt/noo-seat/kiosk");
            std::fs::create_dir_all(&shared).unwrap();
            let cfg = SeatConfig { cli_home: home.to_string_lossy().into_owned(),
                kiosk_dir_at: Some(shared.to_string_lossy().into_owned()), ..cfg() };
            Tree { root, cfg }
        }
        fn cli(&self) -> PathBuf { self.cfg.cli_path() }
        fn seat(&self) -> PathBuf { self.cfg.applier_path() }
        fn serve(&self) -> PathBuf { self.cfg.kiosk_dir().join("noo-kiosk-serve") }
        fn plan(&self) -> Vec<(String, PathBuf)> {
            // The real plan puts the user's CLI FIRST; apply_plan reorders.
            vec![("cli-binary".into(), self.cli()), ("cli-binary".into(), self.seat()), ("kiosk-serve".into(), self.serve())]
        }
        fn allowed(&self, p: &Path) -> bool { seat_path_allowed(p, &self.cfg) }
        fn write(&self, p: &Path, b: &[u8]) -> Result<(), String> { install_file(p, b, &self.cfg) }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(self.cfg.cli_path().parent().unwrap(), std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn run_apply(t: &Tree, w: Writer) -> Result<Vec<String>, String> {
        apply_plan(&t.plan(), &t.cli(), &|k| Ok(format!("new-{k}").into_bytes()), &|p| t.allowed(p), w)
    }

    #[test]
    fn the_seat_copy_is_written_before_the_user_cli_and_both_are_replaced() {
        let t = Tree::new("order");
        std::fs::write(t.cli(), b"old").unwrap();
        std::fs::write(t.seat(), b"old").unwrap();
        let log = std::cell::RefCell::new(Vec::<String>::new());
        let changed = run_apply(&t, &|d, b| {
            log.borrow_mut().push(d.file_name().unwrap().to_string_lossy().into_owned());
            assert!(d != t.cli() || d.exists(), "the CLI must exist when its write starts");
            t.write(d, b)
        }).unwrap();
        assert_eq!(*log.borrow(), vec!["noo".to_string(), "noo-kiosk-serve".into(), "noo".into()]);
        assert_eq!(changed, vec!["cli-binary".to_string(), "kiosk-serve".into()]);
        assert_eq!(std::fs::read(t.cli()).unwrap(), b"new-cli-binary");
        assert_eq!(std::fs::read(t.seat()).unwrap(), b"new-cli-binary");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(t.cli()).unwrap().permissions().mode() & 0o777, 0o755);
        for d in [t.cli().parent().unwrap().to_path_buf(), t.seat().parent().unwrap().to_path_buf()] {
            let names: Vec<String> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            assert!(names.iter().all(|n| !n.starts_with('.')), "a temp file was left: {names:?}");
        }
    }

    #[test]
    fn a_failed_write_keeps_the_old_cli_and_reports_it() {
        let t = Tree::new("userfail");
        std::fs::write(t.cli(), b"old-cli").unwrap();
        std::fs::write(t.seat(), b"old").unwrap();
        let e = run_apply(&t, &|d, b| if d == t.cli() { Err("rename: Permission denied".into()) } else { t.write(d, b) }).unwrap_err();
        assert!(e.contains("Permission denied") && e.contains("already changed"), "{e}");
        assert_eq!(std::fs::read(t.cli()).unwrap(), b"old-cli", "the user's CLI is untouched");
        assert_eq!(std::fs::read(t.seat()).unwrap(), b"new-cli-binary", "the seat copy landed first");
    }

    #[test]
    fn the_atomic_write_never_unlinks_first_and_keeps_the_old_file_on_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = Tree::new("atomic");
        std::fs::write(t.cli(), b"old-cli").unwrap();
        // The directory refuses new entries (the temp file cannot be made):
        // the write fails, and the old file is still there, byte for byte.
        let dir = t.cli().parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = t.write(&t.cli(), b"new-cli");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(r.is_err(), "{r:?}");
        }
        assert_eq!(std::fs::read(t.cli()).unwrap(), if r.is_err() { b"old-cli".to_vec() } else { b"new-cli".to_vec() });
        // A dangling symlink at the target is replaced by a regular file, not followed.
        let t2 = Tree::new("atomic-link");
        std::fs::remove_dir(t2.cli().parent().unwrap()).unwrap();
        std::fs::create_dir_all(t2.cli().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(t2.root.join("nowhere"), t2.cli()).unwrap();
        t2.write(&t2.cli(), b"fresh").unwrap();
        assert_eq!(std::fs::read(t2.cli()).unwrap(), b"fresh");
        assert!(!t2.cli().symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn the_user_cli_is_never_missing_while_it_is_replaced() {
        let t = Tree::new("never-missing");
        std::fs::write(t.cli(), b"old-cli").unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let missing = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (cli, st, mi) = (t.cli(), stop.clone(), missing.clone());
        let watcher = std::thread::spawn(move || {
            while !st.load(std::sync::atomic::Ordering::Relaxed) {
                match std::fs::read(&cli) {
                    Ok(b) if b.starts_with(b"old-cli") || b.starts_with(b"new-cli") => {}
                    _ => { mi.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                }
            }
        });
        for i in 0..40 {
            let body = format!("{}-{i}", if i % 2 == 0 { "new-cli" } else { "old-cli" }).repeat(50_000);
            t.write(&t.cli(), body.as_bytes()).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        watcher.join().unwrap();
        assert_eq!(missing.load(std::sync::atomic::Ordering::Relaxed), 0, "the CLI was missing or unreadable at some instant");
    }

    #[test]
    fn nothing_outside_the_allow_list_is_written() {
        let t = Tree::new("allow");
        let outside = t.root.join("etc-passwd");
        let plan = vec![("kiosk-serve".to_string(), t.serve()), ("kiosk-cdp".to_string(), outside.clone())];
        let wrote = std::cell::RefCell::new(Vec::<PathBuf>::new());
        let e = apply_plan(&plan, &t.cli(), &|_| Ok(b"x".to_vec()), &|p| t.allowed(p),
            &|d, _| { wrote.borrow_mut().push(d.to_path_buf()); Ok(()) }).unwrap_err();
        assert!(e.contains("REFUSED") && e.contains("allow-list"), "{e}");
        assert!(!wrote.borrow().contains(&outside) && !outside.exists());
        // The production guard refuses everything root-owned and everything else.
        let c = cfg();
        for p in ["/etc/passwd", "/home/alex/.bashrc", "/home/alex/.local/bin/other", "/home/alex/.local/bin/../../.bashrc",
                  "/usr/local/bin/noo-kiosk-serve", "/usr/local/bin/noo-kiosk-watchdog", "/usr/local/libexec/noo-seat/noo",
                  "/etc/systemd/system/kiosk.service", "/etc/noo-seat/signing.pub", "/etc/polkit-1/rules.d/49-noo-seat.rules",
                  "/home/alex/.local/libexec/noo-seat/kiosk/noo-kiosk-watchdog",
                  // 0.6.10's home location is no longer a target, and the root watchdog never is.
                  "/home/alex/.local/libexec/noo-seat/kiosk/noo-kiosk-serve", "/opt/noo-seat/kiosk/noo-kiosk-watchdog",
                  "/opt/noo-seat/kiosk/../../../etc/passwd", "/opt/noo-seat/noo-kiosk-serve"] {
            assert!(!seat_path_allowed(Path::new(p), &c), "{p}");
            assert!(install_file(Path::new(p), b"x", &c).unwrap_err().contains("REFUSED"), "{p}");
        }
    }

    #[test]
    fn no_root_owned_write_target_remains_in_the_allow_list() {
        let c = cfg();
        let kinds: Vec<String> = SEAT_KINDS.iter().map(|k| k.to_string()).collect();
        let plan = plan_seat_apply(&kinds, &c).unwrap();
        assert!(!plan.is_empty());
        for (kind, dst) in &plan {
            // Seat-owned only: the seat user's home, or the display's shared
            // dir (seat user : display group; root created it, the seat owns it).
            let seat_owned = dst.starts_with(&c.cli_home) || dst.starts_with(SEAT_KIOSK_DIR);
            assert!(seat_owned, "{kind}: {} is not a seat-owned path", dst.display());
            if kind.starts_with("kiosk-") {
                assert!(dst.starts_with(SEAT_KIOSK_DIR), "{kind}: the display cannot reach {}", dst.display());
            }
        }
        // The kinds that used to land in root-owned places are carried, verified, not applied.
        for k in ["kiosk-watchdog", "unit-kiosk", "unit-kiosk-serve", "unit-kiosk-watchdog", "unit-kiosk-watchdog-timer", "signing-pub"] {
            assert!(seat_targets(k, &c).unwrap().is_empty(), "{k}");
        }
    }

    #[test]
    fn a_missing_user_cli_is_restored_from_the_seat_copy_and_never_left_missing() {
        let t = Tree::new("restore");
        std::fs::write(t.seat(), b"seat-copy").unwrap();
        // The live state: only a dangling `pai` link is left where the CLI was.
        std::os::unix::fs::symlink(t.cli(), t.cli().parent().unwrap().join("pai")).unwrap();
        assert!(!t.cli().exists());
        assert!(restore_user_cli(&t.cli(), &t.seat(), &|d, b| t.write(d, b)).unwrap());
        assert_eq!(std::fs::read(t.cli()).unwrap(), b"seat-copy");
        assert!(t.cli().parent().unwrap().join("pai").exists(), "the link resolves again");
        // Present: untouched. No seat copy: nothing invented, nothing removed.
        std::fs::write(t.cli(), b"mine").unwrap();
        assert!(!restore_user_cli(&t.cli(), &t.seat(), &|d, b| t.write(d, b)).unwrap());
        assert_eq!(std::fs::read(t.cli()).unwrap(), b"mine");
        let t2 = Tree::new("restore-none");
        assert!(!restore_user_cli(&t2.cli(), &t2.seat(), &|d, b| t2.write(d, b)).unwrap());
        assert!(!t2.cli().exists());
        assert!(restore_user_cli(&t2.cli(), &t.seat(), &|_, _| Err("boom".into())).unwrap_err().contains("boom"));
        // A plan that finds the CLI missing writes it.
        let changed = run_apply(&t2, &|d, b| t2.write(d, b)).unwrap();
        assert!(changed.contains(&"cli-binary".to_string()));
        assert_eq!(std::fs::read(t2.cli()).unwrap(), b"new-cli-binary");
    }

    #[test]
    fn the_sync_unit_runs_as_the_seat_user_and_its_comment_matches_the_allow_list() {
        let c = cfg();
        let u = render_sync_service(&c);
        assert!(u.lines().any(|l| l == "User=alex"), "the recurring sync must not be root:\n{u}");
        assert!(u.lines().any(|l| l == "ExecStart=/home/alex/.local/libexec/noo-seat/noo kiosk seat-sync"), "{u}");
        for need in ["Type=oneshot", "NoNewPrivileges=yes", "PrivateTmp=yes"] {
            assert!(u.lines().any(|l| l == need), "{need}");
        }
        let comment: String = u.lines().take_while(|l| l.starts_with('#')).collect::<Vec<_>>().join(" ").replace("# ", "");
        for (kind, dst) in plan_seat_apply(&SEAT_KINDS.iter().map(|k| k.to_string()).collect::<Vec<_>>(), &c).unwrap() {
            let s = dst.to_string_lossy().into_owned();
            let named = if kind.starts_with("kiosk-") { comment.contains("/opt/noo-seat/kiosk/noo-kiosk-{launch,cdp,serve}") } else { comment.contains(&s) };
            assert!(named, "{s} is allow-listed but the unit comment does not name it:\n{comment}");
        }
        assert!(comment.contains("never root"));
    }

    #[test]
    fn the_polkit_rule_grants_the_seat_user_exactly_the_kiosk_units() {
        let r = render_polkit_rule("alex");
        assert!(r.contains("subject.user == \"alex\"") && r.contains("org.freedesktop.systemd1.manage-units"));
        for u in SEAT_RESTARTABLE_UNITS {
            assert!(r.contains(&format!("\"{u}\"")), "{u}");
        }
        assert_eq!(r.matches(".service\"").count() + r.matches(".timer\"").count(), SEAT_RESTARTABLE_UNITS.len());
    }

    #[test]
    fn the_migration_is_one_explicit_root_script_that_moves_everything_and_removes_the_old_layout() {
        let c = cfg();
        let m = seat_install_script(Path::new("/tmp/w"), Path::new(LEGACY_APPLIER_BIN), &c, "alex", SeatScript::Migrate);
        // Stops the old root timer first, then moves state, installs the user copy, removes the root copy.
        let i = |needle: &str| m.find(needle).unwrap_or_else(|| panic!("{needle} missing:\n{m}"));
        assert!(i("disable --now noo-seat-sync.timer") < i("install -d -m 0755 -o root"));
        assert!(m.contains("/var/lib/noo-seat/state.json"));
        assert!(m.contains("/home/alex/.local/libexec/noo-seat/noo"));
        assert!(i("install -m 0644 -o root -g root '/tmp/w/noo-seat-sync.service'") < i("rm -f /usr/local/libexec/noo-seat/noo"));
        assert!(i("rm -f /usr/local/libexec/noo-seat/noo") < i("enable --now noo-seat-sync.timer"));
        // The birth key stays root-owned, readable only by root and the seat user's group.
        assert!(m.contains("install -m 0640 -o root -g 'alex' '/tmp/w/birth.key' /etc/noo-seat/birth.key"));
        // The display's scripts go to the shared dir (never the user tree), and
        // only after the seat's timer is back: the self-check may fail the script.
        assert!(i("enable --now noo-seat-sync.timer") < i("install -d -m 2750 -o 'alex' -g \"$kgrp\" /opt/noo-seat/kiosk"));
        assert!(i("install -m 0750 -o 'alex' -g \"$kgrp\" '/tmp/w'/noo-kiosk-$n /opt/noo-seat/kiosk/noo-kiosk-$n") < i("ln -sfn /opt/noo-seat/kiosk/noo-kiosk-$n /usr/local/bin/noo-kiosk-$n"));
        assert!(!m.contains("cp -f"), "nothing is copied into a home directory for the display:\n{m}");
        assert!(i("journalctl -u kiosk.service") > i("systemctl restart kiosk.service"));
        // The enroll flavour has neither the stop nor the removal.
        let e = seat_install_script(Path::new("/tmp/w"), Path::new("/home/alex/.local/bin/noo"), &c, "alex", SeatScript::Enroll);
        assert!(!e.contains("disable --now") && !e.contains("rm -f") && !e.contains("rm -rf"));
        // Neither touches the user's own CLI: the sync restores/updates that as the user.
        assert!(!m.contains("/home/alex/.local/bin/noo") && !e.contains("'/home/alex/.local/bin/noo'\n"));
    }

    #[test]
    fn a_legacy_root_seat_is_flagged_by_verify_with_the_one_command() {
        use super::super::cluster_verify::Verdict;
        let seen = "2025-10-09T08:53:10Z";
        let now = super::super::cluster_verify::parse_rfc3339_unix(seen).unwrap() + 10;
        let old = json!({"seat_name": "lobby", "last_seen": seen,
            "heartbeat": {"cli_version": "0.6.10", "layout": "legacy-root", "user_cli_current": true, "kiosk_serve": "active", "console_build": "stack-v0.6.10"}});
        let c = seat_checks(&old, "0.6.10", "stack-v0.6.10", now);
        let l = c.iter().find(|c| c.name == "seat layout").expect("a layout check");
        assert_eq!(l.verdict, Verdict::Warn);
        assert!(l.remedy.as_deref().unwrap().contains("sudo /usr/local/libexec/noo-seat/noo kiosk seat-sync --migrate"));
        let mut ok = old.clone();
        ok["heartbeat"]["layout"] = json!("user");
        assert!(seat_checks(&ok, "0.6.10", "stack-v0.6.10", now).iter().all(|c| c.name != "seat layout"));
    }

    #[test]
    fn the_verify_block_names_a_failed_apply() {
        use super::super::cluster_verify::Verdict;
        let seen = "2025-10-09T08:53:10Z";
        let now = super::super::cluster_verify::parse_rfc3339_unix(seen).unwrap() + 10;
        let bad = json!({"seat_name": "lobby", "last_seen": seen,
            "heartbeat": {"cli_version": "0.6.5", "user_cli_current": true, "kiosk_serve": "active", "console_build": "stack-v0.6.5"},
            "staged_sha": "a", "applied_sha": "a", "apply_rc": 65,
            "apply_msg": "apply failed: rename onto /home/alex/.local/bin/noo: Permission denied"});
        let c = seat_checks(&bad, "0.6.5", "stack-v0.6.5", now);
        let b = c.iter().find(|c| c.name == "seat bundle").unwrap();
        assert_eq!(b.verdict, Verdict::Fail);
        assert!(b.detail.starts_with("apply failed: rename"), "{}", b.detail);
        assert!(!b.detail.contains("apply failed: apply failed"));
    }

    // ── the display's shared dir: the root script, run against a fake root ──

    /// A fake `/` for the root script: the units `kiosk setup` writes, and
    /// shims for the commands that need root or a live systemd — `install`
    /// (drops -o/-g, logs them, then really installs), `runuser`, `id`,
    /// `systemctl` (logs; `is-active` answers `$FAKE_STATE`) and `sleep`.
    struct FakeRoot { root: PathBuf, work: PathBuf, log: PathBuf, cfg: SeatConfig }
    impl FakeRoot {
        fn new(tag: &str) -> FakeRoot {
            let root = std::env::temp_dir().join(format!("noo-seat-root-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            for d in ["etc/systemd/system", "usr/local/bin", "home/alex", "_shims", "_work"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            let real_install = ["/usr/bin/install", "/bin/install"].into_iter().find(|p| Path::new(p).exists()).expect("coreutils install");
            let shim = |n: &str, body: String| {
                let p = root.join("_shims").join(n);
                crate::test_exec::write_exec(&p, format!("#!/bin/sh\n{body}"), 0o755);
            };
            shim("install", format!(r#"o=-; g=-; m=-; d=no; last=
n=$#
while [ "$n" -gt 0 ]; do
  a=$1; shift; n=$((n - 1))
  case "$a" in
    -o) o=$1; shift; n=$((n - 1)); continue ;;
    -g) g=$1; shift; n=$((n - 1)); continue ;;
    -m) m=$1 ;;
    -d) d=yes ;;
  esac
  set -- "$@" "$a"; last=$a
done
echo "install owner=$o group=$g mode=$m dir=$d dst=$last" >> "$SHIM_LOG"
exec {real_install} "$@"
"#));
            shim("runuser", "while [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n".into());
            shim("id", "if [ \"$1\" = -gn ] && [ \"$2\" = kiosk ]; then echo kiosk; exit 0; fi\necho \"id: '$2': no such user\" >&2\nexit 1\n".into());
            shim("systemctl", "echo \"systemctl $*\" >> \"$SHIM_LOG\"\nif [ \"$1\" = is-active ]; then echo \"${FAKE_STATE:-active}\"; [ \"${FAKE_STATE:-active}\" = active ]; exit $?; fi\nexit 0\n".into());
            shim("sleep", "exit 0\n".into());
            let work = root.join("_work");
            for f in ["birth.key", "birth.crt", "ca.crt", "signing.pub", "seat.json", "noo-seat-sync.service", "noo-seat-sync.timer", "49-noo-seat.rules", "noo"] {
                std::fs::write(work.join(f), format!("fake {f}\n")).unwrap();
            }
            stage_display_scripts(&work, None).unwrap();
            let cfg = SeatConfig { cli_home: root.join("home/alex").to_string_lossy().into_owned(), ..cfg() };
            let log = root.join("_log");
            FakeRoot { root, work, log, cfg }
        }
        fn at(&self, abs: &str) -> PathBuf { self.root.join(abs.trim_start_matches('/')) }
        /// The display as `noo kiosk setup` (pre-seat) installs it: root copies in /usr/local/bin.
        fn with_display(self) -> FakeRoot {
            use super::super::kiosk as k;
            std::fs::write(self.at("/etc/systemd/system/kiosk.service"), k::render_kiosk_service_in("kiosk", k::Mode::Dedicated, 1, "/usr/local/bin")).unwrap();
            std::fs::write(self.at("/etc/systemd/system/kiosk-serve.service"), k::render_serve_service_in("kiosk", "/usr/local/bin")).unwrap();
            std::fs::write(self.at("/etc/systemd/system/kiosk-watchdog.service"), k::render_watchdog_service()).unwrap();
            for n in ["launch", "cdp", "serve", "watchdog"] {
                std::fs::write(self.at(&format!("/usr/local/bin/noo-kiosk-{n}")), format!("#!/bin/sh\n# root copy {n}\n")).unwrap();
            }
            self
        }
        /// The 0.6.10 migration's result (homeserver): the PATH names are
        /// symlinks into the seat user's home, the units exec through them.
        fn with_home_layout(self) -> FakeRoot {
            let s = self.with_display();
            let hk = s.cfg.home_kiosk_dir();
            std::fs::create_dir_all(&hk).unwrap();
            for n in ["launch", "cdp", "serve"] {
                let b = s.at(&format!("/usr/local/bin/noo-kiosk-{n}"));
                std::fs::write(hk.join(format!("noo-kiosk-{n}")), format!("#!/bin/sh\n# home copy {n}\n")).unwrap();
                std::fs::remove_file(&b).unwrap();
                std::os::unix::fs::symlink(hk.join(format!("noo-kiosk-{n}")), &b).unwrap();
            }
            s
        }
        fn run(&self, kind: SeatScript, state: &str) -> std::process::Output {
            let script = seat_install_script_at(&self.root.to_string_lossy(), &self.work, &self.work.join("noo"), &self.cfg, "alex", kind);
            let sp = self.root.join("_script.sh");
            std::fs::write(&sp, &script).unwrap();
            Command::new("sh").arg(&sp)
                .env("PATH", format!("{}:{}", self.root.join("_shims").display(), std::env::var("PATH").unwrap_or_default()))
                .env("SHIM_LOG", &self.log)
                .env("FAKE_STATE", state)
                .output().unwrap()
        }
        fn log(&self) -> String { std::fs::read_to_string(&self.log).unwrap_or_default() }
        fn unit(&self, n: &str) -> String { std::fs::read_to_string(self.at(&format!("/etc/systemd/system/{n}"))).unwrap_or_default() }
        /// Everything a correct move leaves behind, asserted.
        fn assert_shared_layout(&self) {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = self.at(SEAT_KIOSK_DIR);
            let r = self.root.to_string_lossy();
            let log = self.log();
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777, 0o2750, "the shared dir is 2750");
            assert!(log.contains(&format!("install owner=alex group=kiosk mode=2750 dir=yes dst={r}{SEAT_KIOSK_DIR}\n")), "{log}");
            assert!(log.contains(&format!("install owner=root group=root mode=0755 dir=yes dst={r}{SEAT_OPT_DIR}\n")), "{log}");
            for n in ["launch", "cdp", "serve"] {
                let f = dir.join(format!("noo-kiosk-{n}"));
                assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o750, "{}", f.display());
                assert!(log.contains(&format!("install owner=alex group=kiosk mode=0750 dir=no dst={}\n", f.display())), "{log}");
                let body = std::fs::read_to_string(&f).unwrap();
                assert!(body.contains(&format!("noo-kiosk-{n}")), "the script this noo carries: {}", f.display());
                assert_eq!(std::fs::read_link(self.at(&format!("/usr/local/bin/noo-kiosk-{n}"))).unwrap(),
                    PathBuf::from(format!("{SEAT_KIOSK_DIR}/noo-kiosk-{n}")), "the PATH name leads to the shared dir");
            }
            assert!(self.unit("kiosk.service").lines().any(|l| l == "ExecStart=/opt/noo-seat/kiosk/noo-kiosk-launch"), "{}", self.unit("kiosk.service"));
            assert!(self.unit("kiosk-serve.service").lines().any(|l| l == "ExecStart=/opt/noo-seat/kiosk/noo-kiosk-serve"), "{}", self.unit("kiosk-serve.service"));
            assert!(self.unit("kiosk.service").lines().any(|l| l == "User=kiosk"), "the display user is unchanged");
            // No display unit references anything under a home directory.
            for u in ["kiosk.service", "kiosk-serve.service", "kiosk-watchdog.service"] {
                let t = self.unit(u);
                assert!(!t.contains("/home/") && !t.contains(&self.cfg.cli_home), "{u} references a home path:\n{t}");
            }
            // The root watchdog is untouched: root never runs a seat-writable script.
            assert!(self.unit("kiosk-watchdog.service").contains("ExecStart=/usr/local/bin/noo-kiosk-watchdog"));
            assert!(!self.at("/usr/local/bin/noo-kiosk-watchdog").symlink_metadata().unwrap().file_type().is_symlink());
            assert!(log.contains("systemctl daemon-reload") && log.contains("systemctl restart kiosk-serve.service")
                && log.contains("systemctl restart kiosk.service") && log.contains("systemctl is-active kiosk.service"), "{log}");
            assert_eq!(kiosk_bins_layout(&self.root, &self.cfg.cli_home), "shared");
        }
    }
    impl Drop for FakeRoot {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn the_migration_puts_the_display_in_the_shared_dir_and_checks_it_runs() {
        if !cfg!(target_os = "linux") { return; }
        let f = FakeRoot::new("migrate").with_display();
        assert_eq!(kiosk_bins_layout(&f.root, &f.cfg.cli_home), "root", "setup's root copies");
        let out = f.run(SeatScript::Migrate, "active");
        assert!(out.status.success(), "stdout:\n{}\nstderr:\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        f.assert_shared_layout();
        assert!(String::from_utf8_lossy(&out.stdout).contains("display running from /opt/noo-seat/kiosk"));
        // The seat's own rail landed too, and the timer came back BEFORE the display check.
        let log = f.log();
        assert!(log.find("systemctl enable --now noo-seat-sync.timer").unwrap() < log.find("systemctl restart kiosk.service").unwrap(), "{log}");
        assert!(f.cfg.applier_path().exists(), "the seat's own copy of noo");
        // Nothing is left for the display under the seat user's home.
        assert!(!f.cfg.home_kiosk_dir().exists());
    }

    #[test]
    fn the_root_step_fails_loudly_when_the_display_does_not_come_up() {
        if !cfg!(target_os = "linux") { return; }
        for state in ["activating", "failed"] {
            let f = FakeRoot::new(&format!("dead-{state}")).with_display();
            let out = f.run(SeatScript::Migrate, state);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{state}: a dead display must fail the script:\n{err}");
            assert!(err.contains("THE DISPLAY IS NOT RUNNING") && err.contains(&format!("kiosk.service is '{state}'")), "{err}");
            assert!(err.contains("journalctl -u kiosk.service"), "{err}");
            assert!(!String::from_utf8_lossy(&out.stdout).contains("display running"));
            // It waited the whole window, polling.
            assert_eq!(f.log().matches("systemctl is-active kiosk.service").count(), DISPLAY_SELF_CHECK_SECS as usize);
            // A seat with a dead display still has its sync timer back.
            assert!(f.log().contains("systemctl enable --now noo-seat-sync.timer"));
        }
    }

    /// homeserver after 0.6.10: re-running `--migrate` on the user layout is
    /// the repair — only the display move, the units and the self-check.
    #[test]
    fn re_running_the_migration_repairs_a_display_left_under_a_home_dir() {
        if !cfg!(target_os = "linux") { return; }
        let f = FakeRoot::new("repair").with_home_layout();
        assert_eq!(kiosk_bins_layout(&f.root, &f.cfg.cli_home), "home", "the broken layout is detected");
        let sync = render_sync_service(&f.cfg);
        assert_eq!(migrate_kind(false, Some(&sync), "alex"), SeatScript::Repair);
        let script = seat_install_script_at(&f.root.to_string_lossy(), &f.work, &f.work.join("noo"), &f.cfg, "alex", SeatScript::Repair);
        for absent in ["birth.key", "noo-seat-sync.timer", "disable --now", "polkit", "/var/lib/noo-seat"] {
            assert!(!script.contains(absent), "the repair does only the display move, found {absent}:\n{script}");
        }
        let out = f.run(SeatScript::Repair, "active");
        assert!(out.status.success(), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
        f.assert_shared_layout();
        assert!(!f.cfg.home_kiosk_dir().exists(), "the unreachable home copies are removed");
        // Idempotent: a second run converges to the same layout.
        let again = f.run(SeatScript::Repair, "active");
        assert!(again.status.success(), "stderr:\n{}", String::from_utf8_lossy(&again.stderr));
        f.assert_shared_layout();
    }

    #[test]
    fn a_seat_without_a_display_gets_no_shared_dir_from_enroll() {
        if !cfg!(target_os = "linux") { return; }
        let f = FakeRoot::new("nodisplay");
        let out = f.run(SeatScript::Enroll, "active");
        assert!(out.status.success(), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
        assert!(!f.at(SEAT_KIOSK_DIR).exists());
        assert!(String::from_utf8_lossy(&out.stdout).contains("no kiosk.service on this box yet"));
        assert_eq!(kiosk_bins_layout(&f.root, &f.cfg.cli_home), "absent");
        // Enroll with a display: the same shared dir as the migration.
        let f = FakeRoot::new("enroll-display").with_display();
        assert!(f.run(SeatScript::Enroll, "active").status.success());
        f.assert_shared_layout();
    }

    #[test]
    fn the_full_migration_runs_only_on_the_old_root_layout() {
        let user_unit = render_sync_service(&cfg());
        assert_eq!(migrate_kind(false, Some(&user_unit), "alex"), SeatScript::Repair);
        assert_eq!(migrate_kind(true, Some(&user_unit), "alex"), SeatScript::Migrate, "a root copy left: migrate");
        assert_eq!(migrate_kind(false, Some("[Service]\nExecStart=/usr/local/libexec/noo-seat/noo kiosk seat-sync\n"), "alex"), SeatScript::Migrate);
        assert_eq!(migrate_kind(false, None, "alex"), SeatScript::Migrate);
    }

    #[test]
    fn kiosk_scripts_wait_for_the_shared_dir_and_the_cli_still_updates() {
        let c = cfg();
        let plan = plan_seat_apply(&SEAT_KINDS.iter().map(|k| k.to_string()).collect::<Vec<_>>(), &c).unwrap();
        let (kept, deferred) = defer_kiosk_until_shared_dir(plan.clone(), false);
        assert!(deferred);
        assert!(kept.iter().all(|(k, _)| !k.starts_with("kiosk-")));
        assert!(kept.iter().any(|(k, _)| k == "cli-binary"), "the CLI is not held back with them");
        assert_eq!(defer_kiosk_until_shared_dir(plan.clone(), true), (plan, false));
        let o = ApplyOutcome { cli: "updated", kiosk_deferred: true, ..Default::default() };
        assert_eq!(report_word(&o.line(), "kiosk"), Some("deferred-no-shared-dir"));
        // The writer never creates the shared dir itself.
        let t = Tree::new("noshared");
        std::fs::remove_dir(t.cfg.kiosk_dir()).unwrap();
        let e = install_file(&t.serve(), b"x", &t.cfg).unwrap_err();
        assert!(e.contains("does not exist") && e.contains("seat-sync --migrate"), "{e}");
        assert!(!t.cfg.kiosk_dir().exists());
        // With the dir: 0750.
        std::fs::create_dir_all(t.cfg.kiosk_dir()).unwrap();
        install_file(&t.serve(), b"x", &t.cfg).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(t.serve()).unwrap().permissions().mode() & 0o777, 0o750);
    }

    #[test]
    fn verify_flags_display_binaries_under_a_home_dir_with_the_repair_command() {
        use super::super::cluster_verify::Verdict;
        let seen = "2025-10-09T08:53:10Z";
        let now = super::super::cluster_verify::parse_rfc3339_unix(seen).unwrap() + 10;
        let mut s = json!({"seat_name": "homeserver", "enroll_user": "rbwolf", "last_seen": seen,
            "heartbeat": {"cli_version": "0.6.11", "layout": "user", "user_cli_current": true, "kiosk_serve": "activating",
                          "kiosk_display": "activating", "kiosk_bins": "home", "console_build": ""}});
        let c = seat_checks(&s, "0.6.11", "stack-v0.6.11", now);
        let row = c.iter().find(|c| c.name == "display binaries").expect("a display binaries row");
        assert_eq!(row.verdict, Verdict::Fail, "a dead display is a FAIL");
        assert!(row.detail.contains("display binaries under a home directory the display user cannot reach"), "{}", row.detail);
        assert_eq!(row.remedy.as_deref(), Some("on homeserver: sudo ~rbwolf/.local/libexec/noo-seat/noo kiosk seat-sync --migrate"));
        // Not the 0.6.10 root path, which the migration removed.
        assert!(!row.remedy.as_deref().unwrap().contains(LEGACY_APPLIER_BIN));
        // The user name is taken only when it is a plain account name.
        s["enroll_user"] = json!("x; rm -rf /");
        assert!(seat_checks(&s, "0.6.11", "stack-v0.6.11", now).iter().find(|c| c.name == "display binaries").unwrap()
            .remedy.as_deref().unwrap().contains("~<seat user>/"));
        // Root copies on a user-layout seat: running, but updates never reach them.
        s["heartbeat"]["kiosk_bins"] = json!("root");
        let r = seat_checks(&s, "0.6.11", "stack-v0.6.11", now);
        assert_eq!(r.iter().find(|c| c.name == "display binaries").unwrap().verdict, Verdict::Warn);
        for ok in ["shared", "absent"] {
            s["heartbeat"]["kiosk_bins"] = json!(ok);
            assert!(seat_checks(&s, "0.6.11", "stack-v0.6.11", now).iter().all(|c| c.name != "display binaries"), "{ok}");
        }
    }

    #[test]
    fn seat_units_in_the_bundle_exec_from_the_shared_dir() {
        let params = KioskParams { user: "kiosk".into(), mode: super::super::kiosk::Mode::Dedicated, vt: 1 };
        let files = seat_bundle_files(vec![1], Some(&params), vec![2], &json!({}));
        for (kind, n) in [("unit-kiosk", "launch"), ("unit-kiosk-serve", "serve")] {
            let t = String::from_utf8_lossy(&files.iter().find(|(k, _)| *k == kind).unwrap().1).into_owned();
            assert!(t.lines().any(|l| l == format!("ExecStart=/opt/noo-seat/kiosk/noo-kiosk-{n}")), "{kind}:\n{t}");
        }
    }

    // ── the seat's transport: token URL + trust union ──────────────────

    #[test]
    fn the_token_url_prefers_the_override_then_the_front_door_then_the_gateway() {
        let gw = "https://ctl.tail.ts.net:8080";
        let fd = Some("https://ctl.tail.ts.net/");
        let (u, from) = seat_token_url(Some("https://other.tail.ts.net/"), fd, gw);
        assert_eq!(u, "https://other.tail.ts.net");
        assert_eq!(from, "--controller");
        let (u, from) = seat_token_url(None, fd, gw);
        assert_eq!(u, "https://ctl.tail.ts.net", "the front door wins over the gateway port");
        assert!(from.contains("front door"), "{from}");
        let (u, from) = seat_token_url(None, None, gw);
        assert_eq!(u, gw, "no front door: services.gateway_url");
        assert!(from.contains("gateway_url"), "{from}");
        // An empty override or front door is no answer at all.
        assert_eq!(seat_token_url(Some("  "), Some(""), gw).0, gw);
        // A named instance's front door keeps its mount path (serve strips it).
        assert_eq!(seat_token_url(None, Some("https://ctl.tail.ts.net/obtest"), gw).0, "https://ctl.tail.ts.net/obtest");
    }

    #[test]
    fn a_controller_override_must_be_https_with_a_host() {
        assert!(validate_seat_controller("https://ctl.tail.ts.net").is_ok());
        assert!(validate_seat_controller("https://ctl.tail.ts.net:8080").is_ok());
        for bad in ["http://ctl.tail.ts.net", "ctl.tail.ts.net", "https://", "https:///x"] {
            assert!(validate_seat_controller(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_seat_rail_never_goes_back_to_the_cluster_ca_only_client() {
        // Every seat call (redeem, heartbeat, fetch, fetched, applied) rides
        // `seat_agent`; the node's `ca_agent` trusts the cluster CA alone and
        // refuses the front door's public certificate (homeserver, 10-17).
        let src = include_str!("kiosk_seat.rs");
        let prod = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(!prod.contains("enroll::ca_agent("), "a seat call uses the cluster-CA-only client");
        assert_eq!(prod.matches("seat_agent(&").count(), 2, "redeem + seat-sync both use seat_agent");
    }

    struct TestCa {
        cert: rcgen::Certificate,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn test_ca(name: &str) -> TestCa {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        TestCa { cert, issuer: rcgen::Issuer::new(p, key) }
    }

    /// A 127.0.0.1 leaf signed by `ca`.
    fn leaf(ca: &TestCa) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        p.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &ca.issuer).unwrap();
        (cert.der().clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
    }

    /// A fake controller door: TLS with `ca`'s leaf, no client-certificate
    /// request (what `tailscale serve` does), answering 200 `{"status":"ok"}`
    /// and recording each `<METHOD> <path> <birth-proof?> <body>` it served.
    fn fake_door(ca: &TestCa) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read as _, Write as _};
        use std::sync::{Arc, Mutex};
        let (cert, key) = leaf(ca);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = Arc::new(rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                let Ok(conn) = rustls::ServerConnection::new(cfg.clone()) else { continue };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                        let len = head.lines()
                            .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                if buf.is_empty() {
                    continue; // a refused handshake
                }
                let raw = String::from_utf8_lossy(&buf).to_string();
                let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
                let first = head.lines().next().unwrap_or("").to_string();
                let proof = head.lines().any(|l| l.to_ascii_lowercase().starts_with("x-noo-birth-proof:"));
                let mut parts = first.split(' ');
                let line = format!("{} {} {} {body}", parts.next().unwrap_or(""), parts.next().unwrap_or(""),
                    if proof { "proof" } else { "-" });
                seen2.lock().unwrap().push(line);
                let out = r#"{"status":"ok"}"#;
                let _ = write!(tls, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        (format!("https://127.0.0.1:{port}"), seen)
    }

    fn der_cert(ca: &TestCa) -> ureq::tls::Certificate<'static> {
        ureq::tls::Certificate::from_der(ca.cert.der().as_ref()).to_owned()
    }

    #[test]
    fn the_seat_client_trusts_public_roots_and_the_cluster_ca_and_nothing_else() {
        let cluster = test_ca("noo cluster CA (test)");
        let public = test_ca("Test Public Root");
        let stranger = test_ca("someone else's private CA");
        let agent = seat_agent_with(cluster.cert.pem().as_bytes(), vec![der_cert(&public)], 10).unwrap();
        let get = |url: &str| agent.get(&format!("{url}/bootstrap/seat/lobby/bundle")).call().map(|r| r.status().as_u16());

        let (front_door, _) = fake_door(&public);
        assert_eq!(get(&front_door).expect("a public-root front door is trusted"), 200);
        let (gateway_port, _) = fake_door(&cluster);
        assert_eq!(get(&gateway_port).expect("the gateway's cluster-CA leaf is still trusted"), 200);
        let (other, seen) = fake_door(&stranger);
        let e = get(&other).expect_err("an unrelated private CA must be refused").to_string();
        assert!(e.contains("UnknownIssuer") || e.to_lowercase().contains("certificate"), "{e}");
        assert!(seen.lock().unwrap().is_empty(), "nothing was sent to the refused server");

        // The node's cluster-CA-only client is exactly what failed live: it
        // refuses the front door the seat client accepts.
        let node_only = super::super::enroll::ca_agent(cluster.cert.pem().as_bytes(), 10).unwrap();
        let e = node_only.get(&format!("{front_door}/bootstrap/ca.crt")).call().expect_err("cluster CA alone refuses a public cert");
        assert!(e.to_string().contains("UnknownIssuer"), "{e}");
    }

    #[test]
    fn a_seat_enrolls_and_syncs_through_a_public_cert_front_door() {
        // The homeserver shape: the seat reaches only the `tailscale serve`
        // door (public cert, no client-certificate request). Redeem, then the
        // signed rail calls the timer makes, all over the one seat client.
        let cluster = test_ca("noo cluster CA (test)");
        let public = test_ca("Test Public Root");
        let (door, seen) = fake_door(&public);
        let agent = seat_agent_with(cluster.cert.pem().as_bytes(), vec![der_cert(&public)], 10).unwrap();

        let body = json!({"token": "noo-st-abc", "seat_name": "lobby", "birth_cert": "-----BEGIN CERTIFICATE-----"});
        let mut r = agent.post(&format!("{door}/api/cluster/seat-enroll")).send_json(&body).expect("redeem over the front door");
        assert_eq!(r.status().as_u16(), 200);
        assert!(r.body_mut().read_to_string().unwrap().contains("ok"));
        for (path, sig) in [("heartbeat", true), ("fetched", true), ("applied", true)] {
            let st = agent.post(&format!("{door}/bootstrap/seat/lobby/{path}"))
                .header("content-type", "application/json")
                .header("x-noo-birth-proof", if sig { "1.c2ln" } else { "" })
                .send(&br#"{"sha":"x"}"#[..]).expect(path).status().as_u16();
            assert_eq!(st, 200, "{path}");
        }
        let st = agent.get(&format!("{door}/bootstrap/seat/lobby/bundle")).header("x-noo-birth-proof", "1.c2ln").call().unwrap().status().as_u16();
        assert_eq!(st, 200);

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 5, "{seen:?}");
        assert!(seen[0].starts_with("POST /api/cluster/seat-enroll - ") && seen[0].contains("noo-st-abc"), "{}", seen[0]);
        for (i, p) in ["heartbeat", "fetched", "applied"].iter().enumerate() {
            assert!(seen[i + 1].starts_with(&format!("POST /bootstrap/seat/lobby/{p} proof ")), "{}", seen[i + 1]);
        }
        assert!(seen[4].starts_with("GET /bootstrap/seat/lobby/bundle proof"), "{}", seen[4]);
    }
}
