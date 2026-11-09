// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo node workloads approve | revoke | list` (i573): the node owner's
//! consent to run an add-on's node workloads, kept where the node agent reads
//! it: `<NOO_AGENT_STATE>/addon-workload-approvals.json`
//! (node-agent-go/internal/nodepolicy/consent.go; same schema, version 1).
//!
//! Consent is the node owner's alone. These verbs run ON the node, as root,
//! and write the store directly. They do not go through noo-hostd: its worker
//! spool is writable by the agent's group, and the agent is what the
//! controller drives, so a hostd "approve" op would let the controller grant
//! consent to itself. Nothing on the controller can call these verbs.
//!
//! The store is held to the agent's rules and to its own:
//!   * one exact image digest per approval (`sha256:<64 lower-case hex>`),
//!     never a pattern;
//!   * the state directory is opened O_NOFOLLOW and the file only by
//!     `openat` on that descriptor, so neither is reached through a symlink;
//!   * a store that does not parse is refused and left as it is, never
//!     replaced by a fresh one (that would drop the owner's approvals);
//!   * the new store is a temp file created O_EXCL|O_NOFOLLOW, 0600, chowned
//!     to the node agent by descriptor, fsynced, then renamed over the old.
//!
//! The policy needs nothing here: an unset NOO_ADDON_WORKLOADS is `approve`
//! (an approve node with no approval runs nothing), so an approval is the
//! whole of consent and survives a roll that rewrites /etc/noo-node-agent.env.
//! An explicit `none` there is the owner's kill switch.

use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::args::{ArgError, Args};
use crate::output::{self, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// The store's file name in the agent's state directory (consent.go ApprovalsFile).
pub(crate) const APPROVALS_FILE: &str = "addon-workload-approvals.json";
/// The account the node agent runs as (deploy/noo-node-agent.service).
const AGENT_USER: &str = "noo-agent";
/// The agent's environment (rendered by `noo cluster provision`).
const AGENT_ENV: &str = "/etc/noo-node-agent.env";
/// NOO_AGENT_STATE's default (node-agent-go/internal/config).
const DEFAULT_STATE_DIR: &str = "/var/lib/noo-node-agent";
/// A store bigger than this is not one this CLI wrote.
const MAX_STORE_BYTES: u64 = 1 << 20;

/// One approval: an add-on at one image digest (consent.go Approval).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub addon: String,
    pub digest: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Doc {
    version: u32,
    approvals: Vec<Approval>,
}

/// consent.go addonRe: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`.
pub(crate) fn valid_addon(s: &str) -> bool {
    let b = s.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= 63
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| edge(c) || c == b'-')
}

/// consent.go digestRe: `^sha256:[0-9a-f]{64}$`. One exact digest; there
/// is no pattern, prefix or "any" form.
pub(crate) fn valid_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// The approval asked for, or why it is refused (before anything is read).
pub(crate) fn requested(addon: &str, digest: &str) -> Result<Approval, String> {
    if !valid_addon(addon) {
        return Err(format!("`{addon}` is not an add-on name (lower-case letters, digits and inner dashes, at most 63)"));
    }
    if !valid_digest(digest) {
        return Err(format!(
            "`{digest}` is not one exact image digest: give sha256:<64 lower-case hex>, as the placement's refusal names it"
        ));
    }
    Ok(Approval { addon: addon.to_string(), digest: digest.to_string() })
}

/// Parse a store. Anything the agent would not read (bad JSON, an unknown
/// field, a version other than 1, a malformed entry) is an error.
pub(crate) fn parse(text: &str) -> Result<Vec<Approval>, String> {
    let doc: Doc = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if doc.version != 1 {
        return Err(format!("version {} (this noo reads and writes version 1)", doc.version));
    }
    for a in &doc.approvals {
        if !valid_addon(&a.addon) || !valid_digest(&a.digest) {
            return Err(format!("entry {}@{} is not an add-on and an exact digest", a.addon, a.digest));
        }
    }
    Ok(doc.approvals)
}

/// The store's bytes for `list`: version 1, sorted as the agent sorts
/// (add-on, then digest), each pair once.
pub(crate) fn render(list: &[Approval]) -> String {
    let mut approvals = list.to_vec();
    approvals.sort();
    approvals.dedup();
    let mut s = serde_json::to_string(&Doc { version: 1, approvals }).unwrap_or_default();
    s.push('\n');
    s
}

/// Add `a`; false when it was already there.
pub(crate) fn approve_in(list: &mut Vec<Approval>, a: Approval) -> bool {
    if list.contains(&a) {
        return false;
    }
    list.push(a);
    true
}

/// Remove exactly `a`; false when it was not there.
pub(crate) fn revoke_in(list: &mut Vec<Approval>, a: &Approval) -> bool {
    let before = list.len();
    list.retain(|x| x != a);
    list.len() != before
}

fn cstr(s: &str) -> CString {
    // Only constant names and a pid go through here: no NUL byte.
    CString::new(s).unwrap_or_default()
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// The agent's state directory, held open so nothing in it is reached
/// through a symlink.
pub(crate) struct StateDir {
    fd: OwnedFd,
    path: PathBuf,
}

impl StateDir {
    /// Open `path` itself O_NOFOLLOW. Refused when it is a symlink, not a
    /// directory, writable by everyone, or (with `agent_uid`) owned by
    /// anyone but root or the agent.
    pub(crate) fn open(path: &Path, agent_uid: Option<u32>) -> Result<StateDir, String> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{}: not a path", path.display()))?;
        // SAFETY: c is a valid NUL-terminated path; the result is checked.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                    format!("{} is not a plain directory (a symlink?); refusing to keep consent through it", path.display())
                }
                Some(libc::ENOENT) => format!("{} does not exist: is the node agent installed on this box?", path.display()),
                _ => format!("{}: {e}", path.display()),
            });
        }
        // SAFETY: fd is a freshly opened descriptor this function owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let dir = std::fs::File::from(fd);
        let md = dir.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
        if md.mode() & 0o002 != 0 {
            return Err(format!("{} is writable by everyone; refusing to keep consent there", path.display()));
        }
        if let Some(uid) = agent_uid {
            if md.uid() != 0 && md.uid() != uid {
                return Err(format!(
                    "{} is owned by uid {}, not root or {AGENT_USER}; refusing to keep consent there",
                    path.display(),
                    md.uid()
                ));
            }
        }
        Ok(StateDir { fd: OwnedFd::from(dir), path: path.to_path_buf() })
    }

    fn file(&self) -> PathBuf {
        self.path.join(APPROVALS_FILE)
    }

    /// The approvals. A missing store is empty; a symlink, a non-file, an
    /// unreadable or corrupt store is an error.
    pub(crate) fn read(&self) -> Result<Vec<Approval>, String> {
        let name = cstr(APPROVALS_FILE);
        // SAFETY: a valid dirfd and NUL-terminated name; the result is checked.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(Vec::new()),
                Some(libc::ELOOP) => Err(format!("{} is a symlink; refusing to read or replace it", self.file().display())),
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    Err(format!("{}: permission denied (run it with sudo)", self.file().display()))
                }
                _ => Err(format!("{}: {e}", self.file().display())),
            };
        }
        // SAFETY: fd is a freshly opened descriptor this function owns.
        let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let md = f.metadata().map_err(|e| format!("{}: {e}", self.file().display()))?;
        if !md.file_type().is_file() {
            return Err(format!("{} is not a regular file; refusing to read or replace it", self.file().display()));
        }
        if md.len() > MAX_STORE_BYTES {
            return Err(format!("{} is {} bytes, not a store this noo wrote; refusing to change it", self.file().display(), md.len()));
        }
        let mut text = String::new();
        f.read_to_string(&mut text).map_err(|e| format!("{}: {e}", self.file().display()))?;
        parse(&text).map_err(|why| {
            format!(
                "{} is corrupt ({why}); refusing to change it, so no approval is lost. Fix or remove it by hand",
                self.file().display()
            )
        })
    }

    /// Replace the store with `list`: a temp file beside it (O_EXCL,
    /// O_NOFOLLOW, 0600, chowned to `owner` by descriptor, fsynced), renamed
    /// over the store on the same directory descriptor.
    pub(crate) fn write(&self, list: &[Approval], owner: Option<(u32, u32)>) -> Result<(), String> {
        let dirfd = self.fd.as_raw_fd();
        let tmp = cstr(&format!(".{APPROVALS_FILE}.{}.tmp", std::process::id()));
        let name = cstr(APPROVALS_FILE);
        // A temp a killed run left: unlinkat removes the name, never what a
        // symlink there points at.
        // SAFETY: valid dirfd and NUL-terminated name.
        unsafe { libc::unlinkat(dirfd, tmp.as_ptr(), 0) };
        // SAFETY: valid dirfd and name; mode is the variadic third argument.
        let fd = unsafe {
            libc::openat(
                dirfd,
                tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(os_err(&format!("create a temp store in {}", self.path.display())));
        }
        // SAFETY: fd is a freshly opened descriptor this function owns.
        let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let wrote = (|| -> std::io::Result<()> {
            f.write_all(render(list).as_bytes())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
            }
            f.sync_all()
        })();
        drop(f);
        let undo = || {
            // SAFETY: valid dirfd and NUL-terminated name.
            unsafe { libc::unlinkat(dirfd, tmp.as_ptr(), 0) };
        };
        if let Err(e) = wrote {
            undo();
            return Err(format!("write the store in {}: {e}", self.path.display()));
        }
        // SAFETY: valid dirfd and NUL-terminated names.
        if unsafe { libc::renameat(dirfd, tmp.as_ptr(), dirfd, name.as_ptr()) } != 0 {
            let e = os_err(&format!("replace {}", self.file().display()));
            undo();
            return Err(e);
        }
        // SAFETY: valid dirfd; a failed directory fsync loses no data already renamed.
        unsafe { libc::fsync(dirfd) };
        Ok(())
    }
}

/// Approve `a` in the store under `dir`. Ok(false) when it was already approved.
pub(crate) fn approve_at(dir: &Path, a: Approval, agent: Option<(u32, u32)>) -> Result<bool, String> {
    let sd = StateDir::open(dir, agent.map(|(u, _)| u))?;
    let mut list = sd.read()?;
    if !approve_in(&mut list, a) {
        return Ok(false);
    }
    sd.write(&list, agent)?;
    Ok(true)
}

/// Revoke exactly `a` in the store under `dir`. Ok(false) when it was not there.
pub(crate) fn revoke_at(dir: &Path, a: &Approval, agent: Option<(u32, u32)>) -> Result<bool, String> {
    let sd = StateDir::open(dir, agent.map(|(u, _)| u))?;
    let mut list = sd.read()?;
    if !revoke_in(&mut list, a) {
        return Ok(false);
    }
    sd.write(&list, agent)?;
    Ok(true)
}

/// `KEY`'s last value in an env file's text (`KEY=VALUE`, optional `export`
/// and quotes). None when unset or empty.
pub(crate) fn env_value(text: &str, key: &str) -> Option<String> {
    let mut out = None;
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            let v = v.trim().trim_matches('"').trim_matches('\'').trim();
            out = (!v.is_empty()).then(|| v.to_string());
        }
    }
    out
}

/// The agent's environment file, when it can be read (root can).
fn agent_env() -> String {
    std::fs::read_to_string(AGENT_ENV).unwrap_or_default()
}

/// Where the agent keeps its state: NOO_AGENT_STATE from this process, then
/// from the agent's environment file, then the agent's default.
fn state_dir() -> PathBuf {
    std::env::var("NOO_AGENT_STATE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| env_value(&agent_env(), "NOO_AGENT_STATE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
}

/// The policy the agent reads, in words, and whether an approval admits anything.
pub(crate) fn policy_words(raw: Option<&str>) -> (String, bool) {
    match raw.map(|v| v.trim().to_ascii_lowercase()) {
        None => ("approve (the default)".to_string(), true),
        Some(v) if v == "approve" => ("approve".to_string(), true),
        Some(v) if v == "auto" => ("auto (every placement runs; approvals are not consulted)".to_string(), true),
        Some(v) if v == "none" => ("none (the owner's kill switch: nothing runs, approved or not)".to_string(), false),
        Some(v) => (format!("`{v}`, which the agent reads as none (nothing runs)"), false),
    }
}

/// The agent account's (uid, gid).
fn agent_account() -> Option<(u32, u32)> {
    let c = CString::new(AGENT_USER).ok()?;
    // SAFETY: getpwnam reads the password database; the fields are copied
    // out before anything else can call it.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: pw is non-null and points at the static record getpwnam returned.
    Some(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

/// What the approve and revoke verbs read from the box they run on. The
/// entry points use [`Node::this`]; tests drive the same entry points with a
/// scratch node, so a test exercises the real command line, not a helper.
pub(crate) struct Node {
    pub euid: u32,
    pub agent: Option<(u32, u32)>,
    pub state: PathBuf,
    pub env: String,
    /// This `noo`, by its full path: root's PATH (secure_path) usually lacks
    /// `~/.local/bin`, so a bare `sudo noo` is "command not found" there.
    pub exe: String,
}

impl Node {
    fn this() -> Node {
        Node {
            // SAFETY: geteuid has no preconditions.
            euid: unsafe { libc::geteuid() },
            agent: agent_account(),
            state: state_dir(),
            env: agent_env(),
            exe: std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "noo".to_string()),
        }
    }
}

/// A word the shell reads as itself; anything else is single-quoted.
fn shell_word(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+:@%=,".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The exact command to run again as root, with this `noo` by its full path.
pub(crate) fn as_root(exe: &str, verb: &str, addon: &str, digest: &str) -> String {
    format!("sudo {} node workloads {verb} {addon} {digest}", shell_word(exe))
}

/// `command` is the whole command in backticks, spelled out at each call
/// site: the hint lint checks every suggested command, and cannot resolve a
/// template. `again` is the command to copy, from [`as_root`].
fn need_root(g: &Globals, node: &Node, command: &str, again: &str) {
    if node.euid != 0 {
        output::fail(
            g.json,
            ExitCode::Generic,
            "needs_root",
            &format!("{command} changes this node's consent store, which only root and the node agent may write"),
            Some(&format!("run it on the node as root, with noo by its full path (root's PATH may not reach it): {again}")),
        );
    }
}

fn agent_or_fail(g: &Globals, node: &Node) -> (u32, u32) {
    node.agent.unwrap_or_else(|| {
        output::fail(
            g.json,
            ExitCode::Generic,
            "no_agent",
            &format!("there is no `{AGENT_USER}` account on this box: is it a noomesh node?"),
            None,
        )
    })
}

fn pair(args: &[String]) -> Result<(String, String), ArgError> {
    let mut a = Args::new(args);
    let positional = a.positionals()?;
    match positional.as_slice() {
        [] => Err(ArgError::new("missing <addon>")),
        [_] => Err(ArgError::new("missing <digest>")),
        [addon, digest] => Ok((addon.clone(), digest.clone())),
        [_, _, extra, ..] => Err(ArgError::new(format!("unexpected argument `{extra}` after <digest>"))),
    }
}

fn request_or_fail(g: &Globals, addon: &str, digest: &str) -> Approval {
    requested(addon, digest).unwrap_or_else(|why| output::fail(g.json, ExitCode::Usage, "bad_approval", &why, None))
}

fn store_fail(g: &Globals, why: &str) -> ! {
    output::fail(g.json, ExitCode::Generic, "approvals_store", why, None)
}

/// `noo node workloads approve <addon> <digest>`
pub fn node_workloads_approve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    approve_on(g, args, &Node::this())
}

pub(crate) fn approve_on(g: &Globals, args: &[String], node: &Node) -> Result<i32, Unhandled> {
    let (addon, digest) = pair(args)?;
    let a = request_or_fail(g, &addon, &digest);
    need_root(g, node, "`noo node workloads approve <addon> <digest>`", &as_root(&node.exe, "approve", &addon, &digest));
    let agent = agent_or_fail(g, node);
    let added = approve_at(&node.state, a, Some(agent)).unwrap_or_else(|why| store_fail(g, &why));
    let (policy, admits) = policy_words(env_value(&node.env, "NOO_ADDON_WORKLOADS").as_deref());
    if g.json {
        println!("{}", serde_json::json!({"addon": addon, "digest": digest, "approved": true, "already": !added, "policy": policy}));
        return Ok(0);
    }
    if added {
        ui::done(&format!("approved {addon} at {digest} on this node"));
    } else {
        ui::done(&format!("{addon} at {digest} was already approved on this node"));
    }
    println!("{}", ui::muted(&format!("policy: {policy}")));
    if !admits {
        println!("{}", ui::muted("this approval admits nothing until NOO_ADDON_WORKLOADS is unset or approve"));
    }
    Ok(0)
}

/// `noo node workloads revoke <addon> <digest>`
pub fn node_workloads_revoke(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    revoke_on(g, args, &Node::this())
}

pub(crate) fn revoke_on(g: &Globals, args: &[String], node: &Node) -> Result<i32, Unhandled> {
    let (addon, digest) = pair(args)?;
    let a = request_or_fail(g, &addon, &digest);
    need_root(g, node, "`noo node workloads revoke <addon> <digest>`", &as_root(&node.exe, "revoke", &addon, &digest));
    let agent = agent_or_fail(g, node);
    let removed = revoke_at(&node.state, &a, Some(agent)).unwrap_or_else(|why| store_fail(g, &why));
    if !removed {
        output::fail(
            g.json,
            ExitCode::Generic,
            "not_approved",
            &format!("{addon} at {digest} is not approved on this node; nothing was changed"),
            Some("`noo node workloads list` shows what is approved"),
        );
    }
    if g.json {
        println!("{}", serde_json::json!({"addon": addon, "digest": digest, "revoked": true}));
        return Ok(0);
    }
    ui::done(&format!("revoked {addon} at {digest} on this node"));
    Ok(0)
}

/// `noo node workloads list`
pub fn node_workloads_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    Args::new(args).finish()?;
    let dir = state_dir();
    let agent = agent_account();
    let list = StateDir::open(&dir, agent.map(|(u, _)| u))
        .and_then(|sd| sd.read())
        .unwrap_or_else(|why| store_fail(g, &why));
    let mut list = list;
    list.sort();
    let (policy, _) = policy_words(env_value(&agent_env(), "NOO_ADDON_WORKLOADS").as_deref());
    if g.json {
        println!("{}", serde_json::json!({"policy": policy, "approvals": list}));
        return Ok(0);
    }
    println!("{}", ui::header("node workload approvals", Some(&format!("policy: {policy}"))));
    if list.is_empty() {
        println!("{}", ui::muted("none — no add-on's node workload runs on this node"));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = list.iter().map(|a| vec![a.addon.clone(), a.digest.clone()]).collect();
    println!("{}", ui::table(&[ui::Col::left("add-on"), ui::Col::left("image digest")], &rows));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const D1: &str = "sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844b";
    const D2: &str = "sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241";

    #[test]
    fn consent_commands_accept_addon_and_digest_positionals() {
        // approve and revoke share this parser. Args::one would reject the
        // second positional before either command could reach its root check.
        let args = vec!["rhaddon".to_string(), D1.to_string()];
        assert_eq!(pair(&args).unwrap(), ("rhaddon".to_string(), D1.to_string()));
    }

    #[test]
    fn consent_commands_refuse_missing_extra_and_unknown_arguments() {
        for (args, expected) in [
            (vec![], "missing <addon>"),
            (vec!["rhaddon"], "missing <digest>"),
            (vec!["rhaddon", D1, "extra"], "unexpected argument `extra` after <digest>"),
            (vec!["rhaddon", D1, "--force"], "unknown flag `--force`"),
            (vec!["--force", "rhaddon", D1], "unknown flag `--force`"),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            assert_eq!(pair(&args).unwrap_err().to_string(), expected);
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-node-wl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn me() -> (u32, u32) {
        // SAFETY: no preconditions.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    fn ap(addon: &str, digest: &str) -> Approval {
        Approval { addon: addon.to_string(), digest: digest.to_string() }
    }

    fn stored(dir: &Path) -> Vec<Approval> {
        parse(&std::fs::read_to_string(dir.join(APPROVALS_FILE)).unwrap()).unwrap()
    }

    #[test]
    fn an_approval_names_one_exact_digest_and_never_a_pattern() {
        assert!(requested("rhaddon", D1).is_ok());
        for bad in [
            "sha256:*",
            "*",
            "sha256:",
            "",
            "sha256:2C99870B2514D9E143C3F33F3D5A9B4CBE89516E32343E5AC9C1379A9123844B",
            "sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844",
            "sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844bb",
            "sha512:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844b",
            "2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844b",
            " sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844b",
            "sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a91238*",
        ] {
            assert!(requested("rhaddon", bad).is_err(), "{bad:?} must be refused");
        }
        let too_long = "a".repeat(64);
        for bad in ["", "Rhaddon", "-rh", "rh-", "rh_addon", "rh/addon", "*", too_long.as_str()] {
            assert!(requested(bad, D1).is_err(), "add-on {bad:?} must be refused");
        }
        assert!(requested(&"a".repeat(63), D1).is_ok());
    }

    #[test]
    fn approve_keeps_every_existing_approval_and_writes_the_agents_schema() {
        let d = scratch("keep");
        assert_eq!(approve_at(&d, ap("rhaddon", D1), Some(me())), Ok(true));
        assert_eq!(approve_at(&d, ap("other", D2), Some(me())), Ok(true));
        assert_eq!(approve_at(&d, ap("rhaddon", D1), Some(me())), Ok(false), "approving twice changes nothing");
        assert_eq!(stored(&d), vec![ap("other", D2), ap("rhaddon", D1)]);
        let text = std::fs::read_to_string(d.join(APPROVALS_FILE)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v, serde_json::json!({"version": 1, "approvals": [
            {"addon": "other", "digest": D2}, {"addon": "rhaddon", "digest": D1}]}));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn revoke_removes_exactly_that_approval() {
        let d = scratch("revoke");
        approve_at(&d, ap("rhaddon", D1), Some(me())).unwrap();
        approve_at(&d, ap("rhaddon", D2), Some(me())).unwrap();
        assert_eq!(revoke_at(&d, &ap("rhaddon", D1), Some(me())), Ok(true));
        assert_eq!(stored(&d), vec![ap("rhaddon", D2)], "only the revoked digest is gone");
        assert_eq!(revoke_at(&d, &ap("rhaddon", D1), Some(me())), Ok(false), "revoking it again finds nothing");
        assert_eq!(revoke_at(&d, &ap("rhaddon", D2), Some(me())), Ok(true));
        assert_eq!(stored(&d), Vec::<Approval>::new());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_corrupt_store_is_refused_and_left_exactly_as_it_was() {
        for (tag, body) in [
            ("json", "not json ["),
            ("field", r#"{"version":1,"approvals":[],"extra":true}"#),
            ("version", r#"{"version":2,"approvals":[]}"#),
            ("entry", r#"{"version":1,"approvals":[{"addon":"rhaddon","digest":"sha256:*"}]}"#),
            ("empty", ""),
        ] {
            let d = scratch(&format!("corrupt-{tag}"));
            std::fs::write(d.join(APPROVALS_FILE), body).unwrap();
            let err = approve_at(&d, ap("rhaddon", D1), Some(me())).expect_err(tag);
            assert!(err.contains("corrupt"), "{tag}: {err}");
            assert_eq!(std::fs::read_to_string(d.join(APPROVALS_FILE)).unwrap(), body, "{tag}: the store was changed");
            assert!(revoke_at(&d, &ap("rhaddon", D1), Some(me())).is_err(), "{tag}: revoke too");
            assert_eq!(std::fs::read_to_string(d.join(APPROVALS_FILE)).unwrap(), body, "{tag}: revoke changed it");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn a_store_that_is_a_symlink_is_refused_and_its_target_is_untouched() {
        let d = scratch("link-file");
        let elsewhere = scratch("link-file-target");
        let target = elsewhere.join("victim.json");
        let good = render(&[ap("other", D2)]);
        std::fs::write(&target, &good).unwrap();
        symlink(&target, d.join(APPROVALS_FILE)).unwrap();
        let err = approve_at(&d, ap("rhaddon", D1), Some(me())).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(StateDir::open(&d, Some(me().0)).unwrap().read().is_err(), "list refuses it too");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), good, "the link's target was written");
        assert!(std::fs::symlink_metadata(d.join(APPROVALS_FILE)).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn a_state_directory_that_is_a_symlink_is_refused() {
        let real = scratch("link-dir-real");
        let base = scratch("link-dir");
        let link = base.join("state");
        symlink(&real, &link).unwrap();
        let err = approve_at(&link, ap("rhaddon", D1), Some(me())).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(!real.join(APPROVALS_FILE).exists(), "nothing is written through the link");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&real);
    }

    #[test]
    fn a_state_directory_others_control_is_refused() {
        let d = scratch("open-dir");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = approve_at(&d, ap("rhaddon", D1), Some(me())).unwrap_err();
        assert!(err.contains("writable by everyone"), "{err}");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Owned by someone who is neither root nor the agent.
        let (uid, gid) = me();
        let (owner, agent) = if uid == 0 {
            std::os::unix::fs::chown(&d, Some(65534), Some(65534)).unwrap();
            (65534, 65533)
        } else {
            (uid, uid + 1)
        };
        let err = approve_at(&d, ap("rhaddon", D1), Some((agent, gid))).unwrap_err();
        assert!(err.contains(&format!("owned by uid {owner}")), "{err}");
        assert!(!d.join(APPROVALS_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_store_is_private_to_the_node_agent() {
        let d = scratch("owner");
        // As root (the batch) the store is handed to another account, as the
        // real verb hands it to noo-agent; unprivileged, to this user.
        let owner = if me().0 == 0 { (65534, 65534) } else { me() };
        if me().0 == 0 {
            std::os::unix::fs::chown(&d, Some(0), Some(0)).unwrap();
        }
        approve_at(&d, ap("rhaddon", D1), Some(owner)).unwrap();
        let md = std::fs::metadata(d.join(APPROVALS_FILE)).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
        assert_eq!((md.uid(), md.gid()), owner);
        let leftovers: Vec<_> = std::fs::read_dir(&d).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        assert_eq!(leftovers.len(), 1, "no temp file is left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_policy_reads_from_the_agent_env_and_unset_is_approve() {
        assert_eq!(env_value("A=1\nNOO_ADDON_WORKLOADS=none\n", "NOO_ADDON_WORKLOADS").as_deref(), Some("none"));
        assert_eq!(env_value("export NOO_ADDON_WORKLOADS=\"auto\"\n", "NOO_ADDON_WORKLOADS").as_deref(), Some("auto"));
        assert_eq!(env_value("NOO_ADDON_WORKLOADS=\n", "NOO_ADDON_WORKLOADS"), None);
        assert_eq!(env_value("NOO_ADDON_WORKLOADS_ON_CONTROLLER=1\n", "NOO_ADDON_WORKLOADS"), None);
        assert!(policy_words(None).1 && policy_words(Some("approve")).1);
        assert!(!policy_words(Some("none")).1 && !policy_words(Some("yes")).1);
    }

    fn words(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn quiet() -> Globals {
        Globals { json: true, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true }
    }

    /// A node whose state is a scratch directory and whose agent is this
    /// test's own account; root, as `sudo` makes the real verb.
    fn scratch_node(tag: &str) -> Node {
        Node { euid: 0, agent: Some(me()), state: scratch(tag), env: String::new(), exe: "/home/alex/.local/bin/noo".to_string() }
    }

    #[test]
    fn approve_takes_the_addon_and_the_digest_from_its_command_line() {
        let n = scratch_node("entry-approve");
        assert_eq!(approve_on(&quiet(), &words(&["rhaddon", D1]), &n).ok(), Some(0));
        assert_eq!(stored(&n.state), vec![ap("rhaddon", D1)]);
        let _ = std::fs::remove_dir_all(&n.state);
    }

    #[test]
    fn revoke_takes_the_addon_and_the_digest_from_its_command_line() {
        let n = scratch_node("entry-revoke");
        approve_at(&n.state, ap("rhaddon", D1), Some(me())).unwrap();
        approve_at(&n.state, ap("rhaddon", D2), Some(me())).unwrap();
        assert_eq!(revoke_on(&quiet(), &words(&["rhaddon", D1]), &n).ok(), Some(0));
        assert_eq!(stored(&n.state), vec![ap("rhaddon", D2)]);
        let _ = std::fs::remove_dir_all(&n.state);
    }

    #[test]
    fn the_root_hint_names_this_noo_by_its_full_path() {
        assert_eq!(
            as_root("/home/alex/.local/bin/noo", "approve", "rhaddon", D1),
            format!("sudo /home/alex/.local/bin/noo node workloads approve rhaddon {D1}")
        );
        assert_eq!(
            as_root("/home/al ex/bin/noo", "revoke", "rhaddon", D1),
            format!("sudo '/home/al ex/bin/noo' node workloads revoke rhaddon {D1}")
        );
    }
}
