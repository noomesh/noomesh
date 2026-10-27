// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The jail every foreign CLI runs in (i119). A vendor CLI's file tools act
//! at the model's direction — i.e. at the direction of whoever wrote the
//! task — so the process the driver starts may reach the task's own
//! workspace, its HOME and TMP, and the system trees a runtime needs, and
//! NOTHING else: not the node's key pair (`/etc/noo/pki/nodes`), not the
//! env files (`/etc/noo-*.env`), not the harness's secret files
//! (`/etc/noo/harness-secrets`), not the data root, `/run`, the docker
//! socket, `/home` or `/root`.
//!
//! **Fail closed.** [`command`] either returns a `Command` that will exec
//! the CLI confined, or a [`Refusal`]; there is no unconfined path. A
//! refusal becomes the loop's note ([`Refusal::note`]) and is logged as
//! `harness_jail_refused`.
//!
//! ## Linux: Landlock
//!
//! Raw syscalls through `libc`, not the `landlock` crate: the crate's
//! `restrict_self` consumes the ruleset and builds a status value, and what
//! runs in `pre_exec` (after `fork`, before `exec`, in a child of a
//! multi-threaded process) must be async-signal-safe — no allocation, no
//! locks. So the PARENT builds the whole ruleset (`landlock_create_ruleset`
//! + one `landlock_add_rule` per path, every path opened `O_PATH`) and the
//! CHILD makes exactly two syscalls: `prctl(PR_SET_NO_NEW_PRIVS)` and
//! `landlock_restrict_self(fd)`. The ruleset fd is `O_CLOEXEC` (the kernel
//! creates it so), so it does not survive into the CLI.
//!
//! The ruleset handles every filesystem right the running kernel's ABI
//! knows (v1 … v5+: `REFER` from v2, `TRUNCATE` from v3, `IOCTL_DEV` from
//! v5), so an access the rules do not grant is denied. ABI v1 is the floor:
//! no Landlock, Landlock disabled at boot, or a seccomp filter that hides
//! the syscalls is a refusal.
//!
//! The network is NOT restricted (ABI v4 net rules exist but are not
//! used): the CLI must reach the loopback translator, whose port is
//! ephemeral, and the gateway's user door, whose port is the cluster's.
//!
//! **Other processes' environment.** `/proc` is readable, because runtimes
//! read `/proc/self/*`. Landlock also scopes ptrace: a sandboxed process may
//! only ptrace — and pass a `PTRACE_MODE_READ` check against — a process in
//! its own domain or a nested one (kernel docs, "Landlock: unprivileged
//! access control", *Ptrace restrictions*). `/proc/<pid>/environ`, `mem`,
//! `fd/*` and `root` are all gated on that check (`mm_access` /
//! `ptrace_may_access`), so the CLI cannot read the harness's environment,
//! nor a sibling task's CLI (a different domain). Pinned by
//! `tests::linux::the_jail_holds_on_this_kernel`. The harness also makes
//! itself non-dumpable at start (`harness_main`), so even a same-uid process
//! OUTSIDE any domain cannot read it.
//!
//! ## macOS: `sandbox-exec`
//!
//! `/usr/bin/sandbox-exec -p <profile> <cli> …`, the profile from
//! [`macos_profile`]: everything allowed by default, then the user's whole
//! real home (on a Mac the harness runs as the operator: `~/.ssh`,
//! `~/Documents`, keychains), `~/noomesh` (pki, birth key, env files,
//! secrets) and the data root denied, then the CLI's own trees and the
//! task's workspace allowed again.
//! No `sandbox-exec` is a refusal.
//!
//! The profile also closes other processes: `(deny process-info*)` then
//! `(allow process-info* (target self))` (`proc_pidinfo` on anyone else),
//! and `(deny sysctl-read (sysctl-name "kern.procargs2") …)` — the sysctl
//! `ps -E` reads another process's argv and environment through. On a Mac
//! the harness and the agent run as the CLI's own user.
//!
//! Any other OS: a refusal.
//!
//! ## The self-test
//!
//! A jail is proved on the node, not trusted on faith. At harness start for
//! a foreign kind, [`self_test`] runs `/bin/sh` through [`command`] and
//! checks what it PRINTED: it must read and write its workspace, and must
//! not read a planted secret outside it, a canary in a sibling process's
//! environment, the harness's own environment, or the node's real secrets.
//! A failure is a [`Refusal`] naming the leak; [`gate`] (the driver's
//! probe) returns it for every foreign task and turn until the harness
//! restarts.

use std::path::{Path, PathBuf};

/// A refusal to start a CLI: the jail cannot be built here, or not for
/// these paths. Never "run it anyway".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

impl Refusal {
    fn new(why: impl Into<String>) -> Self {
        Self(why.into())
    }

    /// The loop's checkpoint note for this refusal.
    pub fn note(&self) -> String {
        format!("harness jail unavailable: {}; foreign CLIs never run unjailed", self.0)
    }
}

/// What this host can jail a CLI with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Available {
    /// Landlock, at this ABI version.
    Landlock(u32),
    /// macOS `sandbox-exec`.
    SandboxExec,
}

impl std::fmt::Display for Available {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Landlock(abi) => write!(f, "landlock ABI {abi}"),
            Self::SandboxExec => f.write_str("sandbox-exec"),
        }
    }
}

/// How the driver asks whether a jail can be built (injectable in tests).
pub type Probe = fn() -> Result<Available, Refusal>;

/// One invocation's jail: what the CLI may read and write besides the
/// system trees.
#[derive(Debug, Clone, Default)]
pub struct JailSpec {
    /// The CLI's working directory (read-write).
    pub workspace: PathBuf,
    /// The CLI's HOME (read-write).
    pub home: PathBuf,
    /// The CLI's TMPDIR (read-write).
    pub tmp: PathBuf,
    /// The cluster CA the CLI is handed (`NOO_TLS_CA`): that one FILE is
    /// readable, never its directory.
    pub ca_file: Option<PathBuf>,
    /// Single files the CLI must read (the MCP config beside the
    /// workspace).
    pub extra_ro: Vec<PathBuf>,
    /// The node's data root, denied on macOS (`NOO_DATA_ROOT`); on Linux it
    /// is simply not in the allow-list.
    pub data_root: Option<PathBuf>,
}

/// Read and execute: the system trees a runtime loads from.
pub const SYSTEM_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/opt/noo/vendor"];
/// The `/etc` FILES a CLI needs (resolver, users, time zone, loader) —
/// never the `/etc` tree.
pub const ETC_FILES: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    // OpenSSL reads its config at start; a Node-based CLI (Copilot) exits
    // 13 without it (seen in `harness probe` inside the jail, 2026-10-16).
    "/etc/ssl/openssl.cnf",
];
/// The `/etc` directories read whole: TLS roots and the loader's drop-ins.
pub const ETC_DIRS: &[&str] = &["/etc/ssl/certs", "/etc/ca-certificates", "/etc/ld.so.conf.d"];
/// Device files: read, write (`> /dev/null`), truncate, ioctl. Not
/// `/dev/tty`.
pub const DEV_FILES: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];
/// No rule may name one of these or a directory above one.
pub const NEVER_AT_OR_ABOVE: &[&str] = &[
    "/etc",
    "/etc/noo",
    "/etc/noo/pki",
    "/etc/noo/pki/nodes",
    "/etc/noo/harness-secrets",
    "/etc/noo-harness.env",
    "/etc/noo-node-agent.env",
    "/var/lib/noo",
    "/run",
    "/var/run",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/home",
    "/root",
];
/// The CLI's own directory may not be inside one of these either (the
/// workspace, the CA file and the MCP config are what the driver chose and
/// are exempt).
pub const NEVER_BELOW: &[&str] = &["/etc/noo", "/var/lib/noo"];

/// What a rule grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Directory: read files, list, execute.
    ReadExec,
    /// Directory: read files and list, no execute (`/proc`, TLS roots).
    Read,
    /// One file: read.
    ReadFile,
    /// One device file: read, write, truncate, ioctl.
    Dev,
    /// Directory: everything (create, remove, rename within).
    ReadWrite,
}

/// One allow-list entry, its path canonical (Landlock attaches the rule to
/// the inode the path resolves to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub path: PathBuf,
    pub access: Access,
}

/// A path as the filesystem resolves it: canonical, and whether a dir.
type Resolve<'a> = &'a dyn Fn(&Path) -> Option<(PathBuf, bool)>;

fn resolve_fs(p: &Path) -> Option<(PathBuf, bool)> {
    let c = std::fs::canonicalize(p).ok()?;
    let md = std::fs::metadata(&c).ok()?;
    Some((c, md.is_dir()))
}

/// The allow-list for running `program` under `spec` on Linux.
pub fn allow_list(spec: &JailSpec, program: &Path) -> Result<Vec<Rule>, Refusal> {
    allow_list_with(spec, program, &resolve_fs)
}

fn allow_list_with(spec: &JailSpec, program: &Path, resolve: Resolve) -> Result<Vec<Rule>, Refusal> {
    let mut rules: Vec<Rule> = Vec::new();
    // Optional: present → granted, absent → skipped; wrong type → skipped.
    let optional = |p: &str, access: Access, want_dir: bool, rules: &mut Vec<Rule>| {
        if let Some((c, is_dir)) = resolve(Path::new(p)) {
            if is_dir == want_dir {
                rules.push(Rule { path: c, access });
            }
        }
    };
    for d in SYSTEM_DIRS {
        optional(d, Access::ReadExec, true, &mut rules);
    }
    optional("/proc", Access::Read, true, &mut rules);
    for f in DEV_FILES {
        optional(f, Access::Dev, false, &mut rules);
    }
    for f in ETC_FILES {
        optional(f, Access::ReadFile, false, &mut rules);
    }
    for d in ETC_DIRS {
        optional(d, Access::Read, true, &mut rules);
    }
    let mut checked_below = Vec::new();
    // The CLI's own directory (where the wrapper or binary resolves to).
    let (exe, _) = resolve(program).ok_or_else(|| Refusal::new(format!("the CLI executable {} was not found", program.display())))?;
    let exe_dir = exe.parent().map(Path::to_path_buf).ok_or_else(|| Refusal::new(format!("the CLI executable {} has no directory", exe.display())))?;
    checked_below.push(exe_dir.clone());
    rules.push(Rule { path: exe_dir, access: Access::ReadExec });
    // The cluster CA: that file, never its directory.
    if let Some(ca) = &spec.ca_file {
        match resolve(ca) {
            Some((_, true)) => return Err(Refusal::new(format!("NOO_TLS_CA {} is a directory; the jail grants one CA file, never a directory", ca.display()))),
            Some((c, false)) => rules.push(Rule { path: c, access: Access::ReadFile }),
            None => {}
        }
    }
    for f in &spec.extra_ro {
        match resolve(f) {
            Some((c, false)) => rules.push(Rule { path: c, access: Access::ReadFile }),
            _ => return Err(Refusal::new(format!("{} is not a file the CLI can be given", f.display()))),
        }
    }
    for (what, d) in [("workspace", &spec.workspace), ("HOME", &spec.home), ("TMP", &spec.tmp)] {
        match resolve(d) {
            Some((c, true)) => rules.push(Rule { path: c, access: Access::ReadWrite }),
            _ => return Err(Refusal::new(format!("the task {what} {} is not a directory", d.display()))),
        }
    }
    for r in &rules {
        if let Some(n) = NEVER_AT_OR_ABOVE.iter().find(|n| Path::new(n).starts_with(&r.path)) {
            return Err(Refusal::new(format!("{} would expose {n}", r.path.display())));
        }
    }
    for p in &checked_below {
        if let Some(n) = NEVER_BELOW.iter().find(|n| p.starts_with(n)) {
            return Err(Refusal::new(format!("the CLI's directory {} is inside {n}", p.display())));
        }
    }
    Ok(rules)
}

/// Can a jail be built on this host? Builds (and drops) a ruleset; never
/// restricts the caller.
pub fn probe() -> Result<Available, Refusal> {
    #[cfg(target_os = "linux")]
    {
        let abi = landlock::abi()?;
        drop(landlock::ruleset(abi)?);
        Ok(Available::Landlock(abi))
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(SANDBOX_EXEC).is_file() {
            Ok(Available::SandboxExec)
        } else {
            Err(Refusal::new(format!("{SANDBOX_EXEC} is missing")))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Refusal::new("no jail is implemented on this OS"))
    }
}

/// A `Command` that will exec `program` inside the jail `spec` describes,
/// or why not. The caller adds the CLI's arguments, env, cwd and stdio as
/// for any `Command`. A refusal is logged as `harness_jail_refused`.
pub fn command(program: &Path, spec: &JailSpec) -> Result<tokio::process::Command, Refusal> {
    let out = command_inner(program, spec);
    if let Err(r) = &out {
        tracing::error!(event = "harness_jail_refused", reason = %r, cli = %program.display(), "harness_jail_refused: {}", r.note());
    }
    out
}

#[cfg(target_os = "linux")]
fn command_inner(program: &Path, spec: &JailSpec) -> Result<tokio::process::Command, Refusal> {
    let abi = landlock::abi()?;
    let rules = allow_list(spec, program)?;
    let fd = std::sync::Arc::new(landlock::build(abi, &rules)?);
    let mut cmd = tokio::process::Command::new(program);
    // SAFETY: the hook runs in the forked child before exec; it makes two
    // raw syscalls on an fd the parent opened and keeps alive (the Arc is
    // owned by the closure, which the Command owns) and allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            use std::os::fd::AsRawFd;
            landlock::restrict_self(fd.as_raw_fd())
        });
    }
    Ok(cmd)
}

#[cfg(target_os = "macos")]
fn command_inner(program: &Path, spec: &JailSpec) -> Result<tokio::process::Command, Refusal> {
    if !Path::new(SANDBOX_EXEC).is_file() {
        return Err(Refusal::new(format!("{SANDBOX_EXEC} is missing")));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| Refusal::new("HOME is not set"))?;
    let data_root = spec.data_root.clone().or_else(|| std::env::var_os("NOO_DATA_ROOT").map(PathBuf::from));
    let spec = JailSpec { data_root, ..spec.clone() };
    let profile = macos_profile(&home, &spec)?;
    let mut cmd = tokio::process::Command::new(SANDBOX_EXEC);
    cmd.arg("-p").arg(profile).arg(program);
    Ok(cmd)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn command_inner(_program: &Path, _spec: &JailSpec) -> Result<tokio::process::Command, Refusal> {
    Err(Refusal::new("no jail is implemented on this OS"))
}

// ── macOS ───────────────────────────────────────────────────────────────

/// Where macOS keeps `sandbox-exec`.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

fn sbpl_str(p: &Path) -> Result<String, Refusal> {
    let s = p.to_str().ok_or_else(|| Refusal::new(format!("{} is not UTF-8", p.display())))?;
    if !p.is_absolute() || s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(Refusal::new(format!("{s:?} cannot be named in a sandbox profile")));
    }
    Ok(format!("\"{}\"", s.trim_end_matches('/')))
}

/// The `sandbox-exec` profile for a CLI on a Mac node whose noomesh tree is
/// `<home>/noomesh`. SBPL: the LAST matching rule wins, so the denies come
/// after `allow default` and the re-allows after the denies.
///
/// `home` is the REAL home of the user the harness runs as — on a Mac, the
/// operator's own account. The whole of it is denied (`~/.ssh`,
/// `~/Documents`, keychains, browser profiles), and only what the CLI must
/// reach under it is allowed again below: `~/noomesh/vendor` and
/// `~/noomesh/bin`, the CA file, the extra read-only files, and the task's
/// workspace/HOME/TMP when the driver put them there (by default they are
/// under the system temp dir, `/var/folders/…`, outside home). Metadata of
/// the two directories on the way down (`~` and `~/noomesh`) is readable so
/// a runtime resolving its own path can `stat` them; their listings are not.
pub fn macos_profile(home: &Path, spec: &JailSpec) -> Result<String, Refusal> {
    let base = home.join("noomesh");
    let mut p = String::from("(version 1)\n(allow default)\n");
    // The user's real home: everything a same-uid process could otherwise
    // read on the operator's own account.
    p.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", sbpl_str(home)?));
    // Everything the node keeps: pki (node pair, birth key), the agent's
    // and harness's env files, secrets, the bundle state. Inside home, so
    // already denied; named so a later edit to the home rule cannot open it.
    p.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", sbpl_str(&base)?));
    // Named again, each: a later edit that re-allows part of the tree must
    // not reach these (the secret dirs hold the env files' values).
    p.push_str(&format!(
        "(deny file-read* file-write* (literal {}) (literal {}) (subpath {}) (subpath {}) (subpath {}))\n",
        sbpl_str(&base.join("harness.env"))?,
        sbpl_str(&base.join("agent.env"))?,
        sbpl_str(&base.join("pki"))?,
        sbpl_str(&base.join("secrets"))?,
        sbpl_str(&base.join("harness-secrets"))?
    ));
    // Other processes: a same-uid process can read another's argv and
    // environment (`sysctl(KERN_PROCARGS2)`, what `ps -E` uses) and its
    // details (`proc_pidinfo`). On a Mac the harness and the agent run as
    // the CLI's own user, so both are closed here. The process-info pair
    // is WebKit's WebContent form (deny all, re-allow `(target self)`);
    // the sysctl names are the `kern.procargs*` nodes. The startup
    // self-test proves the result on the node ([`self_test`]).
    p.push_str("(deny process-info*)\n(allow process-info* (target self))\n");
    p.push_str("(deny sysctl-read (sysctl-name \"kern.procargs2\") (sysctl-name \"kern.procargs\"))\n");
    if let Some(d) = &spec.data_root {
        p.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", sbpl_str(d)?));
    }
    // Path resolution down to the CLI: `stat` of home and ~/noomesh, never
    // a listing or a read of anything in them.
    p.push_str(&format!("(allow file-read-metadata (literal {}) (literal {}))\n", sbpl_str(home)?, sbpl_str(&base)?));
    // The CLI itself: the staged vendor tree and its wrapper.
    p.push_str(&format!("(allow file-read* (subpath {}) (subpath {}))\n", sbpl_str(&base.join("vendor"))?, sbpl_str(&base.join("bin"))?));
    if let Some(ca) = &spec.ca_file {
        p.push_str(&format!("(allow file-read* (literal {}))\n", sbpl_str(ca)?));
    }
    for f in &spec.extra_ro {
        p.push_str(&format!("(allow file-read* (literal {}))\n", sbpl_str(f)?));
    }
    p.push_str(&format!(
        "(allow file-read* file-write* (subpath {}) (subpath {}) (subpath {}))\n",
        sbpl_str(&spec.workspace)?,
        sbpl_str(&spec.home)?,
        sbpl_str(&spec.tmp)?
    ));
    Ok(p)
}

// ── Linux ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod landlock {
    use super::{Access, Refusal, Rule};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    const CREATE_RULESET_VERSION: u32 = 1 << 0;
    const RULE_PATH_BENEATH: libc::c_int = 1;

    const EXECUTE: u64 = 1 << 0;
    const WRITE_FILE: u64 = 1 << 1;
    const READ_FILE: u64 = 1 << 2;
    const READ_DIR: u64 = 1 << 3;
    // 1<<4 .. 1<<12: REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR, MAKE_REG,
    // MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM (ABI v1).
    const ABI1_ALL: u64 = (1 << 13) - 1;
    const REFER: u64 = 1 << 13; // ABI v2
    const TRUNCATE: u64 = 1 << 14; // ABI v3
    const IOCTL_DEV: u64 = 1 << 15; // ABI v5
    /// The rights that apply to a file (the rest are directory rights; the
    /// kernel refuses a file rule that names one).
    const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// Every filesystem right this ABI version knows.
    pub fn handled(abi: u32) -> u64 {
        let mut h = ABI1_ALL;
        if abi >= 2 {
            h |= REFER;
        }
        if abi >= 3 {
            h |= TRUNCATE;
        }
        if abi >= 5 {
            h |= IOCTL_DEV;
        }
        h
    }

    fn rights(access: Access, handled: u64) -> u64 {
        let r = match access {
            Access::ReadExec => EXECUTE | READ_FILE | READ_DIR,
            Access::Read => READ_FILE | READ_DIR,
            Access::ReadFile => READ_FILE,
            Access::Dev => READ_FILE | WRITE_FILE | TRUNCATE | IOCTL_DEV,
            Access::ReadWrite => u64::MAX,
        };
        r & handled
    }

    /// The running kernel's Landlock ABI version, at least 1, or why not.
    pub fn abi() -> Result<u32, Refusal> {
        // SAFETY: the version query takes no attribute (NULL, 0).
        let r = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, CREATE_RULESET_VERSION) };
        abi_from(r, std::io::Error::last_os_error())
    }

    pub(super) fn abi_from(r: libc::c_long, err: std::io::Error) -> Result<u32, Refusal> {
        if r < 0 {
            return Err(Refusal::new(match err.raw_os_error() {
                Some(libc::ENOSYS) => "this kernel has no Landlock (landlock_create_ruleset: ENOSYS)".to_string(),
                Some(libc::EOPNOTSUPP) => "Landlock is disabled on this kernel (add landlock to the lsm= boot parameter)".to_string(),
                _ => format!("Landlock is unavailable: {err}"),
            }));
        }
        if r < 1 {
            return Err(Refusal::new(format!("Landlock ABI {r} is below the required v1")));
        }
        Ok(r as u32)
    }

    /// An empty ruleset handling every right `abi` knows.
    pub fn ruleset(abi: u32) -> Result<OwnedFd, Refusal> {
        let attr = RulesetAttr { handled_access_fs: handled(abi) };
        // SAFETY: attr outlives the call; the size is the struct's.
        let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, std::mem::size_of::<RulesetAttr>(), 0u32) };
        if fd < 0 {
            return Err(Refusal::new(format!("landlock_create_ruleset: {}", std::io::Error::last_os_error())));
        }
        // SAFETY: a fresh fd the kernel just returned (O_CLOEXEC), owned here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// The ruleset with every rule added. Runs in the parent.
    pub fn build(abi: u32, rules: &[Rule]) -> Result<OwnedFd, Refusal> {
        let handled = handled(abi);
        let rs = ruleset(abi)?;
        for rule in rules {
            let c = std::ffi::CString::new(rule.path.as_os_str().as_bytes()).map_err(|_| Refusal::new(format!("{} has a NUL", rule.path.display())))?;
            // SAFETY: c is a valid C string for the call.
            let pfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if pfd < 0 {
                return Err(Refusal::new(format!("opening {}: {}", rule.path.display(), std::io::Error::last_os_error())));
            }
            // SAFETY: a fresh fd, owned here (closed on drop).
            let pfd = unsafe { OwnedFd::from_raw_fd(pfd) };
            let md = std::fs::metadata(&rule.path).map_err(|e| Refusal::new(format!("{}: {e}", rule.path.display())))?;
            let mut allowed = rights(rule.access, handled);
            if !md.is_dir() {
                allowed &= FILE_RIGHTS;
            }
            if allowed == 0 {
                continue;
            }
            let attr = PathBeneathAttr { allowed_access: allowed, parent_fd: pfd.as_raw_fd() };
            // SAFETY: attr outlives the call; rs and pfd are open.
            let r = unsafe { libc::syscall(libc::SYS_landlock_add_rule, rs.as_raw_fd(), RULE_PATH_BENEATH, &attr as *const PathBeneathAttr, 0u32) };
            if r < 0 {
                return Err(Refusal::new(format!("landlock_add_rule {}: {}", rule.path.display(), std::io::Error::last_os_error())));
            }
        }
        Ok(rs)
    }

    /// In the forked child, before exec: no new privileges, then the
    /// ruleset. Two syscalls, nothing allocated (async-signal-safe).
    pub fn restrict_self(ruleset: i32) -> std::io::Result<()> {
        // SAFETY: plain syscalls with integer arguments.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Make this process non-dumpable: its `/proc/<pid>/{environ,mem,fd}` turn
/// root-owned, so a same-uid process — jailed or not — cannot read the
/// environment systemd loaded. Linux only; a no-op elsewhere. Costs core
/// dumps, nothing else the harness uses.
pub fn make_undumpable() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// ── the self-test ───────────────────────────────────────────────────────

/// What a passed self-test proved on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    /// `linux` / `macos`.
    pub os: &'static str,
    /// What jailed the shell (`landlock ABI 7`, `sandbox-exec`).
    pub mechanism: Available,
    /// How long the whole test took.
    pub elapsed: std::time::Duration,
    /// Each must-fail that failed and each must-succeed that succeeded.
    pub proved: Vec<String>,
    /// Checks that could not prove anything here (their positive control
    /// failed OUTSIDE the jail too) — said, never silently dropped.
    pub unproved: Vec<String>,
}

impl std::fmt::Display for SelfTestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ok ({}, {})", self.os, self.mechanism)
    }
}

/// Where the self-test plants what the jail must hide, and what the jailed
/// shell is told to try. Built by [`SelfTestPlan::for_this_host`]; the
/// tests build broken ones.
#[derive(Debug, Clone)]
pub struct SelfTestPlan {
    /// The scratch tree: `work`, `home`, `tmp` are created under it and
    /// granted, nothing else of it is.
    pub scratch: PathBuf,
    /// A directory NOT on the allow-list, where the planted secret goes
    /// (Linux: a fresh temp dir; macOS: `~/noomesh/secrets`, which the
    /// profile denies).
    pub plant_dir: PathBuf,
    /// Real node secrets that must stay unreadable if they exist (Linux:
    /// `/etc/noo/pki` — the node pair and the harness's own copy — the
    /// secret dirs and the env files; macOS: [`macos_must_hide`]).
    pub must_hide: Vec<PathBuf>,
    /// macOS: a file planted in the user's REAL home
    /// (`~/.noo-jail-selftest-<id>`), which must be unreadable in the jail
    /// — the operator's own files (`~/.ssh`, `~/Documents`) are only as
    /// closed as this one. Removed after the test. None on Linux, where the
    /// jail is an allow-list that names no home at all.
    pub home_plant: Option<PathBuf>,
}

impl SelfTestPlan {
    /// The plan for this host, under `root` — the driver's own workdir
    /// root, so the test runs where the tasks will (a unit's private or
    /// read-only `/tmp` is the tasks' too).
    pub fn for_this_host(root: &Path) -> Result<Self, Refusal> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let scratch = root.join(format!(".jail-selftest-{}-{id}", std::process::id()));
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| Refusal::new("HOME is not set"))?;
            let base = home.join("noomesh");
            let plant_dir = base.join("secrets").join(format!(".jail-selftest-{id}"));
            let must_hide = macos_must_hide(&home);
            let home_plant = Some(home.join(format!(".noo-jail-selftest-{id}")));
            Ok(Self { scratch, plant_dir, must_hide, home_plant })
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Beside the scratch tree, never inside the granted part of it.
            let plant_dir = root.join(format!(".jail-selftest-secret-{}-{id}", std::process::id()));
            // The harness's own key pair (`/etc/noo/pki/harness`, group
            // noo-harness) is the one its uid CAN read: the jail is all
            // that stands between it and the CLI.
            let must_hide = ["/etc/noo/pki", "/etc/noo/harness-secrets", "/etc/noo/agent-secrets", "/etc/noo-harness.env", "/etc/noo-node-agent.env"]
                .iter()
                .map(PathBuf::from)
                .collect();
            Ok(Self { scratch, plant_dir, must_hide, home_plant: None })
        }
    }
}

/// On a Mac: the node key, both secret dirs and both env files.
pub fn macos_must_hide(home: &Path) -> Vec<PathBuf> {
    let base = home.join("noomesh");
    ["pki", "secrets", "harness-secrets", "agent.env", "harness.env"].iter().map(|r| base.join(r)).collect()
}

/// The verdict for this process: set once, at harness start.
static SELF_TEST: std::sync::OnceLock<Result<SelfTestReport, Refusal>> = std::sync::OnceLock::new();

/// Run the self-test once per process, under `root` (the driver's
/// workdir root), and remember the verdict; later calls return it. A
/// restart re-runs it.
pub async fn self_test(root: &Path) -> Result<SelfTestReport, Refusal> {
    if let Some(v) = SELF_TEST.get() {
        return v.clone();
    }
    let v = match SelfTestPlan::for_this_host(root) {
        Ok(plan) => run_self_test(&plan, &|_, _| {}).await,
        Err(r) => Err(r),
    };
    SELF_TEST.get_or_init(|| v).clone()
}

/// The driver's gate (the default [`Probe`]): a jail can be built here AND,
/// once the startup self-test has run, it passed. A failed self-test
/// refuses every foreign task and turn for the life of the process.
pub fn gate() -> Result<Available, Refusal> {
    gate_from(probe(), SELF_TEST.get())
}

fn gate_from(probe: Result<Available, Refusal>, verdict: Option<&Result<SelfTestReport, Refusal>>) -> Result<Available, Refusal> {
    let a = probe?;
    match verdict {
        Some(Err(r)) => Err(r.clone()),
        _ => Ok(a),
    }
}

const SELF_TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// One run of the self-test, uncached. `widen` may change the jail before
/// it is built — only the tests use it, to prove a wrong jail is caught.
pub async fn run_self_test(plan: &SelfTestPlan, widen: &dyn Fn(&mut JailSpec, &Path)) -> Result<SelfTestReport, Refusal> {
    let started = std::time::Instant::now();
    let mechanism = probe()?;
    let out = tokio::time::timeout(SELF_TEST_BUDGET, self_test_inner(plan, widen)).await;
    let _ = std::fs::remove_dir_all(&plan.scratch);
    // Only the planted file and the directory made for it.
    let _ = std::fs::remove_dir_all(&plan.plant_dir);
    if let Some(f) = &plan.home_plant {
        let _ = std::fs::remove_file(f);
    }
    let (proved, unproved) = match out {
        Ok(r) => r?,
        Err(_) => return Err(Refusal::new(format!("jail self-test did not finish in {}s", SELF_TEST_BUDGET.as_secs()))),
    };
    Ok(SelfTestReport { os: std::env::consts::OS, mechanism, elapsed: started.elapsed(), proved, unproved })
}

fn shell_quote(p: &Path) -> Result<String, Refusal> {
    let s = p.to_str().ok_or_else(|| Refusal::new(format!("{} is not UTF-8", p.display())))?;
    if s.contains('\'') || s.chars().any(char::is_control) {
        return Err(Refusal::new(format!("{s:?} cannot be quoted for the self-test shell")));
    }
    Ok(format!("'{s}'"))
}

/// The shell line that prints process `pid`'s environment, as an attacker
/// in the jail would read it: `/proc/<pid>/environ` on Linux; on macOS `ps
/// -E`, which reads `sysctl(KERN_PROCARGS2)`.
fn read_env_of(pid: u32) -> String {
    if cfg!(target_os = "macos") {
        format!("/bin/ps -E -ww -o command= -p {pid}")
    } else {
        format!("cat /proc/{pid}/environ")
    }
}

/// The text between `@@<name>-begin` and `@@<name>-end`.
fn section<'a>(out: &'a str, name: &str) -> Option<&'a str> {
    let b = format!("@@{name}-begin\n");
    let e = format!("@@{name}-end");
    let start = out.find(&b)? + b.len();
    let len = out[start..].find(&e)?;
    Some(&out[start..start + len])
}

/// The parent's own environment entries a leak would show: `K=V` with a
/// value long enough not to occur by chance.
fn parent_markers() -> Vec<String> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some(format!("{}={}", k.to_str()?, v.to_str()?)))
        .filter(|kv| kv.split_once('=').is_some_and(|(_, v)| v.len() >= 6))
        .collect()
}

async fn self_test_inner(plan: &SelfTestPlan, widen: &dyn Fn(&mut JailSpec, &Path)) -> Result<(Vec<String>, Vec<String>), Refusal> {
    let io = |what: &str, e: std::io::Error| Refusal::new(format!("jail self-test could not {what}: {e}"));
    let (work, home, tmp) = (plan.scratch.join("work"), plan.scratch.join("home"), plan.scratch.join("tmp"));
    for d in [&work, &home, &tmp] {
        std::fs::create_dir_all(d).map_err(|e| io("create its scratch tree", e))?;
    }
    let tag = uuid::Uuid::new_v4().simple().to_string();
    std::fs::write(work.join("in.txt"), format!("inside-{tag}")).map_err(|e| io("write the workspace file", e))?;
    // The planted secret: readable by this user, outside the jail.
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&plan.plant_dir).map_err(|e| io("create the plant dir", e))?;
    }
    let secret = plan.plant_dir.join("node.key");
    let secret_value = format!("NOO-SELFTEST-SECRET-{tag}");
    std::fs::write(&secret, &secret_value).map_err(|e| io("plant the secret", e))?;
    if std::fs::read_to_string(&secret).ok().as_deref() != Some(secret_value.as_str()) {
        return Err(Refusal::new("jail self-test: the planted secret is not readable even outside the jail"));
    }
    // The planted home file (macOS): the operator's own files, by proxy.
    let home_value = format!("NOO-SELFTEST-HOME-{tag}");
    if let Some(f) = &plan.home_plant {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(f)
            .and_then(|mut h| h.write_all(home_value.as_bytes()))
            .map_err(|e| io("plant the home file", e))?;
        if std::fs::read_to_string(f).ok().as_deref() != Some(home_value.as_str()) {
            return Err(Refusal::new("jail self-test: the planted home file is not readable even outside the jail"));
        }
    }
    // A sibling: a plain, dumpable, unjailed process of this user, holding
    // a canary in its environment — what a co-resident agent or another
    // task's process looks like to the jailed CLI.
    let canary = format!("NOO-SELFTEST-CANARY-{tag}");
    let mut sibling = std::process::Command::new("/bin/sleep")
        .arg("30")
        .env_clear()
        .env("NOO_JAIL_CANARY", &canary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| io("start the canary process", e))?;
    let out = self_test_jailed(plan, widen, &work, &home, &tmp, &secret, &secret_value, sibling.id(), &canary, &home_value).await;
    let _ = sibling.kill();
    let _ = sibling.wait();
    out
}

#[allow(clippy::too_many_arguments)]
async fn self_test_jailed(
    plan: &SelfTestPlan,
    widen: &dyn Fn(&mut JailSpec, &Path),
    work: &Path,
    home: &Path,
    tmp: &Path,
    secret: &Path,
    secret_value: &str,
    sibling: u32,
    canary: &str,
    home_value: &str,
) -> Result<(Vec<String>, Vec<String>), Refusal> {
    let mut proved = Vec::new();
    let mut unproved = Vec::new();
    let me = std::process::id();
    // Positive control, OUTSIDE the jail: the same read must work, or the
    // jailed failure proves nothing. The spawn returns once the sibling's
    // exec has replaced its memory but before the kernel records where its
    // environment lives, so for a moment /proc/<pid>/environ reads empty
    // (seen under a loaded test run): wait for the canary, about half a second,
    // before the jailed read is judged against it.
    let mut unjailed = false;
    for _ in 0..25 {
        unjailed = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(read_env_of(sibling))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(canary))
            .unwrap_or(false);
        if unjailed {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut spec = JailSpec { workspace: work.to_path_buf(), home: home.to_path_buf(), tmp: tmp.to_path_buf(), ..Default::default() };
    widen(&mut spec, secret);
    let mut script = String::from("echo \"@@read:$(cat in.txt 2>/dev/null)\"\n");
    script.push_str("echo selftest-write > out.txt 2>/dev/null && echo \"@@write:$(cat out.txt 2>/dev/null)\"\n");
    script.push_str(&format!("echo @@secret-begin; cat {} 2>/dev/null; echo; echo @@secret-end\n", shell_quote(secret)?));
    script.push_str(&format!("echo @@sibling-begin; {} 2>/dev/null; echo; echo @@sibling-end\n", read_env_of(sibling)));
    script.push_str(&format!("echo @@parent-begin; {} 2>/dev/null; echo; echo @@parent-end\n", read_env_of(me)));
    if let Some(f) = &plan.home_plant {
        script.push_str(&format!("echo @@home-begin; cat {} 2>/dev/null; echo; echo @@home-end\n", shell_quote(f)?));
    }
    let hide: Vec<&PathBuf> = plan.must_hide.iter().filter(|p| p.exists()).collect();
    for (i, p) in hide.iter().enumerate() {
        let q = shell_quote(p)?;
        // A directory: its listing and every file one or two levels down.
        // Any byte is a leak, so the first 64 are enough (and a large tree
        // that leaked cannot stall the test).
        script.push_str(&format!(
            "echo @@hide{i}-begin; {{ if [ -d {q} ]; then ls -A {q}; cat {q}/* {q}/*/*; else cat {q}; fi; }} 2>/dev/null | head -c 64; echo; echo @@hide{i}-end\n"
        ));
    }
    let mut cmd = command(Path::new("/bin/sh"), &spec)?;
    let out = cmd
        .arg("-c")
        .arg(&script)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(work)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| Refusal::new(format!("jail self-test could not start the jailed shell: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let tail = |s: &[u8]| String::from_utf8_lossy(s).lines().last().unwrap_or("").to_string();
    // Must succeed: the shell ran, and the task's own tree works.
    let inside = std::fs::read_to_string(work.join("in.txt")).unwrap_or_default();
    if !text.contains(&format!("@@read:{inside}")) {
        return Err(Refusal::new(format!(
            "jail self-test: the jailed shell could not read its own workspace (exit {:?}: {})",
            out.status.code(),
            tail(&out.stderr)
        )));
    }
    proved.push("workspace readable".into());
    if !text.contains("@@write:selftest-write") || std::fs::read_to_string(work.join("out.txt")).map(|s| s.trim() != "selftest-write").unwrap_or(true) {
        return Err(Refusal::new("jail self-test: the jailed shell could not write its own workspace".to_string()));
    }
    proved.push("workspace writable".into());
    // Must fail: every one is judged on what came OUT, not on an exit code.
    let leak = |what: String| Err(Refusal::new(format!("jail self-test failed: {what}")));
    let Some(s) = section(&text, "secret") else { return leak("the secret check did not report".into()) };
    if s.contains(secret_value) {
        return leak(format!("the planted secret {} was readable inside the jail", secret.display()));
    }
    proved.push(format!("planted secret in {} unreadable", plan.plant_dir.display()));
    let Some(s) = section(&text, "sibling") else { return leak("the sibling-environment check did not report".into()) };
    if s.contains(canary) {
        return leak(format!("a sibling process's environment (pid {sibling}) was readable inside the jail"));
    }
    if unjailed {
        proved.push("sibling environment unreadable".into());
    } else {
        unproved.push("sibling environment: unreadable even outside the jail, so the jailed failure proves nothing here".into());
    }
    let Some(s) = section(&text, "parent") else { return leak("the parent-environment check did not report".into()) };
    if let Some(m) = parent_markers().into_iter().find(|m| s.contains(m.as_str())) {
        let name = m.split_once('=').map(|(k, _)| k).unwrap_or("");
        return leak(format!("the harness's own environment was readable inside the jail ({name}=…)"));
    }
    proved.push("harness environment unreadable".into());
    if let Some(f) = &plan.home_plant {
        let Some(s) = section(&text, "home") else { return leak("the home check did not report".into()) };
        if s.contains(home_value) {
            return leak(format!("a file in the user's home ({}) was readable inside the jail", f.display()));
        }
        proved.push(format!("planted file in the user's home ({}) unreadable", f.display()));
    }
    for (i, p) in hide.iter().enumerate() {
        let Some(s) = section(&text, &format!("hide{i}")) else { return leak(format!("the {} check did not report", p.display())) };
        if !s.trim().is_empty() {
            return leak(format!("{} was readable inside the jail", p.display()));
        }
        proved.push(format!("{} unreadable", p.display()));
    }
    Ok((proved, unproved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A fake filesystem: path → (canonical, is_dir).
    fn fake(entries: &[(&str, &str, bool)]) -> BTreeMap<PathBuf, (PathBuf, bool)> {
        entries.iter().map(|(p, c, d)| (PathBuf::from(p), (PathBuf::from(c), *d))).collect()
    }

    fn spec() -> JailSpec {
        JailSpec {
            workspace: "/tmp/noo-harness/t1/work".into(),
            home: "/tmp/noo-harness/t1/home".into(),
            tmp: "/tmp/noo-harness/t1/tmp".into(),
            ca_file: Some("/etc/noo/pki/ca.crt".into()),
            extra_ro: vec!["/tmp/noo-harness/t1/noomesh-mcp.json".into()],
            data_root: None,
        }
    }

    fn base_fs() -> Vec<(&'static str, &'static str, bool)> {
        vec![
            ("/usr", "/usr", true),
            ("/lib", "/usr/lib", true),
            ("/bin", "/usr/bin", true),
            ("/proc", "/proc", true),
            ("/dev/null", "/dev/null", false),
            ("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf", false),
            ("/etc/passwd", "/etc/passwd", false),
            ("/etc/ssl/certs", "/etc/ssl/certs", true),
            ("/etc/noo/pki/ca.crt", "/etc/noo/pki/ca.crt", false),
            ("/usr/local/bin/claude", "/usr/local/bin/claude", false),
            ("/tmp/noo-harness/t1/noomesh-mcp.json", "/tmp/noo-harness/t1/noomesh-mcp.json", false),
            ("/tmp/noo-harness/t1/work", "/tmp/noo-harness/t1/work", true),
            ("/tmp/noo-harness/t1/home", "/tmp/noo-harness/t1/home", true),
            ("/tmp/noo-harness/t1/tmp", "/tmp/noo-harness/t1/tmp", true),
        ]
    }

    fn list(spec: &JailSpec, program: &str, fs: &[(&str, &str, bool)]) -> Result<Vec<Rule>, Refusal> {
        let fs = fake(fs);
        allow_list_with(spec, Path::new(program), &|p| fs.get(p).cloned())
    }

    #[test]
    fn the_allow_list_is_the_documented_one_and_nothing_else() {
        let rules = list(&spec(), "/usr/local/bin/claude", &base_fs()).unwrap();
        let got: Vec<(String, Access)> = rules.iter().map(|r| (r.path.display().to_string(), r.access)).collect();
        let want: Vec<(String, Access)> = [
            ("/usr", Access::ReadExec),
            ("/usr/lib", Access::ReadExec),
            ("/usr/bin", Access::ReadExec),
            ("/proc", Access::Read),
            ("/dev/null", Access::Dev),
            ("/run/systemd/resolve/stub-resolv.conf", Access::ReadFile),
            ("/etc/passwd", Access::ReadFile),
            ("/etc/ssl/certs", Access::Read),
            ("/usr/local/bin", Access::ReadExec),
            ("/etc/noo/pki/ca.crt", Access::ReadFile),
            ("/tmp/noo-harness/t1/noomesh-mcp.json", Access::ReadFile),
            ("/tmp/noo-harness/t1/work", Access::ReadWrite),
            ("/tmp/noo-harness/t1/home", Access::ReadWrite),
            ("/tmp/noo-harness/t1/tmp", Access::ReadWrite),
        ]
        .iter()
        .map(|(p, a)| (p.to_string(), *a))
        .collect();
        assert_eq!(got, want, "absent paths (/lib64, /sbin, /opt/noo/vendor, …) are skipped, present ones granted");
        for r in &rules {
            for bad in ["/etc/noo/pki/nodes", "/etc/noo/pki", "/etc", "/etc/noo-harness.env", "/var/lib/noo", "/run", "/home", "/root"] {
                assert!(!Path::new(bad).starts_with(&r.path), "{} covers {bad}", r.path.display());
            }
        }
    }

    #[test]
    fn the_ca_is_one_file_never_its_directory() {
        let mut s = spec();
        s.ca_file = Some("/etc/noo/pki".into());
        let mut fs = base_fs();
        fs.push(("/etc/noo/pki", "/etc/noo/pki", true));
        let e = list(&s, "/usr/local/bin/claude", &fs).unwrap_err();
        assert!(e.0.contains("is a directory"), "{e}");
        // An absent CA is not granted and not a refusal (the CLI reports TLS).
        s.ca_file = Some("/etc/noo/pki/missing.crt".into());
        let rules = list(&s, "/usr/local/bin/claude", &base_fs()).unwrap();
        assert!(!rules.iter().any(|r| r.path.starts_with("/etc/noo")));
    }

    #[test]
    fn a_cli_whose_directory_would_expose_a_secret_is_refused() {
        for (prog, canon) in [("/x/claude", "/claude"), ("/x/claude", "/etc/claude"), ("/x/claude", "/etc/noo/pki/nodes/claude"), ("/x/claude", "/var/lib/noo/bin/claude"), ("/x/claude", "/home/claude")] {
            let mut fs = base_fs();
            fs.push((prog, canon, false));
            let e = list(&spec(), prog, &fs).unwrap_err();
            assert!(e.0.contains("would expose") || e.0.contains("is inside"), "{canon}: {e}");
        }
        let e = list(&spec(), "/nope/claude", &base_fs()).unwrap_err();
        assert!(e.0.contains("was not found"), "{e}");
    }

    #[test]
    fn a_workspace_that_is_not_there_or_too_wide_is_refused() {
        let mut fs = base_fs();
        fs.retain(|(p, _, _)| *p != "/tmp/noo-harness/t1/tmp");
        assert!(list(&spec(), "/usr/local/bin/claude", &fs).unwrap_err().0.contains("TMP"));
        let mut s = spec();
        s.home = "/home".into();
        let mut fs = base_fs();
        fs.push(("/home", "/home", true));
        assert!(list(&s, "/usr/local/bin/claude", &fs).unwrap_err().0.contains("would expose /home"));
        let mut s = spec();
        s.extra_ro = vec!["/tmp/noo-harness/t1/gone.json".into()];
        assert!(list(&s, "/usr/local/bin/claude", &base_fs()).is_err(), "a missing file the CLI must read is a refusal");
    }

    #[test]
    fn a_refusal_note_says_the_cli_did_not_run() {
        assert_eq!(
            Refusal::new("this kernel has no Landlock").note(),
            "harness jail unavailable: this kernel has no Landlock; foreign CLIs never run unjailed"
        );
        assert_eq!(Available::Landlock(4).to_string(), "landlock ABI 4");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_landlock_or_disabled_landlock_is_a_refusal() {
        let e = landlock::abi_from(-1, std::io::Error::from_raw_os_error(libc::ENOSYS)).unwrap_err();
        assert!(e.0.contains("no Landlock"), "{e}");
        let e = landlock::abi_from(-1, std::io::Error::from_raw_os_error(libc::EOPNOTSUPP)).unwrap_err();
        assert!(e.0.contains("disabled"), "{e}");
        let e = landlock::abi_from(-1, std::io::Error::from_raw_os_error(libc::EPERM)).unwrap_err();
        assert!(e.0.contains("unavailable"), "{e}");
        assert!(landlock::abi_from(0, std::io::Error::from_raw_os_error(0)).is_err());
        assert_eq!(landlock::abi_from(3, std::io::Error::from_raw_os_error(0)).unwrap(), 3);
        // Every right the ABI knows is handled; nothing past it.
        assert_eq!(landlock::handled(1), (1 << 13) - 1);
        assert_eq!(landlock::handled(3), (1 << 15) - 1);
        assert_eq!(landlock::handled(7), (1 << 16) - 1);
    }

    #[test]
    fn the_macos_profile_denies_the_node_tree_and_reallows_the_task() {
        let mut s = spec();
        s.workspace = "/var/folders/x/noo-harness/t1/work".into();
        s.home = "/var/folders/x/noo-harness/t1/home".into();
        s.tmp = "/var/folders/x/noo-harness/t1/tmp".into();
        s.ca_file = Some("/Users/op/noomesh/pki/ca.crt".into());
        s.extra_ro = vec!["/var/folders/x/noo-harness/t1/noomesh-mcp.json".into()];
        s.data_root = Some("/Users/op/noo-data/".into());
        let p = macos_profile(Path::new("/Users/op"), &s).unwrap();
        assert_eq!(
            p,
            "(version 1)\n(allow default)\n\
             (deny file-read* file-write* (subpath \"/Users/op\"))\n\
             (deny file-read* file-write* (subpath \"/Users/op/noomesh\"))\n\
             (deny file-read* file-write* (literal \"/Users/op/noomesh/harness.env\") (literal \"/Users/op/noomesh/agent.env\") (subpath \"/Users/op/noomesh/pki\") (subpath \"/Users/op/noomesh/secrets\") (subpath \"/Users/op/noomesh/harness-secrets\"))\n\
             (deny process-info*)\n\
             (allow process-info* (target self))\n\
             (deny sysctl-read (sysctl-name \"kern.procargs2\") (sysctl-name \"kern.procargs\"))\n\
             (deny file-read* file-write* (subpath \"/Users/op/noo-data\"))\n\
             (allow file-read-metadata (literal \"/Users/op\") (literal \"/Users/op/noomesh\"))\n\
             (allow file-read* (subpath \"/Users/op/noomesh/vendor\") (subpath \"/Users/op/noomesh/bin\"))\n\
             (allow file-read* (literal \"/Users/op/noomesh/pki/ca.crt\"))\n\
             (allow file-read* (literal \"/var/folders/x/noo-harness/t1/noomesh-mcp.json\"))\n\
             (allow file-read* file-write* (subpath \"/var/folders/x/noo-harness/t1/work\") (subpath \"/var/folders/x/noo-harness/t1/home\") (subpath \"/var/folders/x/noo-harness/t1/tmp\"))\n"
        );
        // A path that could break out of the string is a refusal, not escaped.
        s.workspace = "/tmp/a\")(allow default".into();
        assert!(macos_profile(Path::new("/Users/op"), &s).is_err());
        s.workspace = "relative/work".into();
        assert!(macos_profile(Path::new("/Users/op"), &s).is_err());
    }

    /// The secret dirs are denied by name and under the whole tree, and no
    /// later allow reaches into them; other processes' environment is closed.
    #[test]
    fn the_macos_profile_keeps_the_secret_dirs_and_other_processes_closed() {
        let mut s = spec();
        s.workspace = "/var/folders/x/w".into();
        s.home = "/var/folders/x/h".into();
        s.tmp = "/var/folders/x/t".into();
        s.ca_file = Some("/Users/op/noomesh/pki/ca.crt".into());
        s.extra_ro = vec![];
        let p = macos_profile(Path::new("/Users/op"), &s).unwrap();
        let lines: Vec<&str> = p.lines().collect();
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle} missing:\n{p}"));
        let whole = at("(deny file-read* file-write* (subpath \"/Users/op/noomesh\"))");
        let named = at("(subpath \"/Users/op/noomesh/secrets\") (subpath \"/Users/op/noomesh/harness-secrets\")");
        assert!(lines[named].starts_with("(deny "), "{p}");
        assert!(at("(allow default)") < whole && whole <= named);
        for secret in ["/Users/op/noomesh/secrets/NATS_NODE_PASSWORD", "/Users/op/noomesh/harness-secrets/NOO_CLUSTER_SECRET", "/Users/op/noomesh/pki/node.key"] {
            // `stat` of a literal directory is not a read of what is in it.
            for l in lines.iter().filter(|l| l.starts_with("(allow file-") && !l.starts_with("(allow file-read-metadata (literal ")) {
                for path in l.split('"').skip(1).step_by(2) {
                    assert!(!Path::new(secret).starts_with(path), "{l} re-allows {secret}");
                }
            }
        }
        // The real home is denied first, before every re-allow, and the
        // only re-allows under it are the CLI's trees, the CA file and
        // `stat` of the two directories on the way down.
        let home_deny = at("(deny file-read* file-write* (subpath \"/Users/op\"))");
        assert!(at("(allow default)") < home_deny && home_deny < whole, "{p}");
        for l in lines.iter().filter(|l| l.starts_with("(allow file-")) {
            assert!(lines.iter().position(|x| x == l).unwrap() > home_deny, "{l} sits before the home deny");
            for path in l.split('"').skip(1).step_by(2) {
                if Path::new(path).starts_with("/Users/op") {
                    let ok = l.starts_with("(allow file-read-metadata (literal ")
                        || ["/Users/op/noomesh/vendor", "/Users/op/noomesh/bin", "/Users/op/noomesh/pki/ca.crt"].contains(&path);
                    assert!(ok, "{l} re-allows {path} under the real home");
                }
            }
        }
        for private in ["/Users/op/.ssh/id_ed25519", "/Users/op/Documents/x", "/Users/op/Library/Keychains/login.keychain-db"] {
            for l in lines.iter().filter(|l| l.starts_with("(allow file-read* ") || l.starts_with("(allow file-read* file-write* ")) {
                for path in l.split('"').skip(1).step_by(2) {
                    assert!(!Path::new(private).starts_with(path), "{l} re-allows {private}");
                }
            }
        }
        let deny_pi = at("(deny process-info*)");
        let self_pi = at("(allow process-info* (target self))");
        assert!(deny_pi < self_pi, "last match wins: the self re-allow comes after the deny");
        assert!(!p.contains("(allow process-info* (target others))") && !p.contains("(allow sysctl-read"), "{p}");
        let sys = at("(deny sysctl-read");
        assert!(lines[sys].contains("(sysctl-name \"kern.procargs2\")") && lines[sys].contains("(sysctl-name \"kern.procargs\")"));
        // What the self-test reads on a Mac.
        let hide = macos_must_hide(Path::new("/Users/op"));
        for want in ["/Users/op/noomesh/secrets", "/Users/op/noomesh/harness-secrets", "/Users/op/noomesh/pki", "/Users/op/noomesh/agent.env"] {
            assert!(hide.contains(&PathBuf::from(want)), "{want}");
        }
    }

    #[test]
    fn a_failed_self_test_closes_the_gate_and_an_unrun_one_defers_to_the_probe() {
        let ok = Ok(SelfTestReport { os: "linux", mechanism: Available::Landlock(7), elapsed: Default::default(), proved: vec![], unproved: vec![] });
        let bad: Result<SelfTestReport, Refusal> = Err(Refusal::new("jail self-test failed: the planted secret /x was readable inside the jail"));
        assert_eq!(gate_from(Ok(Available::Landlock(7)), None), Ok(Available::Landlock(7)));
        assert_eq!(gate_from(Ok(Available::Landlock(7)), Some(&ok)), Ok(Available::Landlock(7)));
        let e = gate_from(Ok(Available::Landlock(7)), Some(&bad)).unwrap_err();
        assert!(e.note().contains("the planted secret /x was readable") && e.note().contains("never run unjailed"), "{}", e.note());
        let probe_err = Refusal::new("no Landlock");
        assert_eq!(gate_from(Err(probe_err.clone()), Some(&ok)), Err(probe_err));
        assert_eq!(ok.as_ref().unwrap().to_string(), "ok (linux, landlock ABI 7)");
    }

    #[test]
    fn sections_are_read_between_their_markers_only() {
        let out = "x\n@@a-begin\nhello\n@@a-end\n@@b-begin\n@@b-end\n";
        assert_eq!(section(out, "a"), Some("hello\n"));
        assert_eq!(section(out, "b"), Some(""));
        assert_eq!(section(out, "c"), None, "a check that did not report is not a pass");
        assert!(shell_quote(Path::new("/tmp/it's")).is_err());
        assert_eq!(shell_quote(Path::new("/tmp/a b")).unwrap(), "'/tmp/a b'");
    }

    /// Integration, on the running kernel: a shell through the jail, as the
    /// current user. Skips — out loud — where Landlock is unavailable.
    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use std::io::Read;

        fn scratch(tag: &str) -> PathBuf {
            let p = std::env::temp_dir().join(format!("noo-jail-test-{tag}-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        async fn sh(spec: &JailSpec, script: &str) -> (Option<i32>, String, String) {
            let mut cmd = command(Path::new("/bin/sh"), spec).expect("jail built");
            let out = cmd
                .arg("-c")
                .arg(script)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&spec.workspace)
                .stdin(std::process::Stdio::null())
                .output()
                .await
                .unwrap();
            (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
        }

        #[tokio::test]
        async fn the_jail_holds_on_this_kernel() {
            let abi = match probe() {
                Ok(a) => a,
                Err(r) => {
                    eprintln!("SKIPPED the_jail_holds_on_this_kernel: {r} — this host cannot run the integration check");
                    return;
                }
            };
            eprintln!("jail integration on {abi}");
            let root = scratch("it");
            let (work, home, tmp) = (root.join("work"), root.join("home"), root.join("tmp"));
            for d in [&work, &home, &tmp] {
                std::fs::create_dir_all(d).unwrap();
            }
            std::fs::write(work.join("in.txt"), "inside").unwrap();
            // The planted secret: outside the allow-list, readable by this
            // user without the jail.
            let outside = scratch("secret");
            let secret = outside.join("node.key");
            std::fs::write(&secret, "PRIVATE KEY").unwrap();
            let mut plain = String::new();
            std::fs::File::open(&secret).unwrap().read_to_string(&mut plain).unwrap();
            assert_eq!(plain, "PRIVATE KEY", "readable without the jail");
            // A loopback listener: the network is not restricted.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let accept = std::thread::spawn(move || listener.accept().map(|_| ()).is_ok());
            let spec = JailSpec { workspace: work.clone(), home: home.clone(), tmp: tmp.clone(), ..Default::default() };
            let me = std::process::id();
            // dash has no /dev/tcp: python3 makes the loopback connect.
            let script = format!(
                "cat in.txt && echo; \
                 echo written > out.txt && cat out.txt; \
                 if cat {secret} >/dev/null 2>&1; then echo SECRET_READ; else echo secret_denied; fi; \
                 if cat /proc/{me}/environ >/dev/null 2>&1; then echo ENVIRON_READ; else echo environ_denied; fi; \
                 if cat /proc/self/status >/dev/null; then echo self_proc_ok; fi; \
                 if ls /home >/dev/null 2>&1; then echo HOME_LISTED; else echo home_denied; fi; \
                 /usr/bin/env >/dev/null && echo env_ran; \
                 if command -v python3 >/dev/null; then python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", {port}), 5)' && echo tcp_ok; else echo tcp_unchecked; fi",
                secret = secret.display()
            );
            let (code, out, err) = sh(&spec, &script).await;
            eprintln!("--- jailed sh stdout ---\n{out}--- stderr ---\n{err}--- exit {code:?}");
            assert!(out.contains("inside"), "reads the workspace: {out}");
            assert!(out.contains("written"), "writes the workspace: {out}");
            assert!(std::fs::read_to_string(work.join("out.txt")).unwrap().contains("written"));
            assert!(out.contains("secret_denied") && !out.contains("SECRET_READ"), "the planted secret is unreadable: {out}");
            assert!(out.contains("environ_denied") && !out.contains("ENVIRON_READ"), "the parent's environ is unreadable: {out}");
            assert!(out.contains("self_proc_ok"), "its own /proc is readable: {out}");
            assert!(out.contains("home_denied"), "/home is unreachable: {out}");
            assert!(out.contains("env_ran"), "/usr/bin/env executes: {out}");
            if out.contains("tcp_unchecked") {
                eprintln!("loopback connect not checked: no python3 in the jail's PATH");
                drop(std::net::TcpStream::connect(("127.0.0.1", port)));
            } else {
                assert!(out.contains("tcp_ok"), "loopback TCP connects: {out}");
            }
            assert!(accept.join().unwrap());
            // The errno: EACCES, said by the kernel, not a missing file.
            let (_, out, _) = sh(&spec, &format!("cat {} 2>&1; true", secret.display())).await;
            assert!(out.contains("Permission denied"), "EACCES: {out}");
            let (_, out, _) = sh(&spec, &format!("cat /proc/{me}/environ 2>&1; true")).await;
            assert!(out.contains("Permission denied"), "environ is EACCES: {out}");
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
        }

        /// The startup self-test, for real, on this kernel: ok, in time,
        /// and remembered for the process.
        #[tokio::test]
        async fn the_self_test_passes_on_this_kernel() {
            if let Err(r) = probe() {
                eprintln!("SKIPPED the_self_test_passes_on_this_kernel: {r}");
                return;
            }
            let plan = SelfTestPlan::for_this_host(&std::env::temp_dir().join("noo-harness")).unwrap();
            let r = run_self_test(&plan, &|_, _| {}).await.unwrap_or_else(|e| panic!("self-test refused on this host: {e}"));
            eprintln!("harness jail self-test: {r} in {:?}\n  proved: {:?}\n  unproved: {:?}", r.elapsed, r.proved, r.unproved);
            assert_eq!(r.os, "linux");
            assert!(r.elapsed < std::time::Duration::from_secs(2), "{:?}", r.elapsed);
            for want in ["workspace readable", "workspace writable", "planted secret", "sibling environment unreadable", "harness environment unreadable"] {
                assert!(r.proved.iter().any(|p| p.starts_with(want)), "{want} not proved: {r:?}");
            }
            assert!(!plan.scratch.exists() && !plan.plant_dir.exists(), "the self-test cleans up");
            let root = std::env::temp_dir().join("noo-harness");
            let first = self_test(&root).await.unwrap();
            let again = self_test(&root).await.unwrap();
            assert_eq!(first, again, "one verdict per process");
            assert!(gate().is_ok());
        }

        /// A jail that is wrong is caught and named: the planted secret
        /// handed to the jail as a readable file.
        #[tokio::test]
        async fn a_broken_jail_fails_the_self_test_naming_the_leak() {
            if let Err(r) = probe() {
                eprintln!("SKIPPED a_broken_jail_fails_the_self_test_naming_the_leak: {r}");
                return;
            }
            let plan = SelfTestPlan::for_this_host(&std::env::temp_dir().join("noo-harness")).unwrap();
            let e = run_self_test(&plan, &|spec, secret| spec.extra_ro.push(secret.to_path_buf())).await.unwrap_err();
            eprintln!("harness_jail_selftest_failed: {e}");
            assert!(e.0.starts_with("jail self-test failed: the planted secret "), "{e}");
            assert!(e.0.contains(&plan.plant_dir.display().to_string()) && e.0.ends_with("was readable inside the jail"), "{e}");
            // A plan that hides a path the jail grants: named too.
            let mut plan = SelfTestPlan::for_this_host(&std::env::temp_dir().join("noo-harness")).unwrap();
            plan.must_hide = vec![PathBuf::from("/etc/passwd"), PathBuf::from("/usr/bin")];
            let started = std::time::Instant::now();
            let e = run_self_test(&plan, &|_, _| {}).await.unwrap_err();
            assert_eq!(e.0, "jail self-test failed: /etc/passwd was readable inside the jail");
            plan.must_hide = vec![PathBuf::from("/usr/bin")];
            let e = run_self_test(&plan, &|_, _| {}).await.unwrap_err();
            assert_eq!(e.0, "jail self-test failed: /usr/bin was readable inside the jail");
            assert!(started.elapsed() < std::time::Duration::from_secs(4), "a leaking tree is not read whole: {:?}", started.elapsed());
            assert!(!plan.scratch.exists() && !plan.plant_dir.exists());
        }
    }
}
