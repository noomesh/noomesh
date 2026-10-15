// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! From an add-on name to verified, pulled, pinned images.
//!
//! Every path that moves an add-on (`noo addons enable`, `noo addons
//! upgrade`, `noo upgrade --stack`) runs the same steps in the same order:
//!   1. the trust anchor from the installed entitlement
//!      (`addons.<name>` = keys + registry root);
//!   2. fetch `<root>:stack-<tag>` ([`super::lock_fetch`]);
//!   3. [`crate::addon_lock::verify`]: signature, add-on name, registry root,
//!      and for a bundle every fetched file against its signed hash
//!      ([`crate::addon_lock::verify_files`]);
//!   4. the lock lists `<tag>` (`supports`);
//!   5. a lock built on a stack image matches that image's row in the
//!      verified `stack.lock` for `<tag>` (`base_matches`);
//!   6. not older than the pinned version unless `--allow-downgrade`
//!      (`is_downgrade`);
//!   7. pull every image by digest through a throwaway docker config;
//!   8. cache the lock, write the pin, and materialise the bundle files under
//!      `<root>/addons/<addon>/` (a lock without files removes that directory).
//!
//! Steps 1-6 decide; nothing is written until all of them pass. The offline
//! twin ([`offline_check`]) re-runs 1, 3, 4 and the pin comparison from the
//! cache, and holds the materialised files to the cached lock, for `noo
//! addons verify` and the launcher.

use std::path::Path;

use crate::addon_lock::{self, AddonLockError, TrustAnchor, VerifiedLock};
use crate::release_fetch::{FetchClass, FetchError};

use super::lock_fetch::{self, Credential, Fetched};
use super::pins::{self, Pin};

/// What one resolve is for.
#[derive(Debug, Clone, Copy)]
pub struct Want<'a> {
    pub addon: &'a str,
    pub stack_tag: &'a str,
    /// The verified stack lock text for `stack_tag` (rows `name@sha256:…`),
    /// when one is published. A lock with a `base` is refused without it.
    pub stack_lock: Option<&'a str>,
    /// The version pinned now, for the downgrade rule.
    pub pinned: Option<&'a str>,
    pub allow_downgrade: bool,
}

/// Why an add-on lock was not accepted. `why` is the operator's sentence;
/// the remedy depends on the verb, so the caller supplies it.
#[derive(Debug, Clone)]
pub enum Refusal {
    NoEntitlement(String),
    NoAnchor,
    Fetch { reference: String, stack_tag: String, err: FetchError },
    Lock(AddonLockError),
    NotForStack { tag: String, version: String, supports: Vec<String> },
    NoStackLock { image: String, tag: String },
    BaseRowMissing { image: String, tag: String },
    Base(AddonLockError),
    Downgrade { pinned: String, offered: String },
    Pull(String),
    Write(String),
    /// The encrypted store could not be read (a decrypt failure is never
    /// "nothing installed").
    Store(String),
}

impl Refusal {
    pub fn why(&self, addon: &str) -> String {
        match self {
            Refusal::NoEntitlement(e) => format!("{addon} is licensed and no usable entitlement is installed ({e})"),
            Refusal::NoAnchor => format!(
                "the installed entitlement names no signing key or registry for {addon}, so its lock cannot be verified \
                 (the token predates signed add-on locks)"
            ),
            Refusal::Fetch { stack_tag, err, .. } if err.class == FetchClass::NotFound => not_published(stack_tag),
            Refusal::Fetch { reference, err, .. } => match err.class {
                FetchClass::Auth => format!(
                    "the registry refused {reference} (access refused): the controller's {} cannot read {addon}'s package",
                    lock_fetch::TOKEN_KEY
                ),
                _ => format!("{reference}: {}", err.summary()),
            },
            Refusal::Lock(e) => format!("{addon}'s lock refused: {e}"),
            Refusal::NotForStack { tag, version, supports } => format!(
                "{addon} {version} does not support stack {tag} (it lists {})",
                supports.join(", ")
            ),
            Refusal::NoStackLock { image, tag } => format!(
                "{addon} is built on the stack's {image} image, and stack {tag} has no verified stack.lock to check it against"
            ),
            Refusal::BaseRowMissing { image, tag } => format!("stack {tag}'s lock has no {image} row to check {addon}'s base against"),
            Refusal::Base(e) => format!("{addon}: {e}"),
            Refusal::Downgrade { pinned, offered } => format!(
                "{addon} {offered} is older than the pinned {pinned}; an add-on may carry database migrations, so this is \
                 refused without --allow-downgrade"
            ),
            Refusal::Pull(e) => format!("{addon}'s images could not be pulled: {e}"),
            Refusal::Write(e) => format!("{addon}'s pin could not be written: {e}"),
            Refusal::Store(e) => format!("the encrypted store could not be read to resolve {addon}: {e}"),
        }
    }

    /// True when the registry refused the credential: the remedy is the
    /// token, not the add-on.
    pub fn is_auth(&self) -> bool {
        matches!(self, Refusal::Fetch { err, .. } if err.class == FetchClass::Auth)
    }
}

/// The refusal for an add-on lock the registry does not have (HTTP 404,
/// `manifest unknown`): the stack release is out, and the vendor's own
/// release workflow signs the add-on lock for it minutes later. Distinct
/// from an auth or signature failure, whose text and remedy are different.
/// No `<addon>: ` prefix: every caller that prints it beside others already
/// leads with the add-on's name (`x evolve: evolve: …` was the 0.6.4-rc.1
/// rehearsal's output), and the one that does not adds it.
pub fn not_published(stack_tag: &str) -> String {
    let tag = format!("v{}", stack_tag.trim().trim_start_matches("stack-").trim_start_matches('v'));
    format!(
        "no signed lock published yet for {tag} — the vendor publishes it minutes after a stack release; \
         retry shortly, or roll back with `noo upgrade --stack --tag <vX.Y.Z>`"
    )
}

/// True when the refusal is "the registry has no lock for this stack".
pub fn is_not_published(r: &Refusal) -> bool {
    matches!(r, Refusal::Fetch { err, .. } if err.class == FetchClass::NotFound)
}

/// The remedy for a credential refusal, shared by every verb.
pub const TOKEN_FIX: &str = "noo security secrets rotate NOO_ADDON_REGISTRY_TOKEN --set-from-stdin --yes";

/// The digest a stack lock pins for `image` (rows `name@sha256:…`).
pub fn stack_lock_row(text: &str, image: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (name, digest) = l.trim().split_once('@')?;
        (name == image && addon_lock::is_sha256_digest(digest)).then(|| digest.to_string())
    })
}

/// The installed `stack.lock` text when it is for `tag` (header `# tag
/// <tag>`, written by `noo upgrade --stack` after verifying it).
pub fn installed_stack_lock(root: &Path, tag: &str) -> Option<String> {
    let text = std::fs::read_to_string(root.join("stack.lock")).ok()?;
    text.lines().any(|l| l.trim() == format!("# tag {tag}")).then_some(text)
}

/// Steps 3-6 over fetched bytes. Pure.
pub fn check(fetched: &Fetched, anchor: &TrustAnchor, want: &Want) -> Result<VerifiedLock, Refusal> {
    let v = addon_lock::verify(&fetched.lock, &fetched.sig, anchor, want.addon).map_err(Refusal::Lock)?;
    addon_lock::verify_files(&v.lock, &fetched.files).map_err(Refusal::Lock)?;
    if !v.lock.supports(want.stack_tag) {
        return Err(Refusal::NotForStack {
            tag: want.stack_tag.to_string(),
            version: v.lock.version.clone(),
            supports: v.lock.supports_stack.clone(),
        });
    }
    if let Some(base) = &v.lock.base {
        let text = want
            .stack_lock
            .ok_or_else(|| Refusal::NoStackLock { image: base.image.clone(), tag: want.stack_tag.to_string() })?;
        let row = stack_lock_row(text, &base.image)
            .ok_or_else(|| Refusal::BaseRowMissing { image: base.image.clone(), tag: want.stack_tag.to_string() })?;
        v.lock.base_matches(&row).map_err(Refusal::Base)?;
    }
    if let Some(p) = want.pinned {
        if !want.allow_downgrade && addon_lock::is_downgrade(p, &v.lock.version).map_err(Refusal::Lock)? {
            return Err(Refusal::Downgrade { pinned: p.to_string(), offered: v.lock.version.clone() });
        }
    }
    Ok(v)
}

/// Steps 2-6: fetch and check.
pub fn fetch_and_check(
    client: &lock_fetch::Client,
    anchor: &TrustAnchor,
    want: &Want,
) -> Result<(VerifiedLock, Fetched), Refusal> {
    let fetched = client.fetch(&anchor.registry, want.stack_tag).map_err(|err| Refusal::Fetch {
        reference: lock_fetch::artifact_ref(&anchor.registry, want.stack_tag),
        stack_tag: want.stack_tag.to_string(),
        err,
    })?;
    let v = check(&fetched, anchor, want)?;
    Ok((v, fetched))
}

/// The anchor for `addon` from the installed, unexpired entitlement.
pub fn installed_anchor(addon: &str) -> Result<TrustAnchor, Refusal> {
    let token = crate::entitlement::installed_token_checked()
        .map_err(Refusal::Store)?
        .ok_or_else(|| Refusal::NoEntitlement("none installed".into()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ent = crate::entitlement::check(&token, now).map_err(Refusal::NoEntitlement)?;
    ent.addon_anchor(addon).cloned().ok_or(Refusal::NoAnchor)
}

/// The docker side, behind a seam so pulls and the throwaway login are
/// testable without a daemon.
pub trait Docker {
    /// Is this exact reference (by digest) in the local image store?
    fn image_present(&mut self, reference: &str) -> bool;
    /// Pull `refs` (all digest-form) from `host`, logging in with `cred` in
    /// a throwaway config that is removed afterwards.
    fn pull(&mut self, host: &str, refs: &[String], cred: Option<&Credential>) -> Result<(), String>;
    /// The local image id (`sha256:…`) of this exact reference, or why it
    /// could not be read.
    fn image_id(&mut self, reference: &str) -> Result<String, String>;
    /// Running containers, read with `docker inspect` (not `docker ps`,
    /// whose IMAGE column drops the digest of a digest-only reference).
    fn running(&mut self) -> Result<Vec<Container>, String>;
}

/// One running container as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    /// `.Config.Image`: the reference it was created from, digest included.
    pub config_image: String,
    /// `.Image`: the id of the image it actually runs.
    pub image_id: String,
}

/// Parse `docker inspect --format '{{.Name}}\t{{.Config.Image}}\t{{.Image}}'`
/// output. A line that is not three fields is an error, never skipped.
pub fn parse_inspect(out: &str) -> Result<Vec<Container>, String> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            match f.as_slice() {
                [n, c, i] if !n.is_empty() && !c.is_empty() && !i.is_empty() => Ok(Container {
                    name: n.trim_start_matches('/').to_string(),
                    config_image: c.to_string(),
                    image_id: i.to_string(),
                }),
                _ => Err(format!("unexpected docker inspect line {l:?}")),
            }
        })
        .collect()
}

/// Step 7: every image by digest, skipping what is already local.
pub fn pull_images(docker: &mut dyn Docker, v: &VerifiedLock, cred: Option<&Credential>) -> Result<usize, Refusal> {
    let missing: Vec<String> = v.lock.images.values().filter(|r| !docker.image_present(r)).cloned().collect();
    if missing.is_empty() {
        return Ok(0);
    }
    let host = missing[0].split('/').next().unwrap_or_default().to_string();
    docker.pull(&host, &missing, cred).map_err(Refusal::Pull)?;
    if let Some(r) = missing.iter().find(|r| !docker.image_present(r)) {
        return Err(Refusal::Pull(format!("{r} is still not in the local image store after the pull")));
    }
    Ok(missing.len())
}

/// Step 8: cache the lock and set this add-on's pin (other pins kept), as
/// one atomic pair under the pins lock (`pins::set_pin`).
/// Then the bundle files are materialised (or a stale bundle directory is
/// removed for a lock without files). A failure there leaves the new pin
/// with files that do not match it, which every offline check refuses, so
/// the remedy (`noo addons upgrade`) is named rather than a mixed state run.
pub fn record(root: &Path, addon: &str, v: &VerifiedLock, fetched: &Fetched, stack_tag: &str) -> Result<Pin, Refusal> {
    let pin = Pin::from_verified(v, stack_tag, &fetched.lock);
    pins::set_pin(root, addon, &pin, &fetched.lock, &fetched.sig).map_err(Refusal::Write)?;
    pins::materialise(root, addon, &fetched.files).map_err(Refusal::Write)?;
    Ok(pin)
}

/// What the offline check found besides the pin: whether the lock is a
/// bundle (its files verified on disk) or predates bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Overlay {
    /// The lock lists files and `<root>/addons/<addon>/` holds exactly their
    /// signed bytes.
    Bundled,
    /// A `noo-addon-lock/1` lock: no overlay travels with it. `Some(path)`
    /// is the deprecated overlay an earlier CLI left in the slice, `None`
    /// that there is none, so the add-on cannot be composed.
    Legacy(Option<std::path::PathBuf>),
}

/// The offline check: the cached lock still verifies against `anchor`,
/// lists `tag`, and is exactly what the pin says. Returns the pin.
#[cfg(test)]
pub fn offline_check(root: &Path, addon: &str, tag: &str, anchor: &TrustAnchor) -> Result<Pin, String> {
    offline_check_bundle(root, addon, tag, anchor).map(|(p, _)| p)
}

/// [`offline_check`], also saying how the add-on's overlay arrives.
pub fn offline_check_bundle(root: &Path, addon: &str, tag: &str, anchor: &TrustAnchor) -> Result<(Pin, Overlay), String> {
    let all = pins::read(root)?;
    let pin = all.get(addon).cloned().ok_or_else(|| format!("{addon} has no pin in {}", pins::PINS_FILE))?;
    if pin.stack != tag {
        return Err(format!("{addon} is pinned for stack {}, and this stack runs {tag}", pin.stack));
    }
    let (lock, sig) = pins::cached_lock(root, addon, &pin)?;
    let v = addon_lock::verify(&lock, &sig, anchor, addon).map_err(|e| format!("{addon}'s cached lock no longer verifies: {e}"))?;
    if !v.lock.supports(tag) {
        return Err(format!("{addon} {}'s lock does not list stack {tag}", v.lock.version));
    }
    if v.lock.images != pin.images || v.lock.version != pin.version || v.key_index != pin.key_index {
        return Err(format!("{addon}'s pin does not match its signed lock ({} was edited)", pins::PINS_FILE));
    }
    if v.lock.files.is_empty() {
        let legacy = pins::legacy_overlay(root, addon);
        return Ok((pin, Overlay::Legacy(legacy.is_file().then_some(legacy))));
    }
    let found = pins::materialised_files(root, addon, v.lock.files.keys());
    addon_lock::verify_files(&v.lock, &found).map_err(|e| {
        format!(
            "{addon}'s bundle files in {} do not match its signed lock ({e}): they were edited or left from another version",
            pins::addon_dir(root, addon).display()
        )
    })?;
    Ok((pin, Overlay::Bundled))
}

/// The production [`Docker`]. Its throwaway docker configs live under the
/// install's runtime secrets directory (`<root>/secrets/.runtime`, 0700).
pub struct LiveDocker {
    runtime: std::path::PathBuf,
}

impl LiveDocker {
    pub fn new(root: &Path) -> Self {
        LiveDocker { runtime: root.join("secrets").join(".runtime") }
    }
}

fn last_line(b: &[u8]) -> String {
    String::from_utf8_lossy(b).lines().last().unwrap_or("").to_string()
}

impl Docker for LiveDocker {
    fn image_present(&mut self, reference: &str) -> bool {
        std::process::Command::new("docker")
            .args(["image", "inspect", "--format", "{{.Id}}", reference])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn pull(&mut self, host: &str, refs: &[String], cred: Option<&Credential>) -> Result<(), String> {
        // Declared first so it drops LAST: the directory is gone before a
        // deferred Ctrl-C or SIGTERM is re-raised.
        let _signals = DeferSignals::install();
        sweep_stale(&self.runtime);
        let dir = ThrowawayConfig::new(&self.runtime)?;
        if let Some(c) = cred {
            let mut child = std::process::Command::new("docker")
                .arg("--config")
                .arg(&dir.0)
                .args(["login", host, "--username", &c.user, "--password-stdin"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("docker login: {e}"))?;
            if let Some(mut si) = child.stdin.take() {
                crate::child_stdin::write_child_stdin(&mut si, c.token.as_bytes()).map_err(|e| format!("docker login: {e}"))?;
            }
            let out = child.wait_with_output().map_err(|e| format!("docker login: {e}"))?;
            if !out.status.success() {
                return Err(format!("docker login {host} refused the add-on registry token: {}", last_line(&out.stderr)));
            }
        }
        for r in refs {
            let out = std::process::Command::new("docker")
                .arg("--config")
                .arg(&dir.0)
                .args(["pull", "--quiet", r])
                .output()
                .map_err(|e| format!("docker pull: {e}"))?;
            if !out.status.success() {
                return Err(format!("docker pull {r}: {}", last_line(&out.stderr)));
            }
        }
        Ok(())
    }

    fn image_id(&mut self, reference: &str) -> Result<String, String> {
        let out = std::process::Command::new("docker")
            .args(["image", "inspect", "--format", "{{.Id}}", reference])
            .output()
            .map_err(|e| format!("docker image inspect: {e}"))?;
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || id.is_empty() {
            return Err(format!("docker image inspect {reference}: {}", last_line(&out.stderr)));
        }
        Ok(id)
    }

    fn running(&mut self) -> Result<Vec<Container>, String> {
        // A container that exits between `ps` and `inspect` fails the
        // inspect; read once more before calling it an error.
        let mut last = String::new();
        for _ in 0..2 {
            let ps = std::process::Command::new("docker")
                .args(["ps", "-q", "--no-trunc"])
                .output()
                .map_err(|e| format!("docker ps: {e}"))?;
            if !ps.status.success() {
                return Err(format!("docker ps: {}", String::from_utf8_lossy(&ps.stderr).trim()));
            }
            let ids: Vec<String> = String::from_utf8_lossy(&ps.stdout).split_whitespace().map(String::from).collect();
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let out = std::process::Command::new("docker")
                .args(["inspect", "--type", "container", "--format", "{{.Name}}\t{{.Config.Image}}\t{{.Image}}"])
                .args(&ids)
                .output()
                .map_err(|e| format!("docker inspect: {e}"))?;
            if out.status.success() {
                let found = parse_inspect(&String::from_utf8_lossy(&out.stdout)).map_err(|e| format!("docker inspect: {e}"))?;
                if found.len() != ids.len() {
                    return Err(format!("docker inspect: {} of {} running containers read", found.len(), ids.len()));
                }
                return Ok(found);
            }
            last = String::from_utf8_lossy(&out.stderr).trim().to_string();
        }
        Err(format!("docker inspect: {last}"))
    }
}

const THROWAWAY_PREFIX: &str = "noo-addon-docker-";

/// Remove throwaway configs a killed run left behind (SIGKILL, power loss):
/// a registry token must not outlive the operation that needed it.
/// A directory whose owning process (`noo-addon-docker-<pid>-…`) is still
/// alive belongs to a concurrent operation and is left alone.
pub fn sweep_stale(runtime: &Path) {
    let Ok(entries) = std::fs::read_dir(runtime) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(THROWAWAY_PREFIX) else { continue };
        let pid: Option<i32> = rest.split('-').next().and_then(|p| p.parse().ok());
        if pid.is_some_and(pid_alive) {
            continue;
        }
        let _ = std::fs::remove_dir_all(e.path());
    }
}

/// Is `pid` a live process (ours, or one we may not signal)?
fn pid_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        if pid <= 0 {
            return false;
        }
        // SAFETY: signal 0 only checks that the process exists.
        let r = unsafe { libc::kill(pid, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// A docker config directory (mode 0700, under a 0700 parent) that exists
/// for one operation and is removed on drop, so the registry token is never
/// left in `~/.docker/config.json`.
pub struct ThrowawayConfig(pub std::path::PathBuf);

impl ThrowawayConfig {
    pub fn new(runtime: &Path) -> Result<Self, String> {
        let mk = |p: &Path| -> std::io::Result<()> {
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                b.mode(0o700);
            }
            b.create(p)
        };
        if !runtime.is_dir() {
            if let Some(parent) = runtime.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            match mk(runtime) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("{}: {e}", runtime.display())),
            }
        }
        for n in 0..100u32 {
            let p = runtime.join(format!(
                "{THROWAWAY_PREFIX}{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0)
            ));
            match mk(&p) {
                Ok(()) => return Ok(ThrowawayConfig(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
        }
        Err("could not create a throwaway docker config directory".into())
    }
}

impl Drop for ThrowawayConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// While alive, SIGINT/SIGTERM/SIGHUP are recorded instead of killing the
/// process (a signal would skip every destructor, the throwaway config's
/// included). A Ctrl-C still reaches the docker child in the foreground
/// process group, so the pull stops; on drop the previous dispositions come
/// back and a recorded signal is re-raised, so the exit status is still the
/// signal's.
pub struct DeferSignals {
    #[cfg(unix)]
    prev: Vec<(libc::c_int, libc::sighandler_t)>,
}

#[cfg(unix)]
static DEFERRED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

impl DeferSignals {
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            extern "C" fn record(sig: libc::c_int) {
                DEFERRED.store(sig, std::sync::atomic::Ordering::SeqCst);
            }
            DEFERRED.store(0, std::sync::atomic::Ordering::SeqCst);
            let handler = record as *const () as libc::sighandler_t;
            let prev = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                .iter()
                // SAFETY: installing a handler that only stores an atomic.
                .map(|&s| (s, unsafe { libc::signal(s, handler) }))
                // SIG_ERR = the handler was not installed; nothing to restore.
                .filter(|(_, h)| *h != libc::SIG_ERR)
                .collect();
            DeferSignals { prev }
        }
        #[cfg(not(unix))]
        DeferSignals {}
    }
}

impl Drop for DeferSignals {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            for (s, h) in &self.prev {
                // SAFETY: restoring the disposition we replaced.
                unsafe { libc::signal(*s, *h) };
            }
            let sig = DEFERRED.swap(0, std::sync::atomic::Ordering::SeqCst);
            if sig != 0 {
                // SAFETY: re-raising the signal we deferred.
                unsafe { libc::raise(sig) };
            }
        }
    }
}

/// How a pinned image's running containers compare with the pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Running {
    /// Containers created from exactly the pinned digest AND running the
    /// image id that digest has locally.
    Pinned(Vec<String>),
    /// Containers of the same repository that are not that: `(name, why)`.
    Drift(Vec<(String, String)>),
    Absent,
}

/// `repo` of a reference: tag and digest stripped (a registry port kept).
fn repo_of(r: &str) -> &str {
    let base = r.split('@').next().unwrap_or(r);
    let last_slash = base.rfind('/').map(|i| i + 1).unwrap_or(0);
    match base[last_slash..].find(':') {
        Some(c) => &base[..last_slash + c],
        None => base,
    }
}

fn short_id(id: &str) -> &str {
    let h = id.strip_prefix("sha256:").unwrap_or(id);
    &h[..h.len().min(12)]
}

/// Compare one pinned reference (`repo@sha256:…`) with the running
/// containers. `pinned_id` is the local image id of that reference (`None`
/// when it could not be read: nothing can then be confirmed as pinned).
pub fn running_state(pinned_ref: &str, pinned_id: Option<&str>, running: &[Container]) -> Running {
    let want = repo_of(pinned_ref);
    let digest = pinned_ref.split_once('@').map(|(_, d)| d);
    let mut exact = Vec::new();
    let mut drift = Vec::new();
    for c in running.iter().filter(|c| repo_of(&c.config_image) == want) {
        let created_from = c.config_image.split_once('@').map(|(_, d)| d);
        if digest.is_none() || created_from != digest {
            drift.push((c.name.clone(), format!("runs {}", c.config_image)));
            continue;
        }
        match pinned_id {
            Some(id) if id == c.image_id => exact.push(c.name.clone()),
            Some(id) => drift.push((
                c.name.clone(),
                format!("was created from the pinned digest but runs image {}, not {}", short_id(&c.image_id), short_id(id)),
            )),
            None => drift.push((c.name.clone(), format!("runs image {}, and the pinned image's id is unknown", short_id(&c.image_id)))),
        }
    }
    if !drift.is_empty() {
        Running::Drift(drift)
    } else if !exact.is_empty() {
        Running::Pinned(exact)
    } else {
        Running::Absent
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::addon_lock::{AddonLock, BaseImage};
    use crate::release_sig;
    use std::collections::BTreeMap;

    pub(crate) const ROOT: &str = "ghcr.io/example/intel";

    pub(crate) fn seed() -> String {
        "cd".repeat(32)
    }

    pub(crate) fn anchor() -> TrustAnchor {
        let pk = release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&seed()).unwrap());
        TrustAnchor { keys: vec![pk], registry: ROOT.into() }
    }

    pub(crate) fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    pub(crate) fn lock(version: &str, supports: &[&str], base: Option<&str>) -> AddonLock {
        AddonLock {
            format: addon_lock::FORMAT.into(),
            addon: "trellion_intel".into(),
            version: version.into(),
            source_commit: "a".repeat(40),
            supports_stack: supports.iter().map(|s| s.to_string()).collect(),
            images: BTreeMap::from([("trellion-intel".into(), format!("{ROOT}@{}", digest('1')))]),
            base: base.map(|d| BaseImage { image: "trellion".into(), digest: d.into() }),
            files: BTreeMap::new(),
        }
    }

    pub(crate) fn signed(l: &AddonLock) -> Fetched {
        let (bytes, sig) = addon_lock::sign(l, &seed()).unwrap();
        Fetched { lock: bytes, sig, files: BTreeMap::new() }
    }

    /// The overlay text the bundle tests carry (any compose text works; the
    /// image line is what the launcher reads).
    pub(crate) const OVERLAY: &str =
        "services:\n  trellion-intel:\n    image: ${NOO_ADDON_IMAGE_TRELLION_INTEL:-noo-addon-unpinned.invalid/trellion-intel:x}\n";

    /// A signed BUNDLE of `l` (format 2) carrying [`OVERLAY`].
    pub(crate) fn signed_bundle(l: &AddonLock) -> Fetched {
        let mut l = l.clone();
        l.format = addon_lock::FORMAT_V2.into();
        let files = BTreeMap::from([(addon_lock::OVERLAY_FILE.to_string(), OVERLAY.as_bytes().to_vec())]);
        l.files = files.iter().map(|(n, b)| (n.clone(), addon_lock::sha256_ref(b))).collect();
        let (bytes, sig) = addon_lock::sign(&l, &seed()).unwrap();
        Fetched { lock: bytes, sig, files }
    }

    fn want<'a>(stack_lock: Option<&'a str>, pinned: Option<&'a str>) -> Want<'a> {
        Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock, pinned, allow_downgrade: false }
    }

    #[test]
    fn a_good_lock_passes_every_step() {
        let stack = format!("# tag v0.6.0\ngateway@{}\ntrellion@{}\n", digest('9'), digest('2'));
        let f = signed(&lock("1.2.0", &["v0.6.0"], Some(&digest('2'))));
        let v = check(&f, &anchor(), &want(Some(&stack), Some("1.1.0"))).expect("passes");
        assert_eq!(v.key_index, 0);
    }

    /// The registry answers 404 for `<root>:stack-<tag>`: the stack is out and
    /// the vendor has not signed its lock yet. That is "retry shortly", not an
    /// auth or signature failure.
    #[test]
    fn a_lock_the_registry_does_not_have_yet_says_so_and_names_the_way_back() {
        let reg = super::lock_fetch::fake::serve(|_| Default::default());
        let anchor = TrustAnchor { keys: anchor().keys, registry: format!("{}/example/intel", reg.base.trim_start_matches("http://")) };
        let client = lock_fetch::Client::plain_http_for_tests(None);
        let e = fetch_and_check(&client, &anchor, &want(None, None)).unwrap_err();
        assert!(is_not_published(&e) && !e.is_auth(), "{e:?}");
        let why = e.why("trellion_intel");
        assert_eq!(
            why,
            "no signed lock published yet for v0.6.0 — the vendor publishes it minutes after a stack release; \
             retry shortly, or roll back with `noo upgrade --stack --tag <vX.Y.Z>`"
        );
        assert!(!why.contains("access refused") && !why.contains("signature"), "{why}");
    }

    #[test]
    fn the_not_published_tag_is_v_prefixed_whatever_form_it_arrives_in() {
        for t in ["v0.6.4", "0.6.4", "stack-v0.6.4"] {
            assert!(not_published(t).starts_with("no signed lock published yet for v0.6.4 —"), "{t}");
        }
    }

    /// Auth and signature failures keep their own text (and remedy).
    #[test]
    fn auth_and_signature_refusals_keep_their_text() {
        use crate::release_fetch::{FetchClass, FetchError};
        let auth = Refusal::Fetch { reference: "r".into(), stack_tag: "v0.6.0".into(), err: FetchError::new(FetchClass::Auth, "x") };
        assert!(auth.is_auth() && !is_not_published(&auth));
        assert!(auth.why("evolve").contains("(access refused)"), "{}", auth.why("evolve"));
        let bad = Refusal::Lock(AddonLockError::BadSignature("x".into()));
        assert!(!is_not_published(&bad) && bad.why("evolve").contains("lock refused"));
    }

    #[test]
    fn a_tampered_lock_is_refused() {
        let mut f = signed(&lock("1.2.0", &["v0.6.0"], None));
        f.lock = String::from_utf8(f.lock).unwrap().replace("1.2.0", "1.2.1").into_bytes();
        assert!(matches!(check(&f, &anchor(), &want(None, None)), Err(Refusal::Lock(AddonLockError::BadSignature(_)))));
    }

    #[test]
    fn a_lock_for_another_stack_is_refused() {
        let f = signed(&lock("1.2.0", &["v0.5.9"], None));
        let e = check(&f, &anchor(), &want(None, None)).unwrap_err();
        assert!(matches!(e, Refusal::NotForStack { .. }));
        assert!(e.why("trellion_intel").contains("does not support stack v0.6.0 (it lists v0.5.9)"), "{}", e.why("x"));
    }

    #[test]
    fn a_based_lock_needs_the_stack_lock_row_and_must_match_it() {
        let f = signed(&lock("1.2.0", &["v0.6.0"], Some(&digest('2'))));
        assert!(matches!(check(&f, &anchor(), &want(None, None)), Err(Refusal::NoStackLock { .. })));
        let no_row = format!("gateway@{}\n", digest('9'));
        assert!(matches!(check(&f, &anchor(), &want(Some(&no_row), None)), Err(Refusal::BaseRowMissing { .. })));
        let other = format!("trellion@{}\n", digest('3'));
        assert!(matches!(check(&f, &anchor(), &want(Some(&other), None)), Err(Refusal::Base(_))));
    }

    #[test]
    fn downgrades_need_the_flag() {
        let f = signed(&lock("1.1.0", &["v0.6.0"], None));
        let e = check(&f, &anchor(), &want(None, Some("1.2.0"))).unwrap_err();
        assert!(matches!(e, Refusal::Downgrade { .. }));
        assert!(e.why("x").contains("--allow-downgrade"));
        let w = Want { allow_downgrade: true, ..want(None, Some("1.2.0")) };
        assert!(check(&f, &anchor(), &w).is_ok());
        assert!(check(&f, &anchor(), &want(None, Some("1.1.0"))).is_ok(), "the same version is not a downgrade");
    }

    #[test]
    fn a_lock_signed_by_another_key_is_refused() {
        let mut a = anchor();
        a.keys = vec![release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&"ef".repeat(32)).unwrap())];
        let f = signed(&lock("1.2.0", &["v0.6.0"], None));
        assert!(matches!(check(&f, &a, &want(None, None)), Err(Refusal::Lock(AddonLockError::BadSignature(_)))));
    }

    #[derive(Default)]
    pub(crate) struct FakeDocker {
        pub local: Vec<String>,
        pub pulls: Vec<(String, Vec<String>, bool)>,
        pub fail_pull: bool,
        /// `(reference, image id)` for `image_id`.
        pub ids: Vec<(String, String)>,
        pub running: Vec<Container>,
    }

    impl Docker for FakeDocker {
        fn image_present(&mut self, r: &str) -> bool {
            self.local.iter().any(|l| l == r)
        }
        fn pull(&mut self, host: &str, refs: &[String], cred: Option<&Credential>) -> Result<(), String> {
            self.pulls.push((host.into(), refs.to_vec(), cred.is_some()));
            if self.fail_pull {
                return Err("denied".into());
            }
            self.local.extend(refs.iter().cloned());
            Ok(())
        }
        fn image_id(&mut self, r: &str) -> Result<String, String> {
            self.ids.iter().find(|(l, _)| l == r).map(|(_, i)| i.clone()).ok_or_else(|| format!("No such image: {r}"))
        }
        fn running(&mut self) -> Result<Vec<Container>, String> {
            Ok(self.running.clone())
        }
    }

    #[test]
    fn pulls_only_what_is_missing_by_digest() {
        let v = VerifiedLock { lock: lock("1.2.0", &["v0.6.0"], None), key_index: 0 };
        let mut d = FakeDocker::default();
        let cred = Credential { user: "u".into(), token: "t".into() };
        assert_eq!(pull_images(&mut d, &v, Some(&cred)).unwrap(), 1);
        assert_eq!(d.pulls[0].0, "ghcr.io");
        assert!(d.pulls[0].2, "the registry credential must reach the pull");
        assert!(d.pulls[0].1.iter().all(|r| r.contains("@sha256:")));
        assert_eq!(pull_images(&mut d, &v, Some(&cred)).unwrap(), 0, "a local image is not pulled again");
        let mut bad = FakeDocker { fail_pull: true, ..Default::default() };
        assert!(matches!(pull_images(&mut bad, &v, None), Err(Refusal::Pull(_))));
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addon-resolve-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn record_then_offline_check_and_tamper_detection() {
        let d = scratch("offline");
        let f = signed(&lock("1.2.0", &["v0.6.0"], None));
        let v = check(&f, &anchor(), &want(None, None)).unwrap();
        record(&d, "trellion_intel", &v, &f, "v0.6.0").unwrap();
        let pin = offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).expect("verifies");
        assert_eq!(pin.version, "1.2.0");
        assert!(offline_check(&d, "trellion_intel", "v0.6.1", &anchor()).unwrap_err().contains("pinned for stack v0.6.0"));
        assert!(offline_check(&d, "evolve", "v0.6.0", &anchor()).unwrap_err().contains("no pin"));

        // One byte of the cached lock changed: the launcher must refuse.
        let cache = d.join(pins::CACHE_DIR);
        let cached = std::fs::read_dir(&cache).unwrap().flatten().map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "json")).unwrap();
        let text = std::fs::read_to_string(&cached).unwrap().replace("1.2.0", "1.3.0");
        std::fs::write(&cached, text).unwrap();
        assert!(offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap_err().contains("was altered"));
        std::fs::remove_file(&cached).unwrap();
        assert!(offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap_err().contains("is missing"));

        // A pin edited to point elsewhere, with the lock intact.
        record(&d, "trellion_intel", &v, &f, "v0.6.0").unwrap();
        let mut all = pins::read(&d).unwrap();
        all.get_mut("trellion_intel").unwrap().images.insert("trellion-intel".into(), format!("{ROOT}@{}", digest('7')));
        std::fs::write(d.join(pins::PINS_FILE), serde_json::to_vec(&all).unwrap()).unwrap();
        assert!(offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap_err().contains("was edited"));
    }

    #[test]
    fn a_bundle_is_checked_materialised_and_tamper_refused_offline() {
        let d = scratch("bundle");
        let f = signed_bundle(&lock("1.2.0", &["v0.6.0"], None));
        // A fetched file that is not the signed bytes never gets past check.
        let mut bad = f.clone();
        bad.files.get_mut(addon_lock::OVERLAY_FILE).unwrap().push(b'#');
        assert!(matches!(check(&bad, &anchor(), &want(None, None)), Err(Refusal::Lock(AddonLockError::FileMismatch { .. }))));

        let v = check(&f, &anchor(), &want(None, None)).unwrap();
        record(&d, "trellion_intel", &v, &f, "v0.6.0").unwrap();
        let overlay = pins::addon_dir(&d, "trellion_intel").join(addon_lock::OVERLAY_FILE);
        assert_eq!(std::fs::read_to_string(&overlay).unwrap(), OVERLAY);
        let (_, how) = offline_check_bundle(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap();
        assert_eq!(how, Overlay::Bundled);

        // The materialised overlay edited on disk: refused like a lock tamper.
        std::fs::write(&overlay, format!("{OVERLAY}    privileged: true\n")).unwrap();
        let e = offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap_err();
        assert!(e.contains("do not match its signed lock") && e.contains("hashes to"), "{e}");
        std::fs::remove_file(&overlay).unwrap();
        assert!(offline_check(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap_err().contains("is missing"));

        // Moving back to a lock that predates bundles removes the directory,
        // and the add-on is then Legacy: with the old slice overlay, or none.
        let v1 = signed(&lock("1.2.0", &["v0.6.0"], None));
        let vv = check(&v1, &anchor(), &want(None, None)).unwrap();
        record(&d, "trellion_intel", &vv, &v1, "v0.6.0").unwrap();
        assert!(!pins::addon_dir(&d, "trellion_intel").exists());
        assert_eq!(offline_check_bundle(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap().1, Overlay::Legacy(None));
        std::fs::write(pins::legacy_overlay(&d, "trellion_intel"), OVERLAY).unwrap();
        assert_eq!(
            offline_check_bundle(&d, "trellion_intel", "v0.6.0", &anchor()).unwrap().1,
            Overlay::Legacy(Some(pins::legacy_overlay(&d, "trellion_intel")))
        );
    }

    #[test]
    fn stack_lock_rows() {
        let t = format!("# tag v0.6.0\nsource:trellion@abc\ntrellion@{}\n", digest('2'));
        assert_eq!(stack_lock_row(&t, "trellion"), Some(digest('2')));
        assert_eq!(stack_lock_row(&t, "gateway"), None);
    }

    #[test]
    fn running_state_tells_pinned_from_drift() {
        // The real shapes. For a container created from a digest-only
        // reference `docker ps --format '{{.Image}}'` prints just
        // `ghcr.io/example/intel` (Docker 27.5.1, 29.9.0), which can never
        // equal the pin; `docker inspect` keeps the digest in .Config.Image.
        let pinned = format!("{ROOT}@{}", digest('1'));
        let id = digest('a');
        let inspect = format!("/noo-trellion-intel\t{pinned}\t{id}\n/noo-gateway\tnoomesh/gateway:v0.6.0\t{}\n", digest('b'));
        let running = parse_inspect(&inspect).unwrap();
        assert_eq!(running[0], Container { name: "noo-trellion-intel".into(), config_image: pinned.clone(), image_id: id.clone() });
        assert_eq!(running_state(&pinned, Some(&id), &running), Running::Pinned(vec!["noo-trellion-intel".into()]));

        // Right reference, other bytes: recreated from a retagged image.
        match running_state(&pinned, Some(&digest('c')), &running) {
            Running::Drift(d) => assert!(d[0].1.contains("runs image aaaaaaaaaaaa, not cccccccccccc"), "{d:?}"),
            other => panic!("{other:?}"),
        }
        // The pinned id unreadable: nothing is confirmed.
        assert!(matches!(running_state(&pinned, None, &running), Running::Drift(_)));

        // Another digest, or a tag, of the same repository.
        let other = parse_inspect(&format!("/noo-trellion-intel\t{ROOT}@{}\t{id}\n", digest('2'))).unwrap();
        assert!(matches!(running_state(&pinned, Some(&id), &other), Running::Drift(_)));
        let tagged = parse_inspect(&format!("/noo-trellion-intel\t{ROOT}:v0.6.0\t{id}\n")).unwrap();
        match running_state(&pinned, Some(&id), &tagged) {
            Running::Drift(d) => assert_eq!(d[0].1, format!("runs {ROOT}:v0.6.0")),
            other => panic!("{other:?}"),
        }

        // The tag-less string `docker ps` prints is not the pinned digest.
        let ps_shape = vec![Container { name: "noo-trellion-intel".into(), config_image: ROOT.into(), image_id: id.clone() }];
        assert!(matches!(running_state(&pinned, Some(&id), &ps_shape), Running::Drift(_)));

        assert_eq!(running_state(&pinned, Some(&id), &running[1..]), Running::Absent);
        assert_eq!(running_state(&pinned, Some(&id), &[]), Running::Absent);
    }

    #[test]
    fn inspect_lines_that_do_not_parse_are_errors() {
        assert!(parse_inspect("").unwrap().is_empty());
        assert!(parse_inspect("/noo-x\tghcr.io/x/evolve\n").is_err());
        assert!(parse_inspect("/noo-x\t\tsha256:aa\n").is_err());
    }

    #[test]
    fn throwaway_config_is_private_under_the_runtime_dir_and_removed() {
        let root = scratch("throwaway");
        let runtime = root.join("secrets").join(".runtime");
        let p = {
            let t = ThrowawayConfig::new(&runtime).unwrap();
            assert!(t.0.starts_with(&runtime));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(std::fs::metadata(&t.0).unwrap().permissions().mode() & 0o777, 0o700);
                assert_eq!(std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777, 0o700);
            }
            t.0.clone()
        };
        assert!(!p.exists(), "the throwaway docker config outlived its operation");
        // A config a concurrent (live) run holds is left alone.
        let live = runtime.join(format!("{THROWAWAY_PREFIX}{}-9-9", std::process::id()));
        std::fs::create_dir_all(&live).unwrap();
        // A config a killed run left behind is swept before the next pull.
        // (pid 2^22+1 is above Linux's pid_max ceiling: never alive.)
        let stale = runtime.join(format!("{THROWAWAY_PREFIX}4194305-2-3"));
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("config.json"), "{}").unwrap();
        let other = runtime.join("keep-me");
        std::fs::write(&other, "x").unwrap();
        sweep_stale(&runtime);
        assert!(!stale.exists() && other.exists());
        assert!(live.exists(), "a live process's config was swept");
    }

    #[cfg(unix)]
    #[test]
    fn a_signal_during_the_operation_is_deferred_until_cleanup() {
        // SIGHUP's previous disposition is restored and a deferred one is
        // re-raised: test with an ignored signal so the re-raise is harmless.
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        {
            let _g = DeferSignals::install();
            unsafe { libc::raise(libc::SIGHUP) };
            assert_eq!(DEFERRED.load(std::sync::atomic::Ordering::SeqCst), libc::SIGHUP);
        }
        assert_eq!(DEFERRED.load(std::sync::atomic::Ordering::SeqCst), 0);
        let now = unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        assert_eq!(now, libc::SIG_IGN, "the previous disposition was not restored");
    }
}
