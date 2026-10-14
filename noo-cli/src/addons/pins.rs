// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller's add-on pins.
//!
//! Two kinds of file sit beside `stack.lock` in the install root:
//!   * `addons.lock`: for each pinned add-on, the version, the stack tag it is
//!     pinned for, its images as `name: ref@digest`, and the index of the
//!     entitlement key that signed the lock (0 = current). JSON. The launcher
//!     reads it only through `noo addons launch-pins`, which re-verifies it.
//!   * `addon-locks/<addon>-<sha12>.json` and `.json.sig`: the verified lock,
//!     byte for byte, named by its content hash, kept so `noo addons verify`
//!     and the launcher can re-verify it offline against the installed
//!     entitlement. The pin records the full hash (`lock_sha256`).
//!
//! The pair is atomic: a new lock is cached under a NEW name first (the one
//! the old pin names is never touched), then `addons.lock` is replaced by
//! rename, then superseded cache files are removed. A crash or a failed write
//! at any point leaves an old pin whose lock is intact, never a pin whose
//! lock looks tampered with. The read-modify-write of `addons.lock` holds an
//! exclusive `flock` on `.addons.lock.lck`. Every file write is a temporary
//! file plus rename and takes `stack.lock`'s permissions.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::addon_lock::VerifiedLock;

pub const PINS_FILE: &str = "addons.lock";
pub const CACHE_DIR: &str = "addon-locks";

/// One add-on's pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub version: String,
    /// The stack tag this pin was resolved for.
    pub stack: String,
    /// Image name to its `ref@sha256:…`.
    pub images: BTreeMap<String, String>,
    pub key_index: usize,
    /// sha256 (hex) of the cached lock bytes this pin was made from.
    pub lock_sha256: String,
}

impl Pin {
    pub fn from_verified(v: &VerifiedLock, stack_tag: &str, lock_bytes: &[u8]) -> Pin {
        Pin {
            version: v.lock.version.clone(),
            stack: stack_tag.trim().to_string(),
            images: v.lock.images.clone(),
            key_index: v.key_index,
            lock_sha256: sha256_hex(lock_bytes),
        }
    }

    /// The first image's digest, short, for listings.
    pub fn short_digest(&self) -> String {
        self.images
            .values()
            .next()
            .and_then(|r| r.rsplit_once("@sha256:"))
            .map(|(_, h)| format!("sha256:{}", h.get(..12).unwrap_or(h)))
            .unwrap_or_default()
    }
}

pub type Pins = BTreeMap<String, Pin>;

pub fn pins_path(root: &Path) -> PathBuf {
    root.join(PINS_FILE)
}

pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn cache_paths(root: &Path, addon: &str, sha: &str) -> (PathBuf, PathBuf) {
    let d = root.join(CACHE_DIR);
    let short = sha.get(..12).unwrap_or(sha);
    (d.join(format!("{addon}-{short}.json")), d.join(format!("{addon}-{short}.json.sig")))
}

/// The pins on disk. A missing file is no pins; an unreadable one is an
/// error, never "no pins": a launcher that read garbage as empty would
/// refuse for the wrong reason, and an upgrade would lose the downgrade
/// guard.
pub fn read(root: &Path) -> Result<Pins, String> {
    let p = pins_path(root);
    match std::fs::read(&p) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{} is not a pins file: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pins::new()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// The verified lock a pin names, as `(lock bytes, sig text)`; `Err` says
/// what is wrong (missing, or bytes that no longer hash to the pin).
pub fn cached_lock(root: &Path, addon: &str, pin: &Pin) -> Result<(Vec<u8>, String), String> {
    let (l, s) = cache_paths(root, addon, &pin.lock_sha256);
    let lock = std::fs::read(&l).map_err(|e| format!("{addon}'s verified lock {} is missing ({e})", l.display()))?;
    let sig = std::fs::read_to_string(&s).map_err(|e| format!("{addon}'s lock signature {} is missing ({e})", s.display()))?;
    if sha256_hex(&lock) != pin.lock_sha256 {
        return Err(format!("{addon}'s cached lock {} was altered: it no longer hashes to its pin", l.display()));
    }
    Ok((lock, sig))
}

/// The mode new files take: `stack.lock`'s when it exists, else 0644 (what
/// `stack_lock` writes under the usual umask).
#[cfg(unix)]
fn mode_like_stack_lock(root: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(root.join("stack.lock")).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o644)
}

/// Write `bytes` to `path` atomically, with `stack.lock`'s permissions.
pub fn write_atomic(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("pins");
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(std::fs::Permissions::from_mode(mode_like_stack_lock(root)))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

fn write(root: &Path, pins: &Pins) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(pins).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_atomic(root, &pins_path(root), &bytes)
}

/// An exclusive advisory lock on `<root>/.addons.lock.lck`, held for the
/// life of the value, so two writers never interleave a read-modify-write.
struct FileLock(std::fs::File);

impl FileLock {
    fn take(root: &Path) -> Result<FileLock, String> {
        let p = root.join(".addons.lock.lck");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd as _;
            // SAFETY: flock on a descriptor this value owns.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(format!("{}: {}", p.display(), std::io::Error::last_os_error()));
            }
        }
        Ok(FileLock(f))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd as _;
            // SAFETY: unlocking our own descriptor.
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// Set `addon`'s pin from a verified lock: cache the lock under its content
/// name, replace `addons.lock` (other pins kept), then drop superseded cache
/// files. Under the pins lock throughout.
pub fn set_pin(root: &Path, addon: &str, pin: &Pin, lock: &[u8], sig: &str) -> Result<(), String> {
    if sha256_hex(lock) != pin.lock_sha256 {
        return Err(format!("{addon}: the pin does not name these lock bytes"));
    }
    let _held = FileLock::take(root)?;
    let mut all = read(root)?;
    let (l, s) = cache_paths(root, addon, &pin.lock_sha256);
    write_atomic(root, &l, lock)?;
    write_atomic(root, &s, sig.as_bytes())?;
    all.insert(addon.to_string(), pin.clone());
    write(root, &all)?;
    // Superseded cache files for this add-on: nothing names them any more.
    let keep: Vec<std::ffi::OsString> =
        [l, s].iter().filter_map(|p| p.file_name().map(|n| n.to_os_string())).collect();
    if let Ok(entries) = std::fs::read_dir(root.join(CACHE_DIR)) {
        for e in entries.flatten() {
            let n = e.file_name();
            let name = n.to_string_lossy();
            if name.starts_with(&format!("{addon}-")) && !keep.contains(&n) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(())
}

/// The env var the launcher exports for an add-on image and the overlays
/// read: `NOO_ADDON_IMAGE_<NAME>`, the lock's image name upper-cased with
/// `-` and `.` as `_`. Derived, so core names no add-on image.
pub fn image_env_var(image: &str) -> Option<String> {
    let up: String = image
        .chars()
        .map(|c| match c {
            '-' | '.' => '_',
            c => c.to_ascii_uppercase(),
        })
        .collect();
    let ok = !up.is_empty()
        && up.starts_with(|c: char| c.is_ascii_uppercase())
        && up.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    ok.then(|| format!("NOO_ADDON_IMAGE_{up}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addon-pins-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pin() -> Pin {
        Pin {
            version: "1.2.0".into(),
            stack: "v0.6.0".into(),
            images: BTreeMap::from([("evolve".into(), format!("ghcr.io/x/evolve@sha256:{}", "ab".repeat(32)))]),
            key_index: 0,
            lock_sha256: sha256_hex(b"{}"),
        }
    }

    #[test]
    fn round_trip_missing_file_and_garbage() {
        let d = scratch("rt");
        assert!(read(&d).unwrap().is_empty(), "no file is no pins");
        set_pin(&d, "evolve", &pin(), b"{}", "sig").unwrap();
        assert_eq!(read(&d).unwrap(), Pins::from([("evolve".to_string(), pin())]));
        std::fs::write(pins_path(&d), "not json").unwrap();
        assert!(read(&d).is_err(), "garbage must not read as empty");
        assert!(set_pin(&d, "evolve", &pin(), b"{}", "sig").is_err(), "a corrupt pins file is never overwritten as if empty");
    }

    #[test]
    fn a_new_lock_never_touches_the_one_the_old_pin_names_until_the_pin_moves() {
        let d = scratch("pair");
        set_pin(&d, "evolve", &pin(), b"{}", "sig").unwrap();
        let old = pin();
        // The pins file cannot be replaced (a directory squats its temp
        // name's target): the old pin and ITS lock stay intact and verify.
        let mut new = pin();
        new.version = "1.3.0".into();
        new.lock_sha256 = sha256_hex(b"{\"v\":2}");
        std::fs::remove_file(pins_path(&d)).unwrap();
        std::fs::create_dir(pins_path(&d)).unwrap();
        assert!(set_pin(&d, "evolve", &new, b"{\"v\":2}", "sig2").is_err());
        std::fs::remove_dir(pins_path(&d)).unwrap();
        write(&d, &Pins::from([("evolve".to_string(), old.clone())])).unwrap();
        assert_eq!(cached_lock(&d, "evolve", &old).unwrap(), (b"{}".to_vec(), "sig".to_string()));
        // A successful move prunes the superseded files.
        set_pin(&d, "evolve", &new, b"{\"v\":2}", "sig2").unwrap();
        assert!(cached_lock(&d, "evolve", &old).is_err(), "superseded cache file kept");
        assert_eq!(cached_lock(&d, "evolve", &new).unwrap().0, b"{\"v\":2}".to_vec());
        assert!(set_pin(&d, "evolve", &new, b"other", "x").is_err(), "a pin must name its bytes");
    }

    #[cfg(unix)]
    #[test]
    fn writes_take_stack_lock_permissions_and_leave_no_temp_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = scratch("perm");
        std::fs::write(d.join("stack.lock"), "# tag v0.6.0\n").unwrap();
        std::fs::set_permissions(d.join("stack.lock"), std::fs::Permissions::from_mode(0o640)).unwrap();
        set_pin(&d, "evolve", &pin(), b"{}", "noo-sig1 x").unwrap();
        let (l, s) = cache_paths(&d, "evolve", &pin().lock_sha256);
        for p in [pins_path(&d), l, s] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640, "{}", p.display());
        }
        assert_eq!(cached_lock(&d, "evolve", &pin()).unwrap(), (b"{}".to_vec(), "noo-sig1 x".to_string()));
        let stray: Vec<_> = std::fs::read_dir(&d).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".tmp.")).collect();
        assert!(stray.is_empty(), "{stray:?}");
    }

    #[test]
    fn env_var_names_are_derived_and_safe() {
        assert_eq!(image_env_var("trellion-intel").as_deref(), Some("NOO_ADDON_IMAGE_TRELLION_INTEL"));
        assert_eq!(image_env_var("evolve").as_deref(), Some("NOO_ADDON_IMAGE_EVOLVE"));
        for bad in ["", "9x", "a/b", "a:b", "a b"] {
            assert!(image_env_var(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn short_digest() {
        assert_eq!(pin().short_digest(), "sha256:abababababab");
    }
}
