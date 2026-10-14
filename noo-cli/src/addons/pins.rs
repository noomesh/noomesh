// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller's add-on pins.
//!
//! Two kinds of file sit beside `stack.lock` in the install root:
//!   * `addons.lock`: for each pinned add-on, the version, the stack tag it is
//!     pinned for, its images as `name: ref@digest`, and the index of the
//!     entitlement key that signed the lock (0 = current). JSON. The launcher
//!     reads it only through `noo addons launch-pins`, which re-verifies it.
//!   * `addon-locks/<addon>.json` and `.json.sig`: the verified lock, byte for
//!     byte, kept so `noo addons verify` and the launcher can re-verify it
//!     offline against the installed entitlement.
//!
//! Every write is atomic (a temporary file in the same directory, then a
//! rename) and takes the permissions `stack.lock` has, so a reader never sees
//! half a file and the two files cannot differ in who may read them.

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
}

impl Pin {
    pub fn from_verified(v: &VerifiedLock, stack_tag: &str) -> Pin {
        Pin {
            version: v.lock.version.clone(),
            stack: stack_tag.trim().to_string(),
            images: v.lock.images.clone(),
            key_index: v.key_index,
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

fn cache_paths(root: &Path, addon: &str) -> (PathBuf, PathBuf) {
    let d = root.join(CACHE_DIR);
    (d.join(format!("{addon}.json")), d.join(format!("{addon}.json.sig")))
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

/// The verified lock cached for `addon`, as `(lock bytes, sig text)`.
pub fn cached_lock(root: &Path, addon: &str) -> Option<(Vec<u8>, String)> {
    let (l, s) = cache_paths(root, addon);
    Some((std::fs::read(l).ok()?, std::fs::read_to_string(s).ok()?))
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

/// Write the whole pins file.
pub fn write(root: &Path, pins: &Pins) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(pins).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_atomic(root, &pins_path(root), &bytes)
}

/// Cache a verified lock's exact bytes and signature for offline re-verify.
pub fn cache(root: &Path, addon: &str, lock: &[u8], sig: &str) -> Result<(), String> {
    let (l, s) = cache_paths(root, addon);
    write_atomic(root, &l, lock)?;
    write_atomic(root, &s, sig.as_bytes())
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
        }
    }

    #[test]
    fn round_trip_missing_file_and_garbage() {
        let d = scratch("rt");
        assert!(read(&d).unwrap().is_empty(), "no file is no pins");
        let pins = Pins::from([("evolve".to_string(), pin())]);
        write(&d, &pins).unwrap();
        assert_eq!(read(&d).unwrap(), pins);
        std::fs::write(pins_path(&d), "not json").unwrap();
        assert!(read(&d).is_err(), "garbage must not read as empty");
    }

    #[cfg(unix)]
    #[test]
    fn writes_take_stack_lock_permissions_and_leave_no_temp_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = scratch("perm");
        std::fs::write(d.join("stack.lock"), "# tag v0.6.0\n").unwrap();
        std::fs::set_permissions(d.join("stack.lock"), std::fs::Permissions::from_mode(0o640)).unwrap();
        write(&d, &Pins::from([("evolve".to_string(), pin())])).unwrap();
        cache(&d, "evolve", b"{}", "noo-sig1 x").unwrap();
        for p in [pins_path(&d), d.join(CACHE_DIR).join("evolve.json"), d.join(CACHE_DIR).join("evolve.json.sig")] {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640, "{}", p.display());
        }
        assert_eq!(cached_lock(&d, "evolve").unwrap(), (b"{}".to_vec(), "noo-sig1 x".to_string()));
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
