// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `provisioned` add-on state: database schema and roles exist
//! (`noo addons enable <name> --provision-only`), no service of the add-on is
//! composed or started.
//!
//! ## The state model
//!
//! An add-on has TWO independent facts, kept in two places on purpose:
//!
//! | fact | where | who reads it |
//! |---|---|---|
//! | is it switched ON (compose its overlay, start its services) | `addons.<name>` in noomesh.yaml | the launcher (`addon_on`), the gateway |
//! | has its database been provisioned without switching it on | `<root>/addon-provisioned/<name>.json` | `noo addons show|list`, `noo cluster verify` |
//!
//! `provisioned` is therefore NOT a third value of the switch. The switch
//! stays off (or unstated), so every existing reader, the launcher's compose
//! selection above all, already does the right thing without learning a new
//! word: a switch-off add-on is not composed. The marker only lets the CLI say
//! so. The marker lives OUTSIDE `<root>/addons/<name>/` because that
//! directory is the signed bundle: a foreign file there reads as tampering,
//! and `materialise` swaps the whole directory on every upgrade.
//!
//! The effective state is derived, never stored: marker present and switch not
//! on is `provisioned`; switch on is `on` whatever the marker says (a later
//! plain `noo addons enable` clears it anyway). Nothing here holds a secret:
//! the marker names roles and the lock it was provisioned from.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Beside `addons.lock` in the install root.
pub const DIR: &str = "addon-provisioned";

/// What "provisioned" is worded as, everywhere the CLI says it.
pub const WORDS: &str = "provisioned (services not started)";

/// One provisioned add-on. Names and a lock hash only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub addon: String,
    pub schema: String,
    pub role: String,
    pub ddl_role: String,
    /// The version and lock the bundle was verified from.
    pub version: String,
    pub lock_sha256: String,
    /// Unix seconds.
    pub provisioned_at: i64,
}

pub fn path(root: &Path, addon: &str) -> PathBuf {
    root.join(DIR).join(format!("{addon}.json"))
}

/// Record `m`. Atomic (temp file plus rename), `stack.lock`'s permissions.
pub fn mark(root: &Path, m: &Marker) -> Result<(), String> {
    if !super::trust::name_ok(&m.addon) {
        return Err(format!("{:?} is not an add-on name", m.addon));
    }
    let mut bytes = serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    super::pins::write_atomic(root, &path(root, &m.addon), &bytes)
}

/// Forget `addon`'s marker. `Ok(true)` when there was one.
pub fn clear(root: &Path, addon: &str) -> Result<bool, String> {
    if !super::trust::name_ok(addon) {
        return Ok(false);
    }
    let p = path(root, addon);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Every readable marker, by add-on. An unreadable or foreign file is skipped
/// (the state is advisory: the switch is what the launcher obeys).
pub fn read_all(root: &Path) -> BTreeMap<String, Marker> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(root.join(DIR)) else { return out };
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_string) else {
            continue;
        };
        if !super::trust::name_ok(&name) {
            continue;
        }
        let Ok(bytes) = std::fs::read(e.path()) else { continue };
        if let Ok(m) = serde_json::from_slice::<Marker>(&bytes) {
            if m.addon == name {
                out.insert(name, m);
            }
        }
    }
    out
}

/// The markers of add-ons that are provisioned and NOT switched on, given the
/// `addons:` map. Pure: this is the one definition of the state.
pub fn only<'a>(markers: &'a BTreeMap<String, Marker>, declared: &BTreeMap<String, bool>) -> Vec<&'a Marker> {
    markers.values().filter(|m| declared.get(&m.addon) != Some(&true)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(addon: &str) -> Marker {
        Marker {
            addon: addon.into(),
            schema: addon.replace('-', "_"),
            role: format!("noo_{}", addon.replace('-', "_")),
            ddl_role: format!("noo_{}_ddl", addon.replace('-', "_")),
            version: "0.1.0".into(),
            lock_sha256: "ab".repeat(32),
            provisioned_at: 1_700_000_000,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-provisioned-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_marker_round_trips_and_clears() {
        let root = scratch("rt");
        mark(&root, &marker("pai-voice")).unwrap();
        assert_eq!(read_all(&root).get("pai-voice"), Some(&marker("pai-voice")));
        assert!(root.join(DIR).join("pai-voice.json").is_file());
        assert!(clear(&root, "pai-voice").unwrap());
        assert!(read_all(&root).is_empty());
        assert!(!clear(&root, "pai-voice").unwrap(), "clearing twice is not an error");
    }

    /// The state is derived: ON wins over a leftover marker, and an absent or
    /// false switch leaves it provisioned.
    #[test]
    fn provisioned_means_marked_and_not_switched_on() {
        let root = scratch("derive");
        mark(&root, &marker("pai-voice")).unwrap();
        let m = read_all(&root);
        let on: BTreeMap<String, bool> = [("pai-voice".to_string(), true)].into();
        let off: BTreeMap<String, bool> = [("pai-voice".to_string(), false)].into();
        assert!(only(&m, &on).is_empty(), "a switched-on add-on is on, not provisioned");
        assert_eq!(only(&m, &off).len(), 1);
        assert_eq!(only(&m, &BTreeMap::new()).len(), 1, "unstated is not on");
    }

    #[test]
    fn a_foreign_or_renamed_file_is_not_a_marker() {
        let root = scratch("foreign");
        mark(&root, &marker("pai-voice")).unwrap();
        std::fs::write(root.join(DIR).join("junk.json"), "{}").unwrap();
        std::fs::write(root.join(DIR).join("other.json"), serde_json::to_string(&marker("pai-voice")).unwrap()).unwrap();
        std::fs::write(root.join(DIR).join("notes.txt"), "x").unwrap();
        let m = read_all(&root);
        assert_eq!(m.keys().collect::<Vec<_>>(), ["pai-voice"], "{m:?}");
    }

    #[test]
    fn a_marker_holds_names_and_a_hash_and_nothing_else() {
        let text = serde_json::to_string(&marker("pai-voice")).unwrap();
        for f in ["password", "secret", "key", "token"] {
            assert!(!text.to_lowercase().contains(f), "{f} in {text}");
        }
    }
}
