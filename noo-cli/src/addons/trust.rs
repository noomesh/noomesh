// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Third-party add-ons: whom the operator trusts, and a lock handed to the CLI.
//!
//! The add-ons that ship with the stack are trusted through the installed
//! entitlement, whose `addons` block names each one's signing keys and registry
//! root (`resolve::installed_anchor`). The public CLI pins no add-on key of
//! its own, so there is no shipped default to fall back on. An add-on the
//! entitlement has never heard of is trusted only if the OPERATOR says so:
//!
//! ```yaml
//! addon_trust:
//!   pai-voice:
//!     registry: ghcr.io/vendor/pai-voice
//!     keys:
//!       - <64 hex ed25519 public key>
//! ```
//!
//! written by `noo addons trust-key <name> <pubkey> --registry <root>` and
//! removed by `untrust-key`. The section is an admin-gated config section
//! (the gateway refuses a lesser role writing it). An add-on in `ADDON_ROWS`
//! can never be given keys here: the entitlement is its only trust root.
//!
//! A lock for a trusted name is then handled exactly like a built-in
//! add-on's: signature against the trusted keys, `supports_stack` listing
//! this stack, bundle files held to their signed hashes, images pulled by
//! digest from the registry root the keys were trusted for, the pin written
//! to `addons.lock`, and the launcher's verdict covering it.
//!
//! Limits, stated because they differ from a built-in add-on:
//! - images and the lock artifact are fetched ANONYMOUSLY. The controller's
//!   `NOO_ADDON_REGISTRY_TOKEN` is the vendor's credential and is never sent
//!   to a registry the operator named; a private third-party registry is not
//!   supported yet.
//! - the controller pulls from the trusted `registry` root only (no `pull`
//!   proxy root); a lock whose images sit outside it is refused.
//! - a lock supplied with `--lock` must have its bundle files beside it.

use std::collections::BTreeMap;
use std::path::Path;

use serde_yaml::{Mapping, Value};

use super::lock_fetch::Fetched;
use crate::addon_lock::{self, AddonLock, TrustAnchor};

/// The noomesh.yaml section holding operator-trusted keys.
pub const TRUST_SECTION: &str = "addon_trust";
/// The noomesh.yaml section holding per-add-on delegation switches.
pub const DELEGATION_SECTION: &str = "addon_delegation";

/// What a third-party add-on's name may be (mirrors the gateway's registry).
pub fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

/// Is `name` one of the add-ons the CLI ships a row for? Those are trusted
/// through the entitlement and are never third-party.
pub fn is_builtin(name: &str) -> bool {
    crate::commands::addons::row(name).is_some()
}

// ── reading ──────────────────────────────────────────────────────────────

/// The `addon_trust` section of a noomesh.yaml TEXT.
pub fn read(text: &str) -> Result<BTreeMap<String, TrustAnchor>, String> {
    let mut out = BTreeMap::new();
    if text.trim().is_empty() {
        return Ok(out);
    }
    let doc: Value = serde_yaml::from_str(text).map_err(|e| format!("noomesh.yaml does not parse as YAML: {e}"))?;
    let Some(sec) = doc.get(TRUST_SECTION) else { return Ok(out) };
    let Some(map) = sec.as_mapping() else {
        return Err(format!("{TRUST_SECTION} must map an add-on name to {{registry, keys}}"));
    };
    for (k, v) in map {
        let name = k.as_str().ok_or_else(|| format!("{TRUST_SECTION} has a key that is not a name"))?;
        let keys: Vec<String> = v
            .get("keys")
            .and_then(Value::as_sequence)
            .map(|s| s.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let registry = v.get("registry").and_then(Value::as_str).unwrap_or("").to_string();
        out.insert(name.to_string(), TrustAnchor { keys, registry, pull: None });
    }
    Ok(out)
}

/// The trust anchor the operator gave `name`, from this install's noomesh.yaml.
/// `Ok(None)` = none; `Err` = the file cannot be read (never "untrusted").
pub fn trusted_anchor(name: &str) -> Result<Option<TrustAnchor>, String> {
    let path = crate::commands::addons::config_path();
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(read(&text)?.remove(name))
}

/// Third-party add-on names the operator trusts a key for, in noomesh.yaml TEXT.
pub fn trusted_names(text: &str) -> Vec<String> {
    read(text).map(|m| m.into_keys().filter(|n| !is_builtin(n)).collect()).unwrap_or_default()
}

// ── editing ──────────────────────────────────────────────────────────────

/// Replace (or append, or remove when `value` is `None`) the top-level
/// `section:` block of `text`, leaving every other line as it was. The block
/// is regenerated, so comments INSIDE it are not kept; everything outside is.
pub fn replace_section(text: &str, section: &str, value: Option<&Value>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let head = lines.iter().position(|l| {
        !l.starts_with(char::is_whitespace) && l.trim_end().strip_prefix(section).is_some_and(|r| r.trim_start().starts_with(':'))
    });
    let rendered = value.map(|v| {
        let mut m = Mapping::new();
        m.insert(Value::String(section.to_string()), v.clone());
        serde_yaml::to_string(&m).unwrap_or_default()
    });
    let mut out: Vec<String> = Vec::new();
    match head {
        Some(h) => {
            let mut end = h + 1;
            while end < lines.len() {
                let l = lines[end];
                let t = l.trim();
                if t.is_empty() || t.starts_with('#') || l.starts_with(char::is_whitespace) {
                    end += 1;
                } else {
                    break;
                }
            }
            // Trailing blanks and comments after the block belong to what follows.
            while end > h + 1 && (lines[end - 1].trim().is_empty() || lines[end - 1].trim().starts_with('#')) {
                end -= 1;
            }
            out.extend(lines[..h].iter().map(|s| s.to_string()));
            if let Some(r) = &rendered {
                out.extend(r.trim_end().lines().map(str::to_string));
            }
            out.extend(lines[end..].iter().map(|s| s.to_string()));
        }
        None => {
            out.extend(lines.iter().map(|s| s.to_string()));
            if let Some(r) = &rendered {
                if out.last().is_some_and(|l| !l.trim().is_empty()) {
                    out.push(String::new());
                }
                out.extend(r.trim_end().lines().map(str::to_string));
            }
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

fn section_mapping(text: &str, section: &str) -> Result<Mapping, String> {
    if text.trim().is_empty() {
        return Ok(Mapping::new());
    }
    let doc: Value = serde_yaml::from_str(text).map_err(|e| format!("noomesh.yaml does not parse as YAML: {e}"))?;
    match doc.get(section) {
        None | Some(Value::Null) => Ok(Mapping::new()),
        Some(Value::Mapping(m)) => Ok(m.clone()),
        Some(_) => Err(format!("{section} must be a map")),
    }
}

/// `text` with `key` trusted for `name`. A first key needs `registry`.
pub fn add_key(text: &str, name: &str, key: &str, registry: Option<&str>) -> Result<String, String> {
    if !name_ok(name) {
        return Err(format!("`{name}` is not an add-on name (lowercase letters, digits, `-` and `_`, starting with a letter)"));
    }
    if is_builtin(name) {
        return Err(format!(
            "{name} ships with the stack: its signing keys come from the installed entitlement, and trust-key \
             cannot give it others"
        ));
    }
    let key = key.trim().to_ascii_lowercase();
    crate::entitlement::pubkey_from_hex(&key).map_err(|e| format!("`{key}` is not an ed25519 public key (64 hex characters): {e}"))?;
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    let k = Value::String(name.to_string());
    let mut entry = sec.get(&k).and_then(Value::as_mapping).cloned().unwrap_or_default();
    let mut keys: Vec<Value> = entry.get("keys").and_then(Value::as_sequence).cloned().unwrap_or_default();
    if !keys.iter().any(|x| x.as_str() == Some(key.as_str())) {
        keys.push(Value::String(key));
    }
    let have = entry.get("registry").and_then(Value::as_str).map(str::to_string);
    let registry = match (registry.map(str::trim).filter(|r| !r.is_empty()), have) {
        (Some(r), _) => r.to_string(),
        (None, Some(h)) => h,
        (None, None) => {
            return Err(format!(
                "the first key trusted for {name} needs the registry its images come from: \
                 noo addons trust-key {name} <pubkey> --registry <host/path>"
            ))
        }
    };
    if !addon_lock::valid_registry_root(&registry) {
        return Err(format!("registry {registry:?} is not a registry root (host/path, no scheme, tag or digest)"));
    }
    entry.insert(Value::String("registry".into()), Value::String(registry));
    entry.insert(Value::String("keys".into()), Value::Sequence(keys));
    sec.insert(k, Value::Mapping(entry));
    Ok(replace_section(text, TRUST_SECTION, Some(&Value::Mapping(sec))))
}

/// `text` with `key` no longer trusted for `name` (the entry goes with its
/// last key, and the section with its last entry).
pub fn remove_key(text: &str, name: &str, key: &str) -> Result<String, String> {
    let key = key.trim().to_ascii_lowercase();
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    let k = Value::String(name.to_string());
    let Some(mut entry) = sec.get(&k).and_then(Value::as_mapping).cloned() else {
        return Err(format!("no key is trusted for {name}"));
    };
    let mut keys: Vec<Value> = entry.get("keys").and_then(Value::as_sequence).cloned().unwrap_or_default();
    let before = keys.len();
    keys.retain(|x| x.as_str().map(str::to_ascii_lowercase).as_deref() != Some(key.as_str()));
    if keys.len() == before {
        return Err(format!("{key} is not a trusted key for {name}"));
    }
    if keys.is_empty() {
        sec.remove(&k);
    } else {
        entry.insert(Value::String("keys".into()), Value::Sequence(keys));
        sec.insert(k, Value::Mapping(entry));
    }
    let value = (!sec.is_empty()).then(|| Value::Mapping(sec));
    Ok(replace_section(text, TRUST_SECTION, value.as_ref()))
}

/// `text` with `addon_delegation.<name>.tasks` set to `on`. Off removes the
/// switch (absent is off); other keys under the entry are kept.
pub fn set_delegation(text: &str, name: &str, on: bool) -> Result<String, String> {
    if !name_ok(name) {
        return Err(format!("`{name}` is not an add-on name (lowercase letters, digits, `-` and `_`, starting with a letter)"));
    }
    let mut sec = section_mapping(text, DELEGATION_SECTION)?;
    let k = Value::String(name.to_string());
    let mut entry = sec.get(&k).and_then(Value::as_mapping).cloned().unwrap_or_default();
    if on {
        entry.insert(Value::String("tasks".into()), Value::Bool(true));
        sec.insert(k, Value::Mapping(entry));
    } else {
        entry.remove("tasks");
        if entry.is_empty() {
            sec.remove(&k);
        } else {
            sec.insert(k, Value::Mapping(entry));
        }
    }
    let value = (!sec.is_empty()).then(|| Value::Mapping(sec));
    Ok(replace_section(text, DELEGATION_SECTION, value.as_ref()))
}

/// Write `updated` over `path` only if it still parses; the file is left
/// untouched otherwise.
pub fn write_checked(path: &Path, original: &str, updated: &str) -> Result<(), String> {
    if !original.trim().is_empty() && serde_yaml::from_str::<Value>(original).is_err() {
        return Err(format!("{} does not parse as YAML — refusing to edit it", path.display()));
    }
    serde_yaml::from_str::<Value>(updated)
        .map_err(|e| format!("the edit would leave {} unparseable ({e}) — not writing", path.display()))?;
    std::fs::write(path, updated).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── a lock handed to the CLI ─────────────────────────────────────────────

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let mut resp = ureq::get(url).call().map_err(|e| format!("{url}: {e}"))?;
    resp.body_mut().read_to_vec().map_err(|e| format!("{url}: {e}"))
}

/// Read a lock the operator supplied: `<ref>` is the lock JSON (a path, or an
/// `https://` URL), `<ref>.sig` its signature, and every bundle file the lock
/// names sits in the same directory. Nothing here is trusted: the caller
/// verifies the signature and holds each file to its signed hash.
pub fn fetch_supplied(reference: &str) -> Result<Fetched, String> {
    let r = reference.trim();
    let is_url = r.starts_with("https://");
    if r.starts_with("http://") {
        return Err("--lock over http:// is refused; use an https:// URL or a file path".into());
    }
    let (lock, sig, mut get): (Vec<u8>, Vec<u8>, Box<dyn FnMut(&str) -> Result<Vec<u8>, String>>) = if is_url {
        let base = r.rsplit_once('/').map(|(b, _)| b.to_string()).unwrap_or_default();
        (
            http_get(r)?,
            http_get(&format!("{r}.sig"))?,
            Box::new(move |name: &str| http_get(&format!("{base}/{name}"))),
        )
    } else {
        let p = Path::new(r);
        let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
        let lock = std::fs::read(p).map_err(|e| format!("cannot read {r}: {e}"))?;
        let sig_path = format!("{r}.sig");
        let sig = std::fs::read(&sig_path).map_err(|e| format!("cannot read {sig_path}: {e} (the signature sits beside the lock)"))?;
        (lock, sig, Box::new(move |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("cannot read {name} beside the lock: {e}"))))
    };
    let sig = String::from_utf8(sig).map_err(|_| "the signature file is not text".to_string())?;
    // Only the file NAMES are read from the unverified lock, to know what to
    // fetch; each is a plain name (no path), and the bytes are verified later.
    let parsed: AddonLock = serde_json::from_slice(&lock).map_err(|e| format!("the lock is not JSON of the expected shape: {e}"))?;
    let mut files = BTreeMap::new();
    for name in parsed.files.keys() {
        if !addon_lock::valid_file_name(name) {
            return Err(format!("the lock names a bundle file {name:?} that is not a plain file name"));
        }
        files.insert(name.clone(), get(name)?);
    }
    Ok(Fetched { lock, sig, files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addons::resolve::tests::{anchor, lock, seed, signed_bundle, FakeDocker};
    use crate::addons::resolve::{self, Refusal, Want};
    use crate::release_sig;

    fn pk() -> String {
        release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&seed()).unwrap())
    }

    const ROOT: &str = "ghcr.io/example/intel";

    fn pk2() -> String {
        release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&"ab".repeat(32)).unwrap())
    }

    #[test]
    fn trust_key_round_trips_and_keeps_the_rest_of_the_file() {
        let text = "# my config\naddons:\n  trellion: true # keep\ncluster:\n  x: 1\n";
        let added = add_key(text, "pai-voice", &pk().to_uppercase(), Some(ROOT)).unwrap();
        assert!(added.contains("# my config") && added.contains("trellion: true # keep") && added.contains("cluster:"), "{added}");
        let m = read(&added).unwrap();
        assert_eq!(m["pai-voice"].keys, vec![pk()]);
        assert_eq!(m["pai-voice"].registry, ROOT);
        // A second key joins; the registry is kept.
        let two = add_key(&added, "pai-voice", &pk2(), None).unwrap();
        assert_eq!(read(&two).unwrap()["pai-voice"].keys.len(), 2);
        // Re-adding is a no-op on the key list.
        assert_eq!(read(&add_key(&two, "pai-voice", &pk(), None).unwrap()).unwrap()["pai-voice"].keys.len(), 2);
        // Remove one, then the last: the section goes, the rest stays.
        let one = remove_key(&two, "pai-voice", &pk2()).unwrap();
        assert_eq!(read(&one).unwrap()["pai-voice"].keys, vec![pk()]);
        let none = remove_key(&one, "pai-voice", &pk()).unwrap();
        assert!(!none.contains(TRUST_SECTION) && none.contains("cluster:") && none.contains("# my config"), "{none}");
        assert!(remove_key(&none, "pai-voice", &pk()).is_err());
    }

    #[test]
    fn trust_key_refuses_what_it_cannot_stand_behind() {
        let t = "addons:\n  trellion: true\n";
        assert!(add_key(t, "pai-voice", "zz", Some(ROOT)).unwrap_err().contains("ed25519"));
        assert!(add_key(t, "pai-voice", &pk(), None).unwrap_err().contains("--registry"));
        assert!(add_key(t, "pai-voice", &pk(), Some("https://ghcr.io/x")).unwrap_err().contains("registry root"));
        assert!(add_key(t, "../x", &pk(), Some(ROOT)).unwrap_err().contains("not an add-on name"));
        let e = add_key(t, "evolve", &pk(), Some(ROOT)).unwrap_err();
        assert!(e.contains("entitlement"), "a built-in add-on is never re-trusted here: {e}");
    }

    #[test]
    fn delegation_is_written_under_its_own_section() {
        let t = "addons:\n  pai-voice: true\n";
        let on = set_delegation(t, "pai-voice", true).unwrap();
        let v: Value = serde_yaml::from_str(&on).unwrap();
        assert_eq!(v["addon_delegation"]["pai-voice"]["tasks"].as_bool(), Some(true));
        assert_eq!(v["addons"]["pai-voice"].as_bool(), Some(true), "the addons map is untouched");
        let off = set_delegation(&on, "pai-voice", false).unwrap();
        assert!(!off.contains("addon_delegation") && off.contains("pai-voice: true"), "{off}");
    }

    #[test]
    fn a_builtin_is_not_third_party_and_an_unknown_name_is() {
        assert!(is_builtin("evolve") && is_builtin("trellion-intel") && is_builtin("voice"));
        assert!(!is_builtin("pai-voice"));
    }

    fn third_party_lock(stack: &[&str]) -> crate::addon_lock::AddonLock {
        let mut l = lock("1.2.0", stack, None);
        l.addon = "pai-voice".into();
        l
    }

    fn want<'a>(tag: &'a str) -> Want<'a> {
        Want { addon: "pai-voice", stack_tag: tag, stack_lock: None, pinned: None, allow_downgrade: false }
    }

    #[test]
    fn an_unknown_addon_with_a_trusted_lock_verifies_pins_and_is_covered_by_the_launcher_verdict() {
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let v = resolve::check(&f, &anchor(), &want("v0.6.0")).expect("a lock signed by a trusted key verifies");
        let root = std::env::temp_dir().join(format!("noo-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        resolve::record(&root, "pai-voice", &v, &f, "v0.6.0", None).unwrap();
        let names = vec!["pai-voice".to_string()];
        let lines = crate::commands::addon_pins::launch_lines(&root, "v0.6.0", &names, &|_| Ok(anchor()));
        assert_eq!(lines[0], "verified pai-voice 1.2.0 v0.6.0", "{lines:?}");
        assert!(lines[1].starts_with("pin pai-voice NOO_ADDON_IMAGE_"), "{lines:?}");
    }

    #[test]
    fn a_lock_signed_by_an_untrusted_key_is_refused_naming_trust_key() {
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let other = TrustAnchor { keys: vec![release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&"ef".repeat(32)).unwrap())], ..anchor() };
        let r = resolve::check(&f, &other, &want("v0.6.0")).expect_err("untrusted key");
        let why = r.why("pai-voice");
        assert!(matches!(r, Refusal::Lock(_)) && why.contains("trust-key") && why.contains("pai-voice"), "{why}");
        // And a built-in add-on's refusal is the one it always was.
        let builtin = Refusal::Lock(crate::addon_lock::AddonLockError::BadSignature("x".into())).why("evolve");
        assert!(!builtin.contains("trust-key"), "{builtin}");
    }

    #[test]
    fn a_lock_for_another_stack_is_refused() {
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let r = resolve::check(&f, &anchor(), &want("v0.6.1")).expect_err("wrong stack");
        assert!(matches!(r, Refusal::NotForStack { .. }), "{r:?}");
        assert!(r.why("pai-voice").contains("v0.6.1"));
    }

    #[test]
    fn prepare_from_a_supplied_lock_pulls_by_digest_anonymously() {
        use crate::addons::{self, lock_fetch::Client};
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let client = Client::new(None);
        let root = std::env::temp_dir().join(format!("noo-trust-prep-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &client };
        let mut docker = FakeDocker::default();
        let p = addons::prepare_from(&ctx, "pai-voice", &anchor(), Some(f), &mut docker).expect("prepared");
        assert_eq!(p.pulled, 1);
        assert!(p.via.contains("anonymous"), "the vendor token is never sent to an operator-named registry: {}", p.via);
        assert!(docker.pulls.iter().all(|(_, _, had_cred)| !had_cred), "{:?}", docker.pulls);
    }

    #[test]
    fn a_supplied_lock_with_a_missing_bundle_file_or_plain_http_is_refused() {
        assert!(fetch_supplied("http://example.com/lock.json").unwrap_err().contains("https"));
        assert!(fetch_supplied("/nonexistent/lock.json").unwrap_err().contains("cannot read"));
    }
}
