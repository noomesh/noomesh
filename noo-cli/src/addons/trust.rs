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
//! ## Development keys (i163 part A)
//!
//! `noo addons trust-key <name> <pubkey> --registry <root> --dev --expires 14d`
//! trusts a TEMPORARY key, for developing an add-on on this mesh before it
//! ships. It is stored beside the release keys, never among them:
//!
//! ```yaml
//! addon_trust:
//!   pai-voice:
//!     registry: ghcr.io/vendor/pai-voice
//!     keys: []
//!     dev_keys:
//!       - key: <64 hex>
//!         dev: true
//!         expires_at: "2026-11-04T12:00:00Z"
//! ```
//!
//! - scoped: one add-on name, this mesh only (it lives in this noomesh.yaml
//!   and in no entitlement; `TrustAnchor::dev` is never read from JSON);
//! - expiring: `--expires` is required, at most [`DEV_MAX_SECS`] (30 days),
//!   stored as an absolute UTC instant; after it the lock is refused like an
//!   untrusted one (`addon_lock::AddonLockError::DevKeyExpired`), naming the
//!   expiry and the renew command;
//! - never both: a key trusted as a release key for any add-on cannot be
//!   trusted as a development key, and the reverse;
//! - removed by `noo addons untrust-key <name> --dev` (all of the add-on's
//!   development keys) or `untrust-key <name> <pubkey> --dev` (one).
//!
//! Enrolling one is a local operator action on the controller: the CLI edits
//! the install's noomesh.yaml, which only the host's operator can write, and
//! the gateway accepts a write of this section only from an admin.
//!
//! A lock for a trusted name is then handled exactly like a built-in
//! add-on's: signature against the trusted keys, `supports_stack` listing
//! this stack, bundle files held to their signed hashes, images pulled by
//! digest from the registry root the keys were trusted for, the pin written
//! to `addons.lock`, and the launcher's verdict covering it.
//!
//! Limits, stated because they differ from a built-in add-on:
//! - images and the lock artifact are fetched ANONYMOUSLY unless the operator
//!   registered a credential for the add-on (below). The controller's
//!   `NOO_ADDON_REGISTRY_TOKEN` is the vendor's credential and is never sent
//!   to a registry the operator named.
//! - a private package: `noo addons registry-login <name> --registry <root>`
//!   stores a read-only token for THAT add-on in the secret store
//!   (`NOO_ADDON_REGISTRY_CRED_<NAME>`) and records beside its trust entry only
//!   that one exists and the root it is bound to (`registry_credential.root`).
//!   `<root>` must be exactly the root the entry trusts. The token is sent to
//!   that root and nowhere else; `untrust-key` removes it with the entry.
//! - the controller pulls from the trusted `registry` root only (no `pull`
//!   proxy root); a lock whose images sit outside it is refused.
//! - a lock supplied with `--lock` must have its bundle files beside it.

use std::collections::BTreeMap;
use std::path::Path;

use serde_yaml::{Mapping, Value};

use super::lock_fetch::Fetched;
use crate::addon_lock::{self, AddonLock, DevKey, TrustAnchor};

/// The noomesh.yaml section holding operator-trusted keys.
pub const TRUST_SECTION: &str = "addon_trust";
/// The key under `addon_trust.<name>` holding its development keys.
pub const DEV_KEYS: &str = "dev_keys";
/// The longest a development key may be trusted for: 30 days.
pub const DEV_MAX_SECS: i64 = 30 * 86_400;
/// The key under `addon_trust.<name>` recording that a pull credential is
/// stored for it: `{root: <registry root it is bound to>}`. Never the value.
pub const REGISTRY_CREDENTIAL: &str = "registry_credential";
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
        let dev = read_dev_keys(name, v)?;
        out.insert(name.to_string(), TrustAnchor { keys, registry, pull: None, dev });
    }
    Ok(out)
}

/// `addon_trust.<name>.dev_keys`: each record `{key, dev: true, expires_at}`.
/// A record that cannot be read is an error, never a key silently trusted or
/// silently dropped.
fn read_dev_keys(name: &str, entry: &Value) -> Result<Vec<DevKey>, String> {
    let Some(seq) = entry.get(DEV_KEYS) else { return Ok(Vec::new()) };
    if seq.is_null() {
        return Ok(Vec::new());
    }
    let seq = seq
        .as_sequence()
        .ok_or_else(|| format!("{TRUST_SECTION}.{name}.{DEV_KEYS} must be a list of {{key, dev: true, expires_at}}"))?;
    let mut out = Vec::new();
    for r in seq {
        let key = r.get("key").and_then(Value::as_str).map(|k| k.trim().to_ascii_lowercase());
        let stamp = r.get("expires_at").and_then(Value::as_str);
        let at = stamp.and_then(crate::commands::cluster_verify::parse_rfc3339_unix);
        match (key, at, r.get("dev").and_then(Value::as_bool)) {
            (Some(key), Some(expires_at), Some(true)) if crate::entitlement::pubkey_from_hex(&key).is_ok() => {
                out.push(DevKey { key, expires_at })
            }
            _ => {
                return Err(format!(
                    "{TRUST_SECTION}.{name}.{DEV_KEYS} has a record that is not {{key: <64 hex>, dev: true, \
                     expires_at: <YYYY-MM-DDTHH:MM:SSZ>}}; fix it with `noo addons untrust-key {name} --dev`"
                ))
            }
        }
    }
    Ok(out)
}

/// Every development key in a noomesh.yaml TEXT, for every add-on (the
/// release-side guard refuses any of them, whoever they were trusted for).
pub fn all_dev_keys(text: &str) -> Result<Vec<DevKey>, String> {
    Ok(read(text)?.into_values().flat_map(|a| a.dev).collect())
}

/// Parse `--expires`: a whole number with a unit (`14d`, `36h`, `90m`),
/// above zero and at most [`DEV_MAX_SECS`]. Returns seconds.
pub fn parse_dev_ttl(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let unit_ok = t.chars().last().is_some_and(|c| matches!(c, 'd' | 'h' | 'm'));
    let secs = if unit_ok { crate::commands::cluster_provision::parse_ttl_seconds(t) } else { None };
    match secs {
        Some(n) if n > 0 && n <= DEV_MAX_SECS => Ok(n),
        Some(n) if n > DEV_MAX_SECS => Err(format!(
            "--expires {t} is longer than a development key may live (30d at most); renew it before it expires instead"
        )),
        _ => Err(format!("--expires {t:?} is not a duration like 14d, 36h or 90m")),
    }
}

/// Is `key` (lowercase hex) trusted as a release key or a development key
/// for any add-on in `sec`? Returns the add-on name.
fn key_holder(sec: &Mapping, key: &str, dev: bool) -> Option<String> {
    for (n, v) in sec {
        let list = if dev { v.get(DEV_KEYS) } else { v.get("keys") };
        let hit = list.and_then(Value::as_sequence).is_some_and(|s| {
            s.iter().any(|x| {
                let k = if dev { x.get("key").and_then(Value::as_str) } else { x.as_str() };
                k.map(|k| k.trim().to_ascii_lowercase()).as_deref() == Some(key)
            })
        });
        if hit {
            return Some(n.as_str().unwrap_or("?").to_string());
        }
    }
    None
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

/// The root `name`'s stored pull credential is bound to, from a noomesh.yaml
/// TEXT. `None`: none is recorded.
pub fn credential_root(text: &str, name: &str) -> Option<String> {
    let doc: Value = serde_yaml::from_str(text).ok()?;
    let root = doc.get(TRUST_SECTION)?.get(name)?.get(REGISTRY_CREDENTIAL)?.get("root")?.as_str()?.trim();
    (!root.is_empty()).then(|| root.to_string())
}

/// [`credential_root`] for this install's noomesh.yaml. `Err` = unreadable.
pub fn installed_credential_root(name: &str) -> Result<Option<String>, String> {
    let path = crate::commands::addons::config_path();
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(credential_root(&text, name))
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

/// `text` with a pull credential recorded for `name`, bound to `root`. The
/// add-on must hold a trust entry, and `root` must be exactly the registry
/// root that entry trusts (a path under it, or a parent, is refused: the
/// credential travels to the route's root, which is the trusted one).
pub fn set_credential(text: &str, name: &str, root: &str) -> Result<String, String> {
    if !name_ok(name) {
        return Err(format!("`{name}` is not an add-on name (lowercase letters, digits, `-` and `_`, starting with a letter)"));
    }
    if is_builtin(name) {
        return Err(format!("{name} ships with the stack and is pulled with its own licence; it takes no registry credential here"));
    }
    let root = root.trim();
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    let k = Value::String(name.to_string());
    let Some(mut entry) = sec.get(&k).and_then(Value::as_mapping).cloned() else {
        return Err(format!(
            "{name} has no trust entry, so there is no registry to bind a credential to. Trust its signer first: \
             `noo addons trust-key {name} <pubkey> --registry {root}`"
        ));
    };
    let trusted = entry.get("registry").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if trusted != root {
        return Err(format!(
            "{name} trusts the registry root {trusted:?}, not {root:?}. A credential is bound to exactly the root the trust \
             entry names: pass `--registry {trusted}`"
        ));
    }
    let clash = sec.keys().filter_map(Value::as_str).find(|n| *n != name && super::lock_fetch::cred_key(n) == super::lock_fetch::cred_key(name));
    if let Some(other) = clash {
        return Err(format!("{other} is trusted too and would share {name}'s credential slot ({}); rename one of them", super::lock_fetch::cred_key(name)));
    }
    let mut rec = Mapping::new();
    rec.insert(Value::String("root".into()), Value::String(root.to_string()));
    entry.insert(Value::String(REGISTRY_CREDENTIAL.into()), Value::Mapping(rec));
    sec.insert(k, Value::Mapping(entry));
    Ok(replace_section(text, TRUST_SECTION, Some(&Value::Mapping(sec))))
}

/// `text` without the credential record under `name`'s trust entry (no-op
/// when there is none).
pub fn clear_credential(text: &str, name: &str) -> Result<String, String> {
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    let k = Value::String(name.to_string());
    let Some(mut entry) = sec.get(&k).and_then(Value::as_mapping).cloned() else { return Ok(text.to_string()) };
    if entry.remove(REGISTRY_CREDENTIAL).is_none() {
        return Ok(text.to_string());
    }
    sec.insert(k, Value::Mapping(entry));
    Ok(replace_section(text, TRUST_SECTION, Some(&Value::Mapping(sec))))
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
    if let Some(holder) = key_holder(&sec, &key, true) {
        return Err(format!(
            "{key} is trusted as a DEVELOPMENT key for {holder}; a key is never both a development and a release key. \
             Remove it first (`noo addons untrust-key {holder} {key} --dev`), and sign releases with the add-on's release key"
        ));
    }
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
        if key_holder(&sec, &key, true).is_some() {
            return Err(format!("{key} is a development key for {name}: `noo addons untrust-key {name} {key} --dev` removes it"));
        }
        return Err(format!("{key} is not a trusted key for {name}"));
    }
    let dev_left = entry.get(DEV_KEYS).and_then(Value::as_sequence).is_some_and(|s| !s.is_empty());
    if keys.is_empty() && !dev_left {
        sec.remove(&k);
    } else {
        entry.insert(Value::String("keys".into()), Value::Sequence(keys));
        sec.insert(k, Value::Mapping(entry));
    }
    let value = (!sec.is_empty()).then(|| Value::Mapping(sec));
    Ok(replace_section(text, TRUST_SECTION, value.as_ref()))
}

/// `text` with `key` trusted for `name` as a DEVELOPMENT key until
/// `now + ttl_secs` (i163 part A). Trusting the same key again renews it
/// (the new expiry replaces the old). A first key of any kind needs
/// `registry`. Refused: a built-in add-on, a key already trusted as a
/// release key for any add-on, a lifetime outside (0, 30 days].
pub fn add_dev_key(text: &str, name: &str, key: &str, registry: Option<&str>, ttl_secs: i64, now: i64) -> Result<String, String> {
    if !name_ok(name) {
        return Err(format!("`{name}` is not an add-on name (lowercase letters, digits, `-` and `_`, starting with a letter)"));
    }
    if is_builtin(name) {
        return Err(format!(
            "{name} ships with the stack: its signing keys come from the installed entitlement, and it has no \
             development lane here"
        ));
    }
    if ttl_secs <= 0 || ttl_secs > DEV_MAX_SECS {
        return Err("a development key lives more than 0 seconds and at most 30d".into());
    }
    let key = key.trim().to_ascii_lowercase();
    crate::entitlement::pubkey_from_hex(&key).map_err(|e| format!("`{key}` is not an ed25519 public key (64 hex characters): {e}"))?;
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    if let Some(holder) = key_holder(&sec, &key, false) {
        return Err(format!(
            "{key} is trusted as a RELEASE key for {holder}; a key is never both a release and a development key. \
             Generate a separate key for development"
        ));
    }
    let k = Value::String(name.to_string());
    let mut entry = sec.get(&k).and_then(Value::as_mapping).cloned().unwrap_or_default();
    let have = entry.get("registry").and_then(Value::as_str).map(str::to_string);
    let registry = match (registry.map(str::trim).filter(|r| !r.is_empty()), have) {
        (Some(r), _) => r.to_string(),
        (None, Some(h)) => h,
        (None, None) => {
            return Err(format!(
                "the first key trusted for {name} needs the registry its images come from: \
                 noo addons trust-key {name} <pubkey> --registry <host/path> --dev --expires 14d"
            ))
        }
    };
    if !addon_lock::valid_registry_root(&registry) {
        return Err(format!("registry {registry:?} is not a registry root (host/path, no scheme, tag or digest)"));
    }
    let mut dev: Vec<Value> = entry.get(DEV_KEYS).and_then(Value::as_sequence).cloned().unwrap_or_default();
    dev.retain(|r| r.get("key").and_then(Value::as_str).map(|x| x.trim().to_ascii_lowercase()).as_deref() != Some(key.as_str()));
    let mut rec = Mapping::new();
    rec.insert(Value::String("key".into()), Value::String(key));
    rec.insert(Value::String("dev".into()), Value::Bool(true));
    rec.insert(Value::String("expires_at".into()), Value::String(addon_lock::utc_rfc3339(now + ttl_secs)));
    dev.push(Value::Mapping(rec));
    entry.insert(Value::String("registry".into()), Value::String(registry));
    if entry.get("keys").is_none() {
        entry.insert(Value::String("keys".into()), Value::Sequence(Vec::new()));
    }
    entry.insert(Value::String(DEV_KEYS.into()), Value::Sequence(dev));
    sec.insert(k, Value::Mapping(entry));
    Ok(replace_section(text, TRUST_SECTION, Some(&Value::Mapping(sec))))
}

/// `text` without `name`'s development key `key`, or without all of them
/// when `key` is `None`. The entry goes when it holds no key of either kind.
pub fn remove_dev_key(text: &str, name: &str, key: Option<&str>) -> Result<String, String> {
    let mut sec = section_mapping(text, TRUST_SECTION)?;
    let k = Value::String(name.to_string());
    let Some(mut entry) = sec.get(&k).and_then(Value::as_mapping).cloned() else {
        return Err(format!("no key is trusted for {name}"));
    };
    let mut dev: Vec<Value> = entry.get(DEV_KEYS).and_then(Value::as_sequence).cloned().unwrap_or_default();
    let before = dev.len();
    match key.map(|x| x.trim().to_ascii_lowercase()) {
        Some(want) => dev.retain(|r| r.get("key").and_then(Value::as_str).map(|x| x.trim().to_ascii_lowercase()).as_deref() != Some(want.as_str())),
        None => dev.clear(),
    }
    if dev.len() == before {
        return Err(match key {
            Some(x) => format!("{x} is not a development key for {name}"),
            None => format!("{name} has no development key"),
        });
    }
    let release_left = entry.get("keys").and_then(Value::as_sequence).is_some_and(|s| !s.is_empty());
    if dev.is_empty() && !release_left {
        sec.remove(&k);
    } else {
        if dev.is_empty() {
            entry.remove(DEV_KEYS);
        } else {
            entry.insert(Value::String(DEV_KEYS.into()), Value::Sequence(dev));
        }
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

/// Reads one file the lock names, relative to where the lock came from.
type FileGetter = Box<dyn FnMut(&str) -> Result<Vec<u8>, String>>;

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
    let (lock, sig, mut get): (Vec<u8>, Vec<u8>, FileGetter) = if is_url {
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
        Want { addon: "pai-voice", stack_tag: tag, stack_lock: None, pinned: None, pin: None, allow_downgrade: false }
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
        std::fs::write(root.join("docker-compose.cluster.yml"), "services:\n  gateway:\n    image: g\n").unwrap();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &client };
        let mut docker = FakeDocker::default();
        let p = addons::prepare_from(&ctx, "pai-voice", &anchor(), Some(f), &mut docker).expect("prepared");
        assert_eq!(p.pulled, 1);
        assert!(p.via.contains("anonymous"), "the vendor token is never sent to an operator-named registry: {}", p.via);
        assert!(docker.pulls.iter().all(|(_, _, had_cred)| !had_cred), "{:?}", docker.pulls);
    }

    /// The pin path (`noo addons enable | upgrade`) refuses a signed
    /// third-party bundle whose overlay takes a core secret, or whose name is
    /// core's, BEFORE an image is pulled or a pin written. Reverting the
    /// `guards::guard_install` call in `prepare_from` makes both prepare.
    #[test]
    fn prepare_from_refuses_a_core_secret_or_a_core_name_before_anything_is_pulled() {
        use crate::addons::{self, lock_fetch::Client};
        let client = Client::new(None);
        let root = std::env::temp_dir().join(format!("noo-trust-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("docker-compose.cluster.yml"),
            "services:\n  gateway:\n    image: g\nsecrets:\n  noo_jwt_secret:\n    file: ${NOO_SECRET_RUNDIR:-/x}/noo_jwt_secret\n    x-noo-source: NOO_JWT_SECRET\n",
        )
        .unwrap();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &client };
        // 1. Its service takes core's JWT secret by name.
        let overlay = "services:\n  noo-rhaddon:\n    image: x\n    secrets: [noo_jwt_secret]\n";
        let mut l = third_party_lock(&["v0.6.0"]);
        l.addon = "rhaddon".into();
        let f = crate::addons::resolve::tests::signed_bundle_with(&l, overlay);
        let mut docker = FakeDocker::default();
        let r = addons::prepare_from(&ctx, "rhaddon", &anchor(), Some(f), &mut docker).expect_err("refused");
        let why = r.why("rhaddon");
        assert!(matches!(r, Refusal::Decl(_)) && why.contains("rhaddon") && why.contains("NOO_JWT_SECRET"), "{why}");
        assert!(docker.pulls.is_empty(), "nothing is pulled for a refused bundle: {:?}", docker.pulls);
        assert!(!crate::addons::pins::read(&root).unwrap().contains_key("rhaddon"), "nothing is pinned");
        // 2. A third-party add-on named like a core service.
        let mut l = third_party_lock(&["v0.6.0"]);
        l.addon = "grafana".into();
        let f = crate::addons::resolve::tests::signed_bundle_with(&l, "services: {}\n");
        let mut docker = FakeDocker::default();
        let r = addons::prepare_from(&ctx, "grafana", &anchor(), Some(f), &mut docker).expect_err("refused");
        let why = r.why("grafana");
        assert!(why.contains("`grafana` is a core service"), "{why}");
        assert!(docker.pulls.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A signed third-party bundle of `rhaddon` carrying `routes` as its
    /// routes.json beside an empty overlay.
    fn signed_with_routes(routes: &str) -> crate::addons::lock_fetch::Fetched {
        use crate::addon_lock;
        let mut l = third_party_lock(&["v0.6.0"]);
        l.addon = "rhaddon".into();
        l.format = addon_lock::FORMAT_V2.into();
        let files = std::collections::BTreeMap::from([
            (addon_lock::OVERLAY_FILE.to_string(), b"services: {}\n".to_vec()),
            ("routes.json".to_string(), routes.as_bytes().to_vec()),
        ]);
        l.files = files.iter().map(|(n, b)| (n.clone(), addon_lock::sha256_ref(b))).collect();
        let (lock, sig) = addon_lock::sign(&l, &seed()).unwrap();
        crate::addons::lock_fetch::Fetched { lock, sig, files }
    }

    /// The pin path (`noo addons enable | upgrade`) runs the gateway's own
    /// routes.json validator (`addon_manifest::validate`) on the verified
    /// bundle BEFORE an image is pulled or a pin written: an unknown role word
    /// is refused with the gateway's sentence and nothing changes. (The
    /// 2026-10-31 case, `owner_scoped` on a GET, is legal since f99.)
    /// A valid manifest still prepares. Reverting the `refuse_bad_routes`
    /// call in `prepare_from` makes the refused case prepare.
    #[test]
    fn prepare_from_refuses_a_routes_json_the_gateway_refuses_before_any_change() {
        use crate::addons::{self, lock_fetch::Client};
        let client = Client::new(None);
        let root = std::env::temp_dir().join(format!("noo-trust-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("docker-compose.cluster.yml"), "services:\n  gateway:\n    image: g\n").unwrap();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &client };
        let good = include_str!("../../../tests/fixtures/addons/rhaddon/routes.json");
        let mut m: serde_json::Value = serde_json::from_str(good).unwrap();
        m["routes"].as_array_mut().unwrap().push(serde_json::json!({
            "name": "get_v1_workspace", "method": "GET", "path": "/api/rhaddon/v1/workspace", "min_role": "everyone"
        }));
        let bad = m.to_string();
        let gateway = addon_manifest::validate(&addon_manifest::parse(&bad).unwrap(), "rhaddon", addon_manifest::FrontDoor::NotHere).unwrap_err();
        assert!(gateway.contains("is not a role") && gateway.contains("get_v1_workspace"), "{gateway}");
        let mut docker = FakeDocker::default();
        let r = addons::prepare_from(&ctx, "rhaddon", &anchor(), Some(signed_with_routes(&bad)), &mut docker).expect_err("refused");
        let why = r.why("rhaddon");
        assert!(matches!(r, Refusal::Decl(_)) && why.contains(&gateway) && why.contains("nothing was changed"), "{why}");
        assert!(docker.pulls.is_empty(), "nothing is pulled for a refused bundle: {:?}", docker.pulls);
        assert!(!addons::pins::pins_path(&root).exists(), "no pins file is written");
        assert!(!addons::pins::read(&root).unwrap().contains_key("rhaddon"), "nothing is pinned");
        // The same bundle with a valid manifest prepares (and pulls).
        let mut docker = FakeDocker::default();
        addons::prepare_from(&ctx, "rhaddon", &anchor(), Some(signed_with_routes(good)), &mut docker).expect("prepared");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_supplied_lock_with_a_missing_bundle_file_or_plain_http_is_refused() {
        assert!(fetch_supplied("http://example.com/lock.json").unwrap_err().contains("https"));
        assert!(fetch_supplied("/nonexistent/lock.json").unwrap_err().contains("cannot read"));
    }

    // ── development keys (i163 part A) ──────────────────────────────────

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn a_dev_key_is_stored_beside_the_release_keys_with_an_absolute_expiry() {
        let t = "addons:\n  pai-voice: true\n";
        let added = add_dev_key(t, "pai-voice", &pk().to_uppercase(), Some(ROOT), 14 * 86_400, NOW).unwrap();
        let v: Value = serde_yaml::from_str(&added).unwrap();
        let rec = &v[TRUST_SECTION]["pai-voice"][DEV_KEYS][0];
        assert_eq!(rec["key"].as_str(), Some(pk().as_str()));
        assert_eq!(rec["dev"].as_bool(), Some(true));
        assert_eq!(rec["expires_at"].as_str(), Some(addon_lock::utc_rfc3339(NOW + 14 * 86_400).as_str()));
        assert_eq!(v[TRUST_SECTION]["pai-voice"]["keys"].as_sequence().map(Vec::len), Some(0), "never among the release keys");
        let m = read(&added).unwrap();
        assert!(m["pai-voice"].keys.is_empty());
        assert_eq!(m["pai-voice"].dev, vec![DevKey { key: pk(), expires_at: NOW + 14 * 86_400 }]);
        assert_eq!(trusted_names(&added), vec!["pai-voice".to_string()], "a dev-only add-on is a trusted name");
        assert_eq!(all_dev_keys(&added).unwrap().len(), 1);
        // Trusting it again renews it: one record, the new expiry.
        let renewed = add_dev_key(&added, "pai-voice", &pk(), None, 86_400, NOW + 10).unwrap();
        assert_eq!(read(&renewed).unwrap()["pai-voice"].dev, vec![DevKey { key: pk(), expires_at: NOW + 10 + 86_400 }]);
    }

    #[test]
    fn a_key_is_never_both_dev_and_release() {
        let t = "addons:\n  pai-voice: true\n";
        let dev = add_dev_key(t, "pai-voice", &pk(), Some(ROOT), 86_400, NOW).unwrap();
        let e = add_key(&dev, "pai-voice", &pk(), None).unwrap_err();
        assert!(e.contains("DEVELOPMENT") && e.contains("untrust-key"), "{e}");
        // Across add-ons too: a dev key for one is no release key for another.
        let e = add_key(&dev, "other-addon", &pk(), Some(ROOT)).unwrap_err();
        assert!(e.contains("DEVELOPMENT"), "{e}");
        let rel = add_key(t, "pai-voice", &pk(), Some(ROOT)).unwrap();
        let e = add_dev_key(&rel, "pai-voice", &pk(), None, 86_400, NOW).unwrap_err();
        assert!(e.contains("RELEASE"), "{e}");
        let e = add_dev_key(&rel, "other-addon", &pk(), Some(ROOT), 86_400, NOW).unwrap_err();
        assert!(e.contains("RELEASE"), "{e}");
        // A release key and a different dev key sit side by side.
        let both = add_dev_key(&rel, "pai-voice", &pk2(), None, 86_400, NOW).unwrap();
        let a = &read(&both).unwrap()["pai-voice"];
        assert_eq!((a.keys.clone(), a.dev.len()), (vec![pk()], 1));
    }

    #[test]
    fn a_dev_key_refuses_what_it_cannot_stand_behind() {
        let t = "addons:\n  pai-voice: true\n";
        assert!(add_dev_key(t, "pai-voice", &pk(), None, 86_400, NOW).unwrap_err().contains("--registry"));
        assert!(add_dev_key(t, "evolve", &pk(), Some(ROOT), 86_400, NOW).unwrap_err().contains("entitlement"));
        assert!(add_dev_key(t, "pai-voice", "zz", Some(ROOT), 86_400, NOW).unwrap_err().contains("ed25519"));
        assert!(add_dev_key(t, "pai-voice", &pk(), Some(ROOT), DEV_MAX_SECS + 1, NOW).is_err());
        assert!(add_dev_key(t, "pai-voice", &pk(), Some(ROOT), 0, NOW).is_err());
        assert!(add_dev_key(t, "pai-voice", &pk(), Some(ROOT), DEV_MAX_SECS, NOW).is_ok(), "30 days exactly is allowed");
    }

    #[test]
    fn dev_ttl_parsing() {
        assert_eq!(parse_dev_ttl("14d"), Ok(14 * 86_400));
        assert_eq!(parse_dev_ttl("36h"), Ok(36 * 3600));
        assert_eq!(parse_dev_ttl("90m"), Ok(90 * 60));
        assert_eq!(parse_dev_ttl("30d"), Ok(DEV_MAX_SECS));
        assert!(parse_dev_ttl("31d").unwrap_err().contains("30d"));
        assert!(parse_dev_ttl("721h").is_err());
        for bad in ["", "14", "0d", "-1d", "d", "2w", "1.5d", "forever"] {
            assert!(parse_dev_ttl(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn untrust_dev_removes_one_or_all_and_keeps_the_release_keys() {
        let t = "# mine\naddons:\n  pai-voice: true\n";
        let rel = add_key(t, "pai-voice", &pk(), Some(ROOT)).unwrap();
        let one = add_dev_key(&rel, "pai-voice", &pk2(), None, 86_400, NOW).unwrap();
        let k3 = release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(&"12".repeat(32)).unwrap());
        let two = add_dev_key(&one, "pai-voice", &k3, None, 86_400, NOW).unwrap();
        // One by key.
        let left = remove_dev_key(&two, "pai-voice", Some(&k3)).unwrap();
        assert_eq!(read(&left).unwrap()["pai-voice"].dev.len(), 1);
        // All of them; the release key stays, and so does the entry.
        let none = remove_dev_key(&two, "pai-voice", None).unwrap();
        let a = &read(&none).unwrap()["pai-voice"];
        assert_eq!((a.keys.clone(), a.dev.len()), (vec![pk()], 0));
        assert!(!none.contains(DEV_KEYS) && none.contains("# mine"), "{none}");
        assert!(remove_dev_key(&none, "pai-voice", None).unwrap_err().contains("no development key"));
        // A release key is not removed by --dev, and a dev key not without it.
        assert!(remove_dev_key(&one, "pai-voice", Some(&pk())).is_err());
        assert!(remove_key(&one, "pai-voice", &pk2()).unwrap_err().contains("--dev"));
        // Removing the last release key keeps an entry that still has a dev key.
        let dev_only = remove_key(&one, "pai-voice", &pk()).unwrap();
        let a = &read(&dev_only).unwrap()["pai-voice"];
        assert_eq!((a.keys.len(), a.dev.len()), (0, 1));
        // And the last dev key of a dev-only entry takes the entry with it.
        let gone = remove_dev_key(&dev_only, "pai-voice", None).unwrap();
        assert!(!gone.contains(TRUST_SECTION), "{gone}");
    }

    #[test]
    fn an_unreadable_dev_record_is_an_error_never_a_silent_trust() {
        for rec in [
            "{key: zz, dev: true, expires_at: '2026-11-04T12:00:00Z'}".to_string(),
            format!("{{key: {}, dev: true, expires_at: soon}}", pk()),
            format!("{{key: {}, expires_at: '2026-11-04T12:00:00Z'}}", pk()),
            format!("{{key: {}, dev: false, expires_at: '2026-11-04T12:00:00Z'}}", pk()),
        ] {
            let t = format!("addon_trust:\n  pai-voice:\n    registry: {ROOT}\n    keys: []\n    dev_keys:\n      - {rec}\n");
            assert!(read(&t).unwrap_err().contains("dev_keys"), "{rec}");
        }
    }

    fn dev_anchor(expires_at: i64) -> TrustAnchor {
        TrustAnchor { keys: vec![], dev: vec![DevKey { key: pk(), expires_at }], ..anchor() }
    }

    #[test]
    fn a_dev_signed_lock_pins_and_the_launcher_reports_it_as_dev() {
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let later = addon_lock::now_unix() + 86_400;
        let v = resolve::check(&f, &dev_anchor(later), &want("v0.6.0")).expect("a live dev key verifies");
        assert_eq!(v.dev_expires_at, Some(later));
        let root = std::env::temp_dir().join(format!("noo-trust-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        resolve::record(&root, "pai-voice", &v, &f, "v0.6.0", None).unwrap();
        let names = vec!["pai-voice".to_string()];
        let lines = crate::commands::addon_pins::launch_lines(&root, "v0.6.0", &names, &|_| Ok(dev_anchor(later)));
        assert_eq!(lines[0], "verified pai-voice 1.2.0 v0.6.0", "{lines:?}");
        assert_eq!(lines[1], format!("dev pai-voice {later}"), "{lines:?}");
        assert!(lines[2].starts_with("pin pai-voice NOO_ADDON_IMAGE_"), "{lines:?}");
        // Renewed: the verdict carries the new expiry; the pin is not rewritten.
        let renewed = later + 3600;
        let lines = crate::commands::addon_pins::launch_lines(&root, "v0.6.0", &names, &|_| Ok(dev_anchor(renewed)));
        assert_eq!(lines[1], format!("dev pai-voice {renewed}"), "{lines:?}");
        // Expired: refused like an untrusted key, naming the expiry and the renew command.
        let past = addon_lock::now_unix() - 60;
        let lines = crate::commands::addon_pins::launch_lines(&root, "v0.6.0", &names, &|_| Ok(dev_anchor(past)));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("refuse pai-voice "), "{lines:?}");
        assert!(lines[0].contains("expired") && lines[0].contains(&addon_lock::utc_minute(past)), "{lines:?}");
        assert!(lines[0].contains("noo addons trust-key pai-voice <pubkey> --dev --expires"), "{lines:?}");
        // A release-signed lock never emits a dev line.
        let lines = crate::commands::addon_pins::launch_lines(&root, "v0.6.0", &names, &|_| Ok(TrustAnchor { dev: vec![], ..anchor() }));
        assert!(lines.iter().all(|l| !l.starts_with("dev ")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_expired_dev_key_refuses_the_lock_at_resolve_with_the_renew_command() {
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let past = addon_lock::now_unix() - 1;
        let r = resolve::check(&f, &dev_anchor(past), &want("v0.6.0")).expect_err("expired");
        let why = r.why("pai-voice");
        assert!(why.contains("expired") && why.contains("--dev --expires"), "{why}");
    }

    // ── a per-add-on registry credential (i277h) ────────────────────────

    const TOKEN: &str = "ghp_s3cr3tPullToken";

    fn trusted_text() -> String {
        add_key("addons:\n  pai-voice: true\n", "pai-voice", &pk(), Some(ROOT)).unwrap()
    }

    fn bound_client() -> crate::addons::lock_fetch::Client {
        use crate::addons::lock_fetch::{Bound, Client, Credential};
        let cred = Credential { user: "noo".into(), token: TOKEN.into() };
        Client::plain_http_for_tests(None).with_bound(Some(Bound { addon: "pai-voice".into(), root: ROOT.into(), cred }))
    }

    fn prep_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("noo-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("docker-compose.cluster.yml"), "services:\n  gateway:\n    image: g\n").unwrap();
        root
    }

    /// A third-party pull with a stored credential asks docker for ONE login, to
    /// the bound root's host, and says so. Without the binding it is anonymous.
    #[test]
    fn a_stored_credential_is_presented_once_to_the_bound_root() {
        use crate::addons;
        let root = prep_root("cred-pull");
        let bc = bound_client();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &bc };
        let mut docker = FakeDocker::default();
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let p = addons::prepare_with(&ctx, "pai-voice", &anchor(), Some(f), &mut docker, &bc).expect("prepared");
        assert_eq!(docker.pulls.len(), 1, "one login and pull for the one root: {:?}", docker.pulls);
        assert_eq!(docker.pulls[0].0, "ghcr.io");
        assert!(docker.pulls[0].2, "the credential reached the pull");
        assert_eq!(p.via, format!("via {ROOT} (credential for pai-voice)"));
        // The same pull without the binding is anonymous (the old behaviour).
        let mut anon = FakeDocker::default();
        let plain = crate::addons::lock_fetch::Client::plain_http_for_tests(None);
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        addons::prepare_with(&ctx, "pai-voice", &anchor(), Some(f), &mut anon, &plain).expect("prepared");
        assert!(anon.pulls.iter().all(|(_, _, had)| !had), "{:?}", anon.pulls);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The token is on docker's stdin, never in argv; the throwaway config
    /// directory is the only thing the command line names.
    #[test]
    fn docker_login_takes_the_token_on_stdin_never_in_argv() {
        let dir = std::path::Path::new("/run/noo/.runtime/cfg-1");
        let login = resolve::login_args(dir, "ghcr.io", "noo");
        assert!(login.contains(&"--password-stdin".to_string()), "{login:?}");
        assert!(login[0] == "--config" && login[1] == dir.display().to_string(), "{login:?}");
        let pull = resolve::pull_args(dir, "ghcr.io/example/intel@sha256:aa");
        assert!(login.iter().chain(&pull).all(|a| !a.contains(TOKEN) && a != "--password"), "{login:?} {pull:?}");
        assert!(pull.contains(&"--config".to_string()), "a pull never reads the operator's own docker login");
    }

    /// The credential is in the secret store only: not the pins file, not the
    /// cached lock, not the materialised bundle directory.
    #[test]
    fn the_credential_is_in_neither_the_pins_file_nor_the_lock_cache() {
        use crate::addons;
        let root = prep_root("cred-cache");
        let bc = bound_client();
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &bc };
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        let p = addons::prepare_with(&ctx, "pai-voice", &anchor(), Some(f), &mut FakeDocker::default(), &bc).unwrap();
        addons::commit(&root, &p, "v0.6.0").unwrap();
        fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() { walk(&p, out) } else { out.push(p) }
            }
        }
        let mut files = Vec::new();
        walk(&root, &mut files);
        assert!(files.iter().any(|f| f.ends_with(addons::pins::PINS_FILE)), "the pins file was written: {files:?}");
        for f in files {
            let bytes = std::fs::read(&f).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN), "{} holds the credential", f.display());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A private package with no credential: the refusal says so and names the
    /// verb. With a credential the registry still refuses: a different message.
    #[test]
    fn a_refused_private_pull_names_the_verb_and_tells_set_from_unset() {
        use crate::addons;
        let root = prep_root("cred-refused");
        let plain = crate::addons::lock_fetch::Client::plain_http_for_tests(None);
        let ctx = addons::Ctx { root: &root, tag: "v0.6.0", stack_lock: None, allow_downgrade: false, client: &plain };
        let run = |client: &crate::addons::lock_fetch::Client| {
            let mut docker = FakeDocker { fail_pull: true, ..Default::default() };
            let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
            addons::prepare_with(&ctx, "pai-voice", &anchor(), Some(f), &mut docker, client).expect_err("refused")
        };
        let verb = format!("noo addons registry-login pai-voice --registry {ROOT}");
        let unset = run(&plain);
        assert!(matches!(unset, Refusal::PullAuth { credential_set: false, .. }), "{unset:?}");
        let why = unset.why("pai-voice");
        assert!(why.contains(&verb) && why.contains("no credential is set"), "{why}");
        assert_eq!(unset.registry_login_fix("pai-voice").as_deref(), Some(verb.as_str()));
        let set = run(&bound_client());
        assert!(matches!(set, Refusal::PullAuth { credential_set: true, .. }), "{set:?}");
        let why = set.why("pai-voice");
        assert!(why.contains(&verb) && why.contains("refused the credential stored") && !why.contains(TOKEN), "{why}");
        // The lock fetch itself, refused for access, says the same.
        let fetch = Refusal::Fetch {
            reference: format!("{ROOT}:stack-v0.6.0"),
            stack_tag: "v0.6.0".into(),
            err: Box::new(crate::release_fetch::FetchError::new(crate::release_fetch::FetchClass::Auth, "x")),
            via: None,
        };
        assert!(fetch.why("pai-voice").contains(&verb), "{}", fetch.why("pai-voice"));
        assert_eq!(fetch.registry_login_fix("pai-voice").as_deref(), Some(verb.as_str()));
        // A public package still pulls anonymously (the existing contract).
        let mut ok = FakeDocker::default();
        let f = signed_bundle(&third_party_lock(&["v0.6.0"]));
        assert!(addons::prepare_with(&ctx, "pai-voice", &anchor(), Some(f), &mut ok, &plain).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The binding decision: only a record bound to the root trusted now is
    /// used, and a record the store cannot back is loud.
    #[test]
    fn the_client_binds_only_a_record_for_the_trusted_root() {
        use crate::addons::{bound_for, lock_fetch::{Bound, Credential}};
        let cred = |root: &str| Bound { addon: "pai-voice".into(), root: root.into(), cred: Credential { user: "noo".into(), token: TOKEN.into() } };
        let never = |_: &str| -> Result<Option<Bound>, String> { panic!("the store is not read without a record") };
        assert!(bound_for("pai-voice", &anchor(), None, &never).unwrap().is_none());
        assert!(bound_for("pai-voice", &anchor(), Some("ghcr.io/other/place"), &never).unwrap().is_none(), "bound elsewhere: unused");
        let b = bound_for("pai-voice", &anchor(), Some(ROOT), &|r| Ok(Some(cred(r)))).unwrap().unwrap();
        assert_eq!(b.root, ROOT);
        let e = bound_for("pai-voice", &anchor(), Some(ROOT), &|_| Ok(None)).unwrap_err();
        assert!(e.contains("noo addons registry-login pai-voice") && e.contains("NOO_ADDON_REGISTRY_CRED_PAI_VOICE"), "{e}");
        assert!(bound_for("pai-voice", &anchor(), Some(ROOT), &|_| Err("sops: no key".into())).is_err());
    }

    #[test]
    fn the_trust_entry_records_that_a_credential_exists_and_its_root_never_the_value() {
        let t = trusted_text();
        let set = set_credential(&t, "pai-voice", ROOT).unwrap();
        assert_eq!(credential_root(&set, "pai-voice").as_deref(), Some(ROOT));
        assert_eq!(read(&set).unwrap()["pai-voice"].keys, vec![pk()], "the keys are untouched");
        assert!(!set.contains(TOKEN));
        assert_eq!(credential_root(&t, "pai-voice"), None);
        // Cleared again: no record, the trust entry stays.
        let cleared = clear_credential(&set, "pai-voice").unwrap();
        assert_eq!(credential_root(&cleared, "pai-voice"), None);
        assert_eq!(read(&cleared).unwrap()["pai-voice"].keys, vec![pk()]);
        assert_eq!(clear_credential(&cleared, "pai-voice").unwrap(), cleared, "clearing nothing changes nothing");
    }

    #[test]
    fn registry_login_refuses_what_it_cannot_bind() {
        let t = trusted_text();
        // No trust entry.
        let e = set_credential("addons:\n  pai-voice: true\n", "pai-voice", ROOT).unwrap_err();
        assert!(e.contains("no trust entry") && e.contains("trust-key"), "{e}");
        // Not the trusted root: another host, a path under it, a parent of it.
        for bad in ["evil.example/example/intel", "ghcr.io/example/intel/sub", "ghcr.io/example"] {
            let e = set_credential(&t, "pai-voice", bad).unwrap_err();
            assert!(e.contains("--registry ghcr.io/example/intel"), "{bad}: {e}");
        }
        // A built-in add-on is pulled with its licence.
        assert!(set_credential(&t, "evolve", ROOT).unwrap_err().contains("ships with the stack"));
        // Two names that share one store slot are refused.
        let both = add_key(&t, "pai_voice", &pk(), Some(ROOT)).unwrap();
        assert!(set_credential(&both, "pai-voice", ROOT).unwrap_err().contains("NOO_ADDON_REGISTRY_CRED_PAI_VOICE"));
    }

    /// Removing the last key removes the entry, and the credential record with it.
    #[test]
    fn untrusting_the_last_key_takes_the_credential_record_with_it() {
        let set = set_credential(&trusted_text(), "pai-voice", ROOT).unwrap();
        let gone = remove_key(&set, "pai-voice", &pk()).unwrap();
        assert!(credential_root(&gone, "pai-voice").is_none() && !gone.contains("registry_credential"), "{gone}");
        assert!(!read(&gone).unwrap().contains_key("pai-voice"));
        // With a key left, the entry (and its credential) stays.
        let two = add_key(&set, "pai-voice", &pk2(), None).unwrap();
        let one = remove_key(&two, "pai-voice", &pk2()).unwrap();
        assert_eq!(credential_root(&one, "pai-voice").as_deref(), Some(ROOT));
    }

    #[test]
    fn list_shows_set_or_not_set_never_the_value() {
        use crate::commands::addons::credential_cell;
        let t = trusted_text();
        assert_eq!(credential_cell(&t, "pai-voice"), "not set");
        let set = set_credential(&t, "pai-voice", ROOT).unwrap();
        assert_eq!(credential_cell(&set, "pai-voice"), format!("set ({ROOT})"));
        // Re-trusted on another root since: shown, and not used.
        let moved = set.replace(&format!("registry: {ROOT}"), "registry: ghcr.io/example/moved");
        assert!(credential_cell(&moved, "pai-voice").contains("NOT the trusted root"), "{}", credential_cell(&moved, "pai-voice"));
    }
}
