// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security addon-lock sign` / `verify`: the add-on release
//! pipeline's lock verbs, over [`crate::addon_lock`]. They are key-agnostic
//! on purpose: the add-on's seed and public key come from the caller, never
//! from this build, so one implementation of the format serves every
//! add-on and the public tree names no add-on key.
//!
//! The seed is read from `--seed-file <path>`, or from standard input with
//! `--seed-file -` so a workflow can pipe its secret without writing it to
//! disk. It is never read from an environment variable and never printed.
//!
//! `--file <name>=<path>` (repeatable) makes `sign` write a BUNDLE lock
//! (`noo-addon-lock/2`): each file's sha256 is listed under `files`, so the
//! one signature covers the add-on's compose overlay and anything else it
//! ships beside its images. `verify --files-dir <dir>` then holds the files
//! in `<dir>` to those hashes.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;

use crate::addon_lock::{self, AddonLock, BaseImage, TrustAnchor};
use crate::output::{fail, ExitCode};
use crate::release_sig;
use crate::ui;
use crate::{Globals, Unhandled};

const SIGN_USAGE: &str = "usage: noo security addon-lock sign --addon <name> --version <v> --source-commit <sha> --supports <tag>[,<tag>]... --image <name>=<ref@digest>... [--base <image>=<digest>] [--file <name>=<path>]... [--registry <root>] --seed-file <path|-> --out <path>";
const VERIFY_USAGE: &str = "usage: noo security addon-lock verify <path> --key <pubkey>... --addon <name> --registry <root> [--sig <path>] [--stack <tag>] [--files-dir <dir>]";

fn usage_fail(g: &Globals, msg: &str, usage: &str) -> ! {
    fail(g.json, ExitCode::Usage, "usage", msg, Some(usage))
}

fn take(g: &Globals, it: &mut std::slice::Iter<'_, String>, flag: &str, usage: &str) -> String {
    match it.next() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => usage_fail(g, &format!("{flag} needs a value"), usage),
    }
}

/// `name=value` with both halves non-empty.
fn split_pair(s: &str) -> Option<(String, String)> {
    let (k, v) = s.split_once('=')?;
    (!k.trim().is_empty() && !v.trim().is_empty()).then(|| (k.trim().to_string(), v.trim().to_string()))
}

fn read_seed(g: &Globals, path: &str) -> String {
    let mut s = String::new();
    let r = if path == "-" {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|t| s = t)
    };
    if let Err(e) = r {
        let from = if path == "-" { "standard input".to_string() } else { path.to_string() };
        fail(g.json, ExitCode::Generic, "no_seed", &format!("Add-on signing seed unreadable from {from} ({e})"),
            Some("the seed never enters a repo; the add-on's release workflow carries it as a secret"));
    }
    s.trim().to_string()
}

pub fn security_addon_lock_sign(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut addon, mut version, mut commit, mut seed_file, mut out, mut base, mut registry) =
        (None, None, None, None, None, None, None);
    let mut supports: Vec<String> = Vec::new();
    let mut images: BTreeMap<String, String> = BTreeMap::new();
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--file" => {
                let v = take(g, &mut it, a, SIGN_USAGE);
                let Some((name, path)) = split_pair(&v) else {
                    usage_fail(g, &format!("--file {v}: expected <name>=<path>"), SIGN_USAGE)
                };
                if !addon_lock::valid_file_name(&name) {
                    usage_fail(g, &format!("--file {name}: a bundle file name is one plain component ([A-Za-z0-9._-])"), SIGN_USAGE);
                }
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{path}: {e}"), None),
                };
                if files.insert(name.clone(), addon_lock::sha256_ref(&bytes)).is_some() {
                    usage_fail(g, &format!("--file {name} given twice"), SIGN_USAGE);
                }
            }
            "--addon" => addon = Some(take(g, &mut it, a, SIGN_USAGE)),
            "--version" => version = Some(take(g, &mut it, a, SIGN_USAGE)),
            "--source-commit" => commit = Some(take(g, &mut it, a, SIGN_USAGE)),
            "--supports" => supports.extend(
                take(g, &mut it, a, SIGN_USAGE).split(',').map(str::trim).filter(|t| !t.is_empty()).map(String::from),
            ),
            "--image" => {
                let v = take(g, &mut it, a, SIGN_USAGE);
                let Some((name, reference)) = split_pair(&v) else {
                    usage_fail(g, &format!("--image {v}: expected <name>=<ref@digest>"), SIGN_USAGE)
                };
                if images.insert(name.clone(), reference).is_some() {
                    usage_fail(g, &format!("--image {name} given twice"), SIGN_USAGE);
                }
            }
            "--base" => {
                let v = take(g, &mut it, a, SIGN_USAGE);
                let Some((image, digest)) = split_pair(&v) else {
                    usage_fail(g, &format!("--base {v}: expected <image>=<digest>"), SIGN_USAGE)
                };
                base = Some(BaseImage { image, digest });
            }
            "--registry" => registry = Some(take(g, &mut it, a, SIGN_USAGE)),
            "--seed-file" => seed_file = Some(take(g, &mut it, a, SIGN_USAGE)),
            "--out" => out = Some(PathBuf::from(take(g, &mut it, a, SIGN_USAGE))),
            "--help" | "-h" => { println!("{SIGN_USAGE}"); return Ok(0); }
            v => usage_fail(g, &format!("unknown argument {v}"), SIGN_USAGE),
        }
    }
    let (Some(addon), Some(version), Some(commit), Some(seed_file), Some(out)) = (addon, version, commit, seed_file, out) else {
        usage_fail(g, "--addon, --version, --source-commit, --seed-file and --out are required", SIGN_USAGE)
    };
    let mut seen = std::collections::HashSet::new();
    supports.retain(|t| seen.insert(t.clone()));
    let format = if files.is_empty() { addon_lock::FORMAT } else { addon_lock::FORMAT_V2 };
    let lock = AddonLock {
        format: format.to_string(),
        addon: addon.clone(),
        version,
        source_commit: commit.to_lowercase(),
        supports_stack: supports,
        images,
        base,
        files,
    };
    if let Some(r) = registry.as_deref() {
        if !addon_lock::valid_registry_root(r) {
            fail(g.json, ExitCode::Usage, "bad_registry", &format!("Registry root {r:?} is not a registry path"),
                Some("give host/path with no scheme, tag or trailing slash"));
        }
    }
    // Refuse to sign what no verifier would accept.
    if let Err(e) = lock.validate(&addon, registry.as_deref()) {
        fail(g.json, ExitCode::Generic, "addon_lock_invalid", &e.to_string(), Some(SIGN_USAGE));
    }
    let seed = read_seed(g, &seed_file);
    let key = match release_sig::signing_key_from_seed_hex(&seed) {
        Ok(k) => k,
        Err(e) => fail(g.json, ExitCode::Generic, "bad_seed", &format!("Add-on signing seed invalid: {e}"), None),
    };
    let pk = release_sig::pubkey_hex(&key);
    let (bytes, sig) = match addon_lock::sign(&lock, &seed) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "bad_seed", &format!("Add-on signing seed invalid: {e}"), None),
    };
    let sig_path = PathBuf::from(format!("{}.sig", out.display()));
    for (path, data) in [(&out, bytes), (&sig_path, format!("{sig}\n").into_bytes())] {
        if let Err(e) = std::fs::write(path, data) {
            fail(g.json, ExitCode::Generic, "write_failed", &format!("{}: {e}", path.display()), None);
        }
    }
    if g.json {
        println!("{}", serde_json::json!({"signed": out, "sig": sig_path, "addon": addon, "version": lock.version,
            "format": lock.format, "files": lock.files, "pubkey": pk}));
    } else {
        ui::done(&format!("signed {} {} lock to {}  {}", addon, lock.version, out.display(), ui::muted(&format!("key {}…", &pk[..12]))));
    }
    Ok(0)
}

pub fn security_addon_lock_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut file, mut sig_path, mut addon, mut registry, mut stack, mut files_dir) = (None, None, None, None, None, None);
    let mut keys: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => keys.push(take(g, &mut it, a, VERIFY_USAGE).to_lowercase()),
            "--addon" => addon = Some(take(g, &mut it, a, VERIFY_USAGE)),
            "--registry" => registry = Some(take(g, &mut it, a, VERIFY_USAGE)),
            "--sig" => sig_path = Some(PathBuf::from(take(g, &mut it, a, VERIFY_USAGE))),
            "--stack" => stack = Some(take(g, &mut it, a, VERIFY_USAGE)),
            "--files-dir" => files_dir = Some(PathBuf::from(take(g, &mut it, a, VERIFY_USAGE))),
            "--help" | "-h" => { println!("{VERIFY_USAGE}"); return Ok(0); }
            v if v.starts_with('-') => usage_fail(g, &format!("unknown flag {v}"), VERIFY_USAGE),
            v if file.is_none() => file = Some(PathBuf::from(v)),
            v => usage_fail(g, &format!("unexpected argument {v}"), VERIFY_USAGE),
        }
    }
    let (Some(file), Some(addon), Some(registry)) = (file, addon, registry) else {
        usage_fail(g, "a lock path, --addon and --registry are required", VERIFY_USAGE)
    };
    if keys.is_empty() {
        usage_fail(g, "at least one --key is required", VERIFY_USAGE);
    }
    let sig_path = sig_path.unwrap_or_else(|| PathBuf::from(format!("{}.sig", file.display())));
    let bytes = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", file.display()), None),
    };
    let sig = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", sig_path.display()), None),
    };
    let anchor = TrustAnchor { keys, registry, pull: None };
    let v = match addon_lock::verify(&bytes, &sig, &anchor, &addon) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "addon_lock_invalid", &e.to_string(),
            Some("the lock or its signature was altered, or it was signed for another add-on, key or registry")),
    };
    if let Some(dir) = files_dir.as_deref() {
        // Exactly the files the lock lists, read from <dir>; anything else in
        // the directory is not the bundle's business.
        let mut found = BTreeMap::new();
        for name in v.lock.files.keys() {
            if let Ok(b) = std::fs::read(dir.join(name)) {
                found.insert(name.clone(), b);
            }
        }
        if v.lock.files.is_empty() {
            fail(g.json, ExitCode::Generic, "addon_lock_no_files",
                &format!("Add-on lock {} is {} and lists no files to check in {}", file.display(), v.lock.format, dir.display()),
                Some("sign with --file <name>=<path> to make a bundle"));
        }
        if let Err(e) = addon_lock::verify_files(&v.lock, &found) {
            fail(g.json, ExitCode::Generic, "addon_bundle_file_mismatch", &format!("{e} (in {})", dir.display()),
                Some("the file was altered after signing, or the bundle was packaged from other bytes"));
        }
    }
    if let Some(t) = stack.as_deref() {
        if !v.lock.supports(t) {
            fail(g.json, ExitCode::Generic, "addon_lock_unsupported_stack",
                &format!("Add-on {} {} does not support stack {t} (supports {})", v.lock.addon, v.lock.version, v.lock.supports_stack.join(", ")),
                Some("sign a lock that lists this stack version"));
        }
    }
    if g.json {
        println!("{}", serde_json::json!({"verified": true, "file": file, "key_index": v.key_index, "lock": v.lock}));
    } else {
        println!("{}", ui::status_line(ui::Glyph::Ok, &format!(
            "Add-on lock {} {} verifies against add-on key #{}  {}",
            v.lock.addon, v.lock.version, v.key_index, ui::muted(&format!("{}…", &anchor.keys[v.key_index][..12.min(anchor.keys[v.key_index].len())])))));
        let mut rows: Vec<(&str, String)> = vec![
            ("Stack", v.lock.supports_stack.join(", ")),
            ("Source", v.lock.source_commit.clone()),
        ];
        if let Some(b) = &v.lock.base {
            rows.push(("Base", format!("{} {}", b.image, b.digest)));
        }
        print!("{}", ui::kv(&rows));
        for (name, reference) in &v.lock.images {
            println!("  {name}  {}", ui::muted(reference));
        }
        for (name, digest) in &v.lock.files {
            let checked = if files_dir.is_some() { " (checked)" } else { "" };
            println!("  file {name}  {}{checked}", ui::muted(digest));
        }
    }
    Ok(0)
}
