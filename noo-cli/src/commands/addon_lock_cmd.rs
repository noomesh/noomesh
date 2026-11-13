// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security addon-lock sign` / `publish` / `verify`: the add-on release
//! pipeline's lock verbs, over [`crate::addon_lock`]. They are key-agnostic
//! on purpose: the add-on's seed and public key come from the caller, never
//! from this build, so one implementation of the format serves every
//! add-on and the public tree names no add-on key.
//!
//! The seed is read from `--seed-file <path>`, or from standard input with
//! `--seed-file -` so a workflow can pipe its secret without writing it to
//! disk. It is never read from an environment variable and never printed.
//!
//! `verify` is the release-side check (an add-on's release workflow runs it
//! before publishing), so it never ships a development key (i163 part A):
//! every `--key` must be a release key, and a lock that verifies only
//! against a development key is refused. The development keys it knows are
//! the `--dev-key` flags plus every `addon_trust.*.dev_keys` record in this
//! install's noomesh.yaml, when there is one.
//!
//! `publish` pushes what `sign` wrote to the add-on's own registry package
//! (one OCI artifact per supported stack tag, the layout `lock_fetch`
//! reads) and reads each tag back through the upgrade's own fetch, so a
//! broken publish fails at the publisher: [`crate::addons::lock_publish`].
//!
//! `--file <name>=<path>` (repeatable) makes `sign` write a BUNDLE lock
//! (`noo-addon-lock/2`): each file's sha256 is listed under `files`, so the
//! one signature covers the add-on's compose overlay and anything else it
//! ships beside its images. `verify --files-dir <dir>` then holds the files
//! in `<dir>` to those hashes.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::addon_lock::{self, AddonLock, BaseImage, TrustAnchor};
use crate::addons::lock_fetch::{self, Credential};
use crate::addons::lock_publish;
use crate::output::{fail, ExitCode};
use crate::release_sig;
use crate::ui;
use crate::{Globals, Unhandled};

const SIGN_USAGE: &str = "usage: noo security addon-lock sign --addon <name> --version <v> --source-commit <sha> --supports <tag>[,<tag>]... --image <name>=<ref@digest>... [--base <image>=<digest>] [--file <name>=<path>]... [--registry <root>] --seed-file <path|-> --out <path>";
const PUBLISH_USAGE: &str = "usage: noo security addon-lock publish <bundle.json> --registry <root> [--files-dir <dir>] [--user <name>] [--token-file <path|->] [--dry-run]";
/// Where a developer keeps the seed, said wherever sign is described.
const SEED_NOTE: &str = "keep the seed file outside the add-on's repository, mode 0600, never committed";
const VERIFY_USAGE: &str = "usage: noo security addon-lock verify <path> --key <pubkey>... --addon <name> --registry <root> [--sig <path>] [--stack <tag>] [--files-dir <dir>] [--dev-key <pubkey>]...";

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

/// Where a secret was read from, for an error. A value with no `/` or `.`
/// is not echoed: it may be the secret itself, typed where its path goes.
fn secret_source(path: &str, flag: &str) -> String {
    if path == "-" {
        "standard input".to_string()
    } else if path.contains(['/', '.']) {
        path.to_string()
    } else {
        format!("the {flag} value (not shown: a path has a / or a ., and the secret itself never goes on the command line)")
    }
}

fn read_seed(g: &Globals, path: &str) -> String {
    let mut s = String::new();
    let r = if path == "-" {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|t| s = t)
    };
    if let Err(e) = r {
        let from = secret_source(path, "--seed-file");
        fail(g.json, ExitCode::Generic, "no_seed", &format!("Add-on signing seed unreadable from {from} ({e})"),
            Some(&format!("{SEED_NOTE}; a release workflow carries it as a secret and pipes it to --seed-file -")));
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
            "--help" | "-h" => { println!("{SIGN_USAGE}\n  {SEED_NOTE}"); return Ok(0); }
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

/// A secret read from `path` (or standard input for `-`), trimmed. Never
/// printed: a failure names the path only.
fn read_token(g: &Globals, path: &str) -> String {
    let mut s = String::new();
    let r = if path == "-" {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|t| s = t)
    };
    if let Err(e) = r {
        let from = secret_source(path, "--token-file");
        fail(g.json, ExitCode::Generic, "no_token", &format!("Registry token unreadable from {from} ({e})"), None);
    }
    let t = s.trim().to_string();
    if t.is_empty() {
        fail(g.json, ExitCode::Generic, "no_token", &format!("Registry token from {} is empty", secret_source(path, "--token-file")), None);
    }
    t
}

fn read_or_fail(g: &Globals, path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", path.display()), None),
    }
}

fn read_sig_or_fail(g: &Globals, path: &Path) -> String {
    match String::from_utf8(read_or_fail(g, path)) {
        Ok(s) => s,
        Err(_) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{} is not a signature (not text)", path.display()), None),
    }
}

pub fn security_addon_lock_publish(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut bundle, mut registry, mut files_dir, mut user, mut token_file) = (None, None, None, None, None);
    let mut dry_run = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--registry" => registry = Some(take(g, &mut it, a, PUBLISH_USAGE)),
            "--files-dir" => files_dir = Some(PathBuf::from(take(g, &mut it, a, PUBLISH_USAGE))),
            "--user" => user = Some(take(g, &mut it, a, PUBLISH_USAGE)),
            "--token-file" => token_file = Some(take(g, &mut it, a, PUBLISH_USAGE)),
            "--dry-run" => dry_run = true,
            "--help" | "-h" => { println!("{PUBLISH_USAGE}"); return Ok(0); }
            v if v.starts_with('-') => usage_fail(g, &format!("unknown flag {v}"), PUBLISH_USAGE),
            v if bundle.is_none() => bundle = Some(PathBuf::from(v)),
            v => usage_fail(g, &format!("unexpected argument {v}"), PUBLISH_USAGE),
        }
    }
    let (Some(bundle), Some(registry)) = (bundle, registry) else {
        usage_fail(g, "a bundle path and --registry are required", PUBLISH_USAGE)
    };
    let registry = registry.trim().to_string();
    if !addon_lock::valid_registry_root(&registry) {
        fail(g.json, ExitCode::Usage, "bad_registry", &format!("Registry root {registry:?} is not a registry path"),
            Some("give host/path with no scheme, port, tag or trailing slash"));
    }
    // What sign wrote: the bundle and its .sig, the v1 pair beside it when
    // one was signed, and the files the bundle lists.
    let dir = bundle.parent().map(Path::to_path_buf).unwrap_or_default();
    let files_dir = files_dir.unwrap_or_else(|| dir.clone());
    let bundle_bytes = read_or_fail(g, &bundle);
    let bundle_sig = read_sig_or_fail(g, &PathBuf::from(format!("{}.sig", bundle.display())));
    let v1_path = dir.join(lock_fetch::LOCK_TITLE);
    let is_bundle = std::fs::canonicalize(&v1_path).ok() == std::fs::canonicalize(&bundle).ok();
    let v1 = (v1_path.is_file() && !is_bundle).then(|| {
        (read_or_fail(g, &v1_path), read_sig_or_fail(g, &PathBuf::from(format!("{}.sig", v1_path.display()))))
    });
    let has_v1 = v1.is_some();
    // The names come from the bundle; plan() holds the bytes to it.
    let names: Vec<String> = serde_json::from_slice::<AddonLock>(&bundle_bytes)
        .map(|l| l.files.into_keys().collect())
        .unwrap_or_default();
    let mut files = BTreeMap::new();
    for name in names.into_iter().filter(|n| addon_lock::valid_file_name(n)) {
        if let Ok(b) = std::fs::read(files_dir.join(&name)) {
            files.insert(name, b);
        }
    }
    let inputs = lock_publish::Inputs { bundle: bundle_bytes, bundle_sig, v1, files };
    let plan = match lock_publish::plan(inputs, &registry) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "addon_lock_unpublishable", &format!("{}: {e}", bundle.display()),
            Some(&format!("publish the files sign wrote, unchanged; the bundle's files are read from {} (--files-dir)", files_dir.display()))),
    };
    let refs: Vec<String> = plan.tags.iter().map(|t| lock_fetch::artifact_ref(&registry, t)).collect();
    let blobs: Vec<serde_json::Value> = std::iter::once(&plan.config).chain(plan.layers.iter()).map(|b| b.summary()).collect();
    if dry_run {
        if g.json {
            println!("{}", serde_json::json!({"dry_run": true, "addon": plan.addon, "version": plan.version, "registry": registry,
                "refs": refs, "manifest_digest": plan.manifest_digest, "blobs": blobs}));
            return Ok(0);
        }
        ui::say(&format!("Would publish {} {} to {} (nothing pushed):", plan.addon, plan.version, registry));
        for r in &refs {
            ui::say(&ui::sub(r));
        }
        ui::say(&ui::note(&format!("manifest {}", plan.manifest_digest)));
        for b in std::iter::once(&plan.config).chain(plan.layers.iter()) {
            ui::say(&format!("  {}  {}  {} bytes  {}", b.title.as_deref().unwrap_or("(config)"), ui::muted(b.media_type), b.bytes.len(), ui::muted(&b.digest)));
        }
        if !has_v1 {
            ui::say(&ui::note(&format!("no {} beside the bundle: only CLIs that read the bundle (0.6.4 and later) can use this release", lock_fetch::LOCK_TITLE)));
        }
        return Ok(0);
    }
    // The credential: --token-file, else GH_TOKEN / GITHUB_TOKEN. Never printed.
    let (token, source) = match token_file.as_deref() {
        Some(p) => (Some(read_token(g, p)), "--token-file"),
        None => match crate::commands::upgrade::gh_token() {
            Some(t) => (Some(t), "GH_TOKEN/GITHUB_TOKEN"),
            None => (None, "anonymous"),
        },
    };
    let cred = token.map(|token| Credential { user: user.unwrap_or_else(|| lock_fetch::DEFAULT_USER.to_string()), token });
    let pusher = lock_publish::Pusher::new(cred.clone());
    let bound = cred.map(|c| lock_fetch::Bound { addon: plan.addon.clone(), root: registry.clone(), cred: c });
    let fetcher = lock_fetch::Client::new(None).with_bound(bound);
    let out = match lock_publish::publish(&pusher, &fetcher, &registry, &plan) {
        Ok(o) => o,
        Err(e) => fail(g.json, ExitCode::Generic, "addon_lock_publish_failed", &e,
            Some("a push needs a token that can write the package (--token-file, or GH_TOKEN); a read-back failure means the registry does not serve what was pushed, so nothing under that tag is safe to upgrade to")),
    };
    let uploaded: usize = out.iter().map(|p| p.uploaded).sum();
    let published: Vec<String> = out.iter().map(|p| p.reference.clone()).collect();
    if g.json {
        println!("{}", serde_json::json!({"published": true, "addon": plan.addon, "version": plan.version, "registry": registry,
            "refs": published, "verified": true,
            "manifest_digest": plan.manifest_digest, "blobs": blobs, "uploaded": uploaded, "credential": source}));
    } else {
        for p in &out {
            ui::done(&format!("published {}  {}", p.reference, ui::muted("read back: the signed lock and its files, as pushed")));
        }
        ui::say(&ui::note(&format!("{} {}; {uploaded} of {} blobs uploaded (the rest were there); credential: {source}",
            plan.addon, plan.version, blobs.len())));
        if !has_v1 {
            ui::say(&ui::note(&format!("no {} beside the bundle: only CLIs that read the bundle (0.6.4 and later) can use this release", lock_fetch::LOCK_TITLE)));
        }
    }
    Ok(0)
}

/// This install's development keys (`addon_trust.*.dev_keys`), when it has
/// a noomesh.yaml. No file is no keys; a file that does not parse is an error.
fn local_dev_keys() -> Result<Vec<addon_lock::DevKey>, String> {
    let path = crate::commands::addons::config_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => crate::addons::trust::all_dev_keys(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(_) => Ok(Vec::new()),
    }
}

/// Every development key release verification must refuse: the `--dev-key`
/// flags and this install's. Expiry does not matter here (an expired
/// development key is still not a release key), so each is held as
/// never-expiring, which makes a lock it signed verify as dev-signed and be
/// refused by name rather than as a bad signature.
pub(crate) fn release_dev_set(flags: &[String], local: Vec<addon_lock::DevKey>) -> Vec<addon_lock::DevKey> {
    let mut out: Vec<addon_lock::DevKey> = Vec::new();
    for key in flags.iter().cloned().chain(local.into_iter().map(|d| d.key)) {
        if !out.iter().any(|d| d.key == key) {
            out.push(addon_lock::DevKey { key, expires_at: i64::MAX });
        }
    }
    out
}

pub fn security_addon_lock_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut file, mut sig_path, mut addon, mut registry, mut stack, mut files_dir) = (None, None, None, None, None, None);
    let mut keys: Vec<String> = Vec::new();
    let mut dev_flags: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => keys.push(take(g, &mut it, a, VERIFY_USAGE).to_lowercase()),
            "--dev-key" => dev_flags.push(take(g, &mut it, a, VERIFY_USAGE).trim().to_lowercase()),
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
    let local_dev = match local_dev_keys() {
        Ok(d) => d,
        Err(e) => fail(g.json, ExitCode::Generic, "config", &format!("{e} — refusing to verify a release without knowing this install's development keys"), None),
    };
    let dev = release_dev_set(&dev_flags, local_dev);
    if let Err(e) = addon_lock::refuse_dev_in_release(&keys, &dev) {
        fail(g.json, ExitCode::Generic, "addon_lock_dev_key", &e, Some("pass the add-on's release keys to --key"));
    }
    let anchor = TrustAnchor { keys, registry, pull: None, dev };
    let v = match addon_lock::verify(&bytes, &sig, &anchor, &addon) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "addon_lock_invalid", &e.to_string(),
            Some("the lock or its signature was altered, or it was signed for another add-on, key or registry")),
    };
    if v.dev_expires_at.is_some() {
        fail(g.json, ExitCode::Generic, "addon_lock_dev_signed",
            &format!("Add-on lock {} is signed only by a development key; a release never ships one", file.display()),
            Some("re-sign it with the add-on's release key"));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: &str) -> String {
        release_sig::pubkey_hex(&release_sig::signing_key_from_seed_hex(seed).unwrap())
    }

    fn lock() -> AddonLock {
        AddonLock {
            format: addon_lock::FORMAT.into(),
            addon: "pai-voice".into(),
            version: "0.1.0".into(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            supports_stack: vec!["v0.6.10".into()],
            images: BTreeMap::from([("pai-voice".to_string(), format!("ghcr.io/vendor/pai-voice@sha256:{}", "a".repeat(64)))]),
            base: None,
            files: BTreeMap::new(),
        }
    }

    #[test]
    fn a_secret_typed_where_its_path_goes_is_never_echoed() {
        let seed = "cd".repeat(32);
        assert!(!secret_source(&seed, "--seed-file").contains(&seed));
        assert!(!secret_source("fake_token_value_0001", "--token-file").contains("fake_token_value_0001"));
        assert_eq!(secret_source("/run/secrets/seed", "--seed-file"), "/run/secrets/seed");
        assert_eq!(secret_source("seed.hex", "--seed-file"), "seed.hex");
        assert_eq!(secret_source("-", "--token-file"), "standard input");
    }

    #[test]
    fn release_verification_refuses_a_lock_only_a_dev_key_signed() {
        let dev_seed = "cd".repeat(32);
        let (bytes, sig) = addon_lock::sign(&lock(), &dev_seed).unwrap();
        // An expired local record is still a development key here.
        let local = vec![addon_lock::DevKey { key: pk(&dev_seed), expires_at: 1 }];
        let dev = release_dev_set(&[pk(&dev_seed)], local);
        assert_eq!(dev.len(), 1, "the flag and the local record are one key");
        assert_eq!(dev[0].expires_at, i64::MAX);
        let anchor = TrustAnchor { keys: vec![pk(&"ab".repeat(32))], registry: "ghcr.io/vendor/pai-voice".into(), pull: None, dev: dev.clone() };
        let v = addon_lock::verify(&bytes, &sig, &anchor, "pai-voice").expect("verifies, as dev-signed");
        assert!(v.dev_expires_at.is_some(), "the release verb refuses exactly this");
        // Passing the dev key as a release key is refused before any verification.
        // ... and the refusal names no date: the never-expiring hold is not
        // an expiry to show ("expires 292277026596-12-04" before).
        let e = addon_lock::refuse_dev_in_release(&[pk(&dev_seed)], &dev).unwrap_err();
        assert!(e.contains("development key") && !e.contains("expires") && !e.contains("292277026596"), "{e}");
        // A lock signed by the release key passes as a release lock.
        let (bytes, sig) = addon_lock::sign(&lock(), &"ab".repeat(32)).unwrap();
        let v = addon_lock::verify(&bytes, &sig, &anchor, "pai-voice").unwrap();
        assert_eq!((v.key_index, v.dev_expires_at), (0, None));
    }
}
