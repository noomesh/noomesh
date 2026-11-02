// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo models fetch <hf_repo> <file.gguf>` — download a ready-made GGUF
//! from Hugging Face into the controller's model store (`MODELS_DIR`).
//!
//! Before this command the operator curled the file by hand (2026-10-10):
//! the curl hit "Permission denied" because the store belongs to a service
//! account, and the store turned out to be an NFS mount
//! (`/mnt/fleet/models/gguf`) that refuses `chown`. So this command:
//!
//! - resolves the store exactly like `noo cluster sync-model-files`
//!   ([`controller_store_dir`] is the one resolver both use);
//! - refuses, with the exact remedy, when the invoking user cannot write the
//!   store. It never chowns (NFS refuses it) and never escalates;
//! - reads the controller's Hugging Face token from the process env or the
//!   encrypted secrets store (`secrets/env.sops`), and sends it only as an
//!   `Authorization` header — never on argv, never in a log line, and never
//!   to a host other than the Hugging Face endpoint (a CDN redirect is
//!   pre-signed and gets no token);
//! - streams into `.<file>.part` in the store directory and resumes it on a
//!   re-run with an HTTP `Range` request;
//! - verifies the sha256 against Hugging Face's LFS metadata (the
//!   `x-linked-etag` header of the resolve URL, else the API's
//!   `lfs.sha256`), and only then renames into place with mode 0644 so the
//!   model-cache nginx can read it;
//! - pre-warms the gateway's digest cache (`GET
//!   /api/artifacts/manifest/gguf/<file>`), best effort, so the first
//!   `sync-model-files` does not wait on a multi-GB hash.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::args::{ArgError, Args};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

// ── Arguments ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchArgs {
    /// `org/name` on Hugging Face.
    pub repo: String,
    /// Path of the file inside the repo (may contain `/`).
    pub file: String,
    /// Branch, tag or commit; default `main`.
    pub revision: String,
    /// Replace an existing store file whose digest differs.
    pub force: bool,
}

impl FetchArgs {
    /// The name the file gets in the store: the last path segment, because
    /// `sync-model-files -m` and the model cache address bare filenames.
    pub fn store_name(&self) -> &str {
        self.file.rsplit('/').next().unwrap_or(&self.file)
    }
}

/// Parse `<hf_repo> <file.gguf> [--revision <rev>] [--force]`.
pub(crate) fn parse_args(args: &[String]) -> Result<FetchArgs, String> {
    parse_fetch_with(&mut Args::new(args)).map_err(|e| e.0)
}

pub(crate) fn parse_fetch_with(a: &mut Args) -> Result<FetchArgs, ArgError> {
    let revision = a.value(&["--revision", "-r"])?.unwrap_or_else(|| "main".to_string());
    let force = a.flag(&["--force"]);
    let pos = a.positionals()?;
    if pos.len() != 2 {
        return Err(ArgError::new("expected exactly two arguments: <hf_repo> <file.gguf>"));
    }
    let repo = pos[0].trim_matches('/').to_string();
    let file = pos[1].trim_start_matches('/').to_string();
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return Err(ArgError::new(format!("'{repo}' is not a Hugging Face repo id (want <org>/<name>)")));
    }
    if file.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return Err(ArgError::new(format!("'{file}' is not a file path inside the repo")));
    }
    if !file.to_ascii_lowercase().ends_with(".gguf") {
        return Err(ArgError::new(format!("'{file}' is not a .gguf file — the controller store holds GGUF weights only")));
    }
    if revision.is_empty() || revision.contains("..") {
        return Err(ArgError::new(format!("'{revision}' is not a usable revision")));
    }
    Ok(FetchArgs { repo, file, revision, force })
}

// ── Store resolution (shared with `cluster sync-model-files`) ──────────

/// `MODELS_DIR`, else `<NOO_DATA_ROOT>/models`, else `/var/lib/noo/models`.
/// Empty values count as unset. Pure, for the tests.
pub(crate) fn store_dir_from(models_dir: Option<&str>, data_root: Option<&str>) -> String {
    if let Some(m) = models_dir.filter(|s| !s.is_empty()) {
        return m.to_string();
    }
    let root = data_root
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::commands::data_root::DEFAULT_DATA_ROOT);
    format!("{}/models", root.trim_end_matches('/'))
}

/// The controller's GGUF store, from the process env (which already carries
/// `.env` via `ensure_repo_env`).
pub(crate) fn controller_store_dir() -> String {
    let m = std::env::var("MODELS_DIR").ok();
    let r = std::env::var("NOO_DATA_ROOT").ok();
    store_dir_from(m.as_deref(), r.as_deref())
}

// ── Writability ─────────────────────────────────────────────────────────

fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid returns NULL or a pointer into static storage; we copy
    // the name out before any other passwd call. Single-threaded CLI.
    unsafe {
        let p = libc::getpwuid(uid);
        if p.is_null() || (*p).pw_name.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*p).pw_name).to_string_lossy().into_owned()
    }
}

fn group_name(gid: u32) -> String {
    // SAFETY: as `user_name`.
    unsafe {
        let g = libc::getgrgid(gid);
        if g.is_null() || (*g).gr_name.is_null() {
            return gid.to_string();
        }
        std::ffi::CStr::from_ptr((*g).gr_name).to_string_lossy().into_owned()
    }
}

fn can_write_dir(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: c is a valid NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

/// The refusal for a store the invoking user cannot write, with the exact
/// remedy. Pure (names passed in), for the tests.
///
/// No `chown`: the store is commonly an NFS export, where root_squash makes
/// `chown` fail ("Operation not permitted") even under sudo. Group write or
/// an ACL is what works, and on NFS it must be applied on the server that
/// exports the directory.
pub(crate) fn unwritable_guide(dir: &str, owner: &str, group: &str, mode: u32, me: &str) -> (String, Vec<(String, String)>) {
    let msg = format!(
        "the model store {dir} is not writable by {me} (owner {owner}:{group}, mode {:o}) — refusing; nothing was downloaded",
        mode & 0o7777
    );
    let guide = vec![
        (
            format!("sudo chmod g+ws {dir} && sudo usermod -aG {group} {me}"),
            format!("make the store group-writable for '{group}' and join it (log in again afterwards); on NFS run the chmod on the server that exports it"),
        ),
        (
            format!("sudo setfacl -m u:{me}:rwx -m d:u:{me}:rwx {dir}"),
            "or grant just you write access with an ACL (NFSv4 exports: nfs4_setfacl on the server)".to_string(),
        ),
        (
            "noo models fetch <hf_repo> <file.gguf>".to_string(),
            "then re-run; do NOT chown the store — NFS refuses it, and the service account must keep owning it".to_string(),
        ),
    ];
    (msg, guide)
}

// ── Hugging Face transfer ──────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum FetchErr {
    /// 401/403 — gated, private, or a missing/invalid token.
    Auth(u16),
    NotFound,
    /// No LFS sha256 anywhere — nothing to verify against, so no install.
    NoDigest,
    Http(String),
    Io(String),
    Mismatch { expected: String, got: String },
    /// The store already holds a different file of that name.
    Conflict { existing: String, expected: String },
}

impl std::fmt::Display for FetchErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchErr::Auth(s) => write!(f, "Hugging Face refused the request ({s}): the repo is gated or private, or the token is missing/invalid"),
            FetchErr::NotFound => write!(f, "Hugging Face has no such file at that revision (404)"),
            FetchErr::NoDigest => write!(f, "Hugging Face published no LFS sha256 for this file — refusing to install an unverifiable download"),
            FetchErr::Http(e) => write!(f, "{e}"),
            FetchErr::Io(e) => write!(f, "{e}"),
            FetchErr::Mismatch { expected, got } => write!(f, "sha256 mismatch: Hugging Face says {expected}, the download hashes to {got} — the partial file was deleted; re-run to download again"),
            FetchErr::Conflict { existing, expected } => write!(f, "the store already holds a different file of that name (sha256 {existing}, Hugging Face says {expected}) — re-run with --force to replace it"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Remote {
    pub sha256: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    /// Bytes already on disk when this run started (0 = fresh download).
    pub resumed_from: u64,
    /// The store already held this exact file; nothing was transferred.
    pub already_present: bool,
}

/// Every segment of a repo-relative path, percent-encoded; `/` kept.
pub(crate) fn enc_path(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            let mut out = String::new();
            for b in seg.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn resolve_url(base: &str, a: &FetchArgs) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        base.trim_end_matches('/'),
        enc_path(&a.repo),
        enc_path(&a.revision),
        enc_path(&a.file)
    )
}

/// `HF_ENDPOINT` (the variable huggingface_hub honours), else huggingface.co.
pub(crate) fn hf_base() -> String {
    let b = std::env::var("HF_ENDPOINT").unwrap_or_default();
    let b = b.trim().trim_end_matches('/');
    if b.is_empty() { "https://huggingface.co".into() } else { b.to_string() }
}

/// `scheme://host[:port]` of a URL.
fn origin(url: &str) -> &str {
    let after = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[after..].find('/') {
        Some(j) => &url[..after + j],
        None => url,
    }
}

/// Resolve a `Location` header against the URL that returned it.
fn join_location(current: &str, loc: &str) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        loc.to_string()
    } else if loc.starts_with('/') {
        format!("{}{loc}", origin(current))
    } else {
        let dir = current.rsplit_once('/').map(|(d, _)| d).unwrap_or(current);
        format!("{dir}/{loc}")
    }
}

pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        // Redirects are followed by hand (see `get_following`) so the token
        // only ever goes to the Hugging Face origin and `Range` is never lost.
        .max_redirects(0)
        .build()
        .into()
}

/// A sha256 in hex from an etag-ish header value (`"abc…"`, `W/"abc…"`).
pub(crate) fn sha_from_etag(v: &str) -> Option<String> {
    let s = v.trim().trim_start_matches("W/").trim_matches('"').to_ascii_lowercase();
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

fn auth_header(token: Option<&str>) -> Option<String> {
    token.map(str::trim).filter(|t| !t.is_empty()).map(|t| format!("Bearer {t}"))
}

/// LFS metadata: `x-linked-etag` / `x-linked-size` on the resolve URL (HEAD,
/// no redirect followed), else the API's `siblings[].lfs.sha256`.
pub(crate) fn remote_meta(base: &str, token: Option<&str>, a: &FetchArgs) -> Result<Remote, FetchErr> {
    let ag = agent();
    let url = resolve_url(base, a);
    let mut req = ag.head(&url);
    if let Some(h) = auth_header(token) {
        req = req.header("Authorization", h);
    }
    let resp = req.call().map_err(|e| FetchErr::Http(format!("Hugging Face unreachable: {e}")))?;
    let status = resp.status().as_u16();
    match status {
        401 | 403 => return Err(FetchErr::Auth(status)),
        404 => return Err(FetchErr::NotFound),
        _ => {}
    }
    let hdr = |k: &str| resp.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let size = hdr("x-linked-size").and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(sha) = hdr("x-linked-etag").as_deref().and_then(sha_from_etag) {
        return Ok(Remote { sha256: sha, size });
    }

    // Fallback: the model API's LFS block for this sibling.
    let api = format!(
        "{}/api/models/{}/revision/{}?blobs=true",
        base.trim_end_matches('/'),
        enc_path(&a.repo),
        enc_path(&a.revision)
    );
    let mut req = ag.get(&api);
    if let Some(h) = auth_header(token) {
        req = req.header("Authorization", h);
    }
    let mut resp = req.call().map_err(|e| FetchErr::Http(format!("Hugging Face API unreachable: {e}")))?;
    let st = resp.status().as_u16();
    match st {
        401 | 403 => return Err(FetchErr::Auth(st)),
        404 => return Err(FetchErr::NotFound),
        200..=299 => {}
        _ => return Err(FetchErr::Http(format!("Hugging Face API returned {st}"))),
    }
    let text = resp.body_mut().read_to_string().map_err(|e| FetchErr::Http(format!("Hugging Face API read: {e}")))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| FetchErr::Http(format!("Hugging Face API returned non-JSON: {e}")))?;
    let sib = v["siblings"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["rfilename"].as_str() == Some(a.file.as_str())))
        .ok_or(FetchErr::NotFound)?;
    let sha = sib["lfs"]["sha256"].as_str().and_then(sha_from_etag).ok_or(FetchErr::NoDigest)?;
    let size = sib["lfs"]["size"].as_u64().or(size);
    Ok(Remote { sha256: sha, size })
}

/// GET with redirects followed by hand: `Range` goes on every hop, the token
/// only to the Hugging Face origin (a CDN location is pre-signed).
pub(crate) fn get_following(base: &str, url: &str, token: Option<&str>, range_from: u64) -> Result<ureq::http::Response<ureq::Body>, FetchErr> {
    let ag = agent();
    let hf_origin = origin(base).to_string();
    let mut cur = url.to_string();
    for _ in 0..8 {
        let mut req = ag.get(&cur);
        if origin(&cur) == hf_origin {
            if let Some(h) = auth_header(token) {
                req = req.header("Authorization", h);
            }
        }
        if range_from > 0 {
            req = req.header("Range", format!("bytes={range_from}-"));
        }
        let resp = req.call().map_err(|e| FetchErr::Http(format!("download failed: {e}")))?;
        let st = resp.status().as_u16();
        if (300..400).contains(&st) {
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| FetchErr::Http(format!("redirect {st} without a Location")))?;
            cur = join_location(&cur, loc);
            continue;
        }
        return match st {
            401 | 403 => Err(FetchErr::Auth(st)),
            404 => Err(FetchErr::NotFound),
            _ => Ok(resp),
        };
    }
    Err(FetchErr::Http("too many redirects".into()))
}

pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub(crate) fn io(ctx: &str, e: std::io::Error) -> FetchErr {
    FetchErr::Io(format!("{ctx}: {e}"))
}

pub(crate) fn part_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(".{name}.part"))
}

/// Download `a` into `dir`, resuming a `.part` file, verifying the sha256,
/// and renaming into place with mode 0644. `progress(done, total)` is
/// called as bytes arrive.
pub(crate) fn fetch_to_store(
    base: &str,
    token: Option<&str>,
    a: &FetchArgs,
    dir: &Path,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<Outcome, FetchErr> {
    use std::os::unix::fs::PermissionsExt;

    let remote = remote_meta(base, token, a)?;
    let name = a.store_name();
    let dest = dir.join(name);

    if dest.exists() {
        let have = sha256_file(&dest).map_err(|e| io(&format!("reading {}", dest.display()), e))?;
        if have == remote.sha256 {
            let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
            return Ok(Outcome { path: dest, sha256: have, size, resumed_from: 0, already_present: true });
        }
        if !a.force {
            return Err(FetchErr::Conflict { existing: have, expected: remote.sha256 });
        }
    }

    let part = part_path(dir, name);
    let mut have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    if let Some(total) = remote.size {
        if have > total {
            // Longer than the real file: cannot be a prefix of it.
            std::fs::remove_file(&part).map_err(|e| io("removing an oversized partial", e))?;
            have = 0;
        }
    }
    let resumed_from = have;

    let complete = remote.size.is_some_and(|t| have == t && t > 0);
    if !complete {
        let url = resolve_url(base, a);
        let mut resp = get_following(base, &url, token, have)?;
        let st = resp.status().as_u16();
        let mut f = match st {
            206 => OpenOptions::new().append(true).open(&part).map_err(|e| io(&format!("opening {}", part.display()), e))?,
            200 => {
                // The server ignored Range (or there was nothing to resume):
                // start over rather than append a whole file to a prefix.
                have = 0;
                File::create(&part).map_err(|e| io(&format!("creating {}", part.display()), e))?
            }
            416 if have > 0 => {
                // Nothing past what we hold — the hash below decides.
                OpenOptions::new().append(true).open(&part).map_err(|e| io(&format!("opening {}", part.display()), e))?
            }
            _ => return Err(FetchErr::Http(format!("download returned HTTP {st}"))),
        };
        if st != 416 {
            let mut body = resp.body_mut().with_config().limit(u64::MAX).reader();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = body.read(&mut buf).map_err(|e| io("download interrupted (re-run to resume)", e))?;
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n]).map_err(|e| io(&format!("writing {}", part.display()), e))?;
                have += n as u64;
                progress(have, remote.size);
            }
        }
        f.sync_all().map_err(|e| io("flushing the partial file", e))?;
    }

    let got = sha256_file(&part).map_err(|e| io(&format!("hashing {}", part.display()), e))?;
    if got != remote.sha256 {
        let _ = std::fs::remove_file(&part);
        return Err(FetchErr::Mismatch { expected: remote.sha256, got });
    }
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| io("setting mode 0644", e))?;
    std::fs::rename(&part, &dest).map_err(|e| io(&format!("renaming into {}", dest.display()), e))?;
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(have);
    Ok(Outcome { path: dest, sha256: got, size, resumed_from, already_present: false })
}

// ── Token ───────────────────────────────────────────────────────────────

/// The controller's Hugging Face token: process env first (the override
/// lane; startup already filled it from the store, fill-only-unset), then
/// the encrypted store itself. Never printed, never on argv.
pub(crate) fn hf_token() -> Option<String> {
    for k in ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"] {
        if let Ok(v) = std::env::var(k) {
            if !v.trim().is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    let store = crate::commands::secrets::SecretStore::load_sops(
        &crate::envfile::repo_root().join("secrets/env.sops"),
    )
    .ok()?;
    ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"]
        .iter()
        .filter_map(|k| store.value_for_provider_api(k))
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
}

// ── Command ─────────────────────────────────────────────────────────────

pub(crate) fn human(n: u64) -> String {
    const G: f64 = 1024.0 * 1024.0 * 1024.0;
    if n as f64 >= G { format!("{:.2} GB", n as f64 / G) } else { format!("{:.1} MB", n as f64 / (1024.0 * 1024.0)) }
}

/// The controller's model store as a directory this user can write — or the
/// explained refusal (never a chown, never an escalation). Shared by every
/// command that writes into the store; `rerun` is what the last remedy line
/// tells the operator to run again.
pub(crate) fn writable_store(g: &Globals, rerun: &str) -> (String, PathBuf) {
    let store = controller_store_dir();
    let dir = PathBuf::from(&store);
    if !dir.is_dir() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_store",
            &format!("controller model store not found: {store} (from MODELS_DIR, else NOO_DATA_ROOT/models)"),
            Some("set MODELS_DIR in .env to the directory the model-cache serves as /gguf/, or create it"),
        );
    }
    if !can_write_dir(&dir) {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(&dir).ok();
        let (uid, gid, mode) = md.map(|m| (m.uid(), m.gid(), m.mode())).unwrap_or((0, 0, 0));
        // SAFETY: geteuid has no preconditions.
        let me = user_name(unsafe { libc::geteuid() });
        let (msg, mut guide) = unwritable_guide(&store, &user_name(uid), &group_name(gid), mode, &me);
        guide[2].0 = rerun.to_string();
        if g.json {
            fail(true, ExitCode::Generic, "store_not_writable", &msg, Some(&guide[0].0));
        }
        ui::failed(&msg, None);
        let refs: Vec<(&str, &str)> = guide.iter().map(|(c, w)| (c.as_str(), w.as_str())).collect();
        ui::guide(&refs);
        ui::pager_finish();
        std::process::exit(ExitCode::Generic as i32);
    }

    (store, dir)
}

/// `noo models fetch <hf_repo> <file.gguf> [--revision <rev>] [--force]`
pub fn models_fetch(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // `ollama:<tag>` stages a registry.ollama.ai model instead
    // (commands/ollama_stage.rs); everything else is a Hugging Face GGUF.
    if args.first().is_some_and(|a| a.starts_with("ollama:")) {
        return super::ollama_stage::models_fetch_ollama(g, args);
    }
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) => fail(g.json, ExitCode::Usage, "bad_args", &e, Some("noo models fetch <hf_repo> <file.gguf>")),
    };
    let (store, dir) = writable_store(g, "noo models fetch <hf_repo> <file.gguf>");

    let token = hf_token();
    if !g.json {
        println!("{}", ui::header("models fetch", Some(&format!("{}@{} → {store}", a.repo, a.revision))));
        print!("{}", ui::kv(&[
            ("file", a.file.clone()),
            ("token", if token.is_some() { "from the controller's secrets".into() } else { "none (public repos only)".into() }),
        ]));
    }

    let mut last_pct: i64 = -1;
    let mut last_mb: u64 = 0;
    let json = g.json;
    let mut progress = |done: u64, total: Option<u64>| {
        if json {
            return;
        }
        match total {
            Some(t) if t > 0 => {
                let pct = (done * 100 / t) as i64;
                if pct / 5 != last_pct / 5 {
                    last_pct = pct;
                    eprintln!("  {pct:>3}%  {} / {}", human(done), human(t));
                }
            }
            _ => {
                if done / (512 << 20) != last_mb {
                    last_mb = done / (512 << 20);
                    eprintln!("  {}", human(done));
                }
            }
        }
    };

    let out = match fetch_to_store(&hf_base(), token.as_deref(), &a, &dir, &mut progress) {
        Ok(o) => o,
        Err(e) => {
            let hint = match &e {
                FetchErr::Auth(_) => Some("accept the model's licence on huggingface.co with the token's account, and store the token: `noo security secrets rotate HF_TOKEN --prompt`".to_string()),
                FetchErr::NotFound => Some(format!("check the file name at https://huggingface.co/{}/tree/{}", a.repo, a.revision)),
                FetchErr::Io(_) | FetchErr::Http(_) => Some("re-run the same command: the partial download resumes".to_string()),
                _ => None,
            };
            fail(g.json, ExitCode::RemoteError, "fetch_failed", &e.to_string(), hint.as_deref());
        }
    };

    let name = a.store_name().to_string();
    let warm = prewarm_digest(g, &name, &out.sha256);

    if g.json {
        println!("{}", json!({
            "path": out.path.display().to_string(),
            "file": name,
            "sha256": out.sha256,
            "size_bytes": out.size,
            "resumed_from": out.resumed_from,
            "already_present": out.already_present,
            "gateway_digest": warm,
            "next": [
                format!("noo cluster sync-model-files <node> -m {name}"),
                format!("noo cluster place <node> llamacpp {name}"),
            ],
        }));
        return Ok(0);
    }
    if out.already_present {
        ui::done(&format!("{name} already in the store, sha256 verified ({})", human(out.size)));
    } else {
        let resumed = if out.resumed_from > 0 { format!(", resumed from {}", human(out.resumed_from)) } else { String::new() };
        ui::done(&format!("{} — {}, sha256 {} verified{resumed}", out.path.display(), human(out.size), &out.sha256[..16]));
    }
    let sync = format!("noo cluster sync-model-files <node> -m {name}");
    let place = format!("noo cluster place <node> llamacpp {name}");
    ui::guide(&[
        (sync.as_str(), "copy it to a node over the artifact rail (digest-verified)"),
        (place.as_str(), "then run it there"),
    ]);
    Ok(0)
}

/// Ask the gateway to hash the new file now (it caches by path+size+mtime),
/// so the first `sync-model-files` does not wait on it. Best effort: the
/// fetch already succeeded, so nothing here fails the command.
pub(crate) fn prewarm_digest(g: &Globals, name: &str, verified: &str) -> Value {
    use crate::commands::cluster::{warm_gguf_manifest, ManifestWarm};
    // One ask (no waiting out a 202): this command has already verified the
    // bytes; the gateway keeps hashing and sync-model-files waits for it.
    match warm_gguf_manifest(g, name, std::time::Duration::ZERO) {
        ManifestWarm::Ready(s) if s == verified => {
            if !g.json {
                ui::step("gateway digest cache warm (matches)");
            }
            json!({"state": "warm", "sha256": s})
        }
        ManifestWarm::Ready(s) => {
            if !g.json {
                ui::warned(&format!(
                    "THE GATEWAY HASHES {name} TO {s}, NOT {verified} — the gateway may be serving a different MODELS_DIR, or the file changed after the download; nodes will verify against the gateway's digest"
                ));
            }
            json!({"state": "mismatch", "sha256": s})
        }
        ManifestWarm::Hashing(_) => {
            if !g.json {
                ui::step("gateway is hashing the file in the background (large file) — sync-model-files will find it cached");
            }
            json!({"state": "hashing"})
        }
        ManifestWarm::Missing => {
            if !g.json {
                ui::warned(&format!(
                    "the gateway's artifact store does not see {name} — is its NOO_ARTIFACT_GGUF_DIR mount the same directory as this store?"
                ));
            }
            json!({"state": "missing"})
        }
        ManifestWarm::Failed(e) => {
            if !g.json {
                ui::warned(&format!("could not pre-warm the gateway digest ({e}) — sync-model-files will hash it on first use"));
            }
            json!({"state": "failed", "error": e})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_repo_file_and_flags() {
        let a = parse_args(&s(&["unsloth/gemma-4-GGUF", "gemma-Q4_K_M.gguf"])).unwrap();
        assert_eq!(a.repo, "unsloth/gemma-4-GGUF");
        assert_eq!(a.revision, "main");
        assert!(!a.force);
        let a = parse_args(&s(&["o/n", "sub/dir/m.GGUF", "--revision", "v2", "--force"])).unwrap();
        assert_eq!(a.revision, "v2");
        assert!(a.force);
        assert_eq!(a.store_name(), "m.GGUF");
    }

    #[test]
    fn rejects_bad_arguments() {
        for bad in [
            vec!["onlyrepo"],
            vec!["o/n", "m.gguf", "extra"],
            vec!["noslash", "m.gguf"],
            vec!["o/n/x", "m.gguf"],
            vec!["o/..", "m.gguf"],
            vec!["o/n", "m.safetensors"],
            vec!["o/n", "../m.gguf"],
            vec!["o/n", "m.gguf", "--revision"],
            vec!["o/n", "m.gguf", "--bogus"],
        ] {
            assert!(parse_args(&s(&bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn store_resolution_matches_sync_model_files() {
        assert_eq!(store_dir_from(Some("/mnt/fleet/models/gguf"), Some("/data")), "/mnt/fleet/models/gguf");
        assert_eq!(store_dir_from(Some(""), Some("/data/noo/")), "/data/noo/models");
        assert_eq!(store_dir_from(None, None), "/var/lib/noo/models");
        assert_eq!(store_dir_from(None, Some("")), "/var/lib/noo/models");
    }

    #[test]
    fn unwritable_remedy_never_chowns() {
        let (msg, guide) = unwritable_guide("/mnt/fleet/models/gguf", "noo", "noo", 0o40755, "rb");
        assert!(msg.contains("/mnt/fleet/models/gguf") && msg.contains("noo:noo") && msg.contains("755"));
        for (cmd, _) in &guide {
            assert!(!cmd.contains("chown"), "remedy suggests chown: {cmd}");
        }
        assert!(guide[0].0.contains("chmod g+ws /mnt/fleet/models/gguf"));
        assert!(guide[1].0.contains("setfacl"));
    }

    #[test]
    fn etag_and_url_helpers() {
        let h = "a".repeat(64);
        assert_eq!(sha_from_etag(&format!("\"{h}\"")), Some(h.clone()));
        assert_eq!(sha_from_etag(&format!("W/\"{}\"", h.to_uppercase())), Some(h));
        assert_eq!(sha_from_etag("\"abc\""), None);
        let a = parse_args(&s(&["o/n", "dir/m q.gguf"])).unwrap();
        assert_eq!(resolve_url("https://hf.co/", &a), "https://hf.co/o/n/resolve/main/dir/m%20q.gguf");
        assert_eq!(join_location("http://h:1/a/b", "/cdn/x"), "http://h:1/cdn/x");
        assert_eq!(join_location("http://h:1/a/b", "https://cdn/x"), "https://cdn/x");
        // The token is only attached when the hop's origin is the HF origin.
        assert_eq!(origin("https://huggingface.co/o/n/resolve/main/m.gguf"), "https://huggingface.co");
        assert_ne!(origin("https://cdn-lfs.hf.co/x?sig=1"), origin("https://huggingface.co/x"));
    }

    // ── A local Hugging Face stand-in ──────────────────────────────────

    #[derive(Default)]
    struct Seen {
        /// (method, path, range header, had authorization)
        reqs: Vec<(String, String, Option<String>, bool)>,
    }

    struct Hf {
        base: String,
        seen: Arc<Mutex<Seen>>,
    }

    /// Serves `/o/n/resolve/main/m.gguf`: HEAD → 302 with x-linked-etag/size,
    /// GET → 302 to `/cdn/m.gguf`, which honours `Range` unless
    /// `ignore_range`. `etag` is what it advertises as the sha256.
    fn serve(content: Vec<u8>, etag: String, ignore_range: bool, max_conns: usize) -> Hf {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Seen::default()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming().take(max_conns) {
                let Ok(mut st) = stream else { continue };
                let mut rd = BufReader::new(st.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut range = None;
                let mut auth = false;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("range:") {
                        range = Some(v.trim().to_string());
                    }
                    if lower.starts_with("authorization:") {
                        auth = true;
                    }
                }
                seen2.lock().unwrap().reqs.push((method.clone(), path.clone(), range.clone(), auth));
                let resp: Vec<u8> = if path == "/o/n/resolve/main/m.gguf" {
                    let hdrs = format!(
                        "HTTP/1.1 302 Found\r\nLocation: /cdn/m.gguf\r\nx-linked-etag: \"{etag}\"\r\nx-linked-size: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        content.len()
                    );
                    hdrs.into_bytes()
                } else if path == "/cdn/m.gguf" {
                    let start = range
                        .as_deref()
                        .filter(|_| !ignore_range)
                        .and_then(|r| r.strip_prefix("bytes="))
                        .and_then(|r| r.trim_end_matches('-').parse::<usize>().ok());
                    match start {
                        Some(s0) if s0 >= content.len() => b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                        Some(s0) => {
                            let body = &content[s0..];
                            let mut r = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {s0}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                content.len() - 1, content.len(), body.len()
                            ).into_bytes();
                            r.extend_from_slice(body);
                            r
                        }
                        None => {
                            let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", content.len()).into_bytes();
                            r.extend_from_slice(&content);
                            r
                        }
                    }
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                };
                if method == "HEAD" {
                    // Headers only.
                    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
                    let _ = st.write_all(&resp[..end]);
                } else {
                    let _ = st.write_all(&resp);
                }
            }
        });
        Hf { base, seen }
    }

    fn content() -> Vec<u8> {
        (0..300_000u32).map(|i| (i % 251) as u8).collect()
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-models-fetch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn args() -> FetchArgs {
        parse_args(&s(&["o/n", "m.gguf"])).unwrap()
    }

    #[test]
    fn fresh_download_verifies_and_installs_0644() {
        use std::os::unix::fs::PermissionsExt;
        let c = content();
        let hf = serve(c.clone(), sha(&c), false, 8);
        let dir = tmpdir("fresh");
        let out = fetch_to_store(&hf.base, Some("hf_secret"), &args(), &dir, &mut |_, _| {}).unwrap();
        assert_eq!(out.resumed_from, 0);
        assert_eq!(std::fs::read(dir.join("m.gguf")).unwrap(), c);
        let mode = std::fs::metadata(dir.join("m.gguf")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert!(!part_path(&dir, "m.gguf").exists());
        // The token went to the HF origin's resolve URL only — the same
        // origin here, so the CDN hop carries it too; the point pinned is
        // that the redirect was followed with the GET.
        let seen = hf.seen.lock().unwrap();
        assert!(seen.reqs.iter().any(|r| r.0 == "HEAD" && r.3));
        assert!(seen.reqs.iter().any(|r| r.0 == "GET" && r.1 == "/cdn/m.gguf"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resumes_a_partial_with_range() {
        let c = content();
        let hf = serve(c.clone(), sha(&c), false, 8);
        let dir = tmpdir("resume");
        std::fs::write(part_path(&dir, "m.gguf"), &c[..100_000]).unwrap();
        let out = fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap();
        assert_eq!(out.resumed_from, 100_000);
        assert_eq!(std::fs::read(dir.join("m.gguf")).unwrap(), c);
        let seen = hf.seen.lock().unwrap();
        assert!(
            seen.reqs.iter().any(|r| r.1 == "/cdn/m.gguf" && r.2.as_deref() == Some("bytes=100000-")),
            "no Range on the CDN hop: {:?}", seen.reqs
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_ignoring_range_restarts_cleanly() {
        let c = content();
        let hf = serve(c.clone(), sha(&c), true, 8);
        let dir = tmpdir("norange");
        std::fs::write(part_path(&dir, "m.gguf"), &c[..50_000]).unwrap();
        fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dir.join("m.gguf")).unwrap(), c, "a 200 must not be appended to the prefix");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn complete_partial_skips_the_transfer() {
        let c = content();
        let hf = serve(c.clone(), sha(&c), false, 8);
        let dir = tmpdir("complete");
        std::fs::write(part_path(&dir, "m.gguf"), &c).unwrap();
        fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap();
        assert!(!hf.seen.lock().unwrap().reqs.iter().any(|r| r.0 == "GET"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn digest_mismatch_installs_nothing_and_drops_the_partial() {
        let c = content();
        let hf = serve(c.clone(), "b".repeat(64), false, 8);
        let dir = tmpdir("mismatch");
        let err = fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap_err();
        assert!(matches!(err, FetchErr::Mismatch { .. }), "{err}");
        assert!(!dir.join("m.gguf").exists());
        assert!(!part_path(&dir, "m.gguf").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_identical_file_is_a_no_op_and_a_different_one_needs_force() {
        let c = content();
        let hf = serve(c.clone(), sha(&c), false, 16);
        let dir = tmpdir("exists");
        std::fs::write(dir.join("m.gguf"), &c).unwrap();
        let out = fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap();
        assert!(out.already_present);

        std::fs::write(dir.join("m.gguf"), b"other").unwrap();
        let err = fetch_to_store(&hf.base, None, &args(), &dir, &mut |_, _| {}).unwrap_err();
        assert!(matches!(err, FetchErr::Conflict { .. }));
        let mut forced = args();
        forced.force = true;
        fetch_to_store(&hf.base, None, &forced, &dir, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dir.join("m.gguf")).unwrap(), c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_not_found() {
        let hf = serve(vec![], "a".repeat(64), false, 4);
        let a = parse_args(&s(&["o/n", "absent.gguf"])).unwrap();
        let err = fetch_to_store(&hf.base, None, &a, &tmpdir("absent"), &mut |_, _| {}).unwrap_err();
        assert!(matches!(err, FetchErr::NotFound), "{err}");
    }
}
