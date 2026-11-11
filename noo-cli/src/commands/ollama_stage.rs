// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo models fetch ollama:<tag>` — stage an ollama registry model in the
//! controller's model store, so a placed node can import it without ever
//! contacting registry.ollama.ai.
//!
//! A placed node refuses `ollama pull` (`ollama_registry_pull_refused`): its
//! models come from the controller's store. The CONTROLLER makes the one
//! registry contact, and mirrors the tag byte for byte:
//!
//! 1. GET `/v2/<ns>/<name>/manifests/<tag>` from `registry.ollama.ai`
//!    (`NOO_OLLAMA_REGISTRY` overrides, for a mirror). The body is kept as the
//!    registry sent it and parsed only to be validated.
//! 2. The config blob and every layer are downloaded and checked against the
//!    `sha256:` digest and the size the manifest carries. A mismatch installs
//!    nothing further.
//! 3. Into the store (`MODELS_DIR`, the directory nginx serves as `/gguf/`):
//!    `sha256-<hex>.ollama-blob`                one per unique digest, the
//!                                              blob verbatim (shared by tags);
//!    `ollama+<ns>+<name>+<tag>.ollama-manifest` the manifest bytes verbatim,
//!                                              written LAST, so a node that
//!                                              sees it finds every blob.
//!    The manifest is never re-serialized: ollama's digest of a model is the
//!    sha256 of those exact bytes, and the node checks it. The stem is
//!    `OllamaStoreStem` in node-agent-go/internal/docker/ollama_stage.go (same
//!    vectors in both; tests/test_ollama_stage_parity.py).
//! 4. The gateway serves the two kinds as the `ollamablob` and
//!    `ollamamanifest` artifact kinds; the node pushes the blobs into its
//!    ollama through ollama's own API and writes the manifest last.
//!
//! Nothing is rebuilt, so no layer type is refused: a vision projector, an
//! adapter or a type that does not exist yet stages like any other. The
//! limits below are the ones the node applies (node-agent-go/internal/docker/
//! ollama_mirror.go); a manifest outside them is refused here, before any
//! blob is requested. The GGUF + Modelfile rebuild remains only for operator
//! GGUFs (`noo models fetch <hf_repo> <file.gguf>`), and nodes still import a
//! tag staged the OLD way (a `<stem>.Modelfile` + `<stem>.gguf` pair).
//!
//! Failure semantics: registry unreachable or any non-200 is an error and the
//! store is untouched; a digest or size mismatch deletes the partial file; a
//! store manifest that differs is a conflict unless `--force`; an interrupted
//! blob download resumes (HTTP Range) on re-run.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::models_fetch::{agent, download_part, get_following, human, io, sha256_file, writable_store, FetchErr, PartEvent, Retry, RESUME_DELAYS};
use crate::args::{ArgError, Args};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// Limits and store suffixes shared with the node (ollama_mirror.go); the
/// parity test pins that the two sides carry the same values.
pub(crate) const MIRROR_MAX_LAYERS: usize = 64;
pub(crate) const MIRROR_MAX_MANIFEST_BYTES: u64 = 1 << 20;
pub(crate) const MIRROR_MAX_BLOB_BYTES: u64 = 1 << 40;
pub(crate) const MIRROR_BLOB_SUFFIX: &str = ".ollama-blob";
pub(crate) const MIRROR_MANIFEST_SUFFIX: &str = ".ollama-manifest";
/// A blob's store name is this prefix + its hex digest + the suffix.
const MIRROR_BLOB_PREFIX: &str = "sha256-";
/// The layer a manifest must carry to be a model at all.
const MODEL_MEDIA: &str = "application/vnd.ollama.image.model";

// ── The reference ───────────────────────────────────────────────────────

/// `[namespace/]name[:tag]` on registry.ollama.ai, case kept (the registry
/// URL uses what the operator typed); the store NAME is case-folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OllamaRef {
    pub ns: String,
    pub name: String,
    pub tag: String,
}

fn seg_ok(s: &str, allow_dot: bool) -> bool {
    let mut it = s.chars();
    it.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || (allow_dot && c == '.'))
}

/// Parse a registry reference. `library/` and `:latest` are implied; a ref
/// with a host (`hf.co/org/repo`, whose first segment has a dot) or more than
/// two path segments is not on this registry and is refused.
pub(crate) fn parse_ref(input: &str) -> Result<OllamaRef, String> {
    let bad = || format!("'{input}' is not a registry.ollama.ai reference (want [namespace/]name[:tag])");
    let mut r = input.trim();
    if r.to_ascii_lowercase().starts_with("registry.ollama.ai/") {
        r = &r["registry.ollama.ai/".len()..];
    }
    if r.is_empty() {
        return Err(bad());
    }
    let (path, tag) = match r.rfind(':') {
        Some(i) if !r[i..].contains('/') => (&r[..i], &r[i + 1..]),
        _ => (r, "latest"),
    };
    let parts: Vec<&str> = path.split('/').collect();
    let (ns, name) = match parts.as_slice() {
        [n] => ("library", *n),
        [ns, n] => (*ns, *n),
        _ => return Err(bad()),
    };
    // A namespace has no '.': that is what tells `user/model` from a host.
    if !seg_ok(ns, false) || !seg_ok(name, true) || !seg_ok(tag, true) {
        return Err(bad());
    }
    Ok(OllamaRef { ns: ns.to_string(), name: name.to_string(), tag: tag.to_string() })
}

impl OllamaRef {
    /// The name both store files share (no extension): the same string as
    /// `OllamaStoreStem` on the node.
    pub fn stem(&self) -> String {
        format!("ollama+{}+{}+{}", self.ns, self.name, self.tag).to_ascii_lowercase()
    }
    /// `ns/name:tag`, as the registry names it.
    pub fn display(&self) -> String {
        format!("{}/{}:{}", self.ns, self.name, self.tag)
    }
    /// What the operator places: `library/` dropped.
    pub fn short(&self) -> String {
        if self.ns == "library" { format!("{}:{}", self.name, self.tag) } else { self.display() }
    }
}

/// `ollama:<ref> [--force]`.
pub(crate) fn parse_stage_args(args: &[String]) -> Result<(OllamaRef, bool), ArgError> {
    let mut a = Args::new(args);
    let force = a.flag(&["--force"]);
    let mut reference: Option<OllamaRef> = None;
    for s in a.positionals()? {
        let Some(rest) = s.strip_prefix("ollama:") else {
            return Err(ArgError::new(format!("'{s}': an ollama model is given as ollama:<tag> (e.g. ollama:gemma4:12b)")));
        };
        if reference.is_some() {
            return Err(ArgError::new("expected exactly one ollama:<tag> argument"));
        }
        reference = Some(parse_ref(rest)?);
    }
    reference.map(|r| (r, force)).ok_or_else(|| ArgError::new("expected ollama:<tag>"))
}

// ── The registry ────────────────────────────────────────────────────────

/// `NOO_OLLAMA_REGISTRY`, else registry.ollama.ai.
pub(crate) fn registry_base() -> String {
    let b = std::env::var("NOO_OLLAMA_REGISTRY").unwrap_or_default();
    let b = b.trim().trim_end_matches('/');
    if b.is_empty() { "https://registry.ollama.ai".into() } else { b.to_string() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layer {
    pub media: String,
    /// Hex, without the `sha256:` prefix.
    pub sha256: String,
    pub size: u64,
}

/// `[A-Za-z0-9.+/_-]`, 1..=128 chars: what the node accepts as a media type.
fn media_ok(m: &str) -> bool {
    (1..=128).contains(&m.len()) && m.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'/' | b'_' | b'-'))
}

fn layer_of(v: &Value, what: &str) -> Result<Layer, String> {
    let media = v["mediaType"].as_str().ok_or_else(|| format!("{what} has no mediaType"))?.to_string();
    if !media_ok(&media) {
        return Err(format!("{what} has a mediaType that is not 1-128 characters of [A-Za-z0-9.+/_-]"));
    }
    let digest = v["digest"].as_str().ok_or_else(|| format!("{what} has no digest"))?;
    let sha256 = digest
        .strip_prefix("sha256:")
        // Lowercase only, as the node requires: the manifest is stored as the
        // registry sent it, so an uppercase digest could never be imported.
        .filter(|h| h.len() == 64)
        .ok_or_else(|| format!("{what} digest '{digest}' is not sha256:<64 lowercase hex>"))?
        .to_string();
    let size = v["size"].as_u64().ok_or_else(|| format!("{what} has no size"))?;
    if size == 0 || size > MIRROR_MAX_BLOB_BYTES {
        return Err(format!("{what} has size {size}, want 1..={MIRROR_MAX_BLOB_BYTES}"));
    }
    Ok(Layer { media, sha256, size })
}

/// A validated manifest: what is to be mirrored.
#[derive(Debug)]
pub(crate) struct MirrorPlan {
    pub config: Layer,
    pub layers: Vec<Layer>,
}

/// Validate a manifest's bytes with the rules the node applies. Unknown layer
/// types are accepted on purpose; a manifest with no model layer is not a model.
pub(crate) fn check_manifest(raw: &[u8]) -> Result<MirrorPlan, String> {
    if raw.len() as u64 > MIRROR_MAX_MANIFEST_BYTES {
        return Err(format!("the manifest is over {MIRROR_MAX_MANIFEST_BYTES} bytes"));
    }
    let m: Value = serde_json::from_slice(raw).map_err(|e| format!("the manifest is not JSON: {e}"))?;
    if m["schemaVersion"].as_u64() != Some(2) {
        return Err(format!("the manifest's schemaVersion is {}, want 2", m["schemaVersion"]));
    }
    if !m["config"].is_object() {
        return Err("the manifest has no config object".into());
    }
    let config = layer_of(&m["config"], "the manifest's config")?;
    let arr = m["layers"].as_array().ok_or("the manifest has no layers")?;
    if arr.is_empty() {
        return Err("the manifest has no layers".into());
    }
    if arr.len() > MIRROR_MAX_LAYERS {
        return Err(format!("the manifest has {} layers, at most {MIRROR_MAX_LAYERS} are accepted", arr.len()));
    }
    let mut layers = Vec::with_capacity(arr.len());
    for (i, l) in arr.iter().enumerate() {
        layers.push(layer_of(l, &format!("layer {i}"))?);
    }
    // The sum counts each digest once (a blob listed twice is one blob, and
    // must say the same size both times). Each size is <= 2^40 and there are
    // at most 65: no overflow.
    let mut seen: Vec<&Layer> = Vec::new();
    for l in std::iter::once(&config).chain(layers.iter()) {
        let earlier = seen.iter().find(|s| s.sha256 == l.sha256).map(|s| s.size);
        match earlier {
            Some(size) if size != l.size => {
                return Err(format!("blob sha256:{} is listed with two sizes ({} and {})", &l.sha256[..12], size, l.size));
            }
            Some(_) => {}
            None => seen.push(l),
        }
    }
    let sum: u64 = seen.iter().map(|l| l.size).sum();
    if sum > MIRROR_MAX_BLOB_BYTES {
        return Err(format!("the manifest's blobs add up to {sum} bytes, over the {MIRROR_MAX_BLOB_BYTES} limit"));
    }
    if !layers.iter().any(|l| l.media == MODEL_MEDIA) {
        return Err("the manifest has no model layer — not a model".into());
    }
    Ok(MirrorPlan { config, layers })
}

fn manifest_url(base: &str, r: &OllamaRef) -> String {
    format!("{base}/v2/{}/{}/manifests/{}", r.ns, r.name, r.tag)
}

fn blob_url(base: &str, r: &OllamaRef, sha256: &str) -> String {
    format!("{base}/v2/{}/{}/blobs/sha256:{sha256}", r.ns, r.name)
}

/// The manifest's raw bytes, exactly as the registry sent them.
fn get_manifest(base: &str, r: &OllamaRef) -> Result<Vec<u8>, String> {
    let url = manifest_url(base, r);
    let mut resp = agent()
        .get(&url)
        .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
        .call()
        .map_err(|e| format!("registry unreachable ({url}): {e}"))?;
    let st = resp.status().as_u16();
    match st {
        200 => {}
        404 => return Err(format!("the registry has no {} — check the name and tag at https://ollama.com/library/{}", r.display(), r.name)),
        _ => return Err(format!("the registry answered HTTP {st} for {url}")),
    }
    let mut body = Vec::new();
    resp.body_mut()
        .with_config()
        .limit(MIRROR_MAX_MANIFEST_BYTES + 1)
        .reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("reading the manifest (limit {MIRROR_MAX_MANIFEST_BYTES} bytes): {e}"))?;
    if body.len() as u64 > MIRROR_MAX_MANIFEST_BYTES {
        return Err(format!("the manifest is over {MIRROR_MAX_MANIFEST_BYTES} bytes"));
    }
    Ok(body)
}

// ── The store ───────────────────────────────────────────────────────────

fn blob_name(sha256: &str) -> String {
    format!("{MIRROR_BLOB_PREFIX}{sha256}{MIRROR_BLOB_SUFFIX}")
}

#[derive(Debug)]
pub(crate) struct BlobInfo {
    /// Hex, without the `sha256:` prefix.
    pub sha256: String,
    pub media: String,
    pub size: u64,
    /// The store already held this exact blob; it was not transferred.
    pub present: bool,
}

#[derive(Debug)]
pub(crate) struct StageOutcome {
    pub stem: String,
    pub manifest: PathBuf,
    pub manifest_sha256: String,
    /// One per unique digest: the config blob first, then the layers in order.
    pub blobs: Vec<BlobInfo>,
    /// The layers' media types in manifest order (the config is not one).
    pub layer_media: Vec<String>,
    /// Sum of the unique blobs' sizes.
    pub size_bytes: u64,
    /// Bytes of those that were not already in the store.
    pub downloaded: u64,
    /// Bytes resumed from a partial download, across blobs.
    pub resumed_from: u64,
}

/// Bring one blob into `<dir>/sha256-<hex>.ollama-blob`: left alone when it
/// is already there with the right digest and size, otherwise downloaded into
/// `<dir>/.<name>.part` (resuming), verified, and renamed into place 0644.
/// `span` is (bytes of the model finished before this blob, model total), so
/// progress covers the whole model. Returns (bytes resumed, already present).
fn install_blob(
    base: &str,
    r: &OllamaRef,
    layer: &Layer,
    dir: &Path,
    span: (u64, u64),
    progress: &mut dyn FnMut(u64, Option<u64>),
    on_retry: &mut dyn FnMut(Retry),
) -> Result<(u64, bool), FetchErr> {
    use std::os::unix::fs::PermissionsExt;
    let (done_before, total) = span;
    let name = blob_name(&layer.sha256);
    let dest = dir.join(&name);
    if dest.exists() {
        let have = sha256_file(&dest).map_err(|e| io(&format!("reading {}", dest.display()), e))?;
        let len = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        if have == layer.sha256 && len == layer.size {
            progress(done_before + layer.size, Some(total));
            return Ok((0, true));
        }
        // The file's NAME is its digest, so one that does not hash to it is
        // corrupt, never a conflicting choice: replace it without --force.
        std::fs::remove_file(&dest).map_err(|e| io(&format!("removing the corrupt {}", dest.display()), e))?;
    }
    let part = dir.join(format!(".{name}.part"));
    let mut have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    if have > layer.size {
        std::fs::remove_file(&part).map_err(|e| io("removing an oversized partial", e))?;
        have = 0;
    }
    let resumed_from = have;
    let url = blob_url(base, r, &layer.sha256);
    download_part(&mut |from| get_following(base, &url, None, from), &part, Some(layer.size), &RESUME_DELAYS, &mut |e| match e {
        PartEvent::Bytes(done) => progress(done_before + done, Some(total)),
        PartEvent::Retry(rt) => on_retry(rt),
    })?;
    let size = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let got = sha256_file(&part).map_err(|e| io(&format!("hashing {}", part.display()), e))?;
    if size != layer.size || got != layer.sha256 {
        let _ = std::fs::remove_file(&part);
        return Err(FetchErr::Mismatch { expected: layer.sha256.clone(), got });
    }
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644)).map_err(|e| io("setting mode 0644", e))?;
    std::fs::rename(&part, &dest).map_err(|e| io(&format!("renaming into {}", dest.display()), e))?;
    Ok((resumed_from, false))
}

/// Write `body` to `<dir>/<name>` through a temp file, 0644.
fn install_bytes(dir: &Path, name: &str, body: &[u8]) -> Result<PathBuf, FetchErr> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, body).map_err(|e| io(&format!("writing {}", tmp.display()), e))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(|e| io("setting mode 0644", e))?;
    let dest = dir.join(name);
    std::fs::rename(&tmp, &dest).map_err(|e| io(&format!("renaming into {}", dest.display()), e))?;
    Ok(dest)
}

#[derive(Debug)]
pub(crate) enum StageErr {
    /// Anything about the registry or the manifest: nothing was installed.
    Registry(String),
    Fetch(FetchErr),
}

impl std::fmt::Display for StageErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageErr::Registry(e) => write!(f, "{e}"),
            StageErr::Fetch(e) => write!(f, "{e}"),
        }
    }
}

impl From<FetchErr> for StageErr {
    fn from(e: FetchErr) -> Self {
        StageErr::Fetch(e)
    }
}

/// Mirror `r` from the registry at `base` into `dir`. The manifest is fetched
/// and validated, and checked against the store, BEFORE any blob is requested,
/// so a model that cannot be staged is refused without a multi-GB download;
/// the manifest is written after every blob, so its presence means a complete
/// model.
pub(crate) fn stage(
    base: &str,
    r: &OllamaRef,
    dir: &Path,
    force: bool,
    progress: &mut dyn FnMut(u64, Option<u64>),
    on_retry: &mut dyn FnMut(Retry),
) -> Result<StageOutcome, StageErr> {
    let raw = get_manifest(base, r).map_err(StageErr::Registry)?;
    let plan = check_manifest(&raw).map_err(StageErr::Registry)?;
    let stem = r.stem();
    let manifest_name = format!("{stem}{MIRROR_MANIFEST_SUFFIX}");
    let manifest_path = dir.join(&manifest_name);
    let manifest_sha256 = hex::encode(Sha256::digest(&raw));
    // A different manifest under this tag's name is the operator's to replace.
    // The same bytes are fine: a re-run re-verifies the blobs.
    if manifest_path.is_file() {
        let old = std::fs::read(&manifest_path).map_err(|e| io(&format!("reading {}", manifest_path.display()), e))?;
        if old != raw && !force {
            return Err(StageErr::Fetch(FetchErr::Conflict { existing: hex::encode(Sha256::digest(&old)), expected: manifest_sha256 }));
        }
    }
    // Config first, then the layers; a digest listed twice is fetched once.
    let mut want: Vec<&Layer> = Vec::new();
    for l in std::iter::once(&plan.config).chain(plan.layers.iter()) {
        if !want.iter().any(|w| w.sha256 == l.sha256) {
            want.push(l);
        }
    }
    let total: u64 = want.iter().map(|l| l.size).sum();
    let mut blobs = Vec::with_capacity(want.len());
    let (mut done, mut downloaded, mut resumed_total) = (0u64, 0u64, 0u64);
    for l in want {
        let (resumed, present) = install_blob(base, r, l, dir, (done, total), progress, on_retry)?;
        done += l.size;
        resumed_total += resumed;
        if !present {
            downloaded += l.size;
        }
        blobs.push(BlobInfo { sha256: l.sha256.clone(), media: l.media.clone(), size: l.size, present });
    }
    // Last, so a node that sees the manifest finds every blob complete.
    let manifest = install_bytes(dir, &manifest_name, &raw)?;
    Ok(StageOutcome {
        stem,
        manifest,
        manifest_sha256,
        blobs,
        layer_media: plan.layers.iter().map(|l| l.media.clone()).collect(),
        size_bytes: total,
        downloaded,
        resumed_from: resumed_total,
    })
}

// ── The command ─────────────────────────────────────────────────────────

/// `application/vnd.ollama.image.projector` -> `projector`.
fn short_media(m: &str) -> &str {
    m.strip_prefix("application/vnd.ollama.image.").unwrap_or(m)
}

/// `noo models fetch ollama:<tag> [--force]`.
pub fn models_fetch_ollama(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (r, force) = match parse_stage_args(args) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Usage, "bad_args", &e.to_string(), Some("give the model as ollama:<tag>, e.g. ollama:gemma4:12b")),
    };
    let (store, dir) = writable_store(g, "noo models fetch ollama:<tag>");
    let base = registry_base();
    if !g.json {
        println!("{}", ui::header("models fetch", Some(&format!("ollama:{} → {store}", r.short()))));
        print!("{}", ui::kv(&[
            ("registry", base.clone()),
            // The blob count is the manifest's, known only after it is fetched.
            ("store names", format!("{}{MIRROR_MANIFEST_SUFFIX} + one {MIRROR_BLOB_PREFIX}<digest>{MIRROR_BLOB_SUFFIX} per blob", r.stem())),
        ]));
    }
    let json = g.json;
    let mut last_pct: i64 = -1;
    let mut progress = |done: u64, total: Option<u64>| {
        if json {
            return;
        }
        if let Some(t) = total.filter(|t| *t > 0) {
            let pct = (done * 100 / t) as i64;
            if pct / 5 != last_pct / 5 {
                last_pct = pct;
                eprintln!("  {pct:>3}%  {} / {}", human(done), human(t));
            }
        }
    };
    let mut on_retry = |rt: Retry| {
        if !json {
            // On a fresh line: the % lines above are whole lines already.
            eprintln!(
                "  connection dropped at {} — resuming in {}s (attempt {} of {})",
                human(rt.at),
                rt.wait.as_secs(),
                rt.attempt,
                rt.of
            );
        }
    };
    let out = match stage(&base, &r, &dir, force, &mut progress, &mut on_retry) {
        Ok(o) => o,
        Err(e) => {
            let hint = match &e {
                StageErr::Fetch(FetchErr::Io(_) | FetchErr::Http(_) | FetchErr::Dropped(_)) => Some("re-run the same command: the blob download resumes"),
                StageErr::Fetch(FetchErr::Conflict { .. }) => Some("re-run with --force to replace the store's manifest"),
                _ => None,
            };
            fail(g.json, ExitCode::RemoteError, "stage_failed", &e.to_string(), hint);
        }
    };
    let place = format!("noo cluster place <node> ollama {}", r.short());
    if g.json {
        let blobs: Vec<Value> = out
            .blobs
            .iter()
            .map(|b| json!({"digest": format!("sha256:{}", b.sha256), "media_type": b.media, "size": b.size, "present": b.present}))
            .collect();
        println!("{}", json!({
            "ref": r.display(),
            "stem": out.stem,
            "manifest": out.manifest.display().to_string(),
            "manifest_sha256": out.manifest_sha256,
            "blobs": blobs,
            "size_bytes": out.size_bytes,
            "downloaded_bytes": out.downloaded,
            "resumed_from": out.resumed_from,
            "next": [place],
        }));
        return Ok(0);
    }
    let kinds: Vec<&str> = out.layer_media.iter().map(|m| short_media(m.as_str())).collect();
    let present = out.blobs.iter().filter(|b| b.present).count();
    let resumed = if out.resumed_from > 0 { format!(", resumed from {}", human(out.resumed_from)) } else { String::new() };
    ui::done(&format!(
        "{} — {} blobs, {} ({} downloaded, {} already in the store{resumed}); {} layers: {}; manifest sha256 {}… verified against the registry",
        out.manifest.display(),
        out.blobs.len(),
        human(out.size_bytes),
        human(out.downloaded),
        present,
        kinds.len(),
        kinds.join(", "),
        &out.manifest_sha256[..16]
    ));
    ui::guide(&[(
        place.as_str(),
        "a placed node imports it from this store (digest-verified) and never contacts registry.ollama.ai",
    )]);
    Ok(0)
}


/// What `noo cluster import-model <node> <name>` was asked to import, resolved
/// against the controller's store.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ImportTarget {
    /// A converted or hand-made model: `<name>.Modelfile` (+ its weight).
    Plain(String),
    /// A registry tag `noo models fetch ollama:<tag>` staged. Holds the name
    /// the node is sent and placed under (`ref.short()`).
    Staged(OllamaRef),
}

/// Has the mirror of `r` been staged (`noo models fetch ollama:<tag>`)? The
/// manifest is written last, so its presence means every blob is in.
pub(crate) fn mirror_staged(store: &Path, r: &OllamaRef) -> bool {
    store.join(format!("{}{MIRROR_MANIFEST_SUFFIX}", r.stem())).is_file()
}

/// Staged either way: the mirror, or the OLD `<stem>.Modelfile` + `<stem>.gguf`
/// pair, which nodes still import.
fn staged_present(store: &Path, r: &OllamaRef) -> bool {
    let stem = r.stem();
    mirror_staged(store, r) || (store.join(format!("{stem}.Modelfile")).is_file() && store.join(format!("{stem}.gguf")).is_file())
}

/// Resolve the import-model argument. `ollama:<tag>` names a staged tag and
/// nothing else; a bare name is the plain store model, or, when no such model
/// exists, the staged tag of that name. A name that is BOTH is ambiguous and
/// refused (the node would import the plain one; the operator may mean the
/// other). A tag that is not staged is refused naming the command that stages
/// it: never a silent fall-through to a registry pull.
pub(crate) fn resolve_import_target(arg: &str, store: &Path) -> Result<ImportTarget, String> {
    let arg = arg.trim();
    let restage = |r: &OllamaRef| {
        format!(
            "{} is not staged in the controller store ({}): no {}{MIRROR_MANIFEST_SUFFIX} (and no old {}.Modelfile + {}.gguf pair). Stage it with `noo models fetch ollama:{}`, then re-run",
            r.short(), store.display(), r.stem(), r.stem(), r.stem(), r.short()
        )
    };
    if let Some(rest) = arg.strip_prefix("ollama:") {
        let r = parse_ref(rest)?;
        return if staged_present(store, &r) { Ok(ImportTarget::Staged(r)) } else { Err(restage(&r)) };
    }
    let single_component = !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    let plain = single_component && store.join(format!("{arg}.Modelfile")).is_file();
    let staged = parse_ref(arg).ok().filter(|r| staged_present(store, r));
    match (plain, staged) {
        (true, Some(r)) => Err(format!(
            "'{arg}' is both a plain model ({arg}.Modelfile) and a staged registry tag ({}). Say which: `ollama:{}` for the registry tag",
            r.stem(), r.short()
        )),
        (true, None) => Ok(ImportTarget::Plain(arg.to_string())),
        (false, Some(r)) => Ok(ImportTarget::Staged(r)),
        (false, None) => match parse_ref(arg) {
            // A name with a ':' (or a namespace) can only be a registry tag.
            Ok(r) if arg.contains(':') || arg.contains('/') => Err(restage(&r)),
            // A bare name may still be an OCI-artifact model the caller stages.
            _ if single_component => Ok(ImportTarget::Plain(arg.to_string())),
            _ => Err(format!("'{arg}' is neither a store model name nor a registry.ollama.ai reference (want ollama:<tag>)")),
        },
    }
}

/// Is `name` (a file in the store) one this command staged? The default
/// `sync-model-files` sweep leaves these out: they ride a placement, not a
/// push to every node. That is the `ollama+` stems, and the mirror's blobs
/// (`sha256-<hex>.ollama-blob`) and manifests.
pub(crate) fn is_staged_name(name: &str) -> bool {
    name.starts_with("ollama+") || name.ends_with(MIRROR_BLOB_SUFFIX) || name.ends_with(MIRROR_MANIFEST_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// The vectors node-agent-go/internal/docker/ollama_stage_test.go carries.
    const STEM_VECTORS: &[(&str, &str)] = &[
        ("gemma4:12b", "ollama+library+gemma4+12b"),
        ("gemma4", "ollama+library+gemma4+latest"),
        ("gemma4:latest", "ollama+library+gemma4+latest"),
        ("llama3.2:1b", "ollama+library+llama3.2+1b"),
        ("Library/Gemma4:12B", "ollama+library+gemma4+12b"),
        ("user/my-model:q4_K_M", "ollama+user+my-model+q4_k_m"),
        ("registry.ollama.ai/library/gemma4:12b", "ollama+library+gemma4+12b"),
    ];

    #[test]
    fn the_store_names_are_the_nodes_names() {
        for (input, stem) in STEM_VECTORS {
            assert_eq!(&parse_ref(input).unwrap().stem(), stem, "{input}");
        }
    }

    #[test]
    fn a_ref_not_on_the_registry_is_refused() {
        for bad in ["", ":x", "x:", "hf.co/org/repo:Q4", "a/b/c", "../x", "x y", "host.example/model", "a:b:c", "x/", "/x"] {
            assert!(parse_ref(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn stage_args_need_one_ollama_ref() {
        let (r, force) = parse_stage_args(&s(&["ollama:gemma4:12b", "--force"])).unwrap();
        assert_eq!((r.short(), force), ("gemma4:12b".to_string(), true));
        for bad in [vec![], vec!["gemma4:12b"], vec!["ollama:a", "ollama:b"], vec!["ollama:a", "--revision"], vec!["ollama:hf.co/o/r"]] {
            assert!(parse_stage_args(&s(&bad)).is_err(), "accepted {bad:?}");
        }
    }

    fn digest(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn layer_json(media: &str, b: &[u8]) -> Value {
        json!({"mediaType": media, "digest": format!("sha256:{}", digest(b)), "size": b.len()})
    }

    #[test]
    fn staged_names_stay_out_of_the_default_sweep() {
        assert!(is_staged_name("ollama+library+gemma4+12b.gguf"));
        assert!(is_staged_name("ollama+library+gemma4+12b.ollama-manifest"));
        assert!(is_staged_name(&blob_name(&"a".repeat(64))));
        assert!(is_staged_name("sha256-abc.ollama-blob"));
        assert!(!is_staged_name("gemma-4-E2B-it-Q4_K_M.gguf"));
    }

    // ── A registry stand-in ─────────────────────────────────────────────

    struct Registry {
        base: String,
        hits: Arc<Mutex<Vec<String>>>,
    }

    impl Registry {
        /// Did any request touch the blob with this hex digest (either hop)?
        fn hit_blob(&self, hex: &str) -> bool {
            self.hits.lock().unwrap().iter().any(|h| h.ends_with(hex))
        }
        fn blob_hits(&self) -> usize {
            self.hits.lock().unwrap().iter().filter(|h| h.contains("/blobs/") || h.starts_with("/cdn/")).count()
        }
    }

    fn serve(manifest: Value, blobs: HashMap<String, Vec<u8>>, lie: Option<String>, max_conns: usize) -> Registry {
        serve_raw(manifest.to_string().into_bytes(), blobs, lie, max_conns)
    }

    /// Serves `manifest` (the exact bytes) at /v2/library/gemma4/manifests/12b
    /// and blobs at /v2/library/gemma4/blobs/sha256:<hex> (a 307 to
    /// /cdn/<hex> that honours Range, like the real registry's CDN hop). `lie`
    /// serves wrong bytes for that blob.
    fn serve_raw(manifest: Vec<u8>, blobs: HashMap<String, Vec<u8>>, lie: Option<String>, max_conns: usize) -> Registry {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits2 = hits.clone();
        std::thread::spawn(move || {
            for stream in l.incoming().take(max_conns) {
                let Ok(mut st) = stream else { continue };
                let mut rd = BufReader::new(st.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut range = None;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("range:") {
                        range = Some(v.trim().to_string());
                    }
                }
                hits2.lock().unwrap().push(path.clone());
                let resp: Vec<u8> = if path == "/v2/library/gemma4/manifests/12b" {
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", manifest.len()).into_bytes();
                    r.extend_from_slice(&manifest);
                    r
                } else if let Some(hex) = path.strip_prefix("/v2/library/gemma4/blobs/sha256:") {
                    format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: /cdn/{hex}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
                } else if let Some(hex) = path.strip_prefix("/cdn/") {
                    match blobs.get(hex) {
                        Some(content) => {
                            let content = if lie.as_deref() == Some(hex) { vec![b'X'; content.len()] } else { content.clone() };
                            let start = range
                                .as_deref()
                                .and_then(|r| r.strip_prefix("bytes="))
                                .and_then(|r| r.trim_end_matches('-').parse::<usize>().ok());
                            match start {
                                Some(s0) if s0 < content.len() => {
                                    let body = &content[s0..];
                                    let mut r = format!(
                                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {s0}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        content.len() - 1, content.len(), body.len()
                                    ).into_bytes();
                                    r.extend_from_slice(body);
                                    r
                                }
                                _ => {
                                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", content.len()).into_bytes();
                                    r.extend_from_slice(&content);
                                    r
                                }
                            }
                        }
                        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    }
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                };
                let _ = st.write_all(&resp);
            }
        });
        Registry { base, hits }
    }

    fn weight() -> Vec<u8> {
        let mut w = b"GGUF".to_vec();
        w.extend((0..200_000u32).map(|i| (i % 251) as u8));
        w
    }

    /// A text-only model: weight, template, params, config.
    fn model_fixture(w: &[u8]) -> (Value, HashMap<String, Vec<u8>>) {
        let tmpl = b"{{ .Prompt }}".to_vec();
        let params = br#"{"stop":["<end_of_turn>"],"temperature":0.7}"#.to_vec();
        let cfg = br#"{"model_format":"gguf"}"#.to_vec();
        let manifest = json!({
            "schemaVersion": 2,
            "config": layer_json("application/vnd.docker.container.image.v1+json", &cfg),
            "layers": [
                layer_json(MODEL_MEDIA, w),
                layer_json("application/vnd.ollama.image.template", &tmpl),
                layer_json("application/vnd.ollama.image.params", &params),
            ]
        });
        let mut blobs = HashMap::new();
        for b in [w.to_vec(), tmpl, params, cfg] {
            blobs.insert(digest(&b), b);
        }
        (manifest, blobs)
    }

    /// Add a layer of `media` with content `b` to a fixture.
    fn with_layer(mut fx: (Value, HashMap<String, Vec<u8>>), media: &str, b: &[u8]) -> (Value, HashMap<String, Vec<u8>>) {
        fx.0["layers"].as_array_mut().unwrap().push(layer_json(media, b));
        fx.1.insert(digest(b), b.to_vec());
        fx
    }

    /// The registry's bytes, deliberately not the compact form serde writes.
    fn pretty(manifest: &Value) -> Vec<u8> {
        let mut b = serde_json::to_vec_pretty(manifest).unwrap();
        b.extend_from_slice(b"\n");
        b
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-ollama-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    const MANIFEST: &str = "ollama+library+gemma4+12b.ollama-manifest";

    fn run(reg: &Registry, dir: &Path, force: bool) -> Result<StageOutcome, StageErr> {
        let r = parse_ref("gemma4:12b").unwrap();
        stage(&reg.base, &r, dir, force, &mut |_, _| {}, &mut |_| {})
    }

    #[test]
    fn a_projector_model_stages_every_blob_and_the_manifest_verbatim() {
        use std::os::unix::fs::PermissionsExt;
        let w = weight();
        let proj = b"GGUFprojector-bytes".to_vec();
        let (manifest, blobs) = with_layer(model_fixture(&w), "application/vnd.ollama.image.projector", &proj);
        let raw = pretty(&manifest);
        let reg = serve_raw(raw.clone(), blobs.clone(), None, 64);
        let dir = tmpdir("ok");
        let out = run(&reg, &dir, false).unwrap();
        for (hex, content) in &blobs {
            let p = dir.join(format!("sha256-{hex}.ollama-blob"));
            assert_eq!(&std::fs::read(&p).unwrap(), content, "{hex}");
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        }
        // Whitespace and key order included: ollama digests these exact bytes.
        assert_eq!(std::fs::read(dir.join(MANIFEST)).unwrap(), raw);
        assert_eq!(std::fs::metadata(dir.join(MANIFEST)).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(names(&dir).len(), blobs.len() + 1, "{:?}", names(&dir));
        assert_eq!(out.manifest_sha256, digest(&raw));
        assert_eq!(out.blobs.len(), blobs.len());
        assert_eq!(out.blobs[0].media, "application/vnd.docker.container.image.v1+json", "the config comes first");
        assert!(out.layer_media.iter().any(|m| m == "application/vnd.ollama.image.projector"));
        assert_eq!(out.downloaded, out.size_bytes);
        // A second run transfers no blob.
        let before = reg.blob_hits();
        let again = run(&reg, &dir, false).unwrap();
        assert_eq!(reg.blob_hits(), before);
        assert!(again.blobs.iter().all(|b| b.present) && again.downloaded == 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_layer_type_nobody_has_heard_of_stages() {
        let w = weight();
        let (manifest, blobs) = with_layer(model_fixture(&w), "application/vnd.ollama.image.futurething+v9", b"whatever");
        let reg = serve(manifest, blobs, None, 64);
        let dir = tmpdir("future");
        run(&reg, &dir, false).unwrap();
        assert!(dir.join(MANIFEST).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blob_that_does_not_match_its_digest_installs_no_manifest() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let tmpl_hex = digest(b"{{ .Prompt }}");
        let reg = serve(manifest, blobs, Some(tmpl_hex), 64);
        let dir = tmpdir("lie");
        let e = run(&reg, &dir, false).unwrap_err();
        assert!(matches!(e, StageErr::Fetch(FetchErr::Mismatch { .. })), "{e}");
        let left = names(&dir);
        assert!(!left.iter().any(|n| n == MANIFEST || n.ends_with(".part") || n.ends_with(".tmp")), "left behind: {left:?}");
        assert!(!dir.join(blob_name(&digest(b"{{ .Prompt }}"))).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_manifest_is_written_after_every_blob() {
        // The 2nd blob (the model: config is 1st) fails; the 1st is already
        // installed, and the manifest must not exist.
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, Some(digest(&w)), 64);
        let dir = tmpdir("last");
        let e = run(&reg, &dir, false).unwrap_err();
        assert!(matches!(e, StageErr::Fetch(FetchErr::Mismatch { .. })), "{e}");
        assert!(dir.join(blob_name(&digest(br#"{"model_format":"gguf"}"#))).is_file(), "the first blob should be in: {:?}", names(&dir));
        assert!(!dir.join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_different_manifest_in_the_store_is_a_conflict_unless_forced() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let raw = pretty(&manifest);
        let reg = serve_raw(raw.clone(), blobs, None, 64);
        let dir = tmpdir("conflict");
        std::fs::write(dir.join(MANIFEST), b"{\"old\":true}").unwrap();
        let e = run(&reg, &dir, false).unwrap_err();
        match &e {
            StageErr::Fetch(FetchErr::Conflict { existing, expected }) => {
                assert_eq!(existing, &digest(b"{\"old\":true}"));
                assert_eq!(expected, &digest(&raw));
            }
            other => panic!("{other}"),
        }
        assert_eq!(reg.blob_hits(), 0, "a blob was requested before the conflict check");
        assert_eq!(std::fs::read(dir.join(MANIFEST)).unwrap(), b"{\"old\":true}");
        run(&reg, &dir, true).unwrap();
        assert_eq!(std::fs::read(dir.join(MANIFEST)).unwrap(), raw);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_manifest_refuses_a_manifest_over_its_limit_by_itself() {
        // The network read is limited too, so the end-to-end test above cannot
        // tell whether check_manifest's own bound holds; a manifest can also
        // reach it from a file. Valid JSON, over 1 MiB only by trailing space.
        let w = weight();
        let (good, _) = model_fixture(&w);
        let mut big = good.to_string().into_bytes();
        big.resize(MIRROR_MAX_MANIFEST_BYTES as usize + 10, b' ');
        let e = check_manifest(&big).unwrap_err();
        assert!(e.contains("over"), "{e}");
        assert!(check_manifest(good.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn a_corrupt_blob_is_replaced_without_force() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 64);
        let dir = tmpdir("corrupt");
        let p = dir.join(blob_name(&digest(&w)));
        // The SAME size as the real blob: only the hash can tell it is corrupt.
        std::fs::write(&p, vec![b'j'; w.len()]).unwrap();
        run(&reg, &dir, false).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), w);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blob_already_present_is_not_downloaded_again() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 64);
        let dir = tmpdir("shared");
        let tmpl = b"{{ .Prompt }}";
        std::fs::write(dir.join(blob_name(&digest(tmpl))), tmpl).unwrap();
        let out = run(&reg, &dir, false).unwrap();
        assert!(!reg.hit_blob(&digest(tmpl)), "the shared blob was fetched again");
        assert!(reg.hit_blob(&digest(&w)));
        assert_eq!(out.blobs.iter().filter(|b| b.present).count(), 1);
        assert_eq!(out.downloaded, out.size_bytes - tmpl.len() as u64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_blob_resumes_with_range() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 64);
        let dir = tmpdir("resume");
        std::fs::write(dir.join(format!(".{}.part", blob_name(&digest(&w)))), &w[..50_000]).unwrap();
        let out = run(&reg, &dir, false).unwrap();
        assert_eq!(out.resumed_from, 50_000);
        assert_eq!(std::fs::read(dir.join(blob_name(&digest(&w)))).unwrap(), w);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_outside_the_limits_is_refused_before_any_blob_request() {
        let w = weight();
        let (good, blobs) = model_fixture(&w);
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut m = good.clone();
        let one = layer_json(MODEL_MEDIA, b"x");
        m["layers"] = Value::Array(vec![one; MIRROR_MAX_LAYERS + 1]);
        cases.push(("65 layers", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["digest"] = json!("sha256:zz");
        cases.push(("bad digest", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["digest"] = json!(format!("md5:{}", "a".repeat(64)));
        cases.push(("wrong algorithm", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["digest"] = json!(format!("sha256:{}", "g".repeat(64)));
        cases.push(("64 characters, not hex", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["digest"] = json!(format!("sha256:{}", "A".repeat(64)));
        cases.push(("uppercase hex (stored verbatim, so never importable)", m.to_string().into_bytes()));
        let mut m = good.clone();
        let l = layer_json(MODEL_MEDIA, b"x");
        let mut twice = l.clone();
        twice["size"] = json!(2);
        m["layers"] = json!([l, twice]);
        cases.push(("one blob listed with two sizes", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["size"] = json!(0);
        cases.push(("size 0", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["size"] = json!(MIRROR_MAX_BLOB_BYTES + 1);
        cases.push(("size over 1 TiB", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"] = json!([layer_json(MODEL_MEDIA, b"x"), {"mediaType": "a/b", "digest": format!("sha256:{}", "b".repeat(64)), "size": MIRROR_MAX_BLOB_BYTES}]);
        cases.push(("sizes add up to over 1 TiB", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["mediaType"] = json!("bad type!");
        cases.push(("media type with a space", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"][1]["mediaType"] = json!("a".repeat(129));
        cases.push(("media type over 128", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"] = json!([layer_json("application/vnd.ollama.image.template", b"t")]);
        cases.push(("no model layer", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["layers"] = json!([]);
        cases.push(("no layers", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["schemaVersion"] = json!(1);
        cases.push(("schemaVersion 1", m.to_string().into_bytes()));
        let mut m = good.clone();
        m["config"] = json!("sha256:abc");
        cases.push(("config not an object", m.to_string().into_bytes()));
        // Valid JSON, valid fields, over 1 MiB only because of trailing space.
        let mut big = good.to_string().into_bytes();
        big.resize(MIRROR_MAX_MANIFEST_BYTES as usize + 10, b' ');
        cases.push(("over 1 MiB", big));
        for (what, raw) in cases {
            let reg = serve_raw(raw, blobs.clone(), None, 8);
            let dir = tmpdir("limits");
            let e = run(&reg, &dir, false).unwrap_err();
            assert!(matches!(e, StageErr::Registry(_)), "{what}: {e}");
            assert_eq!(reg.blob_hits(), 0, "{what}: a blob was requested");
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "{what}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn the_limits_themselves_are_accepted() {
        let w = weight();
        let (mut m, _) = model_fixture(&w);
        m["layers"] = Value::Array((0..MIRROR_MAX_LAYERS).map(|i| layer_json(MODEL_MEDIA, format!("blob {i}").as_bytes())).collect());
        let plan = check_manifest(m.to_string().as_bytes()).unwrap();
        assert_eq!(plan.layers.len(), MIRROR_MAX_LAYERS);
        // The node accepts lowercase digests only; so does this.
        let mut up = model_fixture(&w).0;
        let d = digest(&w).to_ascii_uppercase();
        up["layers"][0]["digest"] = json!(format!("sha256:{d}"));
        assert!(check_manifest(up.to_string().as_bytes()).is_err());
        // One digest listed twice with the same size is one blob; with two sizes it is refused.
        let mut dup = model_fixture(&w).0;
        let again = dup["layers"][1].clone();
        dup["layers"].as_array_mut().unwrap().push(again);
        check_manifest(dup.to_string().as_bytes()).unwrap();
        dup["layers"][3]["size"] = json!(99);
        assert!(check_manifest(dup.to_string().as_bytes()).unwrap_err().contains("two sizes"));
    }

    #[test]
    fn a_missing_tag_is_the_registrys_404_and_installs_nothing() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 8);
        let dir = tmpdir("404");
        let r = parse_ref("gemma4:nope").unwrap();
        let e = stage(&reg.base, &r, &dir, false, &mut |_, _| {}, &mut |_| {}).unwrap_err();
        assert!(e.to_string().contains("no library/gemma4:nope"), "{e}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_target_resolution() {
        let dir = tmpdir("import-target");
        let touch = |n: &str| std::fs::write(dir.join(n), b"x").unwrap();
        // Nothing staged: a tag is refused naming the fetch command.
        for arg in ["ollama:gemma4:12b", "gemma4:12b", "user/m:q4"] {
            let e = resolve_import_target(arg, &dir).unwrap_err();
            assert!(e.contains("noo models fetch ollama:"), "{arg}: {e}");
        }
        // Half of an old pair is not staged.
        touch("ollama+library+gemma4+12b.gguf");
        assert!(resolve_import_target("ollama:gemma4:12b", &dir).unwrap_err().contains("noo models fetch ollama:gemma4:12b"));
        touch("ollama+library+gemma4+12b.Modelfile");
        for arg in ["ollama:gemma4:12b", "gemma4:12b", "library/gemma4:12b", "ollama:Gemma4:12B"] {
            match resolve_import_target(arg, &dir).unwrap() {
                ImportTarget::Staged(r) => assert_eq!(r.short(), if arg.contains("12B") { "Gemma4:12B" } else { "gemma4:12b" }, "{arg}"),
                other => panic!("{arg}: {other:?}"),
            }
        }
        // A mirror alone (manifest, no Modelfile or weight) is staged.
        touch("ollama+library+qwen3+8b.ollama-manifest");
        for arg in ["ollama:qwen3:8b", "qwen3:8b", "library/qwen3:8b"] {
            match resolve_import_target(arg, &dir).unwrap() {
                ImportTarget::Staged(r) => assert_eq!(r.short(), "qwen3:8b", "{arg}"),
                other => panic!("{arg}: {other:?}"),
            }
        }
        assert!(mirror_staged(&dir, &parse_ref("qwen3:8b").unwrap()));
        assert!(!mirror_staged(&dir, &parse_ref("gemma4:12b").unwrap()));
        // A directory of that name is not a manifest.
        std::fs::create_dir(dir.join("ollama+library+dirmodel+1b.ollama-manifest")).unwrap();
        assert!(resolve_import_target("ollama:dirmodel:1b", &dir).is_err());
        // Bare name unambiguous -> staged :latest only if staged.
        touch("ollama+library+gemma4+latest.gguf");
        touch("ollama+library+gemma4+latest.Modelfile");
        assert!(matches!(resolve_import_target("gemma4", &dir).unwrap(), ImportTarget::Staged(_)));
        // The same bare name as a plain store model too: ambiguous.
        touch("gemma4.Modelfile");
        let e = resolve_import_target("gemma4", &dir).unwrap_err();
        assert!(e.contains("both") && e.contains("ollama:gemma4"), "{e}");
        assert!(matches!(resolve_import_target("ollama:gemma4", &dir).unwrap(), ImportTarget::Staged(_)));
        // Plain model, no staged twin.
        touch("harrier.Modelfile");
        assert_eq!(resolve_import_target("harrier", &dir).unwrap(), ImportTarget::Plain("harrier".into()));
        // Unpublished bare name falls to the existing artifact-staging path.
        assert_eq!(resolve_import_target("newmodel", &dir).unwrap(), ImportTarget::Plain("newmodel".into()));
        // Not a name at all.
        assert!(resolve_import_target("../x", &dir).is_err());
        assert!(resolve_import_target("hf.co/o/r:Q4", &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
