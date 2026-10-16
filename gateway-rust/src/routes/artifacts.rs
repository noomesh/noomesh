// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Artifact control plane — the design.
//!
//! The model cache (nginx, mTLS on :8443) is the DATA plane: it moves multi-GB
//! files well and keeps doing exactly that. What it cannot state is
//! integrity — a node that pulls a GGUF today trusts whatever bytes arrive.
//! This route is the CONTROL plane for that pull: an authenticated manifest
//! that names the artifact's size and sha256, which the agent verifies after
//! downloading. Split on purpose:
//!
//!   - no multi-GB streaming through the gateway — nginx keeps the bytes;
//!   - the design (signing) attaches to this manifest later, not to
//!     the byte stream;
//!   - auth is the standard middleware — the agent's cluster-HMAC bearer
//!     (`verify_cluster_token`) already passes it, so a node can ask without
//!     a JWT.
//!
//! Kinds served: `gguf` (flat model weights, step 1) and `image` (docker
//! image tars exported by `noo cluster sync-images`, step 2). Both are flat
//! files with one hash each. HF repo trees (many files per model) need a
//! manifest-of-files and stay out until a step needs them.
//!
//! Digests are cached in `/data/artifact-digests.json` keyed by
//! (kind/name → size, mtime, sha256): hashing a 15 GB GGUF takes real time,
//! and the answer only changes when the file does. A (size, mtime) match
//! serves the cached hash; any mismatch re-hashes. The cache file riding the
//! existing `noo-data` volume means no new mount and it survives restarts.
//! An in-memory copy sits in front of it, so a cache file that cannot be
//! written (a read-only or wrongly-owned `/data`) costs one hash per process,
//! not one per request.
//!
//! A miss hashes in the BACKGROUND. The request waits up to
//! [`HASH_WAIT_SECS`] for it; a file that takes longer answers
//! `202 {"status":"hashing", "retry_after_secs"}` and the caller asks again.
//! Before this the hash ran inside the request: a 3.3 GB GGUF on the
//! NFS-mounted store took 13.5 s on 2026-10-10, the agent's 15 s budget for
//! the whole round trip ran out, and the `model_file` job failed with "the
//! store does not have it" — for a file the store had. Concurrent requests
//! for the same file share one hash (single-flight), and a pre-warm (`noo
//! cluster sync-model-files` asks before it queues the jobs) starts it early.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path as AxPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::AppState;

use super::AppError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/artifacts/manifest/{kind}/{name}", get(manifest))
}

/// Where the controller's GGUF store is mounted in THIS container. The same
/// host directory is what nginx serves as `/gguf/` — compose mounts it here
/// read-only so the manifest describes exactly the bytes a node will pull.
fn gguf_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("NOO_ARTIFACT_GGUF_DIR").unwrap_or_else(|_| "/artifacts/models".into()),
    )
}

/// Where the controller's exported image tars live in THIS container —
/// `noo cluster sync-images` writes `docker save` output here on the host
/// (`${IMAGES_DIR:-$NOO_DATA_ROOT/images}`), nginx serves it as `/images/`,
/// and compose mounts the same directory here read-only.
fn image_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("NOO_ARTIFACT_IMAGE_DIR").unwrap_or_else(|_| "/artifacts/images".into()),
    )
}

/// The per-kind facts a manifest needs: where the files live in this
/// container, the data-plane prefix a node pulls from, and the required
/// filename extension. Unknown kind → None → 400.
fn kind_facts(kind: &str) -> Option<(PathBuf, &'static str, &'static str)> {
    match kind {
        "gguf" => Some((gguf_dir(), "/gguf", ".gguf")),
        // A Modelfile lives BESIDE its weight in the same store, so it needs
        // no mount and no nginx location of its own — only its own extension,
        // which is what keeps `noo cluster ship-model foo` from being served
        // a `.gguf` when it asked for a recipe. `ollama create` reads
        // `FROM ./<file>` relative to the Modelfile, so the two are only ever
        // useful together.
        "modelfile" => Some((gguf_dir(), "/gguf", ".modelfile")),
        "image" => Some((image_dir(), "/images", ".tar")),
        _ => None,
    }
}

fn digest_cache_path() -> PathBuf {
    PathBuf::from(
        std::env::var("NOO_ARTIFACT_DIGEST_CACHE")
            .unwrap_or_else(|_| "/data/artifact-digests.json".into()),
    )
}

/// The name rules mirror the agent side (preseedGGUF refuses '/', and image
/// tar names are built by `ImageTarName` from [a-z0-9._-] material) — so a
/// name the agent would pull is exactly a name this will serve. Rejecting
/// rather than sanitising: a caller sending `..%2f` is not confused, and a
/// 400 is more honest than a silently different file.
fn valid_artifact_name(name: &str, required_ext: &str) -> bool {
    !name.is_empty()
        && name.len() < 256
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.starts_with('.')
        && {
            let lower = name.to_ascii_lowercase();
            // An image is a `.tar` or, since the controller compresses its
            // exports, a `.tar.gz`. Only the image kind (`.tar`) widens.
            lower.ends_with(required_ext) || (required_ext == ".tar" && lower.ends_with(".tar.gz"))
        }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
struct DigestEntry {
    size: u64,
    /// Seconds since epoch of the file's mtime at hashing time.
    mtime_unix: u64,
    #[serde(with = "sha_hex")]
    sha256: [u8; 32],
}

/// Store the hash as lowercase hex in JSON — the form the Go verifier and a
/// human `sha256sum` both speak.
mod sha_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("sha256 must be 32 bytes"))
    }
}

/// Is a cached entry still a truthful description of the file on disk?
/// Pure, so the staleness contract is testable: same size AND same mtime.
fn cache_entry_fresh(entry: &DigestEntry, size: u64, mtime_unix: u64) -> bool {
    entry.size == size && entry.mtime_unix == mtime_unix
}

fn file_meta(path: &Path) -> Option<(u64, u64)> {
    let md = std::fs::metadata(path).ok()?;
    let mtime = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((md.len(), mtime))
}

async fn load_cache() -> std::collections::HashMap<String, DigestEntry> {
    match tokio::fs::read(digest_cache_path()).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Default::default(),
    }
}

/// Persist (tmp + rename so a crash never leaves half a JSON). A lost
/// write only costs a re-hash after a restart — never wrong data — so the
/// caller logs it rather than failing the request.
async fn store_cache(cache: &std::collections::HashMap<String, DigestEntry>) -> Result<(), String> {
    let path = digest_cache_path();
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(cache).map_err(|e| format!("serialise: {e}"))?;
    tokio::fs::write(&tmp, bytes).await.map_err(|e| format!("write {}: {e}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path).await.map_err(|e| format!("rename to {}: {e}", path.display()))
}

/// Hash the file in a blocking task — a 15 GB GGUF takes tens of seconds and
/// must not sit on the async runtime.
async fn sha256_file(path: PathBuf) -> Result<[u8; 32], String> {
    tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        let f = std::fs::File::open(&path).map_err(|e| format!("open: {e}"))?;
        let mut reader = f;
        let mut hasher = Sha256::new();
        // sha2 0.11 hashers no longer implement io::Write, so this is the
        // io::copy loop by hand (1 MiB reads, retry on EINTR as copy did).
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = match std::io::Read::read(&mut reader, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read: {e}")),
            };
            hasher.update(&buf[..n]);
        }
        Ok::<[u8; 32], String>(hasher.finalize().into())
    })
    .await
    .map_err(|e| format!("hash task: {e}"))?
}

/// How long one manifest request waits for a background hash before it
/// answers 202. Well inside every client's request timeout (the agent's is
/// 60 s per request, the CLI's 30 s), so a slow hash is never a timeout.
pub(crate) const HASH_WAIT_SECS: u64 = 8;
/// What a 202 tells the caller to wait before asking again.
pub(crate) const HASH_RETRY_AFTER_SECS: u64 = 5;

type HashOutcome = Option<Result<[u8; 32], String>>;

/// Digests this process has computed or read, keyed like the file cache.
fn mem_cache() -> &'static Mutex<HashMap<String, DigestEntry>> {
    static M: OnceLock<Mutex<HashMap<String, DigestEntry>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// Hashes in flight: key → (size, mtime it is hashing, result channel).
type InFlight = HashMap<String, (u64, u64, tokio::sync::watch::Receiver<HashOutcome>)>;
fn in_flight() -> &'static Mutex<InFlight> {
    static M: OnceLock<Mutex<InFlight>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// Serialises read-modify-write of the cache FILE, so two hashes finishing
/// together cannot each drop the other's entry.
fn file_cache_lock() -> &'static tokio::sync::Mutex<()> {
    static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// A fresh digest for (key, size, mtime) from memory, then the cache file.
async fn cached_digest(key: &str, size: u64, mtime_unix: u64) -> Option<DigestEntry> {
    if let Some(e) = mem_cache().lock().ok()?.get(key).copied() {
        if cache_entry_fresh(&e, size, mtime_unix) {
            return Some(e);
        }
    }
    let e = load_cache().await.get(key).copied()?;
    if !cache_entry_fresh(&e, size, mtime_unix) {
        return None;
    }
    if let Ok(mut m) = mem_cache().lock() {
        m.insert(key.to_string(), e);
    }
    Some(e)
}

/// Record a new digest in memory and (best effort, but loudly) on disk.
async fn remember_digest(key: &str, e: DigestEntry) {
    if let Ok(mut m) = mem_cache().lock() {
        m.insert(key.to_string(), e);
    }
    let _guard = file_cache_lock().lock().await;
    let mut cache = load_cache().await;
    cache.insert(key.to_string(), e);
    if let Err(why) = store_cache(&cache).await {
        // Not fatal (the memory copy serves this process), but a restart
        // re-hashes everything, so say where and why.
        tracing::warn!(path = %digest_cache_path().display(), error = %why, "artifacts.digest.cache_write_failed");
    }
}

/// The result channel for hashing `path` as (size, mtime): joins a hash
/// already running for the same file version, else starts one.
fn hash_in_background(key: &str, path: PathBuf, size: u64, mtime_unix: u64) -> tokio::sync::watch::Receiver<HashOutcome> {
    let mut flights = in_flight().lock().unwrap_or_else(|p| p.into_inner());
    if let Some((s, m, rx)) = flights.get(key) {
        if *s == size && *m == mtime_unix {
            return rx.clone();
        }
    }
    let (tx, rx) = tokio::sync::watch::channel::<HashOutcome>(None);
    flights.insert(key.to_string(), (size, mtime_unix, rx.clone()));
    let key = key.to_string();
    tokio::spawn(async move {
        tracing::info!(artifact = %key, size, "artifacts.digest.computing");
        let started = std::time::Instant::now();
        let out = sha256_file(path).await;
        match &out {
            Ok(sha256) => {
                tracing::info!(artifact = %key, size, secs = started.elapsed().as_secs_f64(), "artifacts.digest.computed");
                remember_digest(&key, DigestEntry { size, mtime_unix, sha256: *sha256 }).await;
            }
            Err(e) => tracing::warn!(artifact = %key, error = %e, "artifacts.digest.failed"),
        }
        let _ = tx.send(Some(out));
        let mut flights = in_flight().lock().unwrap_or_else(|p| p.into_inner());
        if flights.get(&key).is_some_and(|(s, m, _)| *s == size && *m == mtime_unix) {
            flights.remove(&key);
        }
    });
    rx
}

/// Wait up to `wait` for a background hash. None = still hashing.
async fn await_hash(
    mut rx: tokio::sync::watch::Receiver<HashOutcome>,
    wait: std::time::Duration,
) -> Option<Result<[u8; 32], String>> {
    let done = tokio::time::timeout(wait, rx.wait_for(|v| v.is_some())).await;
    match done {
        Ok(Ok(v)) => v.clone(),
        Ok(Err(_)) => Some(Err("hash task ended without a result".into())),
        Err(_) => None,
    }
}

/// The 202 a caller gets while a large file is still being hashed.
fn hashing_response(kind: &str, name: &str, size: u64) -> Response {
    let body = json!({
        "status": "hashing",
        "kind": kind,
        "name": name,
        "size_bytes": size,
        "retry_after_secs": HASH_RETRY_AFTER_SECS,
        "detail": "the controller is computing this file's sha256; ask again",
    });
    (
        StatusCode::ACCEPTED,
        [(header::RETRY_AFTER, HASH_RETRY_AFTER_SECS.to_string())],
        Json(body),
    )
        .into_response()
}

/// The refusal for the retired `binary` kind. It was the
/// gateway half of the agent swap: this process signed the binary's manifest
/// with its own TLS key and a root daemon on every node installed what that
/// signature named — so a compromised gateway, the web-facing process, could
/// run code as root fleet-wide. Agent binaries now reach a node only in a
/// bundle signed by the fleet signing key over the pull rail.
pub(crate) const BINARY_KIND_RETIRED: &str = "artifact kind 'binary' is retired: \
     agent binaries arrive only in a signed bundle over the pull rail — \
     run `noo cluster provision <node> --wait` on the controller";

/// The refusal for a retired kind, logged loudly; None for every other kind.
fn retired_kind(kind: &str, name: &str) -> Option<AppError> {
    (kind == "binary").then(|| {
        tracing::warn!(artifact = %name, "artifacts.manifest.refused: kind=binary is retired");
        AppError::BadRequest(BINARY_KIND_RETIRED.into())
    })
}

/// GET /api/artifacts/manifest/{kind}/{name}
async fn manifest(
    State(_state): State<Arc<AppState>>,
    AxPath((kind, name)): AxPath<(String, String)>,
) -> Result<Response, AppError> {
    if let Some(refusal) = retired_kind(&kind, &name) {
        return Err(refusal);
    }
    let Some((dir, data_prefix, ext)) = kind_facts(&kind) else {
        return Err(AppError::BadRequest(format!(
            "unknown artifact kind '{kind}' (kinds: gguf, image, modelfile)"
        )));
    };
    if !valid_artifact_name(&name, ext) {
        return Err(AppError::BadRequest(format!(
            "artifact name must be a bare *{ext} filename"
        )));
    }
    let path = dir.join(&name);
    let Some((size, mtime_unix)) = file_meta(&path) else {
        return Err(AppError::NotFound(format!(
            "no {kind} artifact named '{name}' in the controller store"
        )));
    };

    let key = format!("{kind}/{name}");
    let entry = match cached_digest(&key, size, mtime_unix).await {
        Some(e) => e,
        None => {
            let rx = hash_in_background(&key, path.clone(), size, mtime_unix);
            match await_hash(rx, std::time::Duration::from_secs(HASH_WAIT_SECS)).await {
                Some(Ok(sha256)) => DigestEntry { size, mtime_unix, sha256 },
                Some(Err(e)) => return Err(AppError::Internal(format!("hashing {name}: {e}"))),
                None => return Ok(hashing_response(&kind, &name, size)),
            }
        }
    };

    let mut body = json!({
        "kind": kind,
        "name": name,
        "size_bytes": entry.size,
        "sha256": hex::encode(entry.sha256),
        // The data plane a node should pull from; stating it here keeps the
        // pair (where + what-it-hashes-to) in one authenticated answer.
        "data_path": format!("{data_prefix}/{name}"),
    });
    // An image tar also says WHICH image it loads as (the `<tar>.imageid`
    // sidecar the staging export writes) and the release-lock digest it was
    // staged from. The node compares a local image against `image_id` before
    // fetching anything, and checks the loaded image against it after.
    if kind == "image" {
        if let Some(id) = read_image_id_sidecar(&dir, &name) {
            body["image_id"] = json!(id);
        }
        if let Some(rec) = read_staged_index(&dir).images.into_iter().find(|i| i.tar == name) {
            if !rec.lock_digest.is_empty() {
                body["lock_digest"] = json!(rec.lock_digest);
            }
        }
    }
    // No signature. the design signed this manifest with the
    // gateway's TLS key for the worker hostd's agent swap, its only verifier;
    // the design retired the swap, and the gateway's key no longer vouches
    // for anything a node installs. Every remaining kind is verified by the
    // agent that made this mTLS request, against the digest above.
    Ok(Json(body).into_response())
}

// ── staged images: what the controller has put on the rail ─────────────────

/// The staging index `noo upgrade` / `noo cluster stage-images` /
/// `noo cluster sync-images` write beside the tars (`staged-images.json`).
pub(crate) const STAGED_INDEX: &str = "staged-images.json";

#[derive(Deserialize, Default, Debug)]
pub(crate) struct StagedIndex {
    /// The release the lock-driven stage was for — how the gateway, which
    /// holds no NOO_IMAGE_TAG of its own, can name a node's default images.
    #[serde(default)]
    pub release: Option<StagedRelease>,
    /// Registry roots whose images are ours, written by the staging CLI.
    #[serde(default)]
    pub own_roots: Vec<String>,
    #[serde(default)]
    pub images: Vec<StagedImage>,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct StagedRelease {
    pub prefix: String,
    pub tag: String,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct StagedImage {
    #[serde(rename = "ref")]
    pub image: String,
    pub arch: String,
    pub tar: String,
    #[serde(default)]
    pub image_id: String,
    #[serde(default)]
    pub lock_digest: String,
}

/// The image store directory as this container sees it.
pub(crate) fn image_store_dir() -> PathBuf {
    image_dir()
}

/// The staging index, or an empty one (absent, unreadable or malformed —
/// the index only ever ADDS facts; no reader treats its absence as a fact).
pub(crate) fn read_staged_index(dir: &Path) -> StagedIndex {
    std::fs::read(dir.join(STAGED_INDEX))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// `<tar>.imageid` — the local image ID the controller exported into the tar.
/// Only a well-formed `sha256:<64 hex>` is returned: this value gates a node's
/// "my local copy is the staged one" decision.
fn read_image_id_sidecar(dir: &Path, tar_name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(dir.join(format!("{tar_name}.imageid"))).ok()?;
    let id = raw.trim().to_ascii_lowercase();
    let hex = id.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(id)
}

/// Third twin of the tar-name convention (Go `ImageTarName`, Rust CLI
/// `image_tar_name`): '/' and ':' become '_', then `_<arch>.tar`.
pub(crate) fn image_tar_name(image: &str, arch: &str) -> String {
    format!("{}_{arch}.tar", image.replace(['/', ':'], "_"))
}

/// The compressed export's name: `image_tar_name` + ".gz" (twins: Go
/// `ImageTarGzName`, noo-cli `image_tar_gz_name`).
pub(crate) fn image_tar_gz_name(image: &str, arch: &str) -> String {
    format!("{}.gz", image_tar_name(image, arch))
}

/// Whether the store holds this image for `arch` in either form (an older
/// controller store holds the plain `.tar`).
pub(crate) fn image_is_staged(dir: &Path, image: &str, arch: &str) -> bool {
    dir.join(image_tar_gz_name(image, arch)).is_file() || dir.join(image_tar_name(image, arch)).is_file()
}

/// Docker's normalisation of a ref's NAME — twin of Go `normalizeName` and
/// noo-cli `image_stage::normalize_name`; `tests/fixtures/own_image_cases.json`
/// holds all three to one answer.
pub(crate) fn normalize_name(r: &str) -> Option<String> {
    let r = r.trim();
    if r.is_empty() || r.contains(char::is_whitespace) {
        return None;
    }
    let r = r.split('@').next().unwrap_or(r);
    let name = match r.rfind(':') {
        Some(i) if i > r.rfind('/').unwrap_or(0) => &r[..i],
        _ => r,
    };
    let (domain, path) = match name.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => (first, rest.to_string()),
        _ => ("docker.io", name.to_string()),
    };
    if path.is_empty() || path.contains("//") || path.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let domain = if domain == "index.docker.io" { "docker.io" } else { domain };
    let path = if domain == "docker.io" && !path.contains('/') { format!("library/{path}") } else { path };
    Some(format!("{domain}/{path}"))
}

const LOCAL_BUILD_NAMESPACES: [&str; 3] = ["docker.io/noomesh/", "docker.io/pai-assistant/", "docker.io/library/noo-"];

/// Is `image` one of OUR images — rail-only on a node? THE shared rule: the
/// normalised name sits under one of `roots` (the staging index's
/// `own_roots` plus the release prefix — no namespace literal lives here) or
/// a local-build namespace; unparsable counts as ours.
pub(crate) fn is_own_image_with(image: &str, roots: &[&str]) -> bool {
    let Some(name) = normalize_name(image) else { return true };
    roots
        .iter()
        .map(|x| x.trim().trim_end_matches('/'))
        .filter(|x| !x.is_empty())
        .filter_map(normalize_name)
        .any(|root| name.starts_with(&format!("{root}/")))
        || LOCAL_BUILD_NAMESPACES.iter().any(|p| name.starts_with(p))
}

/// The image a placement needs staged, when the gateway can know it: an
/// explicit `image` of ours, or — on an amd64 node with a staged release —
/// the release llama.cpp the agent defaults to (`llamacppDefaultImage`).
/// A third-party image is not required: a node may take it from its public
/// registry under NOO_IMAGE_REGISTRY_FALLBACK. None = nothing to judge.
pub(crate) fn placement_required_image(
    backend: &str,
    body_image: Option<&str>,
    node_arch: &str,
    release: Option<&StagedRelease>,
    own_roots: &[String],
) -> Option<String> {
    if let Some(img) = body_image.map(str::trim).filter(|i| !i.is_empty()) {
        let mut roots: Vec<&str> = own_roots.iter().map(String::as_str).collect();
        if let Some(r) = release {
            roots.push(r.prefix.as_str());
        }
        return is_own_image_with(img, &roots).then(|| img.to_string());
    }
    let r = release?;
    (backend == "llamacpp" && node_arch == "amd64")
        .then(|| format!("{}/llamacpp:{}", r.prefix.trim_end_matches('/'), r.tag))
}

/// The place-time refusal. The phrase "is not staged on the controller" and
/// the `image <ref> for <arch>` shape are parsed by `noo cluster place`,
/// which stages the image and retries — keep them stable.
pub(crate) fn not_staged_refusal(node: &str, image: &str, arch: &str) -> String {
    format!(
        "image {image} for {arch} is not staged on the controller, so {node} cannot start it \
         (a node pulls images only from the controller's artifact rail and holds no registry \
         credential). Stage it: `noo cluster sync-images {node} -i {image}` (or `noo upgrade` for \
         the release images), then place again; --force places it anyway"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_name_twin_matches_the_go_and_cli_convention() {
        assert_eq!(image_tar_name("pai-assistant/node-agent:latest", "amd64"), "pai-assistant_node-agent_latest_amd64.tar");
        assert_eq!(image_tar_name("ghcr.io/x/y:z", "arm64"), "ghcr.io_x_y_z_arm64.tar");
        assert_eq!(image_tar_gz_name("ghcr.io/x/y:z", "arm64"), "ghcr.io_x_y_z_arm64.tar.gz");
        assert_eq!(image_tar_gz_name("a:b", "amd64"), format!("{}.gz", image_tar_name("a:b", "amd64")));
    }

    #[test]
    fn placement_requires_only_images_the_gateway_can_name() {
        let rel = StagedRelease { prefix: "reg.example/acme".into(), tag: "v0.2.103".into() };
        // The host8-ma case: llamacpp on an amd64 node with no explicit image.
        assert_eq!(
            placement_required_image("llamacpp", None, "amd64", Some(&rel), &[]).as_deref(),
            Some("reg.example/acme/llamacpp:v0.2.103")
        );
        // ARM nodes default to upstream llama.cpp (third-party): nothing required.
        assert!(placement_required_image("llamacpp", None, "arm64", Some(&rel), &[]).is_none());
        // An explicit image of ours is required; a third-party one is not.
        assert_eq!(
            placement_required_image("vllm", Some("reg.example/acme/vllm:v1"), "amd64", Some(&rel), &[]).as_deref(),
            Some("reg.example/acme/vllm:v1")
        );
        assert!(placement_required_image("vllm", Some("vllm/vllm-openai:latest"), "amd64", Some(&rel), &[]).is_none());
        // `contains("/noomesh/")` used to call this ours; the shared rule does not.
        assert!(placement_required_image("vllm", Some("quay.io/someone/noomesh/x:1"), "amd64", Some(&rel), &[]).is_none());
        // own_roots from the index count too.
        assert!(placement_required_image("vllm", Some("other.example/ns/v:1"), "amd64", None, &["other.example/ns".into()]).is_some());
        // No staged release, no explicit image: nothing the gateway can judge.
        assert!(placement_required_image("llamacpp", None, "amd64", None, &[]).is_none());
        assert!(placement_required_image("ollama", None, "amd64", Some(&rel), &[]).is_none());
    }

    #[test]
    fn own_image_rule_matches_the_shared_fixture() {
        let fx: serde_json::Value = serde_json::from_str(include_str!("../../../tests/fixtures/own_image_cases.json")).unwrap();
        let roots: Vec<&str> = fx["roots"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        let cases = fx["cases"].as_array().unwrap();
        assert!(cases.len() >= 10, "fixture parse found {} cases", cases.len());
        for c in cases {
            let r = c["ref"].as_str().unwrap();
            assert_eq!(is_own_image_with(r, &roots), c["own"].as_bool().unwrap(), "{r}");
        }
    }

    #[test]
    fn not_staged_refusal_names_the_fix_in_a_parseable_shape() {
        let m = not_staged_refusal("host8-ma", "reg.example/acme/llamacpp:v1", "amd64");
        assert!(m.contains("image reg.example/acme/llamacpp:v1 for amd64 is not staged on the controller"), "{m}");
        assert!(m.contains("noo cluster sync-images host8-ma -i reg.example/acme/llamacpp:v1"), "{m}");
        assert!(m.contains("noo upgrade"), "{m}");
    }

    #[test]
    fn image_id_sidecar_and_index_are_read_defensively() {
        let dir = std::env::temp_dir().join(format!("noo-art-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let id = format!("sha256:{}", "Ab".repeat(32));
        std::fs::write(dir.join("x_amd64.tar.imageid"), format!("{id}\n")).unwrap();
        assert_eq!(read_image_id_sidecar(&dir, "x_amd64.tar"), Some(id.to_ascii_lowercase()));
        // The sidecar of a compressed export is `<name>.tar.gz.imageid`.
        std::fs::write(dir.join("x_amd64.tar.gz.imageid"), format!("{id}\n")).unwrap();
        assert_eq!(read_image_id_sidecar(&dir, "x_amd64.tar.gz"), Some(id.to_ascii_lowercase()));
        std::fs::write(dir.join("bad_amd64.tar.imageid"), "not-an-id").unwrap();
        assert!(read_image_id_sidecar(&dir, "bad_amd64.tar").is_none());
        assert!(read_image_id_sidecar(&dir, "missing.tar").is_none());

        assert!(read_staged_index(&dir).images.is_empty(), "absent index is empty, not an error");
        std::fs::write(
            dir.join(STAGED_INDEX),
            r#"{"release":{"prefix":"p","tag":"v1"},"images":[{"ref":"p/a:v1","arch":"arm64","tar":"p_a_v1_arm64.tar","image_id":"sha256:1","lock_digest":"sha256:2"}]}"#,
        )
        .unwrap();
        let idx = read_staged_index(&dir);
        assert_eq!(idx.release.unwrap().tag, "v1");
        assert_eq!(idx.images[0].lock_digest, "sha256:2");
        std::fs::write(dir.join(STAGED_INDEX), "{garbage").unwrap();
        assert!(read_staged_index(&dir).images.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gguf_names_reject_traversal_and_non_gguf() {
        for bad in [
            "",
            "../secrets.gguf",
            "a/b.gguf",
            "a\\b.gguf",
            "..",
            ".hidden.gguf",
            "model.bin",
            "model.GGUF.txt",
        ] {
            assert!(!valid_artifact_name(bad, ".gguf"), "{bad:?} must be rejected");
        }
        for good in ["gemma-4-26B_q4_0-it.gguf", "bge-reranker-v2-m3-Q8_0.GGUF"] {
            assert!(valid_artifact_name(good, ".gguf"), "{good:?} must be accepted");
        }
    }

    #[test]
    fn an_image_is_staged_in_either_form() {
        let dir = std::env::temp_dir().join(format!("noo-art-staged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!image_is_staged(&dir, "a/b:c", "amd64"));
        std::fs::write(dir.join(image_tar_name("a/b:c", "amd64")), b"x").unwrap();
        assert!(image_is_staged(&dir, "a/b:c", "amd64"));
        std::fs::remove_file(dir.join(image_tar_name("a/b:c", "amd64"))).unwrap();
        std::fs::write(dir.join(image_tar_gz_name("a/b:c", "amd64")), b"x").unwrap();
        assert!(image_is_staged(&dir, "a/b:c", "amd64"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn image_tar_names_follow_the_same_rules() {
        // The agent builds these with ImageTarName: '/'+':' → '_', arch
        // suffix, .tar — so accepted names are exactly that shape.
        for good in [
            "pai-assistant_node-agent_latest_amd64.tar",
            "ghcr.io_noomesh_llamacpp_v0.1.47_arm64.tar",
            // The controller's compressed export (same stem + ".gz").
            "pai-assistant_node-agent_latest_amd64.tar.gz",
            "ghcr.io_noomesh_llamacpp_v0.1.47_arm64.TAR.GZ",
        ] {
            assert!(valid_artifact_name(good, ".tar"), "{good:?} must be accepted");
        }
        // Only the image kind widens: a weight is never served as `.tar.gz`.
        assert!(!valid_artifact_name("m.tar.gz", ".gguf"));
        assert!(!valid_artifact_name("m.tar.gz", ".modelfile"));
        for bad in ["a/b.tar", "..", ".hidden.tar", ".hidden.tar.gz", "a/b.tar.gz", "img.gguf", "img.gz", "img.tgz"] {
            assert!(!valid_artifact_name(bad, ".tar"), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn kinds_are_a_closed_set() {
        assert!(kind_facts("gguf").is_some());
        assert!(kind_facts("image").is_some());
        // Retired: no store, no manifest, no signature.
        assert!(kind_facts("binary").is_none());
        assert!(kind_facts("modelfile").is_some());
        assert!(kind_facts("model").is_none(), "future kinds arrive explicitly, not by default");
        assert!(kind_facts("").is_none());
    }

    #[test]
    fn a_modelfile_shares_the_gguf_store_but_not_its_extension() {
        let (gd, gp, ge) = kind_facts("gguf").unwrap();
        let (md, mp, me) = kind_facts("modelfile").unwrap();
        // Same directory and same data-plane prefix: a Modelfile is only ever
        // useful beside the weight its `FROM ./<file>` names, so giving it a
        // store of its own would be a mount, an nginx location and a way for
        // the two to get separated.
        assert_eq!(gd, md);
        assert_eq!(gp, mp);
        // Different extension, so neither kind can serve the other's file.
        assert_ne!(ge, me);
        assert!(valid_artifact_name("qwen3-tuned.Modelfile", me));
        assert!(!valid_artifact_name("qwen3-tuned.gguf", me));
        assert!(!valid_artifact_name("qwen3-tuned.Modelfile", ge));
        // The convert script writes a capital M; the name check lowercases.
        assert!(valid_artifact_name("a.modelfile", me));
        for bad in ["../x.Modelfile", "a/b.Modelfile", ".hidden.Modelfile"] {
            assert!(!valid_artifact_name(bad, me), "{bad:?} must be rejected");
        }
    }

    /// the design, the negative test: a `binary` manifest request is
    /// refused with the reason and the rail command — before any store is
    /// read — and the gateway no longer signs manifests with its TLS key.
    /// Fails on the pre-retirement route, which served a signed manifest.
    #[test]
    fn binary_manifest_is_refused() {
        let err = retired_kind("binary", "noo-node-agent_amd64.bin").expect("kind=binary must be refused");
        match err {
            AppError::BadRequest(m) => {
                assert!(m.contains("retired"), "{m}");
                assert!(m.contains("noo cluster provision"), "{m}");
            }
            other => panic!("expected BadRequest, got {other}"),
        }
        for live in ["gguf", "image", "modelfile"] {
            assert!(retired_kind(live, "x").is_none(), "{live} is still served");
        }
        let src = include_str!("artifacts.rs");
        let sign_fn = ["fn sign", "_manifest("].concat();
        assert!(!src.contains(&sign_fn), "the gateway must not sign artifact manifests any more");
    }

    #[test]
    fn cache_freshness_is_size_and_mtime() {
        let e = DigestEntry { size: 10, mtime_unix: 100, sha256: [0u8; 32] };
        assert!(cache_entry_fresh(&e, 10, 100));
        // Either changing invalidates: a touched file re-hashes even at the
        // same size, and a same-mtime size change (truncation) re-hashes too.
        assert!(!cache_entry_fresh(&e, 10, 101));
        assert!(!cache_entry_fresh(&e, 11, 100));
    }

    fn temp_file(bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("noo-artifacts-test-{}", uuid::Uuid::new_v4()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[tokio::test]
    async fn a_background_hash_answers_inside_the_wait_and_is_remembered() {
        let p = temp_file(b"abc");
        let key = format!("gguf/{}", p.file_name().unwrap().to_string_lossy());
        let (size, mtime) = file_meta(&p).unwrap();
        let rx = hash_in_background(&key, p.clone(), size, mtime);
        let got = await_hash(rx, std::time::Duration::from_secs(10)).await;
        let sha = got.expect("finished").expect("hashed");
        // sha256("abc")
        assert_eq!(hex::encode(sha), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // Memory serves the repeat even if the cache file could not be written.
        let again = mem_cache().lock().unwrap().get(&key).copied().expect("remembered in memory");
        assert!(cache_entry_fresh(&again, size, mtime));
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn a_hash_that_outlasts_the_wait_reports_still_hashing() {
        // A channel nobody completes stands in for a 15 GB file.
        let (_tx, rx) = tokio::sync::watch::channel::<HashOutcome>(None);
        assert!(await_hash(rx, std::time::Duration::from_millis(50)).await.is_none());
    }

    #[tokio::test]
    async fn concurrent_requests_for_one_file_share_one_hash() {
        let p = temp_file(&[7u8; 4096]);
        let key = format!("gguf/{}", p.file_name().unwrap().to_string_lossy());
        let (size, mtime) = file_meta(&p).unwrap();
        // #[tokio::test] is a current-thread runtime: the spawned hash cannot
        // run (and remove itself) until this test awaits, so the second
        // call deterministically finds the first in flight.
        let first = hash_in_background(&key, p.clone(), size, mtime);
        let second = hash_in_background(&key, p.clone(), size, mtime);
        assert!(first.same_channel(&second), "the second caller must join the first hash");
        let a = await_hash(first, std::time::Duration::from_secs(10)).await.unwrap().unwrap();
        let b = await_hash(second, std::time::Duration::from_secs(10)).await.unwrap().unwrap();
        assert_eq!(a, b);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_202_names_the_retry() {
        let r = hashing_response("gguf", "big.gguf", 3_300_000_000);
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        assert_eq!(r.headers().get(header::RETRY_AFTER).unwrap(), &HASH_RETRY_AFTER_SECS.to_string());
    }

    #[test]
    fn digest_entry_json_roundtrips_as_hex() {
        let e = DigestEntry { size: 5, mtime_unix: 7, sha256: [0xab; 32] };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(&"ab".repeat(32)), "hex form in JSON: {s}");
        let back: DigestEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
