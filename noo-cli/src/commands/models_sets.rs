// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo models stage | accept | rm` and `noo models list --kind`: MODEL SETS
//! (i300 F2b; design: noomesh-internal proposals/i300 sections 3.1-3.3).
//!
//! A model set is a named, versioned directory of files in the controller's
//! model store, described by a signed manifest:
//!
//! ```text
//! <MODELS_DIR>/sets/<id>/<revision>/<files, 0644>
//! <MODELS_DIR>/sets/<id>/<revision>/model-set.json       (the catalog entry)
//! <MODELS_DIR>/sets/<id>/<revision>/model-set.json.sig   (detached, written LAST)
//! <MODELS_DIR>/sets/<id>/license-accepted.json           (`noo models accept`)
//! ```
//!
//! A set with no `.sig` does not exist to `list`: a stage that dies half way
//! leaves files and no signature, and a re-run resumes it.
//!
//! The only source is an AUTHENTICATED Hugging Face fetch of a pinned commit
//! (`hf:<org>/<name>@<40-hex sha>`): the controller's HF token, read the way
//! `noo models fetch` reads it, goes to the Hugging Face origin only and is
//! never put on argv, in a log line, in an error, in the manifest or in the
//! output of this command. Weights are fetched by [`models_fetch`] (resume,
//! sha256 against the LFS metadata, refusal of a file with no digest); the
//! small non-LFS files (README, licence, config) are verified against their
//! git blob id from the same authenticated listing and hashed here. There is
//! no local-directory source and no `--trust-local`.
//!
//! `--extract <archive>[:<glob>]` takes files out of ONE archive of the same
//! repo and commit (an LFS file, so its sha256 is Hugging Face's own): the
//! controller extracts it ([`super::models_extract`]: regular files only,
//! streaming size caps, safe names) into a work dir beside the set, and moves
//! the members into the set only after every one has passed. The set then
//! lists each member with its own sha256 and bytes plus `from_archive`; the
//! archive is not a file of the set. A refusal leaves no set dir and no
//! `model-set.json`.
//!
//! The manifest is validated ([`crate::model_set`], a port of the node
//! agent's validator) before it is written, and signed with the fleet bundle
//! signing key (`pki/signing.key`, ECDSA P-384): `openssl dgst -sha256 -sign`
//! over the exact manifest bytes, the same invocation every bundle is signed
//! with (kiosk_seat.rs, node_fetch.rs; scripts/sign-bundle.sh).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::models_extract::{self, Limits};
use super::models_fetch::{self, FetchArgs, FetchErr};
use crate::args::{ArgError, Args};
use crate::model_set;
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

const SETS_DIR: &str = "sets";
const MANIFEST: &str = "model-set.json";
const SIGNATURE: &str = "model-set.json.sig";
const ACCEPTED: &str = "license-accepted.json";
/// The largest non-LFS file taken into a set. Hugging Face keeps anything
/// bigger in LFS; a bigger file with no LFS digest cannot be verified.
const SMALL_MAX: u64 = 8 << 20;

// ── Arguments ───────────────────────────────────────────────────────────

/// `noo models stage`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StageArgs {
    pub repo: String,
    pub sha: String,
    pub kind: String,
    pub id: String,
    pub modality: String,
    pub runtime: Vec<String>,
    pub needs: String,
    pub license: Option<String>,
    pub license_url: Option<String>,
    pub files: Vec<String>,
    pub fits_model: Option<String>,
    pub fits_revision: Option<String>,
    pub fits_runtime: Option<String>,
    pub accept_license: bool,
    /// `--extract <archive>[:<glob>]`: take the set's files out of an archive.
    pub extract: Option<ExtractSpec>,
    /// `--license-additional <id>=<url>[,<notice path>]`, exactly as declared.
    pub license_additional: Vec<AdditionalLicense>,
}

/// `--extract <archive path>[:<member glob>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtractSpec {
    /// A file of the SAME repo and revision as the set.
    pub archive: String,
    pub glob: Option<String>,
}

/// `--license-additional <id>=<url>[,<notice path>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdditionalLicense {
    pub id: String,
    pub url: String,
    pub notice_path: Option<String>,
}

pub(crate) fn parse_extract(raw: &str) -> Result<ExtractSpec, String> {
    let (archive, glob) = match raw.split_once(':') {
        Some((a, g)) => (a, Some(g)),
        None => (raw, None),
    };
    if !model_set::valid_set_path(archive) {
        return Err(format!(
            "--extract `{archive}` is not a file path of the repo (relative, at most one \
             directory level, characters A-Za-z0-9._-)"
        ));
    }
    if let Some(g) = glob {
        let ok_char = |b: u8| b.is_ascii_alphanumeric() || b"._-*?/".contains(&b);
        if g.is_empty() || g.len() > 128 || !g.bytes().all(ok_char) {
            return Err(format!(
                "--extract member glob `{g}` takes letters, digits, . _ - / and the wildcards * ?"
            ));
        }
    }
    Ok(ExtractSpec { archive: archive.to_string(), glob: glob.map(str::to_string) })
}

pub(crate) fn parse_additional(raw: &str) -> Result<AdditionalLicense, String> {
    let shape = "--license-additional is <id>=<url>[,<notice path>]";
    let Some((id, rest)) = raw.split_once('=') else {
        return Err(format!("`{raw}`: {shape}"));
    };
    let (url, notice) = match rest.rsplit_once(',') {
        Some((u, n)) => (u, Some(n)),
        None => (rest, None),
    };
    if id.is_empty() || url.is_empty() {
        return Err(format!("`{raw}`: {shape}"));
    }
    if let Some(n) = notice {
        if !model_set::valid_set_path(n) {
            return Err(format!("`{raw}`: the notice path `{n}` is not a set file path"));
        }
    }
    Ok(AdditionalLicense {
        id: id.to_string(),
        url: url.to_string(),
        notice_path: notice.map(str::to_string),
    })
}

/// `hf:<org>/<name>@<40-hex commit>` into (repo, commit).
pub(crate) fn parse_spec(spec: &str) -> Result<(String, String), String> {
    let Some(rest) = spec.strip_prefix("hf:") else {
        return Err(format!(
            "`{spec}` is not a source this version stages: the only source is \
             hf:<org>/<name>@<40-hex commit>, an authenticated Hugging Face fetch"
        ));
    };
    let Some((repo, sha)) = rest.split_once('@') else {
        return Err(format!(
            "`{spec}` has no @<commit>: pin a full 40-hex commit sha, never a branch or a tag"
        ));
    };
    if !model_set::hf_repo_ok(repo) {
        return Err(format!("`{repo}` is not a Hugging Face repo id (want <org>/<name>)"));
    }
    if !model_set::commit_ok(sha) {
        return Err(format!(
            "`{sha}` is not a full 40-hex commit sha: a branch or tag name is refused, so a \
             re-run can never fetch different bytes (the commits are listed at \
             https://huggingface.co/{repo}/commits/main)"
        ));
    }
    Ok((repo.to_string(), sha.to_string()))
}

pub(crate) fn parse_stage_with(a: &mut Args) -> Result<StageArgs, ArgError> {
    // Every flag is asked before a positional is demanded or a value judged:
    // the usage tie test runs this parser on empty input.
    let kind = a.value(&["--kind"])?;
    let id = a.value(&["--id"])?;
    let modality = a.value(&["--modality"])?;
    let runtime = a.values(&["--runtime"])?;
    let needs = a.value(&["--needs"])?;
    let license = a.value(&["--license"])?;
    let license_url = a.value(&["--license-url"])?;
    let files = a.values(&["--file"])?;
    let fits_model = a.value(&["--fits-model"])?;
    let fits_revision = a.value(&["--fits-revision"])?;
    let fits_runtime = a.value(&["--fits-runtime"])?;
    let accept_license = a.flag(&["--accept-license"]);
    let extract = a.value(&["--extract"])?;
    let additional = a.values(&["--license-additional"])?;
    let spec = a.one("<hf:repo@sha>")?;
    let (repo, sha) = parse_spec(&spec).map_err(ArgError::new)?;
    let need = |v: Option<String>, flag: &str| {
        v.ok_or_else(|| ArgError::new(format!("{flag} is required")))
    };
    let kind = need(kind, "--kind")?;
    if kind != "voice" && kind != "voice-pack" {
        return Err(ArgError::new(format!("--kind is voice or voice-pack, not `{kind}`")));
    }
    let id = need(id, "--id")?;
    let modality = need(modality, "--modality")?;
    let needs = need(needs, "--needs")?;
    if runtime.is_empty() {
        return Err(ArgError::new("--runtime is required (what loads the set), once or more"));
    }
    if fits_revision.is_some() && fits_model.is_none() {
        return Err(ArgError::new("--fits-revision pins a --fits-model"));
    }
    let extract = extract.map(|raw| parse_extract(&raw)).transpose().map_err(ArgError::new)?;
    let mut license_additional = Vec::new();
    for raw in &additional {
        license_additional.push(parse_additional(raw).map_err(ArgError::new)?);
    }
    Ok(StageArgs {
        repo,
        sha,
        kind,
        id,
        modality,
        runtime,
        needs,
        license,
        license_url,
        files,
        fits_model,
        fits_revision,
        fits_runtime,
        accept_license,
        extract,
        license_additional,
    })
}

/// `<id>` or `<id>@<revision>`.
pub(crate) fn parse_target(t: &str) -> Result<(String, Option<String>), String> {
    let (id, rev) = match t.split_once('@') {
        Some((i, r)) => (i, Some(r)),
        None => (t, None),
    };
    if !model_set::id_ok(id) {
        return Err(format!("`{id}` is not a model set id (lower-case letters, digits, . _ -)"));
    }
    if let Some(r) = rev {
        if !model_set::revision_ok(r) {
            return Err(format!("`{r}` is not a usable revision"));
        }
    }
    Ok((id.to_string(), rev.map(str::to_string)))
}

pub(crate) fn parse_accept_with(a: &mut Args) -> Result<String, ArgError> {
    let t = a.one("<id>")?;
    if !model_set::id_ok(&t) {
        return Err(ArgError::new(format!("`{t}` is not a model set id")));
    }
    Ok(t)
}

pub(crate) struct RmArgs {
    pub id: String,
    pub revision: Option<String>,
    pub force: bool,
    pub yes: bool,
}

pub(crate) fn parse_rm_with(a: &mut Args) -> Result<RmArgs, ArgError> {
    let force = a.flag(&["--force"]);
    let yes = a.flag(&["--yes", "-y"]);
    let t = a.one("<id>[@<rev>]")?;
    let (id, revision) = parse_target(&t).map_err(ArgError::new)?;
    Ok(RmArgs { id, revision, force, yes })
}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) enum StageError {
    /// Hugging Face refused (401/403): a gated repo whose licence the
    /// token's account has not accepted, or no usable token.
    Gated { repo: String, status: u16, has_token: bool },
    /// The licence needs the operator's acceptance first.
    License(String),
    /// The manifest this stage would write breaks the contract.
    Invalid(model_set::Refusal),
    /// The request itself is wrong.
    Input(String),
    /// The archive named by --extract broke an extraction rule.
    Extract(String),
    /// Anything else the transfer said.
    Fetch(String),
    Io(String),
    /// The revision is already staged and signed.
    Exists(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageError::Gated { repo, status: 403, .. } => write!(
                f,
                "accept the licence for {repo} at https://huggingface.co/{repo} with the account \
                 behind this controller's HF token, then re-run"
            ),
            StageError::Gated { repo, status, has_token: false } => write!(
                f,
                "Hugging Face refused {repo} ({status}) and the controller has no HF token: store \
                 one with `noo security secrets rotate HF_TOKEN --prompt`, accept the licence at \
                 https://huggingface.co/{repo} with that account, then re-run"
            ),
            StageError::Gated { repo, status, .. } => write!(
                f,
                "Hugging Face refused this controller's HF token for {repo} ({status}): store a \
                 valid one with `noo security secrets rotate HF_TOKEN --prompt`, and accept the \
                 licence at https://huggingface.co/{repo} with that account, then re-run"
            ),
            StageError::License(m)
            | StageError::Input(m)
            | StageError::Extract(m)
            | StageError::Fetch(m)
            | StageError::Io(m)
            | StageError::Exists(m) => write!(f, "{m}"),
            StageError::Invalid(r) => write!(
                f,
                "refusing to write a manifest that breaks the model-set contract: {r}"
            ),
        }
    }
}

fn map_fetch(repo: &str, has_token: bool, e: FetchErr) -> StageError {
    match e {
        FetchErr::Auth(status) => StageError::Gated { repo: repo.to_string(), status, has_token },
        other => StageError::Fetch(format!("{repo}: {other}")),
    }
}

fn io_err(ctx: &str, e: std::io::Error) -> StageError {
    StageError::Io(format!("{ctx}: {e}"))
}

// ── The Hugging Face listing ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sibling {
    pub path: String,
    pub size: u64,
    /// Stored in LFS (the API carries an `lfs` block).
    pub lfs: bool,
    pub lfs_sha256: Option<String>,
    pub blob_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listing {
    pub gated: bool,
    pub license: Option<String>,
    pub files: Vec<Sibling>,
}

/// What `GET /api/models/<repo>/revision/<sha>?blobs=true` said. The commit it
/// answers for must be the one asked for.
pub(crate) fn read_listing(v: &Value, repo: &str, sha: &str) -> Result<Listing, StageError> {
    match v["sha"].as_str() {
        Some(got) if got == sha => {}
        Some(got) => {
            return Err(StageError::Fetch(format!(
                "{repo}: asked for commit {sha}, Hugging Face answered for {got}"
            )))
        }
        None => {
            return Err(StageError::Fetch(format!(
                "{repo}: Hugging Face's answer does not name the commit: refusing it"
            )))
        }
    }
    let gated = match &v["gated"] {
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty() && s != "false",
        _ => false,
    };
    let license = v["cardData"]["license"].as_str().map(str::to_string);
    let files: Vec<Sibling> = v["siblings"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|s| Sibling {
                    path: s["rfilename"].as_str().unwrap_or("").to_string(),
                    size: s["lfs"]["size"].as_u64().or_else(|| s["size"].as_u64()).unwrap_or(0),
                    lfs: s["lfs"].is_object(),
                    lfs_sha256: s["lfs"]["sha256"].as_str().and_then(models_fetch::sha_from_etag),
                    blob_id: s["blobId"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Listing { gated, license, files })
}

/// Which listed files go into the set: the `--file` choices, else every file
/// but `.gitattributes`. Sorted, each path within the set's path rule.
pub(crate) fn select<'a>(
    l: &'a Listing,
    wanted: &[String],
) -> Result<Vec<&'a Sibling>, StageError> {
    let mut out: Vec<&Sibling> = Vec::new();
    if wanted.is_empty() {
        out.extend(l.files.iter().filter(|s| s.path != ".gitattributes"));
    } else {
        for w in wanted {
            match l.files.iter().find(|s| s.path == *w) {
                Some(s) if out.iter().any(|o| o.path == s.path) => {
                    return Err(StageError::Input(format!("--file {w} is given twice")))
                }
                Some(s) => out.push(s),
                None => {
                    return Err(StageError::Input(format!("the repo has no file `{w}` there")))
                }
            }
        }
    }
    out.sort_by_key(|s| s.path.clone());
    if out.is_empty() {
        return Err(StageError::Input("the repo lists no files to stage".to_string()));
    }
    if let Some(bad) = out.iter().find(|s| !model_set::valid_set_path(&s.path)) {
        return Err(StageError::Input(format!(
            "`{}` cannot be in a model set (relative, at most one directory level, characters \
             A-Za-z0-9._-): choose the files with --file",
            bad.path
        )));
    }
    if out.len() > 64 {
        return Err(StageError::Input(format!(
            "{} files is more than a set holds (64): choose the files with --file",
            out.len()
        )));
    }
    Ok(out)
}

/// `weights` for an LFS file; a README, licence or notice is a `notice`;
/// any other small file is `config`.
pub(crate) fn role_of(path: &str, lfs: bool) -> &'static str {
    if lfs {
        return "weights";
    }
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let notice = ["readme", "license", "licence", "notice", "copying"];
    if notice.iter().any(|p| name.starts_with(p)) {
        "notice"
    } else {
        "config"
    }
}

// ── The manifest ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileRec {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub role: &'static str,
    /// Set when the controller extracted this file from an archive.
    pub from_archive: Option<ArchiveRef>,
}

/// The archive a file was extracted from (`files[].from_archive`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveRef {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

struct Meta<'a> {
    req: &'a StageArgs,
    license_id: &'a str,
    license_url: &'a str,
    accept: &'static str,
    accepted: Option<&'a (String, String)>,
}

fn build_manifest(m: &Meta, files: &[FileRec], needs: &Value) -> Value {
    let mut license = json!({"id": m.license_id, "url": m.license_url, "accept": m.accept});
    if let Some((by, at)) = m.accepted {
        license["accepted"] = json!({"by": by, "at": at});
    }
    let notices: Vec<&str> =
        files.iter().filter(|f| f.role == "notice").map(|f| f.path.as_str()).collect();
    if !notices.is_empty() {
        license["notice_files"] = json!(notices);
    }
    if !m.req.license_additional.is_empty() {
        let extra: Vec<Value> = m
            .req
            .license_additional
            .iter()
            .map(|a| {
                let mut v = json!({"id": a.id, "url": a.url});
                if let Some(n) = &a.notice_path {
                    v["notice_path"] = json!(n);
                }
                v
            })
            .collect();
        license["additional"] = json!(extra);
    }
    let listed: Vec<Value> = files
        .iter()
        .map(|f| {
            let mut v =
                json!({"path": f.path, "bytes": f.bytes, "sha256": f.sha256, "role": f.role});
            if let Some(a) = &f.from_archive {
                v["from_archive"] = json!({"path": a.path, "sha256": a.sha256, "bytes": a.bytes});
            }
            v
        })
        .collect();
    let mut doc = json!({
        "format": model_set::FORMAT,
        "id": m.req.id,
        "revision": m.req.sha,
        "kind": m.req.kind,
        "modality": m.req.modality,
        "runtime": m.req.runtime,
        "source": {"hf": {"repo": m.req.repo, "ref": m.req.sha, "digests": "authenticated"}},
        "license": license,
        "files": listed,
        "needs": needs,
    });
    let mut fits = Map::new();
    if let Some(model) = &m.req.fits_model {
        fits.insert("model".to_string(), json!(model));
        if let Some(rev) = &m.req.fits_revision {
            fits.insert("revision".to_string(), json!(rev));
        }
    }
    if let Some(rt) = &m.req.fits_runtime {
        fits.insert("runtime".to_string(), json!(rt));
    }
    if !fits.is_empty() {
        doc["fits"] = Value::Object(fits);
    }
    doc
}

fn manifest_bytes(doc: &Value) -> Result<Vec<u8>, StageError> {
    let mut b = serde_json::to_vec_pretty(doc)
        .map_err(|e| StageError::Io(format!("serialising the manifest: {e}")))?;
    b.push(b'\n');
    Ok(b)
}

// ── Files on disk ───────────────────────────────────────────────────────

fn mkdir(p: &Path) -> Result<(), StageError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(p).map_err(|e| io_err(&format!("creating {}", p.display()), e))?;
    // Best effort: the model-cache reads this tree as another user, and a
    // directory someone else made may not be ours to chmod.
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
    Ok(())
}

/// `.name.part`, then rename: a reader sees the whole file or none.
fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf, StageError> {
    use std::os::unix::fs::PermissionsExt;
    let part = models_fetch::part_path(dir, name);
    let dest = dir.join(name);
    std::fs::write(&part, data).map_err(|e| io_err(&format!("writing {}", part.display()), e))?;
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| io_err("setting mode 0644", e))?;
    std::fs::rename(&part, &dest)
        .map_err(|e| io_err(&format!("renaming into {}", dest.display()), e))?;
    Ok(dest)
}

// ── Signing ─────────────────────────────────────────────────────────────

/// Sign `data` with the fleet signing key into `out`: ECDSA P-384 over the
/// SHA-256 digest, DER, exactly what `openssl dgst -sha256 -sign` makes of
/// every noo-apply bundle (kiosk_seat.rs, node_fetch.rs, sign-bundle.sh).
pub(crate) fn sign_file(key: &Path, data: &Path, out: &Path) -> Result<(), String> {
    let o = Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(key)
        .arg("-out")
        .arg(out)
        .arg(data)
        .output()
        .map_err(|e| format!("could not run openssl to sign: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "openssl could not sign with {}: {}",
            key.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    match std::fs::metadata(out) {
        Ok(m) if m.len() > 0 => Ok(()),
        _ => Err(format!("openssl exited 0 but wrote no signature to {}", out.display())),
    }
}

/// `openssl dgst -sha256 -verify` of a detached signature, as noo-apply does.
pub(crate) fn verify_file(public: &Path, data: &Path, sig: &Path) -> bool {
    Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(public)
        .arg("-signature")
        .arg(sig)
        .arg(data)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Acceptance records ──────────────────────────────────────────────────

fn accepted_path(models_dir: &Path, id: &str) -> PathBuf {
    models_dir.join(SETS_DIR).join(id).join(ACCEPTED)
}

/// The `{by, at}` `noo models accept <id>` recorded, if any.
pub(crate) fn read_acceptance(models_dir: &Path, id: &str) -> Option<(String, String)> {
    let raw = std::fs::read(accepted_path(models_dir, id)).ok()?;
    let v = model_set::parse_strict(&raw).ok()?;
    let by = v["by"].as_str()?.to_string();
    let at = v["at"].as_str()?.to_string();
    if by.is_empty() || by.len() > 128 || !model_set::rfc3339(&at) {
        return None;
    }
    Some((by, at))
}

pub(crate) fn write_acceptance(
    models_dir: &Path,
    id: &str,
    by: &str,
    at: &str,
) -> Result<PathBuf, StageError> {
    let dir = models_dir.join(SETS_DIR).join(id);
    mkdir(&models_dir.join(SETS_DIR))?;
    mkdir(&dir)?;
    let body = serde_json::to_vec_pretty(&json!({"by": by, "at": at}))
        .map_err(|e| StageError::Io(format!("serialising the acceptance: {e}")))?;
    write_atomic(&dir, ACCEPTED, &body)
}

/// The operator as the audit log names them, safe to put on one log line.
pub(crate) fn clean_identity(raw: &str) -> String {
    let s: String = raw.chars().filter(|c| !c.is_control()).take(128).collect();
    if s.trim().is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

// ── Staging ─────────────────────────────────────────────────────────────

/// What a stage runs against. The token is only ever handed to
/// [`models_fetch`], which sends it to the Hugging Face origin.
pub(crate) struct Env<'a> {
    pub base: &'a str,
    pub token: Option<&'a str>,
    pub models_dir: &'a Path,
    pub by: &'a str,
    pub now: &'a str,
    pub recorded: Option<(String, String)>,
}

#[derive(Debug)]
pub(crate) struct Staged {
    pub dir: PathBuf,
    pub files: Vec<FileRec>,
    pub accept: &'static str,
    pub accepted: Option<(String, String)>,
}

impl Staged {
    pub(crate) fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.bytes).sum()
    }

    /// The `model-set.json` as written to the set dir.
    #[cfg(test)]
    pub(crate) fn manifest(&self) -> Vec<u8> {
        std::fs::read(self.dir.join(MANIFEST)).expect("the set dir holds its manifest")
    }
}

fn list_repo(env: &Env, req: &StageArgs) -> Result<Listing, StageError> {
    let url = format!(
        "{}/api/models/{}/revision/{}?blobs=true",
        env.base.trim_end_matches('/'),
        models_fetch::enc_path(&req.repo),
        req.sha
    );
    let has_token = env.token.is_some();
    let mut resp = match models_fetch::get_following(env.base, &url, env.token, 0) {
        Ok(r) => r,
        Err(FetchErr::NotFound) => {
            return Err(StageError::Fetch(format!(
                "{}: Hugging Face has no such repo or commit {} (404)",
                req.repo, req.sha
            )))
        }
        Err(e) => return Err(map_fetch(&req.repo, has_token, e)),
    };
    let st = resp.status().as_u16();
    if !(200..=299).contains(&st) {
        return Err(StageError::Fetch(format!("{}: Hugging Face API returned {st}", req.repo)));
    }
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| StageError::Fetch(format!("{}: reading the API answer: {e}", req.repo)))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|e| StageError::Fetch(format!("{}: the API answered non-JSON: {e}", req.repo)))?;
    read_listing(&v, &req.repo, &req.sha)
}

fn fetch_lfs(env: &Env, req: &StageArgs, s: &Sibling, dir: &Path) -> Result<FileRec, StageError> {
    let Some(want) = s.lfs_sha256.as_deref() else {
        return Err(StageError::Fetch(format!(
            "{}/{}: Hugging Face published no LFS sha256 for it (a gated repo hides digests \
             until its licence is accepted): refusing an unverifiable download",
            req.repo, s.path
        )));
    };
    let a = FetchArgs {
        repo: req.repo.clone(),
        file: s.path.clone(),
        revision: req.sha.clone(),
        force: false,
    };
    let mut quiet = |_: u64, _: Option<u64>| {};
    let out = models_fetch::fetch_to_store(env.base, env.token, &a, dir, &mut quiet)
        .map_err(|e| map_fetch(&req.repo, env.token.is_some(), e))?;
    if out.sha256 != want {
        return Err(StageError::Fetch(format!(
            "{}/{}: the listing says sha256 {want} but the file's own LFS metadata says {}",
            req.repo, s.path, out.sha256
        )));
    }
    Ok(FileRec {
        path: s.path.clone(),
        bytes: out.size,
        sha256: out.sha256,
        role: role_of(&s.path, true),
        from_archive: None,
    })
}

fn fetch_small(env: &Env, req: &StageArgs, s: &Sibling, dir: &Path) -> Result<FileRec, StageError> {
    let ctx = format!("{}/{}", req.repo, s.path);
    let Some(want) = s.blob_id.as_deref() else {
        return Err(StageError::Fetch(format!(
            "{ctx}: Hugging Face published no digest for it: refusing an unverifiable file"
        )));
    };
    if s.size > SMALL_MAX {
        return Err(StageError::Fetch(format!(
            "{ctx}: {} with no LFS digest cannot be verified: refusing it",
            models_fetch::human(s.size)
        )));
    }
    let a = FetchArgs {
        repo: req.repo.clone(),
        file: s.path.clone(),
        revision: req.sha.clone(),
        force: false,
    };
    let url = models_fetch::resolve_url(env.base, &a);
    let mut resp = models_fetch::get_following(env.base, &url, env.token, 0)
        .map_err(|e| map_fetch(&req.repo, env.token.is_some(), e))?;
    let st = resp.status().as_u16();
    if st != 200 {
        return Err(StageError::Fetch(format!("{ctx}: download returned HTTP {st}")));
    }
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(SMALL_MAX)
        .read_to_vec()
        .map_err(|e| StageError::Fetch(format!("{ctx}: download failed: {e}")))?;
    let got = super::voice_models::git_blob_sha1(&bytes);
    if got != want {
        return Err(StageError::Fetch(format!(
            "{ctx}: digest mismatch (Hugging Face says blob {want}, the download is {got})"
        )));
    }
    let name = s.path.rsplit('/').next().unwrap_or(&s.path);
    write_atomic(dir, name, &bytes)?;
    Ok(FileRec {
        path: s.path.clone(),
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
        role: role_of(&s.path, false),
        from_archive: None,
    })
}

/// The archive `--extract` names, from the listing of the set's own repo at
/// its pinned commit. It must be an LFS file: its sha256 then comes from the
/// authenticated Hugging Face metadata, as a weights file's does.
fn find_archive<'a>(
    listing: &'a Listing,
    req: &StageArgs,
    spec: &ExtractSpec,
) -> Result<&'a Sibling, StageError> {
    let Some(s) = listing.files.iter().find(|s| s.path == spec.archive) else {
        return Err(StageError::Input(format!(
            "--extract names `{}`, which {}@{} does not list: the archive must be a file of the \
             same repo and revision as the set",
            spec.archive,
            req.repo,
            req.sha.get(..12).unwrap_or(&req.sha)
        )));
    };
    if !s.lfs || s.lfs_sha256.is_none() {
        return Err(StageError::Input(format!(
            "--extract `{}` is not an LFS file with a published sha256: refusing an archive \
             whose digest does not come from Hugging Face's own metadata",
            spec.archive
        )));
    }
    Ok(s)
}

/// Remove the extraction work dir (a path this module named) and, when they
/// are left empty, the set's id dir and `sets/`: a refusal leaves no trace.
fn discard_work(work: &Path) {
    let _ = std::fs::remove_dir_all(work);
    if let Some(id_dir) = work.parent() {
        let _ = std::fs::remove_dir(id_dir);
        if let Some(sets) = id_dir.parent() {
            let _ = std::fs::remove_dir(sets);
        }
    }
}

/// Fetch the archive (authenticated, sha256 against the LFS metadata), then
/// extract it into `<work>/out` with the streaming caps. Any extraction
/// refusal discards `work` and returns; a failed download keeps it, so a
/// re-run resumes the partial archive. The members come back as file records
/// with their own digest and a `from_archive`; nothing is in the set yet.
fn stage_extract(
    env: &Env,
    req: &StageArgs,
    archive: &Sibling,
    spec: &ExtractSpec,
    work: &Path,
    taken: &[&Sibling],
    say: &mut dyn FnMut(&str),
) -> Result<Vec<FileRec>, StageError> {
    let adir = work.join("archive");
    mkdir(work)?;
    mkdir(&adir)?;
    say(&format!("{} ({}, to extract)", archive.path, models_fetch::human(archive.size)));
    let fetched = fetch_lfs(env, req, archive, &adir)?;
    let local = adir.join(archive.path.rsplit('/').next().unwrap_or(&archive.path));
    let out = work.join("out");
    let _ = std::fs::remove_dir_all(&out);
    let glob = spec.glob.as_deref();
    let members = match models_extract::extract(&local, glob, &out, &Limits::DEFAULT) {
        Ok(m) => m,
        Err(why) => {
            discard_work(work);
            return Err(StageError::Extract(format!("{}: {why}", spec.archive)));
        }
    };
    if let Some(m) = members.iter().find(|m| taken.iter().any(|t| t.path == m.path)) {
        discard_work(work);
        return Err(StageError::Input(format!(
            "`{}` is both a file of the repo staged as itself and a member of {}",
            m.path, spec.archive
        )));
    }
    if taken.len() + members.len() > 64 {
        discard_work(work);
        return Err(StageError::Input(format!(
            "{} files is more than a set holds (64): narrow the member glob or choose the \
             files with --file",
            taken.len() + members.len()
        )));
    }
    say(&format!("extracted {} file(s) from {}", members.len(), spec.archive));
    let from = ArchiveRef {
        path: spec.archive.clone(),
        sha256: fetched.sha256,
        bytes: fetched.bytes,
    };
    Ok(members
        .into_iter()
        .map(|m| FileRec {
            path: m.path,
            bytes: m.bytes,
            sha256: m.sha256,
            role: "weights",
            from_archive: Some(from.clone()),
        })
        .collect())
}

/// Rename every extracted member from the work dir into the set, then remove
/// the work dir (the archive goes with it). model-set.json and its signature
/// are still written after this, last.
fn place_extracted(work: &Path, set_dir: &Path, recs: &[FileRec]) -> Result<(), StageError> {
    for r in recs {
        if let Some((sub, _)) = r.path.split_once('/') {
            mkdir(&set_dir.join(sub))?;
        }
        let dest = set_dir.join(&r.path);
        std::fs::rename(work.join("out").join(&r.path), &dest)
            .map_err(|e| io_err(&format!("renaming into {}", dest.display()), e))?;
    }
    let _ = std::fs::remove_dir_all(work);
    Ok(())
}

/// Stage `req` into `<models_dir>/sets/<id>/<sha>/`: list the pinned commit,
/// settle the licence, validate the manifest BEFORE any download, fetch and
/// verify every file, write `model-set.json`, then sign it LAST.
pub(crate) fn stage_set(
    env: &Env,
    req: &StageArgs,
    needs: &Value,
    sign: &dyn Fn(&Path, &Path) -> Result<(), String>,
    say: &mut dyn FnMut(&str),
) -> Result<Staged, StageError> {
    let listing = list_repo(env, req)?;
    let mut chosen = select(&listing, &req.files)?;
    // The archive is looked up in THIS repo's listing at THIS commit, so it is
    // always the set's own repo and revision; the archive itself is not a file
    // of the set.
    let archive = match &req.extract {
        Some(spec) => {
            chosen.retain(|s| s.path != spec.archive);
            Some(find_archive(&listing, req, spec)?)
        }
        None => None,
    };

    let accept: &'static str = if listing.gated { "operator" } else { "none" };
    let accepted = if listing.gated {
        if req.accept_license {
            Some((env.by.to_string(), env.now.to_string()))
        } else if let Some(r) = &env.recorded {
            Some(r.clone())
        } else {
            return Err(StageError::License(format!(
                "the licence for {repo} needs the operator's acceptance: read it at \
                 https://huggingface.co/{repo}, then re-run with --accept-license, or run \
                 `noo models accept {id}` first",
                repo = req.repo,
                id = req.id
            )));
        }
    } else {
        if req.accept_license {
            say("this licence needs no operator acceptance; --accept-license is not recorded");
        }
        None
    };
    let license_id = match req.license.clone().or_else(|| listing.license.clone()) {
        Some(l) => l,
        None => {
            return Err(StageError::Input(
                "the model card names no licence: pass --license <id> (an SPDX-style id)"
                    .to_string(),
            ))
        }
    };
    let license_url =
        req.license_url.clone().unwrap_or_else(|| format!("https://huggingface.co/{}", req.repo));
    let meta = Meta {
        req,
        license_id: &license_id,
        license_url: &license_url,
        accept,
        accepted: accepted.as_ref(),
    };

    // The contract, checked on the real shape with placeholder digests, so a
    // bad flag or a bad needs file costs no download.
    let mut placeholder: Vec<FileRec> = chosen
        .iter()
        .map(|s| FileRec {
            path: s.path.clone(),
            bytes: s.size,
            sha256: "0".repeat(64),
            role: role_of(&s.path, s.lfs),
            from_archive: None,
        })
        .collect();
    if let Some(a) = archive {
        // One stand-in for the files the archive will give, so the manifest's
        // from_archive shape is judged before any download.
        placeholder.push(FileRec {
            path: "extracted.bin".to_string(),
            bytes: 1,
            sha256: "0".repeat(64),
            role: "weights",
            from_archive: Some(ArchiveRef {
                path: a.path.clone(),
                sha256: "0".repeat(64),
                bytes: a.size.max(1),
            }),
        });
    }
    let pre = manifest_bytes(&build_manifest(&meta, &placeholder, needs))?;
    model_set::validate(&pre).map_err(StageError::Invalid)?;

    let sets = env.models_dir.join(SETS_DIR);
    let id_dir = sets.join(&req.id);
    let set_dir = id_dir.join(&req.sha);
    if set_dir.join(SIGNATURE).exists() {
        return Err(StageError::Exists(format!(
            "{}@{} is already staged and signed at {}; revisions are immutable (to replace it, \
             `noo models rm {}@{} --force` first)",
            req.id,
            req.sha,
            set_dir.display(),
            req.id,
            req.sha
        )));
    }
    mkdir(&sets)?;
    mkdir(&id_dir)?;
    // Extraction comes first and is all-or-nothing: until every member has
    // passed, the set's own directory does not exist.
    let mut recs: Vec<FileRec> = Vec::new();
    let mut work: Option<PathBuf> = None;
    if let (Some(spec), Some(a)) = (&req.extract, archive) {
        let w = id_dir.join(format!(".extract-{}", req.sha));
        recs = stage_extract(env, req, a, spec, &w, &chosen, say)?;
        work = Some(w);
    }
    mkdir(&set_dir)?;
    if let Some(w) = &work {
        place_extracted(w, &set_dir, &recs)?;
    }

    for s in &chosen {
        let dir = match s.path.split_once('/') {
            Some((sub, _)) => {
                let d = set_dir.join(sub);
                mkdir(&d)?;
                d
            }
            None => set_dir.clone(),
        };
        say(&format!("{} ({})", s.path, models_fetch::human(s.size)));
        let rec = if s.lfs {
            fetch_lfs(env, req, s, &dir)?
        } else {
            fetch_small(env, req, s, &dir)?
        };
        recs.push(rec);
    }
    recs.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = manifest_bytes(&build_manifest(&meta, &recs, needs))?;
    model_set::validate(&manifest).map_err(StageError::Invalid)?;
    let manifest_path = write_atomic(&set_dir, MANIFEST, &manifest)?;

    // The signature goes last: until it exists the set does not exist.
    let sig_part = models_fetch::part_path(&set_dir, SIGNATURE);
    sign(&manifest_path, &sig_part).map_err(StageError::Io)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sig_part, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| io_err("setting mode 0644 on the signature", e))?;
    }
    let sig_path = set_dir.join(SIGNATURE);
    std::fs::rename(&sig_part, &sig_path)
        .map_err(|e| io_err(&format!("renaming into {}", sig_path.display()), e))?;

    Ok(Staged { dir: set_dir, files: recs, accept, accepted })
}

/// The human lines for a finished stage.
pub(crate) fn render(req: &StageArgs, s: &Staged) -> Vec<String> {
    let mut out = vec![format!(
        "{}@{}: {} file(s), {}, signed",
        req.id,
        req.sha.get(..12).unwrap_or(&req.sha),
        s.files.len(),
        models_fetch::human(s.bytes())
    )];
    out.push(format!("source: hf:{}@{} (digests authenticated)", req.repo, req.sha));
    out.push(match &s.accepted {
        Some((by, at)) => format!("licence: operator-accepted by {by} at {at}"),
        None => "licence: no operator acceptance required".to_string(),
    });
    let extracted = s.files.iter().filter(|f| f.from_archive.is_some()).count();
    if extracted > 0 {
        out.push(format!("extracted: {extracted} file(s) from an archive of the same commit"));
    }
    out.push(format!("dir: {}", s.dir.display()));
    out
}

// ── Listing ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub id: String,
    pub revision: String,
    pub kind: String,
    pub digests: String,
    pub license: String,
    pub bytes: u64,
    pub signature: &'static str,
    pub problem: Option<String>,
}

fn sorted_dirs(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let hidden = p
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'));
                    p.is_dir() && !hidden
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn name_of(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

fn license_cell(v: &Value) -> String {
    let lic = &v["license"];
    match lic["accept"].as_str() {
        Some("none") => "not required".to_string(),
        Some("operator") => match (lic["accepted"]["by"].as_str(), lic["accepted"]["at"].as_str()) {
            (Some(by), Some(at)) => format!("{by} {at}"),
            _ => "NOT ACCEPTED".to_string(),
        },
        _ => "?".to_string(),
    }
}

fn digests_cell(v: &Value) -> String {
    let src = &v["source"];
    if let Some(d) = src["hf"]["digests"].as_str() {
        return d.to_string();
    }
    match src["local"]["verified"].as_bool() {
        Some(true) => "local-verified".to_string(),
        Some(false) => "local-unverified".to_string(),
        None => "?".to_string(),
    }
}

/// Every signed set under `<models_dir>/sets`, optionally of one kind. A set
/// with no signature file is not listed. `public` is the fleet `signing.pub`.
pub(crate) fn scan(models_dir: &Path, public: &Path, kind: Option<&str>) -> Vec<Row> {
    let mut rows = Vec::new();
    for id_dir in sorted_dirs(&models_dir.join(SETS_DIR)) {
        for rev_dir in sorted_dirs(&id_dir) {
            let sig = rev_dir.join(SIGNATURE);
            if !sig.is_file() {
                continue;
            }
            let (id, revision) = (name_of(&id_dir), name_of(&rev_dir));
            let path = rev_dir.join(MANIFEST);
            let signature = if !public.is_file() {
                "no signing.pub"
            } else if verify_file(public, &path, &sig) {
                "ok"
            } else {
                "bad"
            };
            let bytes = std::fs::read(&path).unwrap_or_default();
            let mut problem = model_set::validate(&bytes).err().map(|r| r.to_string());
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let misfiled = v["id"] != id.as_str() || v["revision"] != revision.as_str();
            if problem.is_none() && misfiled {
                problem = Some("the manifest names another id or revision than its dir".into());
            }
            let row_kind = v["kind"].as_str().unwrap_or("?").to_string();
            if problem.is_none() && kind.is_some_and(|k| k != row_kind) {
                continue;
            }
            let size: u64 = v["files"]
                .as_array()
                .map(|a| a.iter().filter_map(|f| f["bytes"].as_u64()).sum::<u64>())
                .unwrap_or(0);
            rows.push(Row {
                id,
                revision,
                kind: row_kind,
                digests: digests_cell(&v),
                license: license_cell(&v),
                bytes: size,
                signature,
                problem,
            });
        }
    }
    rows
}

fn row_json(r: &Row) -> Value {
    json!({
        "id": r.id, "revision": r.revision, "kind": r.kind, "digests": r.digests,
        "license": r.license, "bytes": r.bytes, "signature": r.signature, "problem": r.problem,
    })
}

/// `noo models list --kind voice|voice-pack`.
pub(crate) fn list_sets(g: &Globals, kind: &str) -> Result<i32, Unhandled> {
    if kind != "voice" && kind != "voice-pack" {
        let why = format!("--kind is voice or voice-pack, not `{kind}`");
        fail(g.json, ExitCode::Usage, "bad_kind", &why, None);
    }
    let dir = PathBuf::from(models_fetch::controller_store_dir());
    let public = crate::pki::ClusterCa::new(crate::pki::pki_dir()).signing_pub_path();
    let rows = scan(&dir, &public, Some(kind));
    if g.json {
        let arr: Vec<Value> = rows.iter().map(row_json).collect();
        println!("{}", json!({"kind": kind, "sets": arr}));
        return Ok(0);
    }
    println!("{}", ui::header("model sets", Some(&format!("{kind} in {}", dir.display()))));
    if rows.is_empty() {
        println!("{}", ui::muted("no signed model sets of this kind are staged"));
        return Ok(0);
    }
    let cols = [
        ui::Col::left("id"),
        ui::Col::left("revision"),
        ui::Col::left("kind"),
        ui::Col::left("digests"),
        ui::Col::left("licence accepted"),
        ui::Col::right("size"),
        ui::Col::left("signature"),
        ui::Col::left("problem"),
    ];
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.id.clone(),
                r.revision.get(..12).unwrap_or(&r.revision).to_string(),
                r.kind.clone(),
                r.digests.clone(),
                r.license.clone(),
                models_fetch::human(r.bytes),
                r.signature.to_string(),
                r.problem.clone().unwrap_or_default(),
            ]
        })
        .collect();
    print!("{}", ui::table(&cols, &cells));
    for r in rows.iter().filter(|r| r.signature == "bad") {
        let (id, rev) = (&r.id, &r.revision);
        ui::warned(&format!("{id}@{rev}: the signature does NOT verify; do not place it"));
    }
    Ok(0)
}

// ── Commands ────────────────────────────────────────────────────────────

fn audit(line: &str) {
    let root = crate::envfile::repo_root();
    if let Err(e) = super::secrets_reveal::write_audit(&root, line) {
        eprintln!("{}", ui::note(&format!("could not append to the audit log: {e}")));
    }
}

fn read_needs(path: &str) -> Result<Value, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read --needs {path}: {e}"))?;
    let v = model_set::parse_strict(&raw).map_err(|r| format!("--needs {path}: {r}"))?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(format!("--needs {path}: expected a JSON object"))
    }
}

/// `noo models stage hf:<repo>@<sha> --kind ... --id ... --needs <file.json>`
pub fn models_stage(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let req = parse_stage_with(&mut Args::new(args))?;
    let needs = match read_needs(&req.needs) {
        Ok(v) => v,
        Err(e) => fail(
            g.json,
            ExitCode::Usage,
            "bad_needs",
            &e,
            Some("--needs holds profiles, cpu_fallback and arch (noo-model-set-1.schema.json)"),
        ),
    };
    let rerun = "noo models stage <hf:repo@sha> --kind <kind> --id <id>";
    let (_store, dir) = models_fetch::writable_store(g, rerun);

    // The signing key is checked before any download, not after it.
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    if let Err(e) = ca.ensure_signing_key() {
        let why = format!("no fleet signing key: {e}");
        fail(g.json, ExitCode::Generic, "signing_key", &why, None);
    }
    let key = ca.signing_key_path();
    if let Err(e) = std::fs::File::open(&key) {
        fail(
            g.json,
            ExitCode::Generic,
            "signing_key_unreadable",
            &format!("cannot read the fleet signing key {}: {e}", key.display()),
            Some("run as the user that owns the controller's PKI directory"),
        );
    }

    let base = match models_fetch::hf_base() {
        Ok(b) => b,
        Err(why) => {
            let remedy = crate::catalog::HF_ENDPOINT_REMEDY;
            fail(g.json, ExitCode::Usage, "hf_endpoint_refused", &why, Some(remedy))
        }
    };
    let token = models_fetch::hf_token();
    let by = clean_identity(&super::secrets_reveal::whoami());
    let now = super::secrets_reveal::now_rfc3339();
    let env = Env {
        base: &base,
        token: token.as_deref(),
        models_dir: &dir,
        by: &by,
        now: &now,
        recorded: read_acceptance(&dir, &req.id),
    };
    if !g.json {
        println!("{}", ui::header("models stage", Some(&format!("hf:{}@{}", req.repo, req.sha))));
        let token_note = if token.is_some() { "from the controller's secrets" } else { "none" };
        print!("{}", ui::kv(&[
            ("set", format!("{} ({})", req.id, req.kind)),
            ("token", token_note.to_string()),
        ]));
    }
    let sign = |data: &Path, out: &Path| sign_file(&key, data, out);
    let mut say = |line: &str| {
        if !g.json {
            ui::step(line);
        }
    };
    let staged = match stage_set(&env, &req, &needs, &sign, &mut say) {
        Ok(s) => s,
        Err(e) => {
            let (code, exit) = match &e {
                StageError::Gated { .. } => ("gated_repo", ExitCode::RemoteError),
                StageError::License(_) => ("license_not_accepted", ExitCode::Generic),
                StageError::Invalid(_) => ("invalid_manifest", ExitCode::Usage),
                StageError::Input(_) => ("bad_request", ExitCode::Usage),
                StageError::Extract(_) => ("extract_refused", ExitCode::Usage),
                StageError::Exists(_) => ("already_staged", ExitCode::Generic),
                StageError::Fetch(_) => ("fetch_failed", ExitCode::RemoteError),
                StageError::Io(_) => ("stage_failed", ExitCode::Generic),
            };
            let hint = match &e {
                StageError::Fetch(_) | StageError::Io(_) => {
                    Some("re-run the same command: verified files are kept, partials resume")
                }
                _ => None,
            };
            fail(g.json, exit, code, &e.to_string(), hint);
        }
    };

    audit(&format!(
        "{now} model_set_staged id={} revision={} repo={} by={by}",
        req.id, req.sha, req.repo
    ));
    if let Some((aby, at)) = &staged.accepted {
        audit(&format!(
            "{now} model_license_accepted id={} repo={} by={aby} at={at}",
            req.id, req.repo
        ));
    }
    if g.json {
        let files: Vec<Value> = staged
            .files
            .iter()
            .map(|f| {
                let mut v =
                    json!({"path": f.path, "bytes": f.bytes, "sha256": f.sha256, "role": f.role});
                if let Some(a) = &f.from_archive {
                    let from = json!({"path": a.path, "sha256": a.sha256, "bytes": a.bytes});
                    v["from_archive"] = from;
                }
                v
            })
            .collect();
        let accepted = staged.accepted.as_ref().map(|(b, a)| json!({"by": b, "at": a}));
        println!("{}", json!({
            "id": req.id,
            "revision": req.sha,
            "kind": req.kind,
            "dir": staged.dir.display().to_string(),
            "digests": "authenticated",
            "license_accept": staged.accept,
            "accepted": accepted,
            "files": files,
        }));
        return Ok(0);
    }
    let lines = render(&req, &staged);
    if let Some((first, rest)) = lines.split_first() {
        ui::done(first);
        for l in rest {
            println!("{}", ui::sub(l));
        }
    }
    let list_cmd = format!("noo models list --kind {}", req.kind);
    ui::guide(&[(list_cmd.as_str(), "show it with its signature check")]);
    Ok(0)
}

/// `noo models accept <id>`: record the operator's acceptance for later staging.
pub fn models_accept(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let id = parse_accept_with(&mut Args::new(args))?;
    let (_store, dir) = models_fetch::writable_store(g, "noo models accept <id>");
    let by = clean_identity(&super::secrets_reveal::whoami());
    let now = super::secrets_reveal::now_rfc3339();
    if !model_set::rfc3339(&now) {
        let why = "could not read the clock to date the acceptance";
        fail(g.json, ExitCode::Generic, "no_clock", why, None);
    }
    if let Err(e) = write_acceptance(&dir, &id, &by, &now) {
        fail(g.json, ExitCode::Generic, "accept_failed", &e.to_string(), None);
    }
    audit(&format!("{now} model_license_accepted id={id} by={by}"));
    if g.json {
        println!("{}", json!({"id": id, "accepted": {"by": by, "at": now}}));
        return Ok(0);
    }
    ui::done(&format!("recorded: {by} accepts the licence of {id} at {now}"));
    let note = "the licence text is upstream's: read it before staging; the next stage uses this";
    println!("{}", ui::muted(note));
    Ok(0)
}

/// Which nodes place a set. The gateway does not know model sets until the
/// placement side of i300 (H) lands, so there is nothing to ask yet.
// TODO(i300-H): ask the gateway for the placements that reference this set.
fn placements_referencing(_id: &str, _revision: Option<&str>) -> Result<Vec<String>, String> {
    Err("the gateway does not track model-set placements yet (i300 H)".to_string())
}

/// `noo models rm <id>[@<rev>] --force`
pub fn models_rm(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_rm_with(&mut Args::new(args))?;
    let dir = PathBuf::from(models_fetch::controller_store_dir());
    let id_dir = dir.join(SETS_DIR).join(&a.id);
    let targets: Vec<PathBuf> = match &a.revision {
        Some(r) => vec![id_dir.join(r)],
        None => sorted_dirs(&id_dir),
    };
    let targets: Vec<PathBuf> = targets.into_iter().filter(|p| p.is_dir()).collect();
    if targets.is_empty() {
        let why = format!("no staged model set {} under {}", a.id, id_dir.display());
        fail(g.json, ExitCode::Generic, "no_such_set", &why, None);
    }
    match placements_referencing(&a.id, a.revision.as_deref()) {
        Ok(nodes) if !nodes.is_empty() => fail(
            g.json,
            ExitCode::Generic,
            "set_in_use",
            &format!("{} is placed on: {}", a.id, nodes.join(", ")),
            Some("unplace it first"),
        ),
        Ok(_) => {}
        Err(why) if !a.force => fail(
            g.json,
            ExitCode::Generic,
            "placement_unknown",
            &format!("cannot tell whether a node uses {}: {why}", a.id),
            Some("once you know no node places it, re-run with --force"),
        ),
        Err(_) => {}
    }
    let names: Vec<String> = targets.iter().map(|p| p.display().to_string()).collect();
    let what = format!("the staged model set at {}", names.join(", "));
    super::confirm_destructive(g, a.yes, "Remove", &what);
    for t in &targets {
        // The signature first: from that moment the set no longer exists to `list`.
        let _ = std::fs::remove_file(t.join(SIGNATURE));
        if let Err(e) = std::fs::remove_dir_all(t) {
            let why = format!("removing {}: {e}", t.display());
            fail(g.json, ExitCode::Generic, "rm_failed", &why, None);
        }
    }
    // Only succeeds when nothing (not even an acceptance record) is left.
    let _ = std::fs::remove_dir(&id_dir);
    let by = clean_identity(&super::secrets_reveal::whoami());
    let now = super::secrets_reveal::now_rfc3339();
    for t in &targets {
        audit(&format!("{now} model_set_removed id={} revision={} by={by}", a.id, name_of(t)));
    }
    if g.json {
        println!("{}", json!({"id": a.id, "removed": names}));
    } else {
        ui::done(&format!("removed {} ({} revision(s))", a.id, targets.len()));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const REPO: &str = "test-org/test-voice";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-model-sets-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A token-shaped string: `hf_` and 34 alphanumerics.
    fn fake_token() -> String {
        format!("hf_{}", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3f".chars().take(34).collect::<String>())
    }

    /// `hf_` followed by 30 or more alphanumerics, anywhere in `text`.
    fn token_shaped(text: &str) -> bool {
        let mut from = 0;
        while let Some(p) = text[from..].find("hf_") {
            let start = from + p + 3;
            let run = text[start..].bytes().take_while(|c| c.is_ascii_alphanumeric()).count();
            if run >= 30 {
                return true;
            }
            from = start;
        }
        false
    }

    #[test]
    fn the_token_shape_check_sees_a_token_and_only_a_token() {
        let t = fake_token();
        assert_eq!(t.len(), 37);
        assert!(token_shaped(&t));
        assert!(token_shaped(&format!("Authorization: Bearer {t} ok")));
        assert!(!token_shaped("hf_short"));
        assert!(!token_shaped("test-org/test-voice 0123456789abcdef0123456789abcdef01234567"));
    }

    // ── a fake Hugging Face ──────────────────────────────────────────────

    struct Resp {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn resp(status: u16, body: &[u8]) -> Resp {
        Resp { status, headers: Vec::new(), body: body.to_vec() }
    }

    /// (method, path, the Authorization header value if sent)
    type Seen = Vec<(String, String, Option<String>)>;

    struct Fake {
        base: String,
        seen: Arc<Mutex<Seen>>,
    }

    fn serve(handler: impl Fn(&str, &str) -> Resp + Send + 'static) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming().take(256) {
                let Ok(mut st) = stream else { continue };
                let mut rd = BufReader::new(st.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut auth = None;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if h.to_ascii_lowercase().starts_with("authorization:") {
                        auth = h.split_once(':').map(|(_, v)| v.trim().to_string());
                    }
                }
                seen2.lock().unwrap().push((method.clone(), path.clone(), auth));
                let r = handler(&method, &path);
                let mut head = format!("HTTP/1.1 {} X\r\n", r.status);
                for (k, v) in &r.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                let n = r.body.len();
                head.push_str(&format!("Content-Length: {n}\r\nConnection: close\r\n\r\n"));
                let _ = st.write_all(head.as_bytes());
                if method != "HEAD" {
                    let _ = st.write_all(&r.body);
                }
            }
        });
        Fake { base, seen }
    }

    fn sha256_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn weights() -> Vec<u8> {
        (0..3000u32).map(|i| (i % 251) as u8).collect()
    }

    const README: &[u8] = b"# test voice\nlicensed as stated upstream\n";
    const CONFIG: &[u8] = b"sample_rate=24000\n";

    /// The repo's API answer; `gated` is the JSON text of the gated field.
    fn api_body(gated: &Value) -> Vec<u8> {
        let w = weights();
        let blob = crate::commands::voice_models::git_blob_sha1;
        let doc = json!({
            "sha": SHA,
            "gated": gated,
            "cardData": {"license": "apache-2.0"},
            "siblings": [
                {"rfilename": ".gitattributes", "size": 10, "blobId": "1".repeat(40)},
                {"rfilename": "README.md", "size": README.len(), "blobId": blob(README)},
                {"rfilename": "config.json", "size": CONFIG.len(), "blobId": blob(CONFIG)},
                {
                    "rfilename": "weights.bin",
                    "size": w.len(),
                    "blobId": "2".repeat(40),
                    "lfs": {"sha256": sha256_hex(&w), "size": w.len(), "pointerSize": 134},
                },
            ],
        });
        doc.to_string().into_bytes()
    }

    fn hf(gated: Value) -> Fake {
        serve(move |method, path| {
            let w = weights();
            if path.starts_with(&format!("/api/models/{REPO}/revision/{SHA}")) {
                return resp(200, &api_body(&gated));
            }
            let resolve = format!("/{REPO}/resolve/{SHA}/");
            match path.strip_prefix(resolve.as_str()) {
                Some("README.md") => resp(200, README),
                Some("config.json") => resp(200, CONFIG),
                Some("weights.bin") => {
                    let mut r = resp(302, b"");
                    r.headers.push(("Location".into(), "/cdn/weights.bin".into()));
                    r.headers.push(("x-linked-etag".into(), format!("\"{}\"", sha256_hex(&w))));
                    r.headers.push(("x-linked-size".into(), w.len().to_string()));
                    r
                }
                _ if path == "/cdn/weights.bin" && method == "GET" => resp(200, &w),
                _ => resp(404, b""),
            }
        })
    }

    fn denied(status: u16) -> Fake {
        serve(move |_, _| resp(status, b"gated"))
    }

    fn needs() -> Value {
        json!({
            "profiles": [{"name": "gpu", "accel": "cuda", "vram_mb": 4096, "realtime": true}],
            "cpu_fallback": false,
            "arch": ["amd64"],
        })
    }

    fn request(kind: &str) -> StageArgs {
        let mut a = s(&[
            "--kind", kind, "--id", "test-voice-set", "--modality", "tts", "--runtime", "test-rt",
            "--needs", "needs.json",
        ]);
        if kind == "voice-pack" {
            a.extend(s(&["--fits-runtime", "test-rt"]));
        }
        a.push(format!("hf:{REPO}@{SHA}"));
        parse_stage_with(&mut Args::new(&a)).expect("parses")
    }

    fn fake_sign(_data: &Path, out: &Path) -> Result<(), String> {
        std::fs::write(out, b"signature").map_err(|e| e.to_string())
    }

    fn run(
        f: &Fake,
        token: Option<&str>,
        dir: &Path,
        req: &StageArgs,
        recorded: Option<(String, String)>,
    ) -> (Result<Staged, StageError>, Vec<String>) {
        let env = Env {
            base: &f.base,
            token,
            models_dir: dir,
            by: "alice",
            now: "2026-11-05T10:00:00Z",
            recorded,
        };
        let mut lines = Vec::new();
        let mut say = |l: &str| lines.push(l.to_string());
        let r = stage_set(&env, req, &needs(), &fake_sign, &mut say);
        (r, lines)
    }

    // ── arguments ────────────────────────────────────────────────────────

    #[test]
    fn a_branch_name_is_not_a_pin() {
        let e = parse_spec("hf:test-org/test-voice@main").expect_err("branch");
        assert!(e.contains("40-hex"), "{e}");
        assert!(parse_spec("hf:test-org/test-voice").is_err());
        assert!(parse_spec(&format!("local:/tmp/x@{SHA}")).is_err());
        let upper = format!("hf:{REPO}@{}", SHA.to_ascii_uppercase());
        assert!(parse_spec(&upper).is_err());
        let ok = parse_spec(&format!("hf:{REPO}@{SHA}")).unwrap();
        assert_eq!(ok, (REPO.to_string(), SHA.to_string()));
    }

    #[test]
    fn stage_arguments_name_what_is_missing() {
        let spec = format!("hf:{REPO}@{SHA}");
        let e = parse_stage_with(&mut Args::new(&s(&[spec.as_str()]))).expect_err("no flags");
        assert!(e.0.contains("--kind"), "{e}");
        let bad_kind = s(&[spec.as_str(), "--kind", "stt", "--id", "x"]);
        let e = parse_stage_with(&mut Args::new(&bad_kind)).expect_err("kind");
        assert!(e.0.contains("voice"), "{e}");
        let no_spec = s(&["--kind", "voice", "--id", "x"]);
        let e = parse_stage_with(&mut Args::new(&no_spec)).expect_err("spec");
        assert!(e.0.contains("hf:"), "{e}");
    }

    #[test]
    fn targets_and_clean_identities() {
        assert_eq!(parse_target("a-set").unwrap(), ("a-set".to_string(), None));
        let pinned = ("a-set".to_string(), Some("rev1".to_string()));
        assert_eq!(parse_target("a-set@rev1").unwrap(), pinned);
        for bad in ["A", "a@..", "../x"] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
        assert_eq!(clean_identity("al\nice"), "alice");
        assert_eq!(clean_identity(" "), "unknown");
        assert_eq!(clean_identity(&"x".repeat(300)).len(), 128);
    }

    // ── staging ──────────────────────────────────────────────────────────

    #[test]
    fn staging_writes_the_files_then_a_valid_manifest_then_the_signature() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("stage-ok");
        let f = hf(json!(false));
        let (r, lines) = run(&f, None, &dir, &request("voice"), None);
        let staged = r.expect("staged");
        let set = dir.join("sets/test-voice-set").join(SHA);
        assert_eq!(staged.dir, set);
        for name in ["weights.bin", "README.md", "config.json", MANIFEST, SIGNATURE] {
            let md = std::fs::metadata(set.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(md.permissions().mode() & 0o777, 0o644, "{name}");
        }
        assert!(!set.join(".gitattributes").exists());
        let manifest = std::fs::read(set.join(MANIFEST)).unwrap();
        assert_eq!(manifest, staged.manifest());
        model_set::validate(&manifest).expect("the written manifest is valid");
        let v: Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(v["source"]["hf"]["digests"], "authenticated");
        assert_eq!(v["source"]["hf"]["ref"], SHA);
        assert_eq!(v["license"]["accept"], "none");
        assert!(v.get("trust").is_none() && v["license"].get("accepted").is_none());
        let roles: Vec<(&str, &str)> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| (x["path"].as_str().unwrap(), x["role"].as_str().unwrap()))
            .collect();
        let want = [("README.md", "notice"), ("config.json", "config"), ("weights.bin", "weights")];
        assert_eq!(roles, want);
        assert_eq!(v["license"]["notice_files"], json!(["README.md"]));
        assert_eq!(v["files"][2]["sha256"], sha256_hex(&weights()));
        assert_eq!(lines.len(), 3, "{lines:?}");
        // No part file is left behind.
        let left: Vec<String> = std::fs::read_dir(&set)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".part"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_second_stage_of_the_same_revision_is_refused() {
        let dir = tmpdir("stage-twice");
        let f = hf(json!(false));
        assert!(run(&f, None, &dir, &request("voice"), None).0.is_ok());
        let e = run(&f, None, &dir, &request("voice"), None).0.expect_err("twice");
        assert!(matches!(e, StageError::Exists(_)), "{e}");
    }

    #[test]
    fn a_voice_pack_without_what_it_fits_is_refused_before_any_download() {
        let dir = tmpdir("stage-pack");
        let f = hf(json!(false));
        let mut req = request("voice-pack");
        req.fits_runtime = None;
        let e = run(&f, None, &dir, &req, None).0.expect_err("no fits");
        match e {
            StageError::Invalid(r) => assert_eq!(r.code, "fits_required"),
            other => panic!("{other}"),
        }
        let gets: Vec<String> = f.seen.lock().unwrap().iter().map(|r| r.1.clone()).collect();
        let listing_only = gets.iter().all(|p| p.starts_with("/api/"));
        assert!(listing_only, "downloaded before refusing: {gets:?}");
        assert!(!dir.join("sets/test-voice-set").join(SHA).exists());
        let dir_ok = tmpdir("stage-pack-ok");
        let ok = run(&f, None, &dir_ok, &request("voice-pack"), None).0.expect("pack");
        assert_eq!(ok.files.len(), 3);
    }

    #[test]
    fn a_gated_licence_waits_for_the_operator_and_is_recorded_with_who_and_when() {
        let dir = tmpdir("stage-gated");
        let f = hf(json!("manual"));
        let e = run(&f, None, &dir, &request("voice"), None).0.expect_err("not accepted");
        assert!(matches!(e, StageError::License(_)), "{e}");
        let msg = e.to_string();
        assert!(msg.contains("--accept-license"), "{msg}");
        assert!(msg.contains("noo models accept test-voice-set"), "{msg}");
        let n = f.seen.lock().unwrap().len();
        assert_eq!(n, 1, "only the listing was fetched");
        assert!(!dir.join("sets/test-voice-set").join(SHA).exists());

        let mut req = request("voice");
        req.accept_license = true;
        let st = run(&f, None, &dir, &req, None).0.expect("accepted by flag");
        let v: Value = serde_json::from_slice(&st.manifest()).unwrap();
        assert_eq!(v["license"]["accept"], "operator");
        assert_eq!(v["license"]["accepted"], json!({"by": "alice", "at": "2026-11-05T10:00:00Z"}));

        let dir2 = tmpdir("stage-gated-recorded");
        let rec = Some(("bob".to_string(), "2026-10-01T00:00:00Z".to_string()));
        let st = run(&f, None, &dir2, &request("voice"), rec).0.expect("accepted by record");
        let v: Value = serde_json::from_slice(&st.manifest()).unwrap();
        assert_eq!(v["license"]["accepted"], json!({"by": "bob", "at": "2026-10-01T00:00:00Z"}));
    }

    #[test]
    fn an_acceptance_is_recorded_and_read_back() {
        let dir = tmpdir("accept");
        assert_eq!(read_acceptance(&dir, "test-voice-set"), None);
        write_acceptance(&dir, "test-voice-set", "carol", "2026-11-05T11:12:13Z").expect("written");
        assert_eq!(
            read_acceptance(&dir, "test-voice-set"),
            Some(("carol".to_string(), "2026-11-05T11:12:13Z".to_string()))
        );
        // A set listing never mistakes the record for a set.
        let rows = scan(&dir, &dir.join("no-such.pub"), Some("voice"));
        assert!(rows.is_empty());
    }

    // ── the token ────────────────────────────────────────────────────────

    #[test]
    fn the_token_goes_to_hugging_face_and_appears_nowhere_we_write_or_say() {
        let token = fake_token();
        let dir = tmpdir("token-ok");
        let f = hf(json!("manual"));
        let mut req = request("voice");
        req.accept_license = true;
        let (r, lines) = run(&f, Some(token.as_str()), &dir, &req, None);
        let staged = r.expect("staged");

        // It WAS sent, to the Hugging Face origin (the fake is the base).
        let seen = f.seen.lock().unwrap();
        let sent: Vec<Option<String>> = seen.iter().map(|r| r.2.clone()).collect();
        assert!(sent.iter().any(|a| a.as_deref() == Some(format!("Bearer {token}").as_str())));

        // ... and it is in nothing the command wrote or printed.
        let manifest = String::from_utf8(staged.manifest()).unwrap();
        let mut said = lines.clone();
        said.extend(render(&req, &staged));
        let mut everything = vec![manifest, format!("{staged:?}")];
        everything.extend(said);
        let set = dir.join("sets/test-voice-set").join(SHA);
        for name in [MANIFEST, SIGNATURE, "README.md", "config.json"] {
            let on_disk = std::fs::read(set.join(name)).unwrap();
            everything.push(String::from_utf8_lossy(&on_disk).to_string());
        }
        for text in &everything {
            assert!(!text.contains(&token), "the token leaked into: {text}");
            assert!(!token_shaped(text), "a token-shaped string in: {text}");
        }
    }

    #[test]
    fn a_gated_403_is_one_clear_line_and_never_leaks_the_token() {
        let token = fake_token();
        let f = denied(403);
        let dir = tmpdir("token-403");
        let (r, lines) = run(&f, Some(token.as_str()), &dir, &request("voice"), None);
        let e = r.expect_err("403");
        let want = format!(
            "accept the licence for {REPO} at https://huggingface.co/{REPO} with the account \
             behind this controller's HF token, then re-run"
        );
        assert_eq!(e.to_string(), want);
        assert!(matches!(e, StageError::Gated { status: 403, .. }), "{e:?}");
        for text in [e.to_string(), format!("{e:?}"), lines.join("\n")] {
            assert!(!text.contains(&token) && !token_shaped(&text), "leak in: {text}");
        }
        assert!(!dir.join("sets").exists(), "nothing is written for a refused repo");
    }

    #[test]
    fn a_401_without_a_token_says_to_store_one() {
        let f = denied(401);
        let e = run(&f, None, &tmpdir("token-401"), &request("voice"), None).0.expect_err("401");
        let m = e.to_string();
        assert!(m.contains("no HF token"), "{m}");
        assert!(m.contains(&format!("https://huggingface.co/{REPO}")), "{m}");
        assert!(!m.contains("403"));
    }

    #[test]
    fn the_stage_code_has_no_subprocess_that_could_carry_the_token() {
        let own = crate::test_src::own_code(include_str!("models_sets.rs"));
        let stage = crate::test_src::fn_body(&own, "pub(crate) fn stage_set(");
        assert!(!stage.contains("Command::"), "stage_set must not spawn a process");
        assert!(!stage.contains("println!") && !stage.contains("eprintln!"));
        // The only processes here are openssl, and they take paths, never the token.
        for body in [
            crate::test_src::fn_body(&own, "pub(crate) fn sign_file("),
            crate::test_src::fn_body(&own, "pub(crate) fn verify_file("),
        ] {
            assert!(!body.contains("token"), "{body}");
        }
    }

    // ── listing and signing ──────────────────────────────────────────────

    fn openssl_keys(dir: &Path) -> Option<(PathBuf, PathBuf)> {
        let key = dir.join("signing.key");
        let public = dir.join("signing.pub");
        let made = Command::new("openssl")
            .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out"])
            .arg(&key)
            .output()
            .ok()?;
        if !made.status.success() {
            return None;
        }
        let out = Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(&key)
            .arg("-out")
            .arg(&public)
            .output()
            .ok()?;
        out.status.success().then_some((key, public))
    }

    #[test]
    fn list_shows_only_signed_sets_and_catches_a_bad_signature() {
        let dir = tmpdir("list");
        let Some((key, public)) = openssl_keys(&dir) else {
            eprintln!("openssl is not available: skipping the signature round trip");
            return;
        };
        let f = hf(json!(false));
        let env = Env {
            base: &f.base,
            token: None,
            models_dir: &dir,
            by: "alice",
            now: "2026-11-05T10:00:00Z",
            recorded: None,
        };
        let sign = |data: &Path, out: &Path| sign_file(&key, data, out);
        let req = request("voice");
        stage_set(&env, &req, &needs(), &sign, &mut |_: &str| {}).expect("staged and signed");

        let rows = scan(&dir, &public, Some("voice"));
        assert_eq!(rows.len(), 1, "{rows:?}");
        let r = &rows[0];
        assert_eq!(r.id, "test-voice-set");
        assert_eq!((r.revision.as_str(), r.kind.as_str()), (SHA, "voice"));
        assert_eq!(r.digests, "authenticated");
        assert_eq!((r.license.as_str(), r.signature), ("not required", "ok"));
        assert_eq!(r.bytes, weights().len() as u64 + README.len() as u64 + CONFIG.len() as u64);
        assert_eq!(r.problem, None);
        assert!(scan(&dir, &public, Some("voice-pack")).is_empty(), "a kind filter filters");

        // A set with no signature does not exist.
        let set = dir.join("sets/test-voice-set").join(SHA);
        let sig = std::fs::read(set.join(SIGNATURE)).unwrap();
        std::fs::remove_file(set.join(SIGNATURE)).unwrap();
        assert!(scan(&dir, &public, Some("voice")).is_empty());
        std::fs::write(set.join(SIGNATURE), &sig).unwrap();

        // A manifest changed after signing is bad.
        let manifest = std::fs::read_to_string(set.join(MANIFEST)).unwrap();
        std::fs::write(set.join(MANIFEST), manifest.replace("apache-2.0", "mit")).unwrap();
        assert_eq!(scan(&dir, &public, Some("voice"))[0].signature, "bad");
        // And with no public key to check against, it is not called ok.
        let unchecked = scan(&dir, &dir.join("absent.pub"), Some("voice"));
        assert_eq!(unchecked[0].signature, "no signing.pub");
    }

    // ── --extract and --license-additional ───────────────────────────────

    use crate::commands::models_extract::testkit::{file, gz, other, tar};

    /// A fake Hugging Face whose repo holds README.md and one archive,
    /// `voices.tgz`, an LFS file when `lfs` is set.
    fn hf_archive(archive: Vec<u8>, lfs: bool) -> Fake {
        serve(move |method, path| {
            if path.starts_with(&format!("/api/models/{REPO}/revision/{SHA}")) {
                let blob = crate::commands::voice_models::git_blob_sha1;
                let mut arch = json!({
                    "rfilename": "voices.tgz",
                    "size": archive.len(),
                    "blobId": "3".repeat(40),
                });
                if lfs {
                    arch["lfs"] = json!({
                        "sha256": sha256_hex(&archive),
                        "size": archive.len(),
                        "pointerSize": 134,
                    });
                }
                let doc = json!({
                    "sha": SHA,
                    "gated": false,
                    "cardData": {"license": "apache-2.0"},
                    "siblings": [
                        {"rfilename": ".gitattributes", "size": 10, "blobId": "1".repeat(40)},
                        {"rfilename": "README.md", "size": README.len(), "blobId": blob(README)},
                        arch,
                    ],
                });
                return resp(200, doc.to_string().as_bytes());
            }
            let resolve = format!("/{REPO}/resolve/{SHA}/");
            match path.strip_prefix(resolve.as_str()) {
                Some("README.md") => resp(200, README),
                Some("voices.tgz") => {
                    let mut r = resp(302, b"");
                    r.headers.push(("Location".into(), "/cdn/voices.tgz".into()));
                    let etag = format!("\"{}\"", sha256_hex(&archive));
                    r.headers.push(("x-linked-etag".into(), etag));
                    r.headers.push(("x-linked-size".into(), archive.len().to_string()));
                    r
                }
                _ if path == "/cdn/voices.tgz" && method == "GET" => resp(200, &archive),
                _ => resp(404, b""),
            }
        })
    }

    fn request_with(extra: &[&str]) -> StageArgs {
        let mut a = s(&[
            "--kind", "voice", "--id", "test-voice-set", "--modality", "tts", "--runtime",
            "test-rt", "--needs", "needs.json",
        ]);
        a.extend(s(extra));
        a.push(format!("hf:{REPO}@{SHA}"));
        parse_stage_with(&mut Args::new(&a)).expect("parses")
    }

    fn set_dir_of(dir: &Path) -> PathBuf {
        dir.join("sets/test-voice-set").join(SHA)
    }

    /// A refused stage leaves no set dir, no manifest, no work dir.
    fn assert_nothing_left(dir: &Path) {
        let set = set_dir_of(dir);
        assert!(!set.exists(), "{} was left behind", set.display());
        assert!(!set.join(MANIFEST).exists());
        assert_no_work_dir(dir);
    }

    fn assert_no_work_dir(dir: &Path) {
        let work = dir.join("sets/test-voice-set").join(format!(".extract-{SHA}"));
        assert!(!work.exists(), "{} was left behind", work.display());
    }

    fn downloaded_nothing(f: &Fake) -> bool {
        f.seen.lock().unwrap().iter().all(|(_, p, _)| !p.contains("/resolve/"))
    }

    fn two_members() -> Vec<Vec<u8>> {
        vec![file("a.bin", b"alpha"), file("voices/b.bin", b"bravo!")]
    }

    #[test]
    fn extract_and_license_additional_arguments_are_parsed_strictly() {
        let plain = ExtractSpec { archive: "voices.tgz".to_string(), glob: None };
        assert_eq!(parse_extract("voices.tgz").unwrap(), plain);
        let globbed = parse_extract("voices.tgz:voices/*.bin").unwrap();
        assert_eq!(globbed.glob.as_deref(), Some("voices/*.bin"));
        for bad in ["", "../x.tgz", "a/b/c.tgz", "voices.tgz:", "voices.tgz:a b", "/abs.tgz"] {
            assert!(parse_extract(bad).is_err(), "{bad:?}");
        }
        let url = "https://creativecommons.org/licenses/by/4.0/";
        let bare = parse_additional(&format!("CC-BY-4.0={url}")).unwrap();
        assert_eq!((bare.id.as_str(), bare.url.as_str()), ("CC-BY-4.0", url));
        assert_eq!(bare.notice_path, None);
        let with = parse_additional(&format!("CC-BY-4.0={url},NOTICE.txt")).unwrap();
        assert_eq!(with.url, url);
        assert_eq!(with.notice_path.as_deref(), Some("NOTICE.txt"));
        for bad in ["no-equals", "=https://x.example", "id=", "id=https://x.example,../n"] {
            assert!(parse_additional(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn extract_takes_members_out_of_the_archive_and_lists_each_with_from_archive() {
        let dir = tmpdir("extract-ok");
        let archive = gz(&tar(&two_members()));
        let f = hf_archive(archive.clone(), true);
        let req = request_with(&["--extract", "voices.tgz"]);
        let (r, lines) = run(&f, None, &dir, &req, None);
        let staged = r.expect("staged");
        let set = set_dir_of(&dir);
        assert_eq!(std::fs::read(set.join("a.bin")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(set.join("voices/b.bin")).unwrap(), b"bravo!");
        assert!(!set.join("voices.tgz").exists(), "the archive is not part of the set");
        assert!(set.join(SIGNATURE).exists());
        assert_no_work_dir(&dir);
        model_set::validate(&staged.manifest()).expect("the manifest is valid");
        let v: Value = serde_json::from_slice(&staged.manifest()).unwrap();
        let files = v["files"].as_array().unwrap();
        let paths: Vec<&str> = files.iter().map(|x| x["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["README.md", "a.bin", "voices/b.bin"]);
        assert!(files[0].get("from_archive").is_none());
        assert_eq!(files[1]["sha256"], sha256_hex(b"alpha"));
        assert_eq!(files[1]["bytes"], 5);
        for i in [1, 2] {
            assert_eq!(files[i]["from_archive"]["path"], "voices.tgz");
            assert_eq!(files[i]["from_archive"]["sha256"], sha256_hex(&archive));
            assert_eq!(files[i]["from_archive"]["bytes"], archive.len());
        }
        assert!(lines.iter().any(|l| l.contains("extracted 2 file(s)")), "{lines:?}");
        assert!(render(&req, &staged).iter().any(|l| l.contains("extracted: 2")));
    }

    #[test]
    fn a_member_glob_extracts_only_what_it_matches() {
        let dir = tmpdir("extract-glob");
        let f = hf_archive(gz(&tar(&two_members())), true);
        let req = request_with(&["--extract", "voices.tgz:voices/*"]);
        let staged = run(&f, None, &dir, &req, None).0.expect("staged");
        let set = set_dir_of(&dir);
        assert!(set.join("voices/b.bin").exists() && !set.join("a.bin").exists());
        let paths: Vec<&str> = staged.files.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(paths, ["README.md", "voices/b.bin"]);
    }

    #[test]
    fn a_refusal_in_the_middle_of_the_archive_leaves_no_set_dir_and_no_manifest() {
        let dir = tmpdir("extract-allornothing");
        let mut entries = two_members();
        entries.push(other("c.bin", b'2', "/etc/passwd"));
        entries.push(file("d.bin", b"never reached"));
        let f = hf_archive(gz(&tar(&entries)), true);
        let req = request_with(&["--extract", "voices.tgz"]);
        let e = run(&f, None, &dir, &req, None).0.expect_err("refused");
        assert!(matches!(e, StageError::Extract(_)), "{e}");
        assert!(e.to_string().contains("a symlink"), "{e}");
        assert_nothing_left(&dir);
        // The archive without the symlink stages: the refusal was the extractor's.
        let dir = tmpdir("extract-allornothing-control");
        let f = hf_archive(gz(&tar(&two_members())), true);
        assert!(run(&f, None, &dir, &req, None).0.is_ok());
    }

    #[test]
    fn an_archive_member_that_is_also_a_staged_file_is_refused_before_any_set_dir() {
        let dir = tmpdir("extract-collide");
        let f = hf_archive(gz(&tar(&[file("README.md", b"mine")])), true);
        let req = request_with(&["--extract", "voices.tgz"]);
        let e = run(&f, None, &dir, &req, None).0.expect_err("collision");
        assert!(matches!(e, StageError::Input(_)), "{e}");
        assert!(e.to_string().contains("README.md"), "{e}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn an_archive_the_repo_does_not_list_or_that_is_not_lfs_is_refused_before_any_download() {
        let dir = tmpdir("extract-unlisted");
        let f = hf_archive(gz(&tar(&two_members())), true);
        let req = request_with(&["--extract", "other.tgz"]);
        let e = run(&f, None, &dir, &req, None).0.expect_err("not listed");
        assert!(e.to_string().contains("does not list"), "{e}");
        assert!(downloaded_nothing(&f));
        assert_nothing_left(&dir);

        let dir = tmpdir("extract-not-lfs");
        let f = hf_archive(gz(&tar(&two_members())), false);
        let req = request_with(&["--extract", "voices.tgz"]);
        let e = run(&f, None, &dir, &req, None).0.expect_err("no LFS digest");
        assert!(e.to_string().contains("not an LFS file"), "{e}");
        assert!(downloaded_nothing(&f));
        assert_nothing_left(&dir);
    }

    #[test]
    fn license_additional_records_what_is_declared_and_nothing_more() {
        let dir = tmpdir("addl-ok");
        let url = "https://creativecommons.org/licenses/by/4.0/";
        let f = hf_archive(gz(&tar(&two_members())), true);
        let a = format!("CC-BY-4.0={url},README.md");
        let b = "MIT=https://opensource.org/license/mit";
        let flags = ["--extract", "voices.tgz", "--license-additional", a.as_str()];
        let mut all = flags.to_vec();
        all.extend(["--license-additional", b]);
        let req = request_with(&all);
        let staged = run(&f, None, &dir, &req, None).0.expect("staged");
        let v: Value = serde_json::from_slice(&staged.manifest()).unwrap();
        let extra = v["license"]["additional"].as_array().unwrap();
        assert_eq!(extra.len(), 2);
        assert_eq!(extra[0], json!({"id": "CC-BY-4.0", "url": url, "notice_path": "README.md"}));
        // No notice path was given, so none is recorded: nothing is inferred.
        assert_eq!(extra[1], json!({"id": "MIT", "url": "https://opensource.org/license/mit"}));
    }

    #[test]
    fn a_notice_path_that_is_not_a_staged_notice_file_is_refused_before_any_download() {
        for (tag, path) in [("ghost", "ghost.txt"), ("member", "a.bin")] {
            let dir = tmpdir(&format!("addl-{tag}"));
            let f = hf_archive(gz(&tar(&two_members())), true);
            let a = format!("MIT=https://opensource.org/license/mit,{path}");
            let flags = ["--extract", "voices.tgz", "--license-additional", a.as_str()];
            let req = request_with(&flags);
            let e = run(&f, None, &dir, &req, None).0.expect_err("not a notice");
            assert!(matches!(&e, StageError::Invalid(r) if r.code == "notice_not_in_files"), "{e}");
            assert!(downloaded_nothing(&f), "{path}");
            assert_nothing_left(&dir);
        }
    }

    // ── the --file selection and the 64-file cap ─────────────────────────

    #[test]
    fn a_repeated_file_and_a_file_the_repo_does_not_list_are_refused_before_any_download() {
        let f = hf(json!(false));
        let twice = ["--file", "README.md", "--file", "README.md"];
        let unlisted = ["--file", "nope.bin", "--file", "README.md"];
        for (tag, flags, want) in [
            ("twice", twice, "--file README.md is given twice"),
            ("unlisted", unlisted, "the repo has no file `nope.bin`"),
        ] {
            let dir = tmpdir(&format!("select-{tag}"));
            let e = run(&f, None, &dir, &request_with(&flags), None).0.expect_err("refused");
            assert!(matches!(e, StageError::Input(_)), "{e}");
            assert!(e.to_string().contains(want), "{tag}: {e}");
            assert!(downloaded_nothing(&f), "{tag}");
            assert_nothing_left(&dir);
        }
    }

    /// A repo of `n` small files, f0.bin .. f<n-1>.bin; only the listing is served.
    fn repo_of(n: usize) -> Fake {
        serve(move |_, path| {
            if !path.starts_with(&format!("/api/models/{REPO}/revision/{SHA}")) {
                return resp(404, b"");
            }
            let siblings: Vec<Value> = (0..n)
                .map(|i| {
                    let name = format!("f{i}.bin");
                    json!({"rfilename": name, "size": 1, "blobId": "1".repeat(40)})
                })
                .collect();
            let doc = json!({
                "sha": SHA,
                "gated": false,
                "cardData": {"license": "apache-2.0"},
                "siblings": siblings,
            });
            resp(200, doc.to_string().as_bytes())
        })
    }

    #[test]
    fn a_set_of_more_than_64_files_is_refused_before_any_download() {
        let dir = tmpdir("select-65");
        let f = repo_of(65);
        let e = run(&f, None, &dir, &request("voice"), None).0.expect_err("65 files");
        assert!(matches!(e, StageError::Input(_)), "{e}");
        let m = e.to_string();
        assert!(m.contains("65 files is more than a set holds (64)"), "{m}");
        assert!(downloaded_nothing(&f));
        assert_nothing_left(&dir);
        // 64 is within the cap: the stage goes on, and stops at the missing download.
        let dir = tmpdir("select-64");
        let e = run(&repo_of(64), None, &dir, &request("voice"), None).0.expect_err("no files");
        assert!(!e.to_string().contains("more than a set holds"), "{e}");
    }

    #[test]
    fn staged_files_plus_archive_members_past_64_are_refused_and_leave_nothing() {
        let members: Vec<Vec<u8>> = (0..64).map(|i| file(&format!("m{i}.bin"), b"x")).collect();
        let req = request_with(&["--extract", "voices.tgz"]);
        // README.md (staged as itself) + 64 members = 65.
        let dir = tmpdir("extract-cap");
        let f = hf_archive(gz(&tar(&members)), true);
        let e = run(&f, None, &dir, &req, None).0.expect_err("65 files");
        assert!(matches!(e, StageError::Input(_)), "{e}");
        let m = e.to_string();
        assert!(m.contains("65 files is more than a set holds (64)"), "{m}");
        assert!(m.contains("narrow the member glob"), "{m}");
        assert_nothing_left(&dir);
        // README.md + 63 members = 64 stages.
        let dir = tmpdir("extract-cap-ok");
        let f = hf_archive(gz(&tar(&members[..63])), true);
        let staged = run(&f, None, &dir, &req, None).0.expect("64 files");
        assert_eq!(staged.files.len(), 64);
    }
}
