// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The voice add-on's models, staged by the controller (i105).
//!
//! The controller stages everything: noo-whisper and noo-piper never fetch
//! from Hugging Face. Before this, `docker/whisper_server.py` built
//! `WhisperModel("base")` (a huggingface_hub download into HF_HOME) and
//! `docker/piper_server.py` called piper's `download_voice` on first use, so
//! each container reached the internet on its own, as whatever uid it ran
//! as, into a writable volume.
//!
//! Now the CLI downloads them into the controller's model store, the same
//! store `noo models fetch` fills for GGUF weights (`MODELS_DIR`, else
//! `<data root>/models`, [`models_fetch::controller_store_dir`]), with the
//! same transfer: the controller's HF token only to the Hugging Face origin,
//! resume, and a digest check before anything is renamed into place (LFS
//! files against their sha256, small git files against their git blob id).
//! Layout, which `docker/voice_local.py` reads:
//!
//! ```text
//! <store>/voice/whisper/<name, '/' -> '--'>/{model.bin, config.json,
//!                                            tokenizer.json, vocabulary.*,
//!                                            [preprocessor_config.json]}
//! <store>/voice/piper/<voice>.onnx, <voice>.onnx.json
//! ```
//!
//! `docker-compose.voice.yml` mounts the two directories READ-ONLY and runs
//! both containers with `HF_HUB_OFFLINE=1`; a model that is not staged is a
//! 404 naming `noo models pull whisper:<name>` / `piper:<voice>`.
//!
//! Entry points: `noo models pull whisper:<size>|piper:<voice>` (any one, by
//! name), and [`stage_configured`] — the configured pair (`WHISPER_MODEL`,
//! default `base`; `PIPER_VOICE`, default `en_US-lessac-medium`) — run by
//! `noo addons enable voice`, `noo upgrade --stack` and onboard while voice
//! is on.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::commands::models_fetch::{self, FetchArgs, FetchErr};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

pub(crate) const DEFAULT_WHISPER: &str = "base";
pub(crate) const DEFAULT_PIPER: &str = "en_US-lessac-medium";
pub(crate) const PIPER_REPO: &str = "rhasspy/piper-voices";
const REVISION: &str = "main";

/// One voice model, by the id `noo models pull` takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VoiceModel {
    /// A faster-whisper size name (`base`) or a CTranslate2 repo id.
    Whisper(String),
    /// A piper voice id (`en_US-lessac-medium`).
    Piper(String),
}

impl VoiceModel {
    /// `whisper:<name>` / `piper:<voice>`: what the servers' errors name.
    pub(crate) fn id(&self) -> String {
        match self {
            VoiceModel::Whisper(n) => format!("whisper:{n}"),
            VoiceModel::Piper(v) => format!("piper:{v}"),
        }
    }

    /// `None` when `id` is not a voice id at all (an Ollama name); `Some(Err)`
    /// when it is one but malformed.
    pub(crate) fn parse(id: &str) -> Option<Result<VoiceModel, String>> {
        let (kind, name) = id.split_once(':')?;
        let name = name.trim();
        match kind {
            "whisper" => Some(whisper_repo(name).map(|_| VoiceModel::Whisper(name.to_string()))),
            "piper" => Some(piper_paths(name).map(|_| VoiceModel::Piper(name.to_string()))),
            _ => None,
        }
    }
}

/// The directory/file stem for a name: `/` → `--` (the HF cache
/// convention). Mirrors `voice_local.safe_name`.
pub(crate) fn safe_name(name: &str) -> String {
    name.replace('/', "--")
}

fn plain_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The Hugging Face repo a whisper name is staged from. Size names follow
/// faster-whisper's own table (`faster_whisper.utils._MODELS`, 1.1.1); an
/// `<org>/<name>` id is taken as given.
pub(crate) fn whisper_repo(name: &str) -> Result<String, String> {
    let sized = |n: &str| format!("Systran/faster-whisper-{n}");
    let repo = match name {
        "tiny" | "tiny.en" | "base" | "base.en" | "small" | "small.en" | "medium" | "medium.en" | "large-v1" | "large-v2"
        | "large-v3" => sized(name),
        "large" => sized("large-v3"),
        "distil-large-v2" | "distil-medium.en" | "distil-small.en" | "distil-large-v3" => {
            format!("Systran/faster-{name}").replace("faster-distil-", "faster-distil-whisper-")
        }
        "large-v3-turbo" | "turbo" => "mobiuslabsgmbh/faster-whisper-large-v3-turbo".to_string(),
        n => {
            let parts: Vec<&str> = n.split('/').collect();
            if parts.len() != 2 || !parts.iter().all(|p| plain_segment(p)) {
                return Err(format!(
                    "'{n}' is not a whisper model: a size (tiny, base, small, medium, large-v3, *.en, turbo) or a CTranslate2 repo id <org>/<name>"
                ));
            }
            n.to_string()
        }
    };
    Ok(repo)
}

/// The files faster-whisper loads from a CTranslate2 directory (its own
/// `download_model` allow-list).
pub(crate) fn whisper_wants(file: &str) -> bool {
    !file.contains('/')
        && (matches!(file, "config.json" | "preprocessor_config.json" | "model.bin" | "tokenizer.json")
            || file.starts_with("vocabulary."))
}

/// The two repo paths of a piper voice in `rhasspy/piper-voices`:
/// `<lang>/<lang_REGION>/<speaker>/<quality>/<voice>.onnx` and `.onnx.json`.
pub(crate) fn piper_paths(voice: &str) -> Result<[String; 2], String> {
    let bad = || format!("'{voice}' is not a piper voice id (want <lang>_<REGION>-<speaker>-<quality>, e.g. {DEFAULT_PIPER})");
    let (locale, rest) = voice.split_once('-').ok_or_else(bad)?;
    let (speaker, quality) = rest.rsplit_once('-').ok_or_else(bad)?;
    let (lang, region) = locale.split_once('_').ok_or_else(bad)?;
    if ![lang, region, speaker, quality].iter().all(|s| plain_segment(s) && !s.contains('.')) {
        return Err(bad());
    }
    let dir = format!("{lang}/{locale}/{speaker}/{quality}");
    Ok([format!("{dir}/{voice}.onnx"), format!("{dir}/{voice}.onnx.json")])
}

/// `<store>/voice`, from `MODELS_DIR` / `NOO_DATA_ROOT` exactly as the
/// compose mounts resolve them.
pub(crate) fn voice_root_from(models_dir: Option<&str>, data_root: Option<&str>) -> PathBuf {
    PathBuf::from(models_fetch::store_dir_from(models_dir, data_root)).join("voice")
}

pub(crate) fn voice_root() -> PathBuf {
    let m = std::env::var("MODELS_DIR").ok();
    let r = std::env::var("NOO_DATA_ROOT").ok();
    voice_root_from(m.as_deref(), r.as_deref())
}

/// Where a model lands (and what the container sees, read-only).
pub(crate) fn staged_dir(root: &Path, m: &VoiceModel) -> PathBuf {
    match m {
        VoiceModel::Whisper(n) => root.join("whisper").join(safe_name(n)),
        VoiceModel::Piper(_) => root.join("piper"),
    }
}

/// Is `m` loadable from `root`: the files `docker/voice_local.py` requires.
pub(crate) fn is_staged(root: &Path, m: &VoiceModel) -> bool {
    let d = staged_dir(root, m);
    match m {
        VoiceModel::Whisper(_) => ["model.bin", "config.json", "tokenizer.json"].iter().all(|f| d.join(f).is_file()),
        VoiceModel::Piper(v) => {
            let s = safe_name(v);
            d.join(format!("{s}.onnx")).is_file() && d.join(format!("{s}.onnx.json")).is_file()
        }
    }
}

/// The pair compose preloads: `WHISPER_MODEL` / `PIPER_VOICE` from `env`
/// (the process env carries `.env`), else the compose defaults.
pub(crate) fn configured_from(env: &dyn Fn(&str) -> Option<String>) -> [VoiceModel; 2] {
    let pick = |k: &str, d: &str| env(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string());
    [VoiceModel::Whisper(pick("WHISPER_MODEL", DEFAULT_WHISPER)), VoiceModel::Piper(pick("PIPER_VOICE", DEFAULT_PIPER))]
}

pub(crate) fn configured() -> [VoiceModel; 2] {
    configured_from(&|k| std::env::var(k).ok())
}

/// Is the voice add-on declared on (default off).
pub(crate) fn voice_on() -> bool {
    crate::commands::addons::effective("voice")
        .unwrap_or_else(|| crate::commands::addons::row("voice").map(|r| r.default_on).unwrap_or(false))
}

/// A git blob id: sha1 over `blob <len>\0<bytes>` — what the Hugging Face
/// API reports (`blobId`) for a file that is not in LFS.
pub(crate) fn git_blob_sha1(bytes: &[u8]) -> String {
    use sha1::{Digest as _, Sha1};
    let mut h = Sha1::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    hex::encode(h.finalize())
}

/// One file to stage, from the API's `siblings[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wanted {
    pub path: String,
    /// Some(sha256) for an LFS file, else the git blob id.
    pub lfs_sha256: Option<String>,
    pub blob_id: Option<String>,
    pub size: Option<u64>,
}

/// The files of `m` in the repo listing `siblings` (the model API with
/// `?blobs=true`). Err names what is missing.
pub(crate) fn select_files(m: &VoiceModel, siblings: &[Value]) -> Result<Vec<Wanted>, String> {
    let row = |s: &Value| Wanted {
        path: s["rfilename"].as_str().unwrap_or("").to_string(),
        lfs_sha256: s["lfs"]["sha256"].as_str().and_then(models_fetch::sha_from_etag),
        blob_id: s["blobId"].as_str().map(str::to_string),
        size: s["lfs"]["size"].as_u64().or(s["size"].as_u64()),
    };
    match m {
        VoiceModel::Whisper(n) => {
            let w: Vec<Wanted> = siblings.iter().map(row).filter(|w| whisper_wants(&w.path)).collect();
            for need in ["model.bin", "config.json", "tokenizer.json"] {
                if !w.iter().any(|x| x.path == need) {
                    return Err(format!("{} has no {need}: not a faster-whisper (CTranslate2) model", whisper_repo(n)?));
                }
            }
            Ok(w)
        }
        VoiceModel::Piper(v) => {
            let paths = piper_paths(v)?;
            paths
                .iter()
                .map(|p| {
                    siblings
                        .iter()
                        .find(|s| s["rfilename"].as_str() == Some(p.as_str()))
                        .map(row)
                        .ok_or_else(|| format!("{PIPER_REPO} has no {p}: no such piper voice"))
                })
                .collect()
        }
    }
}

/// What one model's staging did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Staged {
    pub id: String,
    pub dir: PathBuf,
    /// (file name, bytes, already present and verified)
    pub files: Vec<(String, u64, bool)>,
}

impl Staged {
    pub(crate) fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.1).sum()
    }
    pub(crate) fn fresh(&self) -> usize {
        self.files.iter().filter(|f| !f.2).count()
    }
    pub(crate) fn json(&self) -> Value {
        json!({
            "id": self.id, "dir": self.dir.display().to_string(), "bytes": self.bytes(),
            "files": self.files.iter().map(|(n, b, have)| json!({"name": n, "bytes": b, "already_present": have})).collect::<Vec<_>>(),
        })
    }
}

fn repo_of(m: &VoiceModel) -> Result<String, String> {
    match m {
        VoiceModel::Whisper(n) => whisper_repo(n),
        VoiceModel::Piper(_) => Ok(PIPER_REPO.to_string()),
    }
}

fn siblings(base: &str, token: Option<&str>, repo: &str) -> Result<Vec<Value>, String> {
    let url = format!(
        "{}/api/models/{}/revision/{}?blobs=true",
        base.trim_end_matches('/'),
        models_fetch::enc_path(repo),
        REVISION
    );
    let mut resp = models_fetch::get_following(base, &url, token, 0).map_err(|e| format!("{repo}: {e}"))?;
    let st = resp.status().as_u16();
    if !(200..=299).contains(&st) {
        return Err(format!("{repo}: Hugging Face API returned {st}"));
    }
    let text = resp.body_mut().read_to_string().map_err(|e| format!("{repo}: reading the API answer: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{repo}: the API answered non-JSON: {e}"))?;
    Ok(v["siblings"].as_array().cloned().unwrap_or_default())
}

/// A small non-LFS file, verified against its git blob id, then renamed
/// into place 0644.
fn fetch_blob(base: &str, token: Option<&str>, repo: &str, w: &Wanted, dir: &Path) -> Result<(u64, bool), String> {
    use std::os::unix::fs::PermissionsExt;
    let name = w.path.rsplit('/').next().unwrap_or(&w.path).to_string();
    let want = w.blob_id.clone().ok_or_else(|| format!("{repo}/{}: Hugging Face published no digest for it — refusing an unverifiable file", w.path))?;
    let dest = dir.join(&name);
    if let Ok(have) = std::fs::read(&dest) {
        if git_blob_sha1(&have) == want {
            return Ok((have.len() as u64, true));
        }
    }
    let a = FetchArgs { repo: repo.to_string(), file: w.path.clone(), revision: REVISION.into(), force: true };
    let url = models_fetch::resolve_url(base, &a);
    let mut resp = models_fetch::get_following(base, &url, token, 0).map_err(|e| format!("{repo}/{}: {e}", w.path))?;
    let st = resp.status().as_u16();
    if st != 200 {
        return Err(format!("{repo}/{}: download returned HTTP {st}", w.path));
    }
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(64 << 20)
        .read_to_vec()
        .map_err(|e| format!("{repo}/{}: download failed: {e}", w.path))?;
    let got = git_blob_sha1(&bytes);
    if got != want {
        return Err(format!("{repo}/{}: digest mismatch (Hugging Face says blob {want}, the download is {got})", w.path));
    }
    let part = models_fetch::part_path(dir, &name);
    std::fs::write(&part, &bytes).map_err(|e| format!("writing {}: {e}", part.display()))?;
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644)).map_err(|e| format!("mode 0644 on {}: {e}", part.display()))?;
    std::fs::rename(&part, &dest).map_err(|e| format!("renaming into {}: {e}", dest.display()))?;
    Ok((bytes.len() as u64, false))
}

/// Stage one model under `root`. `progress` prints per-file lines on stderr.
pub(crate) fn stage(root: &Path, m: &VoiceModel, progress: bool) -> Result<Staged, String> {
    let repo = repo_of(m)?;
    let dir = staged_dir(root, m);
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e} (the model store, MODELS_DIR else <data root>/models, must be writable by you)", dir.display()))?;
    let base = models_fetch::hf_base();
    let token = models_fetch::hf_token();
    let wanted = select_files(m, &siblings(&base, token.as_deref(), &repo)?)?;
    let mut files = Vec::new();
    for w in &wanted {
        let name = w.path.rsplit('/').next().unwrap_or(&w.path).to_string();
        if progress {
            eprintln!("  {}: {name}{}", m.id(), w.size.map(|s| format!(" ({})", models_fetch::human(s))).unwrap_or_default());
        }
        let (bytes, have) = if w.lfs_sha256.is_some() {
            let a = FetchArgs { repo: repo.clone(), file: w.path.clone(), revision: REVISION.into(), force: true };
            let o = models_fetch::fetch_to_store(&base, token.as_deref(), &a, &dir, &mut |_: u64, _: Option<u64>| {})
                .map_err(|e: FetchErr| format!("{repo}/{}: {e}", w.path))?;
            (o.size, o.already_present)
        } else {
            fetch_blob(&base, token.as_deref(), &repo, w, &dir)?
        };
        files.push((name, bytes, have));
    }
    Ok(Staged { id: m.id(), dir, files })
}

/// Create both mount sources (the bind check refuses a missing one).
pub(crate) fn ensure_dirs(root: &Path) -> Result<(), String> {
    for d in ["whisper", "piper"] {
        let p = root.join(d);
        std::fs::create_dir_all(&p).map_err(|e| format!("creating {}: {e}", p.display()))?;
    }
    Ok(())
}

/// One line per outcome, for every caller that reports to a terminal.
pub(crate) fn line(r: &Result<Staged, (String, String)>) -> String {
    match r {
        Ok(s) if s.fresh() == 0 => format!("{} already staged, verified ({}) in {}", s.id, models_fetch::human(s.bytes()), s.dir.display()),
        Ok(s) => format!("{} staged: {} file(s), {} in {}", s.id, s.files.len(), models_fetch::human(s.bytes()), s.dir.display()),
        Err((id, e)) => format!("{id} NOT staged: {e} — retry: noo models pull {id}"),
    }
}

/// Stage the configured whisper model and piper voice. Never fails the
/// caller: each outcome is returned (Err carries the id and why).
pub(crate) fn stage_configured(progress: bool) -> Vec<Result<Staged, (String, String)>> {
    let root = voice_root();
    if let Err(e) = ensure_dirs(&root) {
        return configured().iter().map(|m| Err((m.id(), e.clone()))).collect();
    }
    configured().iter().map(|m| stage(&root, m, progress).map_err(|e| (m.id(), e))).collect()
}

/// `noo upgrade --stack`: stage while voice is on, before the launcher (so
/// the read-only mount sources exist). Best effort, printed.
pub(crate) fn stage_if_on(g: &Globals) {
    if !voice_on() {
        return;
    }
    if !g.json {
        ui::step("staging the voice models (voice is on)");
    }
    for r in stage_configured(!g.json) {
        if g.json {
            continue;
        }
        match &r {
            Ok(_) => ui::done(&line(&r)),
            Err(_) => ui::warned(&line(&r)),
        }
    }
}

/// `noo models pull whisper:<name>|piper:<voice>`.
pub(crate) fn pull(g: &Globals, m: VoiceModel) -> Result<i32, Unhandled> {
    let root = voice_root();
    if let Err(e) = ensure_dirs(&root) {
        fail(g.json, ExitCode::Generic, "store_not_writable", &e, Some("make the model store (MODELS_DIR, else <data root>/models) writable by you, then re-run"));
    }
    if !g.json {
        println!("{}", ui::header("models pull", Some(&format!("{} → {}", m.id(), staged_dir(&root, &m).display()))));
    }
    match stage(&root, &m, !g.json) {
        Ok(s) => {
            if g.json {
                println!("{}", s.json());
            } else {
                ui::done(&line(&Ok(s.clone())));
                ui::guide(&[("noo cluster verify --controller", "the `voice models` row checks the configured pair is staged")]);
            }
            Ok(0)
        }
        Err(e) => fail(g.json, ExitCode::RemoteError, "pull_failed", &format!("{}: {e}", m.id()), Some("re-run the same command: finished files are kept and verified")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(n: &str) -> VoiceModel {
        VoiceModel::Whisper(n.into())
    }
    fn p(v: &str) -> VoiceModel {
        VoiceModel::Piper(v.into())
    }

    #[test]
    fn ids_parse_and_round_trip() {
        assert_eq!(VoiceModel::parse("whisper:base"), Some(Ok(w("base"))));
        assert_eq!(VoiceModel::parse("piper:en_US-lessac-medium"), Some(Ok(p("en_US-lessac-medium"))));
        assert_eq!(w("base").id(), "whisper:base");
        assert_eq!(p("en_GB-alba-medium").id(), "piper:en_GB-alba-medium");
        // An Ollama name, tag and all, is not a voice id.
        assert_eq!(VoiceModel::parse("llama3:8b"), None);
        assert_eq!(VoiceModel::parse("gemma3"), None);
        assert!(matches!(VoiceModel::parse("whisper:../etc"), Some(Err(_))));
        assert!(matches!(VoiceModel::parse("piper:lessac"), Some(Err(_))));
    }

    #[test]
    fn whisper_sizes_map_to_faster_whispers_repos() {
        assert_eq!(whisper_repo("base").unwrap(), "Systran/faster-whisper-base");
        assert_eq!(whisper_repo("small.en").unwrap(), "Systran/faster-whisper-small.en");
        assert_eq!(whisper_repo("large").unwrap(), "Systran/faster-whisper-large-v3");
        assert_eq!(whisper_repo("distil-large-v3").unwrap(), "Systran/faster-distil-whisper-large-v3");
        assert_eq!(whisper_repo("turbo").unwrap(), "mobiuslabsgmbh/faster-whisper-large-v3-turbo");
        assert_eq!(whisper_repo("org/my-ct2-model").unwrap(), "org/my-ct2-model");
        for bad in ["", "huge", "a/b/c", "../x", "org/..", "o/.hidden"] {
            assert!(whisper_repo(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn piper_voices_map_to_their_repo_paths() {
        assert_eq!(
            piper_paths("en_US-lessac-medium").unwrap(),
            ["en/en_US/lessac/medium/en_US-lessac-medium.onnx".to_string(), "en/en_US/lessac/medium/en_US-lessac-medium.onnx.json".to_string()]
        );
        // A speaker with underscores and dashes elsewhere.
        assert_eq!(
            piper_paths("en_GB-northern_english_male-medium").unwrap()[0],
            "en/en_GB/northern_english_male/medium/en_GB-northern_english_male-medium.onnx"
        );
        for bad in ["lessac", "en-lessac-medium", "en_US-medium", "en_US-../x-medium", "en_US-a.b-low"] {
            assert!(piper_paths(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn the_store_is_the_gguf_store_s_voice_dir() {
        assert_eq!(voice_root_from(Some("/mnt/fleet/models"), Some("/data")), PathBuf::from("/mnt/fleet/models/voice"));
        assert_eq!(voice_root_from(None, Some("/data/noo")), PathBuf::from("/data/noo/models/voice"));
        let r = PathBuf::from("/s/voice");
        assert_eq!(staged_dir(&r, &w("base")), PathBuf::from("/s/voice/whisper/base"));
        assert_eq!(staged_dir(&r, &w("org/m")), PathBuf::from("/s/voice/whisper/org--m"));
        assert_eq!(staged_dir(&r, &p("en_US-lessac-medium")), PathBuf::from("/s/voice/piper"));
    }

    #[test]
    fn the_configured_pair_defaults_like_compose() {
        let none = |_: &str| None;
        assert_eq!(configured_from(&none), [w("base"), p("en_US-lessac-medium")]);
        let set = |k: &str| match k {
            "WHISPER_MODEL" => Some("small".to_string()),
            "PIPER_VOICE" => Some(" ".to_string()),
            _ => None,
        };
        assert_eq!(configured_from(&set), [w("small"), p("en_US-lessac-medium")], "blank is unset");
    }

    fn sib(name: &str, lfs: bool) -> Value {
        if lfs {
            json!({"rfilename": name, "size": 10, "blobId": "b", "lfs": {"sha256": "a".repeat(64), "size": 145_000_000}})
        } else {
            json!({"rfilename": name, "size": 2_000, "blobId": "c".repeat(40)})
        }
    }

    #[test]
    fn whisper_selection_is_faster_whispers_allow_list() {
        let s = vec![
            sib(".gitattributes", false),
            sib("README.md", false),
            sib("config.json", false),
            sib("model.bin", true),
            sib("tokenizer.json", false),
            sib("vocabulary.txt", false),
            sib("sub/model.bin", true),
        ];
        let got = select_files(&w("base"), &s).unwrap();
        let names: Vec<&str> = got.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(names, ["config.json", "model.bin", "tokenizer.json", "vocabulary.txt"]);
        let bin = got.iter().find(|x| x.path == "model.bin").unwrap();
        assert_eq!(bin.lfs_sha256.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(bin.size, Some(145_000_000));
        let cfg = got.iter().find(|x| x.path == "config.json").unwrap();
        assert_eq!((cfg.lfs_sha256.as_deref(), cfg.blob_id.as_deref()), (None, Some("c".repeat(40).as_str())));
        // A repo without the weights is not a whisper model.
        let e = select_files(&w("base"), &[sib("config.json", false), sib("tokenizer.json", false)]).unwrap_err();
        assert!(e.contains("model.bin") && e.contains("Systran/faster-whisper-base"), "{e}");
    }

    #[test]
    fn piper_selection_is_exactly_the_voice_pair() {
        let s = vec![
            sib("en/en_US/lessac/medium/en_US-lessac-medium.onnx", true),
            sib("en/en_US/lessac/medium/en_US-lessac-medium.onnx.json", false),
            sib("en/en_US/lessac/low/en_US-lessac-low.onnx", true),
            sib("en/en_US/lessac/medium/MODEL_CARD", false),
        ];
        let got = select_files(&p("en_US-lessac-medium"), &s).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got[0].lfs_sha256.is_some() && got[1].lfs_sha256.is_none());
        let e = select_files(&p("en_US-amy-low"), &s).unwrap_err();
        assert!(e.contains("en/en_US/amy/low/en_US-amy-low.onnx") && e.contains(PIPER_REPO), "{e}");
    }

    #[test]
    fn git_blob_ids_match_git() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(git_blob_sha1(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a");
        // `git hash-object /dev/null`
        assert_eq!(git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn staged_means_the_files_the_servers_require() {
        let root = std::env::temp_dir().join(format!("noo-voice-models-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert!(!is_staged(&root, &w("base")) && !is_staged(&root, &p("en_US-lessac-medium")));
        ensure_dirs(&root).unwrap();
        assert!(root.join("whisper").is_dir() && root.join("piper").is_dir());
        let d = staged_dir(&root, &w("base"));
        std::fs::create_dir_all(&d).unwrap();
        for f in ["model.bin", "config.json"] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        assert!(!is_staged(&root, &w("base")), "no tokenizer.json: faster-whisper would fetch one");
        std::fs::write(d.join("tokenizer.json"), b"{}").unwrap();
        assert!(is_staged(&root, &w("base")));
        std::fs::write(root.join("piper/en_US-lessac-medium.onnx"), b"x").unwrap();
        assert!(!is_staged(&root, &p("en_US-lessac-medium")));
        std::fs::write(root.join("piper/en_US-lessac-medium.onnx.json"), b"{}").unwrap();
        assert!(is_staged(&root, &p("en_US-lessac-medium")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn report_lines_name_the_retry() {
        let ok = Staged { id: "whisper:base".into(), dir: "/s/voice/whisper/base".into(), files: vec![("model.bin".into(), 145 << 20, false), ("config.json".into(), 2048, true)] };
        assert_eq!(ok.bytes(), (145 << 20) + 2048);
        let l = line(&Ok(ok.clone()));
        assert!(l.starts_with("whisper:base staged: 2 file(s), 145.0 MB in /s/voice/whisper/base"), "{l}");
        let have = Staged { files: vec![("model.bin".into(), 10, true)], ..ok };
        assert!(line(&Ok(have)).contains("already staged"));
        let l = line(&Err(("piper:en_US-lessac-medium".into(), "offline".into())));
        assert!(l.contains("NOT staged: offline") && l.ends_with("noo models pull piper:en_US-lessac-medium"), "{l}");
    }

    /// The configured pair is staged on every path that turns voice on or
    /// rolls it: enable, the upgrade (before the launcher, whose bind check
    /// needs the mount sources) and onboard's add-ons step.
    #[test]
    fn every_voice_on_path_stages() {
        let up = include_str!("upgrade.rs");
        let body = &up[up.find("fn upgrade_stack(").expect("upgrade_stack")..];
        let at = |n: &str| body.find(n).unwrap_or_else(|| panic!("{n} not in upgrade_stack"));
        assert!(at("voice_models::stage_if_on(g)") < at("let mut status = launch();"), "stage before the launcher");
        let addons = include_str!("addons.rs");
        assert!(addons.contains("(on && name == \"voice\").then(|| crate::commands::voice_models::stage_configured("), "enable stages");
        let onboard = include_str!("../onboard/mod.rs");
        let i = onboard.find("steps::addons(ctx);").expect("addons step");
        assert!(onboard[i..].find("steps::stage_voice_models(ctx);").is_some_and(|j| j < 200), "onboard stages right after the add-ons step");
        let models = include_str!("models.rs");
        assert!(models.contains("voice_models::VoiceModel::parse(&model)"), "noo models pull takes whisper:/piper: ids");
    }
}
