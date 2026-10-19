// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo models fetch ollama:<tag>` — stage an ollama registry model in the
//! controller's model store, so a placed node can import it without ever
//! contacting registry.ollama.ai.
//!
//! A placed node refuses `ollama pull` (`ollama_registry_pull_refused`): its
//! models come from the controller's store. Until this command the only remedy
//! was a GGUF fetched from Hugging Face. Now the CONTROLLER makes the one
//! registry contact, and the node's side is the path it already has:
//!
//! 1. GET `/v2/<ns>/<name>/manifests/<tag>` from `registry.ollama.ai`
//!    (`NOO_OLLAMA_REGISTRY` overrides, for a mirror).
//! 2. Every layer and the config blob is downloaded and checked against the
//!    `sha256:` digest and the size the manifest carries. A mismatch installs
//!    nothing.
//! 3. Two files go into the store (`MODELS_DIR`, the directory nginx serves as
//!    `/gguf/`), the weight first and the recipe LAST, so a node that sees the
//!    recipe finds the weight complete:
//!    `ollama+<ns>+<name>+<tag>.gguf`       the model layer, verbatim;
//!    `ollama+<ns>+<name>+<tag>.Modelfile`  `FROM` that file plus the
//!    template, system, parameters, licence and messages layers.
//!    The names are `OllamaStoreStem` in node-agent-go/internal/docker/
//!    ollama_stage.go (same vectors in both; tests/test_ollama_stage_parity.py).
//! 4. The node fetches both by name through the gateway's existing
//!    `gguf` and `modelfile` artifact kinds (digest-verified), checks the
//!    weight against the digest this command recorded in the Modelfile, and
//!    runs `ollama create <tag>`.
//!
//! What cannot be rebuilt from a GGUF and a Modelfile is REFUSED, not
//! approximated: a vision projector, an adapter, any layer type this command
//! does not know. A text-only tag stages; for a model that does not, the
//! remedy is a GGUF (`noo models fetch <hf_repo> <file.gguf>`) or the
//! per-node exception `NOO_ALLOW_OLLAMA_REGISTRY_PULL=1`.
//!
//! Failure semantics: registry unreachable or any non-200 is an error and the
//! store is untouched; a digest or size mismatch deletes the partial file; a
//! store file of that name that differs is a conflict unless `--force`; an
//! interrupted weight download resumes (HTTP Range) on re-run.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::models_fetch::{agent, get_following, human, io, prewarm_digest, sha256_file, writable_store, FetchErr};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

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
pub(crate) fn parse_stage_args(args: &[String]) -> Result<(OllamaRef, bool), String> {
    let mut reference: Option<OllamaRef> = None;
    let mut force = false;
    for t in args {
        match t.as_str() {
            "--force" => force = true,
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
            s => {
                let Some(rest) = s.strip_prefix("ollama:") else {
                    return Err(format!("'{s}': an ollama model is given as ollama:<tag> (e.g. ollama:gemma4:12b)"));
                };
                if reference.is_some() {
                    return Err("expected exactly one ollama:<tag> argument".into());
                }
                reference = Some(parse_ref(rest)?);
            }
        }
    }
    reference.map(|r| (r, force)).ok_or_else(|| "expected ollama:<tag>".into())
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

fn layer_of(v: &Value, what: &str) -> Result<Layer, String> {
    let media = v["mediaType"].as_str().ok_or_else(|| format!("{what} has no mediaType"))?.to_string();
    let digest = v["digest"].as_str().ok_or_else(|| format!("{what} has no digest"))?;
    let sha256 = digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{what} digest '{digest}' is not sha256:<64 hex>"))?
        .to_ascii_lowercase();
    let size = v["size"].as_u64().ok_or_else(|| format!("{what} has no size"))?;
    Ok(Layer { media, sha256, size })
}

/// The manifest, sorted into what the Modelfile is built from.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub config: Option<Layer>,
    pub model: Option<Layer>,
    pub template: Option<Layer>,
    pub system: Option<Layer>,
    pub params: Option<Layer>,
    pub messages: Option<Layer>,
    pub licenses: Vec<Layer>,
}

/// Non-weight layers are text; one over this is not a template.
const MAX_TEXT_LAYER: u64 = 1 << 20;

pub(crate) fn plan_layers(manifest: &Value) -> Result<Plan, String> {
    let mut plan = Plan::default();
    if manifest["config"].is_object() {
        plan.config = Some(layer_of(&manifest["config"], "the manifest's config")?);
    }
    let layers = manifest["layers"].as_array().ok_or("the manifest has no layers")?;
    for (i, l) in layers.iter().enumerate() {
        let layer = layer_of(l, &format!("layer {i}"))?;
        let media = layer.media.clone();
        let slot = match media.as_str() {
            "application/vnd.ollama.image.model" => &mut plan.model,
            "application/vnd.ollama.image.template" => &mut plan.template,
            "application/vnd.ollama.image.system" => &mut plan.system,
            "application/vnd.ollama.image.params" => &mut plan.params,
            "application/vnd.ollama.image.messages" => &mut plan.messages,
            "application/vnd.ollama.image.license" => {
                plan.licenses.push(layer);
                continue;
            }
            other => {
                return Err(format!(
                    "this model has a '{other}' layer, which `ollama create` cannot rebuild from a GGUF and a Modelfile \
                     (a vision projector, an adapter or a newer layer type) — refusing rather than stage a model that \
                     would behave differently. Use a text-only tag, a GGUF (`noo models fetch <hf_repo> <file.gguf>`), \
                     or accept NOO_ALLOW_OLLAMA_REGISTRY_PULL=1 on the node"
                ))
            }
        };
        if slot.is_some() {
            return Err(format!("the manifest has two '{}' layers", layer.media));
        }
        *slot = Some(layer);
    }
    let model = plan.model.as_ref().ok_or("the manifest has no model layer — not a GGUF model")?;
    if model.size == 0 {
        return Err("the model layer is empty".into());
    }
    for l in [&plan.template, &plan.system, &plan.params, &plan.messages].into_iter().flatten().chain(plan.licenses.iter()).chain(plan.config.iter()) {
        if l.size > MAX_TEXT_LAYER {
            return Err(format!("layer '{}' is {} bytes — too large to be text", l.media, l.size));
        }
    }
    Ok(plan)
}

fn manifest_url(base: &str, r: &OllamaRef) -> String {
    format!("{base}/v2/{}/{}/manifests/{}", r.ns, r.name, r.tag)
}

fn blob_url(base: &str, r: &OllamaRef, sha256: &str) -> String {
    format!("{base}/v2/{}/{}/blobs/sha256:{sha256}", r.ns, r.name)
}

fn get_manifest(base: &str, r: &OllamaRef) -> Result<Value, String> {
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
    let text = resp.body_mut().read_to_string().map_err(|e| format!("reading the manifest: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("the manifest is not JSON: {e}"))
}

/// A small blob, read whole and verified against its digest and size.
fn get_small_blob(base: &str, r: &OllamaRef, layer: &Layer) -> Result<Vec<u8>, String> {
    let mut resp = get_following(base, &blob_url(base, r, &layer.sha256), None, 0).map_err(|e| e.to_string())?;
    let st = resp.status().as_u16();
    if st != 200 {
        return Err(format!("blob sha256:{} answered HTTP {st}", &layer.sha256[..12]));
    }
    let mut body = Vec::new();
    resp.body_mut()
        .with_config()
        .limit(MAX_TEXT_LAYER + 1)
        .reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("reading blob sha256:{}: {e}", &layer.sha256[..12]))?;
    verify_bytes(&body, layer)?;
    Ok(body)
}

pub(crate) fn verify_bytes(body: &[u8], layer: &Layer) -> Result<(), String> {
    if body.len() as u64 != layer.size {
        return Err(format!(
            "blob sha256:{} is {} bytes, the manifest says {} — nothing was installed",
            &layer.sha256[..12], body.len(), layer.size
        ));
    }
    let got = hex::encode(Sha256::digest(body));
    if got != layer.sha256 {
        return Err(format!(
            "blob sha256:{} hashes to {got} — the registry's bytes do not match its own manifest; nothing was installed",
            &layer.sha256[..12]
        ));
    }
    Ok(())
}

// ── The Modelfile ───────────────────────────────────────────────────────

/// The text layers, decoded.
#[derive(Debug, Default)]
pub(crate) struct Parts {
    pub template: Option<String>,
    pub system: Option<String>,
    pub params: Option<Value>,
    pub messages: Option<Value>,
    pub licenses: Vec<String>,
    pub renderer: Option<String>,
    pub parser: Option<String>,
}

fn text_of(bytes: Vec<u8>, what: &str) -> Result<String, String> {
    let s = String::from_utf8(bytes).map_err(|_| format!("the {what} layer is not UTF-8"))?;
    if s.contains('\0') {
        return Err(format!("the {what} layer contains a NUL"));
    }
    Ok(s)
}

/// `"""text"""`, which cannot carry its own terminator.
fn block(text: &str, what: &str) -> Result<String, String> {
    if text.contains("\"\"\"") {
        return Err(format!("the {what} text contains \"\"\", which a Modelfile cannot quote — this model cannot be staged"));
    }
    Ok(format!("\"\"\"{text}\"\"\""))
}

fn param_value(v: &Value, key: &str) -> Result<String, String> {
    match v {
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::String(s) => {
            if s.contains(['"', '\n', '\r', '\\', '\0']) {
                return Err(format!(
                    "parameter '{key}' has a value with a quote, backslash or newline, which a Modelfile cannot carry faithfully — this model cannot be staged"
                ));
            }
            Ok(format!("\"{s}\""))
        }
        _ => Err(format!("parameter '{key}' has a value of a kind a Modelfile cannot carry")),
    }
}

fn token_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// The recipe the node runs `ollama create` on. Directives are the allow-list
/// the node enforces (`stagedModelfileDirectives`): FROM, TEMPLATE, SYSTEM,
/// PARAMETER, LICENSE, MESSAGE, RENDERER, PARSER.
pub(crate) fn render_modelfile(r: &OllamaRef, model_sha256: &str, parts: &Parts) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("# noo-ollama-stage: v1\n");
    out.push_str(&format!("# source: registry.ollama.ai/{}\n", r.display()));
    out.push_str(&format!("# model-sha256: {model_sha256}\n"));
    out.push_str(&format!("FROM ./{}.gguf\n", r.stem()));
    if let Some(t) = &parts.template {
        out.push_str(&format!("TEMPLATE {}\n", block(t, "template")?));
    }
    if let Some(s) = &parts.system {
        out.push_str(&format!("SYSTEM {}\n", block(s, "system")?));
    }
    if let Some(p) = &parts.params {
        let obj = p.as_object().ok_or("the params layer is not a JSON object")?;
        for (k, v) in obj {
            if !k.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') || k.is_empty() {
                return Err(format!("parameter name '{k}' is not one a Modelfile can carry"));
            }
            match v {
                Value::Array(items) => {
                    for it in items {
                        out.push_str(&format!("PARAMETER {k} {}\n", param_value(it, k)?));
                    }
                }
                other => out.push_str(&format!("PARAMETER {k} {}\n", param_value(other, k)?)),
            }
        }
    }
    if let Some(m) = &parts.messages {
        for (i, msg) in m.as_array().ok_or("the messages layer is not a JSON array")?.iter().enumerate() {
            let role = msg["role"].as_str().unwrap_or("");
            if !matches!(role, "system" | "user" | "assistant") {
                return Err(format!("message {i} has role '{role}'"));
            }
            let content = msg["content"].as_str().ok_or_else(|| format!("message {i} has no content"))?;
            out.push_str(&format!("MESSAGE {role} {}\n", block(content, "message")?));
        }
    }
    for l in &parts.licenses {
        out.push_str(&format!("LICENSE {}\n", block(l, "licence")?));
    }
    if let Some(v) = &parts.renderer {
        if !token_ok(v) {
            return Err(format!("renderer '{v}' is not a plain token"));
        }
        out.push_str(&format!("RENDERER {v}\n"));
    }
    if let Some(v) = &parts.parser {
        if !token_ok(v) {
            return Err(format!("parser '{v}' is not a plain token"));
        }
        out.push_str(&format!("PARSER {v}\n"));
    }
    Ok(out)
}

// ── The store ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct StageOutcome {
    pub stem: String,
    pub gguf: PathBuf,
    pub modelfile: PathBuf,
    pub model_sha256: String,
    pub model_size: u64,
    pub resumed_from: u64,
    /// The store already held this exact weight; it was not transferred.
    pub weight_present: bool,
}

/// Download the model layer into `<dir>/.<name>.part` (resuming), verify size
/// and sha256, check the GGUF magic, and rename into place 0644. An existing
/// store file with the right digest is left alone; one with another digest is
/// a conflict unless `force`.
fn install_weight(
    base: &str,
    r: &OllamaRef,
    layer: &Layer,
    dir: &Path,
    name: &str,
    force: bool,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<(u64, bool), FetchErr> {
    use std::os::unix::fs::PermissionsExt;
    let dest = dir.join(name);
    if dest.exists() {
        let have = sha256_file(&dest).map_err(|e| io(&format!("reading {}", dest.display()), e))?;
        if have == layer.sha256 {
            return Ok((0, true));
        }
        if !force {
            return Err(FetchErr::Conflict { existing: have, expected: layer.sha256.clone() });
        }
    }
    let part = dir.join(format!(".{name}.part"));
    let mut have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    if have > layer.size {
        std::fs::remove_file(&part).map_err(|e| io("removing an oversized partial", e))?;
        have = 0;
    }
    let resumed_from = have;
    if have != layer.size {
        let mut resp = get_following(base, &blob_url(base, r, &layer.sha256), None, have)?;
        let st = resp.status().as_u16();
        let mut f = match st {
            206 => OpenOptions::new().append(true).open(&part).map_err(|e| io(&format!("opening {}", part.display()), e))?,
            200 => {
                // The server ignored Range: start over, never append a whole
                // file to a prefix.
                have = 0;
                File::create(&part).map_err(|e| io(&format!("creating {}", part.display()), e))?
            }
            _ => return Err(FetchErr::Http(format!("blob download returned HTTP {st}"))),
        };
        let mut body = resp.body_mut().with_config().limit(u64::MAX).reader();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = body.read(&mut buf).map_err(|e| io("download interrupted (re-run to resume)", e))?;
            if n == 0 {
                break;
            }
            f.write_all(&buf[..n]).map_err(|e| io(&format!("writing {}", part.display()), e))?;
            have += n as u64;
            progress(have, Some(layer.size));
        }
        f.sync_all().map_err(|e| io("flushing the partial file", e))?;
    }
    let size = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let got = sha256_file(&part).map_err(|e| io(&format!("hashing {}", part.display()), e))?;
    if size != layer.size || got != layer.sha256 {
        let _ = std::fs::remove_file(&part);
        return Err(FetchErr::Mismatch { expected: layer.sha256.clone(), got });
    }
    let mut magic = [0u8; 4];
    let magic_ok = File::open(&part).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"GGUF";
    if !magic_ok {
        let _ = std::fs::remove_file(&part);
        return Err(FetchErr::Io(format!(
            "the model layer sha256:{} verified against its manifest but is not a GGUF file (bad magic) — the partial file was deleted",
            &layer.sha256[..12]
        )));
    }
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o644)).map_err(|e| io("setting mode 0644", e))?;
    std::fs::rename(&part, &dest).map_err(|e| io(&format!("renaming into {}", dest.display()), e))?;
    Ok((resumed_from, false))
}

/// Write `body` to `<dir>/<name>` through a temp file, 0644.
fn install_text(dir: &Path, name: &str, body: &str) -> Result<PathBuf, FetchErr> {
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

/// Pull `r` from the registry at `base` into `dir`. Everything small is
/// fetched and verified BEFORE the weight is touched, so a model that cannot
/// be staged is refused without a multi-GB download; the weight is installed
/// before the Modelfile, so the Modelfile's presence means a complete weight.
pub(crate) fn stage(
    base: &str,
    r: &OllamaRef,
    dir: &Path,
    force: bool,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<StageOutcome, StageErr> {
    let manifest = get_manifest(base, r).map_err(StageErr::Registry)?;
    let plan = plan_layers(&manifest).map_err(StageErr::Registry)?;
    let model = plan.model.clone().expect("plan_layers requires a model layer");

    let mut parts = Parts::default();
    let small = |l: &Layer| get_small_blob(base, r, l).map_err(StageErr::Registry);
    if let Some(l) = &plan.template {
        parts.template = Some(text_of(small(l)?, "template").map_err(StageErr::Registry)?);
    }
    if let Some(l) = &plan.system {
        parts.system = Some(text_of(small(l)?, "system").map_err(StageErr::Registry)?);
    }
    if let Some(l) = &plan.params {
        parts.params = Some(serde_json::from_slice(&small(l)?).map_err(|e| StageErr::Registry(format!("the params layer is not JSON: {e}")))?);
    }
    if let Some(l) = &plan.messages {
        parts.messages = Some(serde_json::from_slice(&small(l)?).map_err(|e| StageErr::Registry(format!("the messages layer is not JSON: {e}")))?);
    }
    for l in &plan.licenses {
        parts.licenses.push(text_of(small(l)?, "licence").map_err(StageErr::Registry)?);
    }
    if let Some(l) = &plan.config {
        // Verified like every blob; read for the two fields newer ollama
        // models need to behave (tool calls, thinking).
        let cfg: Value = serde_json::from_slice(&small(l)?).map_err(|e| StageErr::Registry(format!("the config blob is not JSON: {e}")))?;
        parts.renderer = cfg["renderer"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        parts.parser = cfg["parser"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    }
    let modelfile = render_modelfile(r, &model.sha256, &parts).map_err(StageErr::Registry)?;

    let stem = r.stem();
    let gguf_name = format!("{stem}.gguf");
    let mf_name = format!("{stem}.Modelfile");
    let (resumed_from, weight_present) = install_weight(base, r, &model, dir, &gguf_name, force, progress)?;
    // The recipe is written last, and rewritten on every run: with the same
    // weight it can only differ by what the registry changed in the small
    // layers, and it is the registry's current answer for this tag.
    let modelfile_path = install_text(dir, &mf_name, &modelfile)?;
    Ok(StageOutcome {
        stem,
        gguf: dir.join(gguf_name),
        modelfile: modelfile_path,
        model_sha256: model.sha256,
        model_size: model.size,
        resumed_from,
        weight_present,
    })
}

// ── The command ─────────────────────────────────────────────────────────

/// `noo models fetch ollama:<tag> [--force]`.
pub fn models_fetch_ollama(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (r, force) = match parse_stage_args(args) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Usage, "bad_args", &e, Some("give the model as ollama:<tag>, e.g. ollama:gemma4:12b")),
    };
    let (store, dir) = writable_store(g, "noo models fetch ollama:<tag>");
    let base = registry_base();
    if !g.json {
        println!("{}", ui::header("models fetch", Some(&format!("ollama:{} → {store}", r.short()))));
        print!("{}", ui::kv(&[
            ("registry", base.clone()),
            ("store names", format!("{}.gguf + {}.Modelfile", r.stem(), r.stem())),
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
    let out = match stage(&base, &r, &dir, force, &mut progress) {
        Ok(o) => o,
        Err(e) => {
            let hint = match &e {
                StageErr::Fetch(FetchErr::Io(_) | FetchErr::Http(_)) => Some("re-run the same command: the weight download resumes"),
                StageErr::Fetch(FetchErr::Conflict { .. }) => Some("re-run with --force to replace the store's copy"),
                _ => None,
            };
            fail(g.json, ExitCode::RemoteError, "stage_failed", &e.to_string(), hint);
        }
    };
    let gguf_name = format!("{}.gguf", out.stem);
    let warm = prewarm_digest(g, &gguf_name, &out.model_sha256);
    let place = format!("noo cluster place <node> ollama {}", r.short());
    if g.json {
        println!("{}", json!({
            "ref": r.display(),
            "stem": out.stem,
            "gguf": out.gguf.display().to_string(),
            "modelfile": out.modelfile.display().to_string(),
            "model_sha256": out.model_sha256,
            "size_bytes": out.model_size,
            "resumed_from": out.resumed_from,
            "weight_already_present": out.weight_present,
            "gateway_digest": warm,
            "next": [place],
        }));
        return Ok(0);
    }
    if out.weight_present {
        ui::done(&format!("{} already in the store, sha256 verified ({}); Modelfile refreshed", gguf_name, human(out.model_size)));
    } else {
        let resumed = if out.resumed_from > 0 { format!(", resumed from {}", human(out.resumed_from)) } else { String::new() };
        ui::done(&format!("{} — {}, sha256 {} verified against the registry manifest{resumed}", out.gguf.display(), human(out.model_size), &out.model_sha256[..16]));
    }
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

fn staged_pair_present(store: &Path, r: &OllamaRef) -> bool {
    let stem = r.stem();
    store.join(format!("{stem}.Modelfile")).is_file() && store.join(format!("{stem}.gguf")).is_file()
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
            "{} is not staged in the controller store ({}): no complete {}.Modelfile + {}.gguf pair. Stage it with `noo models fetch ollama:{}`, then re-run",
            r.short(), store.display(), r.stem(), r.stem(), r.short()
        )
    };
    if let Some(rest) = arg.strip_prefix("ollama:") {
        let r = parse_ref(rest)?;
        return if staged_pair_present(store, &r) { Ok(ImportTarget::Staged(r)) } else { Err(restage(&r)) };
    }
    let single_component = !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    let plain = single_component && store.join(format!("{arg}.Modelfile")).is_file();
    let staged = parse_ref(arg).ok().filter(|r| staged_pair_present(store, r));
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
/// push to every node.
pub(crate) fn is_staged_name(name: &str) -> bool {
    name.starts_with("ollama+")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
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
    fn a_layer_the_modelfile_cannot_rebuild_is_refused() {
        let m = json!({"config": layer_json("application/vnd.docker.container.image.v1+json", b"{}"),
            "layers": [layer_json("application/vnd.ollama.image.model", b"GGUFx"),
                       layer_json("application/vnd.ollama.image.projector", b"proj")]});
        let e = plan_layers(&m).unwrap_err();
        assert!(e.contains("projector") && e.contains("NOO_ALLOW_OLLAMA_REGISTRY_PULL"), "{e}");
        let none = json!({"layers": [layer_json("application/vnd.ollama.image.template", b"{{ .Prompt }}")]});
        assert!(plan_layers(&none).unwrap_err().contains("no model layer"));
        let twice = json!({"layers": [layer_json("application/vnd.ollama.image.model", b"GGUFx"),
                                      layer_json("application/vnd.ollama.image.model", b"GGUFy")]});
        assert!(plan_layers(&twice).is_err());
        let bad_digest = json!({"layers": [{"mediaType": "application/vnd.ollama.image.model", "digest": "md5:abc", "size": 3}]});
        assert!(plan_layers(&bad_digest).is_err());
    }

    #[test]
    fn the_modelfile_carries_the_layers_in_the_nodes_allow_list() {
        let r = parse_ref("gemma4:12b").unwrap();
        let parts = Parts {
            template: Some("{{ .Prompt }}\nFROM the user, ADAPTER /etc/shadow\n".into()),
            system: Some("be brief".into()),
            params: Some(json!({"stop": ["<end_of_turn>", "<eos>"], "temperature": 0.7, "num_ctx": 4096})),
            messages: Some(json!([{"role": "user", "content": "hi"}])),
            licenses: vec!["MIT".into()],
            renderer: Some("gemma3".into()),
            parser: None,
        };
        let sha = "1".repeat(64);
        let body = render_modelfile(&r, &sha, &parts).unwrap();
        assert!(body.starts_with("# noo-ollama-stage: v1\n# source: registry.ollama.ai/library/gemma4:12b\n# model-sha256: "));
        assert!(body.contains(&format!("# model-sha256: {sha}\nFROM ./ollama+library+gemma4+12b.gguf\n")));
        for want in [
            "PARAMETER stop \"<end_of_turn>\"\n", "PARAMETER stop \"<eos>\"\n", "PARAMETER temperature 0.7\n",
            "PARAMETER num_ctx 4096\n", "SYSTEM \"\"\"be brief\"\"\"\n", "MESSAGE user \"\"\"hi\"\"\"\n",
            "LICENSE \"\"\"MIT\"\"\"\n", "RENDERER gemma3\n",
        ] {
            assert!(body.contains(want), "missing {want:?} in\n{body}");
        }
        // Every top-level directive is one the node accepts.
        let mut in_block = false;
        for line in body.lines() {
            if in_block {
                in_block = !line.contains("\"\"\"");
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let word = line.split_whitespace().next().unwrap();
            assert!(["FROM", "TEMPLATE", "SYSTEM", "PARAMETER", "LICENSE", "MESSAGE", "RENDERER", "PARSER"].contains(&word), "{word}");
            if let Some(i) = line.find("\"\"\"") {
                in_block = !line[i + 3..].contains("\"\"\"");
            }
        }
    }

    #[test]
    fn text_a_modelfile_cannot_carry_is_refused_not_mangled() {
        let r = parse_ref("m").unwrap();
        let sha = "2".repeat(64);
        for parts in [
            Parts { template: Some("a \"\"\" b".into()), ..Parts::default() },
            Parts { params: Some(json!({"stop": ["a\"b"]})), ..Parts::default() },
            Parts { params: Some(json!({"stop": ["line\nbreak"]})), ..Parts::default() },
            Parts { params: Some(json!({"Bad-Key": 1})), ..Parts::default() },
            Parts { messages: Some(json!([{"role": "tool", "content": "x"}])), ..Parts::default() },
            Parts { renderer: Some("a b".into()), ..Parts::default() },
        ] {
            assert!(render_modelfile(&r, &sha, &parts).is_err(), "{parts:?}");
        }
    }

    #[test]
    fn a_blob_is_checked_against_its_digest_and_size() {
        let l = Layer { media: "m".into(), sha256: digest(b"hello"), size: 5 };
        verify_bytes(b"hello", &l).unwrap();
        assert!(verify_bytes(b"hellO", &l).unwrap_err().contains("hashes to"));
        assert!(verify_bytes(b"hell", &l).unwrap_err().contains("bytes"));
    }

    #[test]
    fn staged_names_stay_out_of_the_default_sweep() {
        assert!(is_staged_name("ollama+library+gemma4+12b.gguf"));
        assert!(!is_staged_name("gemma-4-E2B-it-Q4_K_M.gguf"));
    }

    // ── A registry stand-in ─────────────────────────────────────────────

    struct Registry {
        base: String,
        hits: Arc<Mutex<Vec<String>>>,
    }

    /// Serves manifests at /v2/library/gemma4/manifests/12b and blobs at
    /// /v2/library/gemma4/blobs/sha256:<hex> (a 307 to /cdn/<hex> that honours
    /// Range, like the real registry's CDN hop). `lie` serves wrong bytes for
    /// the model blob.
    fn serve(manifest: Value, blobs: HashMap<String, Vec<u8>>, lie: Option<String>, max_conns: usize) -> Registry {
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
                    let b = manifest.to_string();
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).into_bytes();
                    r.extend_from_slice(b.as_bytes());
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
                layer_json("application/vnd.ollama.image.model", w),
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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-ollama-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn staging_installs_the_weight_then_the_recipe_and_verifies_both() {
        use std::os::unix::fs::PermissionsExt;
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 32);
        let dir = tmpdir("ok");
        let r = parse_ref("gemma4:12b").unwrap();
        let out = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dir.join("ollama+library+gemma4+12b.gguf")).unwrap(), w);
        let mf = std::fs::read_to_string(dir.join("ollama+library+gemma4+12b.Modelfile")).unwrap();
        assert!(mf.contains(&format!("# model-sha256: {}\n", digest(&w))), "{mf}");
        assert!(mf.contains("FROM ./ollama+library+gemma4+12b.gguf\n") && mf.contains("TEMPLATE \"\"\"{{ .Prompt }}\"\"\"\n"), "{mf}");
        assert!(mf.contains("PARAMETER stop \"<end_of_turn>\"\n"), "{mf}");
        for n in ["ollama+library+gemma4+12b.gguf", "ollama+library+gemma4+12b.Modelfile"] {
            assert_eq!(std::fs::metadata(dir.join(n)).unwrap().permissions().mode() & 0o777, 0o644, "{n}");
        }
        assert!(!dir.join(".ollama+library+gemma4+12b.gguf.part").exists());
        assert_eq!(out.model_sha256, digest(&w));
        // The weight is not downloaded a second time.
        let again = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap();
        assert!(again.weight_present);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blob_that_does_not_match_the_manifest_installs_nothing() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, Some(digest(&w)), 32);
        let dir = tmpdir("lie");
        let r = parse_ref("gemma4:12b").unwrap();
        let e = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap_err();
        assert!(matches!(e, StageErr::Fetch(FetchErr::Mismatch { .. })), "{e}");
        let names: Vec<String> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(names.is_empty(), "left behind: {names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_model_is_refused_before_the_weight_is_downloaded() {
        let w = weight();
        let (mut manifest, mut blobs) = model_fixture(&w);
        let proj = b"projector".to_vec();
        manifest["layers"].as_array_mut().unwrap().push(layer_json("application/vnd.ollama.image.projector", &proj));
        blobs.insert(digest(&proj), proj);
        let reg = serve(manifest, blobs, None, 32);
        let dir = tmpdir("proj");
        let r = parse_ref("gemma4:12b").unwrap();
        let e = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap_err();
        assert!(e.to_string().contains("projector"), "{e}");
        assert!(!reg.hits.lock().unwrap().iter().any(|h| h.contains("/blobs/")), "a blob was fetched for a model that is refused");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_different_weight_in_the_store_is_a_conflict_unless_forced() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 64);
        let dir = tmpdir("conflict");
        std::fs::write(dir.join("ollama+library+gemma4+12b.gguf"), b"GGUFold").unwrap();
        let r = parse_ref("gemma4:12b").unwrap();
        let e = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap_err();
        assert!(matches!(e, StageErr::Fetch(FetchErr::Conflict { .. })), "{e}");
        assert_eq!(std::fs::read(dir.join("ollama+library+gemma4+12b.gguf")).unwrap(), b"GGUFold");
        stage(&reg.base, &r, &dir, true, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dir.join("ollama+library+gemma4+12b.gguf")).unwrap(), w);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_weight_resumes_with_range() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 32);
        let dir = tmpdir("resume");
        std::fs::write(dir.join(".ollama+library+gemma4+12b.gguf.part"), &w[..50_000]).unwrap();
        let r = parse_ref("gemma4:12b").unwrap();
        let out = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap();
        assert_eq!(out.resumed_from, 50_000);
        assert_eq!(std::fs::read(dir.join("ollama+library+gemma4+12b.gguf")).unwrap(), w);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_tag_is_the_registrys_404_and_installs_nothing() {
        let w = weight();
        let (manifest, blobs) = model_fixture(&w);
        let reg = serve(manifest, blobs, None, 8);
        let dir = tmpdir("404");
        let r = parse_ref("gemma4:nope").unwrap();
        let e = stage(&reg.base, &r, &dir, false, &mut |_, _| {}).unwrap_err();
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
        // Half a pair is not staged.
        touch("ollama+library+gemma4+12b.gguf");
        assert!(resolve_import_target("ollama:gemma4:12b", &dir).unwrap_err().contains("noo models fetch ollama:gemma4:12b"));
        touch("ollama+library+gemma4+12b.Modelfile");
        for arg in ["ollama:gemma4:12b", "gemma4:12b", "library/gemma4:12b", "ollama:Gemma4:12B"] {
            match resolve_import_target(arg, &dir).unwrap() {
                ImportTarget::Staged(r) => assert_eq!(r.short(), if arg.contains("12B") { "Gemma4:12B" } else { "gemma4:12b" }, "{arg}"),
                other => panic!("{arg}: {other:?}"),
            }
        }
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
