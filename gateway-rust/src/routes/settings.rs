// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Settings routes — config, personas, prompt skills, user directories.
//!
//! Native Rust: YAML config CRUD, settings read/write/export/preference,
//!              file browsing, user dirs, restart status,
//!              prompt skills list/get/create (filesystem markdown scan)
//!              gateway restart (writes a recreate command to the host-watcher spool).
//! NATS delegation: prompt skill evolution (GA engine), persona lens

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, put, delete},
    extract::{Path, Query, State},
    Extension,
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use crate::auth::AuthActor;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use super::{AppError, AppJson, AppResult};
use axum::http::header;

// Python subjects this module has replaced. See `crate::ported`.
crate::ported! {
    GET "/api/prompt-skills" => "worker.prompt_skills.list",
}


pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Settings: Native Rust (YAML config read/write/export) ──
        .route("/api/settings", get(settings_get))
        .route("/api/settings", put(settings_update))
        .route("/api/settings/export", get(settings_export))
        .route("/api/v1/settings", get(settings_get))
        .route("/api/v1/settings", put(settings_update))
        .route("/api/v1/settings/export", get(settings_export))
        .route("/api/v1/settings/preference", get(settings_get_preference))

        // ── Behavioral feature flags: Native Rust (noo_settings SQL) ──
        .route("/api/settings/flags", get(settings_flags_list))
        .route("/api/settings/flags/set", post(settings_flags_set))

        // ── Config sections: Native Rust (YAML file I/O) ──
        .route("/api/config", get(config_get))
        .route("/api/config/{section}", get(config_get_section))
        .route("/api/config/{section}", put(config_update_section))

        // ── User directories: Native Rust (YAML + filesystem) ──
        .route("/api/v1/settings/browse", get(browse_user_dirs))
        .route("/api/v1/settings/user-dirs", get(user_dirs_get))
        .route("/api/v1/settings/user-dirs", post(user_dirs_add))
        .route("/api/v1/settings/user-dirs", delete(user_dirs_remove))
        .route("/api/v1/settings/restart-status", get(restart_status))

        // ── Prompt skills: Native Rust (filesystem markdown scan) ──
        .route("/api/prompt-skills", get(prompt_skills_list))
        .route("/api/prompt-skills/{name}", get(prompt_skills_get))
        .route("/api/prompt-skills", post(prompt_skills_create))
        // LLM-driven create/mutate: the gateway owns this path (the CLI and
        // the MCP tool are core), the evolve add-on decides through its
        // internal `prompt_skills_evolve` row; off, it is an explained 503.
        .route("/api/prompt-skills/evolve", post(prompt_skills_evolve))
        // Writes to an EVOLVED skill (core is refused).
        .route("/api/prompt-skills/{name}", put(prompt_skills_update))
        .route("/api/prompt-skills/{name}/retire", post(prompt_skills_retire))
        .route("/api/prompt-skills/{name}/fitness", post(prompt_skills_fitness))

        // ── Personas: NATS delegation (needs ML) ──
        // /api/v1/personas/{id}/lens REMOVED — same dead import as
        // /api/persona/{id}/chat (see routes/agents.rs). Probed at 400 before
        // removal, never functional.
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

/// Resolve the YAML config path from env or default.
pub(crate) fn config_path() -> String {
    use crate::paths;
    std::env::var("NOO_CONFIG_PATH").unwrap_or_else(|_| {
        paths::resolve(paths::CONFIG_YAML_CANDIDATES)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| paths::CONFIG_YAML_CANDIDATES[0].to_string())
    })
}

/// Internal error helper for the mutation pipeline.
fn cfg_err(msg: String) -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": msg})))
}

/// Mutate the YAML config file safely: advisory flock on `<path>.lock`,
/// FRESH re-read of the on-disk document, apply `mutate`, then atomic
/// tmp+rename write in the same directory.
///
/// The old write path serialized the STARTUP-CACHED document back to disk,
/// which silently reverted any out-of-band edit made to noomesh.yaml while
/// the gateway was running. Every write must therefore be expressed as a
/// mutation of the freshly read document, never as a dump of the cache.
/// (Comments in the YAML are still lost on API writes — serde_yaml does not
/// round-trip them — but out-of-band VALUE edits now survive.)
///
/// Synchronous by design: callers run it inside `spawn_blocking` (flock
/// blocks). The flock also serializes writers WITHIN this process, since
/// each call opens its own file description.
/// Which write path `write_config_bytes` took. Reported so "the config was
/// written without crash-atomicity" is a line in the log, not a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigWriteMode {
    /// Temp file in the same directory, then `rename` — crash-atomic. Needs a
    /// writable directory AND a target that is not a mount point.
    Rename,
    /// Rewrite the existing inode in place, under the flock we already hold.
    /// The only path available when the config is a FILE bind-mount.
    InPlace,
}

/// Can `path` be replaced by a temp-file rename? Both conditions must hold and
/// neither is inferable from the other:
///
/// 1. the parent directory must be writable by this process, and
/// 2. `path` must not be a bind-mount point — `rename(2)` onto one fails
///    **EBUSY** no matter who you are. Verified in a container, not assumed:
///    with `/app` chmod 777 and the process owning it, `mv tmp noomesh.yaml`
///    still returns "Device or resource busy". That is why "make the directory
///    writable" is not on its own a fix for R47, and why this function has to
///    try the rename rather than predict it.
///
/// Returns the temp path to use when a rename is worth attempting.
fn rename_candidate(path: &str) -> Option<String> {
    // The check IS the attempt: create the temp file we would use anyway.
    // Deciding from the mode bits instead would mean reasoning about uid, gid,
    // supplementary groups and ACLs and would still only be a guess — and the
    // caller has to handle a failing rename regardless, because EBUSY on a
    // bind-mounted target is invisible to any permission check.
    //
    // The pid in the name keeps two processes apart; two threads in one
    // process are already serialized by the caller's directory lock.
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::File::create(&tmp).ok().map(|_| tmp)
}

/// Write `bytes` to `path`, atomically when the platform allows it.
///
/// Both modes run under the caller's exclusive flock on `path`, so concurrent
/// writers are serialized either way and the RESULT is identical. They differ
/// only in what a crash *during* the write leaves behind: `Rename` leaves the
/// old file intact, `InPlace` can leave a truncated one. We take `Rename`
/// whenever it is possible and say so when it is not — a fallback on a
/// durability path that nobody can see is worse than the durability gap.
fn write_config_bytes(path: &str, bytes: &[u8]) -> std::io::Result<ConfigWriteMode> {
    use std::io::{Seek as _, Write as _};

    if let Some(tmp) = rename_candidate(path) {
        let attempt = (|| -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        match attempt {
            Ok(()) => return Ok(ConfigWriteMode::Rename),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                // EBUSY is the bind-mounted-file case and is EXPECTED on a
                // dist install; anything else is a surprise worth the log line
                // even though we are about to try the other path.
                tracing::info!(
                    path = %path, error = %e,
                    "config rename not possible here — rewriting in place under the lock"
                );
            }
        }
    }

    // In-place rewrite. `set_len` AFTER the write, not before: truncating
    // first would leave the file empty for the duration of the write, and a
    // reader that does not take the lock (the gateway's own startup, the
    // Python worker) would parse an empty config as a valid empty config.
    //
    // The directory lock is still held by the caller, so no other writer of
    // this config can be inside here at the same time.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "{path} is not writable by the gateway ({e}). It runs as uid 65532 and needs \
                     write permission on this file: `docker run --rm -v \"$PWD/noomesh.yaml:/f\" \
                     alpine sh -c 'chgrp 65532 /f && chmod 660 /f'` (the launcher does this on \
                     start; see docs/reference/config.md)"
                ),
            )
        })?;
    f.rewind()?;
    f.write_all(bytes)?;
    f.set_len(bytes.len() as u64)?;
    f.sync_all()?;
    // Once per process, not per write: an operator who sees it once has the
    // information, and `noo config set` is not a hot path but the dashboard
    // does poll settings writes.
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            path = %path,
            "config written IN PLACE (not crash-atomic): {path} is a bind-mounted file, so \
             tmp+rename returns EBUSY. Writes are still serialized by an flock on the file; \
             only a crash mid-write could truncate it. To regain atomicity, mount the \
             directory containing noomesh.yaml instead of the file."
        );
    });
    Ok(ConfigWriteMode::InPlace)
}

pub(crate) fn locked_mutate_yaml_file<F>(
    path: &str,
    mutate: F,
) -> Result<Value, (StatusCode, Json<Value>)>
where
    F: FnOnce(&mut Value) -> Result<(), (StatusCode, Json<Value>)>,
{
    // `Write` is no longer needed here: the bytes are written by
    // `write_config_bytes`, which owns both write paths.
    use std::os::unix::io::AsRawFd as _;

    // ── Advisory lock: on the config's DIRECTORY ──
    //
    // Three candidates, and only this one is correct:
    //
    // * `<path>.lock`, the original, needs WRITE permission on the directory
    //   to create the sibling. The gateway runs nonroot 65532 and `/app` is
    //   root-owned — it is created by COPY in the image — so every
    //   `noo config set` on a dist install answered
    //     500 Failed to open config lock /app/noomesh.yaml.lock: Permission denied
    //
    // * the config FILE itself needs no directory permission, but it is not a
    //   lock: the write path below replaces the file by rename, so the winner
    //   ends up holding a lock on an orphaned inode while the next writer
    //   locks the new one and the two no longer exclude each other. The
    //   `concurrent_mutations_do_not_lose_updates` test catches exactly this.
    //
    // * the DIRECTORY, opened O_RDONLY. `flock` works on a directory fd, needs
    //   only r+x (which `drwxr-xr-x` gives us), the inode is stable across any
    //   rename of the files inside it, and it exists even when the config file
    //   does not — so a first-ever write can take the lock too. Verified in a
    //   container as uid 65532 against a 0555 directory before being written
    //   here, including that a second fd is refused.
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let lock_dir = std::fs::File::open(&dir).map_err(|e| {
        cfg_err(format!(
            "Failed to open the config directory {} to lock it: {e}",
            dir.display()
        ))
    })?;
    if unsafe { libc::flock(lock_dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(cfg_err(format!(
            "Failed to lock config: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Lock is held until `lock_dir` drops (function exit, any path).

    // ── Fresh read (never the startup cache) ──
    let mut doc: Value = match std::fs::read_to_string(path) {
        Ok(contents) => {
            let yaml_val: serde_yaml::Value = serde_yaml::from_str(&contents).map_err(|e| {
                tracing::error!(path = %path, error = %e, "Refusing to overwrite unparseable config");
                cfg_err(format!("Failed to parse YAML config: {e}"))
            })?;
            serde_json::to_value(&yaml_val)
                .map_err(|e| cfg_err(format!("YAML->JSON conversion failed: {e}")))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => {
            return Err(cfg_err(format!("Failed to read config {path}: {e}")));
        }
    };

    // ── Apply the change ──
    mutate(&mut doc)?;

    // ── Atomic write: tmp file in the same dir, then rename ──
    let yaml_val: serde_yaml::Value = serde_json::from_value(doc.clone())
        .map_err(|e| cfg_err(format!("JSON->YAML conversion failed: {e}")))?;
    let yaml_str = serde_yaml::to_string(&yaml_val)
        .map_err(|e| cfg_err(format!("YAML serialization failed: {e}")))?;

    if let Err(e) = write_config_bytes(path, yaml_str.as_bytes()) {
        tracing::error!(path = %path, error = %e, "Failed to write config file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to write config: {e}"), "path": path})),
        ));
    }

    Ok(doc)
}

/// Async wrapper: run the locked mutation on the blocking pool, then refresh
/// the in-memory cache from the document that actually landed on disk.
/// Returns the new full document (handlers use it to build responses).
pub async fn mutate_config<F>(
    state: &AppState,
    mutate: F,
) -> Result<Value, (StatusCode, Json<Value>)>
where
    F: FnOnce(&mut Value) -> Result<(), (StatusCode, Json<Value>)> + Send + 'static,
{
    let path = config_path();
    let doc = tokio::task::spawn_blocking(move || locked_mutate_yaml_file(&path, mutate))
        .await
        .map_err(|e| cfg_err(format!("Config write task failed: {e}")))??;
    let mut cache = state.config_yaml.write().await;
    *cache = doc.clone();
    // Readers that cannot reach AppState keep their own live view; without
    // this a written value waited for a gateway recreate.
    crate::web_search::refresh_live_config(&doc);
    // a write that lands on an orphaned mount reports success
    // and is lost at the next recreate. Say so now.
    crate::config_mount::check_and_alert(state, &config_path(), "after config write").await;
    Ok(doc)
}

/// Deep-merge `overlay` into `base`. Objects are merged recursively;
/// all other types in `overlay` overwrite `base`.
/// Merge `overlay` into `base`, with an explicit `null` REMOVING the key.
///
/// The config API had no way to unset anything: every write merged, so a key
/// written once stayed forever. That mattered the day `noo_config_set` wrote
/// wrapper keys into live config (#337 — the MCP tool nested its payload under
/// a field name, and this function merged it verbatim). There was no call that
/// could take those back out; the only repair was hand-editing noomesh.yaml on
/// the controller, which is exactly the out-of-band edit the config lock exists
/// to avoid. A YAML config key set to null carries no meaning that "absent"
/// does not, so null is free to mean remove.
fn deep_merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                if overlay_val.is_null() {
                    base_map.remove(key);
                    continue;
                }
                let entry = base_map.entry(key.clone()).or_insert(Value::Null);
                deep_merge(entry, overlay_val);
            }
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Config section handlers
// ═══════════════════════════════════════════════════════════════

/// GET /api/config — Return full config as JSON (from cache).
async fn config_get(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = config_with_legacy_mirrors(&*state.config_yaml.read().await);
    (StatusCode::OK, Json(config)).into_response()
}

/// GET /api/config/{section} — Return a single config section (from cache).
async fn config_get_section(
    State(state): State<Arc<AppState>>,
    Path(section): Path<String>,
) -> impl IntoResponse {
    let config = state.config_yaml.read().await;
    let effective = effective_config_section(&config, &section);

    match config.get(&effective) {
        Some(val) => (StatusCode::OK, Json(val.clone())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Section '{}' not found", section)})),
        )
            .into_response(),
    }
}

/// Config keys that are POSTURE gates and are therefore not settable here by
/// ANYONE — admin included. The first of the two walls #101 built, re-pointed
/// at `posture::RETIRED_YAML_GATES` now that the keys are not merely
/// "read-only through this API" but removed from the YAML tier outright: the
/// gateway refuses to START on a `noomesh.yaml` that sets one
/// (`posture::yaml_gate_refusal`). So writing one through the config API would
/// not weaken the running gate — it would brick the next boot. Refusing here
/// is the kinder failure, and it keeps the admin from arming a trap.
///
/// Distinct from [`GATED_CONFIG_SECTIONS`], which is about WHO may write a
/// section at all. This one is about a KEY nobody may write. Both run.
pub(crate) fn gate_keys() -> Vec<(&'static str, &'static str)> {
    crate::posture::RETIRED_YAML_GATES
        .iter()
        .map(|(section, key, _)| (*section, *key))
        .collect()
}

/// The refusal, if a section write touches a retired gate key. Pure, for tests.
///
/// Matches the key at the top level of the body (`PUT /api/config/security`
/// with `{"exec_approval_mode": …}`) — the shape `noo_config_set` sends.
pub(crate) fn config_write_refused(section: &str, body: &Value) -> Option<String> {
    let touched: Vec<&str> = gate_keys()
        .into_iter()
        .filter(|(sec, key)| *sec == section && body.get(*key).is_some())
        .map(|(_, key)| key)
        .collect();
    if touched.is_empty() {
        return None;
    }
    let gate = crate::posture::RETIRED_YAML_GATES
        .iter()
        .find(|(sec, key, _)| *sec == section && touched.contains(key))
        .map(|(_, _, gate)| *gate)
        .unwrap_or("NOO_EXEC_APPROVAL_MODE");
    Some(format!(
        "{section}.{} cannot be set through the config API: it decides the gate that \
         constrains callers of this API, and it is no longer read from noomesh.yaml at \
         all — the gateway refuses to start on a config that sets it. Set it as posture: \
         `noo security posture set {gate} <value>` (restart to apply)",
        touched.join(", ")
    ))
}

/// Config sections that were renamed, as `(old, new)` (the
/// `video_memory` section is `recall_memory` since 0.6.0). For one release
/// after 0.6.0 both spellings address the SAME section here and in the
/// `config:<section>` control scope (`auth::control_scope_allows`), so an
/// older evolve image holding `config:video_memory` keeps tuning it, and an
/// operator yaml on either key is read. Removed with the old names.
pub(crate) const RENAMED_CONFIG_SECTIONS: &[(&str, &str)] = &[("video_memory", "recall_memory")];

/// Every spelling of `section`: itself, then its old or new name if renamed.
pub(crate) fn config_section_spellings(section: &str) -> Vec<&str> {
    let mut out = vec![section];
    for (old, new) in RENAMED_CONFIG_SECTIONS {
        if section == *old {
            out.push(new);
        } else if section == *new {
            out.push(old);
        }
    }
    out
}

/// The key a read or write of `section` lands on in `doc`. For a renamed
/// section: the NEW key when the document has it (the new name wins when
/// both are present, matching the Python loader), else the OLD key — whether
/// the document has only that (an operator's yaml is never rewritten under
/// them) or has neither. Creating the OLD key while neither exists is the safe
/// default until evolve reads the new one: evolve indexes the raw
/// `GET /api/config` by `video_memory`, so a section created as
/// `recall_memory` would drop its adaptations. The alias-removal release
/// switches the neither-present case to the new key. Any other section is
/// itself.
pub(crate) fn effective_config_section(doc: &Value, section: &str) -> String {
    for (old, new) in RENAMED_CONFIG_SECTIONS {
        if section == *old || section == *new {
            if doc.get(*new).is_some() {
                return (*new).to_string();
            }
            return (*old).to_string();
        }
    }
    section.to_string()
}

/// The full-config view `GET /api/config` serves: the document, plus — for a
/// renamed section held under its NEW key — a read-only mirror under the OLD
/// key with the same (effective) contents. Evolve still indexes the full
/// config by `video_memory`; without the mirror an operator who renamed the
/// yaml section would silently lose every evolve adaptation to it. The
/// mirror also replaces a stale old-key copy when both are present, because
/// the new key is the one in effect. Removed with the old names.
pub(crate) fn config_with_legacy_mirrors(doc: &Value) -> Value {
    let mut out = doc.clone();
    if let Some(m) = out.as_object_mut() {
        for (old, new) in RENAMED_CONFIG_SECTIONS {
            if let Some(v) = doc.get(*new) {
                m.insert((*old).to_string(), v.clone());
            }
        }
    }
    out
}

/// Config sections whose contents decide whether a security control applies.
/// `PUT /api/config/{section}` deep-merges whatever it is handed with no
/// validation, and the agent's own `noo_config_set` tool reaches this route —
/// so before the model could widen the very policy that classified its
/// next tool call. Each entry, and what it gates:
///
/// - `security` — deserialises to `config::SecurityConfig` (`jwt_secret`,
///   `cluster_secret`) and used to carry `exec_approval_mode`, the HIGH-risk
///   gate itself. Now posture-only, but the section stays sealed: the Python
///   worker still reads `high_risk_tools` / `medium_risk_tools` from it, which
///   is the risk classifier's input list.
/// - `tools` — `tools.allowed_paths` feeds `local_files::FilePolicy`. Adding a
///   path makes writes there legal; adding `/` makes every write legal.
/// - `workspace` — `workspace.path` is a WRITABLE root in the same policy, so a
///   `local_files` write inside it classifies MEDIUM instead of HIGH and skips
///   the approval gate entirely.
/// - `watched_folders` — each `writable: true` folder is another writable root,
///   same downgrade.
/// - `tls` — `tls.cert` / `tls.key` / `tls.ca`: which material this process
///   would trust.
///
/// This is a deny-list, not an allow-list, because the route is the general
/// config surface and most sections are ordinary settings. A new gate-bearing
/// section must be added here; `gated_config_sections_are_real()` pins each
/// name against `config.rs` so a rename cannot quietly empty the list.
pub(crate) const GATED_CONFIG_SECTIONS: &[&str] =
    &["security", "tls", "tools", "workspace", "watched_folders"];

/// Who may write a gate-bearing config section: an Admin **person**, and only
/// over their own credential.
///
/// Returns `Some(reason)` to refuse. Two independent rules:
///
/// 1. Any cluster-token caller is refused, `Internal` as well as `Node`. The
///    `Internal` kind is the one that matters: the worker calls back with the
///    controller HMAC, so an agent tool call arrives here as a fully
///    privileged internal service with no person attached. A gate change is a
///    decision by a named human, and a cluster token names none.
/// 2. A JWT caller needs `Role::Admin`. Operator (`write` scope) is not
///    enough — that is the exact scope the posture comments already say must
///    not be able to flip a gate.
///
/// No credential at all is refused too: these sections are never the
/// unauthenticated path.
pub(crate) fn config_section_guard(
    section: &str,
    role: Option<crate::auth::Role>,
    cluster_caller: bool,
) -> Option<String> {
    if !GATED_CONFIG_SECTIONS.contains(&section) {
        return None;
    }
    if cluster_caller {
        return Some(format!(
            "config section '{section}' holds security gates — a cluster \
             credential may not write it. Log in as an admin (noo auth login) \
             and retry; exec-approval lives in posture (noo security posture set)."
        ));
    }
    match role {
        Some(crate::auth::Role::Admin) => None,
        Some(r) => Some(format!(
            "config section '{section}' holds security gates — role '{}' may \
             not write it (admin required).",
            r.as_str()
        )),
        None => Some(format!(
            "config section '{section}' holds security gates — an authenticated \
             admin is required."
        )),
    }
}

/// The `writable` flag on a watched folder, on the OTHER route that can set it.
///
/// `user_dirs_add` edits `watched_folders` directly (its PUT
/// `user-dirs/writable` sibling was removed 2026-09-27 with the legacy
/// dashboard, its only caller), bypassing `PUT /api/config/watched_folders` and therefore its
/// guard. A writable folder is a writable root in `local_files::FilePolicy`,
/// and a write inside a writable root classifies MEDIUM instead of HIGH — so
/// marking a folder writable is one of the ways to route a file write around
/// the exec-approval gate entirely.
///
/// Deliberately narrower than the section guard: ADDING a read-only folder is
/// ordinary ingestion config and stays open to any authenticated caller. Only
/// granting `writable` is an admin decision.
fn writable_folder_guard(
    writable: bool,
    role: Option<crate::auth::Role>,
    cluster_caller: bool,
) -> Option<String> {
    if !writable {
        return None;
    }
    config_section_guard("watched_folders", role, cluster_caller).map(|_| {
        "marking a watched folder `writable` grants a writable root to the file \
         tools, which downgrades writes there from HIGH risk to MEDIUM — admin \
         only, and not over a cluster credential. Add the folder read-only, or \
         have an admin set the flag."
            .to_string()
    })
}

/// PUT /api/config/{section} — Update a single config section and save.
async fn config_update_section(
    State(state): State<Arc<AppState>>,
    Path(section): Path<String>,
    actor: Option<Extension<AuthActor>>,
    requester: Option<Extension<crate::auth::RequesterCtx>>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Two walls, both kept (the key wall first, because it
    // applies to EVERY caller including an admin: a retired gate key in the
    // yaml is a startup refusal, so letting it be written would arm a trap
    // rather than weaken the running gate.
    let refusal = config_write_refused(&section, &body).or_else(|| {
        // ...then the section wall: who may write a gate-bearing section.
        config_section_guard(
            &section,
            requester.as_ref().map(|r| r.0.role),
            cluster.is_some(),
        )
    });
    if let Some(reason) = refusal {
        crate::routes::core::audit_event(
            &state.db,
            "config_update_refused",
            "warning",
            &actor_name(&actor),
            &format!("config:{section}"),
            "refused",
            json!({ "section": section, "keys": top_level_keys(&body), "reason": reason }),
        )
        .await;
        tracing::warn!(target: "security", section = %section, actor = %actor_name(&actor),
            "config_update_refused");
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }

    // Mutate the FRESH on-disk document under the config lock — merging into
    // the startup cache silently reverted out-of-band edits (WP-C hazard 1).
    let requested = section.clone();
    let overlay = body.clone();
    let config = match mutate_config(&state, move |doc| {
        // A renamed section's either spelling writes the one the yaml holds.
        let sec = effective_config_section(doc, &requested);
        if let Some(existing) = doc.get_mut(&sec) {
            deep_merge(existing, &overlay);
        } else if let Some(m) = doc.as_object_mut() {
            m.insert(sec, overlay);
        }
        Ok(())
    })
    .await
    {
        Ok(doc) => doc,
        Err((status, body)) => return (status, body).into_response(),
    };

    // Audit the config change (H-L1). Record the changed keys, not values —
    // config sections can hold sensitive data.
    crate::routes::core::audit_event(
        &state.db,
        "config_update",
        "warning",
        &actor_name(&actor),
        &format!("config:{section}"),
        "ok",
        json!({ "section": section, "keys": top_level_keys(&body) }),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "updated",
            "section": section,
            "data": config.get(effective_config_section(&config, &section)),
        })),
    )
        .into_response()
}

/// Actor name from the auth extension, or "unknown" (e.g. auth-disabled mode).
fn actor_name(actor: &Option<Extension<AuthActor>>) -> String {
    actor
        .as_ref()
        .map(|a| a.0 .0.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Top-level object keys of a JSON body (for audit without logging values).
fn top_level_keys(body: &Value) -> Vec<String> {
    body.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

// ═══════════════════════════════════════════════════════════════
// Settings handlers (ported from Python SettingsStore NATS delegation)
// ═══════════════════════════════════════════════════════════════

/// GET /api/settings, /api/v1/settings — Return full config as JSON (from cache).
///
/// Replaces Python worker.settings.get (SettingsStore.snapshot()).
/// Now reads directly from the YAML config cache instead of delegating to Python.
async fn settings_get(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = state.config_yaml.read().await.clone();
    (StatusCode::OK, Json(config)).into_response()
}

/// PUT /api/settings, /api/v1/settings — Deep-merge body into config and persist.
///
/// Replaces Python worker.settings.update (SettingsStore.restore()).
/// Accepts a partial or full config object, deep-merges into the existing
/// config, writes to disk, and updates the in-memory cache.
async fn settings_update(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Deep-merge into the FRESH on-disk document under the config lock.
    let overlay = body.clone();
    if let Err((status, err_body)) = mutate_config(&state, move |doc| {
        deep_merge(doc, &overlay);
        Ok(())
    })
    .await
    {
        return (status, err_body).into_response();
    }

    crate::routes::core::audit_event(
        &state.db,
        "config_update",
        "warning",
        &actor_name(&actor),
        "config",
        "ok",
        json!({ "keys": top_level_keys(&body) }),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({ "status": "updated" })),
    )
        .into_response()
}

/// GET /api/settings/export, /api/v1/settings/export — Download full config as YAML file.
///
/// Replaces Python worker.settings.export (SettingsStore.snapshot() as download).
/// Returns the config as a YAML file attachment for backup/export.
async fn settings_export(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = state.config_yaml.read().await.clone();

    // Convert JSON Value -> YAML string
    let yaml_val: serde_yaml::Value = match serde_json::from_value(
        serde_json::to_value(&config).unwrap_or_default(),
    ) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("JSON->YAML conversion failed: {e}")})),
            )
                .into_response();
        }
    };

    let yaml_str = match serde_yaml::to_string(&yaml_val) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("YAML serialization failed: {e}")})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-yaml"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"noomesh-settings.yaml\""),
        ],
        yaml_str,
    )
        .into_response()
}

#[derive(Deserialize)]
struct PreferenceParams {
    key: Option<String>,
    default: Option<String>,
}

/// GET /api/v1/settings/preference?key=X&default=Y — Read a specific preference.
///
/// Replaces Python worker.settings.get_preference (SettingsStore.get_preference()).
/// Looks up `preferences.<key>` in the YAML config. Falls back to `default`
/// (or null) if the key is not found.
async fn settings_get_preference(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PreferenceParams>,
) -> impl IntoResponse {
    let key = params.key.unwrap_or_default();
    if key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing 'key' query parameter"})),
        )
            .into_response();
    }

    let config = state.config_yaml.read().await;

    // Look up preferences.<key> in the config
    let value = config
        .get("preferences")
        .and_then(|prefs| prefs.get(&key))
        .cloned()
        .unwrap_or_else(|| {
            // Fall back to the default parameter, or null
            params.default
                .as_ref()
                .map(|d| Value::String(d.clone()))
                .unwrap_or(Value::Null)
        });

    (
        StatusCode::OK,
        Json(json!({ "key": key, "value": value })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════
// User directories handlers
// ═══════════════════════════════════════════════════════════════

/// Extract the `watched_folders.folders` list from the YAML config.
/// Each folder has `host`, `mount`, `label`, `writable` fields.
fn get_folders(config: &Value) -> Vec<Value> {
    config
        .get("watched_folders")
        .and_then(|wf| wf.get("folders"))
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Write the `watched_folders.folders` list into a config document (pure —
/// callers persist via `mutate_config` so the write is locked + fresh + atomic).
fn put_folders(doc: &mut Value, folders: Vec<Value>) -> Result<(), (StatusCode, Json<Value>)> {
    let obj = doc.as_object_mut().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Config root is not an object"})),
        )
    })?;

    let wf = obj
        .entry("watched_folders")
        .or_insert_with(|| json!({}));
    let wf_obj = wf.as_object_mut().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "watched_folders is not an object"})),
        )
    })?;

    wf_obj.insert("folders".into(), Value::Array(folders));
    Ok(())
}

#[derive(Deserialize)]
struct BrowseParams {
    path: Option<String>,
    /// Include dotfiles/dot-dirs in listings. Default false — the picker
    /// is for choosing folders to ingest/watch, and ~/.ssh in the KB is
    /// nobody's intention.
    hidden: Option<bool>,
}

/// A root the OPERATOR has declared, and the only thing the picker will
/// ever show.
///
/// `host` is the path as it exists on the machine; `mount` is where that
/// same directory is visible inside this container. They differ because
/// the compose override `noo onboard` generates bind-mounts each declared
/// directory individually (`<host>:/user-dirs/<base>:ro`). The UI speaks
/// host paths end to end, so every listing is translated back on the way
/// out — what the operator clicks is what lands in `watched_folders`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BrowseRoot {
    label: String,
    host: String,
    mount: String,
}

/// Return `p` minus the `root` prefix, but only on a whole-component
/// boundary.
///
/// A plain `starts_with` would let `/home/alice-old` in under a declared
/// root of `/home/alice`, which is the entire point of having roots.
/// `Some("")` means "p IS the root".
fn strip_root(root: &str, p: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return None;
    }
    if p == root {
        return Some(String::new());
    }
    p.strip_prefix(root)
        .filter(|rest| rest.starts_with('/'))
        .map(|rest| rest.to_string())
}

/// The declared browse roots, in the order the picker should offer them.
///
/// Sources, all operator-declared, none discovered:
///   * `watched_folders.folders[]` — added through this API or `NOO_USER_DIRS`
///     at onboard; each one is a real bind mount.
///   * `workspace` — the read-write scratch root, same machinery.
///   * `tools.allowed_paths` entries that name nothing already covered —
///     container-native roots (`/data`) where host and mount are the same
///     path.
///
/// Until 2026-09-11 this function did not exist: the picker walked a
/// read-only bind of the WHOLE host (`/mnt`, `/home`, `/media` →
/// `/host-fs/...`) and *discovered* roots by scanning it, with a hardcoded
/// allow-list of `/mnt`, `/home`, `/Users`, `/data`, `/workspace`,
/// `/media`, `/run/media`. That made `USER nonroot` the only thing between
/// any gateway file-read bug and `~/.config/sops/age/keys.txt`, `~/.ssh`,
/// and every 0644 file in every home on the box — and on WSL, `/mnt/*` is
/// world-readable, so it was not even a wall. See tracker row R22.
fn declared_browse_roots(config: &Value) -> Vec<BrowseRoot> {
    let mut roots: Vec<BrowseRoot> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for f in get_folders(config) {
        let host = f.get("host").and_then(|v| v.as_str()).unwrap_or_default();
        let mount = f.get("mount").and_then(|v| v.as_str()).unwrap_or_default();
        if host.is_empty() || mount.is_empty() || !seen.insert(mount.to_string()) {
            continue;
        }
        let label = f
            .get("label")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| host.rsplit('/').next().unwrap_or(host).to_string());
        roots.push(BrowseRoot { label, host: host.to_string(), mount: mount.to_string() });
    }

    if let Some(ws) = config.get("workspace") {
        let enabled = ws.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        let host = ws.get("host").and_then(|v| v.as_str()).unwrap_or_default();
        let mount = ws
            .get("mount")
            .or_else(|| ws.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if enabled && !host.is_empty() && !mount.is_empty() && seen.insert(mount.to_string()) {
            roots.push(BrowseRoot {
                label: "Workspace".into(),
                host: host.to_string(),
                mount: mount.to_string(),
            });
        }
    }

    // Container-native declared paths: host == mount, nothing to translate.
    if let Some(paths) = config
        .get("tools")
        .and_then(|t| t.get("allowed_paths"))
        .and_then(|v| v.as_array())
    {
        for p in paths.iter().filter_map(|v| v.as_str()) {
            if p.is_empty() || !seen.insert(p.to_string()) {
                continue;
            }
            roots.push(BrowseRoot {
                label: p.rsplit('/').next().unwrap_or(p).to_string(),
                host: p.to_string(),
                mount: p.to_string(),
            });
        }
    }

    roots
}

/// Map a requested HOST path onto the container path to read, confined to
/// the declared roots. `None` = not under anything the operator declared,
/// which is a refusal, not a fallback.
///
/// Longest root wins, so a declared subdirectory of a declared directory
/// resolves through its own (possibly differently-writable) mount.
fn resolve_declared<'a>(roots: &'a [BrowseRoot], host_path: &str) -> Option<(String, &'a BrowseRoot)> {
    let mut best: Option<(usize, String, &BrowseRoot)> = None;
    for r in roots {
        if let Some(rest) = strip_root(&r.host, host_path) {
            let fs = format!("{}{}", r.mount.trim_end_matches('/'), rest);
            let len = r.host.trim_end_matches('/').len();
            if best.as_ref().map(|(b, _, _)| len > *b).unwrap_or(true) {
                best = Some((len, fs, r));
            }
        }
    }
    best.map(|(_, fs, r)| (fs, r))
}

/// The picker's quick-jump anchors, as the UI wants them: `{label, path}`
/// with HOST paths.
fn browse_roots_json(roots: &[BrowseRoot]) -> Vec<Value> {
    roots
        .iter()
        .map(|r| json!({"label": r.label, "path": r.host}))
        .collect()
}

/// The one sentence the picker shows when it has nothing to browse, or when
/// a path falls outside every declared root. It has to name the fix, because
/// "Access denied" on a directory the operator can plainly see in their own
/// terminal is otherwise just baffling.
const BROWSE_UNDECLARED_HINT: &str = "This gateway browses only directories the operator has declared. \
Add one by typing its full host path (File Locations → Add path, or NOO_USER_DIRS at onboard), then \
restart the stack so the bind mount exists.";

/// GET /api/v1/settings/browse — Browse declared user directories.
///
/// Without `?path=`: folder metadata (host, mount, label, writable, exists).
/// With `?path=X`: the contents of that directory, where X is a HOST path
/// under a declared root. Anything else is a 403 that names the fix.
///
/// This endpoint used to be able to list any directory on the machine. It
/// can no longer reach a directory that is not individually bind-mounted,
/// which means the picker cannot be used to *discover* a folder — only to
/// navigate one already declared. That is the honest trade: a picker that
/// browses the whole host is a host-wide read primitive wearing a file
/// dialog. Adding a folder is now a typed path plus a restart.
async fn browse_user_dirs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BrowseParams>,
) -> impl IntoResponse {
    let config = state.config_yaml.read().await.clone();
    let roots = declared_browse_roots(&config);

    // If a specific path is requested, resolve it inside a declared root.
    if let Some(ref dir_path) = params.path {
        let Some((fs_path, root)) = resolve_declared(&roots, dir_path) else {
            tracing::warn!(path = %dir_path, "browse_path_not_declared");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!("'{dir_path}' is not inside a declared directory"),
                    "hint": BROWSE_UNDECLARED_HINT,
                    "roots": browse_roots_json(&roots),
                })),
            )
                .into_response();
        };

        // A root that has been DECLARED but not yet mounted is the ordinary
        // state between "Add path" and the restart, and it deserves its own
        // sentence. validate_path's failure for a missing path is
        // "Access denied: path does not exist", which reads as a permissions
        // problem for a directory the operator can see in their own terminal.
        if !tokio::fs::metadata(&root.mount).await.map(|m| m.is_dir()).unwrap_or(false) {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!("'{}' is declared but not mounted yet", root.host),
                    "hint": "Restart the stack (`noo stack restart`) so the bind mount is created.",
                    "needs_restart": true,
                    "roots": browse_roots_json(&roots),
                })),
            )
                .into_response();
        }

        // Belt and braces: the root match above is a string operation, so a
        // symlink inside a declared mount could still point out of it.
        // validate_path canonicalizes and re-checks against the mount.
        if let Err(e) = crate::security::validate_path(&fs_path, &[root.mount.as_str()]) {
            tracing::warn!(path = %dir_path, fs_path = %fs_path, error = %e, "browse_path_rejected");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": format!("Access denied: {e}")})),
            )
                .into_response();
        }

        return match list_directory(&fs_path).await {
            Ok(mut entries) => {
                // Hide dotfiles unless explicitly requested.
                if !params.hidden.unwrap_or(false) {
                    entries.retain(|e| {
                        e.get("name")
                            .and_then(|v| v.as_str())
                            .map(|n| !n.starts_with('.'))
                            .unwrap_or(true)
                    });
                }
                // Present HOST paths to the UI — translate the container
                // mount back to the host path the operator declared, so what
                // they pick is what lands in watched_folders / user-dirs.
                for e in entries.iter_mut() {
                    if let Some(p) = e.get("path").and_then(|v| v.as_str()) {
                        if let Some(rest) = strip_root(&root.mount, p) {
                            e["path"] = json!(format!("{}{}", root.host.trim_end_matches('/'), rest));
                        }
                    }
                }
                (
                    StatusCode::OK,
                    Json(json!({
                        "path": dir_path,
                        "entries": entries,
                        "roots": browse_roots_json(&roots),
                    })),
                )
                    .into_response()
            }
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Cannot browse '{}': {}", dir_path, e)})),
            )
                .into_response(),
        };
    }

    // No path — return folder metadata like Python does
    let folders = get_folders(&config);
    let watched_enabled = config
        .get("watched_folders")
        .and_then(|wf| wf.get("enabled"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    let mut dirs = Vec::new();
    for folder in &folders {
        let host = folder.get("host").and_then(|v| v.as_str()).unwrap_or_default();
        let mount = folder.get("mount").and_then(|v| v.as_str()).unwrap_or_default();
        let label = folder.get("label").and_then(|v| v.as_str()).unwrap_or("");
        let writable = folder.get("writable").and_then(|v| v.as_bool()).unwrap_or(false);
        let exists = tokio::fs::metadata(mount).await.map(|m| m.is_dir()).unwrap_or(false);

        dirs.push(json!({
            "host": host,
            "mount": mount,
            "label": label,
            "writable": writable,
            "exists": exists,
        }));
    }

    // Workspace info (if present)
    let workspace = config.get("workspace").and_then(|ws| {
        let enabled = ws.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if !enabled {
            return None;
        }
        let host = ws.get("host").and_then(|v| v.as_str()).unwrap_or_default();
        let mount = ws.get("mount")
            .or_else(|| ws.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let path = ws.get("path").and_then(|v| v.as_str()).unwrap_or_default();
        let exists = !path.is_empty() && std::path::Path::new(path).is_dir();
        Some(json!({
            "host": host,
            "mount": mount,
            "exists": exists,
        }))
    });

    (StatusCode::OK, Json(json!({
        "dirs": dirs,
        "workspace": workspace,
        "watched_folders_enabled": watched_enabled,
        // The picker's whole world. Empty means there is nothing to browse
        // yet, and the UI says so rather than showing an empty /home.
        "roots": browse_roots_json(&roots),
        "browse_hint": BROWSE_UNDECLARED_HINT,
    }))).into_response()
}

/// List the contents of a single directory, returning file metadata.
async fn list_directory(path: &str) -> Result<Vec<Value>, std::io::Error> {
    let mut entries = Vec::new();
    let mut read_dir = tokio::fs::read_dir(path).await?;

    while let Some(entry) = read_dir.next_entry().await? {
        let metadata = entry.metadata().await.ok();
        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

        entries.push(json!({
            "name": entry.file_name().to_string_lossy(),
            "path": entry.path().to_string_lossy(),
            "is_directory": is_dir,
            "size": size,
        }));
    }

    // Sort: directories first, then by name
    entries.sort_by(|a, b| {
        let a_dir = a.get("is_directory").and_then(|v| v.as_bool()).unwrap_or(false);
        let b_dir = b.get("is_directory").and_then(|v| v.as_bool()).unwrap_or(false);
        match (b_dir, a_dir) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => {
                let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                a_name.to_lowercase().cmp(&b_name.to_lowercase())
            }
        }
    });

    Ok(entries)
}

/// GET /api/v1/settings/user-dirs — Return the watched folders list + workspace.
async fn user_dirs_get(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = state.config_yaml.read().await;
    let folders = get_folders(&config);
    let workspace = config.get("workspace").cloned().unwrap_or(json!(null));
    (StatusCode::OK, Json(json!({
        "directories": folders,
        "workspace": workspace,
    }))).into_response()
}

#[derive(Deserialize)]
struct AddFolderBody {
    host: String,
    mount: Option<String>,
    label: Option<String>,
    writable: Option<bool>,
}

/// POST /api/v1/settings/user-dirs — Add a new folder entry.
async fn user_dirs_add(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<crate::auth::RequesterCtx>>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    Json(body): Json<AddFolderBody>,
) -> impl IntoResponse {
    if let Some(reason) = writable_folder_guard(
        body.writable.unwrap_or(false),
        requester.as_ref().map(|r| r.0.role),
        cluster.is_some(),
    ) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }

    // Auto-generate mount path from host basename if not provided or empty
    let mount = body.mount
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| {
            let dir_name = std::path::Path::new(&body.host)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "user-dir".to_string());
            format!("/user-dirs/{}", dir_name)
        });

    let label = body.label.unwrap_or_default();
    let writable = body.writable.unwrap_or(false);

    let new_folder = json!({
        "host": body.host,
        "mount": mount,
        "label": label,
        "writable": writable,
    });

    // Dup-check + insert against the FRESH on-disk document, under the lock.
    let entry = new_folder.clone();
    let mount_key = mount.clone();
    if let Err((status, err_body)) = mutate_config(&state, move |doc| {
        let mut folders = get_folders(doc);
        let already_exists = folders.iter().any(|f| {
            f.get("mount").and_then(|p| p.as_str()) == Some(mount_key.as_str())
        });
        if already_exists {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Directory already exists at mount: {}", mount_key)})),
            ));
        }
        folders.push(entry);
        // Ensure watched_folders.enabled is set
        if let Some(wf) = doc.get_mut("watched_folders").and_then(|v| v.as_object_mut()) {
            wf.insert("enabled".into(), json!(true));
        }
        put_folders(doc, folders)
    })
    .await
    {
        return (status, err_body).into_response();
    }

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "entry": new_folder, "needs_restart": true })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RemoveFolderBody {
    host: String,
}

/// DELETE /api/v1/settings/user-dirs — Remove a folder entry by host path.
async fn user_dirs_remove(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RemoveFolderBody>,
) -> impl IntoResponse {
    let host = body.host.clone();
    if let Err((status, err_body)) = mutate_config(&state, move |doc| {
        let mut folders = get_folders(doc);
        let original_len = folders.len();
        folders.retain(|f| f.get("host").and_then(|p| p.as_str()) != Some(host.as_str()));
        if folders.len() == original_len {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Directory not found: {}", host)})),
            ));
        }
        put_folders(doc, folders)
    })
    .await
    {
        return (status, err_body).into_response();
    }

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "host": body.host, "needs_restart": true })),
    )
        .into_response()
}

/// GET /api/v1/settings/restart-status — Return whether a restart is needed.
///
/// We track this via a simple flag file; any config write could set it.
async fn restart_status() -> AppJson {
    let flag_path = std::env::var("NOO_RESTART_FLAG")
        .unwrap_or_else(|_| "/tmp/noo-restart-needed".into());
    let needs_restart = tokio::fs::metadata(&flag_path).await.is_ok();
    Json(json!({
        "restart_needed": needs_restart,
    }))
}

// ═══════════════════════════════════════════════════════════════
// Behavioral feature flags — native Rust (noo_settings SQL)
// [ported from workers/settings.py + noomesh/settings.py 2026-07-18]
// ═══════════════════════════════════════════════════════════════
//
// The flag REGISTRY is the source of truth for which BEHAVIORAL flags exist,
// their defaults, and their UI grouping. Effective-value resolution order is
// `noo_settings` DB row (admin override) → env var → registered default, with
// the winning layer reported in `source`. Security-posture gates (multi-user,
// auth, TLS) are deliberately NOT here — those live in `noo_security_posture`
// (operator-only) and are never weakenable from the app UI.
//
// Keep this list in sync with `src/noomesh/settings.py::_FLAGS` — the
// Python worker still resolves flags at its own read sites via that module.

/// One registered behavioral flag: key, UI category, default, label, help.
struct FlagSpec {
    key: &'static str,
    category: &'static str,
    default: bool,
    label: &'static str,
    help: &'static str,
    /// Resolved from the `noo_settings` row alone — no env layer. For a
    /// switch whose whole point is an audited, operator-recorded decision
    /// (`kiosk.graph_labels`): an env var could not say who turned it on.
    db_only: bool,
}

/// The kiosk names switch: whether `/api/kiosk/graph` puts entity names and
/// relation types on the wire to the unattended display. Its reader is
/// `routes::kiosk::graph_labels_on`.
pub(crate) const KIOSK_GRAPH_LABELS: &str = "kiosk.graph_labels";

/// Mirror of `noomesh/settings.py::_FLAGS` (same order, same defaults).
const FLAG_REGISTRY: &[FlagSpec] = &[
    // ── Autonomy ──
    //
    // The nine `NOO_AGENT_*` gates and `NOO_SELF_DEVELOP_AUTO_RESTART` were
    // here and are GONE. They belonged to the agent meta-loop,
    // which moved to the evolve add-on: this gateway keeps the scan and no
    // longer decides anything, so a switch here would have been a control on
    // another process's behaviour that this process cannot honour.
    //
    // The three worst of them — "Engine escalation", "Self-edit" and
    // "Self-dev auto-restart" — had no reader in ANY process.
    // They rendered as dashboard toggles beside switches that worked, which
    // is the failure this deletion actually fixes: a switch that does nothing
    // is worse than an absent one, because a reasonable operator concludes
    // the capability exists and is simply off.
    //
    // They live in evolve's compose env now, and evolve's
    // `/api/agent/meta-loop/status` reports the three unbuilt ones as
    // UNIMPLEMENTED rather than "off" — different claims, kept different.
    //
    // NOO_SELF_MODIFY_ENABLED (category "selfdev") was deleted when the
    // state-changing self-admin MCP tools were removed: the model can no
    // longer restart or rebuild its own stack, so there is nothing left for
    // the flag to switch. The `/api/mesh/restart` + `/api/mesh/rebuild`
    // endpoints it used to gate are now gated on the Admin role instead
    // (`routes::admin::mesh_lifecycle_admin_guard`) — the gate was replaced
    // BEFORE the flag was deleted, because dropping a default-off flag on its
    // own would have opened those endpoints rather than closing them.
    //
    // ── Features ──
    FlagSpec { key: "CLOUD_PROVIDERS_ENABLED", category: "features", default: false,
        label: "Cloud model routing", help: "Allow routing to cloud models (claude-* etc.).", db_only: false },
    FlagSpec { key: "NOO_EVOLVE_HOFSTADTER_ENABLED", category: "features", default: true,
        label: "Self-reflection loop", help: "Enable the evolve add-on's self-reflection loop.", db_only: false },
    // ── Kiosk ──
    //
    // Replaces the gateway env var `NOO_KIOSK_GRAPH_LABELS` (retired, now
    // ignored): turning names on meant editing the gateway's environment and
    // restarting it, and nothing recorded who did. DB-only, so the row's
    // `updated_by`/`updated_at` and the audit event are the whole story.
    FlagSpec { key: KIOSK_GRAPH_LABELS, category: "kiosk", default: false,
        label: "Kiosk graph labels",
        help: "Show entity names and relation types on the kiosk display's knowledge graph. \
               Off: the display gets ids, types and degrees only. The page shows LABELS ON \
               while it is on. Applied on the next kiosk fetch (within ~15s), no restart. \
               CLI: noo kiosk labels on|off|status.",
        db_only: true },
];

/// Registered STRING settings (config-graduation phase 2). Same DB-override
/// semantics as the boolean flags, but the raw text value is stored/served.
/// Resolution at the read site: noo_settings row → env var → YAML → default
/// (see `crate::settings::get`). Keep in sync with
/// `src/noomesh/settings.py::_STRING_SETTINGS`.
struct StringSpec {
    key: &'static str,
    category: &'static str,
    default: &'static str,
    label: &'static str,
    help: &'static str,
}

const STRING_REGISTRY: &[StringSpec] = &[
    StringSpec { key: "NOO_HEARTBEAT_TZ", category: "heartbeat",
        default: "America/New_York",
        label: "Heartbeat timezone",
        help: "IANA timezone for heartbeat cron evaluation. Applied within ~15s; \
               POST /api/heartbeat/reload forces an immediate schedule reload." },
    StringSpec { key: "NOO_REPORTS_DRIVE_FOLDER_ID", category: "heartbeat",
        default: "",
        label: "Reports Drive folder",
        help: "Google Drive folder id that report-shaped heartbeat output is uploaded to; \
               the chat then carries a link instead of the text. A task's own \
               config.drive_folder_id overrides it. Empty = send the report inline. \
               Applied within ~15s, no restart. Lost in the 2026-09 controller cutover \
               when it lived only in compose_env." },
    StringSpec { key: "NOO_OPS_WAIT_GRAPH_RECLUSTER_SECS", category: "ops",
        default: "0",
        label: "Wait for graph.recluster",
        help: "Seconds the graph.recluster route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_GRAPH_EXTRACT_RELATIONS_SECS", category: "ops",
        default: "3",
        label: "Wait for graph.extract_relations",
        help: "Seconds the graph.extract_relations route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS", category: "ops",
        default: "3",
        label: "Wait for graph.entity_cleanup",
        help: "Seconds the graph.entity_cleanup route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_SNAPSHOTS_CONSOLIDATE_SECS", category: "ops",
        default: "3",
        label: "Wait for snapshots.consolidate",
        help: "Seconds the snapshots.consolidate route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_GRAPH_NAVIGATE_SECS", category: "ops",
        default: "12",
        label: "Wait for graph.navigate",
        help: "Seconds the graph.navigate route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_GRAPH_TRAVERSE_SECS", category: "ops",
        default: "12",
        label: "Wait for graph.traverse",
        help: "Seconds the graph.traverse route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_RAG_INGEST_SECS", category: "ops",
        default: "3",
        label: "Wait for rag.ingest",
        help: "Seconds the rag.ingest route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_WAIT_DOCS_INGEST_SECS", category: "ops",
        default: "3",
        label: "Wait for docs.ingest",
        help: "Seconds the docs.ingest route holds a request before answering 202 with an \
               operation handle (0 = always a handle; at most 25). `?wait=` overrides it \
               per request. Applied within ~15s." },
    StringSpec { key: "NOO_OPS_RESULT_TTL_SECS", category: "ops",
        default: "86400",
        label: "Operation result retention",
        help: "Seconds a finished operation's result is kept before it is expired (60 to \
               2592000). Applied within ~15s; ops already finished keep the expiry they were given." },
];

/// The registered default of a STRING setting, as text.
pub(crate) fn string_setting_default(key: &str) -> Option<&'static str> {
    STRING_REGISTRY.iter().find(|s| s.key == key).map(|s| s.default)
}

/// Truthy parse: the gateway's single settings parser (`settings::truthy`),
/// so this route and the override cache the kiosk reads always agree.
fn flag_truthy(raw: &str) -> bool {
    crate::settings::truthy(raw)
}

/// GET /api/settings/flags — behavioral flags with current values.
/// [ported from workers/settings.py::_settings_flags_list 2026-07-18]
///
/// Resolution per flag: `noo_settings` DB row → env var → registered default,
/// with the winning layer in `source` ("db" / "env" / "default"). A DB read
/// failure degrades to env/default resolution (never errors), matching the
/// Python handler.
async fn settings_flags_list(State(state): State<Arc<AppState>>) -> AppJson {
    let mut db_keys: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Who last wrote each row, and when: `noo kiosk labels status` and the
    // verify row answer "who turned names on" from this, not from a log.
    let mut db_meta: std::collections::HashMap<String, (Option<String>, Option<String>)> =
        std::collections::HashMap::new();
    match sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT key, value, updated_by, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM noo_settings",
    )
        .fetch_all(&state.db)
        .await
    {
        Ok(rows) => {
            for (k, v, by, at) in rows {
                db_meta.insert(k.clone(), (by, at));
                db_keys.insert(k, v);
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "settings_flags_db_read_failed");
        }
    }

    let mut flags: Vec<Value> = Vec::with_capacity(FLAG_REGISTRY.len());
    for spec in FLAG_REGISTRY {
        let env_val = if spec.db_only { None } else { std::env::var(spec.key).ok() };
        let (value, source) = flag_resolution(spec, db_keys.get(spec.key).map(String::as_str), env_val.as_deref());
        let (by, at) = db_meta.get(spec.key).cloned().unwrap_or((None, None));
        flags.push(json!({
            "key": spec.key,
            "category": spec.category,
            "label": spec.label,
            "help": spec.help,
            "default": spec.default,
            "value": value,
            "source": source,
            "updated_by": by,
            "updated_at": at,
        }));
    }
    let mut string_settings: Vec<Value> = Vec::with_capacity(STRING_REGISTRY.len());
    for spec in STRING_REGISTRY {
        let (value, source) = if let Some(db_val) = db_keys.get(spec.key) {
            (db_val.clone(), "db")
        } else if let Ok(env_val) = std::env::var(spec.key) {
            (env_val, "env")
        } else {
            (spec.default.to_string(), "default")
        };
        string_settings.push(json!({
            "key": spec.key,
            "category": spec.category,
            "label": spec.label,
            "help": spec.help,
            "default": spec.default,
            "value": value,
            "type": "string",
            "source": source,
        }));
    }
    Json(json!({ "flags": flags, "settings": string_settings }))
}

/// Resolve one registered flag: DB row → env (unless `db_only`) → default,
/// naming the winning layer.
fn flag_resolution(spec: &FlagSpec, db: Option<&str>, env: Option<&str>) -> (bool, &'static str) {
    if let Some(v) = db {
        (flag_truthy(v), "db")
    } else if let (false, Some(v)) = (spec.db_only, env) {
        (flag_truthy(v), "env")
    } else {
        (spec.default, "default")
    }
}

/// Who may write a behavioural flag. `None` = allowed.
///
/// - no requester context: the operator CLI on the cluster-HMAC credential
///   (the operator tier — mirrors the Python trust model);
/// - a kiosk credential, whatever role it claims: a display is a screen,
///   not a person, and the one switch most relevant to it
///   (`kiosk.graph_labels`) widens what it may read. `auth::kiosk_may`
///   already refuses every write from it before dispatch; this is the
///   second lock, held where the decision is made;
/// - otherwise Operator or Admin (the old admin/write scopes
///   resolve to Operator).
fn flag_set_refusal(ctx: Option<&crate::auth::RequesterCtx>) -> Option<&'static str> {
    let r = ctx?;
    if r.scopes.iter().any(|s| s == crate::auth::KIOSK_SCOPE) {
        return Some("a kiosk credential cannot change settings");
    }
    if r.role < crate::auth::Role::Operator {
        return Some("operator role required");
    }
    None
}

/// POST /api/settings/flags/set — body {key, value: bool}. Admin-only, audited.
/// [ported from workers/settings.py::_settings_flags_set 2026-07-18]
///
/// Persists the override into `noo_settings` (upsert). JWT callers must carry
/// the `admin` or `write` scope; a call with no requester context is the
/// operator CLI (cluster-HMAC) — trusted, like other admin worker ops.
/// Every change is audit-logged.
async fn settings_flags_set(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    // JWT callers must be Operator or above (the old
    // admin/write scopes resolve to this role); no-context callers
    // (cluster-HMAC / service key) are the operator tier — mirror the
    // Python trust model.
    if let Some(why) = flag_set_refusal(ctx.as_ref().map(|e| &e.0)) {
        return Err(AppError::Forbidden(why.into()));
    }
    let by = ctx
        .as_ref()
        .map(|e| e.0.sub.clone())
        .unwrap_or_else(|| "cluster-cli".to_string());

    let key = body
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    // Settings that decide where results go (the reports folder) are a person's: a door that could set
    // one would redirect every report, and the scheduled-task guard treats the configured target as
    // already registered.
    if crate::task_guard::EGRESS_TARGET_SETTINGS.contains(&key.as_str())
        && !matches!(crate::task_guard::resolve_origin(&state.db, &ctx).await, crate::task_guard::Origin::Person { .. })
    {
        return Err(AppError::Forbidden(format!(
            "{key} decides where results are delivered, so it is set by a person's own credential (an MCP door, agent or service identity cannot)"
        )));
    }
    // Registered STRING settings share this endpoint: the raw text value is
    // upserted as-is (the read sites parse/validate, falling back on error).
    if let Some(sspec) = STRING_REGISTRY.iter().find(|f| f.key == key) {
        let raw = match body.get("value") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        sqlx::query(
            "INSERT INTO noo_settings (key, value, category, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, \
               updated_by = EXCLUDED.updated_by, updated_at = NOW()",
        )
        .bind(&key)
        .bind(&raw)
        .bind(sspec.category)
        .bind(&by)
        .execute(&state.db)
        .await?;
        crate::routes::core::audit_event(
            &state.db,
            "setting_flag_set",
            "info",
            &by,
            &format!("settings:string:{key}"),
            "ok",
            json!({ "setting": &key, "value": &raw, "by": &by }),
        )
        .await;
        tracing::info!(setting = %key, value = %raw, by = %by, "setting_string_set");
        return Ok(Json(json!({ "key": key, "value": raw })));
    }

    let Some(spec) = FLAG_REGISTRY.iter().find(|f| f.key == key) else {
        return Err(AppError::BadRequest(format!("unknown flag '{key}'")));
    };

    // Coerce the value like Python: `raw is True` or str(raw) in TRUTHY.
    let on = match body.get("value") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => flag_truthy(s),
        Some(other) => flag_truthy(&other.to_string()),
        None => false,
    };
    let val = if on { "1" } else { "0" };

    sqlx::query(
        "INSERT INTO noo_settings (key, value, category, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, \
           updated_by = EXCLUDED.updated_by, updated_at = NOW()",
    )
    .bind(&key)
    .bind(val)
    .bind(spec.category)
    .bind(&by)
    .execute(&state.db)
    .await?;
    // This gateway honours it on its next read; others within the 15 s
    // reload (`crate::settings::spawn_refresh`).
    crate::settings::set_override(&key, val);

    crate::routes::core::audit_event(
        &state.db,
        "setting_flag_set",
        "info",
        &by,
        &format!("settings:flag:{key}"),
        "ok",
        json!({ "flag": &key, "value": on, "by": &by }),
    )
    .await;
    tracing::info!(flag = %key, value = on, by = %by, "setting_flag_set");

    Ok(Json(json!({ "key": key, "value": on })))
}

// ═══════════════════════════════════════════════════════════════
// Prompt skills handlers — native Rust (filesystem markdown scan)
// ═══════════════════════════════════════════════════════════════
//
// Scans prompts/skills/core/ and prompts/skills/evolved/ for .md files
// with YAML frontmatter, matching the Python PromptSkillRegistry.
// Directory resolution: /app/prompts/skills/ (Docker), then ./prompts/skills/.

/// Default prompt skills directory candidates.
const SKILLS_CORE_DIRS: &[&str] = &["/app/prompts/skills/core", "prompts/skills/core"];
const SKILLS_EVOLVED_DIRS: &[&str] = &["/app/prompts/skills/evolved", "prompts/skills/evolved"];

/// Scan a directory for .md skill files, returning parsed skill summaries.
/// Skill discovery for the `/api/prompt-skills` surface.
///
/// `scan_skills_dir` / `scan_skills_recursive` / `parse_skill_file` lived
/// here and were a SECOND Rust implementation of skill parsing — the first
/// being the one the selector needs. They are replaced by
/// `crate::prompt_skills`, which now owns parsing for every consumer:
/// this HTTP surface, the coordinator's context injection, and skill
/// selection. Two parsers drifting apart is the failure mode this whole
/// programme exists to remove.
///
/// Output is field-for-field what `parse_skill_file` produced, so the
/// dashboard contract is unchanged.
fn scan_all_skills() -> Vec<crate::prompt_skills::PromptSkill> {
    let root = crate::prompt_skills::find_root();
    let reg = crate::prompt_skills::SkillRegistry::scan(&root);
    let mut all: Vec<crate::prompt_skills::PromptSkill> =
        reg.list_all().into_iter().cloned().collect();
    // Previous behaviour sorted by name; preserved so list order is stable.
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all
}

async fn prompt_skills_list() -> AppJson {
    // List omits `content` (summaries only) — unchanged from before.
    let skills: Vec<Value> = scan_all_skills()
        .iter()
        .map(|s| {
            let mut v = s.to_full_json();
            if let Value::Object(ref mut m) = v {
                m.remove("content");
            }
            v
        })
        .collect();
    Json(json!({"skills": skills}))
}

/// GET /api/prompt-skills/{name} — get a specific prompt skill by name.
///
/// Searches core/ then evolved/ for a .md file matching the name.
/// Returns the full skill including content, or an error if not found.
async fn prompt_skills_get(Path(name): Path<String>) -> AppJson {
    // Security: validate name to prevent path traversal (e.g., "../../etc/passwd").
    // Retained even though lookup is now by registry key rather than by path —
    // the name still reaches a filesystem-derived index, and dropping the guard
    // because "it looks safe now" is how traversal bugs come back.
    if let Err(e) = crate::security::validate_name(&name) {
        return Json(json!({"error": format!("Invalid skill name: {e}")}));
    }

    match scan_all_skills().into_iter().find(|s| s.name == name) {
        Some(skill) => Json(skill.to_full_json()),
        None => Json(json!({"error": format!("Prompt skill '{}' not found", name)})),
    }
}

/// POST /api/prompt-skills/evolve — LLM-driven create/mutate of an evolved
/// prompt skill. Body `{observation?, skill?, role?, apply?}`; a proposal by
/// default, `apply: true` writes through this gateway's skill store. Served
/// by the evolve add-on (its internal `prompt_skills_evolve` route); 503 with
/// the add-on's refusal when it is off, unlicensed or its routes are refused.
async fn prompt_skills_evolve(
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    let requester = ctx.map(|axum::Extension(r)| r);
    crate::addon_proxy::forward_named(
        "evolve",
        "prompt_skills_evolve",
        body.map(|Json(b)| b),
        requester.as_ref(),
    )
    .await
}

/// POST /api/prompt-skills — create or update a skill template.
///
/// Writes a markdown file with YAML frontmatter to the evolved/ directory.
/// Accepts {name, description, content, tags, ...} in the request body.
async fn prompt_skills_create(Json(body): Json<Value>) -> AppJson {
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => return Json(json!({"error": "Missing required field: name"})),
    };

    // Sanitize name for filesystem
    let safe_name: String = name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();

    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");

    // Build YAML frontmatter
    let mut fm = serde_json::Map::new();
    fm.insert("name".into(), json!(name));
    if let Some(v) = body.get("version") { fm.insert("version".into(), v.clone()); }
    else { fm.insert("version".into(), json!("1.0")); }
    if let Some(v) = body.get("description") { fm.insert("description".into(), v.clone()); }
    if let Some(v) = body.get("author") { fm.insert("author".into(), v.clone()); }
    if let Some(v) = body.get("tags") { fm.insert("tags".into(), v.clone()); }
    if let Some(v) = body.get("trigger_keywords") { fm.insert("trigger_keywords".into(), v.clone()); }
    if let Some(v) = body.get("priority") { fm.insert("priority".into(), v.clone()); }
    if let Some(v) = body.get("max_context_chars") { fm.insert("max_context_chars".into(), v.clone()); }
    if let Some(v) = body.get("composable") { fm.insert("composable".into(), v.clone()); }
    if let Some(v) = body.get("requires_tools") { fm.insert("requires_tools".into(), v.clone()); }
    if let Some(v) = body.get("fitness") { fm.insert("fitness".into(), v.clone()); }
    if let Some(v) = body.get("generation") { fm.insert("generation".into(), v.clone()); }
    if let Some(v) = body.get("parent_skill") { fm.insert("parent_skill".into(), v.clone()); }

    // Convert to YAML string
    let yaml_val = Value::Object(fm);
    let fm_str = match serde_yaml::to_string(&yaml_val) {
        Ok(s) => s,
        Err(e) => return Json(json!({"error": format!("YAML serialization failed: {e}")})),
    };

    let file_content = format!("---\n{fm_str}---\n\n{content}\n");

    // Determine target directory
    let evolved_dir = crate::paths::resolve(SKILLS_EVOLVED_DIRS)
        .unwrap_or_else(|| std::path::PathBuf::from(SKILLS_EVOLVED_DIRS[0]));

    // Create directory if needed
    if let Err(e) = tokio::fs::create_dir_all(&evolved_dir).await {
        return Json(json!({"error": format!("Failed to create skills directory: {e}")}));
    }

    let file_path = evolved_dir.join(format!("{safe_name}.md"));

    match tokio::fs::write(&file_path, file_content.as_bytes()).await {
        Ok(_) => {
            tracing::info!(name = %name, path = %file_path.display(), "prompt_skill_created");
            Json(json!({
                "status": "created",
                "name": name,
                "path": file_path.to_string_lossy(),
            }))
        }
        Err(e) => Json(json!({"error": format!("Failed to write skill file: {e}")})),
    }
}

fn store_error(e: crate::prompt_skills::StoreError) -> AppError {
    use crate::prompt_skills::StoreError as E;
    match e {
        E::Core => AppError::BadRequest("core skills are never mutated".into()),
        E::NotFound(m) => AppError::NotFound(m),
        E::Invalid(m) => AppError::BadRequest(m),
        E::Io(m) => AppError::Internal(m),
    }
}

fn checked_skill_name(name: &str) -> Result<(), AppError> {
    crate::security::validate_name(name)
        .map_err(|e| AppError::BadRequest(format!("Invalid skill name: {e}")))
}

/// PUT /api/prompt-skills/{name} — rewrite an EVOLVED skill.
///
/// Body `{content, description?, tags?, priority?, fitness?, generation?,
/// parent_skill?, version?}`. A core skill is 400 `core skills are never
/// mutated`; an unknown name is 404.
async fn prompt_skills_update(Path(name): Path<String>, Json(body): Json<Value>) -> AppResult {
    checked_skill_name(&name)?;
    let root = crate::prompt_skills::find_root();
    let skill = crate::prompt_skills::update_skill(&root, &name, &body).map_err(store_error)?;
    tracing::info!(name = %name, "prompt_skill_updated");
    Ok(Json(json!({"status": "updated", "name": name, "skill": skill.to_summary()})))
}

/// POST /api/prompt-skills/{name}/retire — move an EVOLVED skill into
/// `<its directory>/graveyard/`, out of selection and the listing.
async fn prompt_skills_retire(Path(name): Path<String>) -> AppResult {
    checked_skill_name(&name)?;
    let root = crate::prompt_skills::find_root();
    let to = crate::prompt_skills::retire_skill(&root, &name).map_err(store_error)?;
    tracing::info!(name = %name, path = %to.display(), "prompt_skill_retired");
    Ok(Json(json!({"status": "retired", "name": name, "path": to.to_string_lossy()})))
}

/// POST /api/prompt-skills/{name}/fitness — body `{delta}`. Clamps the skill's
/// fitness to 0..10, persists it, and retires the skill when a negative delta
/// lands on 0. Returns `{name, fitness, retired}`.
async fn prompt_skills_fitness(Path(name): Path<String>, Json(body): Json<Value>) -> AppResult {
    checked_skill_name(&name)?;
    let delta = body
        .get("delta")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| AppError::BadRequest("Missing required field: delta (a number)".into()))?;
    let root = crate::prompt_skills::find_root();
    let (fitness, retired) =
        crate::prompt_skills::adjust_fitness(&root, &name, delta).map_err(store_error)?;
    tracing::info!(name = %name, fitness, retired, "prompt_skill_fitness");
    Ok(Json(json!({"name": name, "fitness": fitness, "retired": retired})))
}

// ═══════════════════════════════════════════════════════════════
// Tests — locked fresh-read mutation of noomesh.yaml (WP-C hazard 1)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {

    /// `video_memory` and `recall_memory` are one section.
    /// Either spelling reads/writes the key the yaml holds; new wins when
    /// both are present; a fresh write lands on the OLD name while evolve
    /// still reads it.
    #[test]
    fn a_renamed_section_resolves_to_the_key_the_yaml_holds() {
        let old_only = json!({"video_memory": {"enabled": true}});
        let new_only = json!({"recall_memory": {"enabled": true}});
        let both = json!({"video_memory": {}, "recall_memory": {}});
        let neither = json!({"memory": {}});
        for asked in ["video_memory", "recall_memory"] {
            assert_eq!(effective_config_section(&old_only, asked), "video_memory");
            assert_eq!(effective_config_section(&new_only, asked), "recall_memory");
            assert_eq!(effective_config_section(&both, asked), "recall_memory", "new wins");
            assert_eq!(effective_config_section(&neither, asked), "video_memory",
                "created under the old key until evolve reads the new one");
        }
        assert_eq!(effective_config_section(&both, "memory"), "memory");

        // The full-config view mirrors the new key under the old one.
        let view = config_with_legacy_mirrors(&new_only);
        assert_eq!(view["video_memory"], json!({"enabled": true}), "evolve reads the old key");
        assert_eq!(view["recall_memory"], json!({"enabled": true}));
        let stale = json!({"video_memory": {"enabled": false}, "recall_memory": {"enabled": true}});
        assert_eq!(config_with_legacy_mirrors(&stale)["video_memory"], json!({"enabled": true}),
            "the mirror shows the section in effect, not the ignored duplicate");
        assert_eq!(config_with_legacy_mirrors(&old_only), old_only, "nothing to mirror");
        assert_eq!(config_with_legacy_mirrors(&neither), neither);
        assert_eq!(config_section_spellings("video_memory"), vec!["video_memory", "recall_memory"]);
        assert_eq!(config_section_spellings("recall_memory"), vec!["recall_memory", "video_memory"]);
        assert_eq!(config_section_spellings("agent"), vec!["agent"]);
        for (old, new) in RENAMED_CONFIG_SECTIONS {
            assert!(!GATED_CONFIG_SECTIONS.contains(old) && !GATED_CONFIG_SECTIONS.contains(new),
                "a renamed section must not straddle the gate");
        }
    }
    use super::*;

    async fn status_and_body(e: AppError) -> (axum::http::StatusCode, Value) {
        use axum::response::IntoResponse;
        let resp = e.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The wire contract of the skill-store refusals: a core skill is a 400
    /// with this exact message, a missing one a 404, a bad body a 400.
    #[tokio::test]
    async fn skill_store_refusals_have_the_contract_status_and_body() {
        use crate::prompt_skills::StoreError;
        let (st, body) = status_and_body(store_error(StoreError::Core)).await;
        assert_eq!(st, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "core skills are never mutated"}));
        let (st, _) = status_and_body(store_error(StoreError::NotFound("x".into()))).await;
        assert_eq!(st, axum::http::StatusCode::NOT_FOUND);
        let (st, _) = status_and_body(store_error(StoreError::Invalid("x".into()))).await;
        assert_eq!(st, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn skill_write_routes_reject_traversal_names() {
        for bad in ["../x", "a/b", ""] {
            assert!(checked_skill_name(bad).is_err(), "{bad:?}");
        }
        assert!(checked_skill_name("code-review").is_ok());
    }

    /// PINNED: the approval gate cannot be switched off
    /// through the config API the model can reach.
    #[test]
    fn gate_keys_are_read_only_through_the_config_api() {
        assert!(config_write_refused("security", &json!({"exec_approval_mode": "auto"})).is_some());
        // `exec_approval_timeout_secs` was the original second entry and it
        // guarded NOTHING: the yaml key is `exec_approval_timeout` (the `_secs`
        // spelling is the ENV var, `NOO_EXEC_APPROVAL_TIMEOUT_SECS`). It is also
        // not a gate — the Rust side ignores the yaml value entirely and the
        // Python worker's window is bounded 10..3600 — so it is covered by the
        // section guard (admin only, no cluster credential), not by a key ban.
        assert!(config_write_refused("security", &json!({"exec_approval_timeout_secs": 1})).is_none());
        assert!(config_write_refused("security", &json!({"exec_approval_timeout": 1})).is_none());
        assert!(config_section_guard("security", Some(Role::Operator), false).is_some(),
            "the timeout is still not an operator's to set");
        assert!(config_write_refused("security", &json!({"rate_limit_rpm": 60})).is_none(), "other security keys stay writable");
        assert!(config_write_refused("services", &json!({"exec_approval_mode": "auto"})).is_none(), "the key is scoped to its section");
        let why = config_write_refused("security", &json!({"exec_approval_mode": "auto"})).unwrap();
        assert!(why.contains("NOO_EXEC_APPROVAL_MODE"), "the refusal names the operator's control");
        assert!(why.contains("refuses to start"), "and says why the yaml is not a place to put it");
    }

    /// The key ban binds an ADMIN too — the half `config_section_guard` does
    /// not do. Writing a retired gate key would not weaken the running gate
    /// (posture already outranks the yaml); it would make the NEXT boot refuse.
    #[test]
    fn the_key_ban_applies_to_every_caller_including_admin() {
        let body = json!({"exec_approval_mode": "strict"});
        assert!(config_section_guard("security", Some(Role::Admin), false).is_none(),
            "an admin may write the section");
        assert!(config_write_refused("security", &body).is_some(),
            "...but not this key, however privileged");
    }

    /// The two lists must agree with posture: the key ban is DERIVED from
    /// `RETIRED_YAML_GATES`, and every retired key's section must also be a
    /// gate-bearing section, or the section guard would let a lesser role
    /// write everything around the one banned key.
    #[test]
    fn the_key_ban_and_the_section_guard_line_up() {
        assert!(!gate_keys().is_empty(), "parsed no gate keys");
        for (section, key) in gate_keys() {
            assert!(
                GATED_CONFIG_SECTIONS.contains(&section),
                "'{section}' holds retired gate key '{key}' but is not a gated section"
            );
        }
    }

    // ── R47: the config write must survive a non-writable directory ──

    /// Drop `w` from a directory for the duration of the closure, then put it
    /// back however the closure ended. Skips (returns `None`) when running as
    /// root, because root ignores the mode bits and the test would prove
    /// nothing — a silent pass is exactly what this must not do.
    fn with_readonly_dir<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, mode bits are not enforced");
            return None;
        }
        let original = std::fs::metadata(dir).unwrap().permissions();
        let mut ro = original.clone();
        ro.set_mode(0o555); // r-x: readable and traversable, NOT writable
        std::fs::set_permissions(dir, ro).unwrap();
        let out = f();
        std::fs::set_permissions(dir, original).unwrap();
        Some(out)
    }

    /// THE R47 REGRESSION. On the standalone controller every
    /// `noo config set` answered 500:
    ///   Failed to open config lock /app/noomesh.yaml.lock: Permission denied
    /// because the lock was a SIBLING FILE and the gateway (uid 65532) cannot
    /// write `/app`, which is root-owned in the image.
    ///
    /// This test reproduces that shape — config file writable, directory not —
    /// and requires the write to SUCCEED. It fails on the old code at the very
    /// first step, before any YAML is touched.
    #[test]
    fn a_config_write_succeeds_with_a_non_writable_directory() {
        let path = temp_yaml("r47-ro-dir");
        std::fs::write(&path, "existing: true\n").unwrap();
        let dir = std::path::Path::new(&path).parent().unwrap().to_path_buf();

        let result = with_readonly_dir(&dir, || {
            locked_mutate_yaml_file(&path, |doc| {
                doc.as_object_mut()
                    .unwrap()
                    .insert("added".into(), json!("by-r47-test"));
                Ok(())
            })
        });
        let Some(result) = result else { return };
        let doc = result.expect(
            "the config write must not need a writable DIRECTORY — the gateway runs nonroot \
             and /app is root-owned, which is R47",
        );
        assert_eq!(doc["added"], json!("by-r47-test"));

        // ...and it must have actually landed on disk, not just in the
        // returned document. The old failure mode in this file was a write
        // path that reported success having changed nothing.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("by-r47-test"), "not written to disk: {on_disk}");
        assert!(on_disk.contains("existing"), "clobbered the rest of the config: {on_disk}");
        let _ = std::fs::remove_file(&path);
    }

    /// The in-place path must leave no tail behind. Writing a SHORTER document
    /// over a longer one without `set_len` leaves the old bytes after the new
    /// ones, and the result still parses as YAML — so this cannot be checked
    /// by "does it load", only by the text.
    #[test]
    fn an_in_place_write_truncates_the_old_tail() {
        let path = temp_yaml("r47-truncate");
        let long = "a_very_long_key_that_takes_bytes: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        std::fs::write(&path, long).unwrap();
        let short = b"b: 1\n";
        write_config_bytes(&path, short).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(
            on_disk, short,
            "the old tail survived the write: {}",
            String::from_utf8_lossy(&on_disk)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// With a writable directory we must still prefer the crash-atomic path —
    /// the fallback is for when the platform forbids rename, not a new default.
    #[test]
    fn a_writable_directory_still_gets_the_atomic_rename() {
        let path = temp_yaml("r47-prefers-rename");
        std::fs::write(&path, "a: 1\n").unwrap();
        let mode = write_config_bytes(&path, b"a: 2\n").unwrap();
        assert_eq!(
            mode,
            ConfigWriteMode::Rename,
            "a writable directory must still use tmp+rename"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a: 2\n");
        let _ = std::fs::remove_file(&path);
    }

    /// ...and with the directory read-only it must report the in-place mode,
    /// so the log line an operator reads is the truth about their install.
    #[test]
    fn a_readonly_directory_reports_the_in_place_mode() {
        let path = temp_yaml("r47-reports-inplace");
        std::fs::write(&path, "a: 1\n").unwrap();
        let dir = std::path::Path::new(&path).parent().unwrap().to_path_buf();
        let mode = with_readonly_dir(&dir, || write_config_bytes(&path, b"a: 3\n"));
        let Some(mode) = mode else { return };
        assert_eq!(mode.unwrap(), ConfigWriteMode::InPlace);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a: 3\n");
        let _ = std::fs::remove_file(&path);
    }

    /// A first-ever write must work: `noo config set` on an install with no
    /// `noomesh.yaml` yet starts from `{}` and creates the file. This is the
    /// established behaviour (`missing_file_starts_from_empty_object`) and the
    /// directory lock is what makes it possible to keep — a lock on the config
    /// FILE could not be taken before the file existed.
    #[test]
    fn a_first_write_creates_the_config() {
        let path = temp_yaml("r47-first-write");
        let _ = std::fs::remove_file(&path);
        let doc = locked_mutate_yaml_file(&path, |doc| {
            doc.as_object_mut().unwrap().insert("fresh".into(), json!(true));
            Ok(())
        })
        .expect("a first write must create the file");
        assert_eq!(doc["fresh"], json!(true));
        assert!(std::fs::read_to_string(&path).unwrap().contains("fresh"));
        let _ = std::fs::remove_file(&path);
    }

    /// The lock must not need the config file to exist, and must not need the
    /// directory to be writable. Those two together are what made R47
    /// unfixable by permissions alone.
    #[test]
    fn the_lock_needs_neither_the_file_nor_a_writable_dir() {
        let path = temp_yaml("r47-lock-only");
        std::fs::write(&path, "a: 1\n").unwrap();
        let dir = std::path::Path::new(&path).parent().unwrap().to_path_buf();
        // Directory read-only AND the write still has to land.
        let out = with_readonly_dir(&dir, || {
            locked_mutate_yaml_file(&path, |doc| {
                doc.as_object_mut().unwrap().insert("b".into(), json!(2));
                Ok(())
            })
        });
        let Some(out) = out else { return };
        out.expect("locking must not need a writable directory");
        let _ = std::fs::remove_file(&path);
    }

    fn temp_yaml(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "noo-settings-test-{}-{}",
            name,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("noomesh.yaml").to_string_lossy().into_owned()
    }

    /// The hazard-1 regression: an edit made to the file on disk AFTER the
    /// gateway cached it at startup must survive a settings PUT. The old
    /// write path dumped the startup cache back to disk; the new path
    /// re-reads fresh under the lock, so the out-of-band key stays.
    #[test]
    fn out_of_band_edit_survives_settings_put() {
        let path = temp_yaml("oob");
        // "Startup": file exists with the original content (a gateway would
        // now cache this document in memory).
        std::fs::write(&path, "channels:\n  telegram: true\n").unwrap();

        // Out-of-band edit while the gateway runs.
        std::fs::write(
            &path,
            "channels:\n  telegram: true\noob_key: edited-on-disk\n",
        )
        .unwrap();

        // Settings PUT arrives, expressed as a mutation (deep-merge of the
        // request body) — exactly what settings_update now does.
        let body = json!({"preferences": {"tone": "brief"}});
        let doc = locked_mutate_yaml_file(&path, move |doc| {
            deep_merge(doc, &body);
            Ok(())
        })
        .unwrap();

        assert_eq!(doc["oob_key"], "edited-on-disk", "out-of-band edit reverted");
        assert_eq!(doc["preferences"]["tone"], "brief");
        assert_eq!(doc["channels"]["telegram"], true);

        // And the document on DISK agrees (atomic rename landed).
        let on_disk: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let on_disk: Value = serde_json::to_value(&on_disk).unwrap();
        assert_eq!(on_disk["oob_key"], "edited-on-disk");
        assert_eq!(on_disk["preferences"]["tone"], "brief");
    }

    #[test]
    fn missing_file_starts_from_empty_object() {
        let path = temp_yaml("missing");
        let _ = std::fs::remove_file(&path);
        let doc = locked_mutate_yaml_file(&path, |doc| {
            if let Some(m) = doc.as_object_mut() {
                m.insert("fresh".into(), json!(1));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(doc["fresh"], 1);
        assert!(std::path::Path::new(&path).exists());
    }

    #[test]
    fn corrupt_yaml_is_never_clobbered() {
        let path = temp_yaml("corrupt");
        let garbage = "foo: [unclosed\n\t{{{";
        std::fs::write(&path, garbage).unwrap();
        let res = locked_mutate_yaml_file(&path, |_| Ok(()));
        assert!(res.is_err(), "corrupt config must fail, not be overwritten");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            garbage,
            "corrupt file must be left untouched for operator recovery"
        );
    }

    #[test]
    fn mutation_error_leaves_file_unchanged() {
        let path = temp_yaml("mut-err");
        std::fs::write(&path, "keep: me\n").unwrap();
        let res = locked_mutate_yaml_file(&path, |_| {
            Err(cfg_err("handler rejected".into()))
        });
        assert!(res.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep: me\n");
    }

    /// Concurrent writers must not lose updates: each increment happens on
    /// the freshly read document under the flock, so N threads x M bumps
    /// always lands at N*M (the old cached read-modify-write lost updates).
    #[test]
    fn concurrent_mutations_do_not_lose_updates() {
        let path = temp_yaml("concurrent");
        std::fs::write(&path, "counter: 0\n").unwrap();

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        locked_mutate_yaml_file(&p, |doc| {
                            let n = doc["counter"].as_i64().unwrap_or(0);
                            doc["counter"] = json!(n + 1);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let on_disk: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let on_disk: Value = serde_json::to_value(&on_disk).unwrap();
        assert_eq!(on_disk["counter"], 200, "lost update under concurrency");
    }

    #[test]
    fn no_tmp_files_left_behind() {
        let path = temp_yaml("tmpclean");
        std::fs::write(&path, "a: 1\n").unwrap();
        locked_mutate_yaml_file(&path, |doc| {
            doc["b"] = json!(2);
            Ok(())
        })
        .unwrap();
        let dir = std::path::Path::new(&path).parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
    }

    // ── PUT /api/config/{section}: gate-bearing sections R8/D1) ──

    use crate::auth::Role;

    /// The exact shape of the hole: the worker calls the gateway back with the
    /// controller HMAC, so `noo_config_set` — a MEDIUM-risk tool the model may
    /// call unsupervised — arrived here as `ClusterKind::Internal` with no
    /// person attached, and could deep-merge anything into `security`.
    #[test]
    fn cluster_credential_cannot_write_a_gated_section() {
        for section in GATED_CONFIG_SECTIONS {
            let reason = config_section_guard(section, None, true)
                .unwrap_or_else(|| panic!("{section} must refuse a cluster caller"));
            assert!(reason.contains("cluster credential"), "{reason}");
        }
        // Admin role + cluster token is still a cluster token: the role claim
        // does not come from a cluster credential, but if one were ever
        // attached the token, not the role, decides.
        assert!(config_section_guard("security", Some(Role::Admin), true).is_some());
    }

    #[test]
    fn only_admin_jwt_may_write_a_gated_section() {
        for section in GATED_CONFIG_SECTIONS {
            assert!(
                config_section_guard(section, Some(Role::Admin), false).is_none(),
                "{section} must accept an admin person"
            );
            for lesser in [Role::Operator, Role::User] {
                assert!(
                    config_section_guard(section, Some(lesser), false).is_some(),
                    "{section} must refuse role {}",
                    lesser.as_str()
                );
            }
            assert!(
                config_section_guard(section, None, false).is_some(),
                "{section} must refuse an unauthenticated caller"
            );
        }
    }

    #[test]
    fn ungated_sections_are_untouched() {
        // The guard is a deny-list; ordinary settings must keep working for
        // the dashboard, the CLI and the agent alike.
        for section in ["memory", "web_search", "heartbeat", "cluster", "self_identity"] {
            for role in [None, Some(Role::User), Some(Role::Operator), Some(Role::Admin)] {
                assert!(config_section_guard(section, role, false).is_none(), "{section}");
                assert!(config_section_guard(section, role, true).is_none(), "{section}");
            }
        }
    }

    /// The `watched_folders` guard has a second door. `user_dirs_add` (and,
    /// until 2026-09-27, `user_dirs_update_writable`) writes the same section without going
    /// through `PUT /api/config/{section}`, so guarding only the latter left
    /// the writable-root downgrade reachable by any authenticated caller.
    #[test]
    fn granting_writable_needs_an_admin_person() {
        assert!(writable_folder_guard(true, None, true).is_some(), "cluster credential");
        assert!(writable_folder_guard(true, None, false).is_some(), "unauthenticated");
        for lesser in [Role::User, Role::Operator] {
            assert!(
                writable_folder_guard(true, Some(lesser), false).is_some(),
                "role {} must not grant a writable root",
                lesser.as_str()
            );
        }
        assert!(writable_folder_guard(true, Some(Role::Admin), false).is_none());
    }

    #[test]
    fn a_read_only_folder_is_not_an_admin_decision() {
        // Narrow on purpose: ingesting a directory read-only widens what the
        // file tools may READ, not what they may write unapproved.
        for role in [None, Some(Role::User), Some(Role::Operator), Some(Role::Admin)] {
            assert!(writable_folder_guard(false, role, false).is_none());
            assert!(writable_folder_guard(false, role, true).is_none());
        }
    }

    /// A deny-list is only as good as its spelling. Each entry must be a real
    /// `AppConfig` field — a renamed section would otherwise leave a guard
    /// entry that matches nothing and a live section with no guard, and every
    /// test above would still pass.
    #[test]
    fn gated_config_sections_are_real() {
        let cfg = include_str!("../config.rs");
        let start = cfg.find("pub struct AppConfig {").expect("AppConfig not found");
        let end = start + cfg[start..].find("\n}").expect("AppConfig unterminated");
        let body = &cfg[start..end];
        for section in GATED_CONFIG_SECTIONS {
            assert!(
                body.contains(&format!("pub {section}:")),
                "'{section}' is not an AppConfig field — the deny-list entry \
                 guards nothing"
            );
        }
    }

    // ── Directory picker: declared roots only (tracker R22) ──────────────
    //
    // The picker used to walk a read-only bind of the whole host
    // (`/mnt`, `/home`, `/media` -> `/host-fs/...`) behind a hardcoded
    // allow-list. These pin the replacement: nothing is reachable that the
    // operator has not declared, and the host<->mount translation is exact.

    fn cfg_with_dirs() -> Value {
        json!({
            "watched_folders": {
                "enabled": true,
                "folders": [
                    {"host": "/home/alice/Documents", "mount": "/user-dirs/Documents", "label": "Docs"},
                    {"host": "/mnt/c/Users/alice/Notes", "mount": "/user-dirs/Notes"},
                ]
            },
            "workspace": {"enabled": true, "host": "/home/alice/ws", "mount": "/workspace", "path": "/workspace"},
            "tools": {"allowed_paths": ["/data", "/user-dirs/Notes"]}
        })
    }

    #[test]
    fn declared_roots_come_from_config_and_nowhere_else() {
        let roots = declared_browse_roots(&cfg_with_dirs());
        let hosts: Vec<&str> = roots.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["/home/alice/Documents", "/mnt/c/Users/alice/Notes", "/home/alice/ws", "/data"],
            "roots must be exactly the declared ones, deduped by mount"
        );
        // A folder with no label falls back to its basename, not an empty chip.
        assert_eq!(roots[0].label, "Docs");
        assert_eq!(roots[1].label, "Notes");
        // /user-dirs/Notes is already a folder mount — allowed_paths must not
        // add it a second time.
        assert_eq!(roots.len(), 4);
    }

    #[test]
    fn an_empty_config_declares_nothing() {
        // Not "/home", not "/mnt": nothing. A picker with no declared roots
        // has nothing to show, and says so.
        assert!(declared_browse_roots(&json!({})).is_empty());
    }

    #[test]
    fn a_path_outside_every_declared_root_does_not_resolve() {
        let roots = declared_browse_roots(&cfg_with_dirs());
        for p in [
            "/home/alice/.ssh",
            "/home/alice/.config/sops/age/keys.txt",
            "/home",
            "/mnt",
            "/mnt/c/Users/alice",
            "/etc/shadow",
            "/",
        ] {
            assert!(
                resolve_declared(&roots, p).is_none(),
                "{p} resolved, but it is not inside any declared root"
            );
        }
    }

    #[test]
    fn a_declared_root_resolves_onto_its_own_mount() {
        let roots = declared_browse_roots(&cfg_with_dirs());
        let (fs, r) = resolve_declared(&roots, "/home/alice/Documents").expect("declared");
        assert_eq!(fs, "/user-dirs/Documents");
        assert_eq!(r.mount, "/user-dirs/Documents");

        let (fs, _) = resolve_declared(&roots, "/home/alice/Documents/a/b").expect("child");
        assert_eq!(fs, "/user-dirs/Documents/a/b");
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_inside() {
        // The bug a plain starts_with would ship: /home/alice/Documents-old
        // is not under /home/alice/Documents.
        let roots = declared_browse_roots(&cfg_with_dirs());
        assert!(resolve_declared(&roots, "/home/alice/Documents-old").is_none());
        assert!(strip_root("/home/alice", "/home/alice-old").is_none());
        assert_eq!(strip_root("/home/alice", "/home/alice"), Some(String::new()));
        assert_eq!(strip_root("/home/alice/", "/home/alice/x"), Some("/x".into()));
    }

    #[test]
    fn the_longest_declared_root_wins() {
        // A declared subdirectory of a declared directory has its own mount,
        // and may have different permissions — resolve through that one.
        let cfg = json!({"watched_folders": {"folders": [
            {"host": "/data/proj", "mount": "/user-dirs/proj"},
            {"host": "/data/proj/secrets", "mount": "/user-dirs/proj-secrets"},
        ]}});
        let roots = declared_browse_roots(&cfg);
        let (fs, _) = resolve_declared(&roots, "/data/proj/secrets/x").expect("declared");
        assert_eq!(fs, "/user-dirs/proj-secrets/x");
    }

    #[test]
    fn the_refusal_hint_tells_the_operator_what_to_do() {
        // A picker that says only "Access denied" about a directory the
        // operator can see in their own terminal is just baffling.
        assert!(BROWSE_UNDECLARED_HINT.contains("declared"));
        assert!(BROWSE_UNDECLARED_HINT.contains("restart"));
    }

    /// A null overlay value removes the key — the only way to take back a
    /// mistaken write, and the repair path for the wrapper keys #337 fixes
    /// at the source.
    #[test]
    fn deep_merge_null_removes_a_key() {
        let mut base = serde_json::json!({"KEEP": "yes", "updates": {"X": "1"}});
        super::deep_merge(&mut base, &serde_json::json!({"updates": null}));
        assert_eq!(base, serde_json::json!({"KEEP": "yes"}));
    }

    #[test]
    fn deep_merge_still_merges_nested_objects() {
        let mut base = serde_json::json!({"a": {"x": 1, "y": 2}});
        super::deep_merge(&mut base, &serde_json::json!({"a": {"y": 9, "z": 3}}));
        assert_eq!(base, serde_json::json!({"a": {"x": 1, "y": 9, "z": 3}}));
    }

    #[test]
    fn deep_merge_removing_an_absent_key_is_a_no_op() {
        let mut base = serde_json::json!({"a": 1});
        super::deep_merge(&mut base, &serde_json::json!({"gone": null}));
        assert_eq!(base, serde_json::json!({"a": 1}));
    }

    // ── kiosk.graph_labels: who may switch it, and how it resolves ──

    fn ctx(role: crate::auth::Role, scopes: &[&str]) -> crate::auth::RequesterCtx {
        crate::auth::RequesterCtx {
            sub: "someone".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }
    }

    /// Operator and Admin may switch a flag; a User may not; the operator
    /// CLI (cluster HMAC, no requester context) may.
    #[test]
    fn only_an_operator_or_admin_may_set_a_flag() {
        use crate::auth::Role;
        assert_eq!(super::flag_set_refusal(Some(&ctx(Role::User, &["read"]))), Some("operator role required"));
        assert_eq!(super::flag_set_refusal(Some(&ctx(Role::Operator, &[]))), None);
        assert_eq!(super::flag_set_refusal(Some(&ctx(Role::Admin, &[]))), None);
        assert_eq!(super::flag_set_refusal(None), None);
    }

    /// The kiosk credential can never switch its own names on: refused
    /// before dispatch by `auth::kiosk_may` (every write, and the flags
    /// routes are not on its read list either), and refused again in the
    /// handler whatever role the claims carry.
    #[test]
    fn the_kiosk_credential_cannot_switch_labels() {
        use axum::http::Method;
        use crate::auth::{kiosk_may, KioskRefusal, Role, KIOSK_SCOPE};
        assert_eq!(kiosk_may(&Method::POST, "/api/settings/flags/set"), Err(KioskRefusal::ReadOnly));
        assert_eq!(kiosk_may(&Method::PUT, "/api/settings/flags/set"), Err(KioskRefusal::ReadOnly));
        assert_eq!(kiosk_may(&Method::GET, "/api/settings/flags"), Err(KioskRefusal::OutOfScope));
        for role in [Role::User, Role::Operator, Role::Admin] {
            assert_eq!(
                super::flag_set_refusal(Some(&ctx(role, &[KIOSK_SCOPE]))),
                Some("a kiosk credential cannot change settings"),
                "a kiosk token claiming {role:?} was let through"
            );
        }
    }

    /// Registered, off by default, and DB-only: the retired env var cannot
    /// stand in for the recorded decision, and the list reports `default`
    /// rather than `env` for it.
    #[test]
    fn kiosk_graph_labels_is_registered_off_and_db_only() {
        let spec = super::FLAG_REGISTRY
            .iter()
            .find(|f| f.key == super::KIOSK_GRAPH_LABELS)
            .expect("kiosk.graph_labels is not in the flag registry");
        assert_eq!(spec.key, "kiosk.graph_labels");
        assert!(!spec.default, "names on a hallway display must be off by default");
        assert!(spec.db_only);
        assert_eq!(super::flag_resolution(spec, None, None), (false, "default"));
        assert_eq!(super::flag_resolution(spec, None, Some("1")), (false, "default"));
        assert_eq!(super::flag_resolution(spec, Some("1"), None), (true, "db"));
        assert_eq!(super::flag_resolution(spec, Some("0"), Some("1")), (false, "db"));
        // An ordinary flag keeps its env layer.
        let cloud = super::FLAG_REGISTRY.iter().find(|f| f.key == "CLOUD_PROVIDERS_ENABLED").unwrap();
        assert_eq!(super::flag_resolution(cloud, None, Some("1")), (true, "env"));
    }
}
