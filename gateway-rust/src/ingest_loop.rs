// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Unified ingest poller for `watched_folders` + `watched_drives`.
//!
//! Spawned once at startup from `main.rs`. Internally launches up to
//! two sub-loops depending on which features are enabled in config:
//!
//!   * Folder loop — walks each configured directory, glob-filters by
//!     suffix, dedupes against the `docs.source_uri` column, and submits
//!     each new file through the memory provider's kb/ingest operation
//!     (NATS `worker.rag.ingest` today) with `source = path`.
//!
//!   * Drive loop — lists each configured shared drive, dedupes via
//!     `gdrive://<file_id>` URIs, downloads new files to a working
//!     directory, and submits via the same kb/ingest operation with an
//!     explicit `source_uri` so dedup persists across restarts.
//!
//! Dedup reads and the metadata backfill write also go through the
//! provider facade — augmentation-plane data.
//!
//! The per-cycle scan logic is exposed as `scan_folders_once` and
//! `scan_drives_once` so an HTTP handler can run a manual scan on
//! demand (used by `POST /api/v1/ingest/scan` for testing).
//!
//! Why this exists: when autonomy was ported to Rust, only the API
//! endpoints were ported — the periodic monitor loop wasn't. So
//! `watched_folders` was silently dead in production. This module
//! restores that behavior natively and adds Drive on the same path.
//! See memory `project_rust_port_gap_autonomy_loop.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::drive;
use crate::state::AppState;

/// Path mounted in both Rust gateway and Python worker for staged ingest files.
const WORKING_DIR: &str = "/data/ingest/working";

/// Result of a single scan cycle. Returned to the HTTP trigger handler
/// and (eventually, see follow-up) snapshotted for `noo autonomy status`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub source: &'static str, // "folders" | "drives"
    pub seen: usize,
    pub new_count: usize,
    /// (file_name, doc_id) for each successfully ingested file.
    pub ingested: Vec<(String, String)>,
    /// Files that were already in `docs` but had empty/missing metadata —
    /// the scan opportunistically backfilled it from the current Drive
    /// state. Pure SQL UPDATE; no re-download / re-embed / re-extract.
    /// Each entry is the file name.
    pub backfilled: Vec<String>,
    /// Drive docs whose stored title didn't match the current Drive name —
    /// repaired in place (SQL UPDATE). Happens when the name contains '/'
    /// (Gemini's "…2026/04/10…" meeting notes) and an older scan derived
    /// the title via Path::file_stem, keeping only the last segment.
    pub title_repairs: Vec<String>,
    pub errors: Vec<String>,
    pub skipped_reason: Option<&'static str>, // populated when source not configured/enabled
}

impl ScanResult {
    fn empty(source: &'static str, reason: &'static str) -> Self {
        Self {
            source,
            seen: 0,
            new_count: 0,
            ingested: vec![],
            backfilled: vec![],
            title_repairs: vec![],
            errors: vec![],
            skipped_reason: Some(reason),
        }
    }
}

// ── Spawn ────────────────────────────────────────────────────────────

/// Spawn the ingest loops for whatever sources are enabled.
/// No-op if neither `watched_folders` nor `watched_drives` is enabled.
pub fn spawn(state: Arc<AppState>) {
    let wf = &state.config.watched_folders;
    let wd = &state.config.watched_drives;

    if wf.enabled && !wf.folders.is_empty() {
        // Snapshot the interval at spawn time. Config reload mid-process is
        // not yet wired; if we add hot reload, restart loops on change.
        let poll = wf.poll_interval_seconds.max(10);
        info!(
            folder_count = wf.folders.len(),
            interval_s = poll,
            "ingest_loop.folders.spawned"
        );
        // 15s grace so DB / RAG worker have time to come up; first scan
        // runs right after the grace (immediate first tick — historical
        // behavior, an operator dropping files sees them picked up fast).
        crate::managed_loop::ManagedLoop::new("ingest_folders", poll)
            .startup_grace(15)
            .immediate_first_tick()
            .spawn(state.clone(), |state| async move {
                let _ = scan_folders_once(&state).await; // errors reported in ScanResult
                Ok(())
            });
    }

    if wd.enabled && !wd.drives.is_empty() {
        let poll = wd.poll_interval_seconds.max(60);
        info!(
            drive_count = wd.drives.len(),
            interval_s = poll,
            "ingest_loop.drives.spawned"
        );
        // WORKING_DIR creation happens inside scan_drives_once each cycle
        // (idempotent), so the loop needs no pre-loop setup.
        crate::managed_loop::ManagedLoop::new("ingest_drives", poll)
            .startup_grace(20)
            .immediate_first_tick()
            .spawn(state.clone(), |state| async move {
                let _ = scan_drives_once(&state).await; // errors reported in ScanResult
                Ok(())
            });
    }
}

/// Run one folder-scan cycle. Safe to call concurrently with the spawned
/// loop — dedup against `docs.source_uri` happens at the start of each
/// call, and PageIndex's content-hash backstop catches any race.
pub async fn scan_folders_once(state: &AppState) -> ScanResult {
    let cfg = &state.config.watched_folders;
    if !cfg.enabled {
        return ScanResult::empty("folders", "watched_folders disabled in config");
    }
    if cfg.folders.is_empty() {
        return ScanResult::empty("folders", "no folders configured");
    }

    let max_size_bytes = cfg.max_file_size_mb.saturating_mul(1024 * 1024);
    let suffixes = patterns_to_suffixes(&cfg.patterns);

    let ingested_meta = match fetch_ingested_uri_meta(state).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "ingest_loop.folders.dedup_query_failed");
            return ScanResult {
                source: "folders",
                seen: 0,
                new_count: 0,
                ingested: vec![],
                backfilled: vec![],
                title_repairs: vec![],
                errors: vec![format!("dedup query failed: {e}")],
                skipped_reason: None,
            };
        }
    };

    // Three buckets:
    //   new_files       — never seen, full ingest path
    //   backfill_targets — already ingested but metadata is empty/{}; SQL UPDATE only
    //   (silently skipped) — already ingested with metadata, nothing to do
    let mut new_files: Vec<(PathBuf, String, String)> = Vec::new();
    let mut backfill_targets: Vec<(PathBuf, String, String)> = Vec::new();
    let mut seen = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for entry in &cfg.folders {
        let mount = entry.mount_path().to_string();
        let label = entry.label().to_string();
        let root = Path::new(&mount);
        if !root.is_dir() {
            debug!(mount = %mount, "ingest_loop.folders.skip_missing");
            continue;
        }
        let walked = walk_dir(root, cfg.recursive, &suffixes, max_size_bytes);
        seen += walked.len();
        for p in walked {
            let uri = p.to_string_lossy().to_string();
            match ingested_meta.get(&uri) {
                None => new_files.push((p, mount.clone(), label.clone())),
                Some(false) => backfill_targets.push((p, mount.clone(), label.clone())),
                Some(true) => {} // already ingested with metadata — skip
            }
        }
        if !label.is_empty() {
            debug!(mount = %mount, label = %label, "ingest_loop.folders.scanned");
        }
    }

    let batch_size = cfg.max_batch_size.min(new_files.len());
    let new_total = new_files.len();
    if new_total > 0 {
        info!(new_count = new_total, batch = batch_size, "ingest_loop.folders.tick");
    }

    let mut ingested_now: Vec<(String, String)> = Vec::new();
    for (path, mount, label) in new_files.into_iter().take(batch_size) {
        let title = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path_str = path.to_string_lossy().to_string();
        let metadata = build_folder_metadata(&path, &mount, &label);

        // Stage to local working dir before ingest. CIFS / OneDrive /
        // Windows-mount sources can return transient `Input/output error`
        // when the Python ingester opens them repeatedly (PDF parse +
        // page extract + OCR fallback all re-open). Copying once into the
        // Docker volume isolates the ingester from the flaky mount.
        // Mirrors scan_drives_once's WORKING_DIR pattern (line ~495) and
        // the original (retired) Python autonomy loop's shutil.copyfile body.
        // The original CIFS path stays as source_uri so dedup + provenance
        // queries continue to track the canonical location.
        // If we can't even copy the source, the file is genuinely
        // unreadable (OneDrive stub with the client offline, corrupted
        // file, hardware fault). Log and skip — pre-existing behavior
        // was to retry the dispatch on every tick, which floods logs
        // forever with confusing "Worker error: Failed to open file"
        // messages. With staging, transient I/O recovers on the next
        // tick (the copy retries), and the failure is surfaced at the
        // right layer.
        let source_for_worker = match stage_to_working_dir(&path).await {
            Ok(local) => local,
            Err(e) => {
                warn!(file = %path_str, error = %e, "ingest_loop.folders.stage_failed");
                errors.push(format!("stage {path_str}: {e}"));
                continue;
            }
        };

        match submit_ingest(state, &source_for_worker, &title, Some(&path_str), Some(metadata)).await {
            Ok(doc_id) => {
                info!(file = %path_str, staged = %source_for_worker, %doc_id, "ingest_loop.folders.ok");
                ingested_now.push((title, doc_id));
            }
            Err(e) => {
                warn!(file = %path_str, staged = %source_for_worker, error = %e, "ingest_loop.folders.failed");
                errors.push(format!("{path_str}: {e}"));
            }
        }
        // Clean up the staged copy. Worker has already read it (success
        // or failure) — keeping it would just consume disk on repeated
        // failures. Failures retry on next tick by re-staging.
        let _ = tokio::fs::remove_file(&source_for_worker).await;
    }

    // Self-healing backfill: docs that are already ingested but have empty
    // metadata get their metadata column populated from current scan data.
    // Pure SQL UPDATE — no download, no embedding cost. Unbatched (just an
    // UPDATE per row); cheap enough that the full set runs every cycle.
    let mut backfilled: Vec<String> = Vec::new();
    if !backfill_targets.is_empty() {
        info!(count = backfill_targets.len(), "ingest_loop.folders.backfill_starting");
    }
    for (path, mount, label) in backfill_targets {
        let path_str = path.to_string_lossy().to_string();
        let title = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let metadata = build_folder_metadata(&path, &mount, &label);
        match backfill_metadata(state, &path_str, &metadata).await {
            Ok(true) => {
                info!(file = %path_str, "ingest_loop.folders.backfilled");
                backfilled.push(title);
            }
            Ok(false) => {
                debug!(file = %path_str, "ingest_loop.folders.backfill_no_match");
            }
            Err(e) => {
                warn!(file = %path_str, error = %e, "ingest_loop.folders.backfill_failed");
                errors.push(format!("backfill {path_str}: {e}"));
            }
        }
    }

    notify(
        &cfg.notify_channels,
        &cfg.notify_recipients,
        "watched folders",
        &ingested_now,
    )
    .await;

    ScanResult {
        source: "folders",
        seen,
        new_count: new_total,
        ingested: ingested_now,
        backfilled,
        title_repairs: vec![],
        errors,
        skipped_reason: None,
    }
}

/// Build the standard metadata block for a watched-folder file. Used by
/// both the new-ingest path and the self-healing backfill path so they
/// stay in lockstep.
fn build_folder_metadata(path: &Path, mount: &str, label: &str) -> serde_json::Value {
    let segments: Vec<String> = path
        .strip_prefix(mount)
        .ok()
        .and_then(|rel| rel.parent())
        .map(|parent| {
            parent
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(s) => s.to_str().map(String::from),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut extra: Vec<(&str, serde_json::Value)> = vec![
        ("source_kind", json!("watched_folder")),
        ("mount", json!(mount)),
    ];
    if !label.is_empty() {
        extra.push(("label", json!(label)));
    }
    build_path_metadata(segments, extra)
}

/// Copy a CIFS / Windows-mount source file into the local Docker volume
/// (`WORKING_DIR`) so the Python ingester can re-open it without hitting
/// transient mount errors. Returns the path of the staged copy.
///
/// Disambiguation: working-dir filename is `folder_<hash>_<basename>`
/// where hash is a short content-free hash of the full source path so
/// two source files with the same basename in different folders don't
/// collide.
async fn stage_to_working_dir(src: &Path) -> Result<String, String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Do NOT swallow this error: when /data is owned by another uid the
    // mkdir fails EACCES here and every copy below then reports a
    // misleading "No such file or directory" — which is exactly how
    // Drive→KB ingestion was silently broken until 2026-08-08. The
    // launcher pre-creates /data/ingest with the gateway's uid; this is
    // the loud backstop for installs that bypassed it.
    if let Err(e) = tokio::fs::create_dir_all(WORKING_DIR).await {
        return Err(format!(
            "cannot create {WORKING_DIR}: {e} — the noo-data volume's \
             /data/ingest must be writable by the gateway uid (the \
             launcher normally ensures this; re-run `noo stack start`)"
        ));
    }

    let mut hasher = DefaultHasher::new();
    src.to_string_lossy().hash(&mut hasher);
    let path_hash = format!("{:x}", hasher.finish());

    let basename = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".to_string());
    let target = format!("{}/folder_{}_{}", WORKING_DIR, &path_hash[..8], basename);

    tokio::fs::copy(src, &target)
        .await
        .map_err(|e| format!("copy {} → {}: {}", src.display(), target, e))?;
    Ok(target)
}

fn walk_dir(root: &Path, recursive: bool, suffixes: &[String], max_size: u64) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ftype = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ftype.is_dir() {
                if recursive {
                    stack.push(p);
                }
                continue;
            }
            if !ftype.is_file() {
                continue;
            }
            let name_lower = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_lowercase(),
                None => continue,
            };
            if !suffixes.iter().any(|s| name_lower.ends_with(s)) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.len() > max_size {
                    continue;
                }
            }
            out.push(p);
        }
    }
    out
}

// ── Drive scan ───────────────────────────────────────────────────────

/// Run one drive-scan cycle. Safe under concurrent invocation — see
/// note on `scan_folders_once`.
pub async fn scan_drives_once(state: &AppState) -> ScanResult {
    let cfg = &state.config.watched_drives;
    if !cfg.enabled {
        return ScanResult::empty("drives", "watched_drives disabled in config");
    }
    if cfg.drives.is_empty() {
        return ScanResult::empty("drives", "no drives configured");
    }

    let http = crate::tls::external_client();

    let max_bytes = cfg.max_file_size_mb.saturating_mul(1024 * 1024);
    // Loud, once per scan — see stage_to_working_dir for why swallowing
    // this turned into per-file ENOENT spam with the real cause hidden.
    if let Err(e) = tokio::fs::create_dir_all(WORKING_DIR).await {
        warn!(error = %e, dir = WORKING_DIR,
              "ingest_loop.drives.working_dir_unwritable — Drive downloads \
               will fail until /data/ingest is writable by the gateway uid");
    }

    let ingested_meta = match fetch_ingested_uri_meta(state).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "ingest_loop.drives.dedup_query_failed");
            return ScanResult {
                source: "drives",
                seen: 0,
                new_count: 0,
                ingested: vec![],
                backfilled: vec![],
                title_repairs: vec![],
                errors: vec![format!("dedup query failed: {e}")],
                skipped_reason: None,
            };
        }
    };

    // (file, folder_path, drive_label, drive_id, scope_folder_id)
    type DriveCandidate = (
        crate::drive::DriveFile,
        String,
        String,
        String,
        Option<String>,
    );
    let mut new_candidates: Vec<DriveCandidate> = Vec::new();
    let mut backfill_candidates: Vec<DriveCandidate> = Vec::new();
    // (source_uri, corrected_title, drive file name) — docs whose stored
    // title doesn't match the current Drive name (slash-truncation bug).
    let mut title_repair_candidates: Vec<(String, String, String)> = Vec::new();
    let mut total_seen = 0usize;
    let mut errors: Vec<String> = Vec::new();

    // Stored titles for already-ingested gdrive:// docs, so the scan can
    // self-heal titles the pre-drive_title code truncated at the last '/'.
    let stored_titles = match state.memory().kb_gdrive_titles().await {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "ingest_loop.drives.title_query_failed");
            HashMap::new()
        }
    };

    for entry in &cfg.drives {
        // Recursive walk = list_files_recursive (returns folder_path per file).
        // Non-recursive = list_files (only top-level of pinned folder or drive root).
        let pairs_result: Result<Vec<(crate::drive::DriveFile, String)>, String> =
            if entry.recursive {
                drive::list_files_recursive(
                    &http,
                    &entry.drive_id,
                    entry.folder_id.as_deref(),
                    Some(&cfg.patterns),
                )
                .await
            } else {
                drive::list_files(
                    &http,
                    &entry.drive_id,
                    entry.folder_id.as_deref(),
                    Some(&cfg.patterns),
                )
                .await
                // Wrap in (file, "") since flat scan has no folder context
                .map(|files| files.into_iter().map(|f| (f, String::new())).collect())
            };

        match pairs_result {
            Ok(pairs) => {
                total_seen += pairs.len();
                for (f, folder_path) in pairs {
                    let uri = format!("gdrive://{}", f.file_id);
                    let cand = (
                        f.clone(),
                        folder_path,
                        entry.label.clone(),
                        entry.drive_id.clone(),
                        entry.folder_id.clone(),
                    );
                    match ingested_meta.get(&uri) {
                        Some(true) => {
                            // Already ingested with metadata — but repair the
                            // title if the stored one doesn't match the Drive
                            // name (truncated by the old file_stem-on-'/' bug).
                            let want = drive_title(&f.name);
                            if stored_titles.get(&uri).is_some_and(|t| t != &want) {
                                title_repair_candidates.push((uri.clone(), want, f.name.clone()));
                            }
                        }
                        Some(false) => backfill_candidates.push(cand), // self-heal target
                        None => {
                            // Truly new — apply size pre-check before queuing
                            if f.size > 0 && f.size > max_bytes {
                                debug!(
                                    file = %f.name, size = f.size, limit = max_bytes,
                                    "ingest_loop.drives.skip_oversized"
                                );
                                continue;
                            }
                            new_candidates.push(cand);
                        }
                    }
                }
            }
            Err(e) => {
                warn!(drive_id = %entry.drive_id, error = %e, "ingest_loop.drives.list_failed");
                errors.push(format!("list {}: {}", entry.drive_id, e));
            }
        }
    }

    let batch_size = cfg.max_batch_size.min(new_candidates.len());
    let new_total = new_candidates.len();
    if new_total > 0 {
        info!(
            new_count = new_total, batch = batch_size, seen = total_seen,
            "ingest_loop.drives.tick"
        );
    }

    let mut ingested_now: Vec<(String, String)> = Vec::new();
    for (f, folder_path, label, drive_id, scope_folder_id) in new_candidates.into_iter().take(batch_size) {
        let (bytes, suffix) = match drive::download(&http, &f, max_bytes).await {
            Ok(v) => v,
            Err(e) => {
                warn!(file = %f.name, error = %e, "ingest_loop.drives.download_failed");
                errors.push(format!("download {}: {}", f.name, e));
                continue;
            }
        };

        let title = drive_title(&f.name);
        let safe_stem: String = title
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();
        let target = format!(
            "{}/gdrive_{}_{}{}",
            WORKING_DIR, f.file_id, safe_stem, suffix
        );
        if let Err(e) = tokio::fs::write(&target, &bytes).await {
            warn!(file = %f.name, target = %target, error = %e, "ingest_loop.drives.write_failed");
            errors.push(format!("write {}: {}", f.name, e));
            continue;
        }

        let source_uri = format!("gdrive://{}", f.file_id);
        let metadata = build_drive_metadata(&f, &folder_path, &label, &drive_id, scope_folder_id.as_deref());

        match submit_ingest(state, &target, &title, Some(&source_uri), Some(metadata)).await {
            Ok(doc_id) => {
                info!(
                    file = %f.name, drive_label = %label, folder_path = %folder_path, %doc_id,
                    "ingest_loop.drives.ok"
                );
                ingested_now.push((f.name.clone(), doc_id));
            }
            Err(e) => {
                warn!(file = %f.name, error = %e, "ingest_loop.drives.ingest_failed");
                errors.push(format!("ingest {}: {}", f.name, e));
            }
        }
    }

    // Self-healing backfill: for each gdrive:// doc that exists in `docs`
    // but has empty metadata, populate it from the current Drive walk.
    // No re-download, no re-ingest — pure SQL UPDATE.
    let mut backfilled: Vec<String> = Vec::new();
    if !backfill_candidates.is_empty() {
        info!(
            count = backfill_candidates.len(),
            "ingest_loop.drives.backfill_starting"
        );
    }
    for (f, folder_path, label, drive_id, scope_folder_id) in backfill_candidates {
        let source_uri = format!("gdrive://{}", f.file_id);
        let metadata = build_drive_metadata(&f, &folder_path, &label, &drive_id, scope_folder_id.as_deref());
        match backfill_metadata(state, &source_uri, &metadata).await {
            Ok(true) => {
                info!(
                    file = %f.name, folder_path = %folder_path,
                    "ingest_loop.drives.backfilled"
                );
                backfilled.push(f.name.clone());
            }
            Ok(false) => {
                debug!(file = %f.name, "ingest_loop.drives.backfill_no_match");
            }
            Err(e) => {
                warn!(file = %f.name, error = %e, "ingest_loop.drives.backfill_failed");
                errors.push(format!("backfill {}: {}", f.name, e));
            }
        }
    }

    // Title repair — pure SQL UPDATE, no re-download / re-embed.
    let mut title_repairs: Vec<String> = Vec::new();
    if !title_repair_candidates.is_empty() {
        info!(
            count = title_repair_candidates.len(),
            "ingest_loop.drives.title_repair_starting"
        );
    }
    for (uri, want, name) in title_repair_candidates {
        match repair_title(state, &uri, &want).await {
            Ok(true) => {
                info!(file = %name, title = %want, "ingest_loop.drives.title_repaired");
                title_repairs.push(want);
            }
            Ok(false) => {
                debug!(file = %name, "ingest_loop.drives.title_repair_no_match");
            }
            Err(e) => {
                warn!(file = %name, error = %e, "ingest_loop.drives.title_repair_failed");
                errors.push(format!("title repair {}: {}", name, e));
            }
        }
    }

    notify(
        &cfg.notify_channels,
        &cfg.notify_recipients,
        "shared drives",
        &ingested_now,
    )
    .await;

    ScanResult {
        source: "drives",
        seen: total_seen,
        new_count: new_total,
        ingested: ingested_now,
        backfilled,
        title_repairs,
        errors,
        skipped_reason: None,
    }
}

/// Title for a Drive file: the name minus any extension, with path
/// separators flattened to '-'. Drive names may legally contain '/'
/// (Gemini titles meeting notes "… 2026/04/10 12:09 EDT - Notes by
/// Gemini"); running the raw name through `Path::file_stem` treated
/// those as directories and kept only the last segment, which is how
/// 82 transcripts ended up titled "10 12:09 EDT - Notes by Gemini".
fn drive_title(name: &str) -> String {
    let sanitized = name.replace(['/', '\\'], "-");
    Path::new(&sanitized)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string()
}

/// Fix a stored doc title in place. Returns whether a row changed.
async fn repair_title(state: &AppState, source_uri: &str, title: &str) -> Result<bool, String> {
    state
        .memory()
        .kb_doc_repair_title(source_uri, title)
        .await
        .map_err(|e| e.to_string())
}

/// Build the standard metadata block for a Drive file. Used by both
/// the new-ingest path and the self-healing backfill path so they
/// stay in lockstep.
fn build_drive_metadata(
    f: &crate::drive::DriveFile,
    folder_path: &str,
    label: &str,
    drive_id: &str,
    scope_folder_id: Option<&str>,
) -> serde_json::Value {
    let segments: Vec<String> = if folder_path.is_empty() {
        vec![]
    } else {
        folder_path.split('/').map(String::from).collect()
    };
    let mut extra: Vec<(&str, serde_json::Value)> = vec![
        ("source_kind", json!("watched_drive")),
        ("drive_id", json!(drive_id)),
        ("file_id", json!(f.file_id)),
        ("mime_type", json!(f.mime_type)),
    ];
    if !label.is_empty() {
        extra.push(("drive_label", json!(label)));
    }
    if let Some(fid) = scope_folder_id {
        extra.push(("scope_folder_id", json!(fid)));
    }
    build_path_metadata(segments, extra)
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Map of `source_uri` → `has_meaningful_metadata`. False means the doc
/// exists but its metadata column is NULL or `'{}'::jsonb`, so it's a
/// candidate for self-healing backfill on the next scan.
///
/// Includes `metadata.aliased_uris` entries — when content-hash dedup
/// hits in `insert_doc`, the new path is recorded as an alias so the
/// canonical `source_uri` doesn't flip-flop. Without including aliases
/// here, files at duplicate-content paths would re-ingest forever
/// (the loop sees the path, dedup query doesn't, ingest succeeds via
/// content-hash dedup → returns same doc_id, repeat).
async fn fetch_ingested_uri_meta(
    state: &AppState,
) -> Result<HashMap<String, bool>, sqlx::Error> {
    state.memory().kb_ingested_uri_meta().await
}

/// Backfill metadata for an existing doc whose metadata column is empty.
/// Pure SQL UPDATE — no re-download, no re-ingest, no embedding cost.
/// Returns Ok(true) if a row was updated, Ok(false) if no match (which
/// can happen if the doc was concurrently re-ingested between the dedup
/// query and this UPDATE, in which case we'd just lose the race — fine).
async fn backfill_metadata(
    state: &AppState,
    source_uri: &str,
    metadata: &serde_json::Value,
) -> Result<bool, String> {
    // The one gateway WRITE into a provider table (`docs.metadata`) that
    // phase 0 flagged — behind the facade, folding into kb/ingest
    // semantics when the contract is served (phase 2).
    state
        .memory()
        .kb_doc_backfill_metadata(source_uri, metadata)
        .await
        .map_err(|e| e.to_string())
}

async fn submit_ingest(
    state: &AppState,
    source: &str,
    title: &str,
    source_uri: Option<&str>,
    metadata: Option<serde_json::Value>,
) -> Result<String, String> {
    let mut payload = json!({
        "source": source,
        "title": title,
    });
    if let Some(uri) = source_uri {
        payload["source_uri"] = json!(uri);
    }
    if let Some(meta) = metadata {
        payload["metadata"] = meta;
    }
    let resp = state
        .memory()
        .kb_ingest(&payload)
        .await
        .map_err(|e| e.to_string())?;
    // Worker responses come wrapped as {"data": {...}, "success": true}.
    // Peel the envelope; fall back to top-level for handlers that don't wrap.
    let body = resp.get("data").unwrap_or(&resp);
    let doc_id = body
        .get("doc_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no doc_id in response: {resp}"))?;
    Ok(doc_id.to_string())
}

/// Build the standard folder-path metadata block.
/// `segments` is the path split on "/" — empty vec for root files.
fn build_path_metadata(
    segments: Vec<String>,
    extra: Vec<(&str, serde_json::Value)>,
) -> serde_json::Value {
    let path_str = segments.join("/");
    let mut obj = serde_json::Map::new();
    obj.insert("folder_path".to_string(), json!(path_str));
    obj.insert("folder_path_segments".to_string(), json!(segments));
    for (k, v) in extra {
        obj.insert(k.to_string(), v);
    }
    serde_json::Value::Object(obj)
}

fn patterns_to_suffixes(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .map(|p| p.trim_start_matches('*').to_lowercase())
        .collect()
}

async fn notify(
    channels: &[String],
    recipients: &[String],
    source_label: &str,
    ingested: &[(String, String)],
) {
    if channels.is_empty() || recipients.is_empty() || ingested.is_empty() {
        return;
    }
    let mut lines = vec![format!(
        "[Mesh] Auto-ingested {} new document(s) from {source_label}:",
        ingested.len()
    )];
    for (name, doc_id) in ingested {
        lines.push(format!("  - {name} (doc_id={})", &doc_id[..doc_id.len().min(8)]));
    }
    let summary = lines.join("\n");

    for (ch, recip) in channels.iter().zip(recipients.iter()) {
        if let Err(e) =
            crate::routes::communication::send_channel_message(ch, recip, &summary, None, None, None).await
        {
            warn!(channel = %ch, error = %e, "ingest_loop.notify_failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::drive_title;

    #[test]
    fn drive_title_flattens_slashed_dates() {
        // Gemini meeting notes carry slashed dates in the doc name —
        // the pre-fix code kept only "10 12:09 EDT - Notes by Gemini".
        assert_eq!(
            drive_title("Weekly sync - 2026/04/10 12:09 EDT - Notes by Gemini"),
            "Weekly sync - 2026-04-10 12:09 EDT - Notes by Gemini"
        );
        assert_eq!(
            drive_title("2026/08/04 11:02 EDT - Notes by Gemini"),
            "2026-08-04 11:02 EDT - Notes by Gemini"
        );
    }

    #[test]
    fn drive_title_strips_extension_and_handles_plain_names() {
        assert_eq!(drive_title("report.pdf"), "report");
        assert_eq!(drive_title("plain doc name"), "plain doc name");
        assert_eq!(drive_title("back\\slash"), "back-slash");
    }
}
