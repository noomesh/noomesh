// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Service-account Google Drive client (read-only) for shared-drive ingestion.
//!
//! Uses the same SA JSON key as the Chat bot (env `GOOGLE_CHAT_CREDENTIALS`)
//! but mints a separate `drive.readonly`-scoped token via `google_auth`.
//! Every query is pinned to a specific shared drive via `corpora=drive` +
//! `driveId` + `supportsAllDrives=true` — the SA never sees other drives.
//!
//! Workspace native files (Google Docs, Sheets) cannot be downloaded
//! directly; they're exported with a synthetic file extension so the
//! downstream PageIndex ingest can detect type by suffix.
//!
//! Recursive listing is implemented client-side (Drive's `files.list`
//! has no native recursion flag): list every folder in the drive once,
//! build a parent→child map, then walk parents to compute each file's
//! human-readable folder path.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::google_auth::drive_readonly_token;

const DRIVE_API: &str = "https://www.googleapis.com/drive/v3";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

/// Workspace native MIME → (export MIME, synthetic suffix) for ingest.
///
/// Google Docs exports as `text/markdown` (Drive API supports it as of
/// 2024) so structural markers (headings, bold, lists, links) survive
/// the round-trip. The previous default of `text/plain` flattened
/// headings to bare text, hurting RAG chunking quality.
fn workspace_export(mime: &str) -> Option<(&'static str, &'static str)> {
    match mime {
        "application/vnd.google-apps.document" => Some(("text/markdown", ".md")),
        "application/vnd.google-apps.spreadsheet" => Some(("text/csv", ".csv")),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct DriveFile {
    pub file_id: String,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub modified_time: String,
    pub parents: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    // mimeType is `default`-able so list_all_folders (which only requests
    // id,name,parents) can still deserialize. For file listings we always
    // request mimeType in the fields param; missing → empty string is fine.
    #[serde(rename = "mimeType", default)]
    mime_type: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(rename = "modifiedTime", default)]
    modified_time: Option<String>,
    #[serde(default)]
    parents: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    files: Vec<RawFile>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

/// List files in a shared drive, optionally pinned to a single folder.
///
/// `suffix_filter` is checked client-side against the file name; pass
/// extensions like `[".pdf", ".txt"]`. Workspace native files bypass
/// the suffix filter — the caller decides whether to export them.
pub async fn list_files(
    http: &Client,
    drive_id: &str,
    folder_id: Option<&str>,
    suffix_filter: Option<&[String]>,
) -> Result<Vec<DriveFile>, String> {
    let token = drive_readonly_token().await?;
    let mut q = vec![
        format!("mimeType != '{}'", FOLDER_MIME),
        "trashed = false".to_string(),
    ];
    if let Some(fid) = folder_id {
        // Drive query strings escape single quotes by doubling
        let safe = fid.replace('\'', "\\'");
        q.push(format!("'{}' in parents", safe));
    }

    let suffixes_lower: Option<Vec<String>> = suffix_filter.map(|s| {
        s.iter()
            .map(|p| p.trim_start_matches('*').to_lowercase())
            .collect()
    });

    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut req = http
            .get(format!("{}/files", DRIVE_API))
            .bearer_auth(&token)
            .query(&[
                ("q", q.join(" and ").as_str()),
                ("fields", "nextPageToken, files(id,name,mimeType,size,modifiedTime,parents)"),
                ("corpora", "drive"),
                ("driveId", drive_id),
                ("includeItemsFromAllDrives", "true"),
                ("supportsAllDrives", "true"),
                ("orderBy", "modifiedTime desc"),
                ("pageSize", "200"),
            ]);
        if let Some(ref tok) = page_token {
            req = req.query(&[("pageToken", tok.as_str())]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("drive list send: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "drive list HTTP {} body={}",
                status,
                body.chars().take(500).collect::<String>()
            ));
        }
        let parsed: ListResponse = resp
            .json()
            .await
            .map_err(|e| format!("drive list parse: {e}"))?;

        for f in parsed.files {
            // Filter regular files by suffix; always include Workspace files
            // so the caller can choose to export them.
            if let Some(ref suffixes) = suffixes_lower {
                if workspace_export(&f.mime_type).is_none() {
                    let name_lower = f.name.to_lowercase();
                    if !suffixes.iter().any(|s| name_lower.ends_with(s)) {
                        continue;
                    }
                }
            }
            let size = f.size.as_deref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            out.push(DriveFile {
                file_id: f.id,
                name: f.name,
                mime_type: f.mime_type,
                size,
                modified_time: f.modified_time.unwrap_or_default(),
                parents: f.parents.unwrap_or_default(),
            });
        }

        page_token = parsed.next_page_token;
        if page_token.is_none() {
            break;
        }
    }

    Ok(out)
}

/// Download a file's bytes. Returns `(content, suffix)` where `suffix`
/// is the file extension to use when persisting to disk (Workspace
/// exports get a synthetic suffix; regular files keep theirs).
pub async fn download(
    http: &Client,
    file: &DriveFile,
    max_bytes: u64,
) -> Result<(Vec<u8>, String), String> {
    let token = drive_readonly_token().await?;

    let (url, query, suffix): (String, Vec<(&str, String)>, String) =
        if let Some((export_mime, syn_suffix)) = workspace_export(&file.mime_type) {
            (
                format!("{}/files/{}/export", DRIVE_API, file.file_id),
                vec![("mimeType", export_mime.to_string())],
                syn_suffix.to_string(),
            )
        } else {
            // Pre-flight size check for direct downloads (Workspace exports
            // don't expose size up-front; we cap via post-download check).
            if file.size > max_bytes {
                return Err(format!(
                    "file too large: {} > {} bytes",
                    file.size, max_bytes
                ));
            }
            let suffix = std::path::Path::new(&file.name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();
            (
                format!("{}/files/{}", DRIVE_API, file.file_id),
                vec![
                    ("alt", "media".to_string()),
                    ("supportsAllDrives", "true".to_string()),
                ],
                suffix,
            )
        };

    let resp = http
        .get(&url)
        .bearer_auth(&token)
        .query(&query)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("drive download send: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "drive download HTTP {} body={}",
            status,
            body.chars().take(200).collect::<String>()
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("drive download body: {e}"))?;
    if (bytes.len() as u64) > max_bytes {
        return Err(format!(
            "downloaded body too large: {} > {} bytes",
            bytes.len(),
            max_bytes
        ));
    }
    Ok((bytes.to_vec(), suffix))
}

// ── Recursive listing ───────────────────────────────────────────────

/// One folder in the drive (id + name + parent id).
#[derive(Debug, Clone)]
struct DriveFolder {
    id: String,
    name: String,
    parent: Option<String>,
}

/// List every folder in the shared drive (one paginated walk). Used to
/// build a parent→child chain for path computation.
async fn list_all_folders(
    http: &Client,
    drive_id: &str,
) -> Result<Vec<DriveFolder>, String> {
    let token = drive_readonly_token().await?;
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut params = vec![
            ("q", format!("mimeType = '{}' and trashed = false", FOLDER_MIME)),
            ("fields", "nextPageToken, files(id,name,parents)".to_string()),
            ("corpora", "drive".to_string()),
            ("driveId", drive_id.to_string()),
            ("includeItemsFromAllDrives", "true".to_string()),
            ("supportsAllDrives", "true".to_string()),
            ("pageSize", "1000".to_string()),
        ];
        if let Some(ref tok) = page_token {
            params.push(("pageToken", tok.clone()));
        }
        let resp = http
            .get(format!("{}/files", DRIVE_API))
            .bearer_auth(&token)
            .query(&params)
            .send()
            .await
            .map_err(|e| format!("folder list send: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "folder list HTTP {} body={}",
                status,
                body.chars().take(500).collect::<String>()
            ));
        }
        let parsed: ListResponse = resp
            .json()
            .await
            .map_err(|e| format!("folder list parse: {e}"))?;
        for f in parsed.files {
            out.push(DriveFolder {
                id: f.id,
                name: f.name,
                parent: f.parents.and_then(|ps| ps.into_iter().next()),
            });
        }
        page_token = parsed.next_page_token;
        if page_token.is_none() {
            break;
        }
    }
    Ok(out)
}

/// List every non-folder file in the drive (no parent constraint).
/// Used by the recursive variant; the paths are computed afterward
/// by walking the folder map.
async fn list_all_files_in_drive(
    http: &Client,
    drive_id: &str,
    suffix_filter: Option<&[String]>,
) -> Result<Vec<DriveFile>, String> {
    // Same as list_files() but with no folder_id constraint
    list_files(http, drive_id, None, suffix_filter).await
}

/// Walk parent chain to compute the human-readable folder path for a
/// file. Returns `None` if `scope` is set and the file isn't under it.
///
/// - `scope = None` → path relative to drive root
/// - `scope = Some(folder_id)` → path relative to that folder; files
///   not descended from it are filtered out
fn compute_folder_path(
    parent_id: &str,
    folder_map: &HashMap<String, (String, Option<String>)>,
    scope: Option<&str>,
) -> Option<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = parent_id.to_string();

    loop {
        // Reached scope root? Return what we've accumulated.
        if let Some(s) = scope {
            if current == s {
                segments.reverse();
                return Some(segments.join("/"));
            }
        }
        match folder_map.get(&current) {
            Some((name, parent_opt)) => {
                segments.push(name.clone());
                match parent_opt {
                    Some(p) => current = p.clone(),
                    None => {
                        // Reached drive root without finding scope
                        if scope.is_some() {
                            return None;
                        }
                        segments.reverse();
                        return Some(segments.join("/"));
                    }
                }
            }
            None => {
                // current is a drive-root id (or folder we can't see).
                // If no scope, treat as drive root reached.
                if scope.is_some() {
                    return None;
                }
                segments.reverse();
                return Some(segments.join("/"));
            }
        }
    }
}

/// Recursive shared-drive listing. For each file returns `(file, folder_path)`
/// where folder_path is `"Engineering/Specs"` or `""` for files at the root
/// of the scope (drive root if `scope` is None, else the pinned folder).
///
/// Two API calls regardless of corpus size: one folders.list (paginated),
/// one files.list (paginated). Path computation is in-memory.
pub async fn list_files_recursive(
    http: &Client,
    drive_id: &str,
    scope_folder_id: Option<&str>,
    suffix_filter: Option<&[String]>,
) -> Result<Vec<(DriveFile, String)>, String> {
    let folders = list_all_folders(http, drive_id).await?;
    let folder_map: HashMap<String, (String, Option<String>)> = folders
        .into_iter()
        .map(|f| (f.id, (f.name, f.parent)))
        .collect();

    let files = list_all_files_in_drive(http, drive_id, suffix_filter).await?;

    let mut out = Vec::new();
    for file in files {
        let parent_id = file.parents.first().cloned();
        let path = match parent_id {
            Some(pid) => compute_folder_path(&pid, &folder_map, scope_folder_id),
            None => {
                // File without parent — drive root only valid if no scope
                if scope_folder_id.is_some() {
                    None
                } else {
                    Some(String::new())
                }
            }
        };
        if let Some(p) = path {
            out.push((file, p));
        }
        // None = file not under scope_folder_id → silently filtered out
    }
    Ok(out)
}
