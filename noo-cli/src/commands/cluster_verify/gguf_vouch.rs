// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The two rows about the controller vouching for GGUF files.
//!
//! `gguf verification` (node): a GGUF backend that started on the file already
//! on the node, without the controller's manifest to check it against, from
//! the agent's `gguf_unverified`. The node re-verifies the file on its own
//! once the controller answers, so the row clears itself.
//!
//! `model store readable` (controller): every file in the controller's model
//! store can be read by the gateway (uid 65532), the account that hashes it
//! for the manifest.

use super::{ok, warn, Check};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The account the gateway runs as; it hashes the store's files.
pub(crate) const GATEWAY_UID: u32 = 65532;
pub(crate) const GATEWAY_GID: u32 = 65532;

const NODE_ROW: &str = "gguf verification";
const STORE_ROW: &str = "model store readable";

/// The `gguf verification` row: each backend in `gguf_unverified`. WARN naming
/// the backend, the model and the reason. No row when the node reports none.
pub(crate) fn gguf_verification_check(id: &str, n: &Value) -> Option<Check> {
    let rows = n.get("gguf_unverified")?.as_array()?;
    if rows.is_empty() {
        return None;
    }
    let parts: Vec<String> = rows
        .iter()
        .map(|r| {
            // While the node hashes the file, that is the state to read; the
            // reason it started unvouched stays with the row's remedy.
            let why = match (r["state"].as_str(), r["verifying_since"].as_str()) {
                (Some("verifying"), Some(t)) => format!("verifying against the controller's manifest since {t}"),
                _ => r["reason"].as_str().unwrap_or("no reason reported").to_string(),
            };
            format!(
                "{} {} started without the controller's verification: {why}",
                r["backend"].as_str().unwrap_or("?"),
                r["model"].as_str().unwrap_or("?"),
            )
        })
        .collect();
    Some(warn(
        NODE_ROW,
        parts.join("; "),
        Some(format!(
            "confirm the file is in the controller's model store and readable (the `{STORE_ROW}` row names any it cannot read); {id} re-verifies on its own once the controller answers"
        )),
    ))
}

/// One entry of the controller's model store, as `stat` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreEntry {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    /// Permission bits, e.g. 0o640.
    pub mode: u32,
    pub is_dir: bool,
}

/// Whether the gateway's account may open this entry: read (and, for a
/// directory, search) by the permission class that applies to it.
pub(crate) fn gateway_can_read(e: &StoreEntry) -> bool {
    let need: u32 = if e.is_dir { 0b101 } else { 0b100 };
    let class = if e.uid == GATEWAY_UID {
        (e.mode >> 6) & 0b111
    } else if e.gid == GATEWAY_GID {
        (e.mode >> 3) & 0b111
    } else {
        e.mode & 0b111
    };
    class & need == need
}

/// The `model store readable` row over the entries found: WARN naming each
/// path the gateway cannot read, its owner and mode, with the chmod.
pub(crate) fn model_store_readable_check(dir: &str, entries: &[StoreEntry]) -> Check {
    let bad: Vec<&StoreEntry> = entries.iter().filter(|e| !gateway_can_read(e)).collect();
    if bad.is_empty() {
        let files = entries.iter().filter(|e| !e.is_dir).count();
        return ok(STORE_ROW, format!("the gateway (uid {GATEWAY_UID}) can read all {files} file(s) in {dir}"));
    }
    let named: Vec<String> = bad
        .iter()
        .map(|e| format!("{} (owner {}:{}, mode {:04o})", e.path, e.uid, e.gid, e.mode & 0o7777))
        .collect();
    let fixes: Vec<String> = bad
        .iter()
        .map(|e| format!("chmod {} {}", if e.is_dir { "0755" } else { "0644" }, e.path))
        .collect();
    warn(
        STORE_ROW,
        format!(
            "the gateway (uid {GATEWAY_UID}) cannot read {} path(s) in {dir}, so it cannot state their sha256 and nodes cannot verify them: {}",
            bad.len(),
            named.join("; ")
        ),
        Some(fixes.join(" && ")),
    )
}

/// Walk the store (depth 3, at most 20000 entries) and stat each entry. Err
/// is the reason the directory could not be read; a missing directory is
/// Ok(None): no store, nothing to judge.
pub(crate) fn read_store(dir: &Path) -> Result<Option<Vec<StoreEntry>>, String> {
    use std::os::unix::fs::MetadataExt;
    if !dir.exists() {
        return Ok(None);
    }
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, u32)> = vec![(dir.to_path_buf(), 0)];
    while let Some((d, depth)) = stack.pop() {
        let rd = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for ent in rd.flatten() {
            if out.len() >= 20_000 {
                return Ok(Some(out));
            }
            let Ok(md) = ent.metadata() else { continue };
            let path = ent.path();
            let is_dir = md.is_dir();
            out.push(StoreEntry {
                path: path.display().to_string(),
                uid: md.uid(),
                gid: md.gid(),
                mode: md.mode() & 0o7777,
                is_dir,
            });
            if is_dir && depth < 3 {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(Some(out))
}

/// The row for this host's store (`MODELS_DIR`), or None when there is no
/// store here. A store this account cannot list is a WARN saying so.
pub(crate) fn model_store_readable_row() -> Option<Check> {
    let dir = crate::commands::models_fetch::controller_store_dir();
    match read_store(Path::new(&dir)) {
        Ok(None) => None,
        Ok(Some(entries)) => Some(model_store_readable_check(&dir, &entries)),
        Err(e) => Some(warn(
            STORE_ROW,
            format!("could not list the controller's model store: {e}"),
            Some(format!("run `noo cluster verify` as a user that can read {dir}")),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use serde_json::json;

    fn file(path: &str, uid: u32, gid: u32, mode: u32) -> StoreEntry {
        StoreEntry { path: path.into(), uid, gid, mode, is_dir: false }
    }

    #[test]
    fn an_unvouched_backend_warns_naming_backend_model_and_reason_with_a_remedy() {
        let n = json!({"gguf_unverified": [{"backend": "llamacpp", "model": "m.gguf",
            "reason": "the controller is still hashing m.gguf; retrying on the next reconcile pass", "since": "t"}]});
        let c = gguf_verification_check("node-a", &n).unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.detail, "llamacpp m.gguf started without the controller's verification: the controller is still hashing m.gguf; retrying on the next reconcile pass");
        let r = c.remedy.unwrap();
        assert!(r.contains("confirm the file is in the controller's model store and readable"), "{r}");
        assert!(r.contains("node-a re-verifies on its own once the controller answers"), "{r}");
    }

    #[test]
    fn a_backend_being_hashed_reads_verifying_since_the_time() {
        let n = json!({"gguf_unverified": [{"backend": "llamacpp", "model": "m.gguf", "reason": "r",
            "state": "verifying", "verifying_since": "2026-11-23T10:00:00Z", "since": "t"}]});
        let c = gguf_verification_check("node-a", &n).unwrap();
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.detail, "llamacpp m.gguf started without the controller's verification: verifying against the controller's manifest since 2026-11-23T10:00:00Z");
    }

    #[test]
    fn no_unvouched_backend_means_no_row() {
        assert!(gguf_verification_check("n", &json!({})).is_none());
        assert!(gguf_verification_check("n", &json!({"gguf_unverified": []})).is_none());
    }

    #[test]
    fn the_gateway_reads_by_owner_group_or_other_class() {
        assert!(gateway_can_read(&file("/s/a.gguf", 1000, 1000, 0o644)));
        assert!(!gateway_can_read(&file("/s/a.gguf", 1000, 1000, 0o600)));
        assert!(!gateway_can_read(&file("/s/a.gguf", 1000, 1000, 0o640)));
        assert!(gateway_can_read(&file("/s/a.gguf", 1000, 65532, 0o640)));
        assert!(gateway_can_read(&file("/s/a.gguf", 65532, 1000, 0o400)));
        // Owner class wins: owned by the gateway with no owner read, group/other open.
        assert!(!gateway_can_read(&file("/s/a.gguf", 65532, 65532, 0o044)));
        // A directory needs search as well as read.
        let d = |mode| StoreEntry { path: "/s/d".into(), uid: 0, gid: 0, mode, is_dir: true };
        assert!(gateway_can_read(&d(0o755)));
        assert!(!gateway_can_read(&d(0o744)));
    }

    #[test]
    fn a_readable_store_is_ok() {
        let c = model_store_readable_check("/m", &[file("/m/a.gguf", 0, 0, 0o644), file("/m/b.gguf", 0, 0, 0o664)]);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("can read all 2 file(s) in /m"), "{}", c.detail);
    }

    #[test]
    fn an_unreadable_file_warns_with_owner_mode_and_chmod() {
        let c = model_store_readable_check("/m", &[file("/m/a.gguf", 0, 0, 0o644), file("/m/b.gguf", 1000, 1000, 0o600)]);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("cannot read 1 path(s) in /m"), "{}", c.detail);
        assert!(c.detail.contains("/m/b.gguf (owner 1000:1000, mode 0600)"), "{}", c.detail);
        assert!(!c.detail.contains("/m/a.gguf"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("chmod 0644 /m/b.gguf"));
    }
}
