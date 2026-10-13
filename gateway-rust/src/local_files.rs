// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Native `local_files` tool — file I/O on operator-configured mounts.
//!
//! Port of the Python `FileExecutor` (`gateway/tools_executor.py`), which
//! ran in trellion behind `worker.tool.generic`. That seam cost four live
//! defects in one afternoon: quote-token corruption, mounts
//! present in only one container, an RPC envelope that hid failures, and
//! a full approval round-trip per missing-content retry. Running natively
//! puts zero hops between the exec-approval gate and the write.
//!
//! Behavior parity notes (deviations are deliberate and listed):
//! - actions `read` / `write` / `list` match the Python executor byte-for
//!   byte on messages; `save` is accepted as an alias of `write` and
//!   `append` is implemented (both were "Unknown action" errors in Python
//!   even though the pre-gate validator already accepted them — models
//!   emit them, so failing after approval wasted an approval).
//!   Risk classification is unaffected: anything that isn't read/list/find
//!   classifies High (`security.rs`), so `save`/`append` still gate.
//! - the read allow-list is the operator's DECLARED roots and nothing
//!   else. Python (and this port R10) also added the
//!   process temp dir and the gateway cwd; the gateway's cwd is `/app`,
//!   which in the shipped image holds `noomesh.yaml`, the compose
//!   override, `prompts/`, `skills/`, `/app/pki` and the Google service
//!   account key when one is configured — so `local_files{read,
//!   "/app/pki/<key>"}` was a read of the gateway's own secrets that no
//!   operator ever declared. Both implicit roots are gone; an install
//!   that declares no roots can read nothing, which is the right
//!   failure. `denied_roots()` is the second lock: those paths stay
//!   unreachable even if an operator declares `/` or `/app` itself.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::config::AppConfig;

/// Read/write policy resolved from config once per call. Separate from
/// `AppConfig` so tests can construct one against a tempdir directly.
#[derive(Debug, Clone)]
pub struct FilePolicy {
    /// Read allow-list (reads, lists). Writable roots are implicitly
    /// readable because `get_file_allowed_paths` includes them upstream.
    pub allowed: Vec<PathBuf>,
    /// Write allow-list: watched folders flagged `writable: true` + the
    /// workspace mount.
    pub writable: Vec<PathBuf>,
    /// Workspace mount, when configured — bare-root writes are redirected
    /// into `<workspace>/requested/` (operator convention, 2026-08-09).
    pub workspace_root: Option<PathBuf>,
}

impl FilePolicy {
    /// Mirror of Python `get_file_allowed_paths()` + the `FileExecutor`
    /// constructor defaults.
    pub fn from_config(cfg: &AppConfig) -> Self {
        // ONLY what the operator declared: `tools.allowed_paths`, the
        // watched-folder mounts and the workspace. No temp dir, no cwd
        // — see the module header.
        let mut allowed: Vec<PathBuf> = Vec::new();
        for p in &cfg.tools.allowed_paths {
            if !p.is_empty() {
                allowed.push(PathBuf::from(p));
            }
        }
        if cfg.watched_folders.enabled {
            for f in &cfg.watched_folders.folders {
                allowed.push(PathBuf::from(f.mount_path()));
            }
        }
        let ws = cfg.workspace.path();
        let workspace_root = if ws.is_empty() {
            None
        } else {
            allowed.push(PathBuf::from(&ws));
            Some(PathBuf::from(&ws))
        };

        let mut writable: Vec<PathBuf> = cfg
            .watched_folders
            .folders
            .iter()
            .filter_map(|f| match f {
                crate::config::FolderEntry::Detailed { mount, writable: true, .. } => {
                    Some(PathBuf::from(mount))
                }
                _ => None,
            })
            .collect();
        if let Some(root) = &workspace_root {
            writable.push(root.clone());
        }

        Self { allowed, writable, workspace_root }
    }
}

/// Resolve a path the way Python's `Path.resolve()` does for prefix
/// checks: canonicalize the deepest EXISTING ancestor (following
/// symlinks), then re-append the non-existent tail. A `..` in the tail is
/// rejected outright — the sanitizer upstream already blocks traversal
/// patterns, and nothing legitimate writes through one.
fn resolve_for_check(path: &Path) -> Result<PathBuf, String> {
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "Access denied: {} contains parent-directory components",
            path.display()
        ));
    }
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(canon) => {
                let mut out = canon;
                for seg in tail.iter().rev() {
                    out.push(seg);
                }
                return Ok(out);
            }
            Err(_) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name.to_os_string());
                    existing = parent.to_path_buf();
                }
                // Ran out of components without finding anything real
                // (relative path whose head doesn't exist) — use as-is.
                _ => return Ok(path.to_path_buf()),
            },
        }
    }
}

/// Paths `local_files` may never touch, whatever the operator declared.
///
/// The allow-list is the control ( removed the implicit
/// `/app` and temp-dir roots that made this reachable in the first
/// place); this is the belt behind the braces, for the operator who
/// declares `/` or `/app` in `tools.allowed_paths` — which is itself a
/// GATED config section, but a gate is not a wall. Reads of the
/// gateway's own configuration, prompts, skills and keys are impossible
/// by construction, not by policy.
///
/// `/app` is the gateway's working directory in the shipped image
/// (`noomesh.yaml`, `docker-compose.override.yml`, `prompts/`,
/// `skills/`, `pki/`, the Google service-account key). `/tls` is the PKI
/// mount every service gets read-only. `/run/secrets` is where compose
/// and swarm drop secret files.
const DENIED_PREFIXES: &[&str] = &[
    "/app",
    "/run/secrets",
    "/tls",
    "/etc/shadow",
    "/etc/ssl/private",
    "/proc/self/environ",
];

/// [`DENIED_PREFIXES`] plus the PKI directory this process was actually
/// pointed at — `NOO_PKI_DIR` when set, else the directory holding
/// `NOO_TLS_CA` / `NOO_TLS_KEY`. A deployment that mounts the CA
/// somewhere other than `/tls` is covered without editing the constant.
pub fn denied_roots() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = DENIED_PREFIXES.iter().map(PathBuf::from).collect();
    if let Ok(dir) = std::env::var("NOO_PKI_DIR") {
        if !dir.trim().is_empty() {
            out.push(PathBuf::from(dir.trim()));
        }
    }
    for var in ["NOO_TLS_CA", "NOO_TLS_KEY", "NOO_TLS_CERT"] {
        if let Ok(file) = std::env::var(var) {
            if let Some(parent) = Path::new(file.trim()).parent() {
                if !parent.as_os_str().is_empty() && parent != Path::new("/") {
                    out.push(parent.to_path_buf());
                }
            }
        }
    }
    out
}

/// Is this resolved path inside a denied root? Checked on the RESOLVED
/// path, so a symlink from a declared root into `/app/pki` is caught —
/// `resolve_for_check` canonicalises the deepest existing ancestor.
fn is_denied(resolved: &Path) -> bool {
    is_under_any(resolved, &denied_roots())
}

fn is_under_any(resolved: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| {
        let root = root.canonicalize().unwrap_or_else(|_| root.clone());
        resolved.starts_with(&root)
    })
}

/// Max chars returned by `read` before truncation — matches Python.
const READ_TRUNCATE_CHARS: usize = 50_000;
/// Max directory entries listed — matches Python.
const LIST_LIMIT: usize = 100;

/// Would this `local_files` write land inside the operator's writable
/// allow-list? Mirrors `run()`'s write arm exactly — same resolver, same
/// bare-root->`requested/` redirect, same prefix checks — without touching
/// the filesystem. Used by the risk classifier: a write the policy already
/// authorizes needs no per-call human approval (a user who has approved the workspace or
/// the task does not have to approve each time). Anything unparseable or unresolvable
/// answers `false` — unknown stays gated.
pub fn write_targets_writable(policy: &FilePolicy, args: &Value) -> bool {
    let Some(path_str) = args
        .get("path")
        .and_then(|p| p.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let Ok(resolved) = resolve_for_check(Path::new(path_str)) else {
        return false;
    };
    if !is_under_any(&resolved, &policy.allowed) || is_denied(&resolved) {
        return false;
    }
    let target = match &policy.workspace_root {
        Some(root) if resolved.parent() == Some(root.as_path()) => match resolved.file_name() {
            Some(name) => root.join("requested").join(name),
            None => return false,
        },
        _ => resolved.clone(),
    };
    is_under_any(&target, &policy.writable)
}

/// Execute one `local_files` action. `Ok` is the success output text,
/// `Err` the error message — the caller maps these onto `ToolResult`
/// success/error exactly like every other native tool.
pub async fn run(policy: &FilePolicy, args: &Value) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or("read")
        .trim()
        .to_lowercase();
    let path_str = args
        .get("path")
        .and_then(|p| p.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "No path provided".to_string())?
        .to_string();

    // Small models name the write payload inconsistently — same alias set
    // as the Python executor and the pre-gate validator (#597).
    let content = ["content", "text", "contents", "data", "body", "file_content"]
        .iter()
        .filter_map(|k| args.get(*k).and_then(|v| v.as_str()))
        .next()
        .map(str::to_string);

    let file_path = PathBuf::from(&path_str);
    let resolved = resolve_for_check(&file_path)?;

    if is_denied(&resolved) {
        // Same message as the allow-list denial on purpose: the model
        // learns "not yours", not the shape of the gateway's own layout.
        return Err(format!(
            "Access denied: {path_str} is outside allowed directories"
        ));
    }
    if !is_under_any(&resolved, &policy.allowed) {
        return Err(format!(
            "Access denied: {path_str} is outside allowed directories"
        ));
    }

    match action.as_str() {
        "read" => {
            if !resolved.exists() {
                return Err(format!("File not found: {path_str}"));
            }
            let bytes = tokio::fs::read(&resolved)
                .await
                .map_err(|e| format!("File operation failed: {e}"))?;
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            if text.chars().count() > READ_TRUNCATE_CHARS {
                text = text.chars().take(READ_TRUNCATE_CHARS).collect::<String>()
                    + "\n... (truncated)";
            }
            Ok(text)
        }

        "write" | "save" | "append" => {
            // Workspace convention: ad-hoc files land in requested/, not
            // the workspace root. Only bare-root writes are redirected —
            // an explicit subdirectory (research/, activity/, …) is
            // respected as chosen.
            let (target, display_path) = match &policy.workspace_root {
                Some(root) if resolved.parent() == Some(root.as_path()) => {
                    let name = resolved
                        .file_name()
                        .ok_or_else(|| format!("Write denied: {path_str} has no file name"))?;
                    let t = root.join("requested").join(name);
                    let d = t.clone();
                    (t, d)
                }
                _ => (resolved.clone(), resolved.clone()),
            };

            if !is_under_any(&target, &policy.writable) {
                return Err(format!(
                    "Write denied: {} is not in a writable directory. \
                     Toggle the directory to writable via the dashboard first.",
                    display_path.display()
                ));
            }
            let content = content
                .ok_or_else(|| "No content provided for write operation".to_string())?;

            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("File operation failed: {e}"))?;
            }
            let (verb, written_len) = if action == "append" {
                use tokio::io::AsyncWriteExt;
                let mut f = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&target)
                    .await
                    .map_err(|e| format!("File operation failed: {e}"))?;
                f.write_all(content.as_bytes())
                    .await
                    .map_err(|e| format!("File operation failed: {e}"))?;
                // tokio::fs::File buffers internally and its Drop closes in
                // the background with errors IGNORED — without this flush
                // the append can report success and lose the bytes (caught
                // twice by content_aliases_accepted_and_save_append_work as
                // a "flake": read-back saw the pre-append content).
                f.flush()
                    .await
                    .map_err(|e| format!("File operation failed: {e}"))?;
                ("File appended", content.len())
            } else {
                tokio::fs::write(&target, content.as_bytes())
                    .await
                    .map_err(|e| format!("File operation failed: {e}"))?;
                ("File written", content.len())
            };

            // Report workspace-relative ("requested/foo.txt") — that is
            // the name the operator sees in their synced folder.
            let display = policy
                .workspace_root
                .as_ref()
                .and_then(|root| display_path.strip_prefix(root).ok())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| display_path.display().to_string());
            Ok(format!("{verb}: {display} ({written_len} bytes)"))
        }

        "list" => {
            if !resolved.is_dir() {
                return Err(format!("Not a directory: {path_str}"));
            }
            let mut rd = tokio::fs::read_dir(&resolved)
                .await
                .map_err(|e| format!("File operation failed: {e}"))?;
            let mut entries: Vec<(bool, String)> = Vec::new();
            while let Ok(Some(entry)) = rd.next_entry().await {
                let is_dir = entry
                    .file_type()
                    .await
                    .map(|t| t.is_dir())
                    .unwrap_or(false);
                entries.push((is_dir, entry.file_name().to_string_lossy().into_owned()));
            }
            entries.sort_by(|a, b| a.1.cmp(&b.1));
            entries.truncate(LIST_LIMIT);
            let output = entries
                .iter()
                .map(|(d, name)| format!("{} {}", if *d { "[D]" } else { "[F]" }, name))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(if output.is_empty() {
                "(empty directory)".to_string()
            } else {
                output
            })
        }

        other => Err(format!(
            "Unknown action: {other}. Use 'read', 'write', or 'list'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(root: &Path) -> FilePolicy {
        FilePolicy {
            allowed: vec![root.to_path_buf()],
            writable: vec![root.to_path_buf()],
            workspace_root: Some(root.to_path_buf()),
        }
    }

    fn tmproot(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lf_test_{name}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// PINNED by design: a write inside the writable
    /// allow-list is pre-authorized — the classifier consumes this to skip
    /// the per-call approval. Outside, unparseable, or traversing paths
    /// all answer false and stay gated.
    #[test]
    fn write_targets_writable_scoping() {
        let root = tmproot("scoped");
        let p = policy(&root);

        // Inside a workspace subdirectory → authorized.
        let inside = root.join("research/report.md");
        assert!(write_targets_writable(&p, &json!({"action":"write","path":inside})));
        // Bare-root write redirects into requested/ — still authorized.
        let bare = root.join("note.txt");
        assert!(write_targets_writable(&p, &json!({"action":"write","path":bare})));
        // Outside every root → not authorized (and run() refuses it too).
        assert!(!write_targets_writable(&p, &json!({"action":"write","path":"/etc/passwd"})));
        // Traversal in the tail is rejected by the resolver → false.
        let sneaky = root.join("research/../../escape.md");
        assert!(!write_targets_writable(&p, &json!({"action":"write","path":sneaky})));
        // No path at all → false.
        assert!(!write_targets_writable(&p, &json!({"action":"write"})));
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let root = tmproot("rw");
        let p = policy(&root);
        let path = root.join("sub").join("a.txt");
        let out = run(&p, &json!({"action": "write", "path": path, "content": "hello"}))
            .await
            .unwrap();
        assert!(out.starts_with("File written:"), "{out}");
        assert!(out.contains("(5 bytes)"), "{out}");
        let text = run(&p, &json!({"action": "read", "path": path})).await.unwrap();
        assert_eq!(text, "hello");
    }

    #[tokio::test]
    async fn bare_workspace_root_write_redirects_to_requested() {
        let root = tmproot("redirect");
        let p = policy(&root);
        let out = run(
            &p,
            &json!({"action": "write", "path": root.join("note.txt"), "content": "x"}),
        )
        .await
        .unwrap();
        assert!(out.contains("requested"), "{out}");
        assert!(root.join("requested/note.txt").is_file());
        // An explicit subdirectory is respected as chosen.
        let out2 = run(
            &p,
            &json!({"action": "write", "path": root.join("research/r.md"), "content": "y"}),
        )
        .await
        .unwrap();
        assert!(!out2.contains("requested"), "{out2}");
        assert!(root.join("research/r.md").is_file());
    }

    #[tokio::test]
    async fn content_aliases_accepted_and_save_append_work() {
        let root = tmproot("alias");
        let p = policy(&root);
        let path = root.join("d/al.txt");
        // gemma has sent all of these for the same field (#597)
        run(&p, &json!({"action": "save", "path": path, "text": "ab"})).await.unwrap();
        let out = run(&p, &json!({"action": "append", "path": path, "body": "cd"}))
            .await
            .unwrap();
        assert!(out.starts_with("File appended:"), "{out}");
        let text = run(&p, &json!({"action": "read", "path": path})).await.unwrap();
        assert_eq!(text, "abcd");
    }

    #[tokio::test]
    async fn denials_match_python_messages() {
        let root = tmproot("deny");
        let p = FilePolicy {
            allowed: vec![root.clone()],
            writable: vec![], // nothing writable
            workspace_root: None,
        };
        let err = run(&p, &json!({"action": "read", "path": "/etc/passwd"}))
            .await
            .unwrap_err();
        assert!(err.starts_with("Access denied:"), "{err}");

        let err = run(
            &p,
            &json!({"action": "write", "path": root.join("x.txt"), "content": "no"}),
        )
        .await
        .unwrap_err();
        assert!(err.starts_with("Write denied:"), "{err}");
        assert!(err.contains("dashboard"), "{err}");

        let p2 = policy(&root);
        let err = run(&p2, &json!({"action": "write", "path": root.join("sub/y.txt")}))
            .await
            .unwrap_err();
        assert_eq!(err, "No content provided for write operation");

        let err = run(&p2, &json!({"action": "read", "path": root.join("missing.txt")}))
            .await
            .unwrap_err();
        assert!(err.starts_with("File not found:"), "{err}");

        let err = run(&p2, &json!({"action": "explode", "path": root.join("z")}))
            .await
            .unwrap_err();
        assert!(err.starts_with("Unknown action: explode"), "{err}");
    }

    #[tokio::test]
    async fn parent_dir_components_rejected_even_inside_allowed_root() {
        let root = tmproot("dotdot");
        let p = policy(&root);
        let sneaky = root.join("sub/../../../etc/passwd");
        let err = run(&p, &json!({"action": "read", "path": sneaky})).await.unwrap_err();
        assert!(err.contains("parent-directory"), "{err}");
    }

    /// the read allow-list is the operator's declared
    /// roots ONLY. Before this, `from_config` seeded it with the process
    /// temp dir and the gateway cwd — and the gateway's cwd is `/app`,
    /// which holds `noomesh.yaml`, `prompts/`, `skills/` and `/app/pki`.
    /// The test fails on the old code: with no declared roots the old
    /// policy still had two, and a read under the temp dir succeeded.
    #[tokio::test]
    async fn no_declared_roots_means_no_readable_roots() {
        let cfg = crate::config::AppConfig::default();
        let p = FilePolicy::from_config(&cfg);
        assert!(
            p.allowed.is_empty(),
            "a default config declares no file roots, so none are readable: {:?}",
            p.allowed
        );

        // Concretely: a file the OLD implicit roots covered.
        let probe = std::env::temp_dir().join(format!("lf_r10_{}.txt", std::process::id()));
        std::fs::write(&probe, "secret").unwrap();
        let err = run(&p, &json!({"action": "read", "path": probe}))
            .await
            .unwrap_err();
        assert!(err.starts_with("Access denied:"), "{err}");
        let _ = std::fs::remove_file(&probe);
    }

    /// Belt and braces for R10: even an operator who declares `/` (or
    /// `/app` itself) in `tools.allowed_paths` cannot make the gateway's
    /// own configuration, PKI or secret mounts readable.
    #[tokio::test]
    async fn denied_roots_refuse_even_when_the_operator_declares_slash() {
        let p = FilePolicy {
            allowed: vec![PathBuf::from("/")],
            writable: vec![PathBuf::from("/")],
            workspace_root: None,
        };
        for path in [
            "/app/noomesh.yaml",
            "/app/pki/gateway/gateway.key",
            "/app/prompts/system.md",
            "/run/secrets/db-password",
            "/tls/ca.crt",
            "/etc/shadow",
        ] {
            let err = run(&p, &json!({"action": "read", "path": path}))
                .await
                .unwrap_err();
            assert!(
                err.starts_with("Access denied:"),
                "{path} must be denied, got: {err}"
            );
            assert!(
                !write_targets_writable(&p, &json!({"action": "write", "path": path})),
                "{path} must never pre-authorize a write"
            );
        }
        // A path NOT on the deny-list under the same declared root still
        // works — otherwise this test would pass on a policy that denies
        // everything.
        let probe = std::env::temp_dir().join(format!("lf_deny_ok_{}.txt", std::process::id()));
        std::fs::write(&probe, "ok").unwrap();
        assert_eq!(
            run(&p, &json!({"action": "read", "path": &probe})).await.unwrap(),
            "ok"
        );
        let _ = std::fs::remove_file(&probe);
    }

    /// The PKI directory this process was actually pointed at is denied
    /// too, not just the literal `/tls` default.
    #[test]
    fn denied_roots_pick_up_the_configured_pki_dir() {
        let prev = std::env::var("NOO_PKI_DIR").ok();
        std::env::set_var("NOO_PKI_DIR", "/srv/mesh-pki");
        assert!(denied_roots().contains(&PathBuf::from("/srv/mesh-pki")));
        match prev {
            Some(v) => std::env::set_var("NOO_PKI_DIR", v),
            None => std::env::remove_var("NOO_PKI_DIR"),
        }
    }

    #[tokio::test]
    async fn list_marks_dirs_and_files() {
        let root = tmproot("list");
        let p = policy(&root);
        std::fs::create_dir_all(root.join("ls/inner")).unwrap();
        std::fs::write(root.join("ls/f.txt"), "x").unwrap();
        let out = run(&p, &json!({"action": "list", "path": root.join("ls")}))
            .await
            .unwrap();
        assert_eq!(out, "[F] f.txt\n[D] inner");
        let err = run(&p, &json!({"action": "list", "path": root.join("ls/f.txt")}))
            .await
            .unwrap_err();
        assert!(err.starts_with("Not a directory:"), "{err}");
    }
}
