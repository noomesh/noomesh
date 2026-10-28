// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Container startup tasks, ported from `docker/entrypoint.py`.
//!
//! These ran as a Python wrapper process that then `exec`'d the gateway. Doing
//! them in-process removes the last reasons this image needs a shell or a
//! `git` binary, which is what lets the runtime move to the shell-less
//! hardened base (`dhi.io/python:3.12-debian13`) — see the design.
//!
//! Migrations are NOT here. They are still the Alembic chain and still need
//! Python; that is the design's job. Everything else entrypoint.py did is.
//!
//! ## Failure policy
//!
//! Every task is best-effort EXCEPT the PKI file check, which mirrors the
//! Python original: a gateway with no usable certificate should fail loudly
//! at startup rather than come up and refuse every mTLS connection.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Result of PKI staging — the paths the TLS layer should use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsPaths {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca: Option<PathBuf>,
}

/// Copy PKI material to a writable location and normalise permissions.
///
/// Port of `entrypoint.py::fix_pki_permissions`. The source is a bind mount
/// which on NTFS/WSL presents everything as 0777, and the TLS layer refuses
/// world-readable keys.
///
/// Per-file tolerant copy, deliberately: a strict recursive copy crash-looped
/// the gateway on 2026-07-08 when rotated keys landed with tighter host
/// permissions. `ca.key` in particular is 0600 on the host and the gateway
/// never needs the CA PRIVATE key — being unable to read it is normal.
pub fn stage_pki(src: &Path, dst: &Path) -> Result<TlsPaths, String> {
    if !src.is_dir() {
        return Ok(TlsPaths::default());
    }
    let _ = std::fs::remove_dir_all(dst);

    warn_low_disk(dst.parent().unwrap_or(dst), "pki staging");

    let mut skipped: Vec<(String, String)> = Vec::new();
    copy_tree(src, src, dst, &mut skipped);
    if !skipped.is_empty() {
        // Each entry carries the actual io::Error. The old log discarded it
        // and said "unreadable" for everything, which sent a live incident
        // (2026-08-23) chasing permissions for an hour while the real error
        // was ENOSPC on a full /var/lib/containerd volume. A permission-
        // denied ca.key is still the expected case — but say WHICH error.
        tracing::info!(
            skipped = ?skipped,
            "pki: files skipped (per-file error attached; permission denied on ca.key is expected)"
        );
    }

    // Required set. Missing here is fatal: the alternative is a gateway that
    // starts and then fails every TLS handshake. Include the copy error we
    // recorded for the file, if we saw one — that is the actual diagnosis.
    for required in ["gateway/gateway.crt", "gateway/gateway.key", "ca.crt"] {
        if !dst.join(required).exists() {
            let reason = skipped
                .iter()
                .find(|(rel, _)| rel == required)
                .map(|(_, err)| format!(" (copy failed: {err})"))
                .unwrap_or_default();
            return Err(format!(
                "PKI file required by the gateway is missing or unreadable: {required}{reason}"
            ));
        }
    }

    set_mode_by_extension(dst, "key", 0o600);
    set_mode_by_extension(dst, "crt", 0o644);

    Ok(TlsPaths {
        cert: Some(dst.join("gateway/gateway.crt")),
        key: Some(dst.join("gateway/gateway.key")),
        ca: Some(dst.join("ca.crt")),
    })
}

fn copy_tree(root: &Path, dir: &Path, dst_root: &Path, skipped: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy_tree(root, &path, dst_root, skipped);
            continue;
        }
        let Ok(rel) = path.strip_prefix(root) else { continue };
        let out = dst_root.join(rel);
        if let Some(parent) = out.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::copy(&path, &out) {
            // Keep the error — "permission denied" vs "no space left on
            // device" are different incidents (see stage_pki's skip log).
            skipped.push((rel.display().to_string(), e.to_string()));
        }
    }
}

/// Warn loudly when the filesystem holding `path` is nearly full. ENOSPC
/// during startup staging otherwise surfaces as per-file copy errors far
/// from the cause (the 2026-08-23 incident: a 100%-full 147G containerd
/// volume read as a permissions problem). Thresholds: < 1 GiB or < 5% free.
pub fn warn_low_disk(path: &Path, label: &str) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut st) } != 0 {
        return;
    }
    let frsize = if st.f_frsize > 0 { st.f_frsize } else { st.f_bsize } as u64;
    let total = st.f_blocks as u64 * frsize;
    let avail = st.f_bavail as u64 * frsize;
    if total == 0 {
        return;
    }
    let pct_free = (avail as f64 / total as f64) * 100.0;
    if avail < 1024 * 1024 * 1024 || pct_free < 5.0 {
        tracing::warn!(
            label,
            path = %path.display(),
            free_mb = avail / (1024 * 1024),
            pct_free = format!("{pct_free:.1}"),
            "LOW DISK on this filesystem — file operations may fail with ENOSPC"
        );
    }
}

fn set_mode_by_extension(dir: &Path, ext: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            set_mode_by_extension(&path, ext, mode);
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        }
    }
}

/// Append the cluster CA to a copy of the system trust bundle.
///
/// Port of `entrypoint.py::install_ca_bundle`. Returns the path to write into
/// `SSL_CERT_FILE` for the child Python process (the Alembic run), which is
/// the only consumer left — Rust's TLS uses `TlsPaths::ca` directly.
///
/// Returns `None` when there is nothing to do: no CA configured, no system
/// bundle, or the CA is already present in it (idempotent across restarts).
pub fn install_ca_bundle(ca_path: Option<&Path>, system_bundle: Option<&Path>, out: &Path) -> Option<PathBuf> {
    let ca = ca_path?;
    if !ca.is_file() {
        return None;
    }
    let bundle = system_bundle?;
    if !bundle.is_file() {
        return None;
    }
    let ca_data = std::fs::read_to_string(ca).ok()?;
    let existing = std::fs::read_to_string(bundle).ok()?;
    if existing.contains(ca_data.trim()) {
        return None;
    }
    let mut f = std::fs::File::create(out).ok()?;
    write!(f, "{existing}\n{ca_data}").ok()?;
    Some(out.to_path_buf())
}

/// Merge packaged defaults into Claude Code's `settings.json`.
///
/// Port of `entrypoint.py::merge_claude_config`. `env` and `mcpServers` are
/// REPLACED from defaults (the container owns them), while `permissions.allow`
/// is UNIONED so an operator's additions survive a restart — matching the
/// Python semantics exactly rather than tidying them.
pub fn merge_claude_settings(defaults: &serde_json::Value, existing: &serde_json::Value) -> serde_json::Value {
    let mut out = existing.clone();
    if !out.is_object() {
        out = serde_json::json!({});
    }
    let obj = out.as_object_mut().expect("object");

    obj.insert(
        "env".into(),
        defaults.get("env").cloned().unwrap_or_else(|| serde_json::json!({})),
    );
    obj.insert(
        "mcpServers".into(),
        defaults.get("mcpServers").cloned().unwrap_or_else(|| serde_json::json!({})),
    );

    let d_allow = defaults
        .get("permissions")
        .and_then(|p| p.get("allow"))
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let e_perms = existing.get("permissions").cloned().unwrap_or_else(|| serde_json::json!({}));
    let e_allow = e_perms.get("allow").and_then(|a| a.as_array()).cloned().unwrap_or_default();

    // Union, de-duplicated. Python used set(), which also loses order; order
    // is not meaningful for an allow list.
    let mut merged: Vec<serde_json::Value> = Vec::new();
    for v in e_allow.into_iter().chain(d_allow) {
        if !merged.contains(&v) {
            merged.push(v);
        }
    }

    let mut perms = e_perms.as_object().cloned().unwrap_or_default();
    if !merged.is_empty() {
        perms.insert("allow".into(), serde_json::Value::Array(merged));
    }
    if !perms.is_empty() {
        obj.insert("permissions".into(), serde_json::Value::Object(perms));
    }
    out
}

/// Whether a git config body already declares a `user.<field>`.
///
/// Deliberately conservative: any `field = value` line inside a `[user]`
/// section counts, so an operator's existing identity is never overwritten.
pub fn git_config_has_user_field(config: &str, field: &str) -> bool {
    let mut in_user = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_user = t.starts_with("[user]");
            continue;
        }
        if in_user {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim() == field && !v.trim().is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

/// Text to append to `.git/config` for whichever identity fields are missing.
///
/// Written directly rather than shelling out to `git config`, which is what
/// the Python original did. The shell-less hardened runtime has no `git`
/// binary, and this is the last thing that needed one.
///
/// Returns `None` when both fields are already set — the idempotent case.
pub fn git_identity_patch(config: &str, email: &str, name: &str) -> Option<String> {
    let need_email = !git_config_has_user_field(config, "email");
    let need_name = !git_config_has_user_field(config, "name");
    if !need_email && !need_name {
        return None;
    }
    let mut s = String::from("\n[user]\n");
    if need_email {
        s.push_str(&format!("\temail = {email}\n"));
    }
    if need_name {
        s.push_str(&format!("\tname = {name}\n"));
    }
    Some(s)
}

/// Ensure `/app/.git` has a commit identity.
///
/// Required by the self-develop Tier 2 pre-restart snapshot, which commits
/// before triggering an auto-restart. Without an identity the commit fails,
/// the snapshot returns nothing, and the rollback safety net disappears
/// silently. Best-effort: the gateway runs fine without git, only rollback
/// degrades.
pub fn ensure_git_identity(repo: &Path) {
    let cfg = repo.join(".git/config");
    if !repo.join(".git").is_dir() {
        return;
    }
    let existing = std::fs::read_to_string(&cfg).unwrap_or_default();
    let Some(patch) = git_identity_patch(&existing, "agent@noomesh.local", "PAI Agent") else {
        return;
    };
    match std::fs::OpenOptions::new().append(true).create(true).open(&cfg) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(patch.as_bytes()) {
                tracing::warn!(error = %e, "git identity: append failed — self-develop rollback will degrade");
            } else {
                tracing::info!("git identity seeded for the self-develop snapshot path");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "git identity: could not open .git/config");
        }
    }
}

/// Run every container startup task, in the order `entrypoint.py::main` did.
///
/// Called from `main()` BEFORE anything reads TLS config or spawns a thread:
/// staging PKI publishes `NOO_TLS_*`, which `tls.rs` reads from the
/// environment, and `set_var` is only sound while the process is
/// single-threaded.
///
/// Migrations are deliberately absent — still Alembic, still Python, still
/// entrypoint.py's job lands.
pub fn run_all() {
    // PKI first: TLS config depends on it, and a missing cert is fatal.
    match stage_pki(Path::new("/app/pki"), Path::new("/tmp/pki")) {
        Ok(paths) => {
            // Published into the environment because tls.rs reads
            // NOO_TLS_* from there. Done before any thread is spawned, which
            // is the soundness condition set_var carries in later editions —
            // worth honouring now so an edition bump is not a landmine.
            if let Some(p) = &paths.cert {
                std::env::set_var("NOO_TLS_CERT", p);
            }
            if let Some(p) = &paths.key {
                std::env::set_var("NOO_TLS_KEY", p);
            }
            if let Some(p) = &paths.ca {
                std::env::set_var("NOO_TLS_CA", p);
            }
            if paths.cert.is_some() {
                tracing::info!("pki staged to /tmp/pki");
            }
        }
        Err(e) => {
            // Matches the Python original: refuse to start rather than come
            // up and fail every mTLS handshake.
            eprintln!("[startup] FATAL: {e}");
            std::process::exit(1);
        }
    }

    // CA bundle — only the child Python (Alembic) still needs this; Rust TLS
    // uses NOO_TLS_CA directly.
    let ca = crate::tls::ca_path();
    let system_bundle = ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"]
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf);
    if let Some(out) = install_ca_bundle(
        ca.as_deref(),
        system_bundle.as_deref(),
        Path::new("/tmp/noo-ca-bundle.pem"),
    ) {
        std::env::set_var("SSL_CERT_FILE", &out);
        tracing::info!(path = %out.display(), "cluster CA appended to trust bundle");
    }

    write_claude_settings();
    ensure_git_identity(Path::new("/app"));
}

/// Merge packaged Claude Code defaults into the user's settings, if present.
fn write_claude_settings() {
    let defaults_path = Path::new("/opt/claude-defaults/settings.json");
    if !defaults_path.exists() {
        return;
    }
    let Ok(raw) = std::fs::read_to_string(defaults_path) else { return };
    let Ok(defaults) = serde_json::from_str::<serde_json::Value>(&raw) else {
        tracing::warn!("claude defaults are not valid JSON — skipping merge");
        return;
    };
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/nonroot".into());
    let target = Path::new(&home).join(".claude/settings.json");
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing = std::fs::read_to_string(&target)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let merged = merge_claude_settings(&defaults, &existing);
    match serde_json::to_string_pretty(&merged) {
        Ok(body) => {
            if let Err(e) = std::fs::write(&target, body) {
                tracing::warn!(error = %e, "claude settings write failed");
            }
        }
        Err(e) => tracing::warn!(error = %e, "claude settings serialise failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn git_identity_is_idempotent_when_already_set() {
        let cfg = "[core]\n\trepositoryformatversion = 0\n[user]\n\temail = me@example.com\n\tname = Me\n";
        assert_eq!(git_identity_patch(cfg, "a@b.c", "X"), None);
    }

    #[test]
    fn git_identity_respects_a_partially_configured_user() {
        // Operator set only the email — we must add name and NOT touch email.
        let cfg = "[user]\n\temail = me@example.com\n";
        let patch = git_identity_patch(cfg, "agent@noomesh.local", "PAI Agent").expect("patch");
        assert!(patch.contains("name = PAI Agent"));
        assert!(!patch.contains("email ="), "must not override an existing email: {patch}");
    }

    #[test]
    fn git_identity_seeds_both_when_absent() {
        let patch = git_identity_patch("[core]\n\tbare = false\n", "a@b.c", "N").expect("patch");
        assert!(patch.contains("email = a@b.c") && patch.contains("name = N"));
    }

    // A `name =` under [remote] is not a user identity. Matching it would
    // make us think identity exists and skip seeding, silently disabling
    // the self-develop rollback.
    #[test]
    fn fields_in_other_sections_do_not_count() {
        let cfg = "[remote \"origin\"]\n\tname = something\n\temail = x@y.z\n";
        assert!(!git_config_has_user_field(cfg, "name"));
        assert!(!git_config_has_user_field(cfg, "email"));
        assert!(git_identity_patch(cfg, "a@b.c", "N").is_some());
    }

    #[test]
    fn empty_value_counts_as_unset() {
        assert!(!git_config_has_user_field("[user]\n\temail =\n", "email"));
    }

    #[test]
    fn claude_merge_replaces_env_and_servers_but_unions_allow() {
        let defaults = json!({
            "env": {"A": "1"},
            "mcpServers": {"noo": {"url": "x"}},
            "permissions": {"allow": ["Bash(ls)", "Read"]}
        });
        let existing = json!({
            "env": {"OLD": "keep-me-not"},
            "mcpServers": {"stale": {}},
            "permissions": {"allow": ["Write"], "deny": ["Bash(rm)"]}
        });
        let merged = merge_claude_settings(&defaults, &existing);

        assert_eq!(merged["env"], json!({"A": "1"}), "env is replaced");
        assert_eq!(merged["mcpServers"]["noo"]["url"], "x");
        assert!(merged["mcpServers"].get("stale").is_none(), "servers replaced");

        let allow: Vec<String> = merged["permissions"]["allow"]
            .as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(allow.contains(&"Write".to_string()), "operator entry survives");
        assert!(allow.contains(&"Bash(ls)".to_string()), "default added");
        // deny is untouched — Python never rewrote it.
        assert_eq!(merged["permissions"]["deny"], json!(["Bash(rm)"]));
    }

    #[test]
    fn claude_merge_dedupes_allow() {
        let d = json!({"permissions": {"allow": ["Read", "Read"]}});
        let e = json!({"permissions": {"allow": ["Read"]}});
        let m = merge_claude_settings(&d, &e);
        assert_eq!(m["permissions"]["allow"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn claude_merge_from_empty_existing() {
        let d = json!({"env": {"A": "1"}, "mcpServers": {}});
        let m = merge_claude_settings(&d, &json!({}));
        assert_eq!(m["env"]["A"], "1");
    }

    #[test]
    fn pki_missing_source_dir_is_not_an_error() {
        let out = stage_pki(Path::new("/nonexistent/pki"), Path::new("/tmp/noo-pki-test-none"));
        assert_eq!(out.unwrap(), TlsPaths::default());
    }

    #[test]
    fn pki_missing_required_file_is_fatal() {
        let base = std::env::temp_dir().join("noo-pki-test-incomplete");
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("gateway")).unwrap();
        std::fs::write(src.join("gateway/gateway.crt"), "x").unwrap();
        // gateway.key and ca.crt deliberately absent.

        let err = stage_pki(&src, &base.join("dst")).expect_err("must fail loudly");
        assert!(err.contains("missing or unreadable"), "got: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pki_required_file_error_carries_the_copy_error() {
        use std::os::unix::fs::PermissionsExt;
        // Root reads through permission bits; this test only proves the
        // error is threaded when the copy DOES fail, so skip as root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let base = std::env::temp_dir().join("noo-pki-test-errno");
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("gateway")).unwrap();
        std::fs::write(src.join("gateway/gateway.crt"), "c").unwrap();
        std::fs::write(src.join("gateway/gateway.key"), "k").unwrap();
        std::fs::write(src.join("ca.crt"), "ca").unwrap();
        // Unreadable required file: the copy fails and the recorded io
        // error must surface in the fatal message — the 2026-08-23
        // incident chased "unreadable" for an hour when the real error
        // was ENOSPC; the errno is the diagnosis.
        std::fs::set_permissions(src.join("gateway/gateway.key"), std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = stage_pki(&src, &base.join("dst")).expect_err("must fail loudly");
        assert!(err.contains("gateway/gateway.key"), "got: {err}");
        assert!(err.contains("copy failed:"), "got: {err}");
        assert!(err.to_lowercase().contains("permission denied"), "got: {err}");
        let _ = std::fs::set_permissions(src.join("gateway/gateway.key"), std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pki_stages_and_tightens_key_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join("noo-pki-test-ok");
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("gateway")).unwrap();
        std::fs::write(src.join("gateway/gateway.crt"), "c").unwrap();
        std::fs::write(src.join("gateway/gateway.key"), "k").unwrap();
        std::fs::write(src.join("ca.crt"), "ca").unwrap();
        // World-readable, as an NTFS bind mount presents everything.
        std::fs::set_permissions(src.join("gateway/gateway.key"), std::fs::Permissions::from_mode(0o777)).unwrap();

        let dst = base.join("dst");
        let paths = stage_pki(&src, &dst).expect("staged");
        assert_eq!(paths.cert, Some(dst.join("gateway/gateway.crt")));

        let mode = std::fs::metadata(dst.join("gateway/gateway.key")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must not stay world-readable");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ca_bundle_is_skipped_when_already_present() {
        let base = std::env::temp_dir().join("noo-ca-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let ca = base.join("ca.crt");
        let bundle = base.join("bundle.pem");
        std::fs::write(&ca, "-----CA-----\n").unwrap();
        std::fs::write(&bundle, "existing\n-----CA-----\n").unwrap();

        let out = install_ca_bundle(Some(&ca), Some(&bundle), &base.join("out.pem"));
        assert_eq!(out, None, "already trusted — must not rewrite on every restart");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ca_bundle_appends_when_absent() {
        let base = std::env::temp_dir().join("noo-ca-test2");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let ca = base.join("ca.crt");
        let bundle = base.join("bundle.pem");
        std::fs::write(&ca, "-----MINE-----\n").unwrap();
        std::fs::write(&bundle, "system\n").unwrap();

        let out = base.join("out.pem");
        assert_eq!(install_ca_bundle(Some(&ca), Some(&bundle), &out), Some(out.clone()));
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("system") && body.contains("-----MINE-----"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
