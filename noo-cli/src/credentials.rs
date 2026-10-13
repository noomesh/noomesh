// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Per-user CLI credential storage — `~/.config/mesh/credentials.json` (0600).
//!
//! Phase 1 of the CLI-auth plan: the CLI
//! stops depending on the shared cluster HMAC secret for its own identity and
//! carries a per-user JWT instead, obtained by `noo auth login` against the
//! gateway's existing `POST /auth/token`.
//!
//! Why a file and NEVER `.env`: `.env` is configuration-only since 02e2037
//! (credentials live in `secrets/env.sops`), it is world-readable in the repo,
//! it is shared by every process on the host, and it is re-encrypted wholesale
//! by the secrets tooling — a per-person, per-machine credential has no
//! business there. The file lives beside the other per-user CLI state
//! (`~/.config/mesh/{pki,model_cache.json}`) and is written 0600 in a 0700
//! directory.
//!
//! The refresh token is stored alongside the access token because the
//! gateway's access tokens are deliberately short-lived (15 min, see
//! `auth_refresh::default_access_minutes`). The gateway hands the refresh out
//! as an httpOnly cookie for the dashboard; a CLI has no cookie jar, so we
//! persist the value and replay it as a `Cookie:` header on
//! `POST /api/auth/refresh`. That is the same credential the browser holds,
//! stored at the same sensitivity (0600).

use std::io::Write;
use std::path::PathBuf;

use serde_json::{json, Value};

/// Stored credential set for one gateway.
#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    /// Gateway base URL this credential was issued by (display + mismatch warning).
    pub gateway: String,
    /// The authenticated subject (JWT `sub`) — for `noo auth status` and 401 text.
    pub subject: String,
    /// Scopes reported at login time (informational; the gateway is authoritative).
    pub scopes: Vec<String>,
    pub access_token: String,
    /// Unix seconds at which `access_token` expires.
    pub expires_at: u64,
    /// Raw refresh token (the `noo_refresh` cookie value), when the gateway issued one.
    pub refresh_token: Option<String>,
    /// Unix seconds at which `refresh_token` expires (best-effort, from `refresh_ttl_days`).
    pub refresh_expires_at: Option<u64>,
}

/// Seconds of headroom before expiry at which we treat the access token as
/// already stale and try to refresh. A command that takes a while to run must
/// not start with a token that dies mid-flight.
pub const REFRESH_SKEW_SECS: u64 = 60;

impl Credentials {
    /// True when the access token is expired or within [`REFRESH_SKEW_SECS`] of it.
    pub fn access_stale_at(&self, now: u64) -> bool {
        self.expires_at <= now.saturating_add(REFRESH_SKEW_SECS)
    }

    /// True when the stored refresh token is present and not known-expired.
    pub fn refresh_usable_at(&self, now: u64) -> bool {
        match (&self.refresh_token, self.refresh_expires_at) {
            (Some(t), _) if t.is_empty() => false,
            (Some(_), Some(exp)) => exp > now,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "version": 1,
            "gateway": self.gateway,
            "subject": self.subject,
            "scopes": self.scopes,
            "access_token": self.access_token,
            "expires_at": self.expires_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_at": self.refresh_expires_at,
        })
    }

    /// Parse a stored file body. Returns `None` for anything that isn't a
    /// usable credential (missing token, wrong shape) — a corrupt file must
    /// degrade to "no stored credential", never to a panic.
    pub fn from_json(v: &Value) -> Option<Credentials> {
        let access_token = v["access_token"].as_str()?.to_string();
        if access_token.is_empty() {
            return None;
        }
        Some(Credentials {
            gateway: v["gateway"].as_str().unwrap_or_default().to_string(),
            subject: v["subject"].as_str().unwrap_or_default().to_string(),
            scopes: v["scopes"]
                .as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
            access_token,
            expires_at: v["expires_at"].as_u64().unwrap_or(0),
            refresh_token: v["refresh_token"].as_str().filter(|s| !s.is_empty()).map(str::to_string),
            refresh_expires_at: v["refresh_expires_at"].as_u64(),
        })
    }
}

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Where the credential file lives: `$NOO_CREDENTIALS_FILE`, else
/// `$XDG_CONFIG_HOME/mesh/credentials.json`, else
/// `~/.config/mesh/credentials.json` — the same directory as the CLI's
/// existing per-user state (`pki/`, `model_cache.json`).
pub fn credentials_path() -> PathBuf {
    if let Ok(p) = std::env::var("NOO_CREDENTIALS_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // A non-default instance keeps its own credential file
    // (`mesh/<instance>/credentials.json`) — two stacks on one host have
    // two gateways with two JWT secrets, and a shared token file would
    // log into whichever one issued last. The default instance keeps the
    // historical path so nothing re-logs-in after upgrade.
    let inst = crate::envfile::instance();
    let leaf = if inst.is_empty() {
        "mesh/credentials.json".to_string()
    } else {
        format!("mesh/{inst}/credentials.json")
    };
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join(&leaf);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".config").join(&leaf)
}

/// Load the stored credential, or `None` if absent/unreadable/corrupt.
pub fn load() -> Option<Credentials> {
    let text = std::fs::read_to_string(credentials_path()).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Credentials::from_json(&v)
}

/// Write the credential file 0600 inside a 0700 directory.
///
/// Written to a temp file in the same directory and renamed, so a failed
/// write can never leave a half-written (or world-readable) credential, and
/// the permissions are set BEFORE any secret bytes are written.
pub fn save(creds: &Credentials) -> Result<PathBuf, String> {
    let path = credentials_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    set_mode(&tmp, 0o600)?;
    let body = serde_json::to_string_pretty(&creds.to_json()).unwrap_or_default();
    f.write_all(body.as_bytes()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    f.write_all(b"\n").ok();
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| format!("cannot install {}: {e}", path.display()))?;
    set_mode(&path, 0o600)?;
    Ok(path)
}

/// The advisory lock guarding a refresh round-trip. Held for as long as the
/// value lives; released on drop AND on process death (that is a property of
/// `flock(2)`, which is why a crashed `noo` cannot wedge the next one).
pub struct FileLock {
    #[allow(dead_code)]
    file: std::fs::File,
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Path of the refresh lock file — beside the credential, never the credential
/// itself (locking the file we are about to `rename()` over would be lost the
/// moment the rename lands).
pub fn lock_path() -> PathBuf {
    credentials_path().with_extension("lock")
}

/// Take the exclusive refresh lock, waiting up to `timeout`.
///
/// Why this exists: the gateway **rotates refresh tokens on every use** and
/// treats a *revoked* token presented again as theft — it revokes the user's
/// entire refresh chain (`gateway-rust/src/routes/core.rs::auth_refresh_handler`).
/// So two concurrent `noo` processes that both spend the same stored refresh
/// token do not merely race on the file: they log the operator out everywhere.
/// One process refreshes; the others wait, re-read the file, and use what it
/// wrote.
#[cfg(unix)]
pub fn lock_for_refresh(timeout: std::time::Duration) -> Result<FileLock, String> {
    use std::os::unix::io::AsRawFd;
    let path = lock_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    set_mode(&path, 0o600)?;
    let fd = file.as_raw_fd();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(FileLock { file });
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "another `noo` process has held the refresh lock ({}) for longer than {}s",
                path.display(),
                timeout.as_secs()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[cfg(not(unix))]
pub fn lock_for_refresh(_timeout: std::time::Duration) -> Result<FileLock, String> {
    let path = lock_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    Ok(FileLock { file })
}

/// Remove the credential file. `Ok(false)` when there was nothing to remove.
pub fn delete() -> Result<bool, String> {
    let path = credentials_path();
    // The lock file carries no secret, but leaving it behind after a logout
    // is litter in the user's config dir.
    let _ = std::fs::remove_file(lock_path());
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot chmod {} to {mode:o}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

/// Show only enough of a token to recognise it in `auth status` output.
/// Never print a full bearer — `status` is a command people paste into issues.
pub fn redact(token: &str) -> String {
    let n = token.chars().count();
    if n <= 8 {
        return "…".to_string();
    }
    let head: String = token.chars().take(6).collect();
    format!("{head}…({n} chars)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path/permission tests mutate process env (`NOO_CREDENTIALS_FILE`,
    /// `HOME`, `XDG_CONFIG_HOME`), which cargo's threaded runner shares. Take
    /// this lock in every test that does, or they flake against each other.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn round_trips_through_json() {
        let c = Credentials {
            gateway: "http://localhost:8080".into(),
            subject: "alice".into(),
            scopes: vec!["read".into(), "write".into()],
            access_token: "jwt-value".into(),
            expires_at: 1_800_000_000,
            refresh_token: Some("refresh-value".into()),
            refresh_expires_at: Some(1_802_000_000),
        };
        assert_eq!(Credentials::from_json(&c.to_json()).unwrap(), c);
    }

    #[test]
    fn corrupt_or_tokenless_files_are_not_credentials() {
        // A half-written / hand-edited file must read as "no credential",
        // not as an empty bearer that then 401s confusingly.
        assert!(Credentials::from_json(&json!({})).is_none());
        assert!(Credentials::from_json(&json!({"access_token": ""})).is_none());
        assert!(Credentials::from_json(&json!({"access_token": 42})).is_none());
    }

    #[test]
    fn missing_optional_fields_still_load() {
        let c = Credentials::from_json(&json!({"access_token": "t"})).unwrap();
        assert_eq!(c.access_token, "t");
        assert_eq!(c.expires_at, 0);
        assert!(c.refresh_token.is_none());
        // expires_at=0 means "unknown" → always treated as stale, so the
        // refresh path runs rather than sending a token we can't vouch for.
        assert!(c.access_stale_at(1_000));
    }

    #[test]
    fn staleness_respects_the_skew_window() {
        let mut c = Credentials::from_json(&json!({"access_token": "t"})).unwrap();
        c.expires_at = 1_000_000;
        assert!(!c.access_stale_at(1_000_000 - REFRESH_SKEW_SECS - 1));
        assert!(c.access_stale_at(1_000_000 - REFRESH_SKEW_SECS));
        assert!(c.access_stale_at(1_000_000 + 5));
    }

    #[test]
    fn refresh_usability_tracks_presence_and_expiry() {
        let mk = |rt: Option<&str>, exp: Option<u64>| Credentials {
            gateway: String::new(),
            subject: String::new(),
            scopes: vec![],
            access_token: "t".into(),
            expires_at: 0,
            refresh_token: rt.map(str::to_string),
            refresh_expires_at: exp,
        };
        assert!(!mk(None, None).refresh_usable_at(10));
        assert!(!mk(Some(""), None).refresh_usable_at(10));
        assert!(mk(Some("r"), None).refresh_usable_at(10));
        assert!(mk(Some("r"), Some(100)).refresh_usable_at(10));
        assert!(!mk(Some("r"), Some(5)).refresh_usable_at(10));
    }

    #[test]
    fn redaction_never_reveals_a_usable_token() {
        let token = "abcdefghijklmnopqrstuvwxyz";
        let shown = redact(token);
        assert!(shown.starts_with("abcdef"));
        assert!(!shown.contains("ghij"));
        assert_eq!(redact("short"), "…");
    }

    #[test]
    fn path_precedence_is_explicit_then_xdg_then_home() {
        let _g = env_lock();
        let saved_home = std::env::var("HOME").ok();
        // Each assertion sets the env it needs and clears the
        // higher-precedence ones first.
        std::env::set_var("NOO_CREDENTIALS_FILE", "/tmp/explicit.json");
        assert_eq!(credentials_path(), PathBuf::from("/tmp/explicit.json"));
        std::env::remove_var("NOO_CREDENTIALS_FILE");

        std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg");
        assert_eq!(credentials_path(), PathBuf::from("/tmp/xdg/mesh/credentials.json"));
        std::env::remove_var("XDG_CONFIG_HOME");

        std::env::set_var("HOME", "/tmp/home");
        assert_eq!(
            credentials_path(),
            PathBuf::from("/tmp/home/.config/mesh/credentials.json")
        );
        match saved_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600_in_a_0700_directory() {
        let _g = env_lock();
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("noo-cred-test-{}", std::process::id()));
        let path = dir.join("credentials.json");
        std::env::set_var("NOO_CREDENTIALS_FILE", &path);
        let c = Credentials {
            gateway: "http://localhost:8080".into(),
            subject: "alice".into(),
            scopes: vec!["admin".into()],
            access_token: "jwt".into(),
            expires_at: 1,
            refresh_token: None,
            refresh_expires_at: None,
        };
        let written = save(&c).expect("save");
        let fmode = std::fs::metadata(&written).unwrap().permissions().mode() & 0o777;
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600, "credential file must be owner-only");
        assert_eq!(dmode, 0o700, "credential dir must be owner-only");
        assert_eq!(load().unwrap(), c);
        assert!(delete().unwrap());
        assert!(!delete().unwrap(), "delete is idempotent");
        std::env::remove_var("NOO_CREDENTIALS_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
