// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Recorded consent to the PersonifAI Add-on License Terms.
//!
//! Two records exist for one entitlement: the issuer's decision, signed into
//! the token (`Entitlement::terms`), and the holder's acceptance at install,
//! appended to `addon-terms-acceptances.jsonl` on the controller. Neither
//! changes what a token unlocks: features stay the only authority.
//!
//! Failure semantics, by path:
//! - the acceptance record is ABSENT on a controller that installed before
//!   terms existed: `show` says "not recorded", it is not an error;
//! - the record file cannot be WRITTEN: the install is refused, because
//!   consent that is not recorded did not happen;
//! - an unreadable or partly corrupt record file on READ is treated as
//!   "no usable record" (corrupt lines are skipped), never as a failure.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// The add-on terms version this build knows as current.
pub const ADDON_TERMS_VERSION: &str = "addon-1.0";
/// Where the terms text is published, for every version.
pub const ADDON_TERMS_URL: &str = "https://noomesh.ai/add-ons/terms";
/// Shown as the heading of the terms block.
pub const ADDON_TERMS_TITLE: &str = "PersonifAI Add-on License Terms";
/// Where an operator registers to obtain an entitlement.
pub const ADDON_REGISTER_URL: &str = "https://noomesh.ai/add-ons";
/// The acceptance log, by meaning, inside the controller state root.
pub const ACCEPTANCES_FILE: &str = "addon-terms-acceptances.jsonl";

/// One consent, as written to the log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Acceptance {
    pub accepted_at: String,
    pub terms_version: String,
    pub terms_url: String,
    pub entitlement_id: String,
    pub entitlement_sub: String,
    pub features: Vec<String>,
    pub os_user: String,
    pub hostname: String,
    pub cli_version: String,
}

/// How the operator answers: typed at a prompt, or by flag with no TTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode<'a> {
    /// A person at a terminal; `typed` is the line they entered.
    Interactive { typed: &'a str },
    /// `--ci` / no TTY / `--json`; `flag` is the `--accept-terms` value.
    NonInteractive { flag: Option<&'a str> },
}

/// Pure decision: did the operator accept `shown` (the version printed)?
/// `Err` carries the refusal message; nothing may be stored on `Err`.
pub fn decide(shown: &str, mode: Mode<'_>) -> Result<(), String> {
    match mode {
        Mode::Interactive { typed } if typed.trim() == "accept" => Ok(()),
        Mode::Interactive { .. } => Err("terms not accepted (type `accept` to accept); nothing was stored".into()),
        Mode::NonInteractive { flag: Some(v) } if v == shown => Ok(()),
        Mode::NonInteractive { flag: Some(v) } => Err(format!(
            "--accept-terms {v} does not match the terms version shown ({shown}); pass --accept-terms {shown} after reading {ADDON_TERMS_URL}; nothing was stored"
        )),
        Mode::NonInteractive { flag: None } => Err(format!(
            "non-interactive install needs --accept-terms {shown} (terms: {ADDON_TERMS_URL}); nothing was stored"
        )),
    }
}

/// The version an install shows and records: what the holder agreed to at
/// issue (the token's), else this build's current one.
pub fn shown_version(token_terms: Option<&str>) -> &str {
    token_terms.filter(|t| !t.is_empty()).unwrap_or(ADDON_TERMS_VERSION)
}

/// The terms block text printed before anything is stored.
pub fn block(token_terms: Option<&str>) -> String {
    let v = shown_version(token_terms);
    let mut s = format!("{ADDON_TERMS_TITLE}\n  version: {v}\n  terms:   {ADDON_TERMS_URL}\n");
    if v != ADDON_TERMS_VERSION {
        s.push_str(&format!(
            "  this token was issued under {v}; the current version, {ADDON_TERMS_VERSION}, is published at the same URL\n"
        ));
    }
    s
}

/// Validate an issue-time `--terms` / `--no-terms` pair. A token is never
/// issued without someone deciding.
#[cfg(any(test, has_entitlement_signer))]
pub fn resolve_issue_terms(terms: Option<String>, no_terms: bool) -> Result<Option<String>, String> {
    match (terms, no_terms) {
        (Some(_), true) => Err("--terms and --no-terms are mutually exclusive".into()),
        (Some(t), false) if t.trim().is_empty() || t.chars().any(char::is_whitespace) => {
            Err("--terms needs a version without spaces, e.g. --terms addon-1.0".into())
        }
        (Some(t), false) => Ok(Some(t)),
        (None, true) => Ok(None),
        (None, false) => Err(format!("issue needs --terms <version> (current: {ADDON_TERMS_VERSION}) or an explicit --no-terms")),
    }
}

/// Where the log lives: the controller state root, the same place the
/// token itself is stored.
pub fn log_path() -> PathBuf {
    crate::envfile::repo_root().join(ACCEPTANCES_FILE)
}

fn os_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// A record for `ent` accepted now under `terms_version`.
pub fn new_acceptance(ent: &crate::entitlement::Entitlement, terms_version: &str) -> Acceptance {
    let accepted_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    Acceptance {
        accepted_at,
        terms_version: terms_version.to_string(),
        terms_url: ADDON_TERMS_URL.to_string(),
        entitlement_id: ent.id.clone(),
        entitlement_sub: ent.sub.clone(),
        features: ent.features.clone(),
        os_user: os_user(),
        hostname: hostname(),
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Append one line. Never truncates; `Err` means consent is NOT recorded.
pub fn append(path: &Path, rec: &Acceptance) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let mut line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)
        .map_err(|e| format!("cannot open {} for append: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(())
}

/// The latest acceptance logged for entitlement `id`, if any. Absent file =
/// None; corrupt lines are skipped.
pub fn latest_for(path: &Path, id: &str) -> Option<Acceptance> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .filter_map(|l| serde_json::from_str::<Acceptance>(l).ok())
        .rfind(|a| a.entitlement_id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn ent() -> crate::entitlement::Entitlement {
        crate::entitlement::Entitlement {
            v: 1, sub: "acme".into(), tier: "intelligent".into(), features: vec!["evolve".into()],
            iat: 1, exp: 0, id: "ent-1".into(), bound: None, max_nodes: None, terms: Some("addon-1.0".into()),
            addons: Default::default(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-terms-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn prompt_accept_only_exact_word() {
        assert!(decide("addon-1.0", Mode::Interactive { typed: "accept\n" }).is_ok());
        assert!(decide("addon-1.0", Mode::Interactive { typed: "yes" }).is_err());
        assert!(decide("addon-1.0", Mode::Interactive { typed: "" }).is_err());
    }

    #[test]
    fn ci_needs_the_exact_version_flag() {
        let no_flag = decide("addon-1.0", Mode::NonInteractive { flag: None }).unwrap_err();
        assert!(no_flag.contains("--accept-terms addon-1.0") && no_flag.contains(ADDON_TERMS_URL));
        let wrong = decide("addon-1.0", Mode::NonInteractive { flag: Some("addon-0.9") }).unwrap_err();
        assert!(wrong.contains("--accept-terms") && wrong.contains(ADDON_TERMS_URL));
        assert!(decide("addon-1.0", Mode::NonInteractive { flag: Some("addon-1.0") }).is_ok());
    }

    #[test]
    fn block_shows_token_version_and_mentions_current_when_different() {
        let same = block(None);
        assert!(same.contains(ADDON_TERMS_TITLE) && same.contains(ADDON_TERMS_VERSION) && same.contains(ADDON_TERMS_URL));
        assert!(!same.contains("issued under"));
        let old = block(Some("addon-0.9"));
        assert!(old.contains("version: addon-0.9") && old.contains("issued under addon-0.9") && old.contains(ADDON_TERMS_VERSION));
        assert_eq!(shown_version(Some("addon-0.9")), "addon-0.9");
        assert_eq!(shown_version(None), ADDON_TERMS_VERSION);
    }

    #[test]
    fn issue_requires_terms_or_no_terms() {
        assert!(resolve_issue_terms(None, false).is_err());
        assert_eq!(resolve_issue_terms(Some("addon-1.0".into()), false).unwrap().as_deref(), Some("addon-1.0"));
        assert_eq!(resolve_issue_terms(None, true).unwrap(), None);
        assert!(resolve_issue_terms(Some("addon-1.0".into()), true).is_err());
        assert!(resolve_issue_terms(Some("a b".into()), false).is_err());
    }

    #[test]
    fn record_has_every_field_and_appends() {
        let d = scratch("append");
        let p = d.join(ACCEPTANCES_FILE);
        let a = new_acceptance(&ent(), "addon-1.0");
        append(&p, &a).unwrap();
        let mut b = new_acceptance(&ent(), "addon-1.0");
        b.entitlement_id = "ent-2".into();
        append(&p, &b).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2, "second write must append, not overwrite");
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        for k in ["accepted_at", "terms_version", "terms_url", "entitlement_id", "entitlement_sub", "features", "os_user", "hostname", "cli_version"] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert!(v["accepted_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(latest_for(&p, "ent-1").unwrap().entitlement_sub, "acme");
        assert_eq!(latest_for(&p, "ent-2").unwrap().entitlement_id, "ent-2");
        assert!(latest_for(&p, "nope").is_none());
        assert!(latest_for(&d.join("absent.jsonl"), "ent-1").is_none());
    }

    #[test]
    fn unwritable_record_refuses() {
        let d = scratch("unwritable");
        // A directory where the file should be: open-for-append fails.
        let p = d.join(ACCEPTANCES_FILE);
        std::fs::create_dir(&p).unwrap();
        assert!(append(&p, &new_acceptance(&ent(), "addon-1.0")).is_err());
    }

    #[test]
    fn docs_url_is_the_const() {
        let docs = include_str!("../../docs/getting-started/add-ons.md");
        assert!(docs.contains(ADDON_TERMS_URL), "add-ons doc must carry {ADDON_TERMS_URL}");
        assert!(docs.contains(ADDON_REGISTER_URL));
        assert!(docs.contains("--accept-terms"));
    }
}
