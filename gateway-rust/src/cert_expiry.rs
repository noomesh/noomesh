// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! PKI certificate expiry scanning.
//!
//! Port of `pki/ca.py::get_expiring_certs` + `_role_of`. Both cert heartbeat
//! actions (`cert_rotation_check`, `cert_auto_rotate`) needed exactly this and
//! nothing more, which is why they could move to Rust at all.
//!
//! ## Scope: parsing only
//!
//! the design deferred the cert actions because "Rust has `rustls-pemfile`
//! (PEM decode) but no X.509 parser, so it cannot read `notAfter`", and
//! treated them as blocked on a dependency decision. That was right about the
//! gap and pessimistic about the size, because `cert_auto_rotate` no longer
//! rotates in-process — it queues the host watcher, which runs the CLI's
//! `rotate-all` closed loop (backup → rotate → reload → probe → auto-revert).
//!
//! So neither action ever mints or signs a certificate. Reading `notAfter` is
//! the whole requirement, and `x509-cert` covers it. If a future change wants
//! in-process issuance, that is a separate decision about key handling and
//! signing — not an extension of this module.

use std::path::{Path, PathBuf};

use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

/// One certificate found under the PKI directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// Path relative to `pki_dir`, as the Python original reported it.
    pub name: String,
    pub path: String,
    pub role: String,
    /// `YYYY-MM-DD`, matching Python's `strftime("%Y-%m-%d")`.
    pub expires: String,
    /// Whole days until expiry. Negative once expired.
    pub days_left: i64,
}

/// Classify a cert by its location under `pki_dir`.
///
/// Port of `_role_of`. `rotate-all` only touches leaves, so `ca`/`other` are
/// the values callers filter on — getting this wrong would either skip a leaf
/// that needs rotating or nominate the CA for rotation.
pub fn role_of(pki_dir: &Path, cert_path: &Path) -> String {
    let rel = match cert_path.strip_prefix(pki_dir) {
        Ok(r) => r,
        Err(_) => return "other".to_string(),
    };
    match rel.components().next().and_then(|c| c.as_os_str().to_str()) {
        Some("gateway") => "gateway".to_string(),
        Some("nodes") => "node".to_string(),
        Some("services") => "service".to_string(),
        _ => {
            if cert_path.file_name().and_then(|n| n.to_str()) == Some("ca.crt") {
                "ca".to_string()
            } else {
                "other".to_string()
            }
        }
    }
}

/// Read `notAfter` from a PEM (or DER) certificate file, as a Unix timestamp.
///
/// Returns `None` for anything unreadable or unparseable. The Python original
/// swallowed `(ValueError, OSError)` and skipped the file; a single malformed
/// cert must not abort the scan and hide every other expiry.
pub fn read_not_after(path: &Path) -> Option<i64> {
    let bytes = std::fs::read(path).ok()?;
    // Accept DER too: `.crt` is used for both encodings in the wild, and a
    // DER file that silently scanned as "no certs found" would under-report
    // expiries — failing quiet in exactly the wrong direction.
    let cert = Certificate::from_pem(&bytes)
        .or_else(|_| Certificate::from_der(&bytes))
        .ok()?;
    Some(cert.tbs_certificate().validity().not_after.to_unix_duration().as_secs() as i64)
}

/// Recursively collect `*.crt` under `dir`, sorted — mirroring
/// `sorted(self.pki_dir.rglob("*.crt"))` so report ordering is stable.
pub fn find_certs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(dir, &mut out);
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("crt") {
            out.push(path);
        }
    }
}

/// Days from `now` until `expires`, truncated toward zero.
///
/// Python computed `(expires - now).days`, which floors — for a future
/// instant that is the same as truncation, and expiry windows are always
/// forward-looking. Split out so the arithmetic is testable without files.
pub fn days_between(now_unix: i64, expires_unix: i64) -> i64 {
    (expires_unix - now_unix).div_euclid(86_400)
}

/// Format a Unix timestamp as `YYYY-MM-DD`.
pub fn format_date(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// All certs under `pki_dir` expiring within `warn_days`.
///
/// Port of `get_expiring_certs`, including its `days_left <= warn_days`
/// comparison — note that already-expired certs (negative `days_left`) are
/// included, which is intended: they are the most urgent, not the least.
pub fn expiring_certs(pki_dir: &Path, warn_days: i64, now_unix: i64) -> Vec<CertInfo> {
    let mut out = Vec::new();
    for path in find_certs(pki_dir) {
        let Some(not_after) = read_not_after(&path) else { continue };
        let days_left = days_between(now_unix, not_after);
        if days_left <= warn_days {
            out.push(CertInfo {
                name: path
                    .strip_prefix(pki_dir)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                path: path.display().to_string(),
                role: role_of(pki_dir, &path),
                expires: format_date(not_after),
                days_left,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn pki() -> PathBuf {
        PathBuf::from("/pki")
    }

    #[test]
    fn role_matches_python_layout() {
        assert_eq!(role_of(&pki(), Path::new("/pki/gateway/server.crt")), "gateway");
        assert_eq!(role_of(&pki(), Path::new("/pki/nodes/host9.crt")), "node");
        assert_eq!(role_of(&pki(), Path::new("/pki/services/tei.crt")), "service");
        assert_eq!(role_of(&pki(), Path::new("/pki/ca.crt")), "ca");
        assert_eq!(role_of(&pki(), Path::new("/pki/stray.crt")), "other");
    }

    // rotate-all only touches leaves. If the CA were ever classified as a
    // leaf, an auto-rotate would try to rotate the trust root.
    #[test]
    fn ca_is_never_a_leaf_role() {
        for p in ["/pki/ca.crt", "/pki/nested/ca.crt"] {
            let role = role_of(&pki(), Path::new(p));
            assert!(
                role == "ca" || role == "other",
                "{p} classified as rotatable leaf role {role}"
            );
        }
    }

    #[test]
    fn path_outside_pki_dir_is_other() {
        assert_eq!(role_of(&pki(), Path::new("/elsewhere/x.crt")), "other");
    }

    #[test]
    fn day_arithmetic() {
        let now = 1_754_000_000;
        assert_eq!(days_between(now, now + 86_400 * 30), 30);
        assert_eq!(days_between(now, now), 0);
        // Partial days truncate down, as Python's timedelta.days does.
        assert_eq!(days_between(now, now + 86_400 * 5 + 3600), 5);
    }

    // Already-expired certs must surface, not be filtered out as "not within
    // the warning window".
    #[test]
    fn expired_certs_have_negative_days_and_still_warn() {
        let now = 1_754_000_000;
        let days = days_between(now, now - 86_400 * 3);
        assert_eq!(days, -3);
        assert!(days <= 30, "an expired cert must fall inside the warn window");
    }

    #[test]
    fn unreadable_file_is_skipped_not_fatal() {
        assert_eq!(read_not_after(Path::new("/nonexistent/nope.crt")), None);
    }

    #[test]
    fn garbage_file_is_skipped_not_fatal() {
        let dir = std::env::temp_dir().join("noo-cert-test-garbage");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("bad.crt");
        std::fs::write(&p, b"not a certificate").unwrap();
        assert_eq!(read_not_after(&p), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A malformed cert sitting in the directory must not hide the others.
    #[test]
    fn scan_continues_past_a_bad_cert() {
        let dir = std::env::temp_dir().join("noo-cert-test-scan");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("gateway")).unwrap();
        std::fs::write(dir.join("gateway/bad.crt"), b"garbage").unwrap();
        std::fs::write(dir.join("gateway/also-bad.crt"), b"garbage").unwrap();
        // Non-.crt files are ignored entirely.
        std::fs::write(dir.join("gateway/key.pem"), b"garbage").unwrap();

        let found = find_certs(&dir);
        assert_eq!(found.len(), 2, "only .crt files are scanned");
        // Unparseable ones drop out rather than aborting the scan.
        assert!(expiring_certs(&dir, 30, 1_754_000_000).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_date_is_iso() {
        // 2026-08-01T00:00:00Z
        assert_eq!(format_date(1_785_542_400), "2026-08-01");
    }
}

/// Cross-check against a real PKI tree, comparing this port's output to the
/// Python original's.
///
/// `#[ignore]`d because CI has no certificates — synthetic fixtures cannot
/// prove the DER/PEM decode agrees with `cryptography` on real material, and
/// this port's whole risk is a subtle disagreement about `notAfter`. Run it
/// against a live PKI when touching this module:
///
/// ```text
/// NOO_VERIFY_PKI_DIR=/path/to/pki cargo test --release verify_against_real_pki -- --ignored --nocapture
/// ```
///
/// Then diff the output against:
///
/// ```text
/// python3 -c "from noomesh.pki.ca import ClusterCA; \
///   [print(f\"{c['name']}|{c['role']}|{c['expires']}|{c['days_left']}\") \
///    for c in ClusterCA(pki_dir='...').get_expiring_certs(warn_days=99999)]"
/// ```
#[cfg(test)]
#[test]
#[ignore]
fn verify_against_real_pki() {
    let Ok(dir) = std::env::var("NOO_VERIFY_PKI_DIR") else {
        panic!("set NOO_VERIFY_PKI_DIR to a real PKI directory");
    };
    let now = chrono::Utc::now().timestamp();
    let certs = expiring_certs(std::path::Path::new(&dir), 99_999, now);
    assert!(!certs.is_empty(), "no certificates parsed from {dir}");
    for c in &certs {
        println!("{}|{}|{}|{}", c.name, c.role, c.expires, c.days_left);
    }
}
