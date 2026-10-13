// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The operator's client certificate.
//!
//! Posture writes (`POST /api/security/posture[/profile]`) refuse an app
//! login by design. The credential the gateway admits instead is an
//! operator client certificate on the connection PLUS an Admin token bound
//! to it (RFC 8705 `cnf`), minted by `POST /api/security/operator-token`
//! over that same connection. See `gateway-rust/src/operator_auth.rs`.
//!
//! ## The leaf
//!
//! `CN=operator:<account>`, `O=Mesh Cluster Operator`, clientAuth only
//! (`pki::ClusterCa::issue_operator_leaf`), 30 days. Issued on the
//! controller (it needs the CA key), registered with the gateway by the
//! account it names (`POST /api/security/operator-certs/register`).
//!
//! ## Where the key lives
//!
//! In the operator's OWN config directory, beside the login it pairs with:
//! `<config>/mesh[/<instance>]/operator/<account>/operator.{crt,key}` —
//! the directory of `credentials.json` (see [`operator_root`]). Directory
//! 0700, key 0600. NEVER under the PKI dir: on a standalone controller that
//! is `~/.noo/pki`, which the stack's containers bind-mount, and a key there
//! would be readable by whatever shares a uid with them. [`refuse_shared_tree`]
//! enforces it at write time, whatever an override says.

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

pub use crate::pki::OPERATOR_DAYS;

/// A held operator leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPair {
    pub cert_pem: String,
    pub key_pem: String,
}

impl OperatorPair {
    /// `x5t#S256` of the certificate: base64url(SHA-256(DER)), unpadded —
    /// the value the gateway binds tokens to and registers.
    pub fn thumbprint(&self) -> Result<String, String> {
        thumbprint_of_pem(&self.cert_pem)
    }
}

/// `x5t#S256` of the first certificate in `pem`.
pub fn thumbprint_of_pem(pem: &str) -> Result<String, String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("not a PEM certificate: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&parsed.contents)))
}

/// An account name as it may appear in a CN and a path component.
pub fn validate_account(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        && !name.starts_with('.');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "'{name}' is not a usable account name for an operator certificate \
             (letters, digits, . _ - @; at most 64; not starting with '.')"
        ))
    }
}

/// `$NOO_OPERATOR_CERT_DIR`, else `operator/` beside the stored login
/// (`credentials::credentials_path()`'s directory).
pub fn operator_root() -> PathBuf {
    if let Ok(d) = std::env::var("NOO_OPERATOR_CERT_DIR") {
        if !d.trim().is_empty() {
            return PathBuf::from(d);
        }
    }
    root_beside(&crate::credentials::credentials_path())
}

fn root_beside(credentials: &Path) -> PathBuf {
    credentials.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(".")).join("operator")
}

/// `<root>/<account>`.
pub fn dir_for(account: &str) -> PathBuf {
    operator_root().join(account)
}

/// The account posture writes act as: `$NOO_OPERATOR`, else the subject of
/// the stored login.
pub fn current_account() -> Option<String> {
    if let Ok(a) = std::env::var("NOO_OPERATOR") {
        if !a.trim().is_empty() {
            return Some(a.trim().to_string());
        }
    }
    crate::credentials::load().map(|c| c.subject).filter(|s| !s.is_empty())
}

/// Lexically normalise (no symlink resolution needed for the comparison:
/// both sides are canonicalised when they exist).
fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Refuse a directory inside the PKI dir — the tree containers mount.
pub fn refuse_shared_tree(dir: &Path, pki_dir: &Path) -> Result<(), String> {
    let pki = canonical_or_self(pki_dir);
    // The target may not exist yet: canonicalise its deepest existing
    // ancestor and re-append the rest.
    let mut existing = dir.to_path_buf();
    let mut tail = Vec::new();
    while !existing.exists() {
        match (existing.file_name().map(|n| n.to_os_string()), existing.parent()) {
            (Some(n), Some(p)) => {
                tail.push(n);
                existing = p.to_path_buf();
            }
            _ => break,
        }
    }
    let mut resolved = canonical_or_self(&existing);
    for n in tail.into_iter().rev() {
        resolved.push(n);
    }
    if resolved.starts_with(&pki) {
        return Err(format!(
            "refusing to write an operator key under {} — that is the PKI dir the stack's containers \
             mount. Operator keys live in the operator's own config dir (unset NOO_OPERATOR_CERT_DIR)",
            pki.display()
        ));
    }
    Ok(())
}

/// Write the pair: directory 0700, cert 0644, key 0600 from its first byte.
/// Replaces an existing pair (rotation). Refuses the shared PKI tree.
pub fn write_pair(dir: &Path, pair: &OperatorPair, pki_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    refuse_shared_tree(dir, pki_dir)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 {}: {e}", dir.display()))?;
    let crt = dir.join("operator.crt");
    let key = dir.join("operator.key");
    write_atomic(&key, pair.key_pem.as_bytes(), 0o600)?;
    write_atomic(&crt, pair.cert_pem.as_bytes(), 0o644)?;
    Ok((crt, key))
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write as _;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .and_then(|mut f| f.write_all(data).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)))
        .and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", path.display()));
    }
    Ok(())
}

/// The pair held for `account`, if both halves are readable.
pub fn load(account: &str) -> Option<OperatorPair> {
    load_from(&dir_for(account))
}

pub fn load_from(dir: &Path) -> Option<OperatorPair> {
    let cert_pem = std::fs::read_to_string(dir.join("operator.crt")).ok()?;
    let key_pem = std::fs::read_to_string(dir.join("operator.key")).ok()?;
    Some(OperatorPair { cert_pem, key_pem })
}

/// Remove the local pair (after a revoke). Missing files are not an error.
pub fn remove(account: &str) -> Result<(), String> {
    let dir = dir_for(account);
    for f in ["operator.key", "operator.crt"] {
        match std::fs::remove_file(dir.join(f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove {}: {e}", dir.join(f).display())),
        }
    }
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{OPERATOR_CN_PREFIX, OPERATOR_ORG};

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-opcert-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The storage rule, end to end through the real issuer:
    /// the key is 0600 in a 0700 directory BESIDE the login, the PKI dir
    /// (the tree containers mount) gains nothing, and the certificate the
    /// issuer produced names the operator the way the gateway reads it.
    #[test]
    fn issue_client_writes_0600_outside_the_container_mounted_tree() {
        let base = scratch("issue");
        let pki = base.join("pki");
        let ca = crate::pki::ClusterCa::new(pki.clone());
        ca.generate_ca("test CA", 30).unwrap();
        let before: Vec<_> = walk(&pki);

        let (cert_pem, key_pem) = ca.issue_operator_leaf("alice", OPERATOR_DAYS).unwrap();
        let pair = OperatorPair { cert_pem, key_pem };
        let creds = base.join("config/mesh/credentials.json");
        let dir = root_beside(&creds).join("alice");
        let (crt, key) = write_pair(&dir, &pair, &pki).unwrap();

        assert_eq!(mode(&key), 0o600, "the operator key must be 0600");
        assert_eq!(mode(&dir), 0o700, "the operator dir must be 0700");
        assert_eq!(mode(&crt), 0o644);
        assert!(!key.starts_with(&pki), "the key must not be under the PKI dir");
        assert_eq!(walk(&pki), before, "issuing an operator leaf must not touch the PKI dir");

        // What the gateway will read: O + the CN prefix, client auth only.
        let (_, p) = x509_parser::pem::parse_x509_pem(pair.cert_pem.as_bytes()).unwrap();
        let cert = p.parse_x509().unwrap();
        let org: Vec<_> = cert.subject().iter_organization().filter_map(|o| o.as_str().ok()).collect();
        assert_eq!(org, vec![OPERATOR_ORG]);
        let cn = cert.subject().iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "operator:alice");
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth, "an operator leaf must never serve");
        assert_eq!(load_from(&dir).unwrap(), pair);
        assert_eq!(pair.thumbprint().unwrap().len(), 43, "base64url SHA-256, unpadded");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_dir_inside_the_pki_tree_is_refused() {
        let base = scratch("refuse");
        let pki = base.join("pki");
        std::fs::create_dir_all(&pki).unwrap();
        let pair = OperatorPair { cert_pem: "c".into(), key_pem: "k".into() };
        for inside in [pki.join("clients/alice"), pki.join("operator")] {
            let e = write_pair(&inside, &pair, &pki).unwrap_err();
            assert!(e.contains("containers"), "{e}");
            assert!(!inside.join("operator.key").exists());
        }
        // Through a symlink into the tree, too.
        let link = base.join("sneaky");
        std::os::unix::fs::symlink(&pki, &link).unwrap();
        assert!(write_pair(&link.join("alice"), &pair, &pki).is_err());
        assert!(write_pair(&base.join("elsewhere/alice"), &pair, &pki).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn account_names_are_bounded() {
        assert!(validate_account("alice").is_ok());
        assert!(validate_account("ops.admin@example").is_ok());
        for bad in ["", "../x", "a/b", ".hidden", "sp ace", &"x".repeat(65)] {
            assert!(validate_account(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_organization_matches_the_gateway() {
        let gw = include_str!("../../gateway-rust/src/node_identity.rs");
        assert!(gw.contains(&format!("pub const OPERATOR_ORG: &str = \"{OPERATOR_ORG}\";")));
        assert!(gw.contains(&format!("pub const OPERATOR_CN_PREFIX: &str = \"{OPERATOR_CN_PREFIX}\";")));
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p.clone());
                }
                out.push(p);
            }
        }
        out.sort();
        out
    }
}
