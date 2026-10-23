// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Where the SOPS age key is — ONE answer for every reader in the CLI (i10a).
//!
//! The key used to be wherever `~/.config/sops/age/keys.txt` said, spelled out
//! at each call site. Sealing it to the TPM (`sudo noo-hostd at-rest
//! seal-age-key`, PR-B) adds a second home: the root unit `noo-unseal.service`
//! decrypts it at boot into RAM at `/run/noo/keys/age.txt`, recorded in the
//! manifest `/etc/noo/at-rest.json` (no secrets in it). After `noo security
//! at-rest finalize` the default path is a symlink to that file and `.env`
//! names it in `SOPS_AGE_KEY_FILE`.
//!
//! [`path`] precedence:
//!   1. `SOPS_AGE_KEY_FILE` when set (sops itself honours it first too);
//!   2. the sealed runtime path when the manifest says sealed — and it is
//!      there, or the default is not (between `seal` and the first unseal the
//!      plaintext still serves; with neither present the runtime path is the
//!      one an error should name);
//!   3. `~/.config/sops/age/keys.txt`.
//! Writers that RESTORE a key (onboard `--from-archive`) use [`default_path`]:
//! the runtime file belongs to the unit, never to a restore.
//!
//! `NOO_AT_REST_MANIFEST` relocates the manifest (tests; the same variable
//! scripts/lib-secrets.sh and scripts/backup-controller.sh read).

use std::path::{Path, PathBuf};

/// The at-rest manifest hostd writes.
pub const MANIFEST_PATH: &str = "/etc/noo/at-rest.json";
/// Where noo-unseal.service puts the unsealed key (tmpfs).
pub const SEALED_RUNTIME_PATH: &str = "/run/noo/keys/age.txt";
/// The sealed credential (root 0600 in a root 0700 dir).
pub const SEALED_CRED_PATH: &str = "/var/lib/noo/sealed/age-key.cred";
/// The boot unit that unseals it.
pub const UNSEAL_UNIT: &str = "noo-unseal.service";
/// The EFI variable that says whether Secure Boot is on.
pub const SECURE_BOOT_VAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// What `/etc/noo/at-rest.json` records about the age key. Missing fields
/// read as empty/false; the manifest is hostd's, this only reads it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub sealed: bool,
    pub cred: String,
    pub runtime: String,
    pub public_key: String,
    /// "7" or "none".
    pub pcrs: String,
    pub secure_boot_at_seal: bool,
    pub secure_boot_known: bool,
    pub sealed_at: String,
    pub sealed_unix: Option<i64>,
    pub operator: String,
}

fn or_default(v: String, d: &str) -> String {
    if v.trim().is_empty() {
        d.to_string()
    } else {
        v
    }
}

impl Manifest {
    /// Parse the manifest text; `None` when it is not a JSON object.
    pub fn parse(text: &str) -> Option<Manifest> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        if !v.is_object() {
            return None;
        }
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let b = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
        Some(Manifest {
            sealed: b("age_key_sealed"),
            cred: or_default(s("age_key_cred"), SEALED_CRED_PATH),
            runtime: or_default(s("age_key_runtime"), SEALED_RUNTIME_PATH),
            public_key: s("age_key_public"),
            pcrs: s("age_key_pcrs"),
            secure_boot_at_seal: b("secure_boot_at_seal"),
            secure_boot_known: b("secure_boot_known"),
            sealed_at: s("age_key_sealed_at"),
            sealed_unix: v.get("age_key_sealed_unix").and_then(|x| x.as_i64()),
            operator: s("operator"),
        })
    }
}

/// `$NOO_AT_REST_MANIFEST`, else [`MANIFEST_PATH`].
pub fn manifest_path() -> PathBuf {
    std::env::var("NOO_AT_REST_MANIFEST")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(MANIFEST_PATH))
}

/// The manifest on this host, if any (unreadable or unparsable reads as none).
pub fn read_manifest() -> Option<Manifest> {
    std::fs::read_to_string(manifest_path()).ok().and_then(|t| Manifest::parse(&t))
}

/// The manifest when it says the age key is sealed.
pub fn sealed_manifest() -> Option<Manifest> {
    read_manifest().filter(|m| m.sealed)
}

/// `~/.config/sops/age/keys.txt` — the plaintext home, and the one a restore
/// writes to.
pub fn default_path() -> PathBuf {
    default_path_in(&std::env::var("HOME").unwrap_or_default())
}

fn default_path_in(home: &str) -> PathBuf {
    PathBuf::from(home).join(".config/sops/age/keys.txt")
}

/// [`path`] with every input injected (tests).
pub(crate) fn resolve(
    env: &dyn Fn(&str) -> Option<String>,
    manifest: Option<&Manifest>,
    exists: &dyn Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(f) = env("SOPS_AGE_KEY_FILE").map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
        return PathBuf::from(f);
    }
    let default = default_path_in(&env("HOME").unwrap_or_default());
    if let Some(m) = manifest {
        if m.sealed {
            let runtime = PathBuf::from(&m.runtime);
            if exists(&runtime) || !exists(&default) {
                return runtime;
            }
        }
    }
    default
}

/// The age key file every reader should use (see the module docs).
pub fn path() -> PathBuf {
    let m = read_manifest();
    resolve(&|k| std::env::var(k).ok(), m.as_ref(), &|p| p.is_file())
}

/// The `# public key: age1…` comment age-keygen writes, if present. Public.
pub fn public_key_of(key: &[u8]) -> Option<String> {
    String::from_utf8_lossy(key).lines().find_map(|l| {
        l.trim().strip_prefix("# public key:").map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    })
}

/// sha256 of key bytes, hex — compared, never printed whole.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    hex::encode(&d[..])
}

/// Secure Boot from the EFI variable's bytes: 4 attribute bytes then the
/// value. `None` when it cannot be read (legacy boot, no efivarfs).
pub fn secure_boot_from(bytes: Option<&[u8]>) -> Option<bool> {
    let b = bytes?;
    if b.len() < 5 {
        return None;
    }
    Some(b[4] == 1)
}

/// Secure Boot on this host now.
pub fn secure_boot_now() -> Option<bool> {
    let b = std::fs::read(SECURE_BOOT_VAR).ok();
    secure_boot_from(b.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    fn sealed() -> Manifest {
        Manifest::parse(r#"{"age_key_sealed": true, "age_key_runtime": "/run/noo/keys/age.txt"}"#).unwrap()
    }

    #[test]
    fn sops_age_key_file_wins_over_everything() {
        let env = env_of(&[("SOPS_AGE_KEY_FILE", "/etc/x/age.txt"), ("HOME", "/home/a")]);
        let m = sealed();
        assert_eq!(resolve(&env, Some(&m), &|_| true), PathBuf::from("/etc/x/age.txt"));
        assert_eq!(resolve(&env, None, &|_| false), PathBuf::from("/etc/x/age.txt"));
    }

    #[test]
    fn a_blank_sops_age_key_file_is_unset() {
        let env = env_of(&[("SOPS_AGE_KEY_FILE", "  "), ("HOME", "/home/a")]);
        assert_eq!(resolve(&env, None, &|_| true), PathBuf::from("/home/a/.config/sops/age/keys.txt"));
    }

    #[test]
    fn sealed_and_unsealed_means_the_runtime_path() {
        let env = env_of(&[("HOME", "/home/a")]);
        let m = sealed();
        // Unsealed this boot: the RAM copy, even while the plaintext remains.
        assert_eq!(resolve(&env, Some(&m), &|_| true), PathBuf::from("/run/noo/keys/age.txt"));
        // Neither present: the runtime path is the one an error must name.
        assert_eq!(resolve(&env, Some(&m), &|_| false), PathBuf::from("/run/noo/keys/age.txt"));
    }

    #[test]
    fn sealed_but_not_yet_unsealed_keeps_the_plaintext_serving() {
        let env = env_of(&[("HOME", "/home/a")]);
        let m = sealed();
        let only_default = |p: &Path| p == Path::new("/home/a/.config/sops/age/keys.txt");
        assert_eq!(resolve(&env, Some(&m), &only_default), PathBuf::from("/home/a/.config/sops/age/keys.txt"));
    }

    #[test]
    fn not_sealed_or_no_manifest_is_the_default() {
        let env = env_of(&[("HOME", "/home/a")]);
        let mut m = sealed();
        m.sealed = false;
        assert_eq!(resolve(&env, Some(&m), &|_| true), PathBuf::from("/home/a/.config/sops/age/keys.txt"));
        assert_eq!(resolve(&env, None, &|_| true), PathBuf::from("/home/a/.config/sops/age/keys.txt"));
    }

    #[test]
    fn manifest_parse_reads_hostds_fields_and_defaults_the_paths() {
        let m = Manifest::parse(
            r#"{"version":1,"age_key_sealed":true,"age_key_pcrs":"7","secure_boot_at_seal":true,
                "secure_boot_known":true,"age_key_sealed_unix":1800000000,"operator":"op",
                "age_key_public":"age1xyz","volume_encrypted":true}"#,
        )
        .unwrap();
        assert!(m.sealed && m.secure_boot_at_seal && m.secure_boot_known);
        assert_eq!((m.pcrs.as_str(), m.sealed_unix, m.operator.as_str()), ("7", Some(1_800_000_000), "op"));
        assert_eq!(m.runtime, SEALED_RUNTIME_PATH);
        assert_eq!(m.cred, SEALED_CRED_PATH);
        assert!(Manifest::parse("[1,2]").is_none());
        assert!(Manifest::parse("{not json").is_none());
    }

    #[test]
    fn public_key_and_secure_boot_parse() {
        assert_eq!(public_key_of(b"# created: x\n# public key: age1abc\nAGE-...\n").as_deref(), Some("age1abc"));
        assert_eq!(public_key_of(b"no comment\n"), None);
        assert_eq!(secure_boot_from(Some(&[6u8, 0, 0, 0, 1][..])), Some(true));
        assert_eq!(secure_boot_from(Some(&[6u8, 0, 0, 0, 0][..])), Some(false));
        assert_eq!(secure_boot_from(Some(&[6u8, 0][..])), None);
        assert_eq!(secure_boot_from(None), None);
    }
}
