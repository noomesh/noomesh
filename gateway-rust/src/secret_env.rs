// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! One reader for every secret: env, `NOO_SECRET_` env, or a FILE.
//!
//! Phase 2 of the file-backed-secrets plan (the design carries the
//! add-on side). Compose still delivers every secret as an environment
//! variable today; this module is what lets a later compose change hand
//! the same container `/run/secrets/<name>` instead, with no reader
//! changing again. Every call site that used to `std::env::var("NAME")`
//! for a name in [`FILE_BACKED_SECRETS`] goes through [`secret`] now, so
//! the precedence has ONE home in this crate — the Python package has the
//! same rule in `noomesh.secret_env` and `tests/test_file_reader_parity.py`
//! keeps the two manifests agreeing.
//!
//! Resolution, for `secret("NAME")`:
//!
//!   1. `NAME_FILE` set and non-empty → read the file, strip exactly one
//!      trailing `\n` (or `\r\n`). Unreadable or empty → `Err` naming the
//!      path. A named file that cannot be read is a broken install, not
//!      "unset": falling through to the env would make a mis-mounted secret
//!      look like a missing one, and the operator would go looking in the
//!      wrong place.
//!   2. `NOO_SECRET_NAME` non-empty → that (the SecretsManager convention
//!      that predates this module; see `docs/reference/env.md`).
//!   3. `NAME` non-empty → that.
//!   4. `Ok(None)` — the call site keeps its own "unset" behaviour.
//!
//! Both `NAME` and `NAME_FILE` non-empty is a compose/launcher skew, not a
//! choice: preflight refuses to start on it ([`both_set_conflicts`]). The
//! per-call reader still answers (`_FILE` wins) so the refusal is reported
//! once, by the check that owns it, rather than as N unrelated errors.
//!
//! Why a file at all: a PEM cannot live on a dotenv line (`jwks.rs` grew
//! three encodings to work around that), `docker inspect` prints every env
//! value to the docker group, and a file under `/run/secrets` is 0400 to
//! one uid and invisible to `inspect`.

use std::fmt;
use std::path::Path;

/// Every name this crate reads through [`secret`]. The parity guard
/// (`tests/test_file_reader_parity.py`) checks that each is delivered to
/// the gateway by compose today (or is on its "file later" allowlist),
/// that the Python manifest agrees on the shared names, and — the direction
/// that matters — that no secret-shaped variable reaches the gateway
/// without being here. Add a reader, add the name.
pub const FILE_BACKED_SECRETS: &[&str] = &[
    "NOO_JWT_SECRET",
    "NOO_CLUSTER_SECRET",
    "NOO_CONTROLLER_SECRET",
    // The bus-principal keys, one per audience
    // `bus_principal::AUDIENCES`. The gateway signs with all three.
    "NOO_BUS_KEY_WORKER",
    "NOO_BUS_KEY_TRELLION",
    "NOO_BUS_KEY_TRELLION_INTEL",
    // The browser container's door key: the gateway signs its
    // browser-route calls with it and hands it to node-started browsers.
    "NOO_BROWSER_KEY",
    "NOO_NODE_AGENT_TOKEN",
    "NOO_ADMIN_PASSWORD",
    "NOO_AUDIT_HMAC_KEY",
    "REDIS_PASSWORD",
    "NOO_TAILSCALE_OAUTH_CLIENT_SECRET",
    "NOO_TAILSCALE_API_KEY",
    "NOO_AGENT_REVIEW_KEY",
    "NOO_INTEGRATIONS_KEY",
    "NOO_GOOGLE_OAUTH_CLIENT_SECRET",
    "NOO_AGENT_SIGNING_KEY",
    "NOO_JWT_SIGNING_KEY",
    "NOO_ENTITLEMENT",
    "NOO_APP_DB_PASSWORD",
    "NOO_EVOLVE_DB_PASSWORD",
    "NOO_EVOLVE_DDL_PASSWORD",
    "NOO_TRELLION_DB_PASSWORD",
    "NOO_TRELLION_DDL_PASSWORD",
    // Every declared system's enable flag and role passwords that no named
    // line above delivers, as ONE `KEY=VALUE` file the launcher writes
    // (system_provision.rs `SYSTEMS_SECRETS`). A new system needs no entry here.
    "NOO_SYSTEMS_SECRETS",
    "NATS_GATEWAY_PASSWORD",
    // The node's own bus password. Never delivered to the gateway container:
    // the node-hosted harness (`noo-gateway harness`, harness_main.rs) reads
    // it from /etc/noo-harness.env, where the applier turns it into a
    // `_FILE` pointer.
    "NATS_NODE_PASSWORD",
    // Tier-2: provider and channel credentials. Issued
    // and rotated by a third party rather than minted by the stack, but a
    // value in Config.Env is just as readable to the docker group — so they
    // arrive as files too, and every reader goes through [`secret`].
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "TAVILY_API_KEY",
    "BRAVE_SEARCH_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "WHATSAPP_TOKEN",
    "GOOGLE_CHAT_BEARER_TOKEN",
    "GOOGLE_CHAT_CREDENTIALS_JSON",
];

/// The env-prefix convention that sits between `_FILE` and the plain name.
pub const PREFIX: &str = "NOO_SECRET_";

/// Suffix that turns a secret's name into the variable naming its file.
pub const FILE_SUFFIX: &str = "_FILE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// `NAME_FILE` names a path that could not be read.
    Unreadable { name: String, path: String, reason: String },
    /// `NAME_FILE` names a file whose content is empty after stripping.
    Empty { name: String, path: String },
}

impl SecretError {
    pub fn name(&self) -> &str {
        match self {
            SecretError::Unreadable { name, .. } | SecretError::Empty { name, .. } => name,
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Unreadable { name, path, reason } => write!(
                f,
                "{name}{FILE_SUFFIX} names {path}, which cannot be read ({reason}); \
                 a named secret file must exist and be readable by this process"
            ),
            SecretError::Empty { name, path } => write!(
                f,
                "{name}{FILE_SUFFIX} names {path}, which is empty; \
                 an empty secret file is a broken mount, not an unset secret"
            ),
        }
    }
}

impl std::error::Error for SecretError {}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

/// Strip exactly one trailing newline — `\r\n` or `\n` — the one an editor
/// or `echo` adds. A second newline, or trailing spaces, are the value's own:
/// a secret is bytes, and a reader that trims freely would silently accept
/// a value the writer did not mean.
pub fn strip_one_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// Read `path` as `name`'s secret file. `Err` when unreadable or empty.
pub fn read_secret_file(name: &str, path: &str) -> Result<String, SecretError> {
    let raw = std::fs::read_to_string(Path::new(path)).map_err(|e| SecretError::Unreadable {
        name: name.to_string(),
        path: path.to_string(),
        reason: e.to_string(),
    })?;
    let value = strip_one_newline(&raw);
    if value.is_empty() {
        return Err(SecretError::Empty { name: name.to_string(), path: path.to_string() });
    }
    Ok(value.to_string())
}

/// [`secret`] over an arbitrary lookup, so the precedence is testable
/// without touching the process environment (and so `nats_credentials::
/// resolve` can take it as its closure).
pub fn secret_from(name: &str, get: impl Fn(&str) -> Option<String>) -> Result<Option<String>, SecretError> {
    if let Some(path) = non_empty(get(&format!("{name}{FILE_SUFFIX}"))) {
        return read_secret_file(name, &path).map(Some);
    }
    if let Some(v) = non_empty(get(&format!("{PREFIX}{name}"))) {
        return Ok(Some(v));
    }
    Ok(non_empty(get(name)))
}

/// The secret called `name`, from the process environment. See the module
/// docs for the order. `Ok(None)` means nothing is configured.
pub fn secret(name: &str) -> Result<Option<String>, SecretError> {
    secret_from(name, |k| std::env::var(k).ok())
}

/// [`secret`] for call sites whose contract is `Option<String>`: an
/// unreadable or empty file is logged at ERROR and answered as "unset". It
/// is not swallowed — preflight ([`file_errors`]) reports the same failure
/// as a critical check and the gateway refuses to start on it. This shape
/// exists so a call site that runs before preflight (the Redis connect, the
/// NATS credential) does not have to grow its own error plumbing.
pub fn secret_opt(name: &str) -> Option<String> {
    match secret(name) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(secret = name, error = %e, "secret_env.file_unreadable");
            None
        }
    }
}

/// [`secret_opt`], empty string when unset. For the sites that used
/// `std::env::var(..).unwrap_or_default()`.
pub fn secret_or_empty(name: &str) -> String {
    secret_opt(name).unwrap_or_default()
}

/// [`secret`] for call sites that need the value or a one-line reason to
/// return: the file error (naming the path), or "`NAME` not set" — the
/// wording the channel senders used before they read through this module.
pub fn secret_required(name: &str) -> Result<String, String> {
    match secret(name) {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(format!("{name} not set")),
        Err(e) => Err(e.to_string()),
    }
}

/// Names in `manifest` where BOTH `NAME` and `NAME_FILE` are non-empty —
/// the compose/launcher skew preflight refuses on. Pure over `get`.
pub fn both_set_conflicts_from(manifest: &[&str], get: impl Fn(&str) -> Option<String>) -> Vec<String> {
    manifest
        .iter()
        .filter(|n| {
            non_empty(get(n)).is_some() && non_empty(get(&format!("{n}{FILE_SUFFIX}"))).is_some()
        })
        .map(|n| n.to_string())
        .collect()
}

/// [`both_set_conflicts_from`] over the process environment and the crate
/// manifest.
pub fn both_set_conflicts() -> Vec<String> {
    both_set_conflicts_from(FILE_BACKED_SECRETS, |k| std::env::var(k).ok())
}

/// Every manifest name whose `_FILE` is set but unreadable or empty — the
/// boot-time version of the per-call `Err`, so the operator reads ONE
/// preflight line naming the path instead of a scatter of downstream
/// failures.
pub fn file_errors() -> Vec<SecretError> {
    FILE_BACKED_SECRETS
        .iter()
        .filter_map(|n| secret(n).err())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    /// A file under the OS temp dir, removed on drop (no `tempfile` crate
    /// in this tree — same shape `local_files.rs` tests use).
    struct TmpFile(std::path::PathBuf);

    impl TmpFile {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn tmpfile(content: &[u8]) -> TmpFile {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "secret_env_test_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content).unwrap();
        TmpFile(path)
    }

    #[test]
    fn trailing_newline_is_stripped_exactly_once() {
        let f = tmpfile(b"s3cret\n\n");
        let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
        assert_eq!(got.as_deref(), Some("s3cret\n"));
        let f = tmpfile(b"s3cret\n");
        let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
        assert_eq!(got.as_deref(), Some("s3cret"));
        let f = tmpfile(b"s3cret");
        let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
        assert_eq!(got.as_deref(), Some("s3cret"));
    }

    #[test]
    fn crlf_counts_as_one_newline() {
        let f = tmpfile(b"s3cret\r\n");
        let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
        assert_eq!(got.as_deref(), Some("s3cret"));
    }

    /// The same byte vectors `tests/test_secret_env.py::BYTE_VECTORS` feeds the
    /// Python reader, which parses THIS body and compares — change one side,
    /// change both. One file must answer the same in both runtimes: only one
    /// trailing `\n` / `\r\n` is trimmed, and a `\r` anywhere else is the
    /// value's own.
    #[test]
    fn byte_vectors_match_the_python_reader() {
        let vectors: [(&[u8], &str); 6] = [
            (b"a\rb\r", "a\rb\r"),
            (b"abc\r\n\r\n", "abc\r\n"),
            (b"x\n", "x"),
            (b"x\r\n", "x"),
            (b"abc\r", "abc\r"),
            (b"a\r\nb\n", "a\r\nb"),
        ];
        for (raw, want) in vectors {
            let f = tmpfile(raw);
            let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
            assert_eq!(got.as_deref(), Some(want), "raw {raw:?}");
        }
    }

    #[test]
    fn a_multi_line_pem_survives_intact() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"; // leak-ok: four-letter placeholder, not key material
        let f = tmpfile(pem.as_bytes());
        let got = secret_from("X", env(&[("X_FILE", f.path().to_str().unwrap())])).unwrap();
        assert_eq!(got.as_deref(), Some(&pem[..pem.len() - 1]));
    }

    #[test]
    fn unreadable_file_is_an_error_naming_the_path() {
        let path = "/nonexistent/secret-env-test/definitely-missing";
        let err = secret_from("X", env(&[("X_FILE", path), ("X", "plain")])).unwrap_err();
        assert!(matches!(err, SecretError::Unreadable { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains(path), "{msg}");
        assert!(msg.contains("X_FILE"), "{msg}");
        // and it did NOT fall through to the plain value
    }

    #[test]
    fn empty_file_is_an_error_not_unset() {
        let f = tmpfile(b"\n");
        let path = f.path().to_str().unwrap();
        let err = secret_from("X", env(&[("X_FILE", path), ("X", "plain")])).unwrap_err();
        assert!(matches!(err, SecretError::Empty { .. }), "{err:?}");
        assert!(err.to_string().contains(path));
    }

    #[test]
    fn precedence_is_file_then_prefix_then_plain() {
        let f = tmpfile(b"from-file\n");
        let path = f.path().to_str().unwrap();
        let all = [("X_FILE", path), ("NOO_SECRET_X", "from-prefix"), ("X", "from-plain")];
        assert_eq!(secret_from("X", env(&all)).unwrap().as_deref(), Some("from-file"));
        assert_eq!(
            secret_from("X", env(&all[1..])).unwrap().as_deref(),
            Some("from-prefix")
        );
        assert_eq!(secret_from("X", env(&all[2..])).unwrap().as_deref(), Some("from-plain"));
        assert_eq!(secret_from("X", env(&[])).unwrap(), None);
    }

    #[test]
    fn empty_values_count_as_unset_at_every_tier() {
        // An empty `_FILE` does not try to open "" — it falls through.
        let got = secret_from("X", env(&[("X_FILE", ""), ("NOO_SECRET_X", ""), ("X", "plain")]));
        assert_eq!(got.unwrap().as_deref(), Some("plain"));
        assert_eq!(secret_from("X", env(&[("X", "")])).unwrap(), None);
    }

    #[test]
    fn both_set_is_a_conflict_only_when_both_are_non_empty() {
        let names = ["A", "B", "C"];
        let got = both_set_conflicts_from(
            &names,
            env(&[("A", "x"), ("A_FILE", "/p"), ("B", "x"), ("B_FILE", ""), ("C_FILE", "/p")]),
        );
        assert_eq!(got, vec!["A".to_string()]);
        // Never mind whether the file exists: the skew is the two names.
        assert!(both_set_conflicts_from(&names, env(&[])).is_empty());
    }

    #[test]
    fn manifest_names_are_unique_upper_snake_and_not_file_vars() {
        let mut seen = std::collections::HashSet::new();
        for n in FILE_BACKED_SECRETS {
            assert!(seen.insert(*n), "duplicate {n}");
            assert!(n.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'), "{n}");
            assert!(!n.ends_with(FILE_SUFFIX), "{n} is a _FILE variable, not a secret name");
            assert!(!n.starts_with(PREFIX), "{n} carries the prefix; list the bare name");
        }
    }
}
