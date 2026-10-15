// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security` LOCAL surface (no gateway) — WP-B1 port of
//! `noomesh/security_cli.py` + `noomesh/onboard/ca_trust.py`:
//!
//!   - `generate-secret [TYPE] [--length N]` — token_urlsafe / Fernet key.
//!   - `scan` — env/config posture checks (same check list, wording and
//!     severities as the Python scan).
//!   - `pki rotate-all` — the former deliberate Python holdout: rotate every
//!     expiring leaf cert (crate::pki), restart the running consumer
//!     containers (gateway last), health-probe, and AUTO-REVERT from the
//!     backup + restart again if consumers come up unhealthy.
//!   - `trust-ca` / `untrust-ca` — OS trust-store install/remove with native
//!     elevation (WSL2 `certutil.exe` via PowerShell RunAs, Linux
//!     pkexec/sudo + `update-ca-certificates`, macOS `security
//!     add-trusted-cert` via osascript). Command construction is pure and
//!     unit-tested; only the thin runners actually execute anything.
//!
//! Python-parity notes:
//!   - `scan` checks the REPO `.env` (envfile::repo_root()) rather than the
//!     cwd `.env` Python uses — the vars being scanned were loaded from the
//!     repo `.env` by `ensure_repo_env`, so that is the file whose
//!     permissions matter. Everything else matches check-for-check.
//!   - `rotate-all` keeps Python's `--force` flag and adds `--yes/-y` as the
//!     repo-wide agent-first confirm alias (see `commands::confirm_destructive`).
//!   - ca_trust.py's macOS elevation calls `shutil.quote`, which does not
//!     exist (it's `shlex.quote`) — the Python macOS path crashes before
//!     running anything. The Rust port quotes properly (POSIX single-quote
//!     escaping); macOS remains untested in CI.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::ui::{self, Col, Glyph};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::output::{fail, ExitCode};
use crate::pki::{pki_dir, ClusterCa, RotateResult};
use crate::{Globals, Unhandled};

// ─────────────────────────────────────────────────────────────────────────
// noo security generate-secret
// ─────────────────────────────────────────────────────────────────────────

/// `noo security generate-secret [TYPE] [--length N]` — TYPE in
/// {general, jwt, cluster, fernet}, default "general". Non-fernet types all
/// print `secrets.token_urlsafe(length)` (length = bytes of entropy,
/// default 32 → 43 chars); `fernet` prints `Fernet.generate_key()` — 32
/// urandom bytes as PADDED urlsafe base64 (44 chars ending `=`).
pub fn security_generate_secret(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut secret_type: Option<String> = None;
    let mut length: Option<usize> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--length" => {
                length = Some(
                    iter.next()
                        .and_then(|v| v.parse::<usize>().ok())
                        .filter(|n| *n > 0 && *n <= 4096)
                        .ok_or(Unhandled)?,
                );
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if secret_type.is_some() {
                    return Err(Unhandled); // at most one positional
                }
                secret_type = Some(t.to_string());
            }
        }
    }
    let secret_type = secret_type.unwrap_or_else(|| "general".to_string());
    if let Some((kind, msg)) = secret_args_problem(&secret_type, length) {
        fail(
            g.json,
            ExitCode::Usage,
            kind,
            &msg,
            Some("noo security generate-secret [general|fernet] [--length <bytes>]"),
        );
    }
    let secret = if secret_type == "fernet" {
        fernet_key()
    } else {
        token_urlsafe(length.unwrap_or(32))
    };
    if g.json {
        println!(
            "{}",
            serde_json::json!({ "type": secret_type, "secret": secret })
        );
    } else {
        ui::value(&secret);
    }
    Ok(0)
}

/// `jwt` and `cluster` print exactly what `general` prints (a URL-safe
/// token); they are kept as names so existing scripts keep working. Only
/// `fernet` differs.
const SECRET_TYPES: &[&str] = &["general", "jwt", "cluster", "fernet"];

/// What is wrong with the arguments, as (error kind, message). A type that
/// is not one of ours used to fall through to `general`, so a typo
/// ("fernat") printed a secret of the WRONG shape without a word; and a
/// `--length` given with `fernet` (always 32 bytes) was ignored.
pub(crate) fn secret_args_problem(secret_type: &str, length: Option<usize>) -> Option<(&'static str, String)> {
    if !SECRET_TYPES.contains(&secret_type) {
        return Some((
            "unknown_secret_type",
            format!("unknown secret type '{secret_type}' (want one of: {})", SECRET_TYPES.join(", ")),
        ));
    }
    if secret_type == "fernet" && length.is_some() {
        return Some(("length_not_applicable", "--length does not apply to fernet: a Fernet key is always 32 bytes".into()));
    }
    None
}

fn urandom(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    buf
}

/// `secrets.token_urlsafe(nbytes)` parity: urlsafe base64, padding stripped.
pub(crate) fn token_urlsafe(nbytes: usize) -> String {
    b64url(&urandom(nbytes), false)
}

/// `cryptography.fernet.Fernet.generate_key()` parity:
/// `base64.urlsafe_b64encode(os.urandom(32))` — 32 bytes, PADDED (44 chars).
fn fernet_key() -> String {
    b64url(&urandom(32), true)
}

/// URL-safe base64 (RFC 4648 §5), with or without `=` padding.
fn b64url(data: &[u8], pad: bool) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else if pad {
            out.push_str("==");
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else if pad && chunk.len() == 2 {
            out.push('=');
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// noo security scan
// ─────────────────────────────────────────────────────────────────────────

/// Everything the scan looks at, gathered up front so the check list itself
/// (`scan_findings`) is a pure, unit-testable function.
pub(crate) struct ScanInputs {
    pub jwt_secret: String,
    pub cluster_secret: String,
    pub redis_password: String,
    pub node_agent_token: String,
    /// `.env` st_mode when the file exists
    /// like Python's `stat().st_mode`).
    pub env_mode: Option<u32>,
    /// Is `.env` on an NTFS/drvfs mount where chmod is a no-op?
    pub env_on_ntfs: bool,
    pub tls_cert: String,
    pub pki_ca_exists: bool,
    /// The gateway base URL this CLI would talk to, and what
    /// `http::resolve_trust` makes of it. `Err` means there is no anchor at
    /// all — a plain-http gateway, or an unusable CA. Both are CRITICAL: the
    /// CLI attaches an operator bearer token to nearly every request.
    pub gateway_url: String,
    pub gateway_trust: Result<crate::http::Trust, String>,
    /// Plaintext backup-passphrase files still sitting under `secrets/`
    /// (repo-relative paths). `noo onboard` used to write
    /// `secrets/age_backup_passphrase.txt` and tell the operator to copy it
    /// into a password manager; nothing ever removed it, so the passphrase
    /// that opens the age-key backup — the key to every other secret — lived
    /// in the clear on the controller forever. `noo security secrets reveal`
    /// replaced that path; this finding is how an install that predates the
    /// change finds out it still has the file.
    pub lingering_passphrase_files: Vec<String>,
    /// Grafana's admin password. Scanned for PLACEHOLDERS as well as
    /// emptiness — the security review found `changeme` shipped in `.env.example` and
    /// `admin` written by `scripts/cluster-init.sh`, and every check in the
    /// fleet (this scan included) treated a published word as "configured".
    pub grafana_password: String,
    /// Private keys under the PKI dir whose mode says more than their
    /// reader (`pki::KeyReader`): `"<rel> <mode> (<reader>)"`, one per key.
    /// A 0644 leaf key is a credential every container uid can read through
    /// a bind mount — the gateway, mounting the whole tree, read every
    /// node's and service's key that way until 2026-09-28.
    pub pki_exposed_keys: Vec<String>,
    /// Service leaf keys with no row in `pki::SERVICE_KEY_READERS`, left
    /// 0644 on purpose so an unknown consumer keeps starting.
    pub pki_unknown_reader_keys: Vec<String>,
    /// `Some(why)` when `secrets/env.sops` EXISTS and the startup loader
    /// could not read it (`envfile::secret_store_state`). Every credential
    /// above was then read from an environment the store never filled, so
    /// their emptiness is the reader's failure, not the store's word — and
    /// the scan must say THAT, once, instead of "unset" six times. Found
    /// 2026-09-28: `ssh host8 noo security scan` reported "JWT secret
    /// unset" CRITICAL because `sops` lives in `~/.local/bin`, which a
    /// non-interactive PATH does not carry.
    pub store_unreadable: Option<String>,
    /// Registries whose login sits base64-encoded inline in
    /// `~/.docker/config.json` with no credential helper covering them.
    /// Names only, never the blobs.
    pub docker_inline_auth_registries: Vec<String>,
    /// Which of the RETIRED shared-bus names (`NATS_USER`, `NATS_PASSWORD`,
    /// `NOO_NATS_LEGACY_SHARED_CREDS`) are still set in this
    /// host's environment, i.e. the secret store or `.env`. Names only.
    pub retired_nats_names: Vec<String>,
    /// Files under `secrets/.runtime/` (repo-relative). The launcher used to
    /// materialise file-shaped credentials there at every start; nothing
    /// writes or reads that directory any more, so anything in it is a
    /// plaintext copy of a stored credential that outlived its mechanism
    /// (a Google SA key sat there 0644 for five days, 2026-09-23→28).
    pub runtime_residue: Vec<String>,
    /// Retired credentials (`secrets::RETIRED_STORE_KEYS`) that still hold a
    /// value as this host resolves them. Names only.
    pub retired_store_keys: Vec<String>,
    /// `Some(why)` when the repo `.env` holds a secret-class value
    /// (`plaintext_env::AtRest::plaintext_problem`) — names only.
    pub env_plaintext_secrets: Option<String>,
}

/// Values that are published somewhere in this repository, its docs, or the
/// wider world, and therefore are not secrets whatever field they sit in.
///
/// Compared case-insensitively after trimming. Keep it short and literal: a
/// fuzzy "looks weak" heuristic would fire on real generated secrets and
/// train operators to ignore the scan.
pub(crate) const PUBLISHED_PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "admin",
    "password",
    "secret",
    "test",
    "example",
    "dev-secret-change-in-production",
];

pub(crate) fn is_published_placeholder(v: &str) -> bool {
    let v = v.trim().to_ascii_lowercase();
    PUBLISHED_PLACEHOLDERS.iter().any(|p| *p == v)
}

type Finding = (&'static str, &'static str, String); // (severity, check, detail)

/// The check list from `security_cli.py::security_scan`, finding-for-finding
/// (same wording, same severities). Returns findings in insertion order;
/// the caller sorts by severity (stable, like Python's `sorted`).
pub(crate) fn scan_findings(i: &ScanInputs) -> Vec<Finding> {
    let mut issues: Vec<Finding> = Vec::new();

    // The store could not be read: ONE finding, and none of the "unset"
    // findings below — they would all be the same failure wearing six
    // scarier hats. HIGH rather than CRITICAL: the posture is unknown, not
    // known-bad, and a verdict the scan could not reach must not fail a
    // gate the way a real finding does (`--strict` still fails it).
    let store_readable = match &i.store_unreadable {
        Some(why) => {
            issues.push((
                "HIGH",
                "Secret Store",
                format!(
                    "secrets/env.sops is present but could not be decrypted: {why} — the credential \
                     checks were skipped; nothing in this scan is evidence that a secret is unset. \
                     Fix the reader and re-run"
                ),
            ));
            false
        }
        None => true,
    };

    if store_readable {
        // JWT secret
        if i.jwt_secret.is_empty() || i.jwt_secret == "dev-secret-change-in-production" {
            issues.push(("CRITICAL", "JWT Secret", "Default or unset — set NOO_JWT_SECRET".into()));
        }

        // NOTE: gateway auth is always on (invariant since config-graduation) — the old NOO_AUTH_ENABLED knob was removed.

        // Cluster secret
        if i.cluster_secret.is_empty() {
            issues.push(("HIGH", "Cluster Secret", "Empty — set NOO_CLUSTER_SECRET".into()));
        }

        // Redis password
        if i.redis_password.is_empty() {
            issues.push(("MEDIUM", "Redis Password", "Unset — set REDIS_PASSWORD".into()));
        }

        // (No "NATS Password" check: the shared bus password was retired by
        // An earlier release — every principal has its own, verified by digest.)

        // Node agent token
        if i.node_agent_token.is_empty() {
            issues.push(("HIGH", "Node Agent Token", "Unset — set NOO_NODE_AGENT_TOKEN".into()));
        }
    }

    // The RETIRED shared NATS credential. Every principal has
    // its own bcrypt user in `monitoring/nats/users.conf`; the shared
    // `NATS_USER`/`NATS_PASSWORD` pair and its bridge are gone from every
    // compose service, the renderer and every reader. What survives on an
    // install that predates the retirement is the stored VALUE — a plaintext
    // credential nothing reads. Nothing deletes a store key automatically,
    // so the scan says where it is and how to remove it. LOW: hygiene, not
    // an exposure that grew today.
    if store_readable && !i.retired_nats_names.is_empty() {
        issues.push(("LOW", "Retired NATS Credential", retired_nats_detail(&i.retired_nats_names)));
    }

    // A secret in plaintext .env. CRITICAL like the plaintext files below:
    // it is a credential in the clear now. The plaintext backend is retired
    // The remedy moves the install onto the store and
    // blanks the copies.
    if let Some(why) = &i.env_plaintext_secrets {
        issues.push((
            "CRITICAL",
            "Secrets At Rest",
            format!(
                "{why} — run '{}', then 'noo security secrets tidy'",
                crate::commands::plaintext_env::REMEDY_ONBOARD
            ),
        ));
    }

    // .env permissions (skip on NTFS/drvfs where chmod is a no-op)
    if let Some(mode) = i.env_mode {
        if mode & 0o044 != 0 && !i.env_on_ntfs {
            issues.push((
                "MEDIUM",
                ".env Permissions",
                format!("World-readable (0o{mode:o}) — chmod 600 .env"),
            ));
        }
    }

    // TLS
    if i.tls_cert.is_empty() {
        issues.push(("MEDIUM", "TLS", "Not configured — set NOO_TLS_CERT + NOO_TLS_KEY".into()));
    }

    // Grafana admin password. Two findings, not one: unset means
    // the launcher will refuse to start the profile, which is loud; a
    // placeholder means it WILL start, with an admin UI whose password is
    // in the repository.
    if !store_readable {
        // Skipped for the same reason as the credentials above.
    } else if is_published_placeholder(&i.grafana_password) {
        issues.push((
            "CRITICAL",
            "Grafana Password",
            format!(
                "'{}' is a published placeholder, not a secret — run 'noo onboard' or set GRAFANA_PASSWORD (and change it inside Grafana, which copied the old one on first boot)",
                i.grafana_password.trim()
            ),
        ));
    } else if i.grafana_password.is_empty() {
        issues.push((
            "MEDIUM",
            "Grafana Password",
            "Unset — the controller/monitoring profiles refuse to start; set GRAFANA_PASSWORD".into(),
        ));
    }

    // Plaintext backup passphrases left on disk.
    //
    // CRITICAL, at the same level as a published Grafana placeholder, and for
    // the same reason: the file is not a risk that might materialise, it is a
    // credential in the clear right now, on the one box whose compromise opens
    // everything else. It is also trivially fixable — read it once, store it
    // off-box, shred it — which is exactly the kind of finding that deserves a
    // loud severity, because nobody will chase a LOW.
    //
    // Since an earlier release the same applies to every credential file an older
    // wizard wrote beside the store. The passphrases are for a human, so the
    // remedy is to read and shred; the rest have a process reader in the
    // store already, so the remedy is one verb that verifies and shreds.
    for rel in &i.lingering_passphrase_files {
        let key = crate::commands::secrets_reveal::LEGACY_PLAINTEXT_FILES
            .iter()
            .find(|(_, p)| *p == rel.as_str())
            .map(|(k, _)| *k)
            .unwrap_or("NOO_AGE_BACKUP_PASSPHRASE");
        let is_passphrase = crate::commands::secrets_reveal::PLAINTEXT_PASSPHRASE_FILES
            .iter()
            .any(|(k, _)| *k == key);
        let (title, detail) = if is_passphrase {
            (
                "Backup Passphrase Plaintext",
                format!(
                    "{rel} holds a backup passphrase in the clear — run 'noo security secrets reveal \
                     {key}' to read it once, store it off this machine, and let the command shred the file"
                ),
            )
        } else {
            (
                "Secret File Plaintext",
                format!(
                    "{rel} holds {key} in the clear beside the encrypted store — run \
                     'noo security secrets absorb-files' to fold it into env.sops and shred it"
                ),
            )
        };
        issues.push(("CRITICAL", title, detail));
    }

    // Files under secrets/.runtime/. The launcher (`scripts/lib-secrets.sh`)
    // used to decode file-shaped credentials there at every start and
    // `noomesh-stop.sh` removed them at stop; the write side is gone (the
    // gateway parses GOOGLE_CHAT_CREDENTIALS_JSON in memory) but a file
    // written before that change outlives it until the next stop — and a
    // controller is not stopped often. Same severity as the other plaintext
    // copies: it is a credential in the clear now, on the controller.
    for rel in &i.runtime_residue {
        issues.push((
            "CRITICAL",
            "Runtime Residue Plaintext",
            format!(
                "{rel} is a materialised copy of a stored credential — nothing writes or reads \
                 secrets/.runtime/ any more (the value lives in env.sops and is parsed in memory) — \
                 run 'shred -u {rel}' (then 'rmdir secrets/.runtime')"
            ),
        ));
    }

    // A retired credential still held. Nothing reads it — the gateway warns
    // at boot and ignores it — so it is hygiene, not exposure: LOW, with the
    // one command that removes it. It must not linger, because a live
    // secret nothing consumes is one nobody will ever think to rotate.
    for key in &i.retired_store_keys {
        let why = crate::commands::secrets::retired_store_key(key).unwrap_or("retired");
        issues.push((
            "LOW",
            "Retired Credential",
            format!(
                "{key} is retired and ignored ({why}) — remove it: '{}'",
                crate::commands::secrets::RETIRED_REMOVE_CMD
            ),
        ));
    }

    // Registry logins stored inline. `docker login` without a credential
    // helper writes `user:token` base64 (not encrypted) into
    // ~/.docker/config.json, readable by every process running as that
    // user; an expired Docker Hub PAT sat there and broke two CI steps.
    // Names only — the blobs are the finding, never the detail.
    if !i.docker_inline_auth_registries.is_empty() {
        let (needed, spare): (Vec<&String>, Vec<&String>) = i
            .docker_inline_auth_registries
            .iter()
            .partition(|r| r.contains("ghcr.io"));
        let mut detail = format!(
            "~/.docker/config.json stores the login for {} inline (base64, no credential helper) — \
             readable by every process running as you",
            i.docker_inline_auth_registries.join(", ")
        );
        if !needed.is_empty() {
            detail.push_str(
                " — ghcr.io is the one the launcher needs (it pulls with YOUR docker login; there is \
                 no registry token in the secret store): keep it behind a credential helper \
                 (set \"credsStore\" to pass or secretservice, then log in again)",
            );
        }
        if !spare.is_empty() {
            detail.push_str(&format!(
                " — nothing in the stack pulls from {}: 'docker logout <registry>' each",
                spare.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        issues.push(("MEDIUM", "Registry Credentials", detail));
    }

    // PKI
    if !i.pki_ca_exists {
        issues.push(("LOW", "Cluster PKI", "No CA — run 'noo security pki init'".into()));
    }

    // Private-key modes. CRITICAL like the plaintext passphrase: a key that
    // is readable beyond its one reader is not a risk that might
    // materialise, it is every container uid holding the identity now, and
    // the fix is one idempotent verb.
    if !i.pki_exposed_keys.is_empty() {
        issues.push((
            "CRITICAL",
            "PKI Key Modes",
            format!(
                "{} private key(s) readable beyond their reader: {} — run 'noo security pki fix-modes' (it prints the sudo line for a key it cannot hand over itself)",
                i.pki_exposed_keys.len(),
                i.pki_exposed_keys.join(", ")
            ),
        ));
    }
    if !i.pki_unknown_reader_keys.is_empty() {
        issues.push((
            "MEDIUM",
            "PKI Key Reader",
            format!(
                "no reader entry for {} (left 0644) — add the container's uid to SERVICE_KEY_READERS in noo-cli/src/pki.rs, or remove the leaf",
                i.pki_unknown_reader_keys.join(", ")
            ),
        ));
    }

    // Gateway transport. Two CRITICALs, because the CLI sends a
    // bearer credential on nearly every request and both states hand it to
    // an unauthenticated peer:
    //   * a plain-http gateway that is not this machine, and
    //   * an https gateway with no usable trust anchor.
    // The CLI already refuses both at request time; the scan is how an
    // operator finds out BEFORE a command fails, and how a fleet audit sees
    // it at all.
    match &i.gateway_trust {
        Err(why) => issues.push((
            "CRITICAL",
            "Gateway Transport",
            format!("{} — {why}", i.gateway_url),
        )),
        Ok(crate::http::Trust::LoopbackPlaintext) if !i.gateway_url.is_empty() => issues.push((
            "LOW",
            "Gateway Transport",
            format!("{} is plain http:// to this machine — fine for local development, never for a real gateway", i.gateway_url),
        )),
        Ok(_) => {}
    }

    issues
}

/// The names an earlier release retired. A value under any of them is read by
/// nothing — not the gateway, the workers, the node agent, nats, nor any
/// compose service.
pub(crate) const RETIRED_NATS_NAMES: &[&str] = &["NATS_USER", "NATS_PASSWORD", "NOO_NATS_LEGACY_SHARED_CREDS"];

/// The "Retired NATS Credential" finding text for the names still set.
/// `noo security secrets tidy` removes them (they are
/// `secrets::RETIRED_STORE_KEYS` rows); it never carries a value.
pub(crate) fn retired_nats_detail(names: &[String]) -> String {
    format!(
        "{} still set — RETIRED: nothing mints, delivers or reads \
         them, and nats no longer defines the user. Remove them: `noo security secrets tidy` (drops them \
         from secrets/env.sops and blanks them in .env). Nodes keep a stale NATS_USER/NATS_PASSWORD in /etc/noo-node-agent.env until \
         re-provisioned (`noo cluster provision <node>`); inert — the agent never presents it",
        names.join(", ")
    )
}

/// Registries in a docker `config.json` whose credential is stored INLINE:
/// an `auths.<registry>` entry with a non-empty `auth` (or a username +
/// password pair) that no `credHelpers[<registry>]` and no `credsStore`
/// covers. Pure over the file text; names only. Unparseable text is no
/// finding — the scan reports posture, not JSON syntax.
pub(crate) fn docker_inline_auth_registries(config_text: &str) -> Vec<String> {
    let Ok(cfg) = serde_json::from_str::<serde_json::Value>(config_text) else {
        return Vec::new();
    };
    let has_store = cfg
        .get("credsStore")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let Some(auths) = cfg.get("auths").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (registry, entry) in auths {
        let helper = cfg
            .pointer(&format!("/credHelpers/{}", registry.replace('/', "~1")))
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if has_store || helper {
            continue;
        }
        let inline_auth = entry
            .get("auth")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let inline_pair = entry.get("password").and_then(|v| v.as_str()).is_some();
        if inline_auth || inline_pair {
            out.push(registry.clone());
        }
    }
    out.sort();
    out
}

/// Every regular file under `<root>/secrets/.runtime/`, as repo-relative
/// paths, sorted. Directories alone are not residue.
pub(crate) fn runtime_residue_files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(root) {
                    out.push(rel.to_string_lossy().into_owned());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join("secrets/.runtime"), root, &mut out);
    out.sort();
    out
}

/// `$DOCKER_CONFIG/config.json`, else `~/.docker/config.json` — the same
/// resolution `scripts/noomesh-start.sh` and the docker CLI use.
fn docker_config_path() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("DOCKER_CONFIG") {
        if !d.is_empty() {
            return Some(PathBuf::from(d).join("config.json"));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker/config.json"))
}

fn severity_rank(sev: &str) -> usize {
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        .iter()
        .position(|s| *s == sev)
        .unwrap_or(4)
}

/// `_is_ntfs_mount` parity: longest /proc/mounts mount-point string-prefix of
/// the resolved path, fs type in {drvfs, 9p, ntfs, ntfs3}. Pure over the
/// mounts text so it's unit-testable.
pub(crate) fn is_ntfs_fs(mounts: &str, resolved: &str) -> bool {
    let mut best_fs = "";
    let mut best_len = 0usize;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let mount_point = parts[1];
            if resolved.starts_with(mount_point) && mount_point.len() > best_len {
                best_fs = parts[2];
                best_len = mount_point.len();
            }
        }
    }
    matches!(best_fs, "drvfs" | "9p" | "ntfs" | "ntfs3")
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// `noo security scan` — local posture scan.
///
/// this used to exit 0 no matter what it found, on "Python
/// parity" grounds, and the comment beside the CRITICAL banner said so.
/// A gate written from that banner would have passed silently on a
/// critical finding, which is the same silent-success shape this repo
/// keeps finding. The exit code is now the verdict:
///
///   0  nothing above the threshold
///   1  at least one CRITICAL (or, with `--strict`, anything at all)
///
/// `--strict` is what a pre-commit hook or a CI job wants: MEDIUM findings
/// are real posture problems, they are just not outages. The default stays
/// CRITICAL-only so `noo security scan` on a dev box does not fail a script
/// over "TLS not configured".
pub fn security_scan(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    crate::ui::auto_page(); // long output: $PAGER on a TTY (no-op otherwise)
    let mut strict = false;
    for a in args {
        match a.as_str() {
            "--strict" => strict = true,
            _ => return Err(Unhandled),
        }
    }

    let env_path = crate::envfile::repo_root().join(".env");
    let (env_mode, env_on_ntfs) = match std::fs::metadata(&env_path) {
        Ok(md) => {
            use std::os::unix::fs::MetadataExt as _;
            let resolved = std::fs::canonicalize(&env_path).unwrap_or(env_path.clone());
            let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
            (
                Some(md.mode()),
                is_ntfs_fs(&mounts, &resolved.to_string_lossy()),
            )
        }
        Err(_) => (None, false),
    };

    let gateway_url = crate::envfile::gateway_url(&g.gateway_override);
    let key_issues = crate::pki::ClusterCa::new(pki_dir()).audit_key_modes();
    let store_problem = match crate::envfile::secret_store_state() {
        crate::envfile::StoreState::Unreadable(e) => Some(e),
        _ => None,
    };
    let inputs = ScanInputs {
        jwt_secret: env_var("NOO_JWT_SECRET"),
        cluster_secret: env_var("NOO_CLUSTER_SECRET"),
        redis_password: env_var("REDIS_PASSWORD"),
        node_agent_token: env_var("NOO_NODE_AGENT_TOKEN"),
        env_mode,
        env_on_ntfs,
        tls_cert: env_var("NOO_TLS_CERT"),
        pki_ca_exists: pki_dir().join("ca.crt").exists(),
        gateway_url: gateway_url.clone(),
        gateway_trust: crate::http::resolve_trust(&gateway_url),
        grafana_password: env_var("GRAFANA_PASSWORD"),
        lingering_passphrase_files: crate::commands::secrets_reveal::lingering_plaintext(|rel| {
            crate::envfile::repo_root().join(rel).exists()
        })
        .into_iter()
        .map(String::from)
        .collect(),
        pki_exposed_keys: key_issues
            .iter()
            .filter(|k| k.kind == crate::pki::KeyIssueKind::Exposed)
            .map(|k| format!("{} {:04o} ({})", k.rel, k.mode, k.reader.describe()))
            .collect(),
        pki_unknown_reader_keys: key_issues
            .iter()
            .filter(|k| k.kind == crate::pki::KeyIssueKind::UnknownReader)
            .map(|k| k.rel.clone())
            .collect(),
        store_unreadable: store_problem.as_ref().map(|e| e.to_string()),
        docker_inline_auth_registries: docker_config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| docker_inline_auth_registries(&t))
            .unwrap_or_default(),
        retired_nats_names: RETIRED_NATS_NAMES
            .iter()
            .filter(|k| !env_var(k).trim().is_empty())
            .map(|k| k.to_string())
            .collect(),
        runtime_residue: runtime_residue_files(&crate::envfile::repo_root()),
        // The shared-NATS names have their own finding ("Retired NATS
        // Credential", which also names the stale node-side lines); keep
        // them out of the generic one so a key is reported once.
        retired_store_keys: crate::commands::secrets::RETIRED_STORE_KEYS
            .iter()
            .filter(|(k, _)| !RETIRED_NATS_NAMES.contains(k))
            .filter(|(k, _)| !env_var(k).trim().is_empty())
            .map(|(k, _)| (*k).to_string())
            .collect(),
        env_plaintext_secrets: crate::commands::plaintext_env::AtRest::read(&crate::envfile::repo_root())
            .plaintext_problem(),
    };
    let mut issues = scan_findings(&inputs);
    issues.sort_by_key(|(sev, _, _)| severity_rank(sev)); // stable, Python parity

    if g.json {
        let items: Vec<serde_json::Value> = issues
            .iter()
            .map(|(sev, check, detail)| {
                serde_json::json!({ "severity": sev, "check": check, "detail": detail })
            })
            .collect();
        let criticals = issues.iter().filter(|(s, _, _)| *s == "CRITICAL").count();
        println!(
            "{}",
            serde_json::json!({
                "issues": items,
                "criticals": criticals,
                "strict": strict,
                "ok": scan_exit(&issues, strict) == 0,
                // A gate reading this must know when the credential checks
                // did not run at all (null = the store was read or absent).
                "store_problem": store_problem.as_ref().map(|e| e.kind()),
            })
        );
        return Ok(scan_exit(&issues, strict));
    }

    if issues.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, "no security issues found"));
        return Ok(0);
    }

    let criticals = issues.iter().filter(|(s, _, _)| *s == "CRITICAL").count();
    println!("{}", ui::header("security scan", Some(&format!("{} findings · {criticals} critical", issues.len()))));
    println!("{}", ui::section("findings"));
    let rows: Vec<Vec<String>> = issues
        .iter()
        .map(|(sev, check, detail)| {
            let (glyph, word) = match *sev {
                "CRITICAL" => (Glyph::Err, ui::err("critical")),
                "HIGH" | "MEDIUM" | "WARNING" => (Glyph::Warn, ui::warn(&sev.to_ascii_lowercase())),
                _ => (Glyph::Bullet, ui::muted(&sev.to_ascii_lowercase())),
            };
            vec![ui::glyph_cell(glyph), word, check.to_string(), detail.to_string()]
        })
        .collect();
    print!("{}", ui::table(&[Col::left(""), Col::left("severity"), Col::left("check"), Col::left("detail")], &rows));
    if criticals > 0 {
        println!("{}", ui::status_line(Glyph::Err, &format!("{criticals} critical issue(s) found")));
        ui::guide(&[("noo security scan --json", "machine-readable findings for a ticket or a CI gate")]);
    } else if strict {
        println!("{}", ui::status_line(Glyph::Warn, &format!("{} finding(s); --strict fails on any of them", issues.len())));
    }
    Ok(scan_exit(&issues, strict))
}

/// The verdict. Kept apart from the printing so it can be tested without a
/// terminal, and so the `--json` path and the human path cannot disagree
/// about what "ok" means.
pub(crate) fn scan_exit(issues: &[Finding], strict: bool) -> i32 {
    if strict {
        return i32::from(!issues.is_empty());
    }
    i32::from(issues.iter().any(|(sev, _, _)| *sev == "CRITICAL"))
}

// ─────────────────────────────────────────────────────────────────────────
// noo security pki rotate-all
// ─────────────────────────────────────────────────────────────────────────

/// Which containers consume which certificates — port of
/// `noomesh/pki/consumers.py::cert_consumers`. `name` is the pki-relative
/// path (e.g. `services/nats/service.crt`); worker node certs are shipped by
/// ansible and reloaded on the worker, so only the controller-local
/// node-agent is returned (and only when the node cert belongs to
/// `local_hostname`).
pub(crate) fn cert_consumers(name: &str, role: &str, local_hostname: &str) -> Vec<String> {
    let parent_name = |n: &str| -> String {
        Path::new(n)
            .parent()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    match role {
        "gateway" => vec!["noo-gateway".into()],
        "service" => {
            let svc = parent_name(name);
            vec![format!("noo-{svc}"), format!("noo-stunnel-{svc}")]
        }
        "node" if !local_hostname.is_empty() && parent_name(name) == local_hostname => {
            vec!["noo-node-agent".into()]
        }
        _ => vec![],
    }
}

fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

fn running_containers() -> Vec<String> {
    let out = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// All restarted containers running (and not unhealthy); gateway serving
/// /health if present. Port of `security_cli.py::_probe_health`, except that
/// the `https://localhost:8080/health` probe VERIFIES the certificate (the
/// Python original passed `verify=False`).
fn probe_health(containers: &[String], timeout_secs: u64) -> (bool, String) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let mut bad: Vec<String> = Vec::new();
        for c in containers {
            let out = Command::new("docker")
                .args([
                    "inspect",
                    "-f",
                    "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    c,
                ])
                .output();
            let state = out
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if !state.starts_with("true") || state.contains("unhealthy") {
                bad.push(c.clone());
            }
        }
        let gw_ok = if containers.iter().any(|c| c.ends_with("-gateway")) {
            https_health_ok(&format!(
                "https://localhost:{}/health",
                8080 + crate::envfile::port_offset()
            ))
        } else {
            true
        };
        if bad.is_empty() && gw_ok {
            return (true, "all consumers healthy".into());
        }
        if Instant::now() >= deadline {
            return (
                false,
                format!(
                    "unhealthy after {timeout_secs}s: {bad:?}{}",
                    if !gw_ok { " gateway /health failing" } else { "" }
                ),
            );
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// GET with a 4s timeout, VERIFIED against the resolved trust anchor. The
/// Python original passed `verify=False`; the gateway cert names `localhost`
/// and `127.0.0.1` (`pki::issue_gateway_cert`) and this code runs on the
/// controller, which holds the CA, so verification costs nothing and a probe
/// that cannot tell WHO answered proves nothing about the rollout it gates.
fn https_health_ok(url: &str) -> bool {
    let Ok(agent) = crate::http::agent_for(url, 4) else {
        return false;
    };
    match agent.get(url).call() {
        Ok(resp) => resp.status().as_u16() == 200,
        Err(_) => false,
    }
}

/// Copy every file under `src_root` to the same relative path under
/// `dst_root` (used for both taking the backup and reverting from it).
fn copy_tree(src_root: &Path, dst_root: &Path) -> Result<(), String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(src_root, &mut files);
    for src in files {
        let rel = src.strip_prefix(src_root).map_err(|e| e.to_string())?;
        let dst = dst_root.join(rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        std::fs::copy(&src, &dst)
            .map_err(|e| format!("copy {} → {}: {e}", src.display(), dst.display()))?;
    }
    Ok(())
}

/// `noo security pki rotate-all [--warn-days N] [--new-days N] [--force|-y/--yes]
///  [--reload/--no-reload]` — rotate all leaf certs expiring soon and reload
/// their consumers. Semantics preserved from the Python command exactly:
/// scan → confirm → backup → rotate → restart consumers (gateway LAST) →
/// health-probe → on failure RESTORE the backup and restart again, exit 1.
/// The CA is never rotated. `--force` is Python's skip-confirm flag;
/// `--yes/-y` is the repo-wide agent-first alias for the same thing.
/// The fleet as the GATEWAY knows it: `(node_id, host, ssh_user)`.
///
/// Replaced the ansible-inventory parser at every call site that asked "who is in
/// this fleet and how do I reach them". That parsed `ansible/inventory/hosts`
/// — a file in the tree deleted in 3695e129 — so on every install since it
/// returned an EMPTY list, and each caller then took its not-found branch
/// while believing it had looked. The registry is the only thing that knows
/// what is enrolled.
///
/// `ssh_user` falls back to the invoking user, matching what the inventory's
/// `ansible_user=` used to supply.
pub(crate) fn fleet_nodes_from_registry(g: &Globals) -> Vec<(String, String, String)> {
    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|b| b["nodes"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|n| {
            let id = n["id"].as_str().or_else(|| n["hostname"].as_str())?.to_string();
            let host = n["ip"]
                .as_str()
                .map(str::to_string)
                .or_else(|| {
                    n["agent_url"].as_str().and_then(|u| {
                        u.split("//").nth(1).and_then(|h| h.split(':').next()).map(str::to_string)
                    })
                })
                .unwrap_or_else(|| id.clone());
            let user = n["ssh_user"].as_str().unwrap_or(&default_user).to_string();
            Some((id, host, user))
        })
        .collect()
}




/// The signed manifest header (bundle format v2).
///
/// A v1 manifest was signed but ANONYMOUS and UNDATED, so a valid bundle
/// was valid anywhere, forever. A cert bundle carries the node's own
/// `node.key`; captured on its way to node A and applied to node B, it
/// handed B node A's private key and, with it, A's identity -- which is
/// now what decides whether a caller may command a box at all
/// (node-agent-go/internal/auth/principal.go). Undated, the same bundle
/// could also be replayed months later to put a rotated cert or a
/// superseded agent-env back on a node.
///
/// The header rides inside the manifest, so the existing signature covers
/// it with no change to the crypto. Comment lines, so an older applier's
/// `while read sum kind` loop cannot mistake a header for a payload line:
/// it refuses the bundle as an unknown kind, which is the right answer
/// from an applier that could not enforce the binding anyway.
///
/// `noo-apply.sh` §1a and `node_fetch::verify_bundle` are the two
/// enforcers; `scripts/sign-bundle.sh` is the third producer and writes
/// the identical three lines.
fn manifest_header(node: &str) -> String {
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("#noo-bundle 2\n#node {node}\n#issued {issued}\n")
}

/// Build a CA-signed cert bundle for one node (§7b): a tar of
/// `manifest` (sha256 per kind) + `manifest.sig` (openssl dgst -sha256
/// signed with ca.key) + `files/<kind>`. noo-apply on the node verifies the
/// signature against the ca.crt it already trusts before touching anything —
/// the SSH key authenticates transport, this signature authenticates
/// content. Returns the bundle path inside `work` on success.
///
/// `with_leaves`: also carry the node's backend door leaves (`svc-<x>.crt`
/// / `.key`) — whatever pairs are on disk under
/// `nodes/<node>/services/`, so a `rotate-all` that re-issued one delivers
/// it. False only for a Mac whose applier predates the kinds
/// (`node_leaves::applier_knows_leaf_kinds`): an unknown kind refuses the
/// whole bundle there, certs included.
fn build_signed_cert_bundle(
    ca: &crate::pki::ClusterCa,
    node: &str,
    work: &Path,
    with_leaves: bool,
) -> Result<PathBuf, String> {
    let files_dir = work.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| e.to_string())?;
    let node_dir = ca.dir.join("nodes").join(node);
    let mut manifest = manifest_header(node);
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    for (src, kind) in [
        (ca.dir.join("ca.crt"), "ca.crt"),
        (node_dir.join("node.crt"), "node.crt"),
        (node_dir.join("node.key"), "node.key"),
    ] {
        let bytes = std::fs::read(&src).map_err(|e| format!("{}: {e}", src.display()))?;
        payloads.push((kind.to_string(), bytes));
    }
    if with_leaves {
        let (leaves, _skipped) = crate::commands::node_leaves::leaf_payloads(ca, node)?;
        for (kind, bytes) in leaves {
            payloads.push((kind.to_string(), bytes));
        }
    }
    // The applier rides a cert push too, for the same reason it rides every
    // provision bundle: a node still running an older noo-apply refuses the
    // v2 header as an unknown kind (exit 76), and §1b self-updates the
    // applier BEFORE the kind loop runs, so carrying it here is what makes
    // a cert push survive the format change on an already-enrolled node.
    let apply = crate::commands::enroll::asset_apply();
    if !apply.is_empty() {
        payloads.push(("applier".to_string(), apply.as_bytes().to_vec()));
    }
    // refresh the node's copy of the fleet signing public key on
    // every cert push, but ONLY once it has adopted one — a node whose
    // applier predates the `signing-pub` kind refuses the whole bundle
    // with exit 76, and `rotate-signing-key` is the verb that upgrades the
    // applier and installs the key together.
    //
    // A node that has NOT adopted gets it too, because the
    // CA-signed lane that used to carry its bundles is retired — a CA
    // signature now authorises only a bundle that carries `signing-pub` (a
    // rollover), so every CA-signed bundle is one. The node adopts on the
    // same apply, and the next bundle is signed by the signing key.
    ca.ensure_signing_key()?;
    let key = ca.bundle_signing_key(node);
    if ca.is_ca_key(&key) {
        return Err(not_adopted(node));
    }
    if ca.signing_adopted(node) {
        let pubkey = std::fs::read(ca.signing_pub_path())
            .map_err(|e| format!("{}: {e}", ca.signing_pub_path().display()))?;
        payloads.push(("signing-pub".to_string(), pubkey));
    }
    for (kind, bytes) in &payloads {
        let kind = kind.as_str();
        let sum = {
            use sha2::{Digest as _, Sha256};
            let mut h = Sha256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        };
        std::fs::write(files_dir.join(kind), bytes).map_err(|e| e.to_string())?;
        manifest.push_str(&format!("{sum}  {kind}\n"));
    }
    let manifest_path = work.join("manifest");
    std::fs::write(&manifest_path, &manifest).map_err(|e| e.to_string())?;
    sign_and_tar(ca, work, &key)
}

/// Sign `work/manifest` with `key` into `manifest.sig` and tar the bundle.
///
/// openssl rather than a rust crate: the signing key is PKCS#8 PEM (rcgen),
/// the node side verifies with the openssl CLI, and using the SAME tool on
/// both ends removes a whole class of encoding mismatches.
///
/// When `key` is the CA key — a rollover, the only bundle the CA may still
/// authorise — the manifest is also COUNTERSIGNED with every signing key this
/// controller retains (`manifest.xsig.<n>`, current first). A
/// node that already holds a signing key accepts a CA-signed rollover only
/// with its own key's countersignature, so a stolen CA key alone can no
/// longer replace the key that authorises code.
fn sign_and_tar(ca: &crate::pki::ClusterCa, work: &Path, key: &Path) -> Result<PathBuf, String> {
    let manifest_path = work.join("manifest");
    let sign = |k: &Path, out: &str| -> bool {
        Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(k)
            .args(["-out"])
            .arg(work.join(out))
            .arg(&manifest_path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !sign(key, "manifest.sig") {
        return Err("openssl signing failed (is openssl installed?)".into());
    }
    let mut members: Vec<String> = vec!["manifest".into(), "manifest.sig".into()];
    if ca.is_ca_key(key) {
        for (n, k) in ca.retained_signing_keys().iter().enumerate() {
            let name = format!("manifest.xsig.{n}");
            if !sign(k, &name) {
                return Err(format!("openssl could not countersign with {}", k.display()));
            }
            members.push(name);
        }
    }
    members.push("files".into());
    let bundle = work.join("bundle.tar");
    let tar_ok = Command::new("tar")
        .arg("-cf")
        .arg(&bundle)
        .arg("-C")
        .arg(work)
        .args(&members)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !tar_ok {
        return Err("tar failed".into());
    }
    Ok(bundle)
}

/// Build a CA-signed bundle from arbitrary (kind, bytes) pairs — the general
/// form of build_signed_cert_bundle, for kinds that are not certs (teardown).
pub(crate) fn build_signed_bundle(
    ca: &crate::pki::ClusterCa,
    node: &str,
    files: &[(&str, Vec<u8>)],
    work: &Path,
) -> Result<PathBuf, String> {
    ca.ensure_signing_key()?;
    let key = ca.bundle_signing_key(node);
    if ca.is_ca_key(&key) {
        return Err(not_adopted(node));
    }
    build_signed_bundle_with_key(ca, node, files, work, &key)
}

/// An earlier release (review item 7): the CA key signs a signing-key ROLLOVER
/// carrying `signing-pub` and nothing else, so a bundle for a node that has
/// not adopted the signing key cannot be built. The node adopts first.
pub(crate) fn not_adopted(node: &str) -> String {
    format!(
        "{node} has not adopted the fleet signing key, and the CA may sign nothing but the key \
         itself — run `noo security pki rotate-signing-key {node} --deliver-only` \
         first (`noo cluster provision {node}` does this for you)"
    )
}

/// The same builder with the signing key named explicitly. Only the
/// signing-key ROLLOVER uses this directly, to force `ca.key` — the one
/// anchor a node that has not adopted (or is being moved off a retired
/// signing key) can still verify. Everything else goes through
/// `build_signed_bundle`, which picks the key from the node's adoption
/// state and must not be bypassed.
pub(crate) fn build_signed_bundle_with_key(
    ca: &crate::pki::ClusterCa,
    node: &str,
    files: &[(&str, Vec<u8>)],
    work: &Path,
    signing_key: &Path,
) -> Result<PathBuf, String> {
    let files_dir = work.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| e.to_string())?;
    // The CA signs a signing-key ROLLOVER and nothing
    // else — `signing-pub` alone. The applier refuses anything more, so it
    // is refused here first, where the error is readable.
    if ca.is_ca_key(signing_key) && !(files.len() == 1 && files[0].0 == "signing-pub") {
        return Err("a CA-signed bundle may carry signing-pub and nothing else".into());
    }
    let mut manifest = manifest_header(node);
    for (kind, bytes) in files {
        let sum = {
            use sha2::{Digest as _, Sha256};
            let mut h = Sha256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        };
        std::fs::write(files_dir.join(kind), bytes).map_err(|e| e.to_string())?;
        manifest.push_str(&format!("{sum}  {kind}\n"));
    }
    std::fs::write(work.join("manifest"), &manifest).map_err(|e| e.to_string())?;
    sign_and_tar(ca, work, signing_key)
}

// ═══ fu72 Batch C: cert delivery over the rails ═══════════════════════
//
// `pki rotate-all` used to re-issue a REMOTE node's cert on the controller's
// disk, print "rotated", and deliver nothing — the node kept serving its old
// cert while the expiry alert cleared.
// Delivery now rides the same rails everything else does: pull-first
// (encrypted bundle staged at the gateway, the node's fetch timer collects,
// noo-apply installs + restarts the agent), gate/SSH fallback for pre-pull
// nodes — teardown's ordering, not push-nodes' gate-first.

/// How a re-issued node cert reached (or failed to reach) its node.
#[derive(Debug)]
pub(crate) enum CertDelivery {
    /// Pull: collected AND the node's heartbeat now reports the new cert's
    /// NotAfter (positive proof it is PRESENTING the re-issued cert).
    Verified,
    /// Pull: the node RAN noo-apply on this exact bundle and reported
    /// exit 0. Direct proof of installation, from the apply-report path
    ///  rather than an inference about it.
    Applied,
    /// Pull: bundle fetched; the agent build predates BOTH cert_not_after
    /// and apply reporting, so presentation is inferred from the node
    /// staying online. Only reachable for a node that has never reported
    /// an apply — see `deliver_signed_bundle`.
    Collected,
    /// Pull: staged, but the node did not fetch within the wait.
    Staged,
    /// Pull: the node FETCHED the bundle (the gateway stamped `fetched_at`
    /// from the node's signed receipt) but no apply report arrived inside
    /// the verify window. Not `Staged` (that is a claim the node never
    /// collected it, which is false here) and not a success: a fetch is not
    /// a delivery (#83). Whatever judges the effect decides from here.
    FetchedUnconfirmed,
    /// A provision bundle is staged-but-uncollected for this node; the
    /// staging slot is one row per node and clobbering it would eat the
    /// pending provision. Deliver the certs after it is collected.
    SkippedPending,
    Failed(String),
}

/// One narration line per node delivery: glyph from the outcome, the
/// node name, the outcome label muted.
/// Per-node delivery outcome, as a sub-line under the node's `ui::item`
/// (the caller has already named the node above it).
fn delivery_line(_node: &str, outcome: &CertDelivery) {
    let glyph = if outcome.ok() { Glyph::Ok } else { Glyph::Err };
    println!("{}", ui::sub(&ui::status_line(glyph, &outcome.label())));
}

impl CertDelivery {
    pub(crate) fn ok(&self) -> bool {
        matches!(
            self,
            CertDelivery::Verified
                | CertDelivery::Applied
                | CertDelivery::Collected
        )
    }
    pub(crate) fn label(&self) -> String {
        match self {
            CertDelivery::Verified => "delivered (node presents the new cert)".into(),
            CertDelivery::Applied => "delivered (node applied the bundle, exit 0)".into(),
            CertDelivery::Collected => "delivered (collected; agent predates cert reporting)".into(),
            CertDelivery::Staged => format!(
                "STAGED, not confirmed within {} s — the node fetches every ~70 s (an idle node every ~3rd tick); \
                 it may have applied since — re-run to check", FETCH_WAIT.as_secs()),
            CertDelivery::FetchedUnconfirmed =>
                "fetched, apply NOT confirmed — the node collected the bundle but no apply report arrived in 150 s; \
                 check the effect (`noo cluster verify <node>`)".into(),
            CertDelivery::SkippedPending =>
                "SKIPPED — a provision bundle is pending for this node; re-run after it collects".into(),
            CertDelivery::Failed(e) => format!("UNDELIVERED — {e}"),
        }
    }
}

/// The node's entry from /api/cluster/nodes, matched id → node_id → name
/// (the #78 lesson: the KV entry uses "id").
pub(crate) fn cluster_node_entry(g: &Globals, name: &str) -> Option<serde_json::Value> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10).and_then(|doc| {
        doc.get("nodes")?.as_array()?.iter().find_map(|nd| {
            let id = nd.get("id").and_then(|v| v.as_str())
                .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                .or_else(|| nd.get("name").and_then(|v| v.as_str()))?;
            if id.eq_ignore_ascii_case(name) { Some(nd.clone()) } else { None }
        })
    })
}

/// NotAfter (unix secs) of a PEM cert on disk; None on any parse trouble.
fn cert_not_after_unix(path: &Path) -> Option<i64> {
    let data = std::fs::read(path).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data).ok()?;
    let cert = pem.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// Deliver an already-built signed bundle to `node`: pull-first, gate
/// fallback. `expected_not_after` (when known) upgrades a pull collection to
/// Verified once the node's heartbeat reports it is presenting a cert with
/// that expiry.
/// Did the node run noo-apply on the CURRENTLY staged bundle and report
/// success? Compares the reported sha against the staged one, so a stale
/// report from a previous bundle can never be read as proof for this one.
fn applied_ok(g: &Globals, node: &str) -> bool {
    let Some(st) = crate::http::get_json_opt(
        g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10) else {
        return false;
    };
    let staged = st.get("sha256").and_then(|v| v.as_str());
    let applied = st.get("applied_sha").and_then(|v| v.as_str());
    let rc = st.get("apply_rc").and_then(|v| v.as_i64());
    matches!((staged, applied, rc), (Some(s), Some(a), Some(0)) if s == a)
}

/// The node ran noo-apply on the CURRENTLY staged bundle and reported a
/// NON-zero exit: the refusal, in words, or None (not reported yet / ok /
/// a stale report for an earlier bundle). Exit 76 is the applier saying a
/// kind is newer than it is; before this was read, that report sat in the
/// status row while the delivery loop waited out its window and printed
/// "STAGED only", and noo-fetch (which records the refused sha, so it stops
/// retrying) went quiet for good.
fn apply_refusal(st: &serde_json::Value, node: &str) -> Option<String> {
    let staged = st.get("sha256").and_then(|v| v.as_str())?;
    let applied = st.get("applied_sha").and_then(|v| v.as_str())?;
    let rc = st.get("apply_rc").and_then(|v| v.as_i64())?;
    if staged != applied || rc == 0 {
        return None;
    }
    if rc == 76 {
        return Some(format!(
            "the node refused the bundle (noo-apply exit 76) — its applier is too old for this kind; \
             run `noo cluster upgrade-applier {node}`"));
    }
    let msg = st.get("apply_msg").and_then(|v| v.as_str()).unwrap_or("").trim();
    Some(format!("the node's noo-apply failed (exit {rc}){}",
        if msg.is_empty() { String::new() } else { format!(": {msg}") }))
}

/// Has this node EVER reported an apply? Distinguishes an agent that simply
/// has not applied yet from one whose build predates apply reporting — the
/// second is the only case allowed to fall back to a weaker signal.
fn node_reports_applies(g: &Globals, node: &str) -> bool {
    crate::http::get_json_opt(
        g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
        .and_then(|st| st.get("applied_at").map(|v| !v.is_null()))
        .unwrap_or(false)
}

/// How long a delivery waits for the node to FETCH a staged bundle. An idle
/// node's noo-fetch timer (60 s + jitter, ~70 s a tick) fetches every 3rd tick
/// — ~210 s — when no poke lands, so the window is two such cadences.
pub(crate) const FETCH_WAIT: Duration = Duration::from_secs(420);
const POLL_STEP: Duration = Duration::from_secs(10);

/// Probe every `step` until `probe` yields a value or `total` of waiting is
/// spent. The probe runs first (a result already there is not slept on) and
/// the budget counts the sleeps, so a test with a no-op `sleep` is exact.
pub(crate) fn poll_until<T>(
    total: Duration,
    step: Duration,
    sleep: &mut dyn FnMut(Duration),
    probe: &mut dyn FnMut() -> Option<T>,
) -> Option<T> {
    let mut waited = Duration::ZERO;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if waited >= total {
            return None;
        }
        sleep(step);
        waited += step;
    }
}

/// Has the node collected the CURRENT staging? `fetched_at` (the node's signed
/// fetch receipt; reset on every stage), or an apply report for exactly the
/// staged sha — which proves a fetch even where the receipt was not stamped.
pub(crate) fn fetch_seen(st: &serde_json::Value) -> bool {
    if st.get("fetched_at").and_then(|v| v.as_str()).is_some() {
        return true;
    }
    match (st.get("sha256").and_then(|v| v.as_str()), st.get("applied_sha").and_then(|v| v.as_str())) {
        (Some(staged), Some(applied)) => staged == applied,
        _ => false,
    }
}

pub(crate) fn deliver_signed_bundle(
    g: &Globals,
    node: &str,
    bundle: &Path,
    work: &Path,
    expected_not_after: Option<i64>,
) -> CertDelivery {
    // Gateway reachability, NON-fatally: the certs are already re-issued on
    // disk by the time delivery runs, and the http helpers under
    // stage_bundle_pull hard-exit on an unreachable gateway — which would
    // kill the command mid-report. Unreachable = a delivery failure to
    // record, not a reason to die.
    if crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10).is_none() {
        return CertDelivery::Failed(
            "gateway unreachable — cert re-issued locally only; re-run when it is back".into(),
        );
    }
    // Staging-slot collision guard: one row per node. A pending
    // (staged-but-unfetched) PROVISION bundle must not be clobbered by a
    // cert refresh — the node would lose its provisioning.
    if let Some(st) = crate::http::get_json_opt(
        g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
    {
        if st.get("staged_at").and_then(|v| v.as_str()).is_some()
            && st.get("fetched_at").map(|v| v.is_null()).unwrap_or(false)
        {
            return CertDelivery::SkippedPending;
        }
    }

    match crate::commands::provision::stage_bundle_pull(g, node, bundle, work) {
        Some(Ok(())) => {
            // Ask the node to fetch NOW over the bus (best effort), then wait
            // for it. An idle node's timer only fetches every 3rd tick
            // (~3-5 min; noo-fetch.sh's steady-state throttle), so the old
            // 180 s window with no poke printed "STAGED only" for nodes that
            // fetched and applied a minute later (host3, v0.2.93 roll). The
            // window is two idle cadences, and an apply report counts as a
            // fetch even when the fetch receipt could not be stamped.
            crate::commands::provision::poke_fetch(g, node);
            let status_path = format!("/api/cluster/provision-bundle/{node}/status");
            let fetched = poll_until(FETCH_WAIT, POLL_STEP, &mut |d| std::thread::sleep(d), &mut || {
                let st = crate::http::get_json_opt(g, &status_path, true, 10)?;
                fetch_seen(&st).then_some(())
            }).is_some();
            if !fetched {
                return CertDelivery::Staged;
            }
            // Fetched is NOT delivered (#83). Two positive proofs, in
            // order of strength, and a fetch alone is neither:
            //
            //   1. the heartbeat reports the served cert's NotAfter matching
            //      what we just issued — the node IS presenting it;
            //   2. the node ran noo-apply on this exact bundle and reported
            //      exit 0.
            //
            // The old code fell through to `Collected` — which `ok()` counts
            // as delivered — when neither arrived inside the window. A
            // TIMEOUT was therefore indistinguishable from a success, which
            // is the same defect fu72 #6 fixed one layer up: rotation that
            // reports delivery it cannot demonstrate. A timeout is `FetchedUnconfirmed`
            // (never `ok()`; `Staged` is only for a bundle nobody collected).
            //
            // The "online implies collected" inference is gone for any node
            // that reports applies. It was never sound — node status is
            // asserted by the node's own outbound heartbeat, so a node whose
            // INBOUND connections all fail still reads online (host9,
            // 2026-09-04: online for hours while every request to it failed
            // on a rejected handshake). It survives only for agents too old
            // to report an apply, where nothing better exists.
            let legacy_agent = !node_reports_applies(g, node);
            let vstart = Instant::now();
            while vstart.elapsed() < Duration::from_secs(150) {
                if let Some(nd) = cluster_node_entry(g, node) {
                    if let (Some(expect), Some(have)) =
                        (expected_not_after, nd.get("cert_not_after").and_then(|v| v.as_i64()))
                    {
                        if have >= expect - 60 {
                            return CertDelivery::Verified;
                        }
                    }
                }
                if applied_ok(g, node) {
                    return CertDelivery::Applied;
                }
                if let Some(why) = crate::http::get_json_opt(
                    g, &format!("/api/cluster/provision-bundle/{node}/status"), true, 10)
                    .and_then(|st| apply_refusal(&st, node))
                {
                    return CertDelivery::Failed(why);
                }
                if legacy_agent
                    && vstart.elapsed() > Duration::from_secs(60)
                    && cluster_node_entry(g, node)
                        .and_then(|nd| {
                            nd.get("status").and_then(|v| v.as_str()).map(|s| {
                                s == "online" || s == "busy"
                            })
                        })
                        .unwrap_or(false)
                {
                    return CertDelivery::Collected;
                }
                std::thread::sleep(Duration::from_secs(10));
            }
            // `fetched` is true here: the loop above returned `Staged` for a
            // node that never collected. A timeout is still not a success
            // (#83), but it is not "not fetched" either — `fetched_at` WAS
            // stamped. Say what is known: collected, outcome unreported.
            CertDelivery::FetchedUnconfirmed
        }
        Some(Err(e)) => CertDelivery::Failed(format!("pull staging failed: {e}")),
        // No birth cert on record = a node enrolled before the pull rail
        // existed. This used to fall back to `noo-gate apply` over SSH; the
        // controller no longer has a privileged path into a node (operator,
        // 2026-09-05), so the answer is to give the node a birth cert rather
        // than to reach in. Re-enrolling is the fix and it is one command.
        None => CertDelivery::Failed(
            "no birth cert on record — this node predates the pull rail and cannot \
             collect a bundle. Re-enroll it (`noo enroll` on the node) so certs \
             can be delivered over the rail.".into(),
        ),
    }
}

/// Build the cert-only bundle for `node` and deliver it
/// step). Used by rotate-all; rotate-ca drives deliver_signed_bundle with
/// its own transition bundles.
fn deliver_node_certs(g: &Globals, ca: &ClusterCa, node: &str) -> CertDelivery {
    let work = std::env::temp_dir().join(format!("noo-certs-{}-{}", node, std::process::id()));
    if std::fs::create_dir_all(&work).is_err() {
        return CertDelivery::Failed("could not create a work dir".into());
    }
    let expected = cert_not_after_unix(&ca.dir.join("nodes").join(node).join("node.crt"));
    let out = match build_signed_cert_bundle(ca, node, &work, node_takes_leaf_kinds(g, node)) {
        Ok(bundle) => deliver_signed_bundle(g, node, &bundle, &work, expected),
        Err(e) => CertDelivery::Failed(format!("bundle build failed: {e}")),
    };
    let _ = std::fs::remove_dir_all(&work);
    out
}

/// Can this node's applier take the `svc-*` leaf kinds? Reads the node's
/// reported OS and version; a node the registry cannot describe is treated
/// as able (the Linux answer, and the one that never withholds a leaf).
fn node_takes_leaf_kinds(g: &Globals, node: &str) -> bool {
    let Some(nd) = cluster_node_entry(g, node) else { return true };
    let darwin = nd.get("capabilities").and_then(|c| c.get("os")).and_then(|v| v.as_str())
        .is_some_and(|o| o.eq_ignore_ascii_case("darwin") || o.eq_ignore_ascii_case("macos"));
    let version = nd.get("app_version").and_then(|v| v.as_str()).unwrap_or("");
    crate::commands::node_leaves::applier_knows_leaf_kinds(darwin, version)
}

/// "nodes/<name>/node.crt" → Some("<name>"). A node's backend door leaf
/// ("nodes/<name>/services/<x>/service.crt") names the same node: it is
/// delivered in that node's cert bundle.
fn cert_node_name(cert_name: &str) -> Option<&str> {
    let mut parts = cert_name.split('/');
    if parts.next() == Some("nodes") { parts.next() } else { None }
}

/// Non-fatal interactive y/N (stderr prompt, default No). False on any
/// non-TTY/read trouble — optional offers must never block a pipe.
fn ask_yn(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};
    if unsafe { libc::isatty(0) } != 1 {
        return false;
    }
    eprint!("{prompt} [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Finding #108 (live, first CA rotation): the controller's SELF-AGENT
/// reads its trust plane from /etc/noo/pki — the same node-shaped anchor
/// remote nodes get via bundles — and NOTHING synced it after a local
/// re-issue: the agent kept the old CA, the gateway presented a new-CA
/// leaf, TLS died, and the controller showed OFFLINE in its own status.
/// Quiet sudo; manual recipe on failure (the #106 posture).
fn sync_self_agent_trust_plane(ca: &ClusterCa, hostname: &str, json: bool) -> bool {
    let etc_node = format!("/etc/noo/pki/nodes/{hostname}");
    if !std::path::Path::new("/etc/noo/pki").is_dir() {
        return true; // no host trust plane (no self-agent) — nothing to sync
    }
    let script = format!(
        "install -m 640 -g noo-agent '{ca_crt}' /etc/noo/pki/ca.crt && \
         mkdir -p '{etc_node}' && \
         install -m 640 -g noo-agent '{crt}' '{etc_node}/node.crt' && \
         install -m 640 -g noo-agent '{key}' '{etc_node}/node.key'",
        ca_crt = ca.ca_cert_path().display(),
        crt = ca.dir.join("nodes").join(hostname).join("node.crt").display(),
        key = ca.dir.join("nodes").join(hostname).join("node.key").display(),
    );
    let ok = Command::new("sudo").args(["-n", "sh", "-c", &script])
        .stdin(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    if ok {
        if !json {
            ui::done("self-agent trust plane synced (/etc/noo/pki)");
        }
    } else if !json {
        ui::warned("self-agent trust plane NOT synced (sudo needs a password): the agent goes offline until you run");
        let nodes = ca.dir.join("nodes").join(hostname);
        for cmd in [
            format!("sudo install -m 640 -g noo-agent {} /etc/noo/pki/ca.crt", ca.ca_cert_path().display()),
            format!("sudo install -m 640 -g noo-agent {}/node.crt {etc_node}/node.crt", nodes.display()),
            format!("sudo install -m 640 -g noo-agent {}/node.key {etc_node}/node.key", nodes.display()),
            "sudo systemctl restart noo-node-agent".to_string(),
        ] {
            println!("    {}", ui::cmd(&cmd));
        }
    }
    ok
}

/// Is `unit` a real unit on this host? (`systemctl cat` exits 0 for any
/// loaded/loadable unit, container-only controllers have none.)
fn systemd_unit_known(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["cat", unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Restart a host unit (plain systemctl first — we may BE root under the
/// watcher — sudo -n fallback), then poll is-active. push-nodes' remote
/// recipe, localized
/// "No running consumers" success on every systemd controller).
fn systemd_restart_unit(unit: &str) -> bool {
    // Finding #106 (live 2026-08-28): a plain `systemctl restart` of a
    // SYSTEM unit as a user triggers polkit's INTERACTIVE auth — a
    // password prompt erupting mid-rotation, then a timeout. Order:
    // root runs systemctl directly; everyone else tries `sudo -n`
    // (quiet, never prompts); failure is reported for a manual restart,
    // never a surprise prompt.
    let am_root = unsafe { libc::geteuid() } == 0;
    let restarted = if am_root {
        Command::new("systemctl").args(["restart", unit]).status()
            .map(|s| s.success()).unwrap_or(false)
    } else {
        Command::new("sudo").args(["-n", "systemctl", "restart", unit])
            .stdin(std::process::Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    };
    if !restarted {
        ui::warned(&format!("could not restart {unit} without prompting"));
        ui::guide(&[(&format!("sudo systemctl restart {unit}"), "restart it yourself; this box's sudo is the operator's")]);
        return false;
    }
    for _ in 0..20 {
        if Command::new("systemctl").args(["is-active", "--quiet", unit]).status()
            .map(|s| s.success()).unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// The node's tailnet IP as the cluster registry has it (a `100.x` address).
///
/// Resolve the device OFF THE TAILNET'S OWN KNOWLEDGE (finding #52c): the
/// recorded enrollment address can be the docker bridge (#52b), but the
/// agent registered with its true tailnet IP, so the cluster table is the
/// reliable source. Read it BEFORE anything forgets the node — forgetting
/// removes the row this reads.
pub(crate) fn registered_tailnet_ip(g: &Globals, name: &str) -> Option<String> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|doc| {
            doc.get("nodes")?.as_array()?.iter().find_map(|nd| {
                let id = nd.get("id").and_then(|v| v.as_str())
                    .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                    .or_else(|| nd.get("name").and_then(|v| v.as_str()))?;
                if id.eq_ignore_ascii_case(name) {
                    nd.get("ip").and_then(|v| v.as_str()).map(str::to_string)
                } else {
                    None
                }
            })
        })
        .filter(|ip| ip.starts_with("100."))
}

/// Delete a node's device record from the tailnet through the gateway
/// (`POST /api/cluster/delete-tailscale-device`), matched by `ip` when known
/// and by the node NAME otherwise (the name is adopted, so the Tailscale
/// hostname may differ — the IP is the better key). Returns one line for the
/// operator; a failure names the console as the fallback rather than failing
/// the verb that called it.
pub(crate) fn delete_tailnet_device(g: &Globals, name: &str, ip: Option<&str>) -> String {
    let mut body = serde_json::json!({"hostname": name});
    if let Some(ip) = ip.filter(|s| !s.is_empty()) {
        body["ip"] = serde_json::Value::String(ip.to_string());
    }
    match crate::http::post_json_try(g, "/api/cluster/delete-tailscale-device", &body, true, 30) {
        Ok(v) => match v["status"].as_str().unwrap_or("") {
            "deleted" => format!("device removed from tailnet ({})",
                v["device_name"].as_str().unwrap_or(name)),
            "not_found" => "device already gone from tailnet".to_string(),
            _ => "device deletion returned an unexpected status".to_string(),
        },
        Err(e) => format!("NOT removed ({e}) — delete it in the Tailscale admin console"),
    }
}

/// `noo cluster teardown-node <node> [--yes]` — graceful node destroy
/// (operator, 2026-08-18). Stages a CA-signed `teardown` bundle on the pull
/// rail: the node dismantles ITSELF (agent, trust, noo-agent), detached,
/// after fetching and acking. Then clears the controller-side state (certs,
/// inventory line). The controller has no privileged path into a node
/// (operator, 2026-09-05), so there is no fallback lane to run a remote
/// teardown over — this is the sanctioned path, and it never touches user
/// data on the node. A node with no birth cert on record predates the pull
/// rail and must be re-enrolled before it can be torn down this way.
pub fn cluster_teardown_node(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<String> = None;
    let mut all = false;
    let mut yes = false;
    let mut purge_data = false;
    let mut purge_ts = false;
    for tok in args {
        match tok.as_str() {
            "-y" | "--yes" => yes = true,
            // Every enrolled node except this box, one confirmation, one
            // tailnet answer
            // three fetch waits and three prompts on the pre-walk teardown).
            "--all" => all = true,
            // Also delete the node's data root (models/caches). Off by
            // default — a rebirth usually WANTS the cached models.
            "--purge-data" => purge_data = true,
            // Also uninstall tailscale — but noo-apply only acts on it if
            // the node's marker says PAI installed it (never a pre-existing
            // one). docker/nvidia are deliberately not offered: pre-existing,
            // high blast radius.
            "--purge-tailscale" => purge_ts = true,
            // Everything: de-enroll + data + tailscale. The full reversal.
            "--factory" => { purge_data = true; purge_ts = true; }
            t if !t.starts_with('-') && node.is_none() => node = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    if all {
        if node.is_some() { return Err(Unhandled); }
        let me = crate::role::detect().node.map(|n| n.name);
        let inventory = fleet_nodes_from_registry(g);
        let targets: Vec<(String, String, String)> = inventory.iter()
            .filter(|(n, _, _)| !me.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(n)))
            .cloned()
            .collect();
        if targets.is_empty() {
            crate::output::fail(g.json, crate::output::ExitCode::Generic, "no_nodes",
                "no enrolled nodes to tear down (this box is never included — `noo offboard` dismantles a controller)", None);
        }
        let names: Vec<&str> = targets.iter().map(|(n, _, _)| n.as_str()).collect();
        super::confirm_destructive(g, yes, "tear down (dismantle the agent on) ALL of", &names.join(", "));
        // One tailnet answer for the whole fleet, asked up front so the loop
        // never blocks between nodes; --purge-tailscale makes it yes.
        let ts_answer = if purge_ts || g.json { Some(purge_ts) } else {
            Some(ask_yn("Also delete each node's device record from the tailnet once it is confirmed gone? \
                         (otherwise the next enroll re-registers as <name>-1, -2, …)"))
        };
        let mut worst = 0;
        let mut rows: Vec<(String, String)> = Vec::new();
        for (name, host, _) in &targets {
            println!("{}", ui::section(&format!("Teardown  {name}")));
            let rc = teardown_one(g, name, host, purge_data, purge_ts, ts_answer)?;
            worst = worst.max(rc);
            rows.push((name.clone(), if rc == 0 { "dismantled".to_string() } else { ui::warn("still alive — see above") }));
        }
        if !g.json {
            println!("{}", ui::section("Fleet teardown"));
            let refs: Vec<(&str, String)> = rows.iter().map(|(n, r)| (n.as_str(), r.clone())).collect();
            eprint!("{}", ui::kv(&refs));
        }
        return Ok(worst);
    }
    let Some(node) = node else { return Err(Unhandled) };
    let inventory = fleet_nodes_from_registry(g);
    let Some((name, host, _)) = inventory.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(&node)).cloned() else {
        // The inventory name is the NODE name (what enroll bound), not the
        // tailnet hostname — `host3` vs `host3-wsl` cost a retry on
        // 2026-09-01. List what IS known instead of pointing at the file.
        let known: Vec<&str> = inventory.iter().map(|(n, _, _)| n.as_str()).collect();
        let hint = if known.is_empty() {
            "the node inventory is empty".to_string()
        } else {
            format!("known nodes: {}", known.join(", "))
        };
        crate::output::fail(g.json, crate::output::ExitCode::Generic, "no_node",
            &format!("'{node}' is not an enrolled node ({hint})"), None);
    };
    super::confirm_destructive(g, yes, "tear down (dismantle the agent on)", &name);
    teardown_one(g, &name, &host, purge_data, purge_ts, None)
}

/// The node's `capabilities.os` as its agent last reported it (linux /
/// darwin). Read BEFORE the teardown is staged: once the node is gone the
/// registry no longer knows. None for an older agent that sent no map.
fn node_os(g: &Globals, name: &str) -> Option<String> {
    crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|doc| {
            doc.get("nodes")?.as_array()?.iter().find_map(|nd| {
                let id = nd.get("id").and_then(|v| v.as_str())
                    .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                    .or_else(|| nd.get("name").and_then(|v| v.as_str()))?;
                if !id.eq_ignore_ascii_case(name) { return None; }
                nd.get("capabilities")?.get("os")?.as_str().map(|o| o.to_ascii_lowercase())
            })
        })
}

/// What to run on the box when a collected teardown did not dismantle it.
/// The linux hint is `noo-deenroll`; a Mac has neither that nor a cgroup
/// story — it has two LaunchDaemons and an identity tree.
fn dismantle_hint(name: &str, os: Option<&str>) -> Vec<(String, String)> {
    if os == Some("darwin") {
        vec![
            ("sudo launchctl bootout system/net.noomesh.node-agent; sudo launchctl bootout system/net.noomesh.fetch".to_string(),
             "on the Mac: stop both daemons (a fetcher older than noo-cli 0.5.4 accepts the teardown kind and ignores it)".to_string()),
            ("sudo rm -f /Library/LaunchDaemons/net.noomesh.*.plist; rm -rf ~/noomesh; tailscale logout".to_string(),
             "on the Mac: remove the plists, the identity tree and the tailnet login".to_string()),
            (format!("noo cluster forget {name}"), "then on the controller: clear the row it kept".to_string()),
        ]
    } else {
        vec![("sudo noo-deenroll".to_string(), "on the node: dismantles it by hand when the fetched teardown did not run".to_string())]
    }
}

/// One node's teardown: stage on the rail, wait for the fetch, verify the
/// heartbeats stop, then the controller-side cleanup. `ts_answer` is the
/// tailnet-device decision when the caller already has one (`--all`).
fn teardown_one(g: &Globals, name: &str, host: &str, purge_data: bool, purge_ts: bool, ts_answer: Option<bool>) -> Result<i32, Unhandled> {
    let name = name.to_string();
    let host = host.to_string();
    let os = node_os(g, &name);
    let mut purge_ts = purge_ts;
    if crate::role::is_self_node(&name) {
        ui::warned(&format!("'{name}' is THIS box: the agent you are dismantling is the one under your feet"));
        if purge_ts {
            // This device's tailnet identity is the CONTROLLER's
            // (tag:controller); leaving the tailnet would strand the fleet.
            ui::warned("--purge-tailscale ignored for the controller's own device: its tailnet identity is the controller's, not the node's");
            purge_ts = false;
        }
    }

    let ca = crate::pki::ClusterCa::new(pki_dir());
    let work = std::env::temp_dir().join(format!("noo-teardown-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&work);
    let mut directives: Vec<&str> = Vec::new();
    if purge_data { directives.push("purge-data"); }
    if purge_ts { directives.push("purge-tailscale"); }
    let payload = if directives.is_empty() {
        name.clone()
    } else {
        format!("{name}\n{}", directives.join(","))
    };
    let mut via_pull = false;
    let sent = match build_signed_bundle(&ca, &name, &[("teardown", payload.into_bytes())], &work) {
        // PULL delivery first (finding #52): a pull-only node has NO pinned
        // controller key by design (#47), so the SSH/gate lane can never
        // reach it — and the recorded enrollment address may be the docker
        // bridge (172.18.0.1: the gateway container's view of the redeem),
        // i.e. the controller itself. Death rides the same rail as birth:
        // encrypt the directive to the birth cert, stage it, let noo-fetch
        // collect it. A node with no birth cert must be re-enrolled — the
        // controller has no SSH path to fall back to.
        Ok(bundle) => match crate::commands::provision::stage_bundle_pull(g, &name, &bundle, &work) {
            Some(Ok(())) => {
                via_pull = true;
                ui::done(&format!("teardown staged on the pull rail  {}", ui::muted(&format!("{name}'s fetch cadence is ~60s"))));
                true
            }
            // No gate lane to fall back to. Both of these are real
            // failures now, and saying so beats reaching in: a staging
            // failure is the gateway's problem, and a node with no birth
            // cert predates the rail and must be re-enrolled.
            Some(Err(e)) => {
                ui::failed(&format!("pull staging failed: {e}"), None);
                false
            }
            None => {
                ui::failed(
                    &format!("{name} has no birth cert on record — it predates the pull rail \
                              and cannot collect a teardown bundle"),
                    Some("re-enroll it (`noo enroll` on the node), then tear it down"),
                );
                false
            }
        },
        Err(e) => { let _ = std::fs::remove_dir_all(&work);
            crate::output::fail(g.json, crate::output::ExitCode::Generic, "bundle_failed", &e, None); }
    };
    let _ = std::fs::remove_dir_all(&work);
    if !sent {
        crate::output::fail(g.json, crate::output::ExitCode::Generic, "teardown_undelivered",
            &format!("could not stage the teardown bundle for {name} on the pull rail"), None);
    }

    // The teardown RIDES the tailnet (finding #77, live on host4
    // 2026-08-27): deleting the node's device before it has FETCHED the
    // bundle cuts the transport out from under the very directive that
    // dismantles it — the node survived intact, stranded off-mesh, and the
    // closer claimed "delivered". Once fetched, the apply is purely local,
    // so wait for fetched_at (v0.1.81 status route) before touching
    // anything the node still needs.
    let mut fetched = !via_pull; // no gate lane exists any more; this is only true when staging itself failed
    if via_pull {
        let mut poll = ui::Poll::start(&format!("waiting for {name} to fetch the teardown before cutting its transport (4 min max)"));
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(240);
        while std::time::Instant::now() < deadline {
            if let Some(st) = crate::http::get_json_opt(
                g, &format!("/api/cluster/provision-bundle/{name}/status"), true, 10)
            {
                if st.get("fetched_at").and_then(|v| v.as_str()).is_some() {
                    fetched = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
            poll.tick(started.elapsed().as_secs());
        }
        if fetched {
            poll.done(&format!("{name} fetched the teardown: dismantling is local from here"));
        } else {
            poll.warned(&format!("{name} has not fetched the teardown after 240s"));
            println!("{}", ui::note("its tailnet device is kept so it still can; an older gateway without the status route reports the same way"));
            ui::guide(&[
                ("noo cluster status", "shows whether the node has gone quiet; re-check before removing its tailnet device"),
                ("noo cluster forget <node>", "controller-side cleanup once the node is confirmed gone"),
            ]);
        }
    }

    // Finding #83: "collected" is a FETCH signal, not an APPLY signal — the
    // node downloaded the bundle, and then (for every pull teardown before
    // the noo-apply cgroup fix) the dismantle died silently while this
    // closer declared victory. Fetched is necessary but not sufficient:
    // verify the dismantle by watching the node's heartbeats STOP. A node
    // still heartbeating is still alive, whatever the bundle status says.
    let mut dismantled = false;
    if fetched {
        let vstart = std::time::Instant::now();
        let vdeadline = vstart + std::time::Duration::from_secs(240);
        // One live line (TTY) / one line per minute (piped) — guide §5 Rhythm.
        let mut vpoll = ui::Poll::start(&format!("verifying the dismantle: waiting for {name}'s heartbeats to stop (up to 240s)"));
        while std::time::Instant::now() < vdeadline {
            let alive = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
                .and_then(|doc| {
                    doc.get("nodes")?.as_array()?.iter().find_map(|nd| {
                        let id = nd.get("id").and_then(|v| v.as_str())
                            .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                            .or_else(|| nd.get("name").and_then(|v| v.as_str()))?;
                        if id.eq_ignore_ascii_case(&name) {
                            nd.get("status").and_then(|v| v.as_str()).map(str::to_string)
                        } else {
                            None
                        }
                    })
                });
            match alive.as_deref() {
                // Gone from the view, or aged into a dead bucket: stopped.
                None | Some("offline") | Some("unknown") => {
                    dismantled = true;
                    vpoll.done(&format!("{name} stopped heartbeating: dismantle confirmed"));
                    break;
                }
                _ => {}
            }
            vpoll.tick(vstart.elapsed().as_secs());
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
        if !dismantled {
            let why = if os.as_deref() == Some("darwin") {
                "a Mac fetcher older than noo-cli 0.5.4 accepts the teardown kind and ignores it; \
                 re-provision it on a newer CLI before the next teardown"
            } else {
                "a pre-#83 noo-apply loses the detached dismantle to the noo-fetch cgroup; \
                 upgrading the stack fixes future teardowns"
            };
            ui::close_warned(&format!("{name} is STILL HEARTBEATING 240s after collecting the teardown: \
                       the dismantle did NOT run ({why})"));
            let hint = dismantle_hint(&name, os.as_deref());
            let refs: Vec<(&str, &str)> = hint.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            ui::guide(&refs);
        }
    }

    let node_pki = ca.dir.join("nodes").join(&name);
    let _ = std::fs::remove_dir_all(&node_pki);
    // (the node's ansible/inventory row used to be stripped here; that
    // file went with the playbook tree in 3695e129 — the gateway registry
    // is what `noo cluster forget` clears)

    // Delete the node's tailnet device via the gateway (which owns the
    // Tailscale credential — OAuth client preferred, personal key fallback;
    // the CLI never sees it). Gated on --purge-tailscale/--factory: a plain
    // teardown deliberately keeps the node's tailscale footprint. The node's
    // inventory host IS its 100.x tailnet IP, which is the stable match key
    // (the PAI name is adopted and decoupled from the tailscale hostname).
    let ts_device: String = if purge_ts && !dismantled {
        "device KEPT — the node has not collected its teardown yet and still needs the \
         tailnet to do so; remove it in the console once the node is gone".to_string()
    } else if purge_ts {
        // Resolve the device OFF THE TAILNET'S OWN KNOWLEDGE (finding #52c):
        // the recorded enrollment address can be the docker bridge (see
        // #52b), but the AGENT registered with its true tailnet IP — the
        // cluster table is the reliable source. The recorded host stays as
        // a fallback candidate; the node NAME rides along for hostname
        // matching (name is adopted, hostname may differ).
        let ip = registered_tailnet_ip(g, &name).unwrap_or_else(|| host.clone());
        delete_tailnet_device(g, &name, Some(&ip))
    } else if dismantled && !g.json && match ts_answer {
        Some(a) => a,
        None => ask_yn(&format!(
            "Also delete {name}'s device record from the tailnet? (offboard offers the same; \
             otherwise the next enroll re-registers as {name}-1, -2, …)")),
    } {
        // Finding #94: offboard OFFERS device deletion, teardown silently
        // required --purge-tailscale — the operator noticed the asymmetry
        // on the first verified dismantle. Same resolution path as the
        // purge branch above.
        let ip = registered_tailnet_ip(g, &name).unwrap_or_else(|| host.clone());
        delete_tailnet_device(g, &name, Some(&ip))
    } else {
        "device left in tailnet (declined / non-interactive; --purge-tailscale forces it)".to_string()
    };

    // Forget the node controller-side (finding #76): DB row + mesh KV, via
    // the agent-less forget route — the old closer said "still yours: clear
    // the cluster DB row" without naming a command, because none existed.
    // Gated on `dismantled` (#77, tightened by #83): a node that is still
    // heartbeating re-registers on its next beat anyway — forgetting it
    // would just fake the cleanup the dismantle failed to do.
    let forgot = if dismantled {
        crate::http::delete_json_try(
            g, &format!("/api/cluster/nodes/{name}/forget"), true, 15)
    } else {
        Err("teardown not yet collected".to_string())
    };
    let db_note = match &forgot {
        Ok(_) => "DB row + mesh entry cleared — the name is first-contact fresh".to_string(),
        Err(e) if !dismantled => format!("DB row kept ({e}) — forget it after the node dismantles"),
        Err(e) => format!("DB row NOT cleared ({e}) — an older gateway lacks the \
                           forget route; it ages out of the mesh view on its own"),
    };

    if g.json {
        println!("{}", serde_json::json!({"status":"ok","node":name,"tailscale_device":ts_device,
            "fetched": fetched, "dismantled": dismantled,
            "forgotten": forgot.is_ok(),
            "note":"node dismantling itself; certs+inventory cleared"}));
    } else {
        if dismantled {
            ui::done(&format!("{name}: teardown verified: collected, and the node stopped heartbeating"));
        } else if fetched {
            ui::warned(&format!("{name}: teardown collected but the node is STILL ALIVE: dismantle it on the box"));
            let hint = dismantle_hint(&name, os.as_deref());
            let refs: Vec<(&str, &str)> = hint.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            ui::guide(&refs);
        } else {
            ui::warned(&format!("{name}: teardown staged but not yet collected: the node keeps its tailnet access until it fetches it"));
        }
        eprint!(
            "{}",
            ui::kv(&[
                ("  data root", if purge_data { ui::warn("purged") } else { "kept (models/caches)".to_string() }),
                ("  tailscale (node)", (if purge_ts { "uninstall requested (only if PAI installed it)" } else { "logged out, package kept" }).to_string()),
                ("  tailscale (tailnet)", ts_device.to_string()),
                ("  controller-side", "certs removed, inventory line dropped".to_string()),
                ("  cluster registry", db_note.clone()),
            ])
        );
    }
    // 0 only when the dismantle was VERIFIED (heartbeats stopped); a staged
    // or collected-but-alive node is 1 so `--all` and scripts can tell.
    Ok(if dismantled { 0 } else { 1 })
}

/// First PEM block of a (possibly concatenated) PEM file.
fn first_pem_block(pem: &str) -> Option<String> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let end_marker = "-----END CERTIFICATE-----";
    let end = pem[start..].find(end_marker)? + start + end_marker.len();
    Some(pem[start..end].to_string() + "\n")
}

/// `noo security pki rotate-ca [--ca-days N] [--leaf-days N] [--yes]
/// [--retire-old]` — REAL cross-signed CA rotation
/// header promised this for months while nothing could produce it, and a
/// bare CA regen bricked both delivery rails with exit 77 fleet-wide).
///
/// Trust-union transition, hard-gated at every step:
///   1. Mint the next CA into pki/ca-next (idempotent — a partial run
///      resumes with the same CA).
///   2. Per remote node: re-issue its leaf UNDER THE NEW CA, and ship a
///      transition bundle {ca.crt = NEW||OLD concat, node.crt, node.key}
///      signed with the OLD key — verified by the anchor the node already
///      trusts, exactly the contract noo-apply documents. After install the
///      node trusts BOTH CAs (Go/curl load the whole PEM pool) and future
///      bundles verify against the FIRST cert in the file: the new one.
///   3. Only when EVERY node's delivery lands: promote locally — anchor
///      NEW||OLD in, new key in, old pair backed up (+ pki/ca-old.crt kept
///      for --retire-old), local leaves re-issued under the new CA, local
///      consumers reloaded. Any node failing = NOTHING promotes; re-run.
///   4. Later, `--retire-old` ships a NEW-only anchor everywhere and drops
///      the old cert from the local anchor — after verifying every leaf on
///      disk chains to the new CA alone.
pub fn pki_rotate_ca(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut ca_days: i64 = 3650;
    let mut leaf_days: i64 = crate::pki::DEFAULT_DAYS;
    let mut yes = false;
    let mut retire_old = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--ca-days" => ca_days = iter.next().and_then(|v| v.parse().ok()).filter(|d: &i64| *d > 0).ok_or(Unhandled)?,
            "--leaf-days" => leaf_days = iter.next().and_then(|v| v.parse().ok()).filter(|d: &i64| *d > 0).ok_or(Unhandled)?,
            "--force" | "--yes" | "-y" => yes = true,
            "--retire-old" => retire_old = true,
            _ => return Err(Unhandled),
        }
    }

    let ca = ClusterCa::new(pki_dir());
    if !ca.ca_exists() {
        fail(g.json, ExitCode::Generic, "no_ca",
            "no cluster CA found — run 'noo security pki init' (or 'noo onboard') first", None);
    }
    if retire_old {
        return rotate_ca_retire(g, &ca, yes);
    }

    let hostname = local_hostname();
    let nodes_dir = ca.dir.join("nodes");
    let remote_nodes: Vec<String> = std::fs::read_dir(&nodes_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().join("node.crt").exists())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| !n.eq_ignore_ascii_case(&hostname))
                .collect()
        })
        .unwrap_or_default();

    if !g.json {
        println!("{}", ui::emph("CA rotation (cross-signed transition)"));
        eprint!(
            "{}",
            ui::kv(&[
                ("  new CA lifetime", format!("{ca_days} days")),
                ("  re-issued leaves", format!("{leaf_days} days")),
                ("  nodes to transition", if remote_nodes.is_empty() { ui::muted("none") } else { remote_nodes.join(", ") }),
            ])
        );
        println!("  {}", ui::muted("nothing on this controller changes until every node confirms"));
    }
    super::confirm_destructive(g, yes, "rotate the cluster CA (transition every node to", "a new CA)");

    // 1. Next CA — idempotent across partial runs.
    let next = ClusterCa::new(ca.dir.join("ca-next"));
    if !next.ca_exists() {
        if let Err(e) = next.generate_ca("Mesh Cluster CA", ca_days) {
            fail(g.json, ExitCode::Generic, "ca_mint", &format!("could not mint the next CA: {e}"), None);
        }
        if !g.json {
            ui::done(&format!("next CA minted at {}", next.dir.display()));
        }
    } else if !g.json {
        println!("{}", ui::status_line(Glyph::Bullet, &format!("resuming with the next CA already at {}", next.dir.display())));
    }

    let new_pem = std::fs::read_to_string(next.ca_cert_path()).unwrap_or_default();
    let old_pem = std::fs::read_to_string(ca.ca_cert_path()).unwrap_or_default();
    if new_pem.is_empty() || old_pem.is_empty() {
        fail(g.json, ExitCode::Generic, "ca_read", "could not read CA certs", None);
    }
    // NEW first: noo-apply (and every future verifier) reads the FIRST cert
    // in the anchor file, so post-transition bundles are signed by the new
    // key; TLS stacks load the whole pool and trust both during transition.
    let transition_anchor = format!("{}\n{}", new_pem.trim_end(), old_pem.trim_start());

    // 2. Per-node: re-issue the leaf under the NEW CA, ship the transition
    //    bundle signed with the OLD key.
    let mut outcomes: Vec<(String, CertDelivery)> = Vec::new();
    if !g.json && !remote_nodes.is_empty() {
        println!("{}", ui::phase("transition nodes"));
    }
    for node in &remote_nodes {
        if !g.json {
            println!("{}", ui::item(node));
            println!("{}", ui::sub(&ui::status_line(Glyph::Step, "transition bundle (new-CA leaf, old-key signature)")));
        }
        let next_node_dir = next.dir.join("nodes").join(node);
        let _ = std::fs::create_dir_all(&next_node_dir);
        let src_dir = nodes_dir.join(node);
        let outcome = (|| -> Result<CertDelivery, String> {
            for f in ["node.crt", "node.key"] {
                std::fs::copy(src_dir.join(f), next_node_dir.join(f))
                    .map_err(|e| format!("copy {f}: {e}"))?;
            }
            next.reissue_in_place(&next_node_dir.join("node.crt"), leaf_days, &crate::pki::NodeRole::Worker)
                .map_err(|e| format!("re-issue under next CA: {e}"))?;
            let work = std::env::temp_dir()
                .join(format!("noo-rotate-ca-{}-{}", node, std::process::id()));
            std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
            let files: Vec<(&str, Vec<u8>)> = vec![
                ("ca.crt", transition_anchor.clone().into_bytes()),
                ("node.crt", std::fs::read(next_node_dir.join("node.crt")).map_err(|e| e.to_string())?),
                ("node.key", std::fs::read(next_node_dir.join("node.key")).map_err(|e| e.to_string())?),
            ];
            // Signed with the OLD key (`ca`, not `next`) — the one anchor
            // the node can verify TODAY. That is the cross-sign.
            let bundle = build_signed_bundle(&ca, node, &files, &work)?;
            let expected = cert_not_after_unix(&next_node_dir.join("node.crt"));
            let d = deliver_signed_bundle(g, node, &bundle, &work, expected);
            let _ = std::fs::remove_dir_all(&work);
            Ok(d)
        })()
        .unwrap_or_else(CertDelivery::Failed);
        if !g.json {
            delivery_line(node, &outcome);
        }
        outcomes.push((node.clone(), outcome));
    }

    let blocked: Vec<&String> = outcomes.iter().filter(|(_, d)| !d.ok()).map(|(n, _)| n).collect();
    if !blocked.is_empty() {
        let detail = format!(
            "{} node(s) did not confirm the transition: {} — NOTHING was promoted; \
             this controller still runs the old CA. Fix the nodes (or teardown/forget \
             truly dead ones) and re-run `noo security pki rotate-ca` — it resumes \
             with the same next CA.",
            blocked.len(),
            blocked.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
        fail(g.json, ExitCode::Generic, "transition_incomplete", &detail, None);
    }

    // 3. Promote. Every node now trusts both CAs and presents a new-CA leaf.
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let backup_dir = ca.dir.join(format!(".rotate-backup-ca-{now_ts}"));
    let _ = std::fs::create_dir_all(&backup_dir);
    for f in ["ca.crt", "ca.key"] {
        if let Err(e) = std::fs::copy(ca.dir.join(f), backup_dir.join(f)) {
            fail(g.json, ExitCode::Generic, "backup_failed",
                &format!("could not back up {f}: {e} — aborting before promotion"), None);
        }
    }
    let promote = (|| -> Result<(), String> {
        std::fs::write(ca.dir.join("ca-old.crt"), &old_pem).map_err(|e| e.to_string())?;
        std::fs::write(ca.dir.join("ca.crt"), &transition_anchor).map_err(|e| e.to_string())?;
        std::fs::copy(next.ca_key_path(), ca.dir.join("ca.key")).map_err(|e| e.to_string())?;
        // The transitioned node leaves become canonical.
        for node in &remote_nodes {
            for f in ["node.crt", "node.key"] {
                std::fs::copy(next.dir.join("nodes").join(node).join(f),
                              nodes_dir.join(node).join(f))
                    .map_err(|e| format!("{node}/{f}: {e}"))?;
            }
        }
        Ok(())
    })();
    if let Err(e) = promote {
        fail(g.json, ExitCode::Generic, "promote_failed",
            &format!("promotion failed midway: {e} — old CA pair is backed up at {}", backup_dir.display()),
            None);
    }

    // Local leaves (gateway, services, this host's node cert) re-issue under
    // the new CA: load_ca now reads the NEW cert (first in the anchor) with
    // the NEW key.
    let mut local_reissue_errs: Vec<String> = Vec::new();
    for info in ca.list_certs() {
        if info.role == "ca" || info.role == "other" {
            continue;
        }
        if info.role == "node"
            && cert_node_name(&info.name).is_some_and(|n| !n.eq_ignore_ascii_case(&hostname))
        {
            continue; // remote leaves were re-issued + delivered above
        }
        // i11a: this host's node cert is the controller's own: keep (and
        // restore) the controller names across the CA rotation.
        let role = match ca.node_of_cert(&info.path) {
            Some(n) if info.role == "node" => crate::pki::NodeRole::of(&n),
            _ => crate::pki::NodeRole::Worker,
        };
        if let Err(e) = ca.reissue_in_place(&info.path, leaf_days, &role) {
            local_reissue_errs.push(format!("{}: {e}", info.name));
        }
    }
    let _ = std::fs::remove_dir_all(&next.dir);

    // Reload local consumers: systemd node-agent + every running container
    // consumer of any leaf (they ALL changed).
    let mut reloaded: Vec<String> = Vec::new();
    if systemd_unit_known("noo-node-agent") {
        let _ = sync_self_agent_trust_plane(&ca, &hostname, g.json);
        if systemd_restart_unit("noo-node-agent") {
            reloaded.push("noo-node-agent (systemd)".to_string());
        }
    }
    let running = running_containers();
    let mut to_restart: Vec<String> = Vec::new();
    for info in ca.list_certs() {
        for c in cert_consumers(&info.name, info.role, &hostname) {
            let c = crate::envfile::instanced(&c);
            if running.contains(&c) && !to_restart.contains(&c) {
                to_restart.push(c);
            }
        }
    }
    to_restart.sort_by_key(|c| c.ends_with("-gateway"));
    for c in &to_restart {
        let _ = Command::new("docker").args(["restart", c]).output();
    }
    let (healthy, health_detail) = if to_restart.is_empty() {
        (true, "no container consumers running".to_string())
    } else {
        probe_health(&to_restart, 150)
    };
    reloaded.extend(to_restart.iter().cloned());

    // Finding #107 (live 2026-08-28): the OS trust store still held ONLY
    // the old CA after promotion — the gateway's new-CA leaf broke the
    // tailnet dashboard's chain. Refresh the anchor + tailscaled; quiet
    // sudo, manual recipe on failure (never an interactive prompt).
    let trust_dst = "/usr/local/share/ca-certificates/mesh-cluster-ca.crt";
    let trust_ok = Command::new("sudo")
        .args(["-n", "sh", "-c"])
        .arg(format!(
            "cp '{}' {trust_dst} && update-ca-certificates >/dev/null && systemctl restart tailscaled",
            ca.ca_cert_path().display()
        ))
        .stdin(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    if trust_ok {
        if !g.json {
            ui::done("OS trust store + tailscaled refreshed onto the new anchor");
        }
    } else if !g.json {
        ui::warned("trust store NOT refreshed (sudo needs a password): the tailnet dashboard's chain breaks until you run");
        println!("    {}", ui::cmd(&format!("sudo cp {} {trust_dst} && sudo update-ca-certificates && sudo systemctl restart tailscaled", ca.ca_cert_path().display())));
    }

    if g.json {
        println!("{}", serde_json::json!({
            "status": if healthy && local_reissue_errs.is_empty() { "rotated" } else { "rotated_with_warnings" },
            "nodes": outcomes.iter().map(|(n, d)| serde_json::json!({
                "node": n, "delivered": d.ok(), "detail": d.label() })).collect::<Vec<_>>(),
            "local_reissue_errors": local_reissue_errs,
            "reloaded": reloaded,
            "healthy": healthy,
            "backup": backup_dir.to_string_lossy(),
        }));
    } else {
        println!();
        ui::done("CA rotated: every node transitioned, controller promoted, leaves re-issued");
        if !local_reissue_errs.is_empty() {
            ui::warned("local re-issue warnings:");
            for e in &local_reissue_errs {
                println!("    {}", ui::muted(e));
            }
        }
        if !healthy {
            ui::warned(&format!("consumers unhealthy after reload ({health_detail}): investigate; old CA pair backed up at {}", backup_dir.display()));
        }
        println!("  {}", ui::muted("the old CA stays trusted (transition anchor) until you finish with"));
        ui::guide(&[("noo security pki rotate-ca --retire-old", "drops the old CA once every node has confirmed the new one")]);
    }
    Ok(if healthy && local_reissue_errs.is_empty() { 0 } else { 1 })
}

/// The --retire-old finisher: verify every leaf chains to the new CA alone,
/// ship NEW-only anchors to every node, then drop the old cert locally.
fn rotate_ca_retire(g: &Globals, ca: &ClusterCa, yes: bool) -> Result<i32, Unhandled> {
    let old_path = ca.dir.join("ca-old.crt");
    if !old_path.exists() {
        fail(g.json, ExitCode::Generic, "nothing_to_retire",
            "no ca-old.crt on record — either no rotation is in transition, or it was already retired",
            None);
    }
    let anchor = std::fs::read_to_string(ca.ca_cert_path()).unwrap_or_default();
    let Some(new_only) = first_pem_block(&anchor) else {
        fail(g.json, ExitCode::Generic, "anchor_parse", "could not parse the current CA anchor", None);
    };
    // Every leaf must verify against the NEW CA alone before the old trust
    // goes away — a straggler would go dark the moment its anchor narrows.
    let work = std::env::temp_dir().join(format!("noo-retire-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&work);
    let new_only_path = work.join("ca-new-only.crt");
    let _ = std::fs::write(&new_only_path, &new_only);
    let mut stragglers: Vec<String> = Vec::new();
    for info in ca.list_certs() {
        if info.role == "ca" || info.role == "other" {
            continue;
        }
        let ok = Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(&new_only_path)
            .arg(&info.path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            stragglers.push(info.name);
        }
    }
    if !stragglers.is_empty() {
        let _ = std::fs::remove_dir_all(&work);
        fail(g.json, ExitCode::Generic, "stragglers",
            &format!("{} leaf cert(s) do not chain to the new CA alone: {} — re-run \
                      `noo security pki rotate-all --warn-days 36500 --yes` (or rotate-ca) first",
                stragglers.len(), stragglers.join(", ")),
            None);
    }
    super::confirm_destructive(g, yes, "retire the OLD cluster CA from", "every trust anchor");

    let hostname = local_hostname();
    let mut failures: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(ca.dir.join("nodes")) {
        for e in rd.filter_map(|e| e.ok()) {
            let Some(node) = e.file_name().to_str().map(str::to_string) else { continue };
            if node.eq_ignore_ascii_case(&hostname) || !e.path().join("node.crt").exists() {
                continue;
            }
            if !g.json {
                println!("{}", ui::item(&node));
                println!("{}", ui::sub(&ui::status_line(Glyph::Step, "shipping the new-only anchor")));
            }
            let nwork = work.join(&node);
            let _ = std::fs::create_dir_all(&nwork);
            let files: Vec<(&str, Vec<u8>)> = vec![("ca.crt", new_only.clone().into_bytes())];
            let outcome = match build_signed_bundle(ca, &node, &files, &nwork) {
                Ok(bundle) => deliver_signed_bundle(g, &node, &bundle, &nwork, None),
                Err(e) => CertDelivery::Failed(e),
            };
            if !g.json {
                delivery_line(&node, &outcome);
            }
            if !outcome.ok() {
                failures.push(node);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    if !failures.is_empty() {
        fail(g.json, ExitCode::Generic, "retire_incomplete",
            &format!("{} node(s) did not confirm the narrowed anchor: {} — the old CA stays \
                      trusted locally; re-run --retire-old when they are reachable",
                failures.len(), failures.join(", ")),
            None);
    }
    let _ = std::fs::write(ca.ca_cert_path(), &new_only);
    let _ = std::fs::remove_file(&old_path);
    if g.json {
        println!("{}", serde_json::json!({"status": "retired"}));
    } else {
        ui::done("old CA retired: single-CA trust everywhere");
    }
    Ok(0)
}

/// `noo security secrets absorb-files` — fold file-shaped credentials into
/// the SOPS store
/// because bind-mounts need files and the sops rail only fed env vars).
/// Shells the script, which verifies the round-trip before shredding.
pub fn secrets_absorb_files(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    // It shreds the source files (after reading each back from the store),
    // so say so before touching anything.
    super::confirm_prompt(
        g,
        yes,
        "Fold plaintext credential files into env.sops and SHRED each one that reads back from the store?",
    );
    let root = crate::envfile::repo_root();
    let script = root.join("scripts/noo-secrets-absorb-files.sh");
    if !script.is_file() {
        fail(g.json, ExitCode::Generic, "script_missing",
            &format!("{} not found — upgrade the install (assets ride the binary)", script.display()),
            None);
    }
    let status = Command::new("bash").arg(&script).current_dir(&root).status();
    let script_rc = match status {
        Ok(s) if s.success() => 0,
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => fail(g.json, ExitCode::Generic, "spawn", &format!("could not run the absorb script: {e}"), None),
    };
    let residue_rc = absorb_plaintext_residue(g, &root);
    Ok(script_rc.max(residue_rc))
}

/// What to do with one legacy plaintext file, given what the store holds
/// for its key. Pure, so the rule is testable without a store.
#[derive(Debug, PartialEq, Eq)]
pub enum Residue {
    /// The store already holds this value (or the file is empty): the file
    /// is a dead copy.
    Shred,
    /// The store has no value: the file is the only copy, so it goes INTO
    /// the store first, and is shredded only after the store reads back.
    Absorb,
    /// The store holds a DIFFERENT value. The store is what the launcher
    /// loads, so the file is stale — but a stale copy is also the only
    /// evidence of what ran before, so it is named and left for a human.
    Conflict,
}

pub fn residue_decision(file_value: &str, stored: Option<&str>, is_hash: bool) -> Residue {
    let file_value = file_value.trim();
    let stored = stored.map(str::trim).filter(|v| !v.is_empty());
    if file_value.is_empty() {
        return Residue::Shred;
    }
    if is_hash {
        // A bcrypt hash cannot be turned back into the password; it is
        // disposable exactly when the password itself is stored.
        return if stored.is_some() { Residue::Shred } else { Residue::Conflict };
    }
    match stored {
        None => Residue::Absorb,
        Some(v) if v == file_value => Residue::Shred,
        Some(_) => Residue::Conflict,
    }
}

/// Fold every `secrets/<name>.txt` an older wizard left behind
/// into the store, then shred it. Nothing at runtime reads those files —
/// the launcher loads the store — so each is either a dead copy of a stored
/// value (shredded), the only copy (absorbed, verified, then shredded), or
/// a copy that disagrees with the store (reported, left alone, exit 1).
fn absorb_plaintext_residue(g: &Globals, root: &Path) -> i32 {
    use crate::commands::secrets::SecretStore;
    use crate::commands::secrets_reveal::{shred_file, ADMIN_HASH_FILE, LEGACY_PLAINTEXT_FILES};

    let present: Vec<(&str, &str)> = LEGACY_PLAINTEXT_FILES
        .iter()
        .copied()
        .filter(|(_, rel)| root.join(rel).is_file())
        .collect();
    if present.is_empty() {
        if !g.json {
            ui::done("no plaintext secret files beside the store");
        }
        return 0;
    }
    let store_path = root.join("secrets/env.sops");
    if !store_path.exists() {
        fail(g.json, ExitCode::Generic, "no_store",
            &format!("{} plaintext secret file(s) present but no encrypted store to fold them into — \
                      run 'noo onboard --only secrets' first", present.len()),
            None);
    }
    let mut store = match SecretStore::load_sops(&store_path) {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "store_unreadable", &e, None),
    };

    let mut shredded: Vec<&str> = Vec::new();
    let mut absorbed: Vec<&str> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    for (key, rel) in present {
        let path = root.join(rel);
        // A retired credential has no reader to fold it in for: shred it,
        // never absorb it (absorbing would put a dead secret back in the
        // store for `secrets tidy` to remove again).
        if crate::commands::secrets::retired_store_key(key).is_some() {
            match shred_file(&path) {
                Ok(()) => shredded.push(rel),
                Err(e) => conflicts.push(format!("{rel}: could not shred: {e}")),
            }
            continue;
        }
        let file_value = std::fs::read_to_string(&path).unwrap_or_default();
        match residue_decision(&file_value, store.get(key), rel == ADMIN_HASH_FILE) {
            Residue::Shred => match shred_file(&path) {
                Ok(()) => shredded.push(rel),
                Err(e) => conflicts.push(format!("{rel}: could not shred: {e}")),
            },
            Residue::Absorb => {
                let value = file_value.trim().to_string();
                if let Err(e) = crate::commands::secrets::store_upsert(&[(key.to_string(), value.clone())]) {
                    conflicts.push(format!("{rel}: {key} could not be written to the store: {e}"));
                    continue;
                }
                // Verify the round-trip on a FRESH decrypt before touching
                // the only copy.
                store = match SecretStore::load_sops(&store_path) {
                    Ok(s) => s,
                    Err(e) => {
                        conflicts.push(format!("{rel}: store written but did not read back ({e}); file kept"));
                        continue;
                    }
                };
                if store.get(key).map(str::trim) != Some(value.as_str()) {
                    conflicts.push(format!("{rel}: {key} did not round-trip through the store; file kept"));
                    continue;
                }
                match shred_file(&path) {
                    Ok(()) => absorbed.push(rel),
                    Err(e) => conflicts.push(format!("{rel}: absorbed but could not shred: {e}")),
                }
            }
            Residue::Conflict => conflicts.push(format!(
                "{rel}: holds a value that is NOT what the store has for {key}. The store is what runs; \
                 if the file is right, 'noo security secrets rotate {key} --set-from-stdin < {rel}' \
                 makes them agree, then re-run this. Left in place."
            )),
        }
    }

    if g.json {
        println!("{}", serde_json::json!({
            "shredded": shredded, "absorbed": absorbed, "conflicts": conflicts,
        }));
    } else {
        for rel in &shredded {
            ui::done(&format!("{rel} shredded (the store already held it)"));
        }
        for rel in &absorbed {
            ui::done(&format!("{rel} absorbed into secrets/env.sops and shredded"));
        }
        for c in &conflicts {
            println!("{}", ui::bad(&format!("✗ {c}")));
        }
    }
    if conflicts.is_empty() { 0 } else { 1 }
}

/// `noo security pki issue-node <node> [ip] [--days N] [--mint-only]` —
/// issue a node cert AND deliver it over the pull rail, waiting for the node
/// to report it applied.
///
/// Delivery is the default. Issuing
/// writes the CONTROLLER's disk and touches no node, so the old two-step
/// form left the operator holding a fresh cert while the node carried on
/// presenting the old one — exactly what happened re-issuing host9 for an
/// address change: every inference to it kept failing on a rejected
/// handshake until a provision carried the cert over. Nobody wants a cert
/// that exists only on the controller, so that is no longer what the verb
/// does by default.
///
/// `--mint-only` keeps the local-only primitive for the cases that genuinely
/// need it: provisioning a FRESH node (the bundle carries the certs itself,
/// and push-nodes is the wrong tool there — it is a RE-KEY that restarts an
/// agent which does not exist yet; found live 2026-08-18 when push-nodes
/// aborted a provision trying to restart a missing unit), and pre-minting
/// for a node that is offline now and will collect later.
pub fn pki_issue_node(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut days: i64 = crate::pki::DEFAULT_DAYS;
    let mut mint_only = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" => days = iter.next().and_then(|v| v.parse().ok()).filter(|d: &i64| *d > 0).ok_or(Unhandled)?,
            "--mint-only" => mint_only = true,
            t if !t.starts_with('-') && node.is_none() => node = Some(t.to_string()),
            t if !t.starts_with('-') && ip.is_none() => ip = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(node) = node else { return Err(Unhandled) };
    // The address goes into the cert's SANs, and the gateway rejects a
    // handshake to a name or address the cert does not carry — so getting
    // this wrong is not cosmetic.
    //
    // It used to read the ansible inventory and fall back to "0.0.0.0"
    // when the node was not in it. That file is retired, so the fallback
    // had become the normal path: certs were being issued naming an
    // address no node has. Worse, it defeats the drift check that
    // re-issues on a changed address — the re-issue would produce the
    // same useless SAN and the node would still fail every inbound
    // handshake.
    //
    // Resolve from the tailnet, which is the address the agent actually
    // registers, and REFUSE rather than invent one.
    //
    // i11a: the controller's own node keeps the controller names on every
    // re-issue, and its tailnet address is this device's, not whichever
    // tailnet device happens to share its node name.
    let role = crate::pki::NodeRole::of(&node);
    let Some(ip) = ip.or_else(|| role.tailnet_ip4(&node)) else {
        fail(
            g.json,
            ExitCode::Generic,
            "no_address",
            &format!(
                "cannot determine an address for '{node}' — pass it explicitly \
                 (`noo security pki issue-node {node} <ip>`). Issuing a cert without \
                 the node's real address produces one that fails every inbound \
                 handshake by name"
            ),
            None,
        );
    };

    let ca = ClusterCa::new(pki_dir());
    if !ca.ca_exists() {
        fail(g.json, ExitCode::Generic, "no_ca", "no cluster CA found — run 'noo onboard' first", None);
    }
    // #79: the tailnet IP is the address the agent registers — a node
    // cert without it fails every gpu_health/dispatch probe by name.
    let ts_ip: Vec<String> = role.tailnet_ip4(&node).into_iter().collect();
    match ca.issue_node_cert(&node, &ip, days, &["node-agent".to_string()], &ts_ip, &role) {
        Ok((crt, key)) => {
            if !mint_only {
                // Deliver over the rail and let the NODE be the judge:
                // `ok()` is true only for a cert the node presents or a
                // bundle it reported applying. A staged-but-unconfirmed
                // delivery exits non-zero, because "the cert exists on the
                // controller" is not the outcome anyone ran this for.
                let d = deliver_node_certs(g, &ca, &node);
                let ok = d.ok();
                if g.json {
                    println!("{}", serde_json::json!({
                        "status": if ok { "ok" } else { "undelivered" },
                        "node": node, "crt": crt, "key": key,
                        "delivered": ok, "delivery": d.label(),
                    }));
                } else {
                    ui::done(&format!("issued cert for {node}: {}", crt.display()));
                    delivery_line(&node, &d);
                    if !ok {
                        ui::guide(&[
                            (&format!("noo cluster provision {node} --wait"), "retry delivery over the rail"),
                            (&format!("noo security pki push-nodes {node}"), "re-stages the cert on the pull rail for this node"),
                        ]);
                    }
                }
                return Ok(if ok { 0 } else { 1 });
            }
            if g.json {
                // `delivered` is stated, not implied. Issuing writes the
                // controller's disk and touches no node — a caller that
                // reads "status: ok" as "the node has it" is the fu72 #6
                // mistake in a different colour.
                println!("{}", serde_json::json!({
                    "status": "ok", "node": node, "crt": crt, "key": key,
                    "delivered": false,
                }));
            } else {
                // The sibling `pki rotate` has said "the node still runs its
                // old cert" since fu72 #6; this one said only "issued", and
                // its hint called provision "the full bundle path, if the
                // node is not enrolled yet" — wrong, and the reason a
                // re-issue for an ADDRESS CHANGE reads as finished when the
                // node has not been told anything (host9, 2026-09-04:
                // re-issued, still presenting the old cert, every inference
                // to it failing).
                ui::done(&format!(
                    "issued cert for {node}: {}  {}",
                    crt.display(),
                    ui::muted("local files only: the node still runs its old cert")
                ));
                ui::guide(&[
                    (&format!("noo security pki issue-node {node}"), "issue AND deliver — the normal form; this run wrote local files only"),
                    (&format!("noo cluster provision {node} --wait"), "delivers what is already on disk and waits for the node to confirm"),
                    ("noo security pki status", "confirms the new expiry"),
                ]);
            }
            Ok(0)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "issue_failed", &e, None),
    }
}

/// `noo security pki push-nodes [NODE] [--days N] [--yes]` — re-issue each
/// registered fleet node's cert (plus the current ca.crt) and stage a
/// CA-signed cert bundle on the pull rail for it to collect.
///
/// This is the missing half of CA rotation: re-onboard regenerates the
/// cluster CA, and every remote agent then crash-retries with "certificate
/// signed by unknown authority" while `cluster status` just shows OFFLINE —
/// certs only ever reached nodes during a full node provisioning run
/// (2026-08-06, handoff item 10). Delivery is the pull rail, and only the
/// pull rail (operator, 2026-09-05): the controller has no privileged path
/// into a node any more, so there is no SSH or scp fallback. A node with no
/// birth cert on record predates the rail and must be re-enrolled
/// (`noo enroll` on the node) before its certs can be delivered.
///
/// `deliver_node_certs` is the same helper `pki issue-node` uses, so the two
/// cannot drift. The node applies the bundle and restarts its own
/// node-agent (host unit or container, whichever the node runs) — nothing
/// here reaches into the node to restart anything.
pub fn pki_push_nodes(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut only: Option<String> = None;
    let mut days: i64 = crate::pki::DEFAULT_DAYS;
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" => {
                days = iter
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|d: &i64| *d > 0)
                    .ok_or(Unhandled)?;
            }
            "--force" | "--yes" | "-y" => yes = true,
            t if !t.starts_with('-') && only.is_none() => only = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }

    let ca = ClusterCa::new(pki_dir());
    if !ca.ca_exists() {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "no_ca",
            "no cluster CA found — run 'noo security pki init' (or 'noo onboard') first",
            None,
        );
    }

    let local_hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let nodes: Vec<(String, String, String)> = fleet_nodes_from_registry(g)
        .into_iter()
        // The controller's own certs are local files — nothing to push.
        .filter(|(name, _, _)| !name.eq_ignore_ascii_case(&local_hostname))
        .filter(|(name, _, _)| only.as_deref().is_none_or(|o| o.eq_ignore_ascii_case(name)))
        .collect();
    if nodes.is_empty() {
        // i11a: the controller's own node is not "unregistered", it is
        // delivered by a different lane. Say which.
        if let Some(o) = only.as_deref().filter(|o| o.eq_ignore_ascii_case(&local_hostname)) {
            crate::output::fail(
                g.json,
                crate::output::ExitCode::Generic,
                "self_node",
                &format!("'{o}' is this controller's own node: its cert rides its provision bundle, not this push"),
                Some(&format!("noo cluster provision {o}   (re-issues it with the controller names and stages it over the rail)")),
            );
        }
        let msg = match &only {
            Some(o) => format!("node '{o}' is not registered with this controller"),
            None => "no remote nodes registered with this controller".to_string(),
        };
        crate::output::fail(g.json, crate::output::ExitCode::Generic, "no_nodes", &msg, None);
    }

    if !g.json {
        println!("{}", ui::phase("plan"));
        println!("  {}", ui::muted(&format!("pushing cluster CA + node certs to {} node(s)", nodes.len())));
        for (name, host, user) in &nodes {
            println!("  {}  {name}  {}", ui::glyph(Glyph::Bullet), ui::muted(&format!("{user}@{host}")));
        }
    }
    super::confirm_destructive(g, yes, "re-key and restart the agent on", "these nodes");

    if !g.json {
        println!("{}", ui::phase("push"));
    }
    let mut failed: Vec<String> = Vec::new();
    for (name, host, _user) in &nodes {
        if !g.json {
            println!("{}", ui::item(name));
            println!("{}", ui::sub(&ui::status_line(Glyph::Step, "issuing the node certificate")));
        }
        // The local controller node is filtered out above; this is a worker.
        let ts_ip: Vec<String> = ClusterCa::tailscale_ip4(name).into_iter().collect();
        let role = crate::pki::NodeRole::Worker;
        if let Err(e) = ca.issue_node_cert(name, host, days, &["node-agent".to_string()], &ts_ip, &role) {
            if !g.json {
                println!("{}", ui::sub(&ui::status_line(Glyph::Err, &format!("cert issuance failed: {e}"))));
            }
            failed.push(name.clone());
            continue;
        }
        // Delivery is the pull rail, and only the pull rail: the CA-signed
        // bundle is staged end-to-end encrypted to the node's birth cert and
        // the node's fetch timer collects it. `deliver_node_certs` is the
        // same helper `pki issue-node` uses, so the two cannot drift.
        //
        // This replaced two SSH lanes — `noo-gate apply` over the controller
        // key, and an ATTENDED scp + `sudo install` that prompted for a
        // password on every node. Both are gone: the controller has no
        // privileged path into a node (operator, 2026-09-05). The rail is
        // also strictly better here, because it reaches a node that is
        // offline right now — the bundle waits, and SSH never could.
        let outcome = deliver_node_certs(g, &ca, name);
        if !g.json {
            delivery_line(name, &outcome);
        }
        if !outcome.ok() {
            failed.push(name.clone());
        }
    }

    if g.json {
        let pushed: Vec<&str> = nodes
            .iter()
            .map(|(n, _, _)| n.as_str())
            .filter(|n| !failed.iter().any(|f| f == n))
            .collect();
        println!(
            "{}",
            serde_json::json!({"ok": failed.is_empty(), "pushed": pushed, "failed": failed})
        );
    } else if failed.is_empty() {
        ui::close_done(&format!("all {} node(s) re-keyed", nodes.len()));
        ui::guide(&[("noo security pki status", "confirms every node cert is on the new expiry")]);
    } else {
        ui::close_failed(&format!("{} node(s) failed: {}", failed.len(), failed.join(", ")), Some("noo security pki push-nodes"));
    }
    Ok(if failed.is_empty() { 0 } else { 1 })
}

// ── who a signing-key rollout is FOR, and what counts as proof ──────────
//
// Both of these are pure, and both are pure because the first cut of each
// was wrong in a way only a live run showed.

/// The controller's PKI node directories, split against the node REGISTRY.
///
/// Live finding on host8, 2026-09-12: the first cut enumerated
/// `<pki>/nodes/*`, and `host8` had been removed from the registry by
/// `noo cluster forget` months earlier while its key material stayed on
/// disk. The rollout counted that directory as a node, could never deliver
/// to it, and reported it as a STRAGGLER — so the operator was told the
/// fleet was not rolled, with a node name that no longer exists, and the
/// only way through was to delete the directory by hand.
///
/// The registry is the authority for "which nodes exist" — it is what
/// `noo cluster status` shows and what the gateway will stage a bundle
/// for. A directory is only ever *material*. The two disagree in both
/// directions and each direction means something different:
///
///   * dir, no registry entry  → ORPHANED MATERIAL. Not a straggler:
///     there is no node to fail. Report it with the purge command.
///   * registry entry, no dir  → a node whose cert was never issued on
///     this controller. It is still a rollout target (the signing key is
///     not a certificate and needs no `node.crt`), so it is not called
///     out as a problem — but it is surfaced, because it usually means
///     this is not the controller that provisioned it.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct RolloutTargets {
    /// Registered, not this host, and matching `only` if one was given.
    pub(crate) nodes: Vec<String>,
    /// PKI dirs with no registered node.
    pub(crate) orphaned: Vec<String>,
    /// Registered nodes with no PKI dir on this controller.
    pub(crate) no_material: Vec<String>,
}

pub(crate) fn split_rollout_targets(
    registered: &[String],
    pki_dirs: &[String],
    hostname: &str,
    only: Option<&str>,
) -> RolloutTargets {
    let is_self = |n: &str| n.eq_ignore_ascii_case(hostname);
    let wanted = |n: &str| only.is_none_or(|o| o.eq_ignore_ascii_case(n));
    let known = |n: &str| registered.iter().any(|r| r.eq_ignore_ascii_case(n));

    // The controller's own box is a TARGET when it is a registered node.
    //
    // It used to be filtered out by hostname, from back when a controller was
    // never also a node. The self-node lane made it one, and the exclusion
    // then became a hole with a deadline: the controller's own node polls and
    // applies bundles like any other, but could never be handed the fleet
    // signing key, so it verified every bundle on the CA-signed compatibility
    // lane — and that lane is removed next release. host8 on 2026-09-12:
    // `rotate-signing-key host8` answered "not registered with this
    // controller" while `cluster status` listed it Online, and its stored
    // apply message was the CA-lane warning. Closing the arm would have
    // stopped the controller's own node applying anything, on every
    // standalone install, which is the default shape.
    //
    // It stays out of `orphaned` either way: the controller's own key
    // material is not a forgotten node's leftovers.
    let mut t = RolloutTargets {
        nodes: registered.iter().filter(|n| wanted(n)).cloned().collect(),
        // The controller's own material is not orphaned, whether or not the
        // controller registers itself as a node.
        orphaned: pki_dirs.iter().filter(|d| !is_self(d) && !known(d)).cloned().collect(),
        no_material: registered
            .iter()
            .filter(|n| !is_self(n) && wanted(n))
            .filter(|n| !pki_dirs.iter().any(|d| d.eq_ignore_ascii_case(n)))
            .cloned()
            .collect(),
    };
    t.nodes.sort();
    t.orphaned.sort();
    t.no_material.sort();
    t
}

/// Did this delivery PROVE the node installed the signing key — and if
/// not, is that the NODE's fault or the REPORT LANE's?
///
/// Three findings shaped this, and all three are the same mistake in
/// different clothes: treating an absent signal as a signal.
///
/// **1. `ok()` is not proof.** `CertDelivery::ok()` counts `Collected` —
/// "the node fetched the bundle and is still online" — as delivered. That
/// is right for a cert, because the node's own heartbeat will contradict
/// it if it is wrong. It is wrong here: writing the `signing-adopted`
/// marker on a collection makes the controller sign every later bundle
/// with a key the node may not hold, and a node that cannot verify a
/// bundle refuses ALL of them.
///
/// **2. Some nodes cannot report at all.** The darwin fetcher never POSTed
/// `/bootstrap/bundle/<node>/applied` (R46, fixed on dev in `53e1495e`) —
/// but every Mac still running `noo-cli` ≤ 0.5.27 sends nothing, on
/// success OR failure. host6 is one.
///
/// **3. So "no report" must not be a straggler.** If it were, those Macs
/// would be permanent stragglers, and they would block the C4 gate that
/// closes the CA-signed bundle lane next release — a gate held open
/// forever by nodes that are very probably fine. The blocking set has to
/// be the nodes that *can* speak and did not say yes, not the nodes that
/// cannot speak.
///
/// Hence the classification takes TWO inputs: the delivery outcome, and
/// whether this node has ever reported an apply at all. The second is what
/// separates "silent because it cannot talk" from "silent because it
/// failed", and it is a property of the node's build, not of this bundle.
///
/// One thing deliberately NOT excused: a bundle that was never collected.
/// `fetched_at` is recorded by the GATEWAY when the fetcher pulls the
/// blob, so it is observable whether or not the node can report — an
/// un-collected bundle is a real delivery failure even on a silent node.
#[derive(Debug, PartialEq)]
pub(crate) enum Adoption {
    /// The node ran noo-apply on this exact bundle and reported exit 0.
    Adopted,
    /// The bundle reached the node, and this node has never reported an
    /// apply for anything — its CLI predates the report lane. The marker
    /// is NOT written (so it keeps receiving CA-signed bundles, the safe
    /// direction), and it is NOT a straggler: there is no evidence against
    /// it, only an absence of evidence for it.
    NoReport,
    /// A node that CAN report and did not adopt, or any node whose bundle
    /// was never collected. The only class that blocks.
    NotAdopted,
}

impl Adoption {
    /// Does this outcome hold the CA-signed lane open? Only a real
    /// straggler does. `NoReport` is unresolved, not failing.
    pub(crate) fn blocks_the_gate(&self) -> bool {
        matches!(self, Adoption::NotAdopted)
    }
}

/// `reports_applies` — has this node EVER reported an apply, for any
/// bundle (`node_reports_applies`)? Not "did it report this one".
pub(crate) fn adoption_of(d: &CertDelivery, reports_applies: bool) -> Adoption {
    match d {
        CertDelivery::Applied | CertDelivery::Verified => Adoption::Adopted,
        // It got there. Whether that silence means anything depends on
        // whether this node can speak.
        CertDelivery::Collected if !reports_applies => Adoption::NoReport,
        CertDelivery::Collected => Adoption::NotAdopted,
        // Never collected, or never staged. Gateway-side facts, true
        // regardless of what the node can say.
        CertDelivery::Staged
        | CertDelivery::FetchedUnconfirmed
        | CertDelivery::SkippedPending
        | CertDelivery::Failed(_) => {
            Adoption::NotAdopted
        }
    }
}

/// `noo security pki rotate-signing-key` — mint (or re-mint) the fleet
/// code-signing key and deliver its PUBLIC half to every node.
///
/// Until this ran, one key did two jobs: it issued every mTLS
/// identity in the cluster AND it signed the bundles that put root code
/// (`noo-node-agent`, `noo-hostd`, `noo-apply` itself, fleet secrets) on
/// every box. Splitting them means the code-signing half can be rotated
/// without re-issuing a single certificate — which is what this verb does.
///
/// The rollover bundle is signed with the **CA key**, on purpose: it is the
/// only anchor a node that has not adopted (or is being moved off a retired
/// signing key) can still verify. It carries `signing-pub` and NOTHING else
/// The CA delivers a public key, never code. A node that
/// already holds a signing key also needs that key's countersignature
/// (`sign_and_tar` writes one per retained key).
///
/// Adoption is per-node and recorded on this controller
/// (`<pki>/nodes/<node>/signing-adopted`). A node that does not confirm
/// keeps getting CA-signed bundles — nothing breaks, it just has not moved
/// yet. Re-run for the stragglers.
pub fn pki_rotate_signing_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut only: Option<String> = None;
    let mut yes = false;
    let mut reuse = false;
    for tok in args {
        match tok.as_str() {
            "--force" | "--yes" | "-y" => yes = true,
            // The bootstrap case: a cluster that has a signing key already
            // (minted with the CA, or lazily on a push) but whose nodes have
            // never been handed the public half. Nothing is rotated; the
            // existing key is delivered.
            "--deliver-only" => reuse = true,
            t if !t.starts_with('-') && only.is_none() => only = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }

    let ca = ClusterCa::new(pki_dir());
    if !ca.ca_exists() {
        fail(g.json, ExitCode::Generic, "no_ca",
            "no cluster CA found — run 'noo security pki init' (or 'noo onboard') first", None);
    }

    let hostname = local_hostname();

    // The REGISTRY is the authority for which nodes exist, not the PKI
    // directory (see `split_rollout_targets`). An unreachable gateway must
    // fail here: `fleet_nodes_from_registry` returns an empty vec on any
    // transport trouble, and "no nodes" would otherwise read as "the whole
    // fleet is rolled" and exit 0.
    if crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10).is_none() {
        fail(g.json, ExitCode::Generic, "gateway_unreachable",
            "cannot reach the gateway, so the node registry cannot be read — refusing to \
             report a rollout against an empty fleet. Start the gateway and re-run.",
            Some("noo health"));
    }
    let registered: Vec<String> =
        fleet_nodes_from_registry(g).into_iter().map(|(n, _, _)| n).collect();
    let pki_dirs: Vec<String> = std::fs::read_dir(ca.dir.join("nodes"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    let targets = split_rollout_targets(&registered, &pki_dirs, &hostname, only.as_deref());
    let nodes = targets.nodes.clone();

    if let Some(o) = only.as_deref() {
        if nodes.is_empty() {
            let detail = if targets.orphaned.iter().any(|d| d.eq_ignore_ascii_case(o)) {
                format!(
                    "'{o}' is not a registered node — but {} holds key material for that name. \
                     That is orphaned material from a forgotten node, not a node to roll; \
                     purge it with `rm -rf {}`.",
                    ca.dir.join("nodes").display(),
                    ca.dir.join("nodes").join(o).display()
                )
            } else {
                format!("'{o}' is not registered with this controller")
            };
            fail(g.json, ExitCode::Generic, "no_such_node", &detail,
                Some("noo cluster status"));
        }
    }

    if !g.json {
        println!("{}", ui::emph(if reuse {
            "fleet signing key — delivering the current public key"
        } else {
            "fleet signing key rotation"
        }));
        println!("{}", ui::kv(&[
            ("  signing key", ca.signing_key_path().display().to_string()),
            ("  public key", ca.signing_pub_path().display().to_string()),
            ("  nodes", if nodes.is_empty() { ui::muted("none") } else { nodes.join(", ") }),
        ]));
        println!("  {}", ui::muted("the rollover bundle is signed by the cluster CA — the anchor every node already has"));
        // Named BEFORE the rollout, not folded into the failures after it.
        // An orphaned directory cannot be rolled and is not a straggler —
        // there is no node behind it to fail.
        if !targets.orphaned.is_empty() {
            println!("{}", ui::section("orphaned material (not stragglers)"));
            for d in &targets.orphaned {
                println!("  {}", ui::warn(&format!(
                    "{d}: key material on this controller, no such node in the registry"
                )));
                println!("    {}", ui::muted(&format!(
                    "rm -rf {}", ca.dir.join("nodes").join(d).display()
                )));
            }
            println!("  {}", ui::muted("left in place — this command never deletes key material"));
        }
        if !targets.no_material.is_empty() {
            println!("  {}", ui::muted(&format!(
                "registered with no cert on this controller (still rolled — the signing key is not a certificate): {}",
                targets.no_material.join(", ")
            )));
        }
    }
    if !reuse {
        super::confirm_destructive(g, yes, "mint a NEW fleet signing key and re-deliver it to",
            "every node (bundles signed by the old key stop verifying)");
    }

    if reuse {
        if let Err(e) = ca.ensure_signing_key() {
            fail(g.json, ExitCode::Generic, "signing_key", &e, None);
        }
    } else {
        // Clear adoption BEFORE minting. `bundle_signing_key` reads these
        // markers, so a marker that outlived its key would have the
        // controller sign with a key the node cannot verify — the exact
        // silent-success shape this repo keeps finding.
        for node in &nodes {
            let _ = std::fs::remove_file(ca.signing_adopted_path(node));
        }
        if only.is_none() {
            if let Ok(rd) = std::fs::read_dir(ca.dir.join("nodes")) {
                for e in rd.flatten() {
                    let _ = std::fs::remove_file(e.path().join("signing-adopted"));
                }
            }
        }
        if let Err(e) = ca.mint_signing_key() {
            fail(g.json, ExitCode::Generic, "signing_key", &format!("could not mint the signing key: {e}"), None);
        }
        if !g.json {
            ui::done("new fleet signing key minted");
        }
    }

    let pubkey = match std::fs::read(ca.signing_pub_path()) {
        Ok(b) if !b.is_empty() => b,
        _ => fail(g.json, ExitCode::Generic, "signing_pub",
            &format!("could not read {}", ca.signing_pub_path().display()), None),
    };

    let mut failed: Vec<String> = Vec::new();
    let mut no_report: Vec<String> = Vec::new();
    if !g.json && !nodes.is_empty() {
        println!("{}", ui::phase("rollover"));
    }
    for node in &nodes {
        if !g.json {
            println!("{}", ui::item(node));
            println!("{}", ui::sub(&ui::status_line(Glyph::Step, "CA-signed rollover bundle (signing-pub only)")));
        }
        let work = std::env::temp_dir().join(format!("noo-signkey-{node}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        if std::fs::create_dir_all(&work).is_err() {
            failed.push(node.clone());
            continue;
        }
        // The key and nothing else: the CA delivers a public
        // key, never code — not even the applier. Every applier on the
        // fleet since #119 knows the `signing-pub` kind.
        let files: Vec<(&str, Vec<u8>)> = vec![("signing-pub", pubkey.clone())];
        // Forced onto the CA key: `build_signed_bundle` would pick the new
        // signing key the moment a marker said the node had adopted, and a
        // rollover must never depend on the key it is rolling.
        let outcome = match build_signed_bundle_with_key(&ca, node, &files, &work, &ca.ca_key_path()) {
            Ok(bundle) => deliver_signed_bundle(g, node, &bundle, &work, None),
            Err(e) => CertDelivery::Failed(e),
        };
        let _ = std::fs::remove_dir_all(&work);
        if !g.json {
            delivery_line(node, &outcome);
        }
        // `outcome.ok()` is NOT the test — see `adoption_of`. A `Collected`
        // is a delivery success and an adoption non-answer, and writing the
        // marker on it would have the controller sign with a key the node
        // may not hold.
        // Asked BEFORE the classification and independently of this
        // bundle: can this node report an apply at all? A `false` here is a
        // property of its build (a Mac on noo-cli <= 0.5.27), not evidence
        // about the rollover.
        let reports = node_reports_applies(g, node);
        let adoption = adoption_of(&outcome, reports);

        // The marker needs POSITIVE proof. Everything else clears it, so a
        // node whose state is unknown keeps receiving CA-signed bundles —
        // the safe direction: each one is a countersigned rollover (proposal
        // 58 A1/A2), which a node on the old or the new key accepts.
        if adoption == Adoption::Adopted {
            let marker = ca.signing_adopted_path(node);
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // The marker records WHICH key was adopted, so an operator
            // reading the PKI dir can tell a stale marker from a current
            // one without guessing.
            let _ = std::fs::write(&marker, format!("{}\n", signing_pub_fingerprint(&pubkey)));
        } else {
            let _ = std::fs::remove_file(ca.signing_adopted_path(node));
        }

        if !g.json && adoption == Adoption::NoReport {
            println!("{}", ui::sub(&ui::status_line(Glyph::Bullet,
                "collected, but this node has never reported an apply for anything — its CLI \
                 predates the report lane, so adoption is UNKNOWN rather than failed; it stays \
                 on the CA-signed lane and is NOT a straggler")));
        }

        // One rule decides what blocks, and it lives on the enum so the
        // report, the exit code and the C4 gate cannot drift apart.
        if adoption.blocks_the_gate() {
            failed.push(node.clone());
        } else if adoption == Adoption::NoReport {
            no_report.push(node.clone());
        }
    }

    let adopted: Vec<&str> = nodes.iter().map(String::as_str)
        .filter(|n| !failed.iter().any(|f| f == n))
        .filter(|n| !no_report.iter().any(|u| u == n))
        .collect();
    // STRAGGLERS are what hold the CA-signed lane open, and they are only
    // the nodes that can report and did not adopt. A node that cannot
    // report is unresolved, not failing — counting it would make every Mac
    // on noo-cli <= 0.5.27 a permanent blocker of the C4 gate.
    let rolled = failed.is_empty();
    let complete = rolled && no_report.is_empty();

    if g.json {
        println!("{}", serde_json::json!({
            // `ok` is the GATE's answer: no stragglers. A node that cannot
            // report is not a straggler, so it does not hold this false —
            // read `no_report` to decide whether to wait for it.
            "ok": rolled,
            // …and `complete` is the stricter one: every node PROVED it.
            "complete": complete,
            "signing_pub": ca.signing_pub_path().to_string_lossy(),
            "fingerprint": signing_pub_fingerprint(&pubkey),
            "adopted": adopted,
            // Four lists, not two. "never got there", "got there and this
            // node's build cannot tell us", and "this node can tell us and
            // said no" are three different problems with three different
            // owners; an operator shown them merged goes hunting for a
            // delivery fault that is not there, and a GATE shown them
            // merged never opens.
            "no_report": no_report,
            "failed": failed,
            // Key material for a node the registry does not know. Reported,
            // never deleted, and never counted as a straggler.
            "orphaned_material": targets.orphaned,
            "registered_without_certs": targets.no_material,
        }));
    } else if complete {
        ui::close_done(&format!(
            "{} node(s) verify bundles against the fleet signing key (sha256:{})",
            adopted.len(), &signing_pub_fingerprint(&pubkey)[..16]));
        ui::guide(&[
            ("noo security pki status", "shows the signing key alongside every certificate"),
            ("noo security pki push-nodes", "the next push is signed by the new key, not the CA"),
        ]);
    } else if rolled {
        // No stragglers — the gate is not blocked. Say so plainly, because
        // the difference between "unresolved" and "failing" is the whole
        // point and an operator reading a red close will treat it as work.
        ui::close_done(&format!(
            "{} node(s) proved adoption; no stragglers",
            adopted.len()));
        println!("  {}", ui::warn(&format!(
            "{} node(s) collected the key but cannot report an apply: {}",
            no_report.len(), no_report.join(", "))));
        println!("    {}", ui::muted(
            "their CLI predates the report lane (fixed for macOS in 53e1495e), so this is a \
             REPORTING gap, not a delivery one — they are NOT stragglers and do not hold the \
             CA-signed lane open"));
        ui::guide(&[
            ("noo cluster logs <node>", "what the fetcher did with the bundle"),
            ("ls -l /etc/noo/pki/signing.pub", "on the node: confirm the key landed, by hand"),
            ("noo cluster provision <node>", "ships a current CLI so the next rollover can report"),
        ]);
    } else {
        let mut why: Vec<String> = Vec::new();
        why.push(format!(
            "{} straggler(s) — reported, not adopted, or never collected the bundle: {}. \
             Re-run when they are reachable",
            failed.len(), failed.join(", ")));
        if !no_report.is_empty() {
            why.push(format!(
                "separately, {} node(s) collected it but cannot report an apply ({}) — a \
                 reporting gap, not a straggler; confirm by hand with `ls -l \
                 /etc/noo/pki/signing.pub` on the node",
                no_report.len(), no_report.join(", ")));
        }
        ui::close_failed(
            &format!("{}. Stragglers keep their old key; a CA-signed rollover countersigned \
                      by it still reaches them, so re-run when they are back.", why.join("; ")),
            Some("noo security pki rotate-signing-key"));
    }
    // Only a straggler is a failure. A node that cannot report leaves the
    // command green with a warning, or the C4 gate can never open.
    Ok(i32::from(!rolled))
}

/// sha256 over the SPKI PEM bytes — the same string the node logs when it
/// verifies, so `noo security pki status` and a node's journal can be
/// compared by eye.
pub(crate) fn signing_pub_fingerprint(pem: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(pem);
    hex::encode(h.finalize())
}

/// Re-issues expiring CERTIFICATES only. The Grafana SSO pair under
/// `pki/sso/` is not a certificate and is never rotated here — by
/// construction (`list_certs` collects `*.crt`) and on purpose: a new SSO
/// key logs every open Grafana tab out. It changes only through
/// `noo security pki issue-sso-key --force`.
pub fn pki_rotate_all(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut warn_days: i64 = 30;
    let mut new_days: i64 = 90;
    let mut skip_confirm = false;
    let mut reload = true;
    let mut deliver = true;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--warn-days" => {
                warn_days = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?;
            }
            "--new-days" => {
                new_days = iter
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|d: &i64| *d > 0)
                    .ok_or(Unhandled)?;
            }
            "--force" | "--yes" | "-y" => skip_confirm = true,
            "--reload" => reload = true,
            "--no-reload" => reload = false,
            // fu72 #2: delivery is the DEFAULT (rotated-but-undelivered was
            // the self-soothing lie). --no-deliver is the explicit opt-out
            // for sandboxes and air-gapped controllers — the closer still
            // says the node certs were NOT delivered.
            "--no-deliver" => deliver = false,
            _ => return Err(Unhandled),
        }
    }

    let ca = ClusterCa::new(pki_dir());
    let expiring = ca.expiring_certs(warn_days);
    if expiring.is_empty() {
        if g.json {
            println!(
                "{}",
                serde_json::json!({ "expiring": [], "results": [], "reloaded": [] })
            );
        } else {
            println!("{}", ui::status_line(Glyph::Ok, &format!("no certificates expiring within {warn_days} days")));
        }
        return Ok(0);
    }

    if !g.json {
        println!("{}", ui::phase("expiring"));
        println!("  {}", ui::muted(&format!("{} certificate(s) expiring within {warn_days} days", expiring.len())));
        for c in &expiring {
            println!("  {}  {}  {}", ui::glyph(Glyph::Warn), c.name, ui::muted(&format!("{} days left", c.days_left)));
        }
    }

    super::confirm_destructive(
        g,
        skip_confirm,
        "rotate",
        &format!("{} expiring certificate(s)", expiring.len()),
    );

    // Backup every expiring cert+key so a failed reload can revert.
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_dir = ca.dir.join(format!(".rotate-backup-{now_ts}"));
    for c in &expiring {
        for src in [c.path.clone(), c.path.with_extension("key")] {
            if src.exists() {
                if let Ok(rel) = src.strip_prefix(&ca.dir) {
                    let dst = backup_dir.join(rel);
                    if let Some(parent) = dst.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if let Err(e) = std::fs::copy(&src, &dst) {
                        fail(
                            g.json,
                            ExitCode::Generic,
                            "backup_failed",
                            &format!("could not back up {}: {e}", src.display()),
                            Some("aborting before rotation — nothing was changed"),
                        );
                    }
                }
            }
        }
    }

    let results = ca.rotate_all_expiring(warn_days, new_days, crate::pki::NodeRole::of);

    if !g.json {
        println!("{}", ui::phase("reissue"));
        let rows: Vec<Vec<String>> = results
            .iter()
            .map(|r| {
                let glyph = if r.status == "rotated" { Glyph::Ok } else { Glyph::Err };
                vec![ui::glyph_cell(glyph), r.name.clone(), r.role.to_string(), if r.status == "rotated" { ui::ok("rotated") } else { ui::err(r.status) }, r.error.clone()]
            })
            .collect();
        print!("{}", ui::table(&[Col::left(""), Col::left("certificate"), Col::left("role"), Col::left("status"), Col::left("detail")], &rows));
    }

    let rotated: Vec<&RotateResult> = results.iter().filter(|r| r.status == "rotated").collect();
    let gateway_rotated = rotated.iter().any(|r| r.role == "gateway");

    // ── fu72 #2: DELIVER re-issued remote node certs ──
    // The old command stopped here: a remote node's cert was re-issued on
    // this disk, the table said "rotated", the expiry alert cleared, and the
    // node kept serving its old cert until it expired. Rotated without
    // delivered is a lie with a countdown on it.
    let hostname = local_hostname();
    let mut deliveries: Vec<(String, CertDelivery)> = Vec::new();
    let mut skipped_delivery: Vec<String> = Vec::new();
    let remote_rotated = rotated.iter().any(|r| {
        r.role == "node" && cert_node_name(&r.name).is_some_and(|n| !n.eq_ignore_ascii_case(&hostname))
    });
    if !g.json && deliver && remote_rotated {
        println!("{}", ui::phase("deliver"));
    }
    // One delivery per node: its cert bundle carries node.crt AND every
    // backend door leaf, so a node whose cert and leaves all rotated is
    // staged once, not once per file (a second staging would find the first
    // still pending and be skipped).
    let mut seen_nodes: Vec<String> = Vec::new();
    for r in &rotated {
        if r.role != "node" {
            continue;
        }
        let Some(node) = cert_node_name(&r.name) else { continue };
        if node.eq_ignore_ascii_case(&hostname) {
            continue; // the local agent reloads below, not over a rail
        }
        if seen_nodes.iter().any(|n| n.eq_ignore_ascii_case(node)) {
            continue;
        }
        seen_nodes.push(node.to_string());
        if !deliver {
            skipped_delivery.push(node.to_string());
            continue;
        }
        if !g.json {
            println!("{}", ui::item(node));
            println!("{}", ui::sub(&ui::status_line(Glyph::Step, "delivering the re-issued cert (pull-first, gate fallback)")));
        }
        let outcome = deliver_node_certs(g, &ca, node);
        if !g.json {
            let glyph = if outcome.ok() { Glyph::Ok } else { Glyph::Err };
            println!("{}", ui::sub(&ui::status_line(glyph, &outcome.label())));
        }
        deliveries.push((node.to_string(), outcome));
    }
    let undelivered = deliveries.iter().filter(|(_, d)| !d.ok()).count();
    if !skipped_delivery.is_empty() && !g.json {
        ui::close_warned(&format!("--no-deliver: re-issued certs for {} were not delivered: those nodes \
                  still run their old certs", skipped_delivery.join(", ")));
        ui::guide(&[
            ("noo security pki rotate-all", "re-runs with delivery"),
            ("noo security pki push-nodes", "delivers the already re-issued certs without rotating again"),
        ]);
    }

    let json_summary = |reloaded: &[String], healthy: Option<bool>, reverted: bool| {
        serde_json::json!({
            "expiring": expiring.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
            "results": results.iter().map(|r| serde_json::json!({
                "name": r.name, "role": r.role, "status": r.status,
                "error": if r.error.is_empty() { serde_json::Value::Null }
                         else { serde_json::Value::String(r.error.clone()) },
            })).collect::<Vec<_>>(),
            "reloaded": reloaded,
            "healthy": healthy,
            "reverted": reverted,
            "deliveries": deliveries.iter().map(|(n, d)| serde_json::json!({
                "node": n, "delivered": d.ok(), "detail": d.label(),
            })).collect::<Vec<_>>(),
            "backup": backup_dir.to_string_lossy(),
        })
    };
    // A rotation whose deliveries failed is NOT a success exit — the node
    // is still counting down on its old cert and someone must act.
    let exit_for_deliveries = |base: i32| -> i32 {
        if undelivered > 0 { 1 } else { base }
    };

    if rotated.is_empty() {
        if g.json {
            println!("{}", json_summary(&[], None, false));
        }
        return Ok(exit_for_deliveries(0));
    }

    if !reload {
        if g.json {
            println!("{}", json_summary(&[], None, false));
            return Ok(exit_for_deliveries(0));
        } else {
            if gateway_rotated {
                ui::close_warned("the gateway certificate was rotated: restart the gateway for the new cert to take effect");
                ui::guide(&[("noo stack restart", "picks up the rotated gateway certificate")]);
            }
            println!("{}", ui::note(&format!("backup kept at {}", backup_dir.display())));
        }
        return Ok(exit_for_deliveries(0));
    }

    // ── Reload consumers: services first, gateway last ──
    // fu72 #2, systemd-first: on a cut-over controller the node-agent is a
    // HOST UNIT — `docker restart` cannot reach it, and the old code printed
    // "No running consumers to reload." as a success over a silent no-op.
    if !g.json {
        println!("{}", ui::phase("reload"));
    }
    let mut reloaded_units: Vec<String> = Vec::new();
    let local_node_rotated = rotated.iter().any(|r| {
        r.role == "node"
            && cert_node_name(&r.name).is_some_and(|n| n.eq_ignore_ascii_case(&hostname))
    });
    if local_node_rotated && systemd_unit_known("noo-node-agent") {
        let _ = sync_self_agent_trust_plane(&ca, &hostname, g.json);
        if systemd_restart_unit("noo-node-agent") {
            if !g.json {
                ui::done("noo-node-agent (systemd) restarted on the new cert");
            }
            reloaded_units.push("noo-node-agent (systemd)".to_string());
        } else if !g.json {
            ui::warned("noo-node-agent (systemd) did NOT come back active");
            ui::guide(&[("systemctl status noo-node-agent", "shows why the agent did not come back")]);
        }
    }
    let running = running_containers();
    let mut to_restart: Vec<String> = Vec::new();
    for r in &rotated {
        for c in cert_consumers(&r.name, r.role, &hostname) {
            // cert_consumers speaks default-instance names; remap ONCE
            // here so the running-set match, the restarts and the health
            // probe all see this instance's real container names.
            let c = crate::envfile::instanced(&c);
            if running.contains(&c) && !to_restart.contains(&c) {
                to_restart.push(c);
            }
        }
    }
    // Suffix compare: instance prefixes vary (noo-gateway / noo-galaxy-gateway).
    to_restart.sort_by_key(|c| c.ends_with("-gateway")); // stable: gateway last

    if to_restart.is_empty() {
        if g.json {
            println!("{}", json_summary(&reloaded_units, None, false));
        } else if reloaded_units.is_empty() {
            println!("{}", ui::muted("no running consumers to reload"));
        }
        return Ok(exit_for_deliveries(0));
    }

    if !g.json {
        ui::step(&format!("reloading consumers: {}", to_restart.join(", ")));
    }
    for c in &to_restart {
        let _ = Command::new("docker").args(["restart", c]).output();
    }

    let (ok, detail) = probe_health(&to_restart, 150);
    if ok {
        let mut all_reloaded = reloaded_units.clone();
        all_reloaded.extend(to_restart.iter().cloned());
        if g.json {
            println!("{}", json_summary(&all_reloaded, Some(true), false));
        } else {
            ui::close_done(&format!("rotation applied: {detail}"));
            if undelivered > 0 {
                ui::warned(&format!("{undelivered} remote deliver{} failed (above): those nodes still run their old certs",
                    if undelivered == 1 { "y" } else { "ies" }));
            }
            println!("{}", ui::note(&format!("backup kept at {} (safe to delete)", backup_dir.display())));
            ui::guide(&[("noo security pki status", "confirms every certificate is on its new expiry")]);
        }
        return Ok(exit_for_deliveries(0));
    }

    // ── Revert: restore backed-up certs, restart again ──
    ui::close_failed(&format!("consumers unhealthy after rotation ({detail}): reverting"), None);
    if let Err(e) = copy_tree(&backup_dir, &ca.dir) {
        fail(
            g.json,
            ExitCode::Generic,
            "revert_failed",
            &format!("restore from backup failed: {e}"),
            Some(&format!("original certs are at {}", backup_dir.display())),
        );
    }
    for c in &to_restart {
        let _ = Command::new("docker").args(["restart", c]).output();
    }
    let (ok2, detail2) = probe_health(&to_restart, 150);
    if ok2 {
        fail(
            g.json,
            ExitCode::Generic,
            "rotation_reverted",
            &format!(
                "Reverted to previous certificates — investigate before retrying \
                 (old certs still expire soon; backup at {})",
                backup_dir.display()
            ),
            None,
        );
    } else {
        fail(
            g.json,
            ExitCode::Generic,
            "revert_unhealthy",
            &format!(
                "REVERT DID NOT RECOVER ({detail2}) — manual intervention needed; \
                 original certs are at {}",
                backup_dir.display()
            ),
            None,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// noo security trust-ca / untrust-ca  (port of onboard/ca_trust.py)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Plat {
    Wsl2,
    Macos,
    Linux,
}

fn detect_plat() -> Plat {
    if cfg!(target_os = "macos") {
        Plat::Macos
    } else if is_wsl2() {
        Plat::Wsl2
    } else {
        Plat::Linux
    }
}

/// Running inside WSL2? (`/proc/version` contains "microsoft" —
/// ca_trust._is_wsl2 parity).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Desktop session available? (DISPLAY or WAYLAND_DISPLAY set.)
fn has_desktop_session() -> bool {
    std::env::var("DISPLAY").map(|v| !v.is_empty()).unwrap_or(false)
        || std::env::var("WAYLAND_DISPLAY").map(|v| !v.is_empty()).unwrap_or(false)
}

/// `shutil.which` equivalent: first executable `name` on `$PATH`.
fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let cand = Path::new(dir).join(name);
        if let Ok(md) = std::fs::metadata(&cand) {
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return Some(cand);
            }
        }
    }
    None
}

/// POSIX single-quote escaping (shlex.quote-style) for the macOS
/// `do shell script` payload.
fn shquote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Build the FULL argv that runs `command` with native OS elevation on
/// `plat` — the pure core of ca_trust.py's `_run_elevated`, extracted so
/// tests can assert command construction without executing anything.
/// Returns None when no elevation method is available (Linux with neither
/// pkexec-with-desktop nor sudo — Python's `return -1` path).
pub(crate) fn elevated_argv(
    plat: Plat,
    command: &[&str],
    desktop: bool,
    have_pkexec: bool,
    have_sudo: bool,
) -> Option<Vec<String>> {
    match plat {
        Plat::Wsl2 => {
            // PowerShell Start-Process -Verb RunAs (Windows UAC). Same
            // quoting as Python: each arg after the program wrapped in
            // double quotes, space-joined.
            let args_str = if command.len() > 1 {
                command[1..]
                    .iter()
                    .map(|a| format!("\"{a}\""))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            };
            let ps_cmd = format!(
                "Start-Process -FilePath '{}' -ArgumentList '{args_str}' -Verb RunAs -Wait",
                command[0]
            );
            Some(vec![
                "powershell.exe".into(),
                "-NoProfile".into(),
                "-Command".into(),
                ps_cmd,
            ])
        }
        Plat::Macos => {
            // osascript native security dialog. (Python's version calls the
            // nonexistent `shutil.quote` and crashes; this is what it meant.)
            let shell_cmd = command.iter().map(|a| shquote(a)).collect::<Vec<_>>().join(" ");
            Some(vec![
                "osascript".into(),
                "-e".into(),
                format!("do shell script \"{shell_cmd}\" with administrator privileges"),
            ])
        }
        Plat::Linux => {
            let prefix = if desktop && have_pkexec {
                "pkexec"
            } else if have_sudo {
                "sudo"
            } else {
                return None;
            };
            let mut argv: Vec<String> = vec![prefix.into()];
            argv.extend(command.iter().map(|s| s.to_string()));
            Some(argv)
        }
    }
}

/// Run `command` elevated; returns the exit code, or -1 if elevation was
/// unavailable or spawning failed (ca_trust `_run_elevated` parity).
fn run_elevated(plat: Plat, command: &[&str]) -> i32 {
    let argv = match elevated_argv(
        plat,
        command,
        has_desktop_session(),
        which("pkexec").is_some(),
        which("sudo").is_some(),
    ) {
        Some(a) => a,
        None => return -1,
    };
    // pkexec/sudo may prompt on the controlling terminal — inherit stdio for
    // the prompt; Python captured output but nothing ever read it.
    match Command::new(&argv[0]).args(&argv[1..]).status() {
        Ok(s) => s.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// Message sink — collects (level, message) so `--json` can report what
/// happened while human mode prints as it goes (ca_trust `Emit` parity;
/// levels: info | success | warning).
struct Emitter {
    json: bool,
    messages: Vec<(String, String)>,
}

impl Emitter {
    fn new(json: bool) -> Self {
        Emitter { json, messages: Vec::new() }
    }
    fn emit(&mut self, level: &str, msg: &str) {
        if !self.json {
            // security_cli's _emit prints every level two-space indented;
            // narration → stdout (guide rev 2); the json summary carries
            // the messages in --json mode.
            for line in msg.lines() {
                println!("  {line}");
            }
        }
        self.messages.push((level.to_string(), msg.to_string()));
    }
}

const LINUX_CA_DIR: &str = "/usr/local/share/ca-certificates";
const LINUX_CA_DEST: &str = "/usr/local/share/ca-certificates/mesh-cluster-ca.crt";
const CA_CN: &str = "Mesh Cluster CA";

/// Is a cert with CN "Mesh Cluster CA" in the Windows Root store?
/// certutil -verifystore returns 0 iff found; a probe failure returns true
/// ("can't check — assume it might be there", Python parity).
fn wsl2_cert_in_store(certutil: &Path) -> bool {
    match Command::new(certutil)
        .args(["-verifystore", "Root", CA_CN])
        .output()
    {
        Ok(o) => o.status.success(),
        Err(_) => true,
    }
}

/// Install `ca_file` into the OS trust store. Returns true on success —
/// port of `ca_trust.install_ca_trust`, platform branch for branch.
fn install_ca_trust(plat: Plat, ca_file: &Path, em: &mut Emitter) -> bool {
    if !ca_file.exists() {
        em.emit("warning", &format!("CA cert not found: {}", ca_file.display()));
        return false;
    }
    match plat {
        // WSL2 installs into the LINUX store, same as native Linux. The old
        // behavior (Windows Root store via certutil) served browser trust,
        // which the MagicDNS access model made obsolete — the browser now
        // sees a public ts.net cert from `tailscale serve`. What the proxy
        // itself verifies the gateway against is the Linux system store of
        // the WSL2 distro tailscaled runs in; installing only into Windows
        // left a stale CA there and 502'd the tailnet dashboard (2026-08-06).
        Plat::Wsl2 => install_ca_linux_store(ca_file, em),
        Plat::Macos => {
            let ca = ca_file.to_string_lossy();
            let cmd = [
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                &ca,
            ];
            if run_elevated(plat, &cmd) == 0 {
                em.emit("success", "Cluster CA installed into macOS System Keychain");
                return true;
            }
            let fallback = std::iter::once("sudo")
                .chain(cmd)
                .map(shquote)
                .collect::<Vec<_>>()
                .join(" ");
            em.emit("warning", &format!("Could not install CA. Run manually:\n  {fallback}"));
            false
        }
        Plat::Linux => install_ca_linux_store(ca_file, em),
    }
}

/// Linux-store install shared by the Linux and WSL2 branches. Elevation is
/// always the Linux flavor (sudo/pkexec) — the WSL2 PowerShell/UAC path
/// must never be used for files inside the distro. A pre-existing file with
/// DIFFERENT bytes (a stale CA from a previous install) is REPLACED, never
/// kept — skip-if-present is what left a July CA in the store while
/// tailscaled failed to verify the new one.
fn install_ca_linux_store(ca_file: &Path, em: &mut Emitter) -> bool {
    if !Path::new(LINUX_CA_DIR).exists() {
        em.emit("warning", "Linux CA directory not found — cannot install CA trust");
        return false;
    }
    let dest = Path::new(LINUX_CA_DEST);
    // Already installed and up-to-date?
    if let (Ok(a), Ok(b)) = (std::fs::read(dest), std::fs::read(ca_file)) {
        if a == b {
            em.emit("success", "Cluster CA already installed in Linux trust store");
            return true;
        }
    }
    let ca = ca_file.to_string_lossy();
    if run_elevated(Plat::Linux, &["cp", &ca, LINUX_CA_DEST]) == 0
        && run_elevated(Plat::Linux, &["update-ca-certificates"]) == 0
    {
        em.emit("success", "Cluster CA installed into Linux trust store");
        // tailscaled reads the trust store at start — a CA replaced under a
        // running daemon is not seen until restart, and serve 502s until then.
        if which("tailscale").is_some() {
            em.emit(
                "info",
                "If tailscaled is running, restart it to pick up the new CA:\n  sudo systemctl restart tailscaled",
            );
        }
        return true;
    }
    em.emit(
        "warning",
        &format!(
            "Could not install CA. Run manually:\n  sudo cp {} {}\n  sudo update-ca-certificates",
            ca_file.display(),
            dest.display()
        ),
    );
    false
}

/// Remove the cluster CA from the OS trust store. Removal is keyed on the
/// certificate CN (or the known Linux filename), so it works even after the
/// CA PEM has been deleted — port of `ca_trust.remove_ca_trust`.
fn remove_ca_trust(plat: Plat, em: &mut Emitter) -> bool {
    match plat {
        // WSL2 removes from BOTH stores: the Linux store (where installs go
        // now) and the Windows Root store (where pre-flip installs put it —
        // legacy cleanup, best-effort).
        Plat::Wsl2 => {
            let linux_ok = remove_ca_linux_store(em);
            if let Some(certutil) = which("certutil.exe") {
                if wsl2_cert_in_store(&certutil) {
                    run_elevated(plat, &["certutil.exe", "-delstore", "Root", CA_CN]);
                    if !wsl2_cert_in_store(&certutil) {
                        em.emit("success", "Cluster CA removed from Windows trust store (legacy)");
                    } else {
                        em.emit(
                            "warning",
                            "Legacy Windows-store CA still present. Run from an elevated \
                             Command Prompt:\n  certutil.exe -delstore Root \"Mesh Cluster CA\"",
                        );
                    }
                }
            }
            linux_ok
        }
        Plat::Macos => {
            let cmd = [
                "security",
                "delete-certificate",
                "-c",
                CA_CN,
                "/Library/Keychains/System.keychain",
            ];
            if run_elevated(plat, &cmd) == 0 {
                em.emit("success", "Cluster CA removed from macOS System Keychain");
                return true;
            }
            let fallback = std::iter::once("sudo")
                .chain(cmd)
                .map(shquote)
                .collect::<Vec<_>>()
                .join(" ");
            em.emit("warning", &format!("Could not remove CA. Run manually:\n  {fallback}"));
            false
        }
        Plat::Linux => remove_ca_linux_store(em),
    }
}

/// Linux-store removal shared by the Linux and WSL2 branches (Linux-flavor
/// elevation in both cases).
fn remove_ca_linux_store(em: &mut Emitter) -> bool {
    let dest = Path::new(LINUX_CA_DEST);
    if !dest.exists() {
        em.emit("info", "Cluster CA not found in Linux trust store (already removed)");
        return true;
    }
    if run_elevated(Plat::Linux, &["rm", "-f", LINUX_CA_DEST]) == 0
        && run_elevated(Plat::Linux, &["update-ca-certificates", "--fresh"]) == 0
    {
        em.emit("success", "Cluster CA removed from Linux trust store");
        return true;
    }
    em.emit(
        "warning",
        &format!(
            "Could not remove CA. Run manually:\n  sudo rm -f {}\n  sudo update-ca-certificates --fresh",
            dest.display()
        ),
    );
    false
}

/// `noo security trust-ca [CA_PATH]` — install the cluster CA into the
/// OS/browser trust store (defaults to `$NOO_PKI_DIR/ca.crt`). Missing CA
/// file → exit 1 with the pki-init hint; an install that could not complete
/// still exits 0 after printing the manual fallback (Python parity).
pub fn security_trust_ca(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut ca_path: Option<String> = None;
    for tok in args {
        if tok.starts_with('-') {
            return Err(Unhandled);
        }
        if ca_path.is_some() {
            return Err(Unhandled);
        }
        ca_path = Some(tok.clone());
    }
    let ca_file = ca_path
        .map(PathBuf::from)
        .unwrap_or_else(|| pki_dir().join("ca.crt"));

    if !ca_file.exists() {
        fail(
            g.json,
            ExitCode::Generic,
            "ca_not_found",
            &format!("CA cert not found: {}", ca_file.display()),
            Some("Run 'noo security pki init' or 'noo onboard' first."),
        );
    }

    if !g.json {
        eprint!("{}", ui::kv(&[("  CA cert", ca_file.display().to_string())]));
    }
    let mut em = Emitter::new(g.json);
    let installed = install_ca_trust(detect_plat(), &ca_file, &mut em);

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "installed": installed,
                "ca": ca_file.to_string_lossy(),
                "messages": em.messages.iter().map(|(l, m)| {
                    serde_json::json!({ "level": l, "message": m })
                }).collect::<Vec<_>>(),
            })
        );
    } else if installed {
        ui::done("CA trusted by the operating system (curl, noo, system tools)");
        // Chrome/Chromium on Linux and Firefox keep their own stores, and WSL2
        // installs into the Linux distro, not Windows: say so rather than promise.
        println!("{}", ui::note("Chrome/Chromium on Linux and Firefox read their own stores, and a Windows browser does not read WSL2's: see docs/getting-started/trust-the-cluster-ca.md"));
        ui::guide(&[
            ("noo health", "the gateway over https, now without a certificate warning"),
            ("noo security untrust-ca", "removes the CA from the OS trust store again"),
        ]);
    } else {
        ui::warned(&format!("not installed automatically: to trust manually, install {} into your OS certificate store", ca_file.display()));
    }
    Ok(0)
}

/// `noo security untrust-ca [-y/--yes]` — remove the cluster CA from the OS
/// trust store. Destructive → agent-first confirm contract. Removal is keyed
/// on the certificate CN, not a file (it works after the PEM is deleted), so
/// there is no CA path to give: passing one is refused rather than ignored.
pub fn security_untrust_ca(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => fail(
                g.json,
                ExitCode::Usage,
                "unexpected_argument",
                &format!("untrust-ca takes no CA path ('{t}'): it removes the cluster CA by name, whatever file it came from"),
                Some("noo security untrust-ca [--yes]"),
            ),
        }
    }

    super::confirm_destructive(g, yes, "untrust", "cluster CA from OS trust store");

    let mut em = Emitter::new(g.json);
    let removed = remove_ca_trust(detect_plat(), &mut em);

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "removed": removed,
                "messages": em.messages.iter().map(|(l, m)| {
                    serde_json::json!({ "level": l, "message": m })
                }).collect::<Vec<_>>(),
            })
        );
    } else if removed {
        ui::done("CA removed from OS trust store");
        ui::guide(&[("noo security trust-ca", "re-trusts the CA if you still use the dashboard from this machine")]);
    } else {
        ui::warned("could not auto-remove: see the instructions above for manual removal");
    }
    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // ── what happens to a plaintext secret file beside the store ──
    #[test]
    fn residue_rule_shreds_only_what_the_store_already_holds() {
        use super::{residue_decision, Residue};
        // Dead copy: the store has the same value.
        assert_eq!(residue_decision("abc\n", Some("abc"), false), Residue::Shred);
        // Only copy: the store has nothing (or a blank) for the key.
        assert_eq!(residue_decision("abc", None, false), Residue::Absorb);
        assert_eq!(residue_decision("abc", Some("  "), false), Residue::Absorb);
        // Disagreement is a human's call, never a silent shred.
        assert_eq!(residue_decision("abc", Some("xyz"), false), Residue::Conflict);
        // An empty file holds nothing worth keeping.
        assert_eq!(residue_decision("  \n", None, false), Residue::Shred);
        // The admin bcrypt hash is disposable exactly when the password it
        // hashes is stored; it can never be absorbed as if it were one.
        assert_eq!(residue_decision("$2b$12$hash", Some("pw"), true), Residue::Shred);
        assert_eq!(residue_decision("$2b$12$hash", None, true), Residue::Conflict);
    }

    // ── who a signing-key rollout is for (live finding, host8 2026-09-12) ──
    //
    // The rollout enumerated `<pki>/nodes/*`. `host8` had been removed from
    // the registry by `noo cluster forget` and its key material left on
    // disk, so the rollout called it a node, could not deliver to it, and
    // reported it as a STRAGGLER — telling the operator the fleet was not
    // rolled, naming a node that does not exist, fixable only by deleting a
    // directory by hand.

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_forgotten_nodes_leftover_pki_dir_is_orphaned_material_not_a_straggler() {
        let t = super::split_rollout_targets(
            &v(&["host3", "host9"]),                    // the registry
            &v(&["host3", "host9", "host8"]),           // what is on disk
            "controller",
            None,
        );
        assert_eq!(t.nodes, v(&["host3", "host9"]), "host8 must not be a rollout target");
        assert_eq!(t.orphaned, v(&["host8"]), "host8 must be reported as orphaned material");
        assert!(t.no_material.is_empty());
    }

    #[test]
    fn the_registry_is_the_authority_even_when_no_cert_was_issued_here() {
        // A node registered with this controller but provisioned elsewhere
        // still needs the signing key: it is not a certificate, so a missing
        // node.crt is irrelevant to whether the key can be delivered. The
        // directory-walk version skipped these silently.
        let t = super::split_rollout_targets(&v(&["host3", "host6"]), &v(&["host3"]), "controller", None);
        assert_eq!(t.nodes, v(&["host3", "host6"]));
        assert_eq!(t.no_material, v(&["host6"]), "surfaced, but not as a failure");
        assert!(t.orphaned.is_empty());
    }

    #[test]
    fn the_controllers_own_node_is_a_rollout_target_when_it_is_registered() {
        // This test used to assert the opposite, on the reasoning that the
        // controller's certs are local files and there is no bundle to
        // deliver to itself. That stopped being true when the controller
        // became a node: its agent polls and applies bundles like any other,
        // so it needs the fleet signing key like any other. Excluded, it
        // verified every bundle on the CA-signed compatibility lane — the one
        // removed next release — and `rotate-signing-key host8` answered
        // "not registered" while `cluster status` listed it Online.
        let t = super::split_rollout_targets(
            &v(&["HOST8", "host3"]),
            &v(&["host8", "host3"]),
            "host8",
            None,
        );
        assert_eq!(t.nodes, v(&["HOST8", "host3"]), "the self node is rolled too");
        assert!(t.orphaned.is_empty(), "{:?}", t.orphaned);
    }

    #[test]
    fn a_controller_that_is_not_a_node_is_still_never_a_target_or_an_orphan() {
        // The other half, and the reason the registry is the authority: a
        // plain controller does not appear in the registry, so it cannot
        // become a target — and its own key material must not read as a
        // forgotten node's leftovers either.
        let t = super::split_rollout_targets(
            &v(&["host3", "host9"]),
            &v(&["host8", "host3", "host9"]),
            "host8",
            None,
        );
        assert_eq!(t.nodes, v(&["host3", "host9"]));
        assert!(t.orphaned.is_empty(), "{:?}", t.orphaned);
    }

    #[test]
    fn naming_one_node_narrows_the_rollout_but_not_the_orphan_report() {
        // The orphan list is a property of the controller's disk, not of the
        // node being rolled — an operator rolling one node should still be
        // told there is material with nobody behind it.
        let t = super::split_rollout_targets(
            &v(&["host3", "host9"]),
            &v(&["host3", "host9", "host8"]),
            "controller",
            Some("host3"),
        );
        assert_eq!(t.nodes, v(&["host3"]));
        assert_eq!(t.orphaned, v(&["host8"]));
    }

    #[test]
    fn an_empty_registry_yields_no_targets_and_every_dir_is_orphaned() {
        // The shape the caller MUST NOT act on: `fleet_nodes_from_registry`
        // returns empty on any transport trouble, and "no nodes" would read
        // as "the whole fleet is rolled". The split is honest about it; the
        // verb guards the gateway separately, and
        // `rotate_signing_key_refuses_to_report_against_an_unreadable_registry`
        // in tests/security_local.rs pins that.
        let t = super::split_rollout_targets(&[], &v(&["host3"]), "controller", None);
        assert!(t.nodes.is_empty());
        assert_eq!(t.orphaned, v(&["host3"]));
    }

    // ── what counts as proof, and what counts as a STRAGGLER ──────────────
    //
    // Two axes, not one: did the bundle arrive, and can this node speak?
    // Conflating them either marks a node adopted on no evidence (host6,
    // 2026-09-12) or makes every un-upgraded Mac a permanent straggler
    // that holds the C4 gate shut forever.

    #[test]
    fn only_a_positive_apply_report_proves_adoption() {
        use super::{adoption_of, Adoption, CertDelivery};
        for reports in [true, false] {
            assert_eq!(adoption_of(&CertDelivery::Applied, reports), Adoption::Adopted);
            assert_eq!(adoption_of(&CertDelivery::Verified, reports), Adoption::Adopted);
        }
    }

    #[test]
    fn a_node_that_cannot_report_is_no_report_and_never_a_straggler() {
        // THE host6 CASE, and the C4 gate case. Every Mac on noo-cli
        // <= 0.5.27 POSTs nothing to /bootstrap/bundle/<node>/applied — on
        // success OR failure — so `Collected` is the best it can ever reach.
        //
        // Marking it adopted would have the controller sign later bundles
        // with a key host6 may not hold, and a node that cannot verify a
        // bundle refuses ALL of them. Marking it a straggler would block the
        // gate that closes the CA-signed lane on nodes that are probably
        // fine. It is neither.
        use super::{adoption_of, Adoption, CertDelivery};
        assert!(CertDelivery::Collected.ok(), "premise: this IS a delivery success");

        let a = adoption_of(&CertDelivery::Collected, false);
        assert_eq!(a, Adoption::NoReport);
        assert_ne!(a, Adoption::Adopted, "a delivery success is not an adoption proof");
        assert!(!a.blocks_the_gate(), "an un-upgraded Mac must not hold the C4 gate shut");
    }

    #[test]
    fn a_node_that_can_report_and_stayed_silent_is_a_straggler() {
        // The other side of the same coin, and the reason the rule needs
        // the second input at all: identical delivery outcome, opposite
        // verdict, because THIS node's build can talk and chose not to.
        use super::{adoption_of, Adoption, CertDelivery};
        let a = adoption_of(&CertDelivery::Collected, true);
        assert_eq!(a, Adoption::NotAdopted);
        assert!(a.blocks_the_gate());
        assert_ne!(
            a, adoption_of(&CertDelivery::Collected, false),
            "the same outcome must classify differently by whether the node can report"
        );
    }

    #[test]
    fn a_bundle_that_was_never_collected_is_a_straggler_even_on_a_silent_node() {
        // Deliberately NOT excused by the report gap. `fetched_at` is
        // written by the GATEWAY when the fetcher pulls the blob, so an
        // un-collected bundle is observable whether or not the node can
        // report — it is a real delivery failure, not an absence of
        // evidence, and excusing it would hide a dead fetch timer behind
        // "old CLI".
        use super::{adoption_of, Adoption, CertDelivery};
        for reports in [true, false] {
            for d in [
                CertDelivery::Staged,
                CertDelivery::FetchedUnconfirmed,
                CertDelivery::SkippedPending,
                CertDelivery::Failed("gateway unreachable".into()),
            ] {
                let a = adoption_of(&d, reports);
                assert_eq!(a, Adoption::NotAdopted, "{d:?} reports={reports}");
                assert!(a.blocks_the_gate(), "{d:?} reports={reports}");
            }
        }
    }

    #[test]
    fn exactly_one_class_blocks_the_gate() {
        // Pinned as a property rather than left implicit: the gate reads
        // this, and a fourth class added later must make a deliberate
        // choice here rather than inheriting one.
        use super::Adoption;
        assert!(!Adoption::Adopted.blocks_the_gate());
        assert!(!Adoption::NoReport.blocks_the_gate());
        assert!(Adoption::NotAdopted.blocks_the_gate());
    }

    // ── the scan's exit code IS the verdict ────────────────
    //
    // `security_scan` used to return Ok(0) on every path, including the one
    // that printed "N critical issue(s) found". A CI gate or a pre-commit
    // hook written against it passed silently on a critical finding — the
    // repo's own silent-success pattern, in the tool whose job is to find
    // that pattern elsewhere.

    fn f(sev: &'static str) -> super::Finding {
        (sev, "check", String::from("detail"))
    }

    #[test]
    fn a_clean_scan_exits_zero_in_both_modes() {
        assert_eq!(super::scan_exit(&[], false), 0);
        assert_eq!(super::scan_exit(&[], true), 0);
    }

    #[test]
    fn a_critical_finding_fails_the_command() {
        assert_eq!(super::scan_exit(&[f("CRITICAL")], false), 1);
        assert_eq!(super::scan_exit(&[f("LOW"), f("CRITICAL")], false), 1);
    }

    #[test]
    fn sub_critical_findings_do_not_fail_the_default_mode() {
        // A dev box with no TLS configured must not fail every script that
        // happens to run the scan; that is what --strict is for.
        let issues = [f("HIGH"), f("MEDIUM"), f("LOW")];
        assert_eq!(super::scan_exit(&issues, false), 0);
    }

    #[test]
    fn strict_fails_on_anything_at_all() {
        for sev in ["HIGH", "MEDIUM", "LOW"] {
            assert_eq!(super::scan_exit(&[f(sev)], true), 1, "--strict ignored a {sev} finding");
        }
    }

    #[test]
    fn the_json_and_human_paths_cannot_disagree_about_ok() {
        // Both call the same function; this pins that they still do, because
        // two copies of the rule is how they drift.
        let src = include_str!("security_local.rs");
        let calls = src.matches("scan_exit(&issues, strict)").count();
        assert!(calls >= 3, "scan_exit is called {calls} times; the json path, the \
                             findings path and the ok flag must all use it");
    }

    #[test]
    fn dismantle_hint_branches_on_the_reported_os() {
        let mac = super::dismantle_hint("host6", Some("darwin"));
        assert!(mac.iter().any(|(c, _)| c.contains("launchctl bootout system/net.noomesh.node-agent")));
        assert!(mac.iter().any(|(c, _)| c == "noo cluster forget host6"));
        assert!(mac.iter().all(|(c, _)| !c.contains("noo-deenroll")), "a Mac has no noo-deenroll");
        for os in [Some("linux"), None] {
            let lin = super::dismantle_hint("host3", os);
            assert_eq!(lin.len(), 1);
            assert_eq!(lin[0].0, "sudo noo-deenroll");
        }
    }

    use super::CertDelivery;

    /// The defect this file has now hit twice: rotation reporting a delivery
    /// it cannot demonstrate. fu72 #6 fixed the version that printed
    /// "rotated" and delivered nothing; this pins the subtler one, where a
    /// 150s wait that produced no proof fell through to `Collected` and
    /// `ok()` counted it as delivered.
    ///
    /// Staged means the bytes are at the gateway and nothing has confirmed
    /// the node installed them. That is not delivery, and under
    /// cert-derived identity it is the difference between a rotated node
    /// and a locked-out one.
    #[test]
    fn staged_is_not_delivered() {
        assert!(!CertDelivery::Staged.ok());
        assert!(!CertDelivery::FetchedUnconfirmed.ok(), "a fetch is not a delivery (#83)");
        assert!(!CertDelivery::SkippedPending.ok());
        assert!(!CertDelivery::Failed("boom".into()).ok());
    }

    /// Positive proofs, in the order the code prefers them: the node is
    /// PRESENTING the new cert, or it RAN the apply and reported exit 0.
    /// Both are observations of the node, not of the controller's disk.
    #[test]
    fn only_node_side_proof_counts_as_delivered() {
        assert!(CertDelivery::Verified.ok());
        assert!(CertDelivery::Applied.ok());
    }

    /// host3, v0.2.93 roll: the report arrived after the first poll (and a
    /// minute past the old 180 s window). The wait must outlast the idle
    /// fetch cadence and see it, with no real sleeping.
    #[test]
    fn a_report_arriving_after_the_first_poll_is_seen() {
        let staged = serde_json::json!({ "sha256": "abc", "staged_at": "t", "fetched_at": null });
        let applied = serde_json::json!({ "sha256": "abc", "staged_at": "t", "fetched_at": null,
                                          "applied_sha": "abc", "apply_rc": 0 });
        assert!(!fetch_seen(&staged));
        assert!(fetch_seen(&applied), "an apply report for the staged sha proves the fetch");
        let stale = serde_json::json!({ "sha256": "new", "applied_sha": "old", "apply_rc": 0 });
        assert!(!fetch_seen(&stale), "a report for an EARLIER bundle is not this fetch");

        let (mut slept, mut probes) = (Duration::ZERO, 0);
        let got = poll_until(FETCH_WAIT, POLL_STEP, &mut |d| slept += d, &mut || {
            probes += 1;
            fetch_seen(if probes >= 8 { &applied } else { &staged }).then_some(())
        });
        assert!(got.is_some());
        assert_eq!(slept, POLL_STEP * 7, "slept only until the report arrived");
        assert!(FETCH_WAIT >= Duration::from_secs(2 * 3 * 70), "two idle cadences at ~70 s/tick");
    }

    #[test]
    fn a_wait_that_truly_times_out_spends_the_whole_window_and_says_not_confirmed() {
        let mut slept = Duration::ZERO;
        let got: Option<()> = poll_until(FETCH_WAIT, POLL_STEP, &mut |d| slept += d, &mut || None);
        assert!(got.is_none());
        assert_eq!(slept, FETCH_WAIT);
        assert!(CertDelivery::Staged.label().contains("420 s"));
    }

    /// Every outcome says which evidence it rests on, because "delivered"
    /// alone is what let the self-soothing loop run: the expiry alert
    /// cleared while the node kept serving its old cert.
    #[test]
    fn labels_name_their_evidence() {
        assert!(CertDelivery::Applied.label().contains("exit 0"));
        assert!(CertDelivery::Verified.label().contains("presents"));
        let st = CertDelivery::Staged.label();
        assert!(st.contains("not confirmed within") && st.contains("~70 s") && st.contains("re-run to check"), "{st}");
        assert!(!st.contains("has not fetched"), "a timeout must not claim the node never fetched: {st}");
        // The incident: a bundle the node DID collect was labelled "has not
        // fetched it yet". The two labels must not be interchangeable.
        let f = CertDelivery::FetchedUnconfirmed.label();
        assert!(f.contains("fetched, apply NOT confirmed") && f.contains("noo cluster verify"), "{f}");
        assert!(!f.contains("has not fetched"), "{f}");
    }

    use super::*;

    // ── secret formats ──────────────────────────────────────────────────

    #[test]
    fn token_urlsafe_shape() {
        let t = token_urlsafe(32);
        assert_eq!(t.len(), 43, "token_urlsafe(32) is 43 chars like Python");
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(token_urlsafe(32), token_urlsafe(32));
        // Other entropy sizes: ceil(4n/3) chars, no padding.
        assert_eq!(token_urlsafe(16).len(), 22);
        assert_eq!(token_urlsafe(64).len(), 86);
    }

    #[test]
    fn fernet_key_shape() {
        // Fernet.generate_key() = urlsafe_b64encode(urandom(32)) — 44 chars,
        // padded (32 bytes → 43 data chars + one '=').
        let k = fernet_key();
        assert_eq!(k.len(), 44);
        assert!(k.ends_with('='));
        assert!(k[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn b64url_known_vectors() {
        // RFC 4648 vectors, urlsafe alphabet.
        assert_eq!(b64url(b"", false), "");
        assert_eq!(b64url(b"f", false), "Zg");
        assert_eq!(b64url(b"f", true), "Zg==");
        assert_eq!(b64url(b"fo", true), "Zm8=");
        assert_eq!(b64url(b"foo", true), "Zm9v");
        assert_eq!(b64url(b"foob", true), "Zm9vYg==");
        assert_eq!(b64url(&[0xfb, 0xff], true), "-_8=");
        assert_eq!(b64url(&[0xfb, 0xff], false), "-_8");
    }

    // ── scan checks ─────────────────────────────────────────────────────

    fn clean_inputs() -> ScanInputs {
        ScanInputs {
            jwt_secret: "s3cret".into(),
            cluster_secret: "c".into(),
            redis_password: "r".into(),
            node_agent_token: "t".into(),
            env_mode: Some(0o100600),
            env_on_ntfs: false,
            tls_cert: "/x/cert.pem".into(),
            pki_ca_exists: true,
            gateway_url: "https://controller.example:8080".into(),
            gateway_trust: Ok(crate::http::Trust::Platform),
            grafana_password: "9f2a-a-real-generated-value".into(),
            lingering_passphrase_files: Vec::new(),
            pki_exposed_keys: Vec::new(),
            pki_unknown_reader_keys: Vec::new(),
            store_unreadable: None,
            docker_inline_auth_registries: Vec::new(),
            retired_nats_names: Vec::new(),
            runtime_residue: Vec::new(),
            retired_store_keys: Vec::new(),
            env_plaintext_secrets: None,
        }
    }

    /// 2026-09-28: over a non-interactive ssh, `sops` (in ~/.local/bin) was
    /// off PATH, the loader fell through silently, and the scan reported
    /// "JWT secret unset" CRITICAL for every key the store holds. The
    /// reader's failure is ONE finding at HIGH; it must never wear the
    /// "unset" findings' clothes.
    #[test]
    fn scan_reports_an_unreadable_store_once_and_never_as_unset() {
        let mut i = clean_inputs();
        i.jwt_secret.clear();
        i.cluster_secret.clear();
        i.redis_password.clear();
        i.node_agent_token.clear();
        i.grafana_password.clear();
        i.store_unreadable = Some("sops not found (searched PATH, /home/u/.local/bin)".into());
        let f = scan_findings(&i);
        let checks: Vec<&str> = f.iter().map(|(_, c, _)| *c).collect();
        assert_eq!(checks, vec!["Secret Store"], "one finding, not six: {f:?}");
        let (sev, _, detail) = &f[0];
        assert_eq!(*sev, "HIGH", "unknown posture is not a CRITICAL verdict");
        assert!(detail.contains("sops not found"), "must carry the classified cause: {detail}");
        assert!(detail.contains("nothing in this scan is evidence"), "{detail}");
        assert!(!detail.to_ascii_lowercase().contains("unset —"), "{detail}");
        // Default exit: a scan that could not decide does not fail a gate
        // the way a real CRITICAL does; --strict still does.
        assert_eq!(scan_exit(&f, false), 0);
        assert_eq!(scan_exit(&f, true), 1);
        // And a READABLE store with the same empty values still fires them
        // all — the gate suppresses the false alarm, not the real one.
        i.store_unreadable = None;
        let f = scan_findings(&i);
        assert!(f.iter().any(|(_, c, _)| *c == "JWT Secret"), "{f:?}");
        assert!(!f.iter().any(|(_, c, _)| *c == "Secret Store"), "{f:?}");
    }

    /// The shared NATS pair is RETIRED. A stored value is a
    /// LOW finding naming `noo security secrets tidy` (nothing deletes it
    /// automatically) — never the value, and never the
    /// old "set NATS_PASSWORD" advice for its absence.
    #[test]
    fn scan_flags_a_retired_nats_credential_and_never_asks_for_one() {
        let mut i = clean_inputs();
        i.retired_nats_names = vec!["NATS_USER".into(), "NATS_PASSWORD".into()];
        let f = scan_findings(&i);
        let hit = f.iter().find(|(_, c, _)| *c == "Retired NATS Credential")
            .unwrap_or_else(|| panic!("a stored retired pair must be flagged: {f:?}"));
        assert_eq!(hit.0, "LOW");
        for needle in ["NATS_USER, NATS_PASSWORD", "RETIRED", "noo security secrets tidy",
                       "/etc/noo-node-agent.env", "noo cluster provision <node>"] {
            assert!(hit.2.contains(needle), "missing {needle:?} in: {}", hit.2);
        }
        // Absent: nothing — the scan no longer asks anyone to SET it.
        let f = scan_findings(&clean_inputs());
        assert!(!f.iter().any(|(_, c, _)| *c == "Retired NATS Credential" || *c == "NATS Password"), "{f:?}");
        // An unreadable store says so once; it is not evidence either way.
        let mut i = clean_inputs();
        i.retired_nats_names = vec!["NATS_PASSWORD".into()];
        i.store_unreadable = Some("sops not found".into());
        assert!(!scan_findings(&i).iter().any(|(_, c, _)| *c == "Retired NATS Credential"));
        assert_eq!(RETIRED_NATS_NAMES, ["NATS_USER", "NATS_PASSWORD", "NOO_NATS_LEGACY_SHARED_CREDS"]);
    }

    /// The three blobs found on the controller and the dev box, as the
    /// shape `docker login` writes. Registries are named, values never
    /// appear, and a credential helper covering a registry clears it.
    #[test]
    fn docker_inline_auths_are_named_and_never_valued() {
        const BLOB: &str = "dXNlcjpnaHBfc2VjcmV0dG9rZW4=";
        let cfg = format!(r#"{{"auths":{{
            "ghcr.io":{{"auth":"{BLOB}"}},
            "https://index.docker.io/v1/":{{"auth":"{BLOB}"}},
            "dhi.io":{{"auth":"{BLOB}"}},
            "empty.example":{{"auth":""}},
            "helper.example":{{}}
        }}}}"#);
        let regs = docker_inline_auth_registries(&cfg);
        assert_eq!(regs, vec!["dhi.io", "ghcr.io", "https://index.docker.io/v1/"], "{regs:?}");

        // A helper for one registry clears that one; a global store clears all.
        let with_helper = cfg.replacen("{\"auths\"", "{\"credHelpers\":{\"ghcr.io\":\"pass\"},\"auths\"", 1);
        assert_eq!(docker_inline_auth_registries(&with_helper), vec!["dhi.io", "https://index.docker.io/v1/"]);
        let with_store = cfg.replacen("{\"auths\"", "{\"credsStore\":\"secretservice\",\"auths\"", 1);
        assert!(docker_inline_auth_registries(&with_store).is_empty());
        assert!(docker_inline_auth_registries("not json").is_empty());
        assert!(docker_inline_auth_registries("{}").is_empty());

        let mut i = clean_inputs();
        i.docker_inline_auth_registries = regs;
        let f = scan_findings(&i);
        let hit = f.iter().find(|(_, c, _)| *c == "Registry Credentials").expect("finding");
        assert_eq!(hit.0, "MEDIUM");
        assert!(!hit.2.contains(BLOB), "the blob must never be printed: {}", hit.2);
        for needle in ["ghcr.io", "dhi.io", "credential helper", "docker logout", "launcher needs"] {
            assert!(hit.2.contains(needle), "missing {needle:?}: {}", hit.2);
        }
        // ghcr.io is what the launcher pulls with; it is named as needed,
        // the other two as spare.
        assert!(hit.2.contains("nothing in the stack pulls from dhi.io, https://index.docker.io/v1/"), "{}", hit.2);
        // Only spare registries: no "keep ghcr" advice.
        let mut i = clean_inputs();
        i.docker_inline_auth_registries = vec!["dhi.io".into()];
        let f = scan_findings(&i);
        let hit = f.iter().find(|(_, c, _)| *c == "Registry Credentials").expect("finding");
        assert!(!hit.2.contains("launcher needs"), "{}", hit.2);
        assert!(hit.2.contains("docker logout"), "{}", hit.2);
    }

    /// The retired operator MCP token left in the store is reported as
    /// retired, with the command that removes it, and fails no gate.
    #[test]
    fn a_retired_credential_is_reported_with_its_removal_command() {
        let mut i = clean_inputs();
        assert!(!scan_findings(&i).iter().any(|(_, c, _)| *c == "Retired Credential"));
        i.retired_store_keys = vec!["NOO_MCP_TOKEN".into()];
        let f = scan_findings(&i);
        let hit = f.iter().find(|(_, c, _)| *c == "Retired Credential").expect("finding");
        assert_eq!(hit.0, "LOW");
        assert!(hit.2.contains("NOO_MCP_TOKEN") && hit.2.contains("noo security secrets tidy"), "{}", hit.2);
        assert!(hit.2.contains("mcp:operator"), "{}", hit.2);
        assert_eq!(scan_exit(&f, false), 0, "a retired leftover is not a CRITICAL");
    }

    /// A Google SA key sat 0644 under secrets/.runtime for five days after
    /// the launcher stopped materialising files there. Any file under that
    /// directory is residue; an empty directory is not.
    #[test]
    fn runtime_residue_is_every_file_under_secrets_runtime() {
        let root = std::env::temp_dir().join(format!("noo-scan-runtime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("secrets/.runtime")).unwrap();
        std::fs::write(root.join("secrets/env.sops"), "ENC[...]\n").unwrap();
        assert!(runtime_residue_files(&root).is_empty(), "an empty dir is not residue");
        assert!(runtime_residue_files(&root.join("nowhere")).is_empty());
        std::fs::write(root.join("secrets/.runtime/google-chat-sa-key.json"), "{}").unwrap();
        std::fs::create_dir_all(root.join("secrets/.runtime/nested")).unwrap();
        std::fs::write(root.join("secrets/.runtime/nested/x.pem"), "k").unwrap();
        let files = runtime_residue_files(&root);
        assert_eq!(files, vec![
            "secrets/.runtime/google-chat-sa-key.json".to_string(),
            "secrets/.runtime/nested/x.pem".to_string(),
        ]);
        let _ = std::fs::remove_dir_all(&root);

        let mut i = clean_inputs();
        i.runtime_residue = files;
        let f = scan_findings(&i);
        let hits: Vec<_> = f.iter().filter(|(_, c, _)| *c == "Runtime Residue Plaintext").collect();
        assert_eq!(hits.len(), 2, "{f:?}");
        assert_eq!(hits[0].0, "CRITICAL");
        assert!(hits[0].2.contains("shred -u secrets/.runtime/google-chat-sa-key.json"), "{}", hits[0].2);
        assert!(hits[0].2.contains("nothing writes or reads"), "{}", hits[0].2);
    }


    /// PLANTED: a 0644 private key under the PKI dir is CRITICAL and the
    /// finding names the file and the verb; a leaf with no reader row is a
    /// MEDIUM that names the table. Neither fires on a clean tree.
    #[test]
    fn scan_flags_an_exposed_private_key_as_critical() {
        let mut i = clean_inputs();
        i.pki_exposed_keys = vec!["nodes/host3/node.key 0644 (the CLI only)".into()];
        let f = scan_findings(&i);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].0, f[0].1), ("CRITICAL", "PKI Key Modes"));
        assert!(f[0].2.contains("nodes/host3/node.key 0644") && f[0].2.contains("pki fix-modes"), "{}", f[0].2);
        let mut i = clean_inputs();
        i.pki_unknown_reader_keys = vec!["services/mystery/service.key".into()];
        let f = scan_findings(&i);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].0, f[0].1), ("MEDIUM", "PKI Key Reader"));
        assert!(f[0].2.contains("SERVICE_KEY_READERS") && f[0].2.contains("services/mystery/service.key"), "{}", f[0].2);

    }

    #[test]
    fn scan_clean_config_has_no_findings() {
        assert!(scan_findings(&clean_inputs()).is_empty());
    }

    #[test]
    fn scan_flags_default_jwt_as_critical() {
        let mut i = clean_inputs();
        i.jwt_secret = "dev-secret-change-in-production".into();
        let f = scan_findings(&i);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, "CRITICAL");
        assert_eq!(f[0].1, "JWT Secret");
        i.jwt_secret = String::new();
        assert_eq!(scan_findings(&i).len(), 1);
    }

    #[test]
    fn scan_world_readable_env_flagged_unless_ntfs() {
        let mut i = clean_inputs();
        i.env_mode = Some(0o100644);
        let f = scan_findings(&i);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1, ".env Permissions");
        assert!(f[0].2.contains("0o100644"), "detail carries Python's oct(mode): {}", f[0].2);
        // NTFS/drvfs mount: chmod is a no-op there — no finding.
        i.env_on_ntfs = true;
        assert!(scan_findings(&i).is_empty());
        // Missing .env: no finding either.
        i.env_on_ntfs = false;
        i.env_mode = None;
        assert!(scan_findings(&i).is_empty());
    }

    /// A gateway the CLI cannot verify is CRITICAL, not a note —
    /// the CLI posts a bearer credential to it. Both shapes must fire:
    /// plain http to somewhere else, and https with no usable anchor.
    #[test]
    fn scan_flags_an_unverifiable_gateway_as_critical() {
        for (url, trust) in [
            (
                "http://gateway.internal:8080",
                Err("refusing to talk to http://gateway.internal:8080 over plain http:// — TLS is required".to_string()),
            ),
            (
                "https://gw.example:8080",
                Err("$NOO_TLS_CA points at /nope/ca.crt but it cannot be read".to_string()),
            ),
        ] {
            let mut i = clean_inputs();
            i.gateway_url = url.into();
            i.gateway_trust = trust;
            let f = scan_findings(&i);
            assert_eq!(f.len(), 1, "exactly one finding for {url}: {f:?}");
            assert_eq!(f[0].0, "CRITICAL", "{url} must be CRITICAL");
            assert_eq!(f[0].1, "Gateway Transport");
            assert!(f[0].2.contains(url), "the finding must name the URL: {}", f[0].2);
        }
    }

    /// The local-development carve-out is reported, but it is not a crisis:
    /// an http gateway on this machine is what `noo` defaults to before TLS
    /// is configured.
    #[test]
    fn scan_reports_loopback_http_as_low() {
        let mut i = clean_inputs();
        i.gateway_url = "http://localhost:8080".into();
        i.gateway_trust = Ok(crate::http::Trust::LoopbackPlaintext);
        let f = scan_findings(&i);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, "LOW");
        assert_eq!(f[0].1, "Gateway Transport");
    }

    /// A verified gateway produces nothing — the check must not fire on the
    /// healthy case, or it is noise and gets ignored.
    #[test]
    fn scan_is_silent_about_a_verified_gateway() {
        let mut i = clean_inputs();
        for t in [
            crate::http::Trust::Enrolled,
            crate::http::Trust::Platform,
            crate::http::Trust::ClusterCa("/etc/noo/pki/ca.crt".into()),
            crate::http::Trust::EnvCa("/x/ca.crt".into()),
        ] {
            i.gateway_trust = Ok(t.clone());
            assert!(scan_findings(&i).is_empty(), "{t:?} must not produce a finding");
        }
    }

    /// A secret in plaintext .env is CRITICAL (the scan exits 1), names the
    /// keys and never a value, and carries the remedy; none is no finding.
    #[test]
    fn a_secret_in_plaintext_env_is_critical_with_the_sops_remedy() {
        let env = vec![
            ("NOO_SECRETS_BACKEND".to_string(), "env".to_string()),
            ("NOO_JWT_SECRET".to_string(), "SENTINEL-plain-value".to_string()),
        ];
        let st = crate::commands::plaintext_env::AtRest {
            env_present: true,
            backend: "env".into(),
            store_present: false,
            store_path: Default::default(),
            plaintext: crate::commands::plaintext_env::plaintext_secret_keys(&env),
            store_split: None,
        };
        let mut i = clean_inputs();
        i.env_plaintext_secrets = st.plaintext_problem();
        let f = scan_findings(&i);
        let mine: Vec<_> = f.iter().filter(|(_, c, _)| *c == "Secrets At Rest").collect();
        assert_eq!(mine.len(), 1, "{f:?}");
        assert_eq!(mine[0].0, "CRITICAL");
        assert!(mine[0].2.contains("NOO_JWT_SECRET"), "{}", mine[0].2);
        assert!(!mine[0].2.contains("SENTINEL"), "{}", mine[0].2);
        assert!(mine[0].2.contains("--secrets-backend sops") && mine[0].2.contains("secrets tidy"), "{}", mine[0].2);
        assert_eq!(scan_exit(&f, false), 1);
        assert!(scan_findings(&clean_inputs()).iter().all(|(_, c, _)| *c != "Secrets At Rest"));
    }

    #[test]
    fn scan_full_check_list_and_severity_sort() {
        // Everything unset/missing → all 8 checks fire; sorted stably by
        // severity, HIGHs keep insertion order (Cluster before Node Agent).
        let i = ScanInputs {
            jwt_secret: String::new(),
            cluster_secret: String::new(),
            redis_password: String::new(),
            node_agent_token: String::new(),
            env_mode: Some(0o100664),
            env_on_ntfs: false,
            tls_cert: String::new(),
            pki_ca_exists: false,
            gateway_url: "https://controller.example:8080".into(),
            gateway_trust: Ok(crate::http::Trust::Platform),
            grafana_password: String::new(),
            pki_exposed_keys: Vec::new(),
            pki_unknown_reader_keys: Vec::new(),
            lingering_passphrase_files: Vec::new(),
            store_unreadable: None,
            docker_inline_auth_registries: Vec::new(),
            retired_nats_names: Vec::new(),
            runtime_residue: Vec::new(),
            retired_store_keys: Vec::new(),
            env_plaintext_secrets: None,
        };
        let mut f = scan_findings(&i);
        f.sort_by_key(|(sev, _, _)| severity_rank(sev));
        let order: Vec<&str> = f.iter().map(|(_, c, _)| *c).collect();
        assert_eq!(
            order,
            vec![
                "JWT Secret",
                "Cluster Secret",
                "Node Agent Token",
                "Redis Password",
                ".env Permissions",
                "TLS",
                "Grafana Password",
                "Cluster PKI",
            ]
        );
    }

    // The backup-passphrase change: onboard used to leave the age-backup passphrase in the clear
    // under secrets/. A scan that did not look for it is how it survived on
    // every controller.
    #[test]
    fn scan_flags_a_lingering_plaintext_passphrase_as_critical() {
        let mut i = clean_inputs();
        i.lingering_passphrase_files = vec!["secrets/age_backup_passphrase.txt".into()];
        let f = scan_findings(&i);
        let hit = f
            .iter()
            .find(|(_, c, _)| *c == "Backup Passphrase Plaintext")
            .expect("no finding — the lingering-plaintext check is not running");
        assert_eq!(hit.0, "CRITICAL");
        assert!(hit.2.contains("secrets/age_backup_passphrase.txt"), "{}", hit.2);
        // The finding has to say what to DO, or it is a nag.
        assert!(hit.2.contains("noo security secrets reveal"), "{}", hit.2);
        assert!(hit.2.contains("NOO_AGE_BACKUP_PASSPHRASE"), "{}", hit.2);
    }

    #[test]
    fn scan_names_the_right_variable_for_each_plaintext_file() {
        let mut i = clean_inputs();
        i.lingering_passphrase_files = vec!["secrets/backup_passphrase.txt".into()];
        let f = scan_findings(&i);
        let hit = f.iter().find(|(_, c, _)| *c == "Backup Passphrase Plaintext").unwrap();
        assert!(hit.2.contains("reveal NOO_BACKUP_PASSPHRASE"), "{}", hit.2);
    }

    // a value published in this repo is not a secret. The old scan
    // saw `changeme` and reported a clean posture, which is the whole reason
    // the placeholder survived in .env.example for as long as it did.
    #[test]
    fn scan_flags_published_grafana_placeholders_as_critical() {
        for bad in ["changeme", "CHANGEME", " admin ", "admin", "password"] {
            let mut i = clean_inputs();
            i.grafana_password = bad.into();
            let f = scan_findings(&i);
            let hit = f.iter().find(|(_, c, _)| *c == "Grafana Password");
            let Some((sev, _, detail)) = hit else {
                panic!("{bad:?}: no Grafana finding — the placeholder check is not running");
            };
            assert_eq!(*sev, "CRITICAL", "{bad:?}");
            assert!(detail.contains("published placeholder"), "{bad:?}: {detail}");
        }
    }

    // The complement: a generated secret must NOT fire, or operators learn
    // to ignore the finding and the check is worth less than nothing.
    #[test]
    fn scan_accepts_a_generated_grafana_password() {
        let mut i = clean_inputs();
        i.grafana_password = token_urlsafe(24);
        assert!(
            !scan_findings(&i).iter().any(|(_, c, _)| *c == "Grafana Password"),
            "a generated password must not be flagged"
        );
        // ...and the guard really can fail: prove it with a known-bad value
        // through the same path, so a check that silently stopped running
        // cannot pass this test.
        i.grafana_password = "changeme".into();
        assert!(scan_findings(&i).iter().any(|(_, c, _)| *c == "Grafana Password"));
    }

    #[test]
    fn ntfs_mount_detection_longest_prefix_wins() {
        let mounts = "\
rootfs / ext4 rw 0 0
C:\\ /mnt/c drvfs rw 0 0
none /mnt/c/deeper tmpfs rw 0 0
";
        assert!(is_ntfs_fs(mounts, "/mnt/c/Users/x/.env"));
        // Longer, non-NTFS mount shadows the drvfs one.
        assert!(!is_ntfs_fs(mounts, "/mnt/c/deeper/.env"));
        assert!(!is_ntfs_fs(mounts, "/home/x/.env"));
        assert!(!is_ntfs_fs("", "/anything"));
    }

    // ── rotate-all pieces ──────────────────────────────────────────────

    #[test]
    fn transition_anchor_puts_the_new_ca_first() {
        // noo-apply (and every verifier) reads the FIRST cert in the anchor:
        // post-transition bundles are new-key-signed, so NEW must lead. The
        // transition bundle itself is old-key-signed and verified against
        // the node's PRE-transition anchor, so OLD trailing is only for the
        // TLS trust pool.
        let new_pem = "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n";
        let old_pem = "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n";
        let anchor = format!("{}\n{}", new_pem.trim_end(), old_pem.trim_start());
        assert!(anchor.starts_with("-----BEGIN CERTIFICATE-----\nNEW"));
        assert!(anchor.contains("OLD"));
        assert_eq!(first_pem_block(&anchor).unwrap().trim(),
                   new_pem.trim(), "retire must recover exactly the new CA");
    }

    #[test]
    fn cert_node_name_extracts_only_node_paths() {
        assert_eq!(cert_node_name("nodes/host5/node.crt"), Some("host5"));
        assert_eq!(cert_node_name("gateway/gateway.crt"), None);
        assert_eq!(cert_node_name("services/nats/service.crt"), None);
        assert_eq!(cert_node_name("nodes/host5/services/vllm/service.crt"), Some("host5"));
    }

    #[test]
    fn cert_delivery_ok_matches_the_honest_set() {
        assert!(CertDelivery::Verified.ok());
        assert!(CertDelivery::Collected.ok());
        assert!(!CertDelivery::Staged.ok());
        assert!(!CertDelivery::SkippedPending.ok());
        assert!(!CertDelivery::Failed("x".into()).ok());
    }

    #[test]
    fn cert_consumers_mapping() {
        // consumers.py parity.
        assert_eq!(
            cert_consumers("gateway/gateway.crt", "gateway", "host1"),
            vec!["noo-gateway"]
        );
        assert_eq!(
            cert_consumers("services/nats/service.crt", "service", "host1"),
            vec!["noo-nats", "noo-stunnel-nats"]
        );
        // Node cert: only the CONTROLLER-LOCAL node-agent, keyed on hostname.
        assert_eq!(
            cert_consumers("nodes/host1/node.crt", "node", "host1"),
            vec!["noo-node-agent"]
        );
        assert!(cert_consumers("nodes/worker2/node.crt", "node", "host1").is_empty());
        assert!(cert_consumers("nodes/host1/node.crt", "node", "").is_empty());
        assert!(cert_consumers("ca.crt", "ca", "host1").is_empty());
    }

    #[test]
    fn gateway_restarts_last() {
        let mut v: Vec<String> = vec![
            "noo-gateway".into(),
            "noo-nats".into(),
            "noo-stunnel-nats".into(),
        ];
        v.sort_by_key(|c| c == "noo-gateway");
        assert_eq!(v.last().map(String::as_str), Some("noo-gateway"));
        assert_eq!(&v[..2], &["noo-nats".to_string(), "noo-stunnel-nats".to_string()]);
    }

    // ── trust-ca command construction ───────────────────────────────────

    #[test]
    fn elevated_argv_wsl2_uses_powershell_runas() {
        let argv = elevated_argv(
            Plat::Wsl2,
            &["certutil.exe", "-addstore", "-f", "Root", "C:\\ca.crt"],
            false,
            false,
            false,
        )
        .unwrap();
        assert_eq!(argv[0], "powershell.exe");
        assert_eq!(argv[1], "-NoProfile");
        assert_eq!(argv[2], "-Command");
        // Python's exact Start-Process construction: program in -FilePath,
        // remaining args double-quoted and space-joined in -ArgumentList.
        assert_eq!(
            argv[3],
            "Start-Process -FilePath 'certutil.exe' \
             -ArgumentList '\"-addstore\" \"-f\" \"Root\" \"C:\\ca.crt\"' -Verb RunAs -Wait"
        );
    }

    #[test]
    fn elevated_argv_macos_uses_osascript_admin() {
        let argv = elevated_argv(
            Plat::Macos,
            &[
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                "/tmp/ca file.crt",
            ],
            false,
            false,
            false,
        )
        .unwrap();
        assert_eq!(argv[0], "osascript");
        assert_eq!(argv[1], "-e");
        assert_eq!(
            argv[2],
            "do shell script \"security add-trusted-cert -d -r trustRoot \
             -k /Library/Keychains/System.keychain '/tmp/ca file.crt'\" \
             with administrator privileges"
        );
    }

    #[test]
    fn elevated_argv_linux_prefers_pkexec_with_desktop() {
        // Desktop + pkexec → pkexec.
        assert_eq!(
            elevated_argv(Plat::Linux, &["update-ca-certificates"], true, true, true).unwrap(),
            vec!["pkexec".to_string(), "update-ca-certificates".to_string()]
        );
        // No desktop → sudo even when pkexec exists.
        assert_eq!(
            elevated_argv(Plat::Linux, &["rm", "-f", "/x"], false, true, true).unwrap(),
            vec!["sudo".to_string(), "rm".to_string(), "-f".to_string(), "/x".to_string()]
        );
        // Desktop but no pkexec → sudo.
        assert_eq!(
            elevated_argv(Plat::Linux, &["cp", "a", "b"], true, false, true).unwrap()[0],
            "sudo"
        );
        // Nothing available → None (Python's -1 path).
        assert!(elevated_argv(Plat::Linux, &["cp", "a", "b"], true, false, false).is_none());
    }

    #[test]
    fn shquote_matches_shlex_quote() {
        assert_eq!(shquote("simple-arg_1.2/ok"), "simple-arg_1.2/ok");
        assert_eq!(shquote("has space"), "'has space'");
        assert_eq!(shquote("it's"), "'it'\\''s'");
        assert_eq!(shquote(""), "''");
    }

}

#[cfg(test)]
mod node_leaf_bundle_tests {
    use super::*;
    use crate::commands::node_leaves::{ensure_node_leaves, NODE_DOOR_LEAVES};

    fn sha(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn built(name: &str, with_leaves: bool) -> (ClusterCa, PathBuf) {
        let dir = std::env::temp_dir().join(format!("noo-leafbundle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = ClusterCa::new(dir.join("pki"));
        ca.generate_ca("noo-test-ca", 3650).unwrap();
        ca.issue_node_cert("host3", "10.0.0.2", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        ensure_node_leaves(&ca, "host3", 90).unwrap();
        // A node that has not adopted gets no CA-signed bundle
        // but the key itself, so the fixture node has adopted.
        ca.ensure_signing_key().unwrap();
        let marker = ca.signing_adopted_path("host3");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "x\n").unwrap();
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        build_signed_cert_bundle(&ca, "host3", &work, with_leaves).expect("bundle");
        (ca, work)
    }

    /// The cert bundle carries every door leaf, each hashed in the manifest,
    /// and the signature over that manifest verifies — so the leaves are
    /// covered by the same signature noo-apply checks, and a swapped key
    /// file fails the node's sha check.
    #[test]
    fn the_cert_bundle_carries_each_leaf_under_the_signature() {
        let (ca, work) = built("carry", true);
        let manifest = std::fs::read_to_string(work.join("manifest")).unwrap();
        for l in NODE_DOOR_LEAVES {
            for kind in [l.crt_kind, l.key_kind] {
                let body = std::fs::read(work.join("files").join(kind))
                    .unwrap_or_else(|_| panic!("bundle lacks {kind}"));
                assert!(manifest.contains(&format!("{}  {kind}\n", sha(&body))), "{kind} not hashed in the manifest");
            }
            let key = std::fs::read(ca.node_service_dir("host3", l.service).join("service.key")).unwrap();
            assert_eq!(std::fs::read(work.join("files").join(l.key_kind)).unwrap(), key);
        }
        // Signature: the node has adopted, so the fleet signing key signs
        let pubkey = ca.signing_pub_path();
        let verifies = |m: &Path| Command::new("openssl").args(["dgst", "-sha256", "-verify"]).arg(&pubkey)
            .arg("-signature").arg(work.join("manifest.sig")).arg(m)
            .status().map(|s| s.success()).unwrap_or(false);
        assert!(verifies(&work.join("manifest")), "the signature does not verify");
        // Dropping one leaf line from the manifest breaks it: the leaves are
        // inside what was signed, not beside it.
        let cut: String = manifest.lines().filter(|l| !l.ends_with("svc-vllm.key"))
            .map(|l| format!("{l}\n")).collect();
        let cut_path = work.join("manifest.cut");
        std::fs::write(&cut_path, cut).unwrap();
        assert!(!verifies(&cut_path), "a manifest without the leaf still verifies — the leaf is not signed");
        let _ = std::fs::remove_dir_all(ca.dir.parent().unwrap());
    }

    /// A Mac whose applier predates the kinds gets the certs alone.
    #[test]
    fn without_leaves_the_bundle_names_no_svc_kind() {
        let (ca, work) = built("bare", false);
        let manifest = std::fs::read_to_string(work.join("manifest")).unwrap();
        assert!(!manifest.contains("svc-"), "{manifest}");
        assert!(manifest.contains("  node.key\n"));
        let _ = std::fs::remove_dir_all(ca.dir.parent().unwrap());
    }
}

#[cfg(test)]
mod apply_refusal_tests {
    use super::apply_refusal;
    use serde_json::json;

    #[test]
    fn exit_76_names_the_fix_and_stale_or_ok_reports_are_silent() {
        let st = |applied: &str, rc: i64| json!({"sha256": "aa", "applied_sha": applied, "apply_rc": rc, "apply_msg": "boom"});
        let w = apply_refusal(&st("aa", 76), "host2").expect("76 is a refusal");
        assert!(w.contains("noo cluster upgrade-applier host2") && w.contains("too old"), "{w}");
        assert!(apply_refusal(&st("aa", 65), "n").unwrap().contains("exit 65): boom"));
        assert!(apply_refusal(&st("aa", 0), "n").is_none());
        assert!(apply_refusal(&st("bb", 76), "n").is_none(), "a report for an earlier bundle is not this one's verdict");
        assert!(apply_refusal(&json!({"sha256": "aa"}), "n").is_none());
    }
}

#[cfg(test)]
mod clifix_security_tests {
    use super::*;

    #[test]
    fn generate_secret_refuses_a_type_it_does_not_know_and_a_length_for_fernet() {
        assert_eq!(secret_args_problem("fernat", None).unwrap().0, "unknown_secret_type");
        assert_eq!(secret_args_problem("fernet", Some(64)).unwrap().0, "length_not_applicable");
        for ok in ["general", "jwt", "cluster"] {
            assert!(secret_args_problem(ok, Some(64)).is_none(), "{ok}");
        }
        assert!(secret_args_problem("fernet", None).is_none());
    }

    fn body_of<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src.find(sig).unwrap_or_else(|| panic!("{sig} not found"));
        let rest = &src[start..];
        &rest[..rest.find("\n}\n").unwrap()]
    }

    #[test]
    fn absorb_files_confirms_before_it_runs_the_script() {
        let body = body_of(include_str!("security_local.rs"), "pub fn secrets_absorb_files(");
        let c = body.find("confirm_prompt(").expect("absorb-files never confirms");
        let r = body.find("Command::new").expect("no script run");
        assert!(c < r);
        assert!(body.contains("\"--yes\"") && body.contains("\"-y\""));
    }

    #[test]
    fn untrust_ca_refuses_a_path_instead_of_ignoring_it() {
        let body = body_of(include_str!("security_local.rs"), "pub fn security_untrust_ca(");
        assert!(!body.contains("let _ = ca_path"), "the argument must not be swallowed");
        assert!(body.contains("takes no CA path"));
    }
}
