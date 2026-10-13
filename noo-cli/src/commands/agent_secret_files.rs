// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The macOS twin of `noo-apply.sh`'s `agent_secret_files`.
//!
//! The provision bundle carries the agent env with plain secret values, and
//! the `nats-creds` / `fleet-secrets` merges append plain lines. Once the
//! installed agent binary can read `NAME_FILE` (it carries
//! [`AGENT_SECRET_CAPABILITY`], which the agent logs at startup — the binary
//! is searched, never executed), each value moves into its own 0600 file
//! under `~/noomesh/secrets/` and the env keeps only a pointer; an agent
//! without the marker gets any pointer inlined back, so an older binary never
//! boots pointed at a file it cannot read. The Linux applier and this file
//! make the same decision from the same inputs;
//! `tests/test_file_reader_parity.py` keeps [`AGENT_SECRET_KEYS`] equal to the
//! Go manifest and the shell list.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Every secret the agent reads through its `_FILE`-aware reader
/// (node-agent-go `internal/config/secretenv.go` `FileBackedSecrets`).
pub(crate) const AGENT_SECRET_KEYS: &[&str] =
    &["NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NATS_NODE_PASSWORD"];

/// The marker an agent that reads `NAME_FILE` carries (Go
/// `config.SecretFilesCapability`).
pub(crate) const AGENT_SECRET_CAPABILITY: &str = "noo-agent-reads-secret-files/1";

/// Every secret the harness reads through `secret_env` (gateway-rust
/// `harness_main.rs` `HARNESS_SECRET_KEYS`).
pub(crate) const HARNESS_SECRET_KEYS: &[&str] =
    &["NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NATS_NODE_PASSWORD"];

/// The marker a harness (gateway) binary that reads `NAME_FILE` carries
/// (`harness_main.rs` `HARNESS_SECRET_FILES_CAPABILITY`).
pub(crate) const HARNESS_SECRET_CAPABILITY: &str = "noo-harness-reads-secret-files/1";

/// Does the binary at `bin` carry `marker`? Searched, never executed.
fn carries_marker(bin: &Path, marker: &str) -> bool {
    let Ok(bytes) = std::fs::read(bin) else { return false };
    let needle = marker.as_bytes();
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// A dotenv value as launchd's runner (`set -a; source`) and systemd read
/// it: CR dropped, quotes removed (single, double, and `'\''` joins).
fn unquote(v: &str) -> String {
    super::env_quote::env_unquote(v)
}

/// The last `KEY=` assignment's value in `lines`.
fn last_value(lines: &[String], key: &str) -> String {
    let prefix = format!("{key}=");
    lines.iter().rev().find_map(|l| l.strip_prefix(&prefix)).map(unquote).unwrap_or_default()
}

/// Write `value` to `path` 0600 without following a link someone planted:
/// the old `.next` is removed and the new one created exclusively
/// (`O_CREAT|O_EXCL` never follows a symlink), then renamed over `path`.
fn write_secret(path: &Path, value: &str) -> Result<(), String> {
    let next = path.with_extension("next");
    let _ = std::fs::remove_file(&next);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&next)
        .map_err(|e| format!("{}: {e}", next.display()))?;
    f.write_all(value.as_bytes()).map_err(|e| format!("{}: {e}", next.display()))?;
    drop(f);
    std::fs::rename(&next, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Converge the agent env at `env` to pointers into `dir` (the agent at
/// `agent_bin` reads them) or to plain values (it does not). `Ok(true)` when
/// the env was rewritten. Ownership is the caller's: on a Mac the whole
/// `~/noomesh` tree is handed to the enrolling user after an apply.
pub(crate) fn converge(env: &Path, dir: &Path, agent_bin: &Path) -> Result<bool, String> {
    converge_with(env, dir, agent_bin, AGENT_SECRET_KEYS, AGENT_SECRET_CAPABILITY)
}

/// [`converge`] for the harness env: the gateway binary,
/// judged by its own marker, over its own key list.
pub(crate) fn converge_harness(env: &Path, dir: &Path, gateway_bin: &Path) -> Result<bool, String> {
    converge_with(env, dir, gateway_bin, HARNESS_SECRET_KEYS, HARNESS_SECRET_CAPABILITY)
}

fn converge_with(env: &Path, dir: &Path, bin: &Path, keys: &[&str], marker: &str) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(env) else { return Ok(false) };
    let capable = carries_marker(bin, marker);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut remove_after = Vec::new();
    for key in keys {
        let file_key = format!("{key}_FILE");
        let file = dir.join(key);
        let plain = last_value(&lines, key);
        let ptr = last_value(&lines, &file_key);
        let drop_both = |lines: &mut Vec<String>| {
            lines.retain(|l| !l.starts_with(&format!("{key}=")) && !l.starts_with(&format!("{file_key}=")));
        };
        if capable {
            if !plain.is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                write_secret(&file, &plain)?;
                drop_both(&mut lines);
                lines.push(format!("{file_key}={}", super::env_quote::env_quote(&file.display().to_string())));
            } else if !ptr.is_empty() {
                lines.retain(|l| l != &format!("{key}="));
            } else {
                let _ = std::fs::remove_file(&file);
            }
        } else if !ptr.is_empty() {
            let v = if plain.is_empty() {
                std::fs::read_to_string(&ptr).unwrap_or_default()
            } else {
                plain
            };
            if v.contains('\n') || v.contains('\r') {
                return Err(format!("{ptr} holds more than one line — not inlining {key} into {}", env.display()));
            }
            drop_both(&mut lines);
            if !v.is_empty() {
                lines.push(format!("{key}={}", super::env_quote::env_quote(&v)));
            }
            remove_after.push(file);
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let changed = out != text;
    if changed {
        if !lines.iter().any(|l| l.starts_with("NODE_ID=") && l.len() > "NODE_ID=".len()) {
            return Err("secret-file conversion lost NODE_ID — aborting".into());
        }
        let tmp = env.with_extension("next");
        std::fs::write(&tmp, &out).map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, env).map_err(|e| e.to_string())?;
    }
    if !capable {
        for key in keys {
            let _ = std::fs::remove_file(dir.join(key));
        }
        for f in remove_after {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir(dir);
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENDERED: &str = "NODE_ID=host6\nNOO_NODE_AGENT_TOKEN=tok\nNOO_CLUSTER_SECRET=\"cs\"\nNATS_PASSWORD=\nNATS_NODE_USER=node-host6\nNATS_NODE_PASSWORD=pw\n";

    fn node(tag: &str, capable: bool) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("noo-asf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        let bin = d.join("bin/noo-node-agent");
        install(&bin, capable);
        let env = d.join("agent.env");
        std::fs::write(&env, RENDERED).unwrap();
        (d.clone(), env, d.join("secrets"), bin)
    }

    fn install(bin: &Path, capable: bool) {
        let mut b = b"\xcf\xfa\xed\xfe junk ".to_vec();
        b.extend_from_slice(if capable { AGENT_SECRET_CAPABILITY.as_bytes() } else { b"plain-env-only" });
        b.extend_from_slice(b" more");
        std::fs::write(bin, b).unwrap();
    }

    #[test]
    fn a_capable_agent_gets_0600_files_and_pointers_only() {
        let (d, env, dir, bin) = node("cap", true);
        assert!(converge(&env, &dir, &bin).unwrap());
        let got = std::fs::read_to_string(&env).unwrap();
        for (k, v) in [("NOO_NODE_AGENT_TOKEN", "tok"), ("NOO_CLUSTER_SECRET", "cs"), ("NATS_NODE_PASSWORD", "pw")] {
            let f = dir.join(k);
            assert_eq!(std::fs::read_to_string(&f).unwrap(), v);
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
            assert!(got.contains(&format!("{k}_FILE={}\n", f.display())), "{got}");
            assert!(!got.lines().any(|l| l.starts_with(&format!("{k}="))), "{got}");
        }
        assert!(got.contains("NODE_ID=host6\n") && got.contains("NATS_NODE_USER=node-host6\n"));
        assert!(!dir.join("NATS_PASSWORD").exists());
        // idempotent
        assert!(!converge(&env, &dir, &bin).unwrap());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn an_old_agent_keeps_or_regains_plain_values() {
        let (d, env, dir, bin) = node("old", false);
        assert!(!converge(&env, &dir, &bin).unwrap(), "an old agent's plain env is left alone");
        assert_eq!(std::fs::read_to_string(&env).unwrap(), RENDERED);
        install(&bin, true);
        assert!(converge(&env, &dir, &bin).unwrap());
        install(&bin, false);
        assert!(converge(&env, &dir, &bin).unwrap(), "rollback inlines the files back");
        let got = std::fs::read_to_string(&env).unwrap();
        assert!(got.contains("NOO_CLUSTER_SECRET=cs\n") && got.contains("NATS_NODE_PASSWORD=pw\n"), "{got}");
        assert!(!got.contains("_FILE="), "{got}");
        assert!(!dir.exists(), "files must not outlive the pointers");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_merge_after_the_flip_replaces_the_file() {
        let (d, env, dir, bin) = node("merge", true);
        converge(&env, &dir, &bin).unwrap();
        let mut t = std::fs::read_to_string(&env).unwrap();
        t.push_str("NATS_NODE_PASSWORD=rotated\n");
        std::fs::write(&env, t).unwrap();
        assert!(converge(&env, &dir, &bin).unwrap());
        assert_eq!(std::fs::read_to_string(dir.join("NATS_NODE_PASSWORD")).unwrap(), "rotated");
        let got = std::fs::read_to_string(&env).unwrap();
        assert_eq!(got.matches("NATS_NODE_PASSWORD_FILE=").count(), 1, "{got}");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_harness_env_converges_on_the_gateway_binary_marker_not_the_agents() {
        let (d, env, dir, _agent_bin) = node("harness", false);
        let hbin = d.join("bin/noo-gateway");
        // An agent marker in the gateway binary is not the harness's marker.
        install(&hbin, true);
        assert!(!converge_harness(&env, &dir, &hbin).unwrap(), "no harness marker: plain values stay");
        assert_eq!(std::fs::read_to_string(&env).unwrap(), RENDERED);
        let mut b = b"\xcf\xfa\xed\xfe gateway ".to_vec();
        b.extend_from_slice(HARNESS_SECRET_CAPABILITY.as_bytes());
        std::fs::write(&hbin, b).unwrap();
        assert!(converge_harness(&env, &dir, &hbin).unwrap());
        let got = std::fs::read_to_string(&env).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("NATS_NODE_PASSWORD")).unwrap(), "pw");
        assert!(got.contains(&format!("NATS_NODE_PASSWORD_FILE={}\n", dir.join("NATS_NODE_PASSWORD").display())), "{got}");
        assert!(!got.contains("NATS_NODE_PASSWORD=pw"), "{got}");
        // a rollback to a harness without the marker inlines it back
        std::fs::write(&hbin, b"\xcf\xfa\xed\xfe old gateway").unwrap();
        assert!(converge_harness(&env, &dir, &hbin).unwrap());
        let got = std::fs::read_to_string(&env).unwrap();
        assert!(got.contains("NATS_NODE_PASSWORD=pw\n") && !got.contains("_FILE="), "{got}");
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_planted_link_is_not_written_through() {
        let (d, env, dir, bin) = node("link", true);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("NOO_CLUSTER_SECRET.next")).unwrap();
        converge(&env, &dir, &bin).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert_eq!(std::fs::read_to_string(dir.join("NOO_CLUSTER_SECRET")).unwrap(), "cs");
        let _ = std::fs::remove_dir_all(d);
    }
}
