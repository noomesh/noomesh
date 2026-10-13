// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo onboard` never leaves a secret in plaintext `.env`.
//!
//! Driven through the BUILT binary against a throwaway install root
//! (`NOO_REPO_ROOT`, its own `HOME`), never the real `.env`, store or age key.
//! Nothing here reaches a gateway: `-G` points at a closed loopback port.
//!
//! * A missing SOPS init script, and a failing one, STOP the wizard (exit 1)
//!   with the reason and the fix — and `.env` holds no secret afterwards.
//!   Both used to warn "leaving plaintext .env" and finish green.
//! * `--secrets-backend env` is refused as retired (exit 2), touching nothing.
//! * With `sops` + `age` on PATH (a controller; CI has neither and skips it),
//!   a fresh `--ci --only secrets` run ends with every minted secret in
//!   `secrets/env.sops` and a `.env` that holds none.

use std::path::Path;
use std::process::{Command, Output};

fn bin() -> String {
    std::env::var("NOO_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_noo").to_string())
}

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

/// Removed when the test ends, panicking or not (it holds an age key).
fn scratch(tag: &str) -> ScratchDir {
    let d = ScratchDir::new(&format!("noo-onboard-sops-{tag}"));
    std::fs::create_dir_all(d.join("home")).unwrap();
    std::fs::create_dir_all(d.join("data")).unwrap();
    // Config only, as the environment step leaves it on a fresh install. The
    // data root is the scratch dir's own (empty), so the data-plane guard
    // never looks at a real one.
    std::fs::write(
        d.join(".env"),
        format!("NODE_ID=onboard-test\nNOO_DATA_ROOT={}\n", d.join("data").display()),
    )
    .unwrap();
    d
}

fn onboard(root: &Path, args: &[&str]) -> Output {
    let real_home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{real_home}/.local/bin:{}", std::env::var("PATH").unwrap_or_default());
    Command::new(bin())
        .args(["-G", "https://127.0.0.1:1", "onboard"])
        .args(args)
        .env("NOO_REPO_ROOT", root)
        .env("HOME", root.join("home"))
        .env("NOO_HOME", root.join("home/.noo"))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .env("PATH", path)
        .env_remove("NOO_SECRETS_BACKEND")
        .env_remove("NOO_ADMIN_USER")
        .env_remove("NOO_BACKUP_PASSPHRASE")
        .env_remove("NOO_AGE_BACKUP_PASSPHRASE")
        .output()
        .expect("run noo")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// Every key in `.env` that holds a value and is shaped like a secret. The
/// crate's own rule is `plaintext_env::secret_class`; this is a deliberately
/// broader needle list, so the test cannot pass by sharing the rule's blind
/// spots.
fn secrets_in_env(root: &Path) -> Vec<String> {
    let body = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    body.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, v)| {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            !v.is_empty()
                && k != "NOO_SECRETS_BACKEND"
                && ["PASSWORD", "SECRET", "TOKEN", "_KEY", "PASSPHRASE", "CREDENTIAL"]
                    .iter()
                    .any(|n| k.contains(n))
        })
        .map(|(k, _)| k.trim().to_string())
        .collect()
}

fn write_script(root: &Path, body: &str) {
    let dir = root.join("scripts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("noo-secrets-sops-init.sh"), body).unwrap();
}

#[test]
fn a_missing_init_script_stops_onboard_and_leaves_no_secret_in_env() {
    let root = scratch("missing");
    let out = onboard(&root, &["--ci", "--only", "secrets"]);
    let all = text(&out);
    let leaked = secrets_in_env(&root);
    let store = root.join("secrets/env.sops").exists();
    assert_eq!(out.status.code(), Some(1), "onboard must fail: {all}");
    assert!(all.contains("SOPS init script is missing"), "names the cause: {all}");
    assert!(all.contains("onboarding did NOT complete"), "says it stopped: {all}");
    assert!(leaked.is_empty(), "secrets written to plaintext .env: {leaked:?}\n{all}");
    assert!(!store, "no store was expected");
    assert!(!all.contains("setup complete"), "{all}");
}

#[test]
fn a_failing_init_script_stops_onboard_and_leaves_no_secret_in_env() {
    let root = scratch("failing");
    write_script(&root, "#!/bin/bash\necho 'simulated: could not auto-install age/sops' >&2\nexit 1\n");
    let out = onboard(&root, &["--ci", "--only", "secrets"]);
    let all = text(&out);
    let leaked = secrets_in_env(&root);
    assert_eq!(out.status.code(), Some(1), "onboard must fail: {all}");
    assert!(all.contains("SOPS init script failed"), "names the cause: {all}");
    assert!(leaked.is_empty(), "secrets written to plaintext .env: {leaked:?}\n{all}");
}

/// A script that exits 0 but produced no store is the same failure — the
/// wizard checks the store, not the exit code alone.
#[test]
fn an_init_script_that_makes_no_store_is_a_failure_too() {
    let root = scratch("nostore");
    write_script(&root, "#!/bin/bash\nexit 0\n");
    let out = onboard(&root, &["--ci", "--only", "secrets"]);
    let all = text(&out);
    let leaked = secrets_in_env(&root);
    assert_eq!(out.status.code(), Some(1), "onboard must fail: {all}");
    assert!(leaked.is_empty(), "secrets written to plaintext .env: {leaked:?}\n{all}");
}

#[test]
fn the_env_backend_is_refused_as_retired_and_nothing_is_touched() {
    for args in [
        &["--ci", "--secrets-backend", "env"][..],
        &["--ci", "--secrets-backend=env"][..],
        &["--ci", "--standalone", "--secrets-backend", "env"][..],
    ] {
        let root = scratch("envflag");
        let before = std::fs::read_to_string(root.join(".env")).unwrap();
        let out = onboard(&root, args);
        let all = text(&out);
        let after = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
        let materialised = root.join("home/.noo").exists();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {all}");
        assert!(all.contains("retired"), "{args:?}: {all}");
        assert!(all.contains("--secrets-backend sops"), "names the sops path: {all}");
        assert_eq!(after, before, "{args:?} touched .env");
        assert!(!materialised, "{args:?} materialised a standalone home before refusing");
    }
}

fn have(tool: &str) -> bool {
    let real_home = std::env::var("HOME").unwrap_or_default();
    Command::new("sh")
        .args(["-c", &format!("PATH=\"{real_home}/.local/bin:$PATH\" command -v {tool}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The proof on a real store: a fresh, unattended secrets step ends with the
/// store armed, every minted secret inside it, and none in `.env`.
#[test]
fn a_fresh_ci_run_ends_on_sops_with_a_secret_free_env() {
    if !(have("sops") && have("age-keygen")) {
        eprintln!("SKIP: sops/age not on PATH (expected on CI; runs on a controller)");
        return;
    }
    let root = scratch("fresh");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/noo-secrets-sops-init.sh");
    write_script(&root, &std::fs::read_to_string(script).unwrap());
    let out = onboard(&root, &["--ci", "--only", "secrets"]);
    let all = text(&out);
    let leaked = secrets_in_env(&root);
    let env = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    let real_home = std::env::var("HOME").unwrap_or_default();
    let dec = Command::new("sh")
        .args(["-c", &format!(
            "PATH=\"{real_home}/.local/bin:$PATH\" SOPS_AGE_KEY_FILE='{}' sops -d --input-type dotenv --output-type dotenv '{}'",
            root.join("age.key").display(),
            root.join("secrets/env.sops").display()
        )])
        .output()
        .unwrap();
    let keys: Vec<String> = String::from_utf8_lossy(&dec.stdout)
        .lines()
        .filter_map(|l| l.split_once('=').filter(|(_, v)| !v.is_empty()).map(|(k, _)| k.to_string()))
        .collect();
    assert!(leaked.is_empty(), "secrets in plaintext .env after onboard: {leaked:?}\n{all}");
    assert!(env.lines().any(|l| l.trim() == "NOO_SECRETS_BACKEND=sops"), "backend not armed: {env}\n{all}");
    assert!(dec.status.success(), "store does not decrypt: {}", String::from_utf8_lossy(&dec.stderr));
    for k in ["NOO_JWT_SECRET", "POSTGRES_PASSWORD", "NOO_ADMIN_PASSWORD", "NOO_BACKUP_PASSPHRASE"] {
        assert!(keys.iter().any(|x| x == k), "{k} not in the store: {keys:?}\n{all}");
    }
    assert!(!keys.iter().any(|k| k == "NODE_ID"), "config leaked into the store: {keys:?}");
}

/// Encrypt `plain` (dotenv) into `<root>/secrets/env.sops` with a fresh age
/// key at `<root>/age.key` and a `.sops.yaml` whose rule matches it.
fn seal_store(root: &Path, plain: &str) {
    let real_home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{real_home}/.local/bin:{}", std::env::var("PATH").unwrap_or_default());
    let key = root.join("age.key");
    assert!(Command::new("age-keygen").arg("-o").arg(&key).env("PATH", &path).output().unwrap().status.success());
    let out = Command::new("age-keygen").arg("-y").arg(&key).env("PATH", &path).output().unwrap();
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    std::fs::write(
        root.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: secrets/.*\\.sops$\n    age: \"{pubkey}\"\n"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    let store = root.join("secrets/env.sops");
    let enc = Command::new("sops")
        .arg("-e")
        .arg("--filename-override")
        .arg(&store)
        .args(["--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin"])
        .env("SOPS_AGE_KEY_FILE", &key)
        .env("PATH", &path)
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin.take().unwrap().write_all(plain.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    assert!(enc.status.success() && !enc.stdout.is_empty(), "sops encrypt failed");
    std::fs::write(&store, &enc.stdout).unwrap();
}

/// Does the store hold `key=value`? Compared here so no value reaches an
/// assertion message.
fn store_holds(root: &Path, key: &str, value: &str) -> bool {
    let real_home = std::env::var("HOME").unwrap_or_default();
    let out = Command::new("sh")
        .args(["-c", &format!(
            "PATH=\"{real_home}/.local/bin:$PATH\" SOPS_AGE_KEY_FILE='{}' sops -d --input-type dotenv --output-type dotenv '{}'",
            root.join("age.key").display(),
            root.join("secrets/env.sops").display()
        )])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().any(|l| l == format!("{key}={value}"))
}

/// The arm step on an install already on sops: a secret-class key the store
/// holds stays there with ITS value, even when `.env` carries a stale one.
/// With the name-only classifier the arm step moved the store's value out
/// ("config") and the carry then put `.env`'s STALE value in its place —
/// the live entitlement replaced by an old one.
#[test]
fn the_arm_step_keeps_a_secret_class_key_and_its_store_value() {
    if !(have("sops") && have("age-keygen")) {
        eprintln!("SKIP: sops/age not on PATH (expected on CI; runs on a controller)");
        return;
    }
    const LIVE: &str = "THROWAWAY-live-entitlement-hhhh8888";
    const STALE: &str = "THROWAWAY-stale-entitlement-iiii9999";
    let root = scratch("arm-keeps");
    seal_store(&root, &format!("NOO_ENTITLEMENT={LIVE}\nNOO_JWT_SECRET=THROWAWAY-jwt-jjjj0000\n"));
    let env = std::fs::read_to_string(root.join(".env")).unwrap();
    std::fs::write(root.join(".env"), format!("{env}NOO_SECRETS_BACKEND=sops\nNOO_ENTITLEMENT={STALE}\n")).unwrap();
    let out = onboard(&root, &["--ci", "--only", "secrets"]);
    let all = text(&out);
    let live_kept = store_holds(&root, "NOO_ENTITLEMENT", LIVE);
    let env_after = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    assert!(!all.contains(LIVE) && !all.contains(STALE), "a value reached the output");
    assert!(live_kept, "the store's NOO_ENTITLEMENT was replaced or removed\n{all}");
    assert!(!env_after.contains(LIVE) && !env_after.contains(STALE), "a value is still in plaintext .env");
}
