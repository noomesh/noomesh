// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Integration tests for `noo security secrets` — driven through the BUILT
//! binary against a THROWAWAY sops store with its own age key.
//!
//! Nothing here touches the real `secrets/env.sops`, the real `.env`, or the
//! real age key: each test builds a scratch repo root (`NOO_REPO_ROOT`) with
//! its own `age.key`, its own `.sops.yaml`, and dummy values, and points
//! `SOPS_AGE_KEY_FILE` at it.
//!
//! **These tests need `sops` and `age` on PATH and SKIP without them.** The
//! build container (`scripts/cargo-docker.sh`) has neither, so the in-
//! container `cargo test` skips them. The `noo-cli` CI job then installs the
//! versions and digests pinned in `scripts/noo-secrets-sops-init.sh` on the
//! runner and runs this test binary there with `NOO_REQUIRE_SOPS=1`, which
//! turns a skip into a failure. They had silently never run anywhere until
//! #643 fixed the fixture's working directory, and three had gone stale.
//! The pure unit-test suite in `src/commands/secrets.rs` — including
//! `no_value_ever_reaches_output` — stays the gate that needs no external
//! tool. What these add is proof that the sops invocations themselves are
//! right: the `--filename-override` creation-rule match, the both-type-flags
//! decrypt, and the prepare→verify→rename commit.
//!
//! The Postgres half (`ALTER ROLE` + login verification + revert-on-failure)
//! is exercised against a throwaway container; see
//! `docs/security/secrets.md` for the manual procedure. It is not
//! automated here because it needs a running docker daemon and a pulled
//! image, which is not CI material for this crate.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Path to the binary under test.
///
/// `CARGO_BIN_EXE_noo` is baked in at COMPILE time. This repo has no host
/// Rust toolchain — cargo runs inside a container with the crate bind-mounted
/// at `/w` (see `scripts/cargo-docker.sh`) — so the baked path is a container
/// path that does not exist on the host. But `sops` and `age` are installed
/// on the HOST (`~/.local/bin`, by `scripts/noo-secrets-sops-init.sh`) and
/// not in the build container, which is the only place these tests can
/// actually run rather than skip.
///
/// `$NOO_TEST_BIN` bridges the two: build in the container, then run the test
/// binary on the host pointing at the host-visible `noo`. Unset (normal
/// `cargo test`, including CI) it falls back to the baked path.
fn bin() -> String {
    std::env::var("NOO_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_noo").to_string())
}

/// Dummy values. Every assertion about "no value leaked" keys off these.
const V_PG: &str = "THROWAWAY-postgres-value-aaaa1111";
const V_JWT: &str = "THROWAWAY-jwt-value-bbbb2222";
const V_CLUSTER: &str = "THROWAWAY-cluster-value-cccc3333";
const V_ANTHROPIC: &str = "THROWAWAY-anthropic-value-dddd4444";
const V_WEIRD: &str = "THROWAWAY-unclassified-value-eeee5555";
const ALL_VALUES: &[&str] = &[V_PG, V_JWT, V_CLUSTER, V_ANTHROPIC, V_WEIRD];

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// True when this host can run the sops-backed tests at all.
fn tooling_available() -> bool {
    if have("sops") && have("age-keygen") {
        return true;
    }
    // CI's host-side step installs both and sets this, so a skip there is a
    // broken install, not a missing tool — fail instead of looking green.
    assert!(
        std::env::var("NOO_REQUIRE_SOPS").ok().as_deref() != Some("1"),
        "NOO_REQUIRE_SOPS=1 but sops/age-keygen are not on PATH"
    );
    eprintln!("SKIP: sops/age not on PATH (see module docs)");
    false
}

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

/// A scratch repo root that removes itself when the test ends, panicking or
/// not (`NOO_KEEP_TEST_DIRS=1` keeps it). It holds an age key and a store.
fn scratch(tag: &str) -> ScratchDir {
    let d = ScratchDir::new(&format!("noo-cli-secrets-{tag}"));
    std::fs::create_dir_all(d.join("secrets")).unwrap();
    d
}

/// Build a throwaway repo root: age key, `.sops.yaml` whose creation rule
/// matches `secrets/*.sops`, an encrypted store, and a config-only `.env`.
fn make_fixture(tag: &str, extra_env: &str) -> ScratchDir {
    make_fixture_with_store(tag, extra_env, "")
}

/// [`make_fixture`] with `extra_store` (dotenv lines) appended to the store.
fn make_fixture_with_store(tag: &str, extra_env: &str, extra_store: &str) -> ScratchDir {
    let root = scratch(tag);
    let key = root.join("age.key");
    let ok = Command::new("age-keygen")
        .arg("-o")
        .arg(&key)
        .output()
        .expect("age-keygen");
    assert!(ok.status.success(), "age-keygen failed");
    let pubkey = String::from_utf8(
        Command::new("age-keygen")
            .args(["-y"])
            .arg(&key)
            .output()
            .expect("age-keygen -y")
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();

    std::fs::write(
        root.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: secrets/.*\\.sops$\n    age: \"{pubkey}\"\n"),
    )
    .unwrap();

    let plain = format!(
        "POSTGRES_PASSWORD={V_PG}\n\
         NOO_JWT_SECRET={V_JWT}\n\
         NOO_CLUSTER_SECRET={V_CLUSTER}\n\
         ANTHROPIC_API_KEY={V_ANTHROPIC}\n\
         WEIRD_TOKEN={V_WEIRD}\n\
         REDIS_PASSWORD=\n\
         {extra_store}"
    );
    let store = root.join("secrets/env.sops");
    let out = Command::new("sops")
        .arg("-e")
        .arg("--filename-override")
        .arg(&store)
        .args(["--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin"])
        .env("SOPS_AGE_KEY_FILE", &key)
        // sops finds `.sops.yaml` from its working directory: run it in the
        // fixture, or a checkout's own `.sops.yaml` (the real recipients)
        // wins and the throwaway key cannot decrypt the result.
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin.take().unwrap().write_all(plain.as_bytes())?;
            c.wait_with_output()
        })
        .expect("sops -e");
    assert!(out.status.success() && !out.stdout.is_empty(), "sops encrypt failed");
    std::fs::write(&store, &out.stdout).unwrap();

    std::fs::write(
        root.join(".env"),
        format!("NOO_SECRETS_BACKEND=sops\nNOO_NODE_NAME=fixture\n{extra_env}"),
    )
    .unwrap();
    root
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("NOO_REPO_ROOT", root)
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .env_remove("NOO_TOKEN")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn noo")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Decrypted key NAMES only — never values. Used to prove a rotation did not
/// drop keys, which is the documented silent failure mode of this store.
fn key_names(root: &Path) -> Vec<String> {
    let out = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(root.join("secrets/env.sops"))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .output()
        .expect("sops -d");
    assert!(out.status.success(), "fixture store did not decrypt");
    let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
        .collect();
    v.sort();
    v
}

/// Is `key` still holding `value` in the store? Compared inside this helper
/// so no value is ever returned to a test body or an assertion message.
fn value_is(root: &Path, key: &str, value: &str) -> bool {
    let out = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(root.join("secrets/env.sops"))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .output()
        .expect("sops -d");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l == format!("{key}={value}"))
}

// ─────────────────────────────────────────────────────────────────────────

/// The whole point. Drive the REAL command against a REAL encrypted store
/// holding known values, and assert that not one of them appears in stdout
/// or stderr, in either output mode.
///
/// The unit test `no_value_ever_reaches_output` covers the renderers; this
/// covers the command end to end, including anything sops or a child process
/// might print on the way through.
#[test]
fn audit_never_prints_a_value() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("noleak", &format!("ANTHROPIC_API_KEY={V_ANTHROPIC}\n"));

    for args in [
        vec!["security", "secrets", "audit"],
        vec!["--json", "security", "secrets", "audit"],
    ] {
        let o = run(&root, &args);
        // The fixture carries ERROR findings on purpose (ANTHROPIC_API_KEY
        // duplicated into .env, a blank REDIS_PASSWORD), and the audit exits 1
        // on any ERROR finding since 9f7f1ae4 — a detector that exits 0 is
        // one no script can notice. So exit 1 is the audit WORKING here.
        //
        // What the old `success()` check guarded is still guarded: a run that
        // never decrypted the store prints nothing, and "nothing leaked" from
        // nothing proves nothing. The key NAMES must be in the output, so the
        // store was opened and rendered, and the leak checks below have
        // something to look through.
        assert_eq!(o.status.code(), Some(1), "audit did not run to its findings: {}", stderr(&o));
        let out = stdout(&o);
        for k in ["POSTGRES_PASSWORD", "NOO_JWT_SECRET", "ANTHROPIC_API_KEY", "credential-in-env"] {
            assert!(out.contains(k), "`{}` never rendered {k} — the store was not read:\n{}", args.join(" "), stderr(&o));
        }
        let combined = format!("{}{}", stdout(&o), stderr(&o));
        for v in ALL_VALUES {
            assert!(
                !combined.contains(v),
                "VALUE LEAKED via `{}`: {v}\n---\n{combined}",
                args.join(" ")
            );
            // A truncated leak is still a leak.
            assert!(
                !combined.contains(&v[..14]),
                "VALUE PREFIX LEAKED via `{}`: {}\n---\n{combined}",
                args.join(" "),
                &v[..14]
            );
        }
    }
}

#[test]
fn audit_reports_the_documented_table_and_findings() {
    if !tooling_available() {
        return;
    }
    // ANTHROPIC_API_KEY duplicated into .env — the config-only violation.
    let root = make_fixture("table", &format!("ANTHROPIC_API_KEY={V_ANTHROPIC}\n"));
    let o = run(&root, &["security", "secrets", "audit"]);
    let s = stdout(&o);

    // Header columns, in order.
    assert!(s.contains("KEY"), "{s}");
    for col in ["SOPS", "ENV", "STATE", "LEN", "SHA256", "CLASS"] {
        assert!(s.contains(col), "missing column {col} in:\n{s}");
    }
    // Presence + classification.
    assert!(s.contains("POSTGRES_PASSWORD"));
    assert!(s.contains("db-password"));
    assert!(s.contains("fleet-wide"));
    assert!(s.contains("provider-issued"));
    // A blank value is reported as BLANK.
    assert!(s.contains("BLANK"), "blank value not surfaced in:\n{s}");
    // The four flags.
    assert!(s.contains("credential-in-env"));
    assert!(s.contains("blank-value"));
    assert!(s.contains("unclassified-credential"));
    // And the standing warning about how NOT to inspect the store.
    assert!(s.contains("NEVER diff plaintext"), "{s}");

    // JSON shape.
    let o = run(&root, &["--json", "security", "secrets", "audit"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).expect("audit --json is JSON");
    assert_eq!(v["secrets_backend"], "sops");
    let pg = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"] == "POSTGRES_PASSWORD")
        .expect("POSTGRES_PASSWORD row");
    assert_eq!(pg["in_sops"], true);
    assert_eq!(pg["in_env"], false);
    assert_eq!(pg["state"], "set");
    assert_eq!(pg["class"], "db-password");
    assert_eq!(pg["rotation"], "auto");
    assert_eq!(pg["length"], V_PG.len());
    assert_eq!(pg["sha256_8"].as_str().unwrap().len(), 8);
    // There is no field that could carry a value.
    assert!(pg.get("value").is_none());
    assert!(!stdout(&o).contains(V_PG));
}

#[test]
fn dry_run_touches_nothing() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("dryrun", "");
    let before = std::fs::read(root.join("secrets/env.sops")).unwrap();
    let o = run(
        &root,
        &["security", "secrets", "rotate", "NOO_JWT_SECRET", "--dry-run"],
    );
    assert!(o.status.success());
    assert!(stdout(&o).contains("nothing will be touched"));
    assert!(stdout(&o).contains("INVALIDATES EVERY ISSUED TOKEN"));
    assert_eq!(
        before,
        std::fs::read(root.join("secrets/env.sops")).unwrap(),
        "--dry-run modified the store"
    );
    assert!(value_is(&root, "NOO_JWT_SECRET", V_JWT));
}

/// A real rotation: value replaced, every OTHER key preserved byte-for-byte,
/// a backup left behind, and no temp file surviving.
#[test]
fn rotate_replaces_one_key_and_preserves_the_rest() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("rotate", "");
    let keys_before = key_names(&root);

    let o = run(
        &root,
        &["security", "secrets", "rotate", "NOO_JWT_SECRET", "--yes"],
    );
    assert!(o.status.success(), "rotate failed: {}", stderr(&o));

    // The key set is IDENTICAL — a re-encrypt that silently drops keys is the
    // documented failure mode this guards against.
    assert_eq!(keys_before, key_names(&root), "rotation changed the key set");
    // Target changed; everything else untouched.
    assert!(!value_is(&root, "NOO_JWT_SECRET", V_JWT), "value not rotated");
    assert!(value_is(&root, "POSTGRES_PASSWORD", V_PG), "collateral change");
    assert!(value_is(&root, "ANTHROPIC_API_KEY", V_ANTHROPIC), "collateral change");

    // A backup of the previous store exists.
    let backups: Vec<_> = std::fs::read_dir(root.join("secrets"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".bak_"))
        .collect();
    assert_eq!(backups.len(), 1, "expected exactly one backup");
    // And no half-written temp file survived.
    let leftovers: Vec<_> = std::fs::read_dir(root.join("secrets"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("rotating"))
        .collect();
    assert!(leftovers.is_empty(), "a .rotating temp file survived");

    // The report names the key, its length and digest — never the value.
    let combined = format!("{}{}", stdout(&o), stderr(&o));
    assert!(combined.contains("NOO_JWT_SECRET"));
    // The store changed; the running containers did not. The report must say
    // so, name the container that holds the old value, and give the remedy
    // that actually recreates it (`--force` — a plain restart keeps the old
    // environment). The wording moved from "must be RECREATED" to a sentence
    // that names the consumers and why a restart is not enough.
    assert!(combined.contains("must be recreated"), "{combined}");
    assert!(combined.contains("noo-gateway"), "the consumer holding the old value is not named");
    assert!(combined.contains("noo stack restart --force"), "the remedy is not the one that recreates");
    for v in ALL_VALUES {
        assert!(!combined.contains(v), "VALUE LEAKED in rotate output: {v}");
    }
}

/// Fleet-wide keys are refused, loudly, with the sequence — and refusing one
/// key aborts the whole batch rather than rotating the others.
#[test]
fn fleet_wide_is_refused_and_aborts_the_batch() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("fleet", "");
    let before = std::fs::read(root.join("secrets/env.sops")).unwrap();

    let o = run(
        &root,
        &[
            "security",
            "secrets",
            "rotate",
            "NOO_JWT_SECRET",
            "NOO_CLUSTER_SECRET",
            "--yes",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "refusal must exit non-zero");
    let s = stdout(&o);
    assert!(s.contains("held by EVERY node"));
    assert!(s.contains("There is NO fleet push"));
    assert!(s.contains("cluster upgrade-agents"));
    assert!(s.contains("REFUSED"));
    assert!(s.contains("all-or-nothing"));

    // The other key in the same batch was NOT rotated.
    assert_eq!(
        before,
        std::fs::read(root.join("secrets/env.sops")).unwrap(),
        "a refused batch still modified the store"
    );
    assert!(value_is(&root, "NOO_JWT_SECRET", V_JWT));
}

#[test]
fn provider_issued_is_refused_without_stdin_and_accepted_with_it() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("provider", "");
    let o = run(
        &root,
        &["security", "secrets", "rotate", "ANTHROPIC_API_KEY", "--yes"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("CANNOT be generated locally"));
    assert!(stdout(&o).contains("--set-from-stdin"));
    assert!(value_is(&root, "ANTHROPIC_API_KEY", V_ANTHROPIC));

    // Piped in, it goes through — and the piped value never appears in output.
    const NEW: &str = "THROWAWAY-newly-issued-provider-key-ffff6666";
    let mut child = Command::new(bin())
        .args([
            "security",
            "secrets",
            "rotate",
            "ANTHROPIC_API_KEY",
            "--set-from-stdin",
            "--yes",
        ])
        .env("NOO_REPO_ROOT", &root)
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{NEW}\n").as_bytes())
            .unwrap();
    }
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "stdin rotate failed: {}", stderr(&o));
    assert!(value_is(&root, "ANTHROPIC_API_KEY", NEW), "stdin value not stored");
    let combined = format!("{}{}", stdout(&o), stderr(&o));
    assert!(!combined.contains(NEW), "the piped value was echoed back");
    assert!(!combined.contains(V_ANTHROPIC), "the old value was printed");
}

/// Agent-first confirm contract: `--json` requires `--yes`, and a non-TTY
/// stdin errors rather than hanging on a prompt nobody can answer.
#[test]
fn confirm_contract_holds() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("confirm", "");
    let before = std::fs::read(root.join("secrets/env.sops")).unwrap();

    let o = run(&root, &["security", "secrets", "rotate", "NOO_JWT_SECRET"]);
    assert!(!o.status.success());
    // The message is "confirmation required: pass --yes (stdin is not a
    // TTY; ...)" (commands/mod.rs), but the human error renderer prints it
    // sentence-cased: "x Confirmation required: ...". The contract is the
    // words, the flag and the reason, not the case of the first letter.
    let err = stderr(&o).to_lowercase();
    assert!(err.contains("confirmation required"), "{err}");
    assert!(err.contains("--yes"), "the refusal must name the flag that satisfies it: {err}");
    assert!(err.contains("not a tty"), "{err}");

    let o = run(
        &root,
        &["--json", "security", "secrets", "rotate", "NOO_JWT_SECRET"],
    );
    assert!(!o.status.success());
    let v: serde_json::Value = serde_json::from_str(stderr(&o).trim()).expect("json error");
    assert_eq!(v["code"], "confirmation_required");

    assert_eq!(
        before,
        std::fs::read(root.join("secrets/env.sops")).unwrap(),
        "an unconfirmed run modified the store"
    );
}

/// Rotation replaces, it never invents: a key absent from the store is
/// refused rather than created.
#[test]
fn absent_and_unknown_keys_are_refused() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("absent", "");
    let o = run(
        &root,
        &["security", "secrets", "rotate", "NATS_PASSWORD", "--yes"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(!key_names(&root).contains(&"NATS_PASSWORD".to_string()));

    let o = run(
        &root,
        &["security", "secrets", "rotate", "MADE_UP_KEY", "--yes"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("not in the rotation registry"));
}

/// `--all-generated` must never sweep in a fleet-wide or provider-issued key.
#[test]
fn all_generated_only_covers_self_generatable_keys() {
    if !tooling_available() {
        return;
    }
    let root = make_fixture("allgen", "");
    let o = run(
        &root,
        &[
            "--json",
            "security",
            "secrets",
            "rotate",
            "--all-generated",
            "--dry-run",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).expect("json");
    let keys: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["key"].as_str().unwrap())
        .collect();
    for forbidden in [
        "NOO_CLUSTER_SECRET",
        "NOO_NODE_AGENT_TOKEN",
        "NATS_PASSWORD",
        "ANTHROPIC_API_KEY",
        "NOO_AGE_BACKUP_PASSPHRASE",
    ] {
        assert!(
            !keys.contains(&forbidden),
            "{forbidden} must never be in --all-generated"
        );
    }
    assert!(keys.contains(&"NOO_JWT_SECRET"));
    assert!(keys.contains(&"POSTGRES_PASSWORD"));
}

/// `tidy` moves CONFIG out of the store — never a secret whose name lacks a
/// credential word. host8, 2026-10-02: tidy moved `NOO_ENTITLEMENT` and
/// `NOO_FILECRED_GOOGLE_CHAT_B64` into plaintext `.env`, the verify row then
/// FAILed, and the launcher refuses to start an install in that state.
#[test]
fn tidy_keeps_a_secret_class_key_in_the_store_and_leaves_env_alone() {
    if !tooling_available() {
        return;
    }
    const V_ENT: &str = "THROWAWAY-entitlement-ffff6666";
    const V_CRED: &str = "THROWAWAY-filecred-gggg7777";
    let root = make_fixture_with_store(
        "tidy-keeps",
        "",
        &format!("NOO_ENTITLEMENT={V_ENT}\nNOO_FILECRED_GOOGLE_CHAT_B64={V_CRED}\nNODE_IP=10.0.0.9\n"),
    );
    let env_before = std::fs::read_to_string(root.join(".env")).unwrap();
    let out = run(&root, &["security", "secrets", "tidy", "--yes"]);
    let all = format!("{}{}", stdout(&out), stderr(&out));
    let names = key_names(&root);
    let ent_kept = value_is(&root, "NOO_ENTITLEMENT", V_ENT);
    let cred_kept = value_is(&root, "NOO_FILECRED_GOOGLE_CHAT_B64", V_CRED);
    let env_after = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(out.status.success(), "{all}");
    for v in ALL_VALUES.iter().chain([V_ENT, V_CRED].iter()) {
        assert!(!all.contains(v), "a value reached the output");
    }
    assert!(ent_kept && cred_kept, "a secret left the store: {names:?}\n{all}");
    assert!(!names.iter().any(|k| k == "NODE_IP"), "config stays in the store: {names:?}");
    // Only the config key moved into .env; neither secret did.
    assert_eq!(env_after, format!("{env_before}NODE_IP=10.0.0.9\n"), "{all}");
}

/// The fixture cleans up after itself: the directory (age key, store, `.env`)
/// is gone once the guard drops, including when the test that held it
/// panicked. Needs no sops, so it runs everywhere.
#[test]
fn a_fixture_directory_is_gone_after_its_guard_drops() {
    let d = ScratchDir::with_keep("noo-cli-secrets-dropcheck", false);
    std::fs::write(d.join("age.key"), "AGE-SECRET-KEY-THROWAWAY").unwrap();
    let path = d.to_path_buf();
    assert!(path.join("age.key").is_file());
    drop(d);
    assert!(!path.exists(), "{} survived its guard", path.display());

    // A panicking test unwinds through the guard's Drop.
    let path = std::panic::catch_unwind(|| {
        let d = ScratchDir::with_keep("noo-cli-secrets-dropcheck-panic", false);
        let p = d.to_path_buf();
        std::fs::write(d.join(".env"), "X=1\n").unwrap();
        std::panic::panic_any(p);
    })
    .expect_err("the closure panics")
    .downcast::<PathBuf>()
    .expect("the panic carries the path");
    assert!(!path.exists(), "{} survived a panicking test", path.display());

    // The escape hatch keeps it, and says so; this test then removes it.
    let d = ScratchDir::with_keep("noo-cli-secrets-dropcheck-keep", true);
    let path = d.to_path_buf();
    drop(d);
    assert!(path.exists(), "NOO_KEEP_TEST_DIRS did not keep the directory");
    std::fs::remove_dir_all(&path).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────
// `secrets remove`
// ─────────────────────────────────────────────────────────────────────────

const V_EDGE1: &str = "THROWAWAY-edge1-leftover-ffff6666";
const V_EDGE_1: &str = "THROWAWAY-edge-1-real-gggg7777";

/// A fixture holding the leftover node password beside the real one, with a
/// users.conf that authorises only `node-edge-1`.
fn remove_fixture(tag: &str) -> ScratchDir {
    let root = make_fixture_with_store(
        tag,
        "",
        &format!("NATS_NODE_PASSWORD_EDGE1={V_EDGE1}\nNATS_NODE_PASSWORD_EDGE_1={V_EDGE_1}\n"),
    );
    std::fs::create_dir_all(root.join("monitoring/nats")).unwrap();
    std::fs::write(
        root.join("monitoring/nats/users.conf"),
        "authorization {\n  users = [\n    {\n      user: \"gateway\"\n      password: \"$2b$11$g\"\n    }\n    {\n      user: \"node-edge-1\"\n      password: \"$2b$11$a\"\n    }\n  ]\n}\n",
    )
    .unwrap();
    root
}

fn run_remove(root: &Path, args: &[&str]) -> Output {
    let mut full = vec!["security", "secrets", "remove"];
    full.extend_from_slice(args);
    Command::new(bin())
        .args(full)
        .env("NOO_REPO_ROOT", root)
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        // No docker project: the running-container check sees nothing, so the
        // test depends on the fixture and not on whatever runs on this host.
        .env("NOO_VERIFY_COMPOSE_PROJECT", "noo-test-no-such-project")
        .env_remove("NOO_TOKEN")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn noo")
}

fn backups(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join("secrets"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("env.sops.bak_"))
        .collect()
}

#[test]
fn remove_refuses_a_consumed_key_and_changes_nothing() {
    if !tooling_available() {
        return;
    }
    let root = remove_fixture("rm-refuse");
    let before = key_names(&root);
    // One consumed (registry), one live node password, one removable: the
    // whole run must abort, not remove the removable one.
    let o = run_remove(
        &root,
        &["--yes", "NOO_JWT_SECRET", "NATS_NODE_PASSWORD_EDGE_1", "NATS_NODE_PASSWORD_EDGE1"],
    );
    assert_eq!(o.status.code(), Some(1), "{}{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("REFUSED  NOO_JWT_SECRET"), "{out}");
    assert!(out.contains("REFUSED  NATS_NODE_PASSWORD_EDGE_1") && out.contains("node `edge-1`"), "{out}");
    assert!(out.contains("REMOVE   NATS_NODE_PASSWORD_EDGE1"), "{out}");
    assert_eq!(key_names(&root), before, "a refused run changed the store");
    assert!(backups(&root).is_empty(), "a refused run wrote a backup");
}

#[test]
fn remove_dry_run_changes_nothing() {
    if !tooling_available() {
        return;
    }
    let root = remove_fixture("rm-dry");
    let before = key_names(&root);
    let o = run_remove(&root, &["--dry-run", "NATS_NODE_PASSWORD_EDGE1"]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("dry run") && stdout(&o).contains("REMOVE   NATS_NODE_PASSWORD_EDGE1"));
    assert_eq!(key_names(&root), before);
    assert!(backups(&root).is_empty());
    assert!(!root.join("secrets/reveal-audit.log").exists());
}

#[test]
fn remove_deletes_the_unused_key_and_only_that_one() {
    if !tooling_available() {
        return;
    }
    let root = remove_fixture("rm-ok");
    let before = key_names(&root);
    let o = run_remove(&root, &["--yes", "NATS_NODE_PASSWORD_EDGE1"]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    let after = key_names(&root);
    let want: Vec<String> = before.iter().filter(|k| *k != "NATS_NODE_PASSWORD_EDGE1").cloned().collect();
    assert_eq!(after, want, "exactly the one key should be gone");
    // The survivors keep their values.
    assert!(value_is(&root, "NATS_NODE_PASSWORD_EDGE_1", V_EDGE_1));
    assert!(value_is(&root, "NOO_JWT_SECRET", V_JWT));
    // An encrypted backup of the prior store exists, still holds the key, and
    // is named in the output.
    let bak = backups(&root);
    assert_eq!(bak.len(), 1, "{bak:?}");
    assert!(stdout(&o).contains(&bak[0]), "{}", stdout(&o));
    let dec = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(root.join("secrets").join(&bak[0]))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&dec.stdout).contains("NATS_NODE_PASSWORD_EDGE1="));
    // Audit row: the key name, never a value.
    let log = std::fs::read_to_string(root.join("secrets/reveal-audit.log")).unwrap();
    assert!(log.contains("secret_removed name=NATS_NODE_PASSWORD_EDGE1"), "{log}");
    let combined = format!("{}{}{}", stdout(&o), stderr(&o), log);
    for v in [V_EDGE1, V_EDGE_1, V_JWT] {
        assert!(!combined.contains(v), "a value leaked: {v}");
    }
    // Without --yes and without a TTY it must refuse rather than hang.
    let again = run_remove(&root, &["NATS_NODE_PASSWORD_EDGE_1"]);
    assert_ne!(again.status.code(), Some(0));
    assert!(value_is(&root, "NATS_NODE_PASSWORD_EDGE_1", V_EDGE_1));
}
