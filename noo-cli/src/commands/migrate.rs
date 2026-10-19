// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo migrate` — move a STANDALONE controller to another device.
//!
//! Not schema migrations — those are `noo db
//! upgrade`; the help strings disambiguate loudly.
//!
//! `export` seals everything worth carrying into ONE passphrase-encrypted
//! archive: the age key (root of trust), secrets/env.sops + .sops.yaml, the
//! .env config, noomesh.yaml, the FULL pki/ tree (ca.key unchanged is the
//! load-bearing requirement — workers pin the CA anchor and enroll REFUSES
//! on a mismatch, so a regenerated CA orphans every node), the fleet
//! inventory, and a fresh pg_dump. Deliberately NOT carried: models/caches
//! (re-pulled), docker images (pulled), the tailnet DEVICE identity (the
//! new machine joins fresh and reuses the NAME).
//!
//! `import` restores onto a fresh box: guard → decrypt/extract (traversal-
//! safe) → age key first (runbook order; nothing downstream works without
//! it) → materialize the deploy slice at THIS binary's version → overlay
//! the state → tailnet guidance (same name = workers reconnect untouched)
//! → start stack → psql restore → SAN-coverage cert re-issue if the
//! hostname/IP changed. Encryption is the repo's standard openssl
//! aes-256-cbc/pbkdf2 `-pass env:` shape (backup-controller.sh) — no new
//! dependency, scriptable via --passphrase-file.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui;

const MANIFEST: &str = "manifest.json";

/// State files under the home worth carrying (dirs copied recursively).
const STATE_PATHS: &[&str] =
    &[".env", ".sops.yaml", "noomesh.yaml", "secrets", "pki"];

fn age_key_path() -> PathBuf {
    std::env::var("SOPS_AGE_KEY_FILE").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".config/sops/age/keys.txt")
    })
}

/// Passphrase from --passphrase-file, else a hidden double prompt.
pub(crate) fn resolve_passphrase(g: &Globals, file: &Option<String>, confirm: bool) -> String {
    if let Some(f) = file {
        match std::fs::read_to_string(f) {
            Ok(s) if !s.trim().is_empty() => return s.trim().to_string(),
            _ => fail(g.json, ExitCode::Generic, "passphrase_file",
                &format!("could not read a passphrase from {f}"), None),
        }
    }
    if g.json {
        fail(g.json, ExitCode::Generic, "passphrase_required",
            "--json mode cannot prompt — pass --passphrase-file", None);
    }
    let Some(p) = crate::commands::cluster_provision::read_hidden("Archive passphrase") else {
        fail(g.json, ExitCode::Generic, "passphrase_required", "a passphrase is required", None);
    };
    if confirm {
        let again = crate::commands::cluster_provision::read_hidden("Confirm passphrase");
        if again.as_deref() != Some(p.as_str()) {
            fail(g.json, ExitCode::Generic, "passphrase_mismatch", "passphrases do not match", None);
        }
    }
    p
}

pub(crate) fn openssl_crypt(encrypt: bool, input: &Path, output: &Path, pass: &str) -> bool {
    let mut cmd = Command::new("openssl");
    cmd.args(["enc", "-aes-256-cbc", "-pbkdf2", "-salt"]);
    if !encrypt {
        cmd.arg("-d");
    }
    cmd.arg("-in").arg(input).arg("-out").arg(output)
        .args(["-pass", "env:NOO_MIGRATE_PASS"])
        .env("NOO_MIGRATE_PASS", pass);
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    if src.is_file() {
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        std::fs::copy(src, dst).map_err(|e| format!("{}: {e}", src.display()))?;
        return Ok(());
    }
    for entry in walk(src)? {
        let rel = entry.strip_prefix(src).unwrap();
        let to = dst.join(rel);
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        std::fs::copy(&entry, &to).map_err(|e| format!("{}: {e}", entry.display()))?;
    }
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn sha256_file(p: &Path) -> Option<String> {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(p).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// A fresh staging directory for plaintext (the dump, the decrypted tarball,
/// the controller's secrets and CA key): `<tmp>/<prefix>-<64 random bits>`,
/// created with mode 0700, refusing one that already exists. The previous
/// `<prefix>-<pid>` was predictable, created with the default umask, and
/// `remove_dir_all`-ed first — so another local user could pre-create it
/// (or race the 0644 dump and tarball inside it) and read the controller's
/// whole state. mkdtemp semantics: the name is unguessable, and `mkdir`
/// failing with EEXIST is a retry, never a reuse.
fn private_stage(prefix: &str) -> Result<PathBuf, String> {
    use std::io::Read as _;
    use std::os::unix::fs::DirBuilderExt as _;
    for _ in 0..16 {
        let mut raw = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut raw))
            .map_err(|e| format!("cannot read /dev/urandom for a private staging name: {e}"))?;
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", hex::encode(raw)));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create the private staging directory {}: {e}", dir.display())),
        }
    }
    Err("could not find an unused private staging directory name".into())
}

// ═══ export ═════════════════════════════════════════════════════════════

/// Decrypt + safely extract a migration archive into a temp stage for the
/// converged onboard flow (`noo onboard --from-archive`). Returns
/// (stage_root, extracted_dir, manifest). Caller removes stage_root.
pub(crate) fn open_archive(
    g: &Globals,
    archive: &str,
    pass_file: &Option<String>,
) -> Result<(std::path::PathBuf, std::path::PathBuf, serde_json::Value), String> {
    let pass = resolve_passphrase(g, pass_file, false);
    let stage = private_stage("noo-archive")?;
    let tarball = stage.join("bundle.tar.gz");
    if !openssl_crypt(false, Path::new(archive), &tarball, &pass) {
        let _ = std::fs::remove_dir_all(&stage);
        return Err("decryption failed (wrong passphrase, or not a migration archive; \
                    long pasted passphrases: use --passphrase-file)".into());
    }
    let tar_bytes = std::fs::read(&tarball).map_err(|e| e.to_string())?;
    let extracted = stage.join("x");
    std::fs::create_dir_all(&extracted).map_err(|e| e.to_string())?;
    crate::onboard::standalone::extract_bundle_safely(&tar_bytes, &extracted)?;
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(extracted.join(MANIFEST)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("manifest: {e}"))?;
    if manifest["kind"] != "noo-migrate" {
        let _ = std::fs::remove_dir_all(&stage);
        return Err("not a noo migration archive (manifest kind mismatch)".into());
    }
    Ok((stage, extracted, manifest))
}

pub fn migrate_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut out: Option<String> = None;
    let mut pass_file: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-o" | "--out" => out = iter.next().cloned(),
            "--passphrase-file" => pass_file = iter.next().cloned(),
            _ => return Err(Unhandled),
        }
    }

    // Source resolution: a standalone home, or a REPO CHECKOUT (the HOST3
    // shape — same state layout, .env/secrets/pki/noomesh.yaml at the
    // repo root). A repo source is recorded in the manifest so import can
    // pin the target onto dist images (a dev-mode .env imported verbatim
    // would try to BUILD on the new box — the #43 class).
    let standalone_home = crate::onboard::standalone::default_home();
    let (home, source_kind) = if standalone_home.join(".noo-standalone").is_file() {
        (standalone_home, "standalone")
    } else {
        let repo = crate::envfile::repo_root();
        if repo.join(".env").is_file() && repo.join("pki/ca.crt").is_file() {
            (repo, "repo")
        } else {
            fail(g.json, ExitCode::Generic, "no_source",
                &format!("no controller found: neither a standalone install at {} nor a repo \
                          checkout with .env + pki here", standalone_home.display()),
                Some("run from the controller (repo checkout), or on a machine with ~/.noo"));
        }
    };
    // Three phases (guide §5 Rhythm): Collect → Seal → Verify.
    if !g.json {
        println!("{}", ui::phase("Collect"));
        let mut rows: Vec<(&str, String)> = vec![
            ("source", format!("{source_kind} at {}", home.display())),
            ("carries", "database dump, secrets (sops + age key), PKI, config, inventory".to_string()),
            ("does not carry", "models and caches, docker images, the tailnet device".to_string()),
        ];
        if source_kind == "repo" {
            rows.push(("note", "a repo source pins the target to dist images on import".to_string()));
        }
        print!("{}", ui::kv(&rows));
    }
    // A migration archive with no database is worse than none — the same
    // fail-closed doctrine as the backup script's PG_OK gate.
    let pg = crate::envfile::container("postgres");
    let pg_up = Command::new("docker").args(["inspect", "-f", "{{.State.Running}}", &pg])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true").unwrap_or(false);
    if !pg_up {
        fail(g.json, ExitCode::Generic, "postgres_down",
            &format!("{pg} is not running — export needs a live database for a fresh dump"),
            Some("start the stack (noo stack start), then export"));
    }
    let age_key = age_key_path();
    if !age_key.is_file() {
        fail(g.json, ExitCode::Generic, "no_age_key",
            &format!("no age key at {} — nothing could decrypt the carried secrets", age_key.display()),
            None);
    }

    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim().to_string();
    let ts = crate::onboard::steps::tailscale_identity().ok();
    let out_path = PathBuf::from(out.unwrap_or_else(|| {
        format!("noo-migrate-{}.tar.gz.enc", if host.is_empty() { "controller" } else { &host })
    }));
    let pass = resolve_passphrase(g, &pass_file, true);

    let stage = match private_stage("noo-migrate") {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "stage_failed", &e, Some("check that the temp directory is writable")),
    };
    let result = (|| -> Result<(String, usize), String> {
        std::fs::create_dir_all(stage.join("db")).map_err(|e| e.to_string())?;

        // Fresh dump, never a stale backup file. Plain SQL like every other
        // rail here — restore is psql, no pg_restore anywhere in the fleet.
        ui::step(&format!("dumping the database ({pg})"));
        let dump = Command::new("bash")
            .arg("-c")
            .arg(format!("umask 077; set -o pipefail; docker exec {pg} pg_dump -U noo noomesh | gzip > '{}'",
                stage.join("db/pg.sql.gz").display()))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !dump {
            return Err("pg_dump failed".into());
        }

        ui::step("staging controller state");
        for rel in STATE_PATHS {
            let src = home.join(rel);
            if src.exists() {
                copy_tree(&src, &stage.join("home").join(rel))?;
            }
        }
        // Skip rotated sops backups — point-in-time noise.
        if let Ok(rd) = std::fs::read_dir(stage.join("home/secrets")) {
            for e in rd.filter_map(|e| e.ok()) {
                if e.file_name().to_string_lossy().starts_with("env.sops.bak") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        copy_tree(&age_key, &stage.join("age/keys.txt"))?;

        let read_env = |k: &str| crate::onboard::env::read_env_key(&home.join(".env"), k);
        let manifest = serde_json::json!({
            "kind": "noo-migrate", "format": 1,
            "source_kind": source_kind,
            "cli_version": env!("CARGO_PKG_VERSION"),
            "exported_at_host": host,
            "ts_dnsname": ts.as_ref().map(|t| t.0.clone()),
            "ts_ip": ts.as_ref().map(|t| t.1.clone()),
            "image_tag": read_env("NOO_IMAGE_TAG"),
            "install_mode": read_env("NOO_INSTALL_MODE"),
            "data_root": read_env("NOO_DATA_ROOT"),
            "node_id": read_env("NODE_ID"),
            "pg_dump_sha256": sha256_file(&stage.join("db/pg.sql.gz")),
        });
        std::fs::write(stage.join(MANIFEST), serde_json::to_string_pretty(&manifest).unwrap())
            .map_err(|e| e.to_string())?;

        if !g.json { println!("{}", ui::phase("Seal")); }
        ui::step("sealing (aes-256-cbc, pbkdf2)");
        let tarball = stage.join("bundle.tar.gz");
        let tar_ok = Command::new("tar")
            .arg("-czf").arg(&tarball).arg("-C").arg(&stage)
            .args([MANIFEST, "db", "home", "age"])
            .status().map(|s| s.success()).unwrap_or(false);
        if !tar_ok {
            return Err("tar failed".into());
        }
        if !openssl_crypt(true, &tarball, &out_path, &pass) {
            return Err("openssl encryption failed".into());
        }
        let _ = std::fs::set_permissions(&out_path, {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::Permissions::from_mode(0o600)
        });
        ui::done("sealed");
        // Self-verify: the archive must decrypt and list its load-bearing
        // members before we call it a migration.
        if !g.json { println!("{}", ui::phase("Verify")); }
        ui::step("decrypting the archive back and listing its members");
        let vt = stage.join("verify.tar.gz");
        if !openssl_crypt(false, &out_path, &vt, &pass) {
            return Err("self-verify decrypt failed".into());
        }
        let listing = Command::new("tar").arg("-tzf").arg(&vt).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        for need in [MANIFEST, "db/pg.sql.gz", "home/secrets/env.sops", "home/pki/ca.key", "age/keys.txt"] {
            if !listing.lines().any(|l| l == need) {
                return Err(format!("self-verify: {need} missing from the archive"));
            }
        }
        ui::done("all load-bearing members present");
        let bytes = std::fs::metadata(&out_path).map(|m| m.len() as usize).unwrap_or(0);
        Ok((out_path.display().to_string(), bytes))
    })();
    let _ = std::fs::remove_dir_all(&stage);

    match result {
        Ok((path, bytes)) => {
            if g.json {
                println!("{}", serde_json::json!({"status":"ok","archive":path,"bytes":bytes}));
            } else {
                ui::close_done(&format!("migration archive sealed ({:.1} MB)", bytes as f64 / 1e6));
                println!("{}", ui::note("workers stay trusted (the CA travels); reuse the tailnet name on the new box"));
                // The archive path is the value a script captures.
                ui::value(&path);
                let import = format!("noo migrate import {path}");
                ui::guide(&[
                    (import.as_str(), "on the new device, after installing noo: restores this archive and converges the stack"),
                    ("noo stack stop && sudo tailscale serve reset", "after the new controller is green: retire this one"),
                ]);
            }
            Ok(0)
        }
        Err(e) => {
            if !g.json { println!(); }
            fail(g.json, ExitCode::Generic, "export_failed", &e,
                Some("nothing was written outside the temp stage"))
        }
    }
}

// ═══ import ═════════════════════════════════════════════════════════════

/// `noo migrate import` — RETIRED as a separate workflow (operator,
/// 2026-09-01: "no need for a dead path"). The converged flow is
/// `noo onboard --from-archive`: same wizard, answers pre-filled from the
/// archive, the DB restore sequenced inside the services step, and every
/// onboard assertion (tailnet tags, serve, OAuth, SAN re-issue, embedder,
/// watcher) running identically. This forwarder translates the old flags
/// and hands over — one implementation, two spellings.
/// `--force` never did anything (the converged flow always lets live files
/// beat the archive), so it is refused rather than accepted and ignored.
pub(crate) const FORCE_REMOVED: &str =
    "--force is not an option of `migrate import`: live files always beat the archive, so there is nothing to force";

pub fn migrate_import(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut archive: Option<String> = None;
    let mut pass_file: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--passphrase-file" => pass_file = iter.next().cloned(),
            "--data-root" => {
                // The converged storage step asks (with the manifest/env as
                // the default); honor the old flag by seeding the env lane.
                if let Some(dr) = iter.next() {
                    std::env::set_var("NOO_DATA_ROOT", dr);
                }
            }
            "--force" => {
                crate::output::fail(
                    g.json,
                    crate::output::ExitCode::Usage,
                    "usage",
                    FORCE_REMOVED,
                    None,
                );
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t if archive.is_none() => archive = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(archive) = archive else { return Err(Unhandled) };
    // One hand-off line, then the wizard owns the screen (its own phases).
    ui::step(&format!("handing over to noo onboard --from-archive {archive}"));
    println!("{}", ui::note("migrate import is that wizard, pre-filled from the archive: verify, restore, converge"));
    let mut fwd: Vec<String> = vec!["--from-archive".into(), archive];
    if let Some(f) = pass_file {
        fwd.push("--passphrase-file".into());
        fwd.push(f);
    }
    crate::onboard::onboard(g, &fwd)
}

#[cfg(test)]
mod stage_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// The plaintext staging directory is private and unguessable: 0700, a
    /// random suffix (not the pid), and a second call never reuses the first.
    #[test]
    fn the_staging_directory_is_private_and_unpredictable() {
        let a = private_stage("noo-migrate-test").unwrap();
        let b = private_stage("noo-migrate-test").unwrap();
        assert_ne!(a, b);
        for d in [&a, &b] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is {:o}", d.display(), mode);
            let name = d.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.ends_with(&format!("-{}", std::process::id())), "the suffix is the pid again: {name}");
            assert_eq!(name.len(), "noo-migrate-test-".len() + 16, "64 random bits, hex: {name}");
        }
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// The old name was predictable; a squatter who pre-creates the pid-named
    /// directory gets nothing from a new staging directory.
    #[test]
    fn a_pre_created_pid_named_directory_is_never_adopted() {
        let squat = std::env::temp_dir().join(format!("noo-migrate-test2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&squat);
        let s = private_stage("noo-migrate-test2").unwrap();
        assert_ne!(s, squat);
        let _ = std::fs::remove_dir_all(&squat);
        let _ = std::fs::remove_dir_all(&s);
    }

    /// The export source carries no pid-named stage and the dump runs under a
    /// restrictive umask.
    #[test]
    fn export_and_import_no_longer_stage_under_a_pid_name() {
        let src = include_str!("migrate.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        assert!(!code.contains("std::process::id()"), "a pid-named stage is back");
        assert!(code.contains("umask 077; set -o pipefail; docker exec"), "the dump lost its umask");
    }
}
