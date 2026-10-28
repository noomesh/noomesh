// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::{reconcile_integration_key, AuditKeyRefusal, AuditKeyStage};
use crate::commands::secrets::SecretStore;
use std::io::Write;
use std::process::{Command, Stdio};

#[path = "../../tests/common/scratch_dir.rs"]
mod scratch_dir;

struct KeyEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Drop for KeyEnvironment {
    fn drop(&mut self) {
        for (key, prior) in &self.0 {
            if let Some(value) = prior { std::env::set_var(key, value); }
            else { std::env::remove_var(key); }
        }
    }
}

#[test]
fn integration_upgrade_key_round_trips_without_rotation_or_plaintext() {
    for tool in ["sops", "age-keygen"] {
        if !Command::new(tool).arg("--version").output().is_ok_and(|r| r.status.success()) {
            assert_ne!(std::env::var("NOO_REQUIRE_SOPS").ok().as_deref(), Some("1"),
                "required SOPS upgrade regression tooling unavailable");
            eprintln!("SKIP: install sops and age-keygen to run the upgrade-store regression");
            return;
        }
    }
    let root = scratch_dir::ScratchDir::new("noo-integration-upgrade");
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    let key = root.join("fixture.age");
    assert!(Command::new("age-keygen").arg("-o").arg(&key).output().unwrap().status.success());
    let public = Command::new("age-keygen").arg("-y").arg(&key).output().unwrap();
    assert!(public.status.success());
    let public = String::from_utf8(public.stdout).unwrap();
    std::fs::write(root.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: secrets/.*\\.sops$\n    age: {}\n", public.trim())).unwrap();
    let env_before = "NOO_SECRETS_BACKEND=sops\nNOO_NODE_NAME=fixture\n";
    std::fs::write(root.join(".env"), env_before).unwrap();
    let _restore = KeyEnvironment(["SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY"].into_iter()
        .map(|k| (k, std::env::var_os(k))).collect());
    std::env::set_var("SOPS_AGE_KEY_FILE", &key);
    std::env::remove_var("SOPS_AGE_KEY");
    let store_path = root.join("secrets/env.sops");
    let encrypt = |plain: &[u8]| {
        let mut child = Command::new("sops").current_dir(&root)
            .args(["-e", "--input-type", "dotenv", "--output-type", "dotenv", "--filename-override"])
            .arg(&store_path).arg("/dev/stdin").stdin(Stdio::piped())
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(plain).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "fixture encryption failed");
        std::fs::write(&store_path, output.stdout).unwrap();
    };
    // The old audit key is already present on a 0.6.13 installation.
    encrypt(b"NOO_AUDIT_HMAC_KEY=fixture-audit-key-already-present-32\nFIXTURE_EXISTING=preserve-me\n");
    assert_eq!(reconcile_integration_key(&root), Ok(AuditKeyStage::Minted));
    let store = SecretStore::load_sops(&store_path).unwrap();
    let integration = store.get("NOO_INTEGRATIONS_KEY").unwrap().to_owned();
    assert!(integration.len() >= 32);
    assert!(store.get("NOO_AUDIT_HMAC_KEY") == Some("fixture-audit-key-already-present-32"));
    assert!(store.get("FIXTURE_EXISTING") == Some("preserve-me"));
    let ciphertext = std::fs::read(&store_path).unwrap();
    assert!(!String::from_utf8_lossy(&ciphertext).contains(&integration));
    assert_eq!(reconcile_integration_key(&root), Ok(AuditKeyStage::AlreadyPresent));
    assert!(SecretStore::load_sops(&store_path).unwrap().get("NOO_INTEGRATIONS_KEY") == Some(integration.as_str()),
        "a second upgrade must not rotate the encryption key");
    assert!(std::fs::read(&store_path).unwrap() == ciphertext, "present keys must not rewrite the store");
    assert!(std::fs::read_to_string(root.join(".env")).unwrap() == env_before);

    encrypt(b"NOO_AUDIT_HMAC_KEY=fixture-audit-key-already-present-32\nNOO_INTEGRATIONS_KEY=\n");
    let blank = std::fs::read(&store_path).unwrap();
    assert!(matches!(reconcile_integration_key(&root), Err(AuditKeyRefusal::Store(_))));
    assert!(std::fs::read(&store_path).unwrap() == blank);
    std::fs::write(&store_path, b"unreadable-fixture").unwrap();
    assert!(matches!(reconcile_integration_key(&root), Err(AuditKeyRefusal::Store(_))));
    assert!(std::fs::read(&store_path).unwrap() == b"unreadable-fixture");
    std::fs::remove_file(&store_path).unwrap();
    assert_eq!(reconcile_integration_key(&root), Err(AuditKeyRefusal::NoStore));
    assert!(std::fs::read_to_string(root.join(".env")).unwrap() == env_before);
}
