// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons enable evolve` end to end: the BUILT binary
//! against a throwaway sops store with its own age key and a fake gateway on
//! loopback that answers the service-key routes.
//!
//! What this proves beyond the unit tests in `commands::addon_enable`: the
//! live side — the systems manifest read from noomesh.yaml, the real
//! `mint_missing` into a real encrypted store, the key POST and the
//! `store_provisioned` write, and that the switch flips only after both. And
//! that `noo config launch-check system-credentials` agrees with the result.
//!
//! **Needs `sops` and `age` on PATH and SKIPS without them** (see
//! tests/secrets_store.rs for why CI runners lack them); the pure ordering
//! and refusal rules are covered by the unit tests, which need nothing.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

fn bin() -> String {
    std::env::var("NOO_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_noo").to_string())
}

fn have(tool: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {tool}")]).output().map(|o| o.status.success()).unwrap_or(false)
}

const FAKE_KEY: &str = "THROWAWAY-svc-evolve-key-ffff6666";
const V_PG: &str = "THROWAWAY-postgres-value-aaaa1111";

const CONFIG: &str = "\
# Runtime config.
addons:
  trellion: false
  evolve: false  # licensed
systems:
  evolve:
    role: noo_evolve
    ddl_role: noo_evolve_ddl
    schema: evolve
    password_env: NOO_EVOLVE_DB_PASSWORD
    ddl_password_env: NOO_EVOLVE_DDL_PASSWORD
";

fn fixture(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("noo-addon-enable-it-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    let key = root.join("age.key");
    assert!(Command::new("age-keygen").arg("-o").arg(&key).output().unwrap().status.success());
    let pubkey = String::from_utf8(Command::new("age-keygen").arg("-y").arg(&key).output().unwrap().stdout).unwrap();
    std::fs::write(
        root.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: secrets/.*\\.sops$\n    age: \"{}\"\n", pubkey.trim()),
    )
    .unwrap();
    let store = root.join("secrets/env.sops");
    let mut c = Command::new("sops")
        .arg("-e")
        .arg("--filename-override")
        .arg(&store)
        .args(["--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin"])
        .env("SOPS_AGE_KEY_FILE", &key)
        // sops finds .sops.yaml by walking up from its CWD, not from the
        // target: run from the test's cwd it would find the REPO's rule and
        // encrypt to the real recipient.
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(format!("POSTGRES_PASSWORD={V_PG}\n").as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success(), "sops encrypt failed");
    std::fs::write(&store, out.stdout).unwrap();
    std::fs::write(root.join(".env"), "NOO_SECRETS_BACKEND=sops\nNOO_NODE_NAME=fixture\n").unwrap();
    std::fs::write(root.join("noomesh.yaml"), CONFIG).unwrap();
    root
}

/// Key NAMES in the store — never values.
fn key_names(root: &Path) -> Vec<String> {
    let out = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(root.join("secrets/env.sops"))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .output()
        .unwrap();
    assert!(out.status.success(), "the fixture store did not decrypt — every absence below would be vacuous");
    String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string())).collect()
}

fn store_text(root: &Path) -> String {
    let out = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(root.join("secrets/env.sops"))
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A fake gateway: the service-key listing, the scope vocabulary (404, as an
/// older gateway answers) and the mint. Records every request line.
struct Gateway {
    url: String,
    log: Arc<Mutex<Vec<String>>>,
}

fn gateway() -> Gateway {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(Mutex::new(false));
    let (log2, active2) = (log.clone(), active.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            let req = line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            log2.lock().unwrap().push(req.clone());
            let (status, resp) = match req.as_str() {
                "GET /api/security/service-keys" => {
                    let keys = if *active2.lock().unwrap() {
                        r#"[{"consumer":"svc:evolve","active":true,"superseded_at":null,"scopes":["addon"]}]"#
                    } else {
                        "[]"
                    };
                    (200, format!(r#"{{"keys":{keys}}}"#))
                }
                "POST /api/security/service-keys" => {
                    *active2.lock().unwrap() = true;
                    (200, format!(r#"{{"key":"{FAKE_KEY}","consumer":"svc:evolve"}}"#))
                }
                _ => (404, r#"{"detail":"not found"}"#.to_string()),
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                resp.len()
            );
        }
    });
    Gateway { url, log }
}

fn noo(root: &Path, gw: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("NOO_REPO_ROOT", root)
        .env("HOME", root)
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"))
        .env("NOO_GATEWAY_URL", gw)
        .env_remove("NOO_TOKEN")
        .env_remove("NOO_EVOLVE_DDL_PASSWORD")
        .env_remove("NOO_EVOLVE_DB_PASSWORD")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn noo")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn enable_mints_the_ddl_password_and_the_key_then_flips_and_a_second_run_is_a_no_op() {
    if !(have("sops") && have("age-keygen")) {
        eprintln!("SKIP: sops/age not on PATH");
        return;
    }
    let root = fixture("happy");
    let gw = gateway();

    // Before: the launcher's check agrees evolve is off, so nothing is missing.
    let pre = noo(&root, &gw.url, &["config", "launch-check", "system-credentials", root.join("noomesh.yaml").to_str().unwrap()]);
    assert_eq!(pre.status.code(), Some(0), "{}", text(&pre));

    let o = noo(&root, &gw.url, &["addons", "enable", "evolve"]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    let names = key_names(&root);
    for k in ["NOO_EVOLVE_DDL_PASSWORD", "NOO_EVOLVE_DB_PASSWORD", "NOO_SVC_KEY_EVOLVE"] {
        assert!(names.iter().any(|n| n == k), "{k} not in the store after enable: {names:?}\n{out}");
    }
    assert!(names.iter().any(|n| n == "POSTGRES_PASSWORD"), "the mint dropped an existing key");
    assert!(!out.contains(FAKE_KEY) && !out.contains(V_PG), "a value reached the output:\n{out}");
    let yaml = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap();
    assert!(yaml.contains("evolve: true") && yaml.contains("# licensed"), "{yaml}");
    let mints = |log: &Arc<Mutex<Vec<String>>>| log.lock().unwrap().iter().filter(|r| *r == "POST /api/security/service-keys").count();
    assert_eq!(mints(&gw.log), 1);

    // The launcher's check now passes for an enabled evolve: the env the
    // launcher would export is the store, so hand it over the way
    // load_secrets does.
    let mut launch = Command::new(bin());
    launch
        .args(["config", "launch-check", "system-credentials", root.join("noomesh.yaml").to_str().unwrap()])
        .env("NOO_REPO_ROOT", &root)
        .env("HOME", &root)
        .env("SOPS_AGE_KEY_FILE", root.join("age.key"));
    for line in store_text(&root).lines() {
        if let Some((k, v)) = line.split_once('=') {
            launch.env(k, v);
        }
    }
    let l = launch.output().unwrap();
    assert_eq!(l.status.code(), Some(0), "{}", text(&l));

    // Second enable: nothing minted, no key POSTed, the file unchanged.
    let before_store = store_text(&root);
    let o2 = noo(&root, &gw.url, &["addons", "enable", "evolve"]);
    assert!(o2.status.success(), "{}", text(&o2));
    assert_eq!(mints(&gw.log), 1, "a second enable minted another key");
    assert_eq!(std::fs::read_to_string(root.join("noomesh.yaml")).unwrap(), yaml);
    assert!(store_text(&root) == before_store, "a second enable changed the store");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_unreachable_gateway_changes_nothing() {
    if !(have("sops") && have("age-keygen")) {
        eprintln!("SKIP: sops/age not on PATH");
        return;
    }
    let root = fixture("down");
    // A port nothing listens on.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let o = noo(&root, &dead, &["addons", "enable", "evolve"]);
    assert!(!o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read_to_string(root.join("noomesh.yaml")).unwrap(), CONFIG, "the switch flipped anyway");
    assert!(!key_names(&root).iter().any(|n| n == "NOO_EVOLVE_DDL_PASSWORD"), "minted for an enable that refused");
    assert!(text(&o).contains("noomesh.yaml is unchanged"), "{}", text(&o));

    // And the launcher refuses the state the old flag-only path left.
    std::fs::write(root.join("noomesh.yaml"), CONFIG.replace("evolve: false", "evolve: true")).unwrap();
    let l = Command::new(bin())
        .args(["config", "launch-check", "system-credentials", root.join("noomesh.yaml").to_str().unwrap()])
        .env("NOO_REPO_ROOT", &root)
        .env("HOME", &root)
        .env_remove("NOO_EVOLVE_DDL_PASSWORD")
        .env_remove("NOO_EVOLVE_DB_PASSWORD")
        .output()
        .unwrap();
    assert_eq!(l.status.code(), Some(3), "{}", text(&l));
    assert!(text(&l).contains("noo systems enable evolve"), "{}", text(&l));
    let _ = std::fs::remove_dir_all(&root);
}
