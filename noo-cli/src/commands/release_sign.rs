// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security release-sign` / `release-verify` — the release pipeline's
//! signing verbs. The seed comes from the
//! `NOO_RELEASE_SIGNING_SEED` env (Actions secret) or `--seed-file`; the
//! verb refuses to sign with a key whose public half is not baked into this
//! build, so a wrong secret cannot produce a signature nobody can verify.

use std::path::PathBuf;
use crate::output::{fail, ExitCode};
use crate::release_sig;
use crate::ui;
use crate::{Globals, Unhandled};

const SIGN_USAGE: &str = "usage: noo security release-sign <file> [--seed-file <path>] [--out <file.sig>]";
const VERIFY_USAGE: &str = "usage: noo security release-verify <file> [<file.sig>]";

pub fn release_sign(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut file: Option<PathBuf> = None;
    let mut seed_file: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--seed-file" => seed_file = it.next().map(PathBuf::from),
            "--out" => out = it.next().map(PathBuf::from),
            "--help" | "-h" => { println!("{SIGN_USAGE}"); return Ok(0); }
            v if v.starts_with('-') => fail(g.json, ExitCode::Usage, "usage", &format!("unknown flag {v}"), Some(SIGN_USAGE)),
            v => file = Some(PathBuf::from(v)),
        }
    }
    let Some(file) = file else {
        fail(g.json, ExitCode::Usage, "usage", "a file to sign is required", Some(SIGN_USAGE))
    };
    let seed_hex = match std::env::var("NOO_RELEASE_SIGNING_SEED").ok().filter(|s| !s.trim().is_empty()) {
        Some(s) => s,
        None => {
            let p = seed_file.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".config/noo/release-signing.seed")
            });
            match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(e) => fail(g.json, ExitCode::Generic, "no_seed",
                    &format!("no release signing seed: NOO_RELEASE_SIGNING_SEED unset and {} unreadable ({e})", p.display()),
                    Some("the seed never enters the repo; the release workflow carries it as a secret")),
            }
        }
    };
    let key = match release_sig::signing_key_from_seed_hex(&seed_hex) {
        Ok(k) => k,
        Err(e) => fail(g.json, ExitCode::Generic, "bad_seed", &e, None),
    };
    let pk = release_sig::pubkey_hex(&key);
    if !release_sig::RELEASE_PUBKEYS_HEX.contains(&pk.as_str()) {
        fail(g.json, ExitCode::Generic, "key_not_baked",
            &format!("this seed's public key ({pk}) is not baked into this build — a signature from it would verify nowhere"),
            Some("add the key to RELEASE_PUBKEYS_HEX and ship a CLI before signing with it"));
    }
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", file.display()), None),
    };
    let sig = release_sig::sign(&key, &data);
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.sig", file.display())));
    if let Err(e) = std::fs::write(&out, format!("{sig}\n")) {
        fail(g.json, ExitCode::Generic, "write_failed", &format!("{}: {e}", out.display()), None);
    }
    if g.json {
        println!("{}", serde_json::json!({"signed": file, "sig": out, "pubkey": pk}));
    } else {
        ui::done(&format!("signed {} to {}  {}", file.display(), out.display(), ui::muted(&format!("key {}…", &pk[..12]))));
        ui::guide(&[(&format!("noo security release-verify {} {}", file.display(), out.display()), "proves the signature against the key baked into this binary")]);
    }
    Ok(0)
}

pub fn release_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") || pos.is_empty() {
        println!("{VERIFY_USAGE}");
        return Ok(if pos.is_empty() { 2 } else { 0 });
    }
    let file = PathBuf::from(pos[0]);
    let sig_path = pos.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(format!("{}.sig", file.display())));
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", file.display()), None),
    };
    let sig = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed", &format!("{}: {e}", sig_path.display()), None),
    };
    match release_sig::verify(&data, &sig) {
        Ok(i) => {
            if g.json {
                println!("{}", serde_json::json!({"verified": true, "file": file, "key_index": i}));
            } else {
                println!("{}", ui::status_line(ui::Glyph::Ok, &format!("{} verifies against release key #{i}  {}", file.display(), ui::muted(&format!("{}…", &release_sig::RELEASE_PUBKEYS_HEX[i][..12])))));
            }
            Ok(0)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "release_signature_invalid", &e,
            Some("the file or its signature was altered, or it was signed with a key this build does not carry")),
    }
}
