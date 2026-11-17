// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! i908: a node installs root code only if the RELEASE key listed it.
//!
//! The fleet signing key decides what a node APPLIES; it does not decide
//! what root code the node runs. Every root-run payload must be listed, by
//! sha256, in a list the release key signed ([`crate::release_sig`]): the
//! CLI release's `sha256sums.txt`, carried in the bundle as `release-sums` +
//! `release-sums.sig`, with `release-version` (the text whose sha256 is the
//! list's `noo-release-version` row). The Linux applier does this in shell
//! (`scripts/noo-apply.sh` §1c, which also checks the agent against the
//! stack lock); this module is the Mac lane's check and the controller's
//! own pre-check before it stages a bundle.
//!
//! On a Mac the root-run kinds are:
//!   * `cli-binary` — `/usr/local/bin/noo`, run by the root fetch daemon: it
//!     IS the Mac's applier, so it is checked before it replaces itself;
//!   * `hostd-binary` — the root helper;
//!   * `agent-plist`, `harness-plist` — LaunchDaemon definitions launchd
//!     loads as root. A plist names the program and the account it runs as,
//!     so it is root code. They are rendered per node (the user's name), so
//!     no release can list them; each must instead be byte-for-byte the
//!     template this release's CLI renders for THIS node's user (never root).
//!
//! `agent-binary` and `harness-binary` run as the user, but they are release
//! assets too, so they are held to the list as well. `run-agent` and
//! `run-harness` run as the user (the plists' UserName) and are not root code.
//!
//! The floor: a list older than the one this node last applied (or than the
//! CLI doing the check) is refused, so a superseded release cannot be
//! replayed. No dev path: anything not in a published release or rc is
//! refused with one line naming the kind, its sha256 and the remedy (75).

use std::collections::BTreeMap;

/// The file under the node's root anchor directory that records the floor.
pub const FLOOR_FILE: &str = "release-floor";
/// The exit code a release refusal reports (the Linux applier exits with it).
pub const REFUSED: i64 = 75;
/// What every refusal tells the reader to do.
pub const REMEDY: &str = "roll to a published release or rc (on the controller: noo upgrade --all)";

/// The release asset a Mac root-run binary kind must be listed under:
/// `<prefix><arch>-apple-darwin`, the arch one token (no `-`).
fn darwin_asset_ok(kind: &str, name: &str) -> bool {
    let prefix = match kind {
        "cli-binary" => "noo-",
        "hostd-binary" => "noo-hostd-",
        "agent-binary" => "noo-node-agent-",
        "harness-binary" => "noo-gateway-",
        _ => return false,
    };
    name.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix("-apple-darwin"))
        .is_some_and(|arch| !arch.is_empty() && arch.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}

/// The binary kinds a Mac bundle holds to the release list.
pub const DARWIN_LISTED: &[&str] = &["cli-binary", "hostd-binary", "agent-binary", "harness-binary"];
/// The LaunchDaemon kinds a Mac bundle holds to this release's templates.
pub const DARWIN_PLISTS: &[&str] = &["agent-plist", "harness-plist"];

/// A fixed-width sort key for `X.Y.Z` / `X.Y.Z-rc.N` (`stack-` and `v`
/// prefixes dropped); a final sorts after its rcs. None for any other shape.
pub fn version_key(v: &str) -> Option<(u32, u32, u32, u32)> {
    let v = v.trim();
    let v = v.strip_prefix("stack-").unwrap_or(v);
    let v = v.strip_prefix('v').unwrap_or(v);
    let (core, rc) = match v.split_once("-rc.") {
        Some((c, r)) => (c, Some(r)),
        None => (v, None),
    };
    let num = |s: &str, max: usize| -> Option<u32> {
        if s.is_empty() || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let mut it = core.split('.');
    let (a, b, c) = (num(it.next()?, 5)?, num(it.next()?, 5)?, num(it.next()?, 5)?);
    if it.next().is_some() {
        return None;
    }
    let rc = match rc {
        Some(r) => num(r, 4)?,
        None => u32::MAX,
    };
    Some((a, b, c, rc))
}

/// Is `a` an OLDER release than `b`? False when either is malformed.
pub fn older(a: &str, b: &str) -> bool {
    matches!((version_key(a), version_key(b)), (Some(x), Some(y)) if x < y)
}

/// The recorded `release` floor in a floor file's text, if any.
pub fn floor_release(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("release ")).map(str::trim)
}

/// The floor file's text after recording `version` (raised, never lowered;
/// any `stack` line the Linux applier wrote is kept).
pub fn raised_floor(current: Option<&str>, version: &str) -> String {
    let cur = current.unwrap_or("");
    let keep = floor_release(cur).filter(|f| version_key(f).is_some() && !older(f, version));
    let mut out = String::from("# noo (i908): the oldest release this node installs root code from. Written by the applier.\n");
    out.push_str(&format!("release {}\n", keep.unwrap_or(version)));
    for l in cur.lines().filter(|l| l.starts_with("stack ")) {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Every asset name `sums` lists with `sha` (`<hex>  <name>`, `*name` and a
/// path prefix normalised as [`crate::release_sig::manifest_sha_for`] does).
pub fn names_for<'a>(sums: &'a str, sha: &str) -> Vec<&'a str> {
    sums.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (sum, name) = (it.next()?, it.next()?);
            let name = name.trim_start_matches('*').rsplit('/').next().unwrap_or(name);
            sum.eq_ignore_ascii_case(sha).then_some(name)
        })
        .collect()
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn refuse(what: &str, why: &str) -> String {
    format!("REFUSED {what} — {why}; {REMEDY} ({REFUSED})")
}

/// The Mac lane's check over a bundle's verified payloads (see the module
/// doc). `user` is the account this node's daemons run as; `floor` the floor
/// file's text; `own_version` the version of the CLI doing the check (also
/// a floor). Ok(None): the bundle carries no root code, nothing to check.
/// Ok(Some(version)): every root kind is listed in release `version`.
pub fn darwin_check(
    payloads: &BTreeMap<String, Vec<u8>>,
    user: &str,
    floor: Option<&str>,
    own_version: &str,
    keys: &[&str],
) -> Result<Option<String>, String> {
    let root: Vec<&str> = DARWIN_LISTED.iter().chain(DARWIN_PLISTS).copied().filter(|k| payloads.contains_key(*k)).collect();
    if root.is_empty() {
        return Ok(None);
    }
    let kinds = root.join(" ");
    let get = |k: &str| payloads.get(k).ok_or_else(|| refuse(&kinds, &format!("the bundle carries root code but no release-signed list ({k})")));
    let sums = get("release-sums")?;
    let sig = String::from_utf8_lossy(get("release-sums.sig")?).to_string();
    let ver_bytes = get("release-version")?;
    crate::release_sig::verify_with_keys(sums, &sig, keys)
        .ok();
    let sums = String::from_utf8_lossy(sums).to_string();
    let version = std::str::from_utf8(ver_bytes).ok()
        .and_then(|t| t.strip_suffix('\n'))
        .filter(|v| !v.contains('\n') && version_key(v).is_some())
        .ok_or_else(|| refuse("release-version", "it is not one X.Y.Z or X.Y.Z-rc.N line"))?
        .to_string();
    if !crate::release_sig::manifest_names_version(&sums, &version) {
        return Err(refuse("release-version", &format!("{version} is not the release the signed list names")));
    }
    if let Some(f) = floor.and_then(floor_release) {
        if version_key(f).is_none() {
            return Err(refuse(&format!("release {version}"), &format!("the floor record names '{f}', which is not a version")));
        }
        if older(&version, f) {
            return Err(refuse(&format!("release {version}"), &format!("this node already applied release {f}; an older signed release is never installed again")));
        }
    }
    if older(&version, own_version) {
        return Err(refuse(&format!("release {version}"), &format!("this node's CLI is already {own_version}; an older signed release is never installed again")));
    }
    for kind in DARWIN_LISTED.iter().copied().filter(|k| payloads.contains_key(*k)) {
        let sha = sha256_hex(&payloads[kind]);
        if !names_for(&sums, &sha).iter().any(|n| darwin_asset_ok(kind, n)) {
            return Err(refuse(kind, &format!("sha256 {sha} is not in release {version}'s signed list")));
        }
    }
    for kind in DARWIN_PLISTS.iter().copied().filter(|k| payloads.contains_key(*k)) {
        let template = match kind {
            "agent-plist" => crate::commands::provision::DARWIN_AGENT_PLIST,
            _ => crate::commands::provision::DARWIN_HARNESS_PLIST,
        };
        let plain = !user.is_empty() && user != "root"
            && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !plain || payloads[kind] != template.replace("__USER__", user).into_bytes() {
            let sha = sha256_hex(&payloads[kind]);
            return Err(refuse(kind, &format!("sha256 {sha} is not release {version}'s LaunchDaemon for {user}")));
        }
    }
    Ok(Some(version))
}

/// The controller's pre-check: every root-run kind in `files` is listed in
/// the verified `sums` (and, for a Linux agent, in the verified `lock`), so a
/// bundle the node would refuse is refused here, before it is staged, with
/// the same words. Ok(()) also when the bundle carries no root code.
pub fn controller_check(files: &[(&str, Vec<u8>)], darwin: bool, sums: &str, version: &str, lock: Option<&str>) -> Result<(), String> {
    for (kind, bytes) in files {
        let sha = sha256_hex(bytes);
        let listed = match (darwin, *kind) {
            (true, k) if DARWIN_LISTED.contains(&k) => names_for(sums, &sha).iter().any(|n| darwin_asset_ok(k, n)),
            (false, "applier") => names_for(sums, &sha).contains(&"noo-apply.sh"),
            (false, "fetcher") => names_for(sums, &sha).contains(&"noo-fetch.sh"),
            (false, "hostd-binary") => names_for(sums, &sha).iter().any(|n| linux_asset_ok("noo-hostd-", n)),
            (false, "harness-binary") => names_for(sums, &sha).iter().any(|n| linux_asset_ok("noo-gateway-", n)),
            (false, "agent-binary") => lock.is_some_and(|l| lock_lists_agent(l, &sha)),
            _ => true,
        };
        if !listed {
            let list = if !darwin && *kind == "agent-binary" { "the stack's signed lock".to_string() } else { format!("release {version}'s signed list") };
            return Err(refuse(kind, &format!("sha256 {sha} is not in {list}; the node would refuse it")));
        }
    }
    Ok(())
}

fn linux_asset_ok(prefix: &str, name: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix("-unknown-linux-gnu").or_else(|| r.strip_suffix("-unknown-linux-musl")))
        .is_some_and(|arch| !arch.is_empty() && arch.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
}

/// Does the signed stack lock carry a `# node-agent-sha256 linux/<arch> <sha>` row for `sha`?
pub fn lock_lists_agent(lock: &str, sha: &str) -> bool {
    lock.lines().any(|l| {
        let mut it = l.trim_end().splitn(4, ' ');
        matches!((it.next(), it.next(), it.next(), it.next()),
            (Some("#"), Some("node-agent-sha256"), Some("linux/amd64" | "linux/arm64"), Some(s)) if s.eq_ignore_ascii_case(sha))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_sig::{pubkey_hex, sign, signing_key_from_seed_hex};

    fn release_key() -> ed25519_dalek::SigningKey {
        signing_key_from_seed_hex(&"42".repeat(32)).unwrap()
    }

    /// A bundle's payloads: `carried`, plus a release list (release `version`,
    /// signed by the test release key) vouching for `listed`.
    fn bundle(version: &str, listed: &[(&str, &[u8])], carried: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        let ver = format!("{version}\n");
        let mut sums = format!("{}  noo-release-version\n", sha256_hex(ver.as_bytes()));
        for (kind, b) in listed {
            let name = match *kind {
                "cli-binary" => "noo-aarch64-apple-darwin",
                "hostd-binary" => "noo-hostd-aarch64-apple-darwin",
                "agent-binary" => "noo-node-agent-aarch64-apple-darwin",
                "harness-binary" => "noo-gateway-aarch64-apple-darwin",
                other => other,
            };
            sums.push_str(&format!("{}  {name}\n", sha256_hex(b)));
        }
        let mut p: BTreeMap<String, Vec<u8>> = carried.iter().map(|(k, b)| (k.to_string(), b.to_vec())).collect();
        p.insert("release-sums.sig".into(), sign(&release_key(), sums.as_bytes()).into_bytes());
        p.insert("release-sums".into(), sums.into_bytes());
        p.insert("release-version".into(), ver.into_bytes());
        p
    }

    fn check_as(p: &BTreeMap<String, Vec<u8>>, floor: Option<&str>, own: &str) -> Result<Option<String>, String> {
        let pk = pubkey_hex(&release_key());
        darwin_check(p, "alice", floor, own, &[pk.as_str()])
    }

    fn check(p: &BTreeMap<String, Vec<u8>>, floor: Option<&str>) -> Result<Option<String>, String> {
        check_as(p, floor, "0.6.27")
    }

    const CLI: &[u8] = b"cli bytes";

    #[test]
    fn listed_root_code_passes_and_config_needs_no_list() {
        let p = bundle("0.6.27", &[("cli-binary", CLI)], &[("cli-binary", CLI)]);
        assert_eq!(check(&p, None).unwrap().as_deref(), Some("0.6.27"));
        let mut cfg = BTreeMap::new();
        cfg.insert("agent-env".to_string(), b"NODE_ID=x\n".to_vec());
        assert_eq!(check(&cfg, None).unwrap(), None);
    }

    #[test]
    fn every_root_kind_not_in_the_list_is_refused() {
        let unlisted: &[u8] = b"unlisted";
        for kind in DARWIN_LISTED {
            let p = bundle("0.6.27", &[], &[(*kind, unlisted)]);
            let e = check(&p, None).unwrap_err();
            assert!(e.contains(kind) && e.contains(&sha256_hex(unlisted)) && e.ends_with("(75)"), "{e}");
        }
        // Listed, but under another kind's asset name.
        let x: &[u8] = b"x";
        let p = bundle("0.6.27", &[("harness-binary", x)], &[("hostd-binary", x)]);
        assert!(check(&p, None).unwrap_err().contains("hostd-binary"));
    }

    #[test]
    fn root_code_without_a_list_is_refused() {
        let mut p = BTreeMap::new();
        p.insert("cli-binary".to_string(), CLI.to_vec());
        assert!(check(&p, None).unwrap_err().contains("no release-signed list"));
    }

    #[test]
    fn a_list_the_release_key_did_not_sign_is_refused() {
        let mut p = bundle("0.6.27", &[("cli-binary", CLI)], &[("cli-binary", CLI)]);
        let other = signing_key_from_seed_hex(&"07".repeat(32)).unwrap();
        let sums = p["release-sums"].clone();
        p.insert("release-sums.sig".into(), sign(&other, &sums).into_bytes());
        assert!(check(&p, None).unwrap_err().contains("does not verify"));
        // The genuine signature over a list edited afterwards.
        let evil: &[u8] = b"evil";
        let mut q = bundle("0.6.27", &[("cli-binary", CLI)], &[("cli-binary", evil)]);
        let mut s = q["release-sums"].clone();
        s.extend_from_slice(format!("{}  noo-aarch64-apple-darwin\n", sha256_hex(evil)).as_bytes());
        q.insert("release-sums".into(), s);
        assert!(check(&q, None).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn the_floor_refuses_an_older_release() {
        let p = bundle("0.6.27", &[("cli-binary", CLI)], &[("cli-binary", CLI)]);
        assert!(check(&p, Some("release 0.6.28\n")).unwrap_err().contains("already applied release 0.6.28"));
        assert!(check(&p, Some("release 0.6.27\n")).is_ok());
        assert!(check(&p, Some("release 0.6.27-rc.4\n")).is_ok());
        assert!(check(&p, Some("release $(id)\n")).unwrap_err().contains("not a version"));
        // The CLI doing the check is a floor too.
        assert!(check_as(&p, None, "0.6.28-rc.1").unwrap_err().contains("already 0.6.28-rc.1"));
        // A version text the list does not name.
        let mut q = p.clone();
        q.insert("release-version".into(), b"0.6.99\n".to_vec());
        assert!(check(&q, None).unwrap_err().contains("not the release the signed list names"));
    }

    #[test]
    fn a_plist_must_be_this_releases_template_for_this_user() {
        let good = crate::commands::provision::DARWIN_AGENT_PLIST.replace("__USER__", "alice");
        let p = bundle("0.6.27", &[], &[("agent-plist", good.as_bytes())]);
        assert!(check(&p, None).is_ok());
        let root = crate::commands::provision::DARWIN_AGENT_PLIST.replace("__USER__", "root");
        let p = bundle("0.6.27", &[], &[("agent-plist", root.as_bytes())]);
        assert!(check(&p, None).unwrap_err().contains("agent-plist"));
        let evil = good.replace("<key>UserName</key><string>alice</string>\n", "");
        assert_ne!(evil, good);
        let p = bundle("0.6.27", &[], &[("agent-plist", evil.as_bytes())]);
        assert!(check(&p, None).unwrap_err().contains("agent-plist"));
        let h = crate::commands::provision::DARWIN_HARNESS_PLIST.replace("__USER__", "bob");
        let p = bundle("0.6.27", &[], &[("harness-plist", h.as_bytes())]);
        assert!(check(&p, None).unwrap_err().contains("harness-plist"), "another user's plist passed");
    }

    #[test]
    fn versions_order_finals_after_their_rcs() {
        assert!(older("0.6.27-rc.3", "0.6.27") && older("0.6.9", "0.6.10") && older("v0.6.27", "stack-v0.6.28"));
        assert!(!older("0.6.27", "0.6.27") && !older("0.6.28", "0.6.27-rc.9"));
        for bad in ["", "0.6", "0.6.27.1", "0.6.x", "0.6.27-rc.", "0.6.27-beta.1", "$(id)"] {
            assert!(version_key(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_floor_rises_and_never_falls() {
        let t = raised_floor(None, "0.6.27");
        assert_eq!(floor_release(&t), Some("0.6.27"));
        let with_stack = format!("{t}stack v0.6.27\n");
        let t = raised_floor(Some(with_stack.as_str()), "0.6.26");
        assert_eq!(floor_release(&t), Some("0.6.27"));
        assert!(t.contains("stack v0.6.27\n"), "{t}");
        assert_eq!(floor_release(&raised_floor(Some(t.as_str()), "0.6.28-rc.1")), Some("0.6.28-rc.1"));
    }

    #[test]
    fn the_controller_refuses_what_the_node_would() {
        let sums = format!("{}  noo-apply.sh\n{}  noo-hostd-x86_64-unknown-linux-gnu\n", sha256_hex(b"apply"), sha256_hex(b"hostd"));
        let lock = format!("# stack v0.6.27\n# node-agent-sha256 linux/amd64 {}\n", sha256_hex(b"agent"));
        let ok: Vec<(&str, Vec<u8>)> = vec![("applier", b"apply".to_vec()), ("hostd-binary", b"hostd".to_vec()),
            ("agent-binary", b"agent".to_vec()), ("agent-env", b"x".to_vec())];
        assert!(controller_check(&ok, false, &sums, "0.6.27", Some(lock.as_str())).is_ok());
        let bad: Vec<(&str, Vec<u8>)> = vec![("fetcher", b"f".to_vec()), ("harness-binary", b"hostd".to_vec()), ("agent-binary", b"other".to_vec())];
        for one in &bad {
            let e = controller_check(std::slice::from_ref(one), false, &sums, "0.6.27", Some(lock.as_str())).unwrap_err();
            assert!(e.contains(one.0), "{e}");
        }
        let agent: Vec<(&str, Vec<u8>)> = vec![("agent-binary", b"agent".to_vec())];
        assert!(controller_check(&agent, false, &sums, "0.6.27", None).is_err());
    }

    /// The shell applier pins the same release keys as release_sig (the
    /// Python guard tests/test_apply_release_check.py reads both too).
    #[test]
    fn the_shell_applier_pins_the_release_keys() {
        let Ok(src) = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/noo-apply.sh")) else { return };
        let line = src.lines().find(|l| l.starts_with("RELEASE_PUBKEYS_HEX=")).expect("RELEASE_PUBKEYS_HEX in noo-apply.sh");
        let keys: Vec<&str> = line.trim_start_matches("RELEASE_PUBKEYS_HEX=").trim_matches('"').split_whitespace().collect();
        assert_eq!(keys, crate::release_sig::RELEASE_PUBKEYS_HEX);
    }
}
