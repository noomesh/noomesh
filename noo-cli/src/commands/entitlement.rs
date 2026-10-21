// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security entitlement` — install / show / verify, plus keygen / issue
//! (the signer, in entitlement_signer.rs, present only in builds that carry
//! that file; every other build answers those two verbs with "not available
//! in this build"). install / show / verify need only the public key baked
//! into this binary.

use crate::entitlement_terms as terms;
use crate::entitlement::{self, Entitlement, KNOWN_FEATURES, STORE_KEY};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

pub(super) const USAGE: &str = "Usage: noo security entitlement keygen [--out <file>]\n\
       noo security entitlement issue --sub <customer> (--terms <version> | --no-terms) [--tier intelligent] [--features a,b] [--days <n>] [--id <id>] [--addon <name>=<registry>:<key>[,<key>]]... [--pull-host <host>] [--bind-key <hex>] [--key <file>]\n\
       noo security entitlement install <token> [--enable] [--ci] [--accept-terms <version>]\n\
       noo security entitlement show\n\
       noo security entitlement verify <token>\n\
       noo security entitlement pubkey";

pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn print_ent(g: &Globals, ent: &Entitlement, verdict: &str, acceptance: Option<Option<&terms::Acceptance>>) {
    if g.json {
        let mut o = serde_json::json!({"entitlement": ent, "verdict": verdict});
        if let Some(a) = acceptance {
            o["install_acceptance"] = serde_json::json!(a);
        }
        println!("{o}");
        return;
    }
    println!("{}", ui::header("entitlement", Some(&ent.sub)));
    let mut rows: Vec<(&str, String)> = vec![
        ("subject", ent.sub.clone()),
        ("tier", format!("{}{}", ent.tier, if ent.features.is_empty() { String::new() } else { ui::muted(&format!("  [{}]", ent.features.join(", "))) })),
        ("id", if ent.id.is_empty() { ui::dash().to_string() } else { ui::muted(&ent.id) }),
        ("issued", fmt_ts(ent.iat)),
        ("expires", if ent.exp == 0 { "never".to_string() } else { fmt_ts(ent.exp) }),
    ];
    rows.push(("terms accepted at issue", terms_at_issue(ent)));
    if let Some(a) = acceptance {
        rows.push(("terms accepted at install", match a {
            Some(a) => format!("{} on {} ({}@{}, {})", a.terms_version, a.accepted_at, a.os_user, a.hostname, a.cli_version),
            None => "not recorded on this controller".to_string(),
        }));
    }
    if let Some(b) = &ent.bound {
        rows.push(("bound", b.clone()));
    }
    if let Some(n) = ent.max_nodes {
        rows.push(("seats", format!("{n} nodes")));
    }
    if let Some(k) = ent.controller_key() {
        rows.push(("controller key", format!("{}  {}", entitlement::short_key_id(k), ui::muted("(`noo security entitlement pubkey` shows this controller's)"))));
    }
    let valid = verdict.starts_with("valid");
    rows.push(("verdict", if valid { ui::ok(verdict) } else { ui::err(verdict) }));
    print!("{}", ui::kv(&rows));
    println!("{}", ui::section("features"));
    for (feature, what) in KNOWN_FEATURES {
        let (glyph, label) = if ent.grants(feature) { (Glyph::Ok, "unlocks".to_string()) } else { (Glyph::Bullet, ui::muted("not granted")) };
        println!("  {}  {what}  {label}", ui::glyph_cell(glyph));
    }
    if !ent.addons.is_empty() {
        println!("{}", ui::section("add-on signers"));
        print!("{}", ui::kv(&addon_signer_rows(ent)));
    }
}

/// One row per add-on trust block: the registry root and the current key
/// (#0) by short id, plus how many older keys still verify.
pub(super) fn addon_signer_rows(ent: &Entitlement) -> Vec<(&str, String)> {
    ent.addons
        .iter()
        .map(|(name, a)| {
            let older = match a.keys.len() {
                0 | 1 => String::new(),
                n => ui::muted(&format!("  (+{} older)", n - 1)),
            };
            let key0 = a.keys.first().map(|k| entitlement::short_key_id(k)).unwrap_or_else(|| ui::dash().to_string());
            let pull = a.pull.as_deref().map(|p| ui::muted(&format!("  pulled via {p}"))).unwrap_or_default();
            (name.as_str(), format!("{}  key #0 {key0}{older}{pull}", a.registry))
        })
        .collect()
}

pub(super) fn terms_at_issue(ent: &Entitlement) -> String {
    match &ent.terms {
        Some(t) => t.clone(),
        None => "none recorded (issued before terms)".to_string(),
    }
}

fn fmt_ts(ts: i64) -> String {
    // Enough precision for a licence; avoids pulling a date crate in.
    let days = ts / 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} (unix {ts})")
}

/// Howard Hinnant's days→civil, for printing dates without chrono.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Builds without entitlement_signer.rs carry no licence signer.
#[cfg(not(has_entitlement_signer))]
fn signer_unavailable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(0);
    }
    fail(g.json, ExitCode::Generic, "not_available_in_this_build", "this command is not available in this build", Some("`verify`, `install` and `show` work in every build"))
}

#[cfg(not(has_entitlement_signer))]
pub fn entitlement_keygen(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    signer_unavailable(g, args)
}

#[cfg(not(has_entitlement_signer))]
pub fn entitlement_issue(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    signer_unavailable(g, args)
}

pub fn entitlement_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let token = match args {
        [t] if !t.starts_with('-') => t.clone(),
        _ => { eprintln!("{USAGE}"); return Ok(2); }
    };
    match entitlement::check(&token, now()) {
        Ok(ent) => { print_ent(g, &ent, "valid (features above are what it unlocks)", None); Ok(0) }
        Err(e) => {
            match entitlement::verify(&token) {
                Ok(ent) => print_ent(g, &ent, &format!("INVALID — {e}"), None),
                Err(_) => fail(g.json, ExitCode::Generic, "entitlement_invalid", &e, None),
            }
            Ok(1)
        }
    }
}

pub fn entitlement_install(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // `--enable` also switches on the add-ons the token grants. Opt-in,
    // never automatic: a licence covering three features does not mean the
    // operator wants three more containers running, and enabling changes
    // which containers run.
    let mut token: Option<String> = None;
    let mut enable = false;
    let mut ci = false;
    let mut accept_terms: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--enable" => enable = true,
            "--ci" => ci = true,
            "--accept-terms" => accept_terms = Some(it.next().cloned().unwrap_or_default()),
            t if !t.starts_with('-') && token.is_none() => token = Some(t.trim().to_string()),
            _ => { eprintln!("{USAGE}"); return Ok(2); }
        }
    }
    let Some(token) = token else { eprintln!("{USAGE}"); return Ok(2); };
    let ent = match entitlement::check(&token, now()) {
        Ok(e) => e,
        Err(e) => fail(g.json, ExitCode::Generic, "entitlement_invalid", &format!("refusing to install: {e}"), None),
    };
    // Consent comes before storage. Nothing below runs unless the terms were
    // accepted AND the acceptance was written down.
    let shown = terms::shown_version(ent.terms.as_deref()).to_string();
    eprint!("{}", terms::block(ent.terms.as_deref()));
    let interactive = !ci && !g.json && unsafe { libc::isatty(0) } == 1;
    let decision = if interactive {
        use std::io::{BufRead as _, Write as _};
        eprint!("Type `accept` to accept these terms and install: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        terms::decide(&shown, terms::Mode::Interactive { typed: &line })
    } else {
        terms::decide(&shown, terms::Mode::NonInteractive { flag: accept_terms.as_deref() })
    };
    if let Err(msg) = decision {
        fail(g.json, ExitCode::Generic, "terms_not_accepted", &msg, Some(terms::ADDON_TERMS_URL));
    }
    let record_path = terms::log_path();
    if let Err(e) = terms::append(&record_path, &terms::new_acceptance(&ent, &shown)) {
        fail(g.json, ExitCode::Generic, "terms_record_failed", &format!("refusing to install: the acceptance could not be recorded ({e}); consent that is not recorded did not happen"), Some("make the controller state home writable, then re-run"));
    }
    let recorded = format!("acceptance of {shown} recorded in {}", record_path.display());
    let root = crate::envfile::repo_root();
    let where_ = if crate::envfile::sops_backend_active() {
        if let Err(e) = crate::commands::secrets::store_upsert(&[(STORE_KEY.to_string(), token.clone())]) {
            fail(g.json, ExitCode::Generic, "store_write_failed", &format!("{e} — token NOT stored; the {recorded} (it records consent, not installation)"), None);
        }
        "secrets/env.sops"
    } else {
        if let Err(e) = crate::onboard::env::update_env_key(&root.join(".env"), STORE_KEY, &token) {
            fail(g.json, ExitCode::Generic, "env_write_failed", &format!("{e} — token NOT stored; the {recorded} (it records consent, not installation)"), None);
        }
        ".env"
    };
    // Features are the only authority — `addons.rs` says tiers are bundle
    // labels. An operator hit exactly that on 2026-09-14: a token reading
    // `tier: intelligent` with an empty feature list unlocked nothing.
    let unlocks = crate::commands::addons::addons_granted_by(&ent.features);
    let unlock_names: Vec<&str> = unlocks.iter().map(|r| r.key).collect();
    let (enabled, failed, principals) = if enable {
        enable_unlocked(
            &crate::commands::addons::config_path(),
            &unlock_names,
            &mut crate::commands::addon_enable::Live { g, force: false, lock: None },
        )
    } else {
        (Vec::new(), Vec::new(), crate::commands::addon_enable::PrincipalStep::Unchanged)
    };

    if g.json {
        println!("{}", serde_json::json!({
            "installed": true, "store": where_, "terms_accepted": shown, "terms_record": record_path, "entitlement": ent,
            "unlocks": unlock_names,
            "enabled": enabled.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            "enable": enabled.iter().map(|(k, e)| crate::commands::addon_enable::report_json(k, e)).collect::<Vec<_>>(),
            "failed": failed.iter().map(|(k, r)| serde_json::json!({"addon": k, "error": r.why, "fix": r.fix})).collect::<Vec<_>>(),
            "nats_principals": crate::commands::addon_enable::principals_json(&principals),
            "restart_required": !enabled.is_empty(),
        }));
    } else {
        ui::done(&format!("entitlement for '{}' installed as {STORE_KEY} in {where_}", ent.sub));
        println!("{}", ui::note(&recorded));
        if unlock_names.is_empty() {
            println!("{}", ui::note(
                "this token grants no add-on features — tiers are labels, features are the \
                 authority, so nothing is unlocked by it",
            ));
        } else if enable {
            for (k, e) in &enabled {
                crate::commands::addon_enable::report(k, e);
            }
            crate::commands::addon_enable::report_principals(&principals);
            for (k, r) in &failed {
                ui::failed(
                    &format!("{k} not enabled: {} — noomesh.yaml is unchanged for it; the licence IS installed", r.why),
                    Some(&r.fix),
                );
            }
        } else {
            // Show the blast radius before the operator chooses it.
            println!("{}", ui::note(&format!(
                "it unlocks: {}. Nothing was switched on — re-run with --enable, or \
                 `noo addons enable <name>`",
                unlock_names.join(", "),
            )));
        }
        // Never restart here. Enabling changes which containers run, and a
        // command that installs a licence must not bounce a live fleet.
        ui::guide(&[
            ("noo addons list", "declared vs effective for every add-on"),
            ("noo stack restart --force", "applies any change — nothing is restarted for you"),
            ("noo security entitlement show", "confirms what is installed and when it expires"),
        ]);
    }
    // The licence is installed either way; an add-on it could not switch on
    // is still a failure the caller must see.
    Ok(if failed.is_empty() { 0 } else { 1 })
}

/// `--enable`: every unlocked add-on through `addon_enable::enable`, the
/// same path `noo addons enable` takes — credentials, then the declared
/// key, then the switch. A licence that unlocks an add-on must not leave it
/// declared on over credentials nobody minted (the stack-v0.2.80 rehearsal:
/// the next restart crash-looped the gateway). One add-on's refusal does not
/// stop the next.
///
/// Then, once, after every switch: the add-on NATS principals (mint, render,
/// HUP), exactly as `noo addons enable` and `noo upgrade --stack` do. Before
/// this the fresh-install path skipped it and intel ran on the worker
/// fallback until the next `upgrade --stack` (0.6.6-rc.1 rehearsal).
pub(crate) fn enable_unlocked<'a>(
    config: &std::path::Path,
    names: &[&'a str],
    ops: &mut dyn crate::commands::addon_enable::EnableOps,
) -> crate::commands::addon_enable::EnableOutcomes<'a> {
    let mut enabled = Vec::new();
    let mut failed = Vec::new();
    for &name in names {
        match crate::commands::addon_enable::enable(config, name, ops) {
            Ok(e) => enabled.push((name, e)),
            Err(r) => failed.push((name.to_string(), r)),
        }
    }
    let principals = if enabled.is_empty() {
        crate::commands::addon_enable::PrincipalStep::Unchanged
    } else {
        ops.reconcile_principals()
    };
    (enabled, failed, principals)
}

/// `noo security entitlement pubkey`: this controller's add-on key, the
/// 64-hex ed25519 public key the operator sends the vendor so the
/// entitlement is bound to this controller (`cnf`, `issue --bind-key`).
/// Derived from the cluster CA (`addons::pop`), so it is stable for the
/// cluster's life and nothing new is stored. Prints only a public key.
pub fn entitlement_pubkey(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    match args {
        [] => {}
        [h] if h == "--help" || h == "-h" => {
            println!("{USAGE}");
            return Ok(0);
        }
        _ => {
            eprintln!("{USAGE}");
            return Ok(2);
        }
    }
    let key = match crate::addons::pop::controller_key() {
        Ok(k) => k,
        Err(e) => fail(g.json, ExitCode::Generic, "controller_key_unreadable", &e, Some("noo security pki status")),
    };
    let hex = crate::addons::pop::pubkey_hex(&key);
    // Whether the installed entitlement is bound, and to this key.
    let bound = entitlement::installed_token().and_then(|t| entitlement::verify(&t).ok()).map(|e| e.controller_key().map(str::to_string));
    if g.json {
        println!("{}", serde_json::json!({
            "public_key_hex": hex,
            "derived_from": "cluster CA",
            "installed_entitlement_bound": bound.as_ref().map(|b| b.is_some()),
            "installed_entitlement_matches": bound.as_ref().and_then(|b| b.as_ref()).map(|b| b.eq_ignore_ascii_case(&hex)),
        }));
        return Ok(0);
    }
    // The key is the value a script captures: stdout, plain.
    ui::value(&hex);
    println!("{}", ui::note("this controller's add-on key (ed25519, derived from the cluster CA); send it to the vendor to bind the entitlement to this controller"));
    match &bound {
        Some(Some(b)) if b.eq_ignore_ascii_case(&hex) => println!("{}", ui::note("the installed entitlement is bound to this key")),
        Some(Some(b)) => println!("{}", ui::note(&format!(
            "the installed entitlement is bound to another key ({}): add-on pulls through the vendor's registry are refused until it is reissued for this one",
            entitlement::short_key_id(b)))),
        Some(None) => println!("{}", ui::note("the installed entitlement is not bound to a controller key")),
        None => {}
    }
    Ok(0)
}

pub fn entitlement_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let Some(token) = entitlement::installed_token() else {
        if g.json {
            println!("{}", serde_json::json!({"installed": false}));
        } else {
            println!("{}", ui::muted("no entitlement installed: the Intelligent tier is a licensed add-on"));
            ui::guide(&[("noo security entitlement install <token>", "installs the token issued for this deployment")]);
        }
        return Ok(1);
    };
    let show_acceptance = entitlement::verify(&token)
        .ok()
        .map(|ent| terms::latest_for(&terms::log_path(), &ent.id));
    match entitlement::check(&token, now()) {
        Ok(ent) => { print_ent(g, &ent, "valid (features above are what it unlocks)", show_acceptance.as_ref().map(|a| a.as_ref())); Ok(0) }
        Err(e) => {
            match entitlement::verify(&token) {
                Ok(ent) => print_ent(g, &ent, &format!("INVALID — {e}"), show_acceptance.as_ref().map(|a| a.as_ref())),
                Err(_) => fail(g.json, ExitCode::Generic, "entitlement_invalid", &format!("installed token is not usable: {e}"), None),
            }
            Ok(1)
        }
    }
}

#[cfg(test)]
mod enable_tests {
    use super::enable_unlocked;
    use crate::commands::addon_enable::tests::{scratch, Fake, CONFIG};
    use crate::commands::addon_enable::KeyStep;

    /// `entitlement install --enable` mints what the add-on needs before it
    /// declares it on. The rehearsal that filed 1261 took the flag-only
    /// path: the switch said on, the DDL password did not exist, and the
    /// next restart crash-looped the gateway.
    #[test]
    fn install_enable_mints_credentials_and_the_key_before_flipping() {
        let p = scratch("ent-enable");
        let mut ops = Fake { declares_key: true, ..Default::default() };
        let (enabled, failed, _) = enable_unlocked(&p, &["evolve"], &mut ops);
        assert!(failed.is_empty(), "{failed:?}");
        let (_, e) = &enabled[0];
        assert!(
            ops.store.iter().any(|k| k == "NOO_EVOLVE_DDL_PASSWORD"),
            "the entitlement --enable path did not mint the DDL password: calls {:?}",
            ops.calls
        );
        assert!(matches!(e.key, KeyStep::Issued { .. }), "no service key was provisioned: {:?}", ops.calls);
        assert_eq!(ops.calls, ["pin:evolve", "plan:evolve", "mint:evolve", "issue:evolve", "principals"]);
    }

    /// `entitlement install --enable` gives the add-on its own NATS
    /// principal (mint + render + HUP) like `noo addons enable` — once,
    /// AFTER the switch is written (the render reads what is declared on).
    /// The 0.6.6-rc.1 rehearsal: fresh install, intel stayed on the worker
    /// fallback until the next `noo upgrade --stack`.
    #[test]
    fn install_enable_renders_the_addon_nats_principals_after_the_switch() {
        let p = scratch("ent-principals");
        let mut ops = Fake { config: Some(p.clone()), ..Default::default() };
        let (enabled, failed, principals) = enable_unlocked(&p, &["evolve", "trellion-intel"], &mut ops);
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(enabled.len(), 2);
        assert_eq!(
            ops.calls.iter().filter(|c| *c == "principals").count(), 1,
            "reconcile must run exactly once, after every add-on: {:?}", ops.calls
        );
        assert_eq!(ops.calls.last().map(String::as_str), Some("principals"), "{:?}", ops.calls);
        assert!(
            ops.declared_at_reconcile.iter().any(|a| a == "evolve")
                && ops.declared_at_reconcile.iter().any(|a| a == "trellion-intel"),
            "reconcile ran before the switches were written: saw {:?}", ops.declared_at_reconcile
        );
        assert!(matches!(principals, crate::commands::addon_enable::PrincipalStep::Rendered { .. }));
    }

    /// Nothing enabled, nothing to render: a refusal does not touch the bus.
    #[test]
    fn install_enable_refusal_does_not_reconcile() {
        let p = scratch("ent-refuse-principals");
        let mut ops = Fake { declares_key: true, fail_mint: true, ..Default::default() };
        let (_, _, principals) = enable_unlocked(&p, &["evolve"], &mut ops);
        assert!(!ops.calls.iter().any(|c| c == "principals"), "{:?}", ops.calls);
        assert_eq!(principals, crate::commands::addon_enable::PrincipalStep::Unchanged);
    }

    #[test]
    fn install_enable_refusal_leaves_the_flag_off_and_is_reported() {
        let p = scratch("ent-refuse");
        let mut ops = Fake { declares_key: true, fail_mint: true, ..Default::default() };
        let (enabled, failed, _) = enable_unlocked(&p, &["evolve"], &mut ops);
        assert!(enabled.is_empty());
        assert_eq!(failed.len(), 1);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG);
    }
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, terms_at_issue};
    use crate::entitlement::Entitlement;

    #[test]
    fn show_prints_terms_both_ways() {
        let mut e = Entitlement { v: 1, sub: "a".into(), tier: "intelligent".into(), features: vec![], iat: 0, exp: 0, id: "i".into(), bound: None, max_nodes: None, terms: None, addons: Default::default(), cnf: None };
        assert_eq!(terms_at_issue(&e), "none recorded (issued before terms)");
        e.terms = Some("addon-1.0".into());
        assert_eq!(terms_at_issue(&e), "addon-1.0");
    }

    #[test]
    fn show_lists_addon_signers_by_registry_and_key_zero() {
        let mut e = Entitlement { v: 1, sub: "a".into(), tier: "t".into(), features: vec![], iat: 0, exp: 0, id: "i".into(), bound: None, max_nodes: None, terms: None, addons: Default::default(), cnf: None };
        assert!(super::addon_signer_rows(&e).is_empty());
        e.addons.insert("evolve".into(), crate::addon_lock::TrustAnchor { keys: vec!["cd".repeat(32), "ef".repeat(32)], registry: "ghcr.io/example/evolve".into(), pull: None, dev: vec![] });
        let rows = super::addon_signer_rows(&e);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "evolve");
        assert!(rows[0].1.starts_with("ghcr.io/example/evolve  key #0 cdcdcdcdcdcdcdcd…"), "{}", rows[0].1);
        assert!(rows[0].1.contains("+1 older"), "{}", rows[0].1);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(1_800_000_000 / 86_400), (2027, 1, 15));
    }
}
