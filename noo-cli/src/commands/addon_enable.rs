// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Switching an add-on ON: the one path `noo addons enable <name>` and
//! `noo security entitlement install <token> --enable` both take
//!
//! ## What went wrong
//!
//! Both commands used to flip `addons.<name>` in noomesh.yaml and nothing
//! else. On the stack-v0.2.80 rehearsal (evolve, standalone sandbox) the next
//! `noo stack restart --force` crash-looped the gateway: evolve was declared
//! on, the broker needs `NOO_EVOLVE_DDL_PASSWORD` to create the role, and only
//! `noo systems enable` mints it. After that was fixed by hand, `cluster
//! verify` failed on `service keys`, because nothing had provisioned the
//! add-on's gateway key either. Three commands claimed to switch the add-on
//! on and none of them produced a runnable add-on.
//!
//! ## The order, and why the flag is last
//!
//!   1. **plan the key** (read-only): does the add-on's overlay declare a key
//!      (`x-noo-addon`), and does the gateway already hold an active one for
//!      that consumer? Refuses before anything changes when the gateway
//!      cannot answer, when this install has no encrypted store to keep a new
//!      key in, or when the gateway would refuse a declared scope word.
//!   2. **mint credentials**: [`systems::mint_credentials`], the same
//!      function `noo systems enable` runs. Mint-if-absent, never rotate.
//!   3. **issue the key** when step 1 found none: mint, store, and revoke
//!      what was minted if the store write fails. An existing key is never
//!      rotated — that is `noo security service-key provision`'s job, with
//!      its diff and its proof of use.
//!   4. **flip** `addons.<name>` — last, so any refusal above leaves
//!      noomesh.yaml exactly as it was. A switch that says on over missing
//!      credentials is the state that took the gateway down.
//!
//! Nothing is restarted: which containers run changes on the operator's next
//! `noo stack restart --force`, which then finds the credentials and the key
//! waiting.
//!
//! ## Why no second prompt for the key
//!
//! `service-key provision` asks y/N before granting, because there the
//! operator is granting a key to something that is already running and the
//! words are the whole decision. Here the decision is "run this add-on", and
//! the add-on cannot run without the grant its release declares: declining
//! the key while accepting the add-on buys a container that is refused on
//! every call. So enabling IS the consent — the same call the onboard wizard
//! made in `provision_service_keys` — and the request is still SHOWN, word by
//! word with the route each opens, from the gateway's own listing, before the
//! key is minted. The declaration is the one embedded in this binary, never a
//! hand-edited `~/.noo` overlay, so the request cannot be widened on disk.
//! `--scopes` overrides and rotations stay with `provision`.
//!
//! Values never pass through here: credentials are minted inside
//! `secrets::mint_missing`, and the gateway's raw key goes straight from the
//! response into `store_provisioned`.

use std::path::{Path, PathBuf};

use crate::commands::secrets::{self, ProvisionRequest, ProvisionTargets};
use crate::commands::systems;
use crate::Globals;

/// Why an enable was refused, and the one command that completes it. The
/// switch is never flipped when one of these is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub why: String,
    pub fix: String,
}

/// What step 1 found about the add-on's gateway key.
#[derive(Debug, Clone)]
pub(crate) enum KeyPlan {
    /// The add-on's overlay declares no key (voice, identity).
    NotDeclared,
    /// The gateway already holds an active key for the consumer: left alone.
    Present { consumer: String },
    /// No active key: step 3 mints one with the declared request.
    Issue { targets: ProvisionTargets, request: Box<ProvisionRequest>, routes_known: bool },
}

/// What step 3 did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyStep {
    NotDeclared,
    AlreadyActive { consumer: String },
    Issued { consumer: String, secret_key: String },
}

/// Per-add-on results of enabling several (`entitlement install --enable`):
/// what was enabled, and what was refused with its fix.
pub(crate) type EnableOutcomes<'a> = (Vec<(&'a str, Enabled)>, Vec<(String, Refusal)>);

/// The outcome of a completed enable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enabled {
    /// Credential NAMES minted in step 2 (empty when all were present).
    pub minted: Vec<String>,
    pub key: KeyStep,
    /// False when `addons.<name>` already said true (nothing was written).
    pub flipped: bool,
    pub config: PathBuf,
}

/// The three side effects, behind a seam so the ORDER — and the promise that
/// a refusal leaves noomesh.yaml untouched — is testable without a gateway or
/// a sops key. [`Live`] is the only production implementation.
pub(crate) trait EnableOps {
    fn plan_key(&mut self, addon: &str) -> Result<KeyPlan, Refusal>;
    fn mint_credentials(&mut self, addon: &str) -> Result<Vec<String>, Refusal>;
    fn issue_key(&mut self, addon: &str, plan: &KeyPlan) -> Result<(), Refusal>;
}

/// Is `addons.<name>` already declared true in `config`?
fn declared_on(config: &Path, name: &str) -> bool {
    std::fs::read_to_string(config)
        .map(|t| crate::commands::addons::declared_in(&t).get(name) == Some(&true))
        .unwrap_or(false)
}

/// Enable `addon`: plan the key, mint credentials, issue the key, flip the
/// switch — in that order, stopping at the first refusal with noomesh.yaml
/// untouched. Idempotent: a second run mints nothing, issues nothing and
/// writes nothing.
pub(crate) fn enable(config: &Path, addon: &str, ops: &mut dyn EnableOps) -> Result<Enabled, Refusal> {
    let plan = ops.plan_key(addon)?;
    let minted = ops.mint_credentials(addon)?;
    let key = match &plan {
        KeyPlan::NotDeclared => KeyStep::NotDeclared,
        KeyPlan::Present { consumer } => KeyStep::AlreadyActive { consumer: consumer.clone() },
        KeyPlan::Issue { targets, .. } => {
            ops.issue_key(addon, &plan)?;
            KeyStep::Issued { consumer: targets.consumer.clone(), secret_key: targets.secret_key.clone() }
        }
    };
    let flipped = if declared_on(config, addon) {
        false
    } else {
        crate::commands::addons::write_addon_at(config, addon, true).map_err(|e| Refusal {
            why: format!("{e} (credentials and key, if any, are in place)"),
            fix: format!("noo addons enable {addon}"),
        })?;
        true
    };
    Ok(Enabled { minted, key, flipped, config: config.to_path_buf() })
}

// ── the live side ──────────────────────────────────────────────────────

const TIMEOUT: u64 = 15;

/// The production [`EnableOps`]: the systems manifest and sops store under
/// `repo_root()`, and the gateway this CLI talks to, with the credential
/// `noo security service-key provision` uses.
pub(crate) struct Live<'a> {
    pub g: &'a Globals,
}

fn sops_path() -> PathBuf {
    crate::envfile::repo_root().join("secrets/env.sops")
}

impl EnableOps for Live<'_> {
    fn plan_key(&mut self, addon: &str) -> Result<KeyPlan, Refusal> {
        let Some(targets) = secrets::addon_decl(addon).and_then(|_| secrets::provision_targets(addon)) else {
            return Ok(KeyPlan::NotDeclared);
        };
        let listing = crate::http::get_json_try(self.g, "/api/security/service-keys", true, TIMEOUT).map_err(|e| Refusal {
            why: format!(
                "{addon} needs a gateway key ({}), and the gateway could not list its keys ({e}). \
                 Nothing was changed",
                targets.consumer
            ),
            // `stack start` rather than `status`: the launcher names any
            // missing system credential itself, which is the one way a
            // gateway is down BECAUSE of an earlier flag-only enable.
            fix: format!("noo stack start   # bring the gateway up, then: noo addons enable {addon}"),
        })?;
        let active = listing["keys"].as_array().is_some_and(|ks| {
            ks.iter().any(|k| {
                k["consumer"].as_str() == Some(targets.consumer.as_str()) && k["active"].as_bool().unwrap_or(false)
            })
        });
        if active {
            return Ok(KeyPlan::Present { consumer: targets.consumer });
        }
        if !sops_path().exists() {
            return Err(Refusal {
                why: format!(
                    "{addon}'s gateway key is kept in the encrypted store, and {} does not exist. \
                     Nothing was changed",
                    sops_path().display()
                ),
                fix: "noo onboard --only secrets".into(),
            });
        }
        let vocab = crate::http::get_json_try(self.g, "/api/security/service-keys/scopes", true, TIMEOUT).ok();
        let request = secrets::provision_request(&targets.consumer, &[], vocab.as_ref(), None);
        if !request.refused.is_empty() {
            return Err(Refusal {
                why: format!(
                    "{} asks for {}, which this gateway does not issue. Nothing was changed",
                    targets.overlay.as_deref().unwrap_or(addon),
                    request.refused.join(", ")
                ),
                fix: "noo upgrade --stack   # the gateway and the add-on's declaration are from different releases".into(),
            });
        }
        Ok(KeyPlan::Issue { targets, request: Box::new(request), routes_known: vocab.is_some() })
    }

    fn mint_credentials(&mut self, addon: &str) -> Result<Vec<String>, Refusal> {
        let path = systems::manifest_path();
        let Ok(text) = std::fs::read_to_string(&path) else { return Ok(Vec::new()) };
        let manifest = systems::parse_systems(&text).map_err(|e| Refusal {
            why: format!("{}: {e}. Nothing was changed", path.display()),
            fix: "noo systems status".into(),
        })?;
        let Some(entry) = manifest.get(addon) else { return Ok(Vec::new()) };
        systems::mint_credentials(entry, &sops_path()).map(|(minted, _backup)| minted).map_err(|e| Refusal {
            why: format!(
                "could not mint {}'s credentials ({}): {e}. The switch was not flipped",
                addon,
                systems::required_keys(entry).join(", ")
            ),
            fix: format!("noo systems enable {addon}   # then: noo addons enable {addon}"),
        })
    }

    fn issue_key(&mut self, addon: &str, plan: &KeyPlan) -> Result<(), Refusal> {
        let KeyPlan::Issue { targets, request, routes_known } = plan else { return Ok(()) };
        if !self.g.json {
            crate::commands::security::render_provision_request(
                targets,
                request,
                secrets::MintMode::Issue,
                *routes_known,
                None,
            );
        }
        let scopes = secrets::provisioned_scopes(&targets.consumer, &[]);
        let fix = format!("noo security service-key provision {addon}   # then: noo addons enable {addon}");
        let minted = crate::http::post_json_try(
            self.g,
            "/api/security/service-keys",
            &serde_json::json!({ "consumer": targets.consumer, "scopes": scopes }),
            true,
            TIMEOUT,
        )
        .map_err(|e| Refusal {
            why: format!("the gateway did not mint {}'s key ({e}). The switch was not flipped", targets.consumer),
            fix: fix.clone(),
        })?;
        let Some(raw) = minted["key"].as_str() else {
            return Err(Refusal {
                why: format!("the gateway returned no key for {}. The switch was not flipped", targets.consumer),
                fix,
            });
        };
        if let Err(why) = secrets::store_provisioned(&targets.secret_key, raw) {
            // An active row nobody holds reads as "installed, not yet called":
            // revoke it so the listing tells the truth (provision's rule).
            let _ = crate::http::post_json_try(
                self.g,
                &format!("/api/security/service-keys/{}/revoke", targets.consumer),
                &serde_json::json!({}),
                true,
                TIMEOUT,
            );
            return Err(Refusal {
                why: format!(
                    "{}'s key was minted but could not be stored ({why}) — revoked, so none is left \
                     orphaned. The switch was not flipped",
                    targets.consumer
                ),
                fix,
            });
        }
        Ok(())
    }
}

/// The lines an enable prints on success (non-JSON), shared by both callers.
pub(crate) fn report(addon: &str, e: &Enabled) {
    use crate::ui;
    if e.minted.is_empty() {
        ui::done(&format!("{addon}: credentials present — nothing minted"));
    } else {
        ui::done(&format!("{addon}: minted {} into the encrypted store", e.minted.join(", ")));
    }
    match &e.key {
        KeyStep::NotDeclared => {}
        KeyStep::AlreadyActive { consumer } => ui::done(&format!("{consumer} already holds an active key — left alone")),
        KeyStep::Issued { consumer, secret_key } => {
            ui::done(&format!("{consumer}: key minted and stored as {secret_key}"))
        }
    }
    if e.flipped {
        ui::done(&format!("{addon} declared on in {}", e.config.display()));
    } else {
        ui::done(&format!("{addon} was already declared on in {} — nothing changed there", e.config.display()));
    }
}

/// The JSON object an enable contributes, shared by both callers.
pub(crate) fn report_json(addon: &str, e: &Enabled) -> serde_json::Value {
    let key = match &e.key {
        KeyStep::NotDeclared => serde_json::json!({ "declared": false }),
        KeyStep::AlreadyActive { consumer } => serde_json::json!({ "consumer": consumer, "state": "already_active" }),
        KeyStep::Issued { consumer, secret_key } => {
            serde_json::json!({ "consumer": consumer, "state": "issued", "stored_as": secret_key })
        }
    };
    serde_json::json!({
        "addon": addon,
        "credentials_minted": e.minted,
        "service_key": key,
        "flipped": e.flipped,
        "config": e.config.display().to_string(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake that mirrors the live semantics: credentials are minted only
    /// when absent, a key is planned only when none is active, and each
    /// step can be told to fail. It records every call so the ORDER is
    /// asserted, not assumed.
    #[derive(Default)]
    pub(crate) struct Fake {
        pub store: Vec<String>,
        pub active_key: bool,
        pub declares_key: bool,
        pub fail_plan: bool,
        pub fail_mint: bool,
        pub fail_issue: bool,
        pub calls: Vec<String>,
    }

    pub(crate) const CREDS: [&str; 2] = ["NOO_EVOLVE_DB_PASSWORD", "NOO_EVOLVE_DDL_PASSWORD"];

    impl EnableOps for Fake {
        fn plan_key(&mut self, addon: &str) -> Result<KeyPlan, Refusal> {
            self.calls.push(format!("plan:{addon}"));
            if self.fail_plan {
                return Err(Refusal { why: "gateway down".into(), fix: "noo stack status".into() });
            }
            if !self.declares_key {
                return Ok(KeyPlan::NotDeclared);
            }
            let targets = ProvisionTargets {
                consumer: format!("svc:{addon}"),
                secret_key: format!("NOO_SVC_KEY_{}", addon.to_ascii_uppercase()),
                containers: vec![format!("noo-{addon}")],
                addon: Some(addon.into()),
                overlay: None,
            };
            if self.active_key {
                return Ok(KeyPlan::Present { consumer: targets.consumer });
            }
            let request = secrets::provision_request(&targets.consumer, &[], None, None);
            Ok(KeyPlan::Issue { targets, request: Box::new(request), routes_known: false })
        }
        fn mint_credentials(&mut self, addon: &str) -> Result<Vec<String>, Refusal> {
            self.calls.push(format!("mint:{addon}"));
            if self.fail_mint {
                return Err(Refusal { why: "sops refused".into(), fix: format!("noo systems enable {addon}") });
            }
            let mut minted = Vec::new();
            for k in CREDS {
                if !self.store.iter().any(|s| s == k) {
                    self.store.push(k.into());
                    minted.push(k.to_string());
                }
            }
            Ok(minted)
        }
        fn issue_key(&mut self, addon: &str, _plan: &KeyPlan) -> Result<(), Refusal> {
            self.calls.push(format!("issue:{addon}"));
            if self.fail_issue {
                return Err(Refusal { why: "mint 500".into(), fix: "provision".into() });
            }
            self.active_key = true;
            Ok(())
        }
    }

    pub(crate) const CONFIG: &str = "\
# Runtime config.
addons:
  trellion: true
  evolve: false  # licensed
";

    pub(crate) fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("noo-addon-enable-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("noomesh.yaml");
        std::fs::write(&p, CONFIG).unwrap();
        p
    }

    fn evolve_on(p: &Path) -> bool {
        crate::commands::addons::declared_in(&std::fs::read_to_string(p).unwrap()).get("evolve") == Some(&true)
    }

    #[test]
    fn enabling_mints_the_missing_ddl_password_and_the_service_key_then_flips() {
        let p = scratch("mints");
        let mut ops = Fake { declares_key: true, ..Default::default() };
        let e = enable(&p, "evolve", &mut ops).expect("enable");
        assert!(e.minted.contains(&"NOO_EVOLVE_DDL_PASSWORD".to_string()), "{e:?}");
        assert_eq!(
            e.key,
            KeyStep::Issued { consumer: "svc:evolve".into(), secret_key: "NOO_SVC_KEY_EVOLVE".into() }
        );
        assert!(e.flipped && evolve_on(&p));
        assert_eq!(ops.calls, ["plan:evolve", "mint:evolve", "issue:evolve"], "the flag is last, after both mints");
        assert!(std::fs::read_to_string(&p).unwrap().contains("# licensed"), "comments survive the flip");
    }

    #[test]
    fn a_second_enable_is_a_no_op() {
        let p = scratch("twice");
        let mut ops = Fake { declares_key: true, ..Default::default() };
        enable(&p, "evolve", &mut ops).expect("first");
        let after_first = std::fs::read_to_string(&p).unwrap();
        ops.calls.clear();
        let e = enable(&p, "evolve", &mut ops).expect("second");
        assert!(e.minted.is_empty(), "nothing is re-minted: {e:?}");
        assert_eq!(e.key, KeyStep::AlreadyActive { consumer: "svc:evolve".into() }, "an active key is never rotated");
        assert!(!e.flipped);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), after_first, "the file is not rewritten");
        assert!(!ops.calls.iter().any(|c| c.starts_with("issue:")), "{:?}", ops.calls);
    }

    #[test]
    fn a_mint_failure_leaves_noomesh_yaml_unchanged() {
        let p = scratch("mintfail");
        let mut ops = Fake { declares_key: true, fail_mint: true, ..Default::default() };
        let r = enable(&p, "evolve", &mut ops).expect_err("must refuse");
        assert!(r.fix.contains("noo systems enable evolve"), "{r:?}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG, "the switch was flipped over a failed mint");
        assert!(!ops.calls.iter().any(|c| c.starts_with("issue:")), "no key for an add-on left off");
    }

    #[test]
    fn a_key_failure_leaves_noomesh_yaml_unchanged() {
        let p = scratch("keyfail");
        let mut ops = Fake { declares_key: true, fail_issue: true, ..Default::default() };
        enable(&p, "evolve", &mut ops).expect_err("must refuse");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG);
    }

    #[test]
    fn an_unreachable_gateway_refuses_before_anything_is_minted() {
        let p = scratch("gwdown");
        let mut ops = Fake { declares_key: true, fail_plan: true, ..Default::default() };
        enable(&p, "evolve", &mut ops).expect_err("must refuse");
        assert!(ops.store.is_empty(), "credentials were minted for an enable that could not finish");
        assert_eq!(ops.calls, ["plan:evolve"]);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG);
    }

    #[test]
    fn an_addon_with_no_declared_key_still_mints_and_flips() {
        let p = scratch("nokey");
        let mut ops = Fake::default();
        let e = enable(&p, "evolve", &mut ops).expect("enable");
        assert_eq!(e.key, KeyStep::NotDeclared);
        assert!(e.flipped && evolve_on(&p));
    }

    /// The real declaration this path provisions from: evolve's overlay
    /// declares a key, so enabling evolve is never a flag-only change.
    #[test]
    fn evolve_declares_the_key_enabling_provisions() {
        let t = secrets::provision_targets("evolve").expect("evolve's x-noo-addon is embedded");
        assert_eq!(t.consumer, "svc:evolve");
        assert_eq!(t.secret_key, "NOO_SVC_KEY_EVOLVE");
        assert!(secrets::addon_decl("evolve").is_some());
        assert!(secrets::addon_decl("voice").is_none(), "voice calls no gateway route and declares no key");
    }
}
