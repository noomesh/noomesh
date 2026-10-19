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
//!   0. **pin the signed lock** (licensed add-ons only): resolve the add-on's
//!      signed lock for the running stack tag from its own registry package,
//!      verify it against the entitlement's trust anchor, pull its images by
//!      digest and write the pin (`addons.lock`). FIRST, before any credential
//!      is minted: an add-on with no verifiable release for this stack must
//!      refuse with nothing changed. See `crate::addons`.
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
pub(crate) type EnableOutcomes<'a> = (Vec<(&'a str, Enabled)>, Vec<(String, Refusal)>, PrincipalStep);

/// What step 0 did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PinStep {
    /// Not a licensed add-on: it ships with the stack, nothing to pin.
    NotLicensed,
    /// Not pinned, and why (a development checkout pins no stack tag;
    /// `--force` without a licence). The launcher refuses it until pinned.
    Skipped(String),
    Pinned { version: String, stack: String, key_index: usize, pulled: usize },
}

/// The outcome of a completed enable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enabled {
    pub pin: PinStep,
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
    fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal>;
    fn plan_key(&mut self, addon: &str) -> Result<KeyPlan, Refusal>;
    fn mint_credentials(&mut self, addon: &str) -> Result<Vec<String>, Refusal>;
    fn issue_key(&mut self, addon: &str, plan: &KeyPlan) -> Result<(), Refusal>;
    /// After the switch: give every declared add-on its own NATS principal
    /// (mint + render users.conf + HUP noo-nats) — the reconcile `noo addons
    /// enable` and `noo upgrade --stack` run. Without it a fresh install's
    /// add-on presents the worker principal until the next `upgrade --stack`
    /// (the 0.6.6-rc.1 rehearsal: `nats principals !`, empty
    /// /run/secrets/nats_addon_password).
    fn reconcile_principals(&mut self) -> PrincipalStep;
}

/// What the add-on NATS principal reconcile did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrincipalStep {
    /// Every declared add-on principal was already rendered (or no users.conf yet).
    Unchanged,
    Rendered { users: usize, minted: Vec<String>, reloaded: bool },
    /// Best-effort: the add-on falls back to the worker principal for now.
    Failed(String),
}

/// Human line for a [`PrincipalStep`] — the same wording `upgrade --stack` prints.
pub(crate) fn report_principals(step: &PrincipalStep) {
    use crate::ui;
    match step {
        PrincipalStep::Unchanged => {}
        PrincipalStep::Rendered { users, minted, reloaded } => ui::done(&format!(
            "add-on NATS principals rendered ({users} principals{}){}",
            if minted.is_empty() { String::new() } else { format!("; minted {}", minted.join(", ")) },
            if *reloaded { "; noo-nats reloaded" } else { "" }
        )),
        PrincipalStep::Failed(e) => ui::warned(&format!(
            "an add-on's NATS principal was not rendered ({e}) — it presents the worker principal \
             until then; run: noo cluster nats-users render"
        )),
    }
}

pub(crate) fn principals_json(step: &PrincipalStep) -> serde_json::Value {
    match step {
        PrincipalStep::Unchanged => serde_json::json!({"rendered": false}),
        PrincipalStep::Rendered { users, minted, reloaded } =>
            serde_json::json!({"rendered": true, "principals": users, "minted": minted, "nats_reloaded": reloaded}),
        PrincipalStep::Failed(e) => serde_json::json!({"rendered": false, "error": e}),
    }
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
    let pin = ops.pin_lock(addon)?;
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
    Ok(Enabled { pin, minted, key, flipped, config: config.to_path_buf() })
}

// ── the live side ──────────────────────────────────────────────────────

const TIMEOUT: u64 = 15;

/// The production [`EnableOps`]: the systems manifest and sops store under
/// `repo_root()`, and the gateway this CLI talks to, with the credential
/// `noo security service-key provision` uses.
pub(crate) struct Live<'a> {
    pub g: &'a Globals,
    /// `--force`: enabling a licensed add-on with no usable licence. Its lock
    /// cannot be verified without the licence's trust anchor, so step 0 is
    /// skipped (said so); the launcher refuses the add-on until it is pinned.
    pub force: bool,
    /// `--lock <path|https-url>`: a third-party add-on's signed lock handed
    /// over by the operator. Ignored for an add-on the CLI ships.
    pub lock: Option<String>,
}

fn sops_path() -> PathBuf {
    crate::envfile::repo_root().join("secrets/env.sops")
}

/// The remedy for a step-0 refusal, by cause.
pub(crate) fn pin_fix(addon: &str, r: &crate::addons::resolve::Refusal) -> String {
    use crate::addons::resolve::Refusal as R;
    if r.is_auth() {
        return r.auth_fix().to_string();
    }
    match r {
        R::NoEntitlement(_) => "noo security entitlement install <token>".into(),
        R::Untrusted(_) | R::Lock(crate::addon_lock::AddonLockError::BadSignature(_)) if crate::addons::resolve::third_party(addon) => {
            format!("noo addons trust-key {addon} <pubkey> --registry <root>")
        }
        R::Supplied(_) => format!("noo addons enable {addon} --lock <path|https-url>"),
        R::Store(_) => "noo security secrets audit".into(),
        R::NoAnchor => "noo security entitlement show   # a token naming the add-on's signer is needed; ask for a reissue".into(),
        R::Downgrade { .. } => format!("noo addons upgrade {addon} --allow-downgrade"),
        r @ R::Fetch { .. } if crate::addons::resolve::is_not_published(r) => {
            format!("noo addons upgrade {addon} --check   # retry shortly: the vendor signs the lock minutes after a stack release")
        }
        R::Fetch { .. } | R::NotForStack { .. } | R::NoStackLock { .. } | R::BaseRowMissing { .. } => {
            format!("noo addons upgrade {addon} --check   # shows what the add-on publishes for this stack")
        }
        _ => format!("noo addons upgrade {addon}"),
    }
}

impl EnableOps for Live<'_> {
    fn reconcile_principals(&mut self) -> PrincipalStep {
        use crate::commands::nats_users as nu;
        match nu::reconcile_addon_principals(self.g, &crate::envfile::repo_root()) {
            Ok(None) => PrincipalStep::Unchanged,
            Ok(Some(out)) => PrincipalStep::Rendered { users: out.users, minted: out.minted, reloaded: nu::hup_nats() },
            Err(e) => PrincipalStep::Failed(e),
        }
    }
    fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal> {
        use crate::addons::{self, resolve::Refusal as R};
        let third_party = crate::addons::resolve::third_party(addon);
        if !third_party && crate::commands::addons::row(addon).and_then(|r| r.licensed).is_none() {
            return Ok(PinStep::NotLicensed);
        }
        let root = crate::envfile::repo_root();
        let Some(tag) = addons::current_tag(&root) else {
            return Ok(PinStep::Skipped(
                "this install pins no stack tag (a development checkout builds its own images)".into(),
            ));
        };
        let stack_lock = addons::resolve::installed_stack_lock(&root, &tag);
        // A third-party registry is the OPERATOR's choice, not the vendor's: it
        // gets no credential (the vendor token is never sent to it) and no
        // entitlement proxy. Anonymous pulls only.
        let client = if third_party {
            addons::lock_fetch::Client::new(None)
        } else {
            addons::installed_client().map_err(|e| Refusal {
                why: format!("{e}. Nothing was changed"),
                fix: "noo security secrets audit".into(),
            })?
        };
        let ctx = addons::Ctx {
            root: &root,
            tag: &tag,
            stack_lock: stack_lock.as_deref(),
            allow_downgrade: false,
            client: &client,
        };
        if !self.g.json {
            crate::ui::step(&format!("{addon}: resolving its signed lock for stack {tag}"));
        }
        let outcome = if third_party {
            let supplied = match self.lock.as_deref().map(addons::trust::fetch_supplied).transpose() {
                Ok(s) => s,
                Err(e) => {
                    let r = R::Supplied(e);
                    return Err(Refusal { why: format!("{}. Nothing was changed", r.why(addon)), fix: pin_fix(addon, &r) });
                }
            };
            addons::resolve::installed_anchor(addon)
                .and_then(|a| addons::prepare_from(&ctx, addon, &a, supplied, &mut addons::resolve::LiveDocker::new(&root)))
        } else {
            addons::prepare(&ctx, addon, &mut addons::resolve::LiveDocker::new(&root))
        };
        let prepared = match outcome {
            Ok(p) => p,
            Err(r @ (R::NoEntitlement(_) | R::NoAnchor)) if self.force => {
                return Ok(PinStep::Skipped(format!(
                    "{} (--force); the launcher refuses {addon} until `noo addons upgrade {addon}` pins it",
                    r.why(addon)
                )));
            }
            Err(r) => return Err(Refusal { why: format!("{}. Nothing was changed", r.why(addon)), fix: pin_fix(addon, &r) }),
        };
        if !self.g.json {
            crate::ui::step(&format!("{addon}: lock verified, images pulled {}", prepared.via));
        }
        let pin = addons::commit(&root, &prepared, &tag).map_err(|r| Refusal {
            why: format!("{}. The images are pulled; noomesh.yaml is unchanged", r.why(addon)),
            fix: pin_fix(addon, &r),
        })?;
        Ok(PinStep::Pinned { version: pin.version, stack: pin.stack, key_index: pin.key_index, pulled: prepared.pulled })
    }

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
    match &e.pin {
        PinStep::NotLicensed => {}
        PinStep::Skipped(why) => ui::warned(&format!("{addon}: not pinned: {why}")),
        PinStep::Pinned { version, stack, key_index, pulled } => ui::done(&format!(
            "{addon} {version} pinned for stack {stack} (lock signed by add-on key #{key_index}; {pulled} image(s) pulled by digest)"
        )),
    }
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
    let pin = match &e.pin {
        PinStep::NotLicensed => serde_json::json!({ "state": "not_licensed" }),
        PinStep::Skipped(why) => serde_json::json!({ "state": "skipped", "why": why }),
        PinStep::Pinned { version, stack, key_index, pulled } => serde_json::json!({
            "state": "pinned", "version": version, "stack": stack, "key_index": key_index, "pulled": pulled,
        }),
    };
    serde_json::json!({
        "addon": addon,
        "pin": pin,
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
        pub fail_pin: bool,
        pub calls: Vec<String>,
        /// When set, `reconcile_principals` records which add-ons this
        /// config declared on AT THE TIME of the call (the render reads the
        /// declared add-ons, so it must follow the switch).
        pub config: Option<PathBuf>,
        pub declared_at_reconcile: Vec<String>,
    }

    pub(crate) const CREDS: [&str; 2] = ["NOO_EVOLVE_DB_PASSWORD", "NOO_EVOLVE_DDL_PASSWORD"];

    impl EnableOps for Fake {
        fn reconcile_principals(&mut self) -> PrincipalStep {
            self.calls.push("principals".into());
            if let Some(c) = &self.config {
                let text = std::fs::read_to_string(c).unwrap_or_default();
                self.declared_at_reconcile = crate::commands::addons::declared_in(&text)
                    .into_iter()
                    .filter(|(_, on)| *on)
                    .map(|(k, _)| k.to_string())
                    .collect();
            }
            PrincipalStep::Rendered { users: 5, minted: vec!["NATS_TRELLION_INTEL_PASSWORD".into()], reloaded: true }
        }
        fn pin_lock(&mut self, addon: &str) -> Result<PinStep, Refusal> {
            self.calls.push(format!("pin:{addon}"));
            if self.fail_pin {
                return Err(Refusal { why: "no lock for this stack".into(), fix: format!("noo addons upgrade {addon} --check") });
            }
            Ok(PinStep::Pinned { version: "1.0.0".into(), stack: "v0.6.0".into(), key_index: 0, pulled: 1 })
        }
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
        assert_eq!(ops.calls, ["pin:evolve", "plan:evolve", "mint:evolve", "issue:evolve"], "the lock is pinned first and the flag is last");
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
        assert_eq!(ops.calls, ["pin:evolve", "plan:evolve"]);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG);
    }

    /// No verifiable release for this stack: refused before a credential is
    /// minted or a key planned, and noomesh.yaml is untouched.
    #[test]
    fn a_lock_refusal_changes_nothing_at_all() {
        let p = scratch("pinfail");
        let mut ops = Fake { declares_key: true, fail_pin: true, ..Default::default() };
        let r = enable(&p, "evolve", &mut ops).expect_err("must refuse");
        assert!(r.fix.contains("noo addons upgrade evolve --check"), "{r:?}");
        assert_eq!(ops.calls, ["pin:evolve"], "nothing may run after a lock refusal");
        assert!(ops.store.is_empty());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), CONFIG);
    }

    #[test]
    fn pin_remedies_name_real_causes() {
        use crate::addons::resolve::Refusal as R;
        use crate::release_fetch::{FetchClass, FetchError};
        let auth = R::Fetch { reference: "r".into(), stack_tag: "v0.6.4".into(), err: Box::new(FetchError::new(FetchClass::Auth, "x")), via: None };
        assert_eq!(pin_fix("evolve", &auth), crate::addons::resolve::TOKEN_FIX);
        let nf = R::Fetch { reference: "r".into(), stack_tag: "v0.6.4".into(), err: Box::new(FetchError::new(FetchClass::NotFound, "x")), via: None };
        assert!(pin_fix("evolve", &nf).starts_with("noo addons upgrade evolve --check"));
        assert!(pin_fix("evolve", &R::NoEntitlement("none".into())).starts_with("noo security entitlement install"));
        let d = R::Downgrade { pinned: "2".into(), offered: "1".into() };
        assert_eq!(pin_fix("evolve", &d), "noo addons upgrade evolve --allow-downgrade");
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
