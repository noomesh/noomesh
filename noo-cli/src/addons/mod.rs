// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Licensed add-ons on the controller: their signed locks, the pins those
//! locks produce, and the images pulled by digest. The verbs live in
//! `commands::addon_pins`; this is the machinery they share with
//! `noo upgrade --stack` and the launcher's reader.

pub mod check;
pub mod decls;
pub mod guards;
pub mod lock_fetch;
pub mod pins;
pub mod pop;
pub mod provisioned;
pub mod resolve;
pub mod resources;
pub mod trust;

use std::path::Path;

use crate::addon_lock::{TrustAnchor, VerifiedLock};

use lock_fetch::{Credential, Fetched};
use resolve::{Docker, Refusal, Want};

/// The stack tag this install runs: `NOO_IMAGE_TAG` in its `.env`. `None`
/// on a development checkout that pins no tag (it builds its images).
pub fn current_tag(root: &Path) -> Option<String> {
    let t = crate::onboard::env::read_env_key(&root.join(".env"), "NOO_IMAGE_TAG");
    let t = t.trim().trim_matches('"').trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// The licensed add-ons declared on in `root`'s noomesh.yaml (each one's own
/// default when silent). An unreadable or unparseable file is an error, never
/// "no add-ons": that would skip every hold and every check.
pub fn licensed_on(root: &Path) -> Result<Vec<&'static str>, String> {
    let declared = crate::commands::addons::declared_map_at(&root.join("noomesh.yaml"))?;
    let mut on: Vec<&'static str> = crate::commands::addons::ADDON_ROWS
        .iter()
        .filter(|r| r.licensed.is_some())
        .filter(|r| crate::commands::addons::resolve(declared.get(r.key).copied(), r.default_on))
        .map(|r| r.key)
        .collect();
    // Third-party add-ons: declared on AND given a trusted key by the
    // operator (`noo addons trust-key`). A name with no trust is not
    // guessed at here; the launcher refuses an enabled add-on it cannot
    // verify, and `noo addons upgrade <name>` says what is missing.
    let text = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap_or_default();
    for n in trust::trusted_names(&text) {
        if declared.get(&n).copied() == Some(true) {
            on.push(Box::leak(n.into_boxed_str()));
        }
    }
    Ok(on)
}

/// A lock that passed every check and whose images are local, ready to be
/// recorded.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub addon: String,
    pub verified: VerifiedLock,
    pub fetched: Fetched,
    pub pulled: usize,
    /// The proxy root the images were pulled from (`None` = the registry).
    pub pulled_from: Option<String>,
    /// Which host and credential the lock and images came through.
    pub via: String,
}

/// The lock client for the verbs that pull, with the credentials the route
/// selector needs (`lock_fetch::Route`): the vendor token when the store
/// holds one, and only then nothing else; otherwise the entitlement
/// credential for anchors that name a `pull` root.
pub fn installed_client() -> Result<lock_fetch::Client, String> {
    let cred = lock_fetch::installed_credential()?;
    let proxy = if cred.is_some() { None } else { lock_fetch::installed_proxy_auth()? };
    Ok(lock_fetch::Client::new(cred).with_proxy(proxy))
}

/// The client for third-party add-on `addon`, trusted for `anchor`: the vendor
/// token is never in it. When the trust entry records a pull credential bound to
/// this anchor's registry root, the client carries it for that root only; the
/// store is read just then. A recorded credential the store cannot produce is an
/// error, never an anonymous pull that fails later with a bare "unauthorized".
pub fn third_party_client(addon: &str, anchor: &TrustAnchor) -> Result<lock_fetch::Client, Refusal> {
    let recorded = trust::installed_credential_root(addon)
        .map_err(|e| Refusal::Untrusted(format!("the trust list could not be read to resolve {addon}: {e}")))?;
    let bound = bound_for(addon, anchor, recorded.as_deref(), &|root| lock_fetch::stored_bound(addon, root)).map_err(Refusal::Store)?;
    Ok(lock_fetch::Client::new(None).with_bound(bound))
}

/// [`third_party_client`]'s decision over its inputs: the root the trust entry
/// records a credential for, and a reader of the store. A record bound to some
/// other root than the one trusted now (the registry was re-trusted since) is
/// not used.
fn bound_for(
    addon: &str,
    anchor: &TrustAnchor,
    recorded: Option<&str>,
    read: &dyn Fn(&str) -> Result<Option<lock_fetch::Bound>, String>,
) -> Result<Option<lock_fetch::Bound>, String> {
    let Some(root) = recorded.map(str::trim).filter(|r| *r == anchor.registry.trim()) else { return Ok(None) };
    match read(root)? {
        Some(b) => Ok(Some(b)),
        None => Err(format!(
            "noomesh.yaml records a registry credential for {addon} ({root}), and the encrypted store holds none ({}). \
             Register it again: `noo addons registry-login {addon} --registry {root}`",
            lock_fetch::cred_key(addon)
        )),
    }
}

/// Where and against what one or more add-ons are resolved.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub tag: &'a str,
    /// The verified stack lock text for `tag`, when one is published.
    pub stack_lock: Option<&'a str>,
    pub allow_downgrade: bool,
    pub client: &'a lock_fetch::Client,
}

/// Steps 1-7 for one add-on against `ctx.tag`: anchor, fetch, verify, stack
/// membership, base, downgrade, pull. Writes nothing.
pub fn prepare(ctx: &Ctx, addon: &str, docker: &mut dyn Docker) -> Result<Prepared, Refusal> {
    let anchor = resolve::installed_anchor(addon)?;
    prepare_from(ctx, addon, &anchor, None, docker)
}

/// Steps 2-6 over a lock that is either `supplied` (a third-party lock the
/// operator handed over with `--lock`) or fetched from the anchor's registry.
/// Pure over its inputs apart from the fetch.
pub fn resolve_lock(
    client: &lock_fetch::Client,
    anchor: &TrustAnchor,
    want: &Want,
    supplied: Option<Fetched>,
) -> Result<(VerifiedLock, Fetched), Refusal> {
    match supplied {
        Some(f) => resolve::check(&f, anchor, want).map(|v| (v, f)),
        None => resolve::fetch_and_check(client, anchor, want),
    }
}

/// [`prepare`] against an explicit anchor and, optionally, a supplied lock.
/// A third-party add-on goes through here with the anchor the operator
/// trusted and its own client ([`third_party_client`]).
pub fn prepare_from(
    ctx: &Ctx,
    addon: &str,
    anchor: &TrustAnchor,
    supplied: Option<Fetched>,
    docker: &mut dyn Docker,
) -> Result<Prepared, Refusal> {
    // Whoever calls this, a third-party add-on is fetched with its OWN client:
    // the vendor's registry token must never reach a registry the operator
    // named, and the add-on's credential goes to its trusted root only.
    if resolve::third_party(addon) {
        let own = third_party_client(addon, anchor)?;
        return prepare_with(ctx, addon, anchor, supplied, docker, &own);
    }
    prepare_with(ctx, addon, anchor, supplied, docker, ctx.client)
}

/// [`prepare_from`] with the client chosen by the caller.
fn prepare_with(
    ctx: &Ctx,
    addon: &str,
    anchor: &TrustAnchor,
    supplied: Option<Fetched>,
    docker: &mut dyn Docker,
    client: &lock_fetch::Client,
) -> Result<Prepared, Refusal> {
    let anchor = anchor.clone();
    let ctx = &Ctx {
        root: ctx.root,
        tag: ctx.tag,
        stack_lock: ctx.stack_lock,
        allow_downgrade: ctx.allow_downgrade,
        client,
    };
    let current = pins::read(ctx.root).map_err(Refusal::Write)?;
    let pin = current.get(addon);
    let pinned = pin.map(|p| p.version.clone());
    let want = Want {
        addon,
        stack_tag: ctx.tag,
        stack_lock: ctx.stack_lock,
        pinned: pinned.as_deref(),
        pin,
        allow_downgrade: ctx.allow_downgrade,
    };
    let route = ctx.client.route(&anchor).map_err(Refusal::Route)?;
    let (verified, fetched) = resolve_lock(ctx.client, &anchor, &want, supplied)?;
    // What the overlay takes from core, and (third-party) its name: refused
    // here, before an image is pulled or a pin written (`guards`).
    guards::guard_install(ctx.root, addon, &fetched.files).map_err(Refusal::Decl)?;
    // The gateway refuses a bad routes.json whole at load: refuse it here, by its own rules.
    check::refuse_bad_routes(addon, &fetched.files)?;
    resolve::require_bundle(&verified, ctx.tag)?;
    let mut cred = || -> Result<Option<Credential>, String> {
        ctx.client.docker_credential(&route).map_err(|e| format!("{}: {}", route.host(), e.summary()))
    };
    let pulled = resolve::pull_images(docker, &verified, &route, &mut cred).map_err(|r| match r {
        // Fail loud: a third-party pull refused for access names the verb, and
        // tells "no credential set" from "the credential was refused".
        Refusal::Pull(e) if resolve::third_party(addon) && resolve::pull_unauthorized(&e) => Refusal::PullAuth {
            root: route.root().to_string(),
            credential_set: ctx.client.presents_bound(&route),
            detail: e,
        },
        r => r,
    })?;
    Ok(Prepared {
        addon: addon.to_string(),
        verified,
        fetched,
        pulled,
        pulled_from: route.pulled_from(),
        via: ctx.client.describe(&route),
    })
}

/// Step 8 for a prepared add-on.
pub fn commit(root: &Path, p: &Prepared, tag: &str) -> Result<pins::Pin, Refusal> {
    resolve::record(root, &p.addon, &p.verified, &p.fetched, tag, p.pulled_from.clone())
}
