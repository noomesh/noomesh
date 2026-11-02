// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The admin side of add-on access (noomesh-internal f99): read and change
//! who may use each feature an add-on declares, see what one person may use,
//! and name the super admins. The console's "Add-on access" page and the CLI
//! use these routes; there is no second write path.
//!
//! - `GET  /api/addons/{addon}/access`: the add-on's features, every setting,
//!   and the super admins. Operator or above.
//! - `PUT  /api/addons/{addon}/access`: `{feature, subject, value: on|off|inherit,
//!   reason?}`. Admin; a setting that covers an admin is a super admin's, and
//!   turning one off takes a reason (`addon_access::check_change`). Audited
//!   (`addon_access_set`).
//! - `GET  /api/security/users/{username}/addon-access`: every declared
//!   feature of every add-on, on or off for that account, and the setting
//!   that decided it. Operator or above.
//! - `PUT  /api/security/users/{username}/super-admin`: `{on, reason,
//!   password}`. A super admin only, re-entering their own password; never an
//!   agent or door token; never leaves the install without a super admin.
//!   Audited (`super_admin_set`).
//!
//! Enforcement on the add-on's own routes is not here: it is the one check
//! `addon_access::decide` feeds (f99 PR 3).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{AppError, AppResult};
use crate::addon_access::{self, Change, Facts, SetTo, Subject};
use crate::audit::{AuditEvent, AuditKind};
use crate::auth::{account_of, Role};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/addons/{addon}/access", get(access_get).put(access_set))
        .route("/api/security/users/{username}/addon-access", get(person_view))
        .route("/api/security/users/{username}/super-admin", put(super_admin_set))
}

/// A write takes effect on the next request: reload the settings every check
/// reads. A failed reload leaves the periodic one to catch up, and says so.
async fn reload_now(state: &AppState) {
    if let Err(e) = addon_access::reload(&state.db).await {
        tracing::warn!(error = %e, "addon_access_reload_after_write_failed: the change applies within the periodic re-read");
    }
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Internal(format!("database: {e}"))
}

/// The registered add-on's manifest, or 404 naming why.
fn manifest_of(addon: &str) -> Result<crate::addon_proxy::AddonManifest, AppError> {
    crate::addon_registry::get(addon)
        .map(|e| e.manifest().clone())
        .ok_or_else(|| AppError::NotFound(format!("add-on {addon:?} is not registered on this gateway (`noo addons list`)")))
}

/// Does `feature` open a write route the add-on did not declare `owner_scoped`?
fn has_unscoped_write(m: &crate::addon_proxy::AddonManifest, feature: &str) -> bool {
    m.routes.iter().any(|r| {
        !r.internal
            && r.feature.as_deref() == Some(feature)
            && addon_manifest::is_write_method(&r.method)
            && !r.owner_scoped
    })
}

/// The facts `decide` needs about an account, read from the database.
async fn facts_of(state: &AppState, account: &str, super_admins: &[String]) -> Result<Facts, AppError> {
    let role = crate::repo::users::enabled_role(&state.db, account)
        .await
        .map_err(db_err)?
        .and_then(|r| r.parse::<Role>().ok());
    let teams = crate::repo::kb_grants::get_roles(&state.db, account)
        .await
        .map_err(db_err)?
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r.as_str().and_then(|s| s.strip_prefix("team:")).map(str::to_string))
        .collect();
    Ok(Facts {
        account: Some(account.to_string()),
        key: None,
        role,
        teams,
        super_admin: super_admins.iter().any(|s| s == account),
    })
}

/// Is the caller a super admin? `super_admins` already counts every enabled
/// admin while no account is flagged; an empty list (no admin row at all, the
/// env bootstrap admin) lets an admin act as one, so the install can never be
/// left with nobody able to change admin settings.
fn acts_as_super_admin(account: &str, super_admins: &[String]) -> bool {
    super_admins.is_empty() || super_admins.iter().any(|s| s == account)
}

async fn access_get(
    State(state): State<Arc<AppState>>,
    _op: crate::authz::Operator,
    Path(addon): Path<String>,
) -> AppResult {
    let m = manifest_of(&addon)?;
    let settings: Vec<_> = crate::repo::addon_access::list(&state.db)
        .await
        .map_err(db_err)?
        .into_iter()
        .filter(|r| r.addon == addon)
        .collect();
    let declared: Vec<&str> = m.features.iter().map(|f| f.name.as_str()).collect();
    let features: Vec<Value> = m
        .features
        .iter()
        .map(|f| {
            let routes: Vec<&str> = m
                .routes
                .iter()
                .filter(|r| !r.internal && r.feature.as_deref() == Some(f.name.as_str()))
                .map(|r| r.name.as_str())
                .collect();
            json!({
                "name": f.name, "title": f.title, "description": f.description, "suggested": f.suggested,
                "delegate": f.delegate, "routes": routes,
                "ui": m.ui.as_ref().and_then(|u| u.feature.as_deref()) == Some(f.name.as_str()),
                "has_unscoped_write": has_unscoped_write(&m, &f.name),
            })
        })
        .collect();
    // A setting for a feature the add-on no longer declares opens nothing; it
    // is kept (a downgrade then upgrade does not lose it) and shown as stale.
    let stale: Vec<&str> = settings
        .iter()
        .filter(|r| !declared.contains(&r.feature.as_str()))
        .map(|r| r.feature.as_str())
        .collect();
    let super_admins = crate::repo::addon_access::super_admins(&state.db).await.map_err(db_err)?;
    Ok(Json(json!({
        "addon": addon,
        "legacy": m.features.is_empty(),
        "features": features,
        "settings": settings,
        "stale_features": stale,
        "super_admins": super_admins,
    })))
}

#[derive(Deserialize)]
struct SetBody {
    feature: String,
    subject: String,
    value: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn access_set(
    State(state): State<Arc<AppState>>,
    admin: crate::authz::Admin,
    Path(addon): Path<String>,
    Json(body): Json<SetBody>,
) -> AppResult {
    let by = account_of(admin.sub()).to_string();
    let m = manifest_of(&addon)?;
    if m.features.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{addon} declares no features yet: its routes keep their own min_role until it ships a manifest with features"
        )));
    }
    let feature = body.feature.trim();
    if m.feature(feature).is_none() {
        return Err(AppError::BadRequest(format!(
            "{addon} declares no feature {feature:?} (GET /api/addons/{addon}/access lists them)"
        )));
    }
    let subject = Subject::parse(body.subject.trim()).map_err(AppError::BadRequest)?;
    let value = SetTo::parse(body.value.trim()).map_err(AppError::BadRequest)?;
    let covers_admin = match &subject {
        Subject::Role(r) => *r == Role::Admin,
        Subject::User(u) => {
            let role = crate::repo::users::role_of(&state.db, u).await.map_err(db_err)?;
            let Some(role) = role else {
                return Err(AppError::BadRequest(format!("no account {u:?}")));
            };
            role == "admin"
        }
        Subject::Team(t) => {
            if !crate::repo::kb_grants::team_exists(&state.db, t).await.map_err(db_err)? {
                return Err(AppError::BadRequest(format!("no team {t:?} (`noo security team list`)")));
            }
            false
        }
        Subject::Key(_) => false,
    };
    let super_admins = crate::repo::addon_access::super_admins(&state.db).await.map_err(db_err)?;
    let reason = body.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
    let change = Change {
        covers_admin,
        has_unscoped_write: has_unscoped_write(&m, feature),
        by_super_admin: acts_as_super_admin(&by, &super_admins),
        reason: reason.map(str::to_string),
    };
    addon_access::check_change(&subject, value, &change).map_err(AppError::Forbidden)?;
    let subject_s = subject.as_string();
    let before = crate::repo::addon_access::list(&state.db)
        .await
        .map_err(db_err)?
        .into_iter()
        .find(|r| r.addon == addon && r.feature == feature && r.subject == subject_s)
        .map(|r| if r.allowed { "on" } else { "off" })
        .unwrap_or("inherit");
    match value {
        SetTo::Inherit => {
            crate::repo::addon_access::clear(&state.db, &addon, feature, &subject_s).await.map_err(db_err)?;
        }
        SetTo::On | SetTo::Off => {
            crate::repo::addon_access::set(&state.db, &addon, feature, &subject_s, value == SetTo::On, &by, "operator", reason)
                .await
                .map_err(db_err)?;
        }
    }
    reload_now(&state).await;
    let after = body.value.trim();
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::AddonAccessSet, &by, &format!("addon:{addon}")).details(json!({
            "addon": addon, "feature": feature, "subject": subject_s, "from": before, "to": after, "reason": reason,
        })),
    )
    .await;
    tracing::info!(addon = %addon, feature, subject = %subject_s, from = before, to = after, by = %by, "addon_access_set");
    Ok(Json(json!({"addon": addon, "feature": feature, "subject": subject_s, "from": before, "to": after})))
}

async fn person_view(
    State(state): State<Arc<AppState>>,
    _op: crate::authz::Operator,
    Path(username): Path<String>,
) -> AppResult {
    let account = username.trim();
    if !crate::repo::users::exists(&state.db, account).await.map_err(db_err)? {
        return Err(AppError::NotFound(format!("no account {account:?}")));
    }
    let super_admins = crate::repo::addon_access::super_admins(&state.db).await.map_err(db_err)?;
    let facts = facts_of(&state, account, &super_admins).await?;
    let settings: Vec<_> = crate::repo::addon_access::list(&state.db)
        .await
        .map_err(db_err)?
        .iter()
        .map(|r| r.setting())
        .collect();
    let mut addons: Vec<Value> = Vec::new();
    for entry in crate::addon_registry::all() {
        let m = entry.manifest();
        let features: Vec<Value> = m
            .features
            .iter()
            .map(|f| {
                let d = addon_access::decide(&settings, &m.addon, &f.name, &facts);
                json!({"feature": f.name, "title": f.title, "allowed": d.allowed, "decided_by": d.decided_by})
            })
            .collect();
        addons.push(json!({"addon": m.addon, "legacy": m.features.is_empty(), "features": features}));
    }
    addons.sort_by(|a, b| a["addon"].as_str().cmp(&b["addon"].as_str()));
    Ok(Json(json!({
        "account": account,
        "role": facts.role.map(Role::as_str),
        "teams": facts.teams,
        "super_admin": facts.super_admin,
        "addons": addons,
    })))
}

#[derive(Deserialize)]
struct SuperAdminBody {
    on: bool,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    password: String,
}

async fn super_admin_set(
    State(state): State<Arc<AppState>>,
    admin: crate::authz::Admin,
    Path(username): Path<String>,
    Json(body): Json<SuperAdminBody>,
) -> AppResult {
    let r = &admin.0;
    // A person's flag, set by a person: never an agent or a door's token.
    if r.act.is_some() || r.harness.is_some() {
        return Err(AppError::Forbidden(
            "a super admin is named by a person signed in directly, not by an agent or door token".into(),
        ));
    }
    let by = account_of(&r.sub).to_string();
    let super_admins = crate::repo::addon_access::super_admins(&state.db).await.map_err(db_err)?;
    if !acts_as_super_admin(&by, &super_admins) {
        return Err(AppError::Forbidden(format!(
            "only a super admin names super admins (the super admins: {})",
            super_admins.join(", ")
        )));
    }
    if body.reason.trim().is_empty() {
        return Err(AppError::BadRequest("a reason is required".into()));
    }
    // Fresh proof: the caller's own password, checked against the stored hash.
    let hash = crate::repo::users::login_row(&state.db, &by)
        .await
        .map_err(db_err)?
        .map(|row| row.1);
    let proved = hash.is_some_and(|h| bcrypt::verify(&body.password, &h).unwrap_or(false));
    if !proved {
        return Err(AppError::Forbidden("re-enter your own password to change super admins".into()));
    }
    let target = username.trim();
    let role = crate::repo::users::enabled_role(&state.db, target).await.map_err(db_err)?;
    if body.on && role.as_deref() != Some("admin") {
        return Err(AppError::BadRequest(format!(
            "{target} is not an enabled admin: make the account an admin first"
        )));
    }
    if !body.on && super_admins.len() == 1 && super_admins[0] == target {
        return Err(AppError::Conflict(format!(
            "{target} is the last super admin; name another one first"
        )));
    }
    let was = super_admins.iter().any(|s| s == target);
    // The first explicit change on an install with no flag yet keeps the
    // admins who were super admins implicitly.
    crate::repo::addon_access::flag_implicit_super_admins(&state.db).await.map_err(db_err)?;
    let n = crate::repo::addon_access::set_super_admin(&state.db, target, body.on).await.map_err(db_err)?;
    if n == 0 {
        return Err(AppError::NotFound(format!("no account {target:?}")));
    }
    reload_now(&state).await;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::SuperAdminSet, &by, target)
            .details(json!({"from": was, "to": body.on, "reason": body.reason.trim()})),
    )
    .await;
    tracing::warn!(target, from = was, to = body.on, by = %by, "super_admin_set");
    Ok(Json(json!({"account": target, "super_admin": body.on, "was": was})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(v: Value) -> crate::addon_proxy::AddonManifest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_feature_with_a_write_route_not_owner_scoped_is_flagged() {
        let m = manifest(json!({
            "version": 1, "addon": "evolve", "base_url_env": "NOO_EVOLVE_URL", "base_url_default": "https://noo-evolve:8090",
            "features": [{"name": "manage", "title": "Manage", "suggested": "operator"},
                         {"name": "mine", "title": "Mine", "suggested": "user"}],
            "routes": [
                {"name": "voices", "method": "PUT", "path": "/api/sample/voices", "feature": "manage"},
                {"name": "notes", "method": "POST", "path": "/api/sample/notes", "feature": "mine", "owner_scoped": true},
                {"name": "list", "method": "GET", "path": "/api/sample/list", "feature": "mine"}
            ]
        }));
        assert!(has_unscoped_write(&m, "manage"));
        assert!(!has_unscoped_write(&m, "mine"), "an owner_scoped write and a read do not count");
    }

    /// A fresh install (admin created after migration 104) and an upgraded
    /// one (admins flagged by it) must name the same super admins: with no
    /// flag set, every enabled admin is one, and the first explicit change
    /// writes that set down before it applies.
    #[test]
    fn a_fresh_install_counts_its_admins_as_super_admins_until_one_is_named() {
        let repo = include_str!("../repo/addon_access.rs");
        let read = repo.split("pub async fn super_admins").nth(1).unwrap().split("pub async fn").next().unwrap();
        assert!(read.contains("super_admin OR (role = 'admin' AND NOT EXISTS"), "{read}");
        let flag = repo.split("pub async fn flag_implicit_super_admins").nth(1).unwrap().split("pub async fn").next().unwrap();
        assert!(flag.contains("SET super_admin = true") && flag.contains("NOT EXISTS"), "a no-op once any is flagged");
    }

    #[test]
    fn with_no_super_admin_an_admin_acts_as_one() {
        assert!(acts_as_super_admin("ana", &[]));
        assert!(acts_as_super_admin("ana", &["ana".to_string()]));
        assert!(!acts_as_super_admin("bo", &["ana".to_string()]));
    }

    /// The super-admin route proves the caller fresh and refuses tokens that
    /// do not name a person, before it writes anything.
    #[test]
    fn super_admin_changes_check_the_caller_before_writing() {
        let src = include_str!("addon_access.rs");
        let body = src.split("async fn super_admin_set(").nth(1).unwrap().split("\n#[cfg(test)]").next().unwrap();
        let write = body.find("set_super_admin(").expect("the write");
        for guard in ["r.act.is_some() || r.harness.is_some()", "acts_as_super_admin(&by", "bcrypt::verify(", "is the last super admin", "flag_implicit_super_admins("] {
            let at = body.find(guard).unwrap_or_else(|| panic!("{guard}"));
            assert!(at < write, "{guard} runs before the write");
        }
    }
}
