// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Who may use an add-on feature (noomesh-internal f99).
//!
//! An add-on DECLARES its features (`features` in its route manifest); this
//! module holds noomesh's answer to "may this person use it". The operator,
//! 2026-10-31: "the add-on just reports its api and features; noomesh decides
//! which endpoints and features to allow, the same way for every add-on."
//!
//! A setting is `(add-on, feature, subject) -> on | off`; no row is
//! "inherit". Subjects, most specific first:
//!
//! 1. `user:<account>` or `key:<consumer>`: the credential itself;
//! 2. `team:<name>`: when a person's teams disagree, OFF wins (closing one team
//!    out is a decision; letting another in is not a reason to override it);
//! 3. `role:<tier>`, read from the person's own tier down (`role:operator`
//!    covers operators and admins, `role:user` covers everyone);
//! 4. nothing set: off.
//!
//! A **super admin** holds every feature and is not a cell anyone can switch.
//! Changing a setting that covers an admin (`role:admin`, or the account of an
//! admin) is for a super admin only, and turning one off takes a reason.
//!
//! [`decide`] is pure: the caller hands it the settings and the facts about
//! the requester, so every rule above is a table-driven test.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::addon_proxy::{AddonManifest, RouteRole, RouteSpec, UiRole, UiSpec};
use crate::auth::{RequesterCtx, Role};

/// Who a setting applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {
    Role(Role),
    Team(String),
    User(String),
    Key(String),
}

impl Subject {
    /// `role:user`, `team:<t>`, `user:<u>`, `key:<k>`: the stored spelling.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (kind, rest) = s.split_once(':').ok_or_else(|| format!("subject {s:?} is not <kind>:<name>"))?;
        let name_ok = !rest.is_empty()
            && rest.len() <= 128
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.@".contains(&b));
        if !name_ok {
            return Err(format!("subject {s:?}: the name after `{kind}:` is 1-128 characters of [A-Za-z0-9_.@-]"));
        }
        match kind {
            "role" => rest
                .parse::<Role>()
                .map(Subject::Role)
                .map_err(|_| format!("subject {s:?}: a role is user, operator or admin")),
            "team" => Ok(Subject::Team(rest.to_string())),
            "user" => Ok(Subject::User(rest.to_string())),
            "key" => Ok(Subject::Key(rest.to_string())),
            other => Err(format!("subject {s:?}: kind {other:?} is not role, team, user or key")),
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Subject::Role(r) => format!("role:{}", r.as_str()),
            Subject::Team(t) => format!("team:{t}"),
            Subject::User(u) => format!("user:{u}"),
            Subject::Key(k) => format!("key:{k}"),
        }
    }
}

/// One stored setting, as [`decide`] needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub addon: String,
    pub feature: String,
    pub subject: String,
    pub allowed: bool,
}

/// What is known about the requester, resolved by the gateway (never by the
/// add-on).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The account (`auth::account_of(sub)`), for a person.
    pub account: Option<String>,
    /// The service-key consumer, for a machine credential.
    pub key: Option<String>,
    pub role: Option<Role>,
    pub teams: Vec<String>,
    pub super_admin: bool,
}

/// The answer, and the setting that gave it (shown to admins and in the
/// person view; a refusal names it too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub decided_by: String,
}

impl Decision {
    fn new(allowed: bool, by: impl Into<String>) -> Self {
        Decision { allowed, decided_by: by.into() }
    }
}

/// May the requester described by `facts` use `feature` of `addon`?
pub fn decide(settings: &[Setting], addon: &str, feature: &str, facts: &Facts) -> Decision {
    if facts.super_admin {
        return Decision::new(true, "super admin");
    }
    let value = |subject: &str| {
        settings
            .iter()
            .find(|s| s.addon == addon && s.feature == feature && s.subject == subject)
            .map(|s| s.allowed)
    };
    // 1. The credential itself.
    for subject in [facts.key.as_ref().map(|k| format!("key:{k}")), facts.account.as_ref().map(|a| format!("user:{a}"))]
        .into_iter()
        .flatten()
    {
        if let Some(v) = value(&subject) {
            return Decision::new(v, subject);
        }
    }
    // 2. Teams: off wins.
    let mut teams: Vec<&String> = facts.teams.iter().collect();
    teams.sort();
    let set: Vec<(String, bool)> =
        teams.iter().filter_map(|t| value(&format!("team:{t}")).map(|v| (format!("team:{t}"), v))).collect();
    if let Some((by, _)) = set.iter().find(|(_, v)| !v) {
        return Decision::new(false, by.clone());
    }
    if let Some((by, _)) = set.first() {
        return Decision::new(true, by.clone());
    }
    // 3. Role, from the person's own tier down.
    if let Some(own) = facts.role {
        for tier in [Role::Admin, Role::Operator, Role::User].into_iter().filter(|t| *t <= own) {
            let subject = format!("role:{}", tier.as_str());
            if let Some(v) = value(&subject) {
                return Decision::new(v, subject);
            }
        }
    }
    Decision::new(false, "nothing set")
}

/// The value a write asks for: `on`, `off`, or `inherit` (remove the row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTo {
    On,
    Off,
    Inherit,
}

impl SetTo {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "on" => Ok(SetTo::On),
            "off" => Ok(SetTo::Off),
            "inherit" => Ok(SetTo::Inherit),
            other => Err(format!("value {other:?} — use on, off or inherit")),
        }
    }
}

/// Facts about the setting being changed that the write rules need.
#[derive(Debug, Clone, Default)]
pub struct Change {
    /// The subject covers an admin: `role:admin`, or the account of an admin.
    pub covers_admin: bool,
    /// The feature opens a write route that is not `owner_scoped`.
    pub has_unscoped_write: bool,
    /// The person making the change is a super admin.
    pub by_super_admin: bool,
    /// The reason given, if any.
    pub reason: Option<String>,
}

/// May this change be made? `Err` is the sentence the admin sees.
pub fn check_change(subject: &Subject, value: SetTo, change: &Change) -> Result<(), String> {
    if change.covers_admin && !change.by_super_admin {
        return Err(format!(
            "{} covers an admin: only a super admin changes it",
            subject.as_string()
        ));
    }
    if change.covers_admin && value == SetTo::Off && change.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
        return Err(format!("turning a feature off for {} needs a reason", subject.as_string()));
    }
    let operator_or_up = matches!(subject, Subject::Role(Role::Operator | Role::Admin));
    if value == SetTo::On && change.has_unscoped_write && !operator_or_up {
        return Err(format!(
            "this feature has a write route the add-on did not declare owner_scoped, so it opens to \
             role:operator or role:admin only, not {} (the add-on must declare owner_scoped first)",
            subject.as_string()
        ));
    }
    Ok(())
}

// ── The settings in force ────────────────────────────────────────────────

/// What every check reads: the settings, the super admins and each account's
/// teams, loaded together so one request sees one consistent picture.
#[derive(Debug, Default)]
struct Snapshot {
    settings: Vec<Setting>,
    super_admins: Vec<String>,
    teams: HashMap<String, Vec<String>>,
}

static SNAPSHOT: RwLock<Option<Arc<Snapshot>>> = RwLock::new(None);

fn snapshot() -> Option<Arc<Snapshot>> {
    SNAPSHOT.read().ok().and_then(|s| s.clone())
}

/// How often the settings are re-read without a write in this process (a
/// restore, a write by another gateway). A write through the admin routes
/// reloads at once.
pub const REFRESH_SECS: u64 = 60;

/// Re-read the settings, the super admins and team membership (`team:<name>`
/// KB roles) into the snapshot every check reads.
pub async fn reload(db: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let settings = crate::repo::addon_access::list(db).await?.iter().map(|r| r.setting()).collect();
    let super_admins = crate::repo::addon_access::super_admins(db).await?;
    let mut teams: HashMap<String, Vec<String>> = HashMap::new();
    for (user, roles) in crate::repo::kb_grants::list_grants(db).await? {
        let t: Vec<String> = roles
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r.as_str()?.strip_prefix("team:").map(str::to_string))
            .collect();
        if !t.is_empty() {
            teams.insert(user, t);
        }
    }
    if let Ok(mut w) = SNAPSHOT.write() {
        *w = Some(Arc::new(Snapshot { settings, super_admins, teams }));
    }
    Ok(())
}

/// Load now and every [`REFRESH_SECS`]. Until the first load succeeds, every
/// feature of a features manifest is refused (fail closed); after that a
/// failed re-read keeps the last settings and says so once.
pub fn spawn_refresh(db: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut failing = false;
        loop {
            match reload(&db).await {
                Ok(()) if failing => {
                    tracing::info!("addon_access_refresh_recovered");
                    failing = false;
                }
                Ok(()) => {}
                Err(e) => {
                    if !failing {
                        tracing::error!(error = %e, "addon_access_refresh_failed: add-on features keep the last settings read (none yet: refused)");
                    }
                    failing = true;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(REFRESH_SECS)).await;
        }
    });
}

/// May this account use the feature, by the settings in force?
pub fn feature_allows(addon: &str, feature: &str, account: &str, role: Role) -> Decision {
    let Some(s) = snapshot() else {
        return Decision::new(false, "access settings not loaded yet");
    };
    let facts = Facts {
        account: Some(account.to_string()),
        key: None,
        role: Some(role),
        teams: s.teams.get(account).cloned().unwrap_or_default(),
        super_admin: s.super_admins.iter().any(|x| x == account),
    };
    decide(&s.settings, addon, feature, &facts)
}

// ── The one check every surface calls ────────────────────────────────────

/// May a requester (`role`, `scopes`, and the account when known) call this
/// route? A manifest without features keeps exactly its route's own rule
/// (`min_role`/`scopes`); a features manifest asks the route's feature.
/// No account (a check that does not know one) is refused for a feature.
pub fn route_permits(m: &AddonManifest, r: &RouteSpec, role: Role, scopes: &[String], account: Option<&str>) -> bool {
    if m.features.is_empty() {
        return r.permits(role, scopes);
    }
    match (account, r.feature.as_deref()) {
        (Some(a), Some(f)) => feature_allows(&m.addon, f, a, role).allowed,
        _ => false,
    }
}

/// The proxy's and the WS door's check for a person: `Err` is the response.
pub fn route_check(m: &AddonManifest, spec: &RouteSpec, r: &RequesterCtx) -> Result<(), Response> {
    if m.features.is_empty() {
        return if spec.permits(r.role, &r.scopes) { Ok(()) } else { Err(crate::addon_proxy::forbidden(m, spec)) };
    }
    let account = crate::auth::account_of(&r.sub);
    let feature = spec.feature.as_deref().unwrap_or("");
    let d = feature_allows(&m.addon, feature, account, r.role);
    if d.allowed {
        Ok(())
    } else {
        Err(refusal(m, feature, account, &d))
    }
}

/// The UI origin's check for a person.
pub fn ui_check(m: &AddonManifest, ui: &UiSpec, r: &RequesterCtx) -> Result<(), Response> {
    if m.features.is_empty() {
        return if ui.permits(r.role) { Ok(()) } else { Err(crate::addon_ui::ui_forbidden(&m.addon, ui)) };
    }
    let account = crate::auth::account_of(&r.sub);
    let feature = ui.feature.as_deref().unwrap_or("");
    let d = feature_allows(&m.addon, feature, account, r.role);
    if d.allowed {
        Ok(())
    } else {
        Err(refusal(m, feature, account, &d))
    }
}

/// Can this person open the add-on's UI (the console's list)? `None` role is
/// a machine credential, which the console list does not narrow.
pub fn ui_opens_for(m: &AddonManifest, ui: &UiSpec, role: Option<Role>, account: Option<&str>) -> bool {
    let Some(role) = role else { return true };
    if m.features.is_empty() {
        return ui.permits(role);
    }
    match (account, ui.feature.as_deref()) {
        (Some(a), Some(f)) => feature_allows(&m.addon, f, a, role).allowed,
        _ => false,
    }
}

/// The `x-noo-requester-features` value for this requester and add-on: the
/// declared features it holds, comma-separated, in declaration order. `None`
/// for a manifest without features (the header is not sent at all).
pub fn requester_features(m: &AddonManifest, r: &RequesterCtx) -> Option<String> {
    if m.features.is_empty() {
        return None;
    }
    let account = crate::auth::account_of(&r.sub);
    Some(held_features(m, |f| feature_allows(&m.addon, f, account, r.role).allowed))
}

fn held_features(m: &AddonManifest, holds: impl Fn(&str) -> bool) -> String {
    m.features.iter().filter(|f| holds(&f.name)).map(|f| f.name.as_str()).collect::<Vec<_>>().join(",")
}

/// One refusal shape on every surface (f99 section 5): the add-on, the
/// feature in the add-on's words, the account and the setting that decided.
/// It never lists who DOES hold the feature.
pub fn refusal(m: &AddonManifest, feature: &str, account: &str, d: &Decision) -> Response {
    let title = m.feature(feature).map(|f| f.title.as_str()).unwrap_or(feature);
    tracing::debug!(addon = %m.addon, feature, account, decided_by = %d.decided_by, "addon_feature_refused");
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "addon_feature_not_granted",
            "addon": m.addon,
            "feature": feature,
            "feature_title": title,
            "decided_by": d.decided_by,
            "detail": format!(
                "{}: \"{title}\" is off for {account} ({}). An admin turns it on in the add-on's access settings.",
                m.addon, d.decided_by
            ),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(subject: &str, allowed: bool) -> Setting {
        Setting { addon: "rhaddon".into(), feature: "transcripts".into(), subject: subject.into(), allowed }
    }
    fn person(account: &str, role: Role, teams: &[&str]) -> Facts {
        Facts {
            account: Some(account.into()),
            role: Some(role),
            teams: teams.iter().map(|t| t.to_string()).collect(),
            ..Facts::default()
        }
    }
    fn d(settings: &[Setting], facts: &Facts) -> (bool, String) {
        let r = decide(settings, "rhaddon", "transcripts", facts);
        (r.allowed, r.decided_by)
    }

    #[test]
    fn nothing_set_is_off_and_a_super_admin_is_always_on() {
        assert_eq!(d(&[], &person("ana", Role::Admin, &[])), (false, "nothing set".into()));
        let off = [set("role:admin", false), set("user:root", false)];
        let mut root = person("root", Role::Admin, &[]);
        root.super_admin = true;
        assert_eq!(d(&off, &root), (true, "super admin".into()));
    }

    #[test]
    fn the_most_specific_setting_wins() {
        let s = [set("role:user", true), set("team:guests", false), set("user:ana", true)];
        assert_eq!(d(&s, &person("ana", Role::User, &["guests"])), (true, "user:ana".into()));
        assert_eq!(d(&s, &person("bo", Role::User, &["guests"])), (false, "team:guests".into()));
        assert_eq!(d(&s, &person("cy", Role::User, &[])), (true, "role:user".into()));
        // Off for users, on for the studio team.
        let s = [set("role:user", false), set("team:studio", true)];
        assert_eq!(d(&s, &person("di", Role::User, &["studio"])), (true, "team:studio".into()));
        assert_eq!(d(&s, &person("ed", Role::User, &[])), (false, "role:user".into()));
    }

    #[test]
    fn when_teams_disagree_off_wins() {
        let s = [set("team:a", true), set("team:b", false)];
        assert_eq!(d(&s, &person("ana", Role::User, &["a", "b"])), (false, "team:b".into()));
        assert_eq!(d(&s, &person("ana", Role::User, &["a"])), (true, "team:a".into()));
    }

    #[test]
    fn a_role_setting_covers_its_tier_and_every_tier_above() {
        let s = [set("role:operator", true)];
        assert!(!d(&s, &person("u", Role::User, &[])).0, "a user is below operator");
        assert_eq!(d(&s, &person("o", Role::Operator, &[])), (true, "role:operator".into()));
        assert_eq!(d(&s, &person("a", Role::Admin, &[])), (true, "role:operator".into()));
        // The person's own tier is read first.
        let s = [set("role:user", true), set("role:admin", false)];
        assert_eq!(d(&s, &person("a", Role::Admin, &[])), (false, "role:admin".into()));
        assert_eq!(d(&s, &person("o", Role::Operator, &[])), (true, "role:user".into()));
    }

    #[test]
    fn a_key_is_its_own_subject_and_another_addon_or_feature_never_counts() {
        let key = Facts { key: Some("svc-rhaddon".into()), ..Facts::default() };
        assert_eq!(d(&[set("key:svc-rhaddon", true)], &key), (true, "key:svc-rhaddon".into()));
        assert!(!d(&[set("role:user", true)], &key).0, "a key has no role");
        let other = [Setting { addon: "other".into(), feature: "transcripts".into(), subject: "role:user".into(), allowed: true },
            Setting { addon: "rhaddon".into(), feature: "export".into(), subject: "role:user".into(), allowed: true }];
        assert!(!d(&other, &person("u", Role::User, &[])).0);
    }

    #[test]
    fn subjects_parse_and_print_the_same_spelling() {
        for s in ["role:user", "role:operator", "role:admin", "team:studio", "user:ana", "key:svc-rhaddon"] {
            assert_eq!(Subject::parse(s).unwrap().as_string(), s);
        }
        for bad in ["user", "role:root", "group:x", "user:", "user:a b", "team:<x>"] {
            assert!(Subject::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn admin_settings_are_for_a_super_admin_and_off_takes_a_reason() {
        let admin = Subject::parse("role:admin").unwrap();
        let ordinary = Change { covers_admin: true, ..Change::default() };
        assert!(check_change(&admin, SetTo::On, &ordinary).unwrap_err().contains("only a super admin"));
        let sa = Change { covers_admin: true, by_super_admin: true, ..Change::default() };
        assert!(check_change(&admin, SetTo::On, &sa).is_ok(), "back on needs no reason");
        assert!(check_change(&admin, SetTo::Off, &sa).unwrap_err().contains("needs a reason"));
        let why = Change { reason: Some("pilot ended".into()), ..sa };
        assert!(check_change(&admin, SetTo::Off, &why).is_ok());
    }

    fn manifest(v: serde_json::Value) -> AddonManifest {
        serde_json::from_value(v).unwrap()
    }

    fn legacy() -> AddonManifest {
        manifest(json!({
            "version": 1, "addon": "evolve", "base_url_env": "NOO_EVOLVE_URL", "base_url_default": "https://noo-evolve:8090",
            "routes": [
                {"name": "status", "method": "GET", "path": "/api/sample/status", "min_role": "user"},
                {"name": "items", "method": "GET", "path": "/api/sample/items", "scopes": ["evolve:read_items"]},
                {"name": "secret", "method": "GET", "path": "/api/sample/secret", "min_role": "admin"},
                {"name": "notes", "method": "POST", "path": "/api/sample/notes", "min_role": "user", "owner_scoped": true},
                {"name": "run", "method": "POST", "path": "/api/sample/run", "min_role": "operator"}
            ]
        }))
    }

    /// P8: for a manifest without features the one check IS the route's own
    /// rule, proved against `permits` on every route, role and scope set.
    #[test]
    fn a_legacy_manifest_keeps_exactly_its_route_rule() {
        let m = legacy();
        let sets: [&[&str]; 4] = [&[], &["read"], &["read", "evolve:read_items"], &["read", "write", "admin"]];
        for r in &m.routes {
            for role in [Role::User, Role::Operator, Role::Admin] {
                for set in sets {
                    let held: Vec<String> = set.iter().map(|x| x.to_string()).collect();
                    for account in [None, Some("ana")] {
                        assert_eq!(route_permits(&m, r, role, &held, account), r.permits(role, &held), "{} {role:?} {set:?}", r.name);
                    }
                }
            }
        }
    }

    /// Before the settings are loaded, a features route is refused to every
    /// account and every role (fail closed). Nothing in the unit tests loads
    /// them, so this holds for the whole test binary.
    #[test]
    fn a_feature_is_refused_until_the_settings_are_loaded() {
        let m = manifest(json!({
            "version": 1, "addon": "evolve", "base_url_env": "NOO_EVOLVE_URL", "base_url_default": "https://noo-evolve:8090",
            "features": [{"name": "converse", "title": "Talk", "suggested": "user"}],
            "routes": [{"name": "s", "method": "GET", "path": "/api/sample/s", "feature": "converse"}],
            "ui": {"feature": "converse"}
        }));
        let r = &m.routes[0];
        for role in [Role::User, Role::Operator, Role::Admin] {
            assert!(!route_permits(&m, r, role, &[], Some("ana")), "{role:?}");
            assert!(!route_permits(&m, r, role, &[], None), "{role:?}: no account");
            assert!(!ui_opens_for(&m, m.ui.as_ref().unwrap(), Some(role), Some("ana")));
        }
        assert!(ui_opens_for(&m, m.ui.as_ref().unwrap(), None, None), "a machine credential's listing is not narrowed");
        assert_eq!(feature_allows("evolve", "converse", "ana", Role::Admin).decided_by, "access settings not loaded yet");
    }

    /// Every surface asks the one check; none keeps a `permits` of its own.
    #[test]
    fn every_surface_calls_the_one_check() {
        let body = |src: &'static str, start: &str| -> &'static str {
            src.split(start).nth(1).unwrap_or_else(|| panic!("{start}")).split("\n\u{7d}\n").next().unwrap()
        };
        let proxy = include_str!("addon_proxy.rs");
        let serve = body(proxy, "\nasync fn serve(");
        assert!(serve.contains("crate::addon_access::route_check(manifest, spec, r)") && !serve.contains(".permits("));
        let ws = body(include_str!("addon_ws.rs"), "pub(crate) fn admit(");
        assert!(ws.contains("crate::addon_access::route_check(manifest, spec, r)") && !ws.contains(".permits("));
        let ui = include_str!("addon_ui.rs");
        for f in ["pub(crate) async fn serve_ui(", "async fn ui_session("] {
            let b = body(ui, f);
            assert!(b.contains("crate::addon_access::ui_check(") && !b.contains(".permits("), "{f}");
        }
        assert!(body(ui, "pub fn ui_entries(").contains("crate::addon_access::ui_opens_for("));
        for f in ["fn owner_scoped_allows_for(", "fn get_allows_for("] {
            assert!(body(proxy, f).contains("crate::addon_access::route_permits("), "{f}");
        }
    }

    /// f99: the hint header lists exactly the held features, in declaration
    /// order, and is not sent at all for a manifest without features.
    #[test]
    fn the_requester_features_hint_lists_what_is_held_and_nothing_for_a_legacy_manifest() {
        let m = manifest(json!({
            "version": 1, "addon": "evolve", "base_url_env": "NOO_EVOLVE_URL", "base_url_default": "https://noo-evolve:8090",
            "features": [{"name": "converse", "title": "Talk", "suggested": "user"},
                         {"name": "transcripts", "title": "Read", "suggested": "user"},
                         {"name": "manage", "title": "Manage", "suggested": "operator"}],
            "routes": [{"name": "s", "method": "GET", "path": "/api/sample/s", "feature": "converse"}]
        }));
        assert_eq!(held_features(&m, |f| f != "transcripts"), "converse,manage");
        assert_eq!(held_features(&m, |_| false), "");
        let r = RequesterCtx { sub: "ana".into(), scopes: vec![], role: Role::Admin, harness: None, act: None };
        assert!(requester_features(&legacy(), &r).is_none(), "no header for a legacy manifest");
        assert_eq!(requester_features(&m, &r).as_deref(), Some(""), "nothing held before the settings load");
    }

    #[test]
    fn an_unscoped_write_opens_to_operators_and_admins_only() {
        let c = Change { has_unscoped_write: true, by_super_admin: true, ..Change::default() };
        for s in ["role:user", "team:studio", "user:ana", "key:svc"] {
            let e = check_change(&Subject::parse(s).unwrap(), SetTo::On, &c).unwrap_err();
            assert!(e.contains("owner_scoped"), "{s}: {e}");
            assert!(check_change(&Subject::parse(s).unwrap(), SetTo::Off, &c).is_ok(), "{s}: off is always allowed");
        }
        assert!(check_change(&Subject::parse("role:operator").unwrap(), SetTo::On, &c).is_ok());
    }
}
