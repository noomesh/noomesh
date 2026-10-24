// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `POST /api/monitoring/grafana-session` — open Grafana as the noomesh
//! account at the browser.
//!
//! Grafana runs `[auth.jwt]` (`configs/grafana/grafana.ini`): it accepts a
//! token in `?auth_token=` on the first navigation, then in the
//! `X-JWT-Assertion` header its own front end attaches to every API call,
//! and verifies it against `/app/pki/sso/grafana.pub` — the public half of
//! a key pair that exists for this one purpose (`noo security pki
//! issue-sso-key`; onboard issues it). JWT auth in Grafana is stateless:
//! no Grafana session cookie is created, the token IS the session, and it
//! lasts `NOO_GRAFANA_SESSION_TTL` minutes (5 by default, 60 at most).
//!
//! What this handler decides, and from where:
//!
//! - **who**: the account behind the login token's `sub`, re-read from
//!   `noo_users` on every call. The role in the Grafana token is the LIVE
//!   tier, never the access token's `role` claim, and a disabled or
//!   deleted account is refused — a demotion or a disable takes effect at
//!   the next "Open Grafana", whatever login JWT the browser still holds.
//! - **which credentials may ask**: a person's login token only. An
//!   exchanged token (`act`), a node-hosted harness token, a kiosk or
//!   add-on subject, a service key and the cluster HMAC are all refused —
//!   a Grafana tab has a person in front of it or it has no business
//!   existing.
//! - **what the token is worth elsewhere**: nothing. `aud = "noo-grafana"`
//!   and no `kid`, so `auth::verify_token_with` refuses it twice over
//!   (`auth::tests::the_gateway_refuses_a_grafana_token`).
//!
//! The private key is read from disk on every mint rather than cached at
//! startup: the roll order is "issue the key, then the stack", but an
//! install that issues it AFTER the gateway came up should not have to
//! restart to make the button work. One small file read per click.

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;

use axum::{extract::State, routing::post, Extension, Json, Router};
use serde_json::{json, Value};

use crate::auth::{Role, RequesterCtx};
use crate::state::AppState;

use super::{AppError, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    // A literal path: the OpenAPI generator and the drift checker read
    // route strings (see identity.rs for the same rule).
    Router::new().route("/api/monitoring/grafana-session", post(grafana_session))
}

/// Where the gateway finds the SSO private key. `NOO_GRAFANA_SSO_KEY` names
/// it outright (compose sets `/app/pki/sso/grafana.key`); otherwise the
/// same PKI roots `autonomy_evaluators::count_certs_expiring_within` walks.
pub const GRAFANA_SSO_KEY_ENV: &str = "NOO_GRAFANA_SSO_KEY";
/// Where the browser reaches Grafana: `GRAFANA_ROOT_URL` on the host, the
/// URL the BROWSER uses, not the compose-network one.
pub const GRAFANA_URL_ENV: &str = "NOO_GRAFANA_URL";

/// The relative path of the SSO key under a PKI root. Shared with the CLI
/// (`noo-cli/src/pki.rs`) and `grafana.ini` by the Python parity test.
pub const GRAFANA_SSO_KEY_REL: &str = "sso/grafana.key";

fn sso_key_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var(GRAFANA_SSO_KEY_ENV).ok().filter(|s| !s.trim().is_empty()) {
        return std::path::PathBuf::from(p);
    }
    let roots: Vec<String> = std::env::var("NOO_PKI_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .into_iter()
        .chain(["/tmp/pki".to_string(), "/app/pki".to_string()])
        .collect();
    roots
        .iter()
        .map(|r| std::path::Path::new(r).join(GRAFANA_SSO_KEY_REL))
        .find(|p| p.is_file())
        .unwrap_or_else(|| std::path::Path::new("/app/pki").join(GRAFANA_SSO_KEY_REL))
}

/// Read and parse the SSO private key. The error names the file and the
/// command that creates it, because "503" alone sends an operator to the
/// logs for something the response could have said.
pub fn load_sso_key(path: &std::path::Path) -> Result<jsonwebtoken::EncodingKey, String> {
    let pem = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Grafana SSO key {} is not readable ({e}). Fix: `noo security pki issue-sso-key` on the \
             controller, then recreate the gateway and Grafana (`noo stack restart --force`); the key \
             must be readable by uid 65532 (0640, group 65532)",
            path.display()
        )
    })?;
    let kp = rcgen::KeyPair::from_pem(&pem)
        .map_err(|e| format!("Grafana SSO key {} is not a usable PEM key pair: {e}", path.display()))?;
    let raw = kp.public_key_raw();
    if raw.len() != 65 || raw[0] != 0x04 {
        return Err(format!(
            "Grafana SSO key {} is not a P-256 key (Grafana verifies ES256 only). Fix: `noo security pki issue-sso-key --force`",
            path.display()
        ));
    }
    jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| format!("Grafana SSO key {} could not be loaded for ES256: {e}", path.display()))
}

/// Compose the URL the tab opens. `url_login = true` reads `auth_token`
/// from the query on the first navigation; Grafana's front end then
/// caches it in memory and sends it as `X-JWT-Assertion`.
pub fn grafana_login_url(base: &str, token: &str) -> String {
    format!("{}/?auth_token={token}", base.trim_end_matches('/'))
}

/// The credentials that may ask. `None` = not a JWT login at all (cluster
/// HMAC, a service key): refused. A JWT that names software rather than
/// a person is refused too.
pub fn person_at_the_browser(ctx: &Option<Extension<RequesterCtx>>) -> Result<String, String> {
    // Every refusal says why AND what is needed.
    let refuse = |why: &str| Err(format!("{why} — {}", crate::auth::grafana_needs()));
    let Some(Extension(r)) = ctx else {
        return refuse("a service credential (cluster HMAC or service key) cannot open Grafana");
    };
    if r.act.is_some() {
        return refuse("an exchanged (delegated) token cannot open Grafana");
    }
    if r.harness.is_some() {
        return refuse("a harness token cannot open Grafana");
    }
    if r.sub.starts_with("kiosk:") || r.sub.starts_with(crate::auth::ADDON_SUBJECT_PREFIX) {
        return refuse("a kiosk or add-on credential cannot open Grafana");
    }
    Ok(r.sub.clone())
}

/// Where the gateway reaches Grafana itself, over the compose network —
/// NOT `NOO_GRAFANA_URL`, which is the browser's URL (often `localhost`,
/// i.e. the gateway's own container). Grafana's leaf names `grafana`.
pub const GRAFANA_INTERNAL_URL: &str = "https://grafana:3000";

/// The Grafana login the evidence probe signs in as. Not a valid noomesh
/// account name (`.` is outside `auth::valid_name_segment`), so it can never
/// be a person's login; Grafana creates it once, as a Viewer, on first use.
pub const GRAFANA_PROBE_SUBJECT: &str = "noo.gateway-probe";

/// How long a good answer is believed, and a bad one. A bad one is
/// re-asked sooner, so a Grafana that comes up correct is noticed quickly.
const EVIDENCE_OK_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const EVIDENCE_ERR_TTL: std::time::Duration = std::time::Duration::from_secs(15);

type Evidence = (Result<(), String>, std::time::Instant);
static EVIDENCE: std::sync::OnceLock<std::sync::Mutex<Option<Evidence>>> = std::sync::OnceLock::new();

/// The URL a provisioned data source of `typ` must have: the gateway's
/// `/api/grafana-ds/<typ>` route.
pub fn gateway_ds_url(typ: &str) -> String {
    format!("https://gateway:8080{}{typ}", crate::auth::GRAFANA_DS_PREFIX)
}

/// Judge what Grafana itself reports: its `prometheus` and
/// `loki` data sources (`GET /api/datasources/uid/<uid>`) must dial the
/// gateway, and shared dashboards (`GET /api/frontend/settings`) must be off.
/// Pure, so each failure is pinned without a Grafana.
pub fn grafana_ds_evidence(prometheus: &Value, loki: &Value, frontend: &Value) -> Result<(), String> {
    for (typ, ds) in [("prometheus", prometheus), ("loki", loki)] {
        let url = ds.get("url").and_then(Value::as_str).unwrap_or("").trim().trim_end_matches('/');
        let want = gateway_ds_url(typ);
        if url != want {
            let shown = if url.is_empty() { "nothing" } else { url };
            return Err(format!(
                "Grafana's {typ} data source dials {shown}, not the gateway ({want}) — Grafana is running older configs. \
                 Fix: noo upgrade --all, run from the current CLI release (it re-lays configs/grafana and recreates Grafana)"
            ));
        }
    }
    if frontend.get("publicDashboardsEnabled").and_then(Value::as_bool) != Some(false) {
        return Err("Grafana's shared (public) dashboards are not off — Grafana is running an older grafana.ini. \
                    Fix: noo upgrade --all, run from the current CLI release"
            .into());
    }
    Ok(())
}

/// Ask the running Grafana, as [`GRAFANA_PROBE_SUBJECT`] (a Viewer, signed
/// with the SSO key the gateway already holds), for the facts
/// [`grafana_ds_evidence`] judges. Unreachable, refusing, or unreadable is
/// an `Err` — never read as "fine".
pub async fn fetch_grafana_evidence(base: &str, key: &jsonwebtoken::EncodingKey) -> Result<(), String> {
    let token = crate::auth::mint_grafana_jwt_with(GRAFANA_PROBE_SUBJECT, Role::User, 60, key)
        .ok_or_else(|| "could not sign the Grafana probe token".to_string())?;
    let client = crate::tls::cluster_client();
    let base = base.trim_end_matches('/');
    let mut got = Vec::with_capacity(3);
    for path in ["/api/datasources/uid/prometheus", "/api/datasources/uid/loki", "/api/frontend/settings"] {
        let resp = client
            .get(format!("{base}{path}"))
            .header(crate::auth::GRAFANA_JWT_HEADER, &token)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("Grafana did not answer at {base}{path} ({e}) — is the grafana container running?"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("Grafana answered {status} for {path}, so its data sources could not be checked"));
        }
        let v: Value = resp.json().await.map_err(|e| format!("Grafana's {path} was not JSON: {e}"))?;
        got.push(v);
    }
    grafana_ds_evidence(&got[0], &got[1], &got[2])
}

/// [`crate::auth::grafana_viewer_gate`] with this process's declaration
/// and Grafana's (cached) evidence.
async fn viewer_gate(key: &jsonwebtoken::EncodingKey) -> Result<(), String> {
    let flag = std::env::var(crate::auth::GRAFANA_DS_GATE_ENV).ok();
    if !crate::auth::grafana_ds_gate_declared(flag.as_deref()) {
        return crate::auth::grafana_viewer_gate(flag.as_deref(), None);
    }
    let cell = EVIDENCE.get_or_init(|| std::sync::Mutex::new(None));
    let cached = cell.lock().ok().and_then(|g| g.clone()).filter(|(r, at)| {
        at.elapsed() < if r.is_ok() { EVIDENCE_OK_TTL } else { EVIDENCE_ERR_TTL }
    });
    let evidence = match cached {
        Some((r, _)) => r,
        None => {
            let r = fetch_grafana_evidence(GRAFANA_INTERNAL_URL, key).await;
            if let Err(why) = &r {
                tracing::warn!("grafana_viewer_gate_closed: {why}");
            }
            if let Ok(mut g) = cell.lock() {
                *g = Some((r.clone(), std::time::Instant::now()));
            }
            r
        }
    };
    crate::auth::grafana_viewer_gate(flag.as_deref(), Some(evidence))
}

/// `POST /api/monitoring/grafana-session` — mint a Grafana session for the
/// account at the browser and return the URL to open it with. Any
/// authenticated noomesh login: the account is RE-READ from `noo_users`
/// (a disabled or deleted account is refused with 403) and its LIVE tier
/// becomes the token's `role`, with the Grafana org role from
/// `auth::GRAFANA_ORG_ROLES` (admin→Admin, operator→Editor, user→Viewer —
/// dashboards only) as `grafana_role`. Every 403 on this route has a body
/// naming why and which tiers open Grafana. The token is ES256 with the dedicated
/// SSO key (`${NOO_PKI_DIR}/sso/grafana.key`), `aud = noo-grafana`, no
/// `kid`, and lives `NOO_GRAFANA_SESSION_TTL` minutes (5 default, 60
/// max); the gateway itself refuses it. 503 with the fix when
/// `NOO_GRAFANA_URL` or the key is absent. One audit row per mint
/// (`grafana_session_issued`). Exchanged, harness, kiosk and add-on
/// tokens, service keys and the cluster HMAC are refused: a person has to
/// be at the browser.
async fn grafana_session(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let sub = person_at_the_browser(&ctx).map_err(AppError::Forbidden)?;

    let base = std::env::var(GRAFANA_URL_ENV).ok().filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        AppError::Unavailable(format!(
            "Grafana SSO is not configured: {GRAFANA_URL_ENV} is empty. Fix: `noo upgrade --stack` on \
             the controller derives GRAFANA_ROOT_URL and NOO_GRAFANA_BIND_ADDR from NOO_BIND_MODE and \
             recreates the stack (or set both in .env by hand, then `noo stack restart --force`)"
        ))
    })?;
    let key_path = sso_key_path();
    let key = load_sso_key(&key_path).map_err(AppError::Unavailable)?;

    // The ACCOUNT, live. A connection name resolves to its account, the
    // same as every other place a person accumulates.
    let account = crate::auth::account_of(&sub);
    let row: Option<(String, serde_json::Value, bool)> =
        sqlx::query_as("SELECT role, scopes, COALESCE(disabled, false) FROM noo_users WHERE username = $1")
            .bind(account)
            .fetch_optional(&state.db)
            .await?;
    let (live, disabled) = match row {
        None => (None, false),
        Some((role_col, scopes_col, disabled)) => {
            // Same resolution as `users::effective_tier`: an unparseable
            // role column reads as Admin, never as User.
            let from_col: Role = role_col.trim().parse().unwrap_or(Role::Admin);
            let list: Vec<String> = serde_json::from_value(scopes_col).unwrap_or_default();
            (Some(from_col.max(Role::from_scopes(&list))), disabled)
        }
    };
    // the design, fail closed: a read-only account is a Viewer only when
    // this compose declares the gateway-routed data sources AND the running
    // Grafana proves it. Asked only for that tier; operators never wait on
    // a Grafana round trip.
    let viewer = if live == Some(Role::User) && !disabled {
        viewer_gate(&key).await
    } else {
        Ok(())
    };
    let (role, grafana_role) = crate::auth::grafana_session_role(live, disabled, &viewer)
        .map_err(|e| AppError::Forbidden(format!("account '{account}': {e}")))?;

    let ttl = crate::auth::grafana_session_ttl_secs(
        std::env::var(crate::auth::GRAFANA_SESSION_TTL_ENV).ok().as_deref(),
    );
    let token = crate::auth::mint_grafana_jwt_with(account, role, ttl, &key)
        .ok_or_else(|| AppError::Internal("could not sign the Grafana session token".into()))?;
    let jti = token
        .split('.')
        .nth(1)
        .and_then(|mid| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mid).ok()
        })
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|c| c["jti"].as_str().map(str::to_string))
        .unwrap_or_default();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);

    tracing::info!(account, role = role.as_str(), grafana_role, ttl, "grafana_session_issued");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::GrafanaSessionIssued, account, "grafana")
            .details(json!({ "role": role.as_str(), "grafana_role": grafana_role, "jti": jti, "expires_in": ttl })),
    )
    .await;

    Ok(Json(json!({
        "url": grafana_login_url(&base, &token),
        "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        // The noomesh tier, and the Grafana org role auth::GRAFANA_ORG_ROLES
        // gives it (the token carries both; grafana.ini reads the second).
        "role": role.as_str(),
        "grafana_role": grafana_role,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handler must take its role from `grafana_session_role`, the pure
    /// function whose table is pinned in auth.rs. A pure-function test
    /// stays green whether or not anything calls it (identity.rs rule).
    #[test]
    fn the_handler_takes_its_role_from_the_live_row_function() {
        let src = include_str!("monitoring.rs");
        let body = src.split("async fn grafana_session(").nth(1).expect("the handler exists");
        let body = body.split("#[cfg(test)]").next().unwrap();
        assert!(body.contains("grafana_session_role("), "the handler must call auth::grafana_session_role");
        assert!(body.contains("FROM noo_users"), "the handler must re-read the account row");
        assert!(body.contains("mint_grafana_jwt_with("), "the handler must mint through the pinned mint");
        assert!(
            !body.contains("r.role") && !body.contains(".role,") && !body.contains("ctx.role"),
            "the handler must not take the role from the access token's RequesterCtx"
        );
    }

    /// The tier gate opens this route to a User by `auth::GRAFANA_SESSION_PATH`
    /// the router registers the literal. One path.
    #[test]
    fn the_tier_gate_exemption_names_the_registered_route() {
        let src = include_str!("monitoring.rs");
        assert!(src.contains(&format!(".route(\"{}\"", crate::auth::GRAFANA_SESSION_PATH)));
    }

    /// what Grafana reports is judged, not assumed.
    #[test]
    fn grafanas_own_data_sources_are_the_evidence() {
        let ds = |url: &str| json!({ "url": url, "type": "x" });
        let off = json!({ "publicDashboardsEnabled": false });
        let good_p = ds("https://gateway:8080/api/grafana-ds/prometheus");
        let good_l = ds("https://gateway:8080/api/grafana-ds/loki/");
        assert_eq!(grafana_ds_evidence(&good_p, &good_l, &off), Ok(()));
        // The old CLI's provisioning: direct.
        let e = grafana_ds_evidence(&ds("https://prometheus:9090"), &good_l, &off).unwrap_err();
        assert!(e.contains("dials https://prometheus:9090") && e.contains("noo upgrade --all"), "{e}");
        assert!(grafana_ds_evidence(&good_p, &ds("https://loki:3100"), &off).is_err());
        // Missing, or pointing at someone else's /api/grafana-ds/.
        assert!(grafana_ds_evidence(&json!({}), &good_l, &off).is_err());
        assert!(grafana_ds_evidence(&ds("https://evil:8080/api/grafana-ds/prometheus"), &good_l, &off).is_err());
        // The old grafana.ini: public dashboards on (Grafana 12's default), or not said.
        assert!(grafana_ds_evidence(&good_p, &good_l, &json!({ "publicDashboardsEnabled": true })).is_err());
        assert!(grafana_ds_evidence(&good_p, &good_l, &json!({})).is_err());
        assert_eq!(gateway_ds_url("loki"), "https://gateway:8080/api/grafana-ds/loki");
    }

    /// An unreachable Grafana is a closed gate with a reason, never a pass.
    #[test]
    fn an_unreachable_grafana_is_refused() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let enc = jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let e = rt.block_on(fetch_grafana_evidence("https://127.0.0.1:1", &enc)).unwrap_err();
        assert!(e.contains("Grafana did not answer"), "{e}");
        let closed = crate::auth::grafana_viewer_gate(Some("1"), Some(Err(e)));
        assert!(crate::auth::grafana_session_role(Some(Role::User), false, &closed).is_err());
    }

    /// The handler asks the gate for the read-only tier, through the live
    /// probe, and hands the answer to the pinned role function.
    #[test]
    fn the_handler_gates_the_read_only_viewer() {
        let src = include_str!("monitoring.rs");
        let body = src.split("async fn grafana_session(").nth(1).expect("the handler exists");
        let body = body.split("#[cfg(test)]").next().unwrap();
        assert!(body.contains("if live == Some(Role::User) && !disabled {\n        viewer_gate(&key).await"), "{body}");
        assert!(body.contains("grafana_session_role(live, disabled, &viewer)"));
        let gate = src.split("async fn viewer_gate(").nth(1).expect("viewer_gate exists");
        let gate = gate.split("\n}\n").next().unwrap();
        assert!(gate.contains("fetch_grafana_evidence(GRAFANA_INTERNAL_URL, key)"));
        assert!(gate.contains("grafana_viewer_gate(flag.as_deref(), Some(evidence))"));
    }

    #[test]
    fn only_a_person_at_the_browser_may_ask() {
        let person = |sub: &str, act: bool, harness: bool| {
            Some(Extension(RequesterCtx {
                sub: sub.into(),
                scopes: vec![],
                role: Role::User,
                harness: harness.then(|| "node:host3".to_string()),
                act: act.then(|| crate::auth::Actor { sub: "key:svc".into(), iss_user: None, task: None }),
            }))
        };
        assert_eq!(person_at_the_browser(&person("alice", false, false)).as_deref(), Ok("alice"));
        assert_eq!(person_at_the_browser(&person("alice/laptop", false, false)).as_deref(), Ok("alice/laptop"));
        assert!(person_at_the_browser(&None).is_err(), "HMAC / service key");
        assert!(person_at_the_browser(&person("alice", true, false)).is_err(), "exchanged");
        assert!(person_at_the_browser(&person("alice", false, true)).is_err(), "harness");
        assert!(person_at_the_browser(&person("kiosk:hall", false, false)).is_err(), "kiosk");
        assert!(person_at_the_browser(&person("addon:evolve", false, false)).is_err(), "add-on");
        // Every refusal names what is needed, not just "no".
        for p in [None, person("alice", true, false), person("alice", false, true), person("kiosk:hall", false, false)] {
            let e = person_at_the_browser(&p).unwrap_err();
            assert!(e.contains("needs") && e.contains("user (as Grafana Viewer)"), "{e}");
        }
    }

    #[test]
    fn the_login_url_is_the_root_with_the_token_in_the_query() {
        assert_eq!(grafana_login_url("https://g:3000/", "T"), "https://g:3000/?auth_token=T");
        assert_eq!(grafana_login_url("https://g:3000", "T"), "https://g:3000/?auth_token=T");
    }

    /// An absent key is an explained 503, naming the command; a present
    /// P-256 key loads. A P-384 key (what the fleet CA and signing key use)
    /// is refused by name, since Grafana verifies ES256 only.
    #[test]
    fn the_sso_key_loader_names_the_fix() {
        let dir = std::env::temp_dir().join(format!("noo-sso-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let Err(missing) = load_sso_key(&dir.join("grafana.key")) else { panic!("an absent key must be an error") };
        assert!(missing.contains("issue-sso-key"), "{missing}");
        let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        std::fs::write(dir.join("grafana.key"), p256.serialize_pem()).unwrap();
        load_sso_key(&dir.join("grafana.key")).expect("a P-256 key loads");
        let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        std::fs::write(dir.join("grafana.key"), p384.serialize_pem()).unwrap();
        let Err(wrong) = load_sso_key(&dir.join("grafana.key")) else { panic!("a P-384 key must be an error") };
        assert!(wrong.contains("P-256"), "{wrong}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
