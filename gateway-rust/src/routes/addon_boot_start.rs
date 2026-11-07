// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `POST /api/addons/{addon}/boot-start`: what happened when the controller
//! started an add-on after a reboot (noomesh-internal i509, step 3).
//!
//! After a reboot, `noo addons after-boot` (a oneshot unit run as the install
//! owner) starts each enabled add-on whose containers are down, once, through
//! the normal launcher start, and reports each attempt here with the owner's
//! stored CLI credential. Body: `{boot_id, outcome: started|failed, code?,
//! detail?}`.
//!
//! - Who: an operator or admin login (`authz::Operator`). A call with no user
//!   context (cluster HMAC, node token, service key) is refused by the
//!   extractor; an add-on delegated token is confined to the task routes by
//!   the auth layer and is refused here as well.
//! - Which add-on: one that is switched on. A registered add-on, or one the
//!   registry REFUSED (its reason is in `/health`): `refused_by_guard` is
//!   exactly the report of an add-on that is on but did not pass, so a
//!   refused add-on must be reportable. Anything else is 404.
//! - What is checked: `boot_id` is a UUID; `outcome` and `code` come from
//!   the shared list `testdata/addon_boot_start_codes.json` (a byte copy of
//!   `tests/fixtures/addon_boot_start_codes.json`, kept identical by
//!   `tests/test_addon_boot_start_codes_parity.py`); `failed` needs a code,
//!   `started` may omit it; `detail` is at most 4 KiB. A bad body is 400 and
//!   the message names the field.
//! - `failed` raises a PERSISTING operator alert, kind
//!   `addon.boot_start_failed`, target the add-on. Its text is a template
//!   (the code's plain-English description) and its one command is
//!   `noo stack restart <addon>`. `detail` goes into the alert's detail,
//!   which is logged under the alert's reference and never sent to a channel.
//! - `started` clears that alert (a "recovered" message only when one was
//!   announced).
//! - The same (add-on, boot_id, outcome) twice is recorded once; the repeat
//!   answers 200 with `duplicate: true`, never 409 (a re-run after a crash).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use axum::{
    extract::{Path, State},
    routing::post,
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{AppError, AppResult};
use crate::operator_alert::{self, OperatorAlert};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/addons/{addon}/boot-start", post(boot_start))
}

/// The alert kind a failed boot start raises, and the kind `started` clears.
pub const ALERT_KIND: &str = "addon.boot_start_failed";

/// The most `detail` may carry, in bytes.
pub const DETAIL_MAX: usize = 4096;

/// How long a reported (add-on, boot_id, outcome) is remembered. A boot is
/// reported once by design; this only has to outlast a crash and re-run.
const DEDUP_SECS: i64 = 30 * 86_400;

/// The shared list, as this crate reads it.
const CODES_JSON: &str = include_str!("../testdata/addon_boot_start_codes.json");

#[derive(Debug, Deserialize)]
struct Codes {
    format: String,
    outcomes: Vec<String>,
    codes: BTreeMap<String, String>,
}

/// The parsed shared list. The file is compiled in and pinned by the parity
/// test, so a parse failure is a build defect: it is stated, not hidden.
fn codes() -> &'static Codes {
    static C: OnceLock<Codes> = OnceLock::new();
    C.get_or_init(|| {
        let c: Codes = serde_json::from_str(CODES_JSON)
            .expect("testdata/addon_boot_start_codes.json is compiled in and must parse");
        assert_eq!(c.format, "noo-addon-boot-start-codes/1", "addon_boot_start_codes.json: unknown format");
        c
    })
}

#[derive(Debug, Deserialize)]
struct Body {
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

/// A report the route accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    boot_id: String,
    failed: bool,
    code: Option<String>,
    detail: String,
}

/// Check a body against the contract. `Err` is the 400 message.
fn check(b: Body) -> Result<Report, String> {
    let c = codes();
    let boot_id = b.boot_id.as_deref().map(str::trim).unwrap_or("");
    let boot_id = uuid::Uuid::parse_str(boot_id)
        .map_err(|_| format!("boot_id {boot_id:?}: must be a UUID (the kernel's /proc/sys/kernel/random/boot_id)"))?
        .hyphenated()
        .to_string();
    let outcome = b.outcome.as_deref().unwrap_or("");
    if !c.outcomes.iter().any(|o| o == outcome) {
        return Err(format!("outcome {outcome:?}: must be one of {}", c.outcomes.join(", ")));
    }
    let failed = outcome == "failed";
    let code = match b.code.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(code) if c.codes.contains_key(code) => Some(code.to_string()),
        Some(code) => return Err(format!("code {code:?}: unknown; known codes are {}", known(c))),
        None if failed => return Err(format!("code: a failed start needs one of {}", known(c))),
        None => None,
    };
    let detail = b.detail.unwrap_or_default();
    if detail.len() > DETAIL_MAX {
        return Err(format!("detail: {} bytes, at most {DETAIL_MAX}", detail.len()));
    }
    Ok(Report { boot_id, failed, code, detail })
}

fn known(c: &Codes) -> String {
    c.codes.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
}

/// Is `addon` switched on: registered, or refused by the registry (on, but it
/// did not pass, which is what `refused_by_guard` reports)?
fn switched_on(registered: bool, refused: bool) -> bool {
    registered || refused
}

/// The alert a failed start raises. Its text is ours (the code's
/// description), never the caller's: `detail` is logged, not sent.
fn failed_alert(addon: &str, r: &Report, by: &str) -> OperatorAlert {
    let code = r.code.as_deref().unwrap_or("");
    let why = codes().codes.get(code).map_or(code, String::as_str);
    OperatorAlert::new(ALERT_KIND, addon, format!("🔌 Add-on '{addon}' did not start after the reboot: {why}."))
        .detail(format!("boot_id {} code {code} reported by {by}: {}", r.boot_id, r.detail))
        .investigate(format!("noo stack restart {addon}"))
        .persisting()
}

/// The message that closes [`failed_alert`].
fn recovered_alert(addon: &str) -> OperatorAlert {
    OperatorAlert::new(ALERT_KIND, addon, format!("✅ Add-on '{addon}' is started again."))
        .investigate(format!("noo stack restart {addon}"))
}

fn dedup_key(addon: &str, r: &Report) -> String {
    let outcome = if r.failed { "failed" } else { "started" };
    format!("noo:addons:boot_start:{addon}:{}:{outcome}", r.boot_id)
}

/// Report an add-on's start after a reboot (`noo addons after-boot`): `failed`
/// raises a persisting `addon.boot_start_failed` alert naming
/// `noo stack restart <addon>`, `started` clears it. Operator or above.
async fn boot_start(
    State(state): State<Arc<AppState>>,
    op: crate::authz::Operator,
    delegated: Option<Extension<crate::addon_delegation::AddonDelegation>>,
    Path(addon): Path<String>,
    Json(body): Json<Body>,
) -> AppResult {
    if delegated.is_some() {
        return Err(AppError::Forbidden("an add-on token may not report a boot start (log in as an Operator or above)".into()));
    }
    let on = switched_on(crate::addon_registry::get(&addon).is_some(), crate::addon_registry::refusal(&addon).is_some());
    if !on {
        return Err(AppError::NotFound(format!("add-on {addon:?} is not enabled on this gateway (`noo addons list`)")));
    }
    let r = check(body).map_err(AppError::BadRequest)?;
    if !operator_alert::cooldown_acquired(&state, &dedup_key(&addon, &r), DEDUP_SECS).await {
        tracing::info!(addon = %addon, boot_id = %r.boot_id, failed = r.failed, "addon_boot_start_duplicate");
        return Ok(Json(json!({"addon": addon, "boot_id": r.boot_id, "recorded": false, "duplicate": true})));
    }
    let alerted = if r.failed {
        operator_alert::send_operator_alert_with(&state, failed_alert(&addon, &r, op.sub()), 0).await
            == operator_alert::AlertOutcome::Sent
    } else {
        if !r.detail.is_empty() {
            tracing::info!(addon = %addon, boot_id = %r.boot_id, detail = %r.detail, "addon_boot_start_started_detail");
        }
        operator_alert::clear_operator_alert(&state, recovered_alert(&addon)).await
    };
    tracing::info!(addon = %addon, boot_id = %r.boot_id, failed = r.failed, code = ?r.code, by = %op.sub(), "addon_boot_start_recorded");
    let out: Value = json!({"addon": addon, "boot_id": r.boot_id, "recorded": true, "duplicate": false, "alert_queued": alerted});
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";

    fn body(boot_id: &str, outcome: &str, code: Option<&str>, detail: Option<String>) -> Body {
        Body {
            boot_id: Some(boot_id.into()),
            outcome: Some(outcome.into()),
            code: code.map(Into::into),
            detail,
        }
    }

    #[test]
    fn the_shared_list_parses_and_names_the_four_codes() {
        let c = codes();
        assert_eq!(c.outcomes, ["started", "failed"]);
        let keys: Vec<&str> = c.codes.keys().map(String::as_str).collect();
        assert_eq!(keys, ["gateway_wait_timeout", "launcher_failed", "refused_by_guard", "still_down_after_start"]);
    }

    #[test]
    fn a_failed_start_with_a_known_code_is_accepted() {
        let r = check(body(BOOT, "failed", Some("launcher_failed"), Some("exit 1".into()))).unwrap();
        assert!(r.failed);
        assert_eq!(r.code.as_deref(), Some("launcher_failed"));
        assert_eq!(r.detail, "exit 1");
    }

    #[test]
    fn a_started_report_needs_no_code() {
        let r = check(body(BOOT, "started", None, None)).unwrap();
        assert!(!r.failed);
        assert_eq!(r.code, None);
    }

    #[test]
    fn boot_id_must_be_a_uuid() {
        for bad in ["", "boot-1", "6f1c2d3e-4a5b-4c6d-8e7f", "../../etc"] {
            let e = check(body(bad, "started", None, None)).unwrap_err();
            assert!(e.starts_with("boot_id"), "{bad:?}: {e}");
        }
        let missing = Body { boot_id: None, outcome: Some("started".into()), code: None, detail: None };
        assert!(check(missing).unwrap_err().starts_with("boot_id"));
    }

    #[test]
    fn boot_id_is_stored_in_one_spelling_so_dedup_cannot_be_dodged() {
        let upper = check(body(&BOOT.to_uppercase(), "started", None, None)).unwrap();
        assert_eq!(upper.boot_id, BOOT);
    }

    #[test]
    fn an_unknown_outcome_is_refused() {
        for bad in ["", "ok", "Failed", "stopped"] {
            let e = check(body(BOOT, bad, Some("launcher_failed"), None)).unwrap_err();
            assert!(e.starts_with("outcome"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn an_unknown_code_is_refused_on_either_outcome() {
        for outcome in ["failed", "started"] {
            let e = check(body(BOOT, outcome, Some("disk_full"), None)).unwrap_err();
            assert!(e.starts_with("code \"disk_full\": unknown"), "{outcome}: {e}");
        }
    }

    #[test]
    fn a_failed_start_without_a_code_is_refused() {
        for code in [None, Some(""), Some("  ")] {
            let e = check(body(BOOT, "failed", code, None)).unwrap_err();
            assert!(e.starts_with("code: a failed start needs"), "{code:?}: {e}");
        }
    }

    #[test]
    fn detail_is_capped_at_4_kib() {
        assert!(check(body(BOOT, "failed", Some("launcher_failed"), Some("x".repeat(DETAIL_MAX)))).is_ok());
        let e = check(body(BOOT, "failed", Some("launcher_failed"), Some("x".repeat(DETAIL_MAX + 1)))).unwrap_err();
        assert!(e.starts_with("detail"), "{e}");
    }

    #[test]
    fn a_refused_add_on_is_switched_on_and_an_absent_one_is_not() {
        assert!(switched_on(true, false));
        assert!(switched_on(false, true), "refused_by_guard must be reportable for an add-on the registry refused");
        assert!(!switched_on(false, false));
    }

    #[test]
    fn the_failed_alert_persists_names_the_restart_and_keeps_detail_out_of_the_text() {
        let r = check(body(BOOT, "failed", Some("refused_by_guard"), Some("raw launcher evidence".into()))).unwrap();
        let a = failed_alert("rhaddon", &r, "rb");
        assert_eq!(a.kind, ALERT_KIND);
        assert_eq!(a.target, "rhaddon");
        assert!(a.persisting);
        assert_eq!(a.investigate.as_deref(), Some("noo stack restart rhaddon"));
        assert!(a.summary.contains("the add-on guards refused"), "{}", a.summary);
        assert!(!a.summary.contains("raw launcher"), "detail must not reach the summary: {}", a.summary);
        assert!(a.detail.contains("raw launcher evidence") && a.detail.contains(BOOT));
    }

    #[test]
    fn started_clears_the_same_kind_and_target() {
        let c = recovered_alert("rhaddon");
        assert_eq!((c.kind.as_str(), c.target.as_str()), (ALERT_KIND, "rhaddon"));
        assert!(!c.persisting);
    }

    #[test]
    fn dedup_is_per_addon_boot_and_outcome() {
        let f = check(body(BOOT, "failed", Some("launcher_failed"), None)).unwrap();
        let s = check(body(BOOT, "started", None, None)).unwrap();
        assert_ne!(dedup_key("a", &f), dedup_key("a", &s), "a failure then a start in one boot are two reports");
        assert_ne!(dedup_key("a", &f), dedup_key("b", &f));
        assert_eq!(dedup_key("a", &f), dedup_key("a", &check(body(&BOOT.to_uppercase(), "failed", Some("launcher_failed"), None)).unwrap()));
    }
}
