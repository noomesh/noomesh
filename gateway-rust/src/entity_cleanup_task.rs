// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `entity_cleanup`: the scheduled junk-entity cleanup.
//!
//! The action runs the SAME core as `POST /api/v1/graph/entity-cleanup`
//! (`routes::knowledge::entity_cleanup_run`): the same 5,000 cap, the same busy / recluster
//! refusal, the audit row written BEFORE the delete, staged deletes restorable for 30 days
//! (`graph_prune_staging`, restore by run id), the run id in the result.
//!
//! ## Config
//!
//! `{apply: bool (default false), max_delete: int (default 1000, cap 5000), examples: int (default 0)}`.
//! A task is a DRY RUN unless it is both configured `apply: true` AND authorised.
//!
//! ## Authorised
//!
//! Who may make a task apply is `task_guard`'s rule: a person's credential (no `harness` claim, no
//! `act`, Admin), directly or by approving a proposal an agent filed. Either records the account and
//! the time on the task row (`authorised_by`, `authorised_at`) and, here, the exact settings the
//! person decided (`authorised_config`). A run applies only while the live config still matches
//! them, so a write that went around the guard cannot widen what was approved: it previews.
//!
//! ## What reaches a channel
//!
//! A [`SystemReport`]: `lines` are counts and the run id (the channel's general message), `detail`
//! (run record and log) the counts by reason and type. No entity name appears in either; the
//! worker's `examples` are written to the gateway log only, and only if the task asked for them.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::auth::{RequesterCtx, Role};
use crate::heartbeat_actions::{NativeOutcome, SystemReport};
use crate::routes::knowledge::{entity_cleanup_audit_details, entity_cleanup_request, entity_cleanup_run, CleanupCaller};

/// The heartbeat action name.
pub const ACTION: &str = "entity_cleanup";
/// Default per-run delete cap for a scheduled run: a fifth of the route's ceiling.
pub const DEFAULT_MAX_DELETE: i64 = 1000;

// ───────────────────────────── config ─────────────────────────────

/// A task's cleanup settings, validated by the route's own request parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub apply: bool,
    pub max_delete: i64,
    pub examples: i64,
}

/// Parse a task's `config`. Absent fields take the scheduled defaults (preview, 1000, no
/// examples); a bad value is an error. The bounds are `entity_cleanup_request`'s, so the cap
/// cannot differ from the route's.
pub fn parse_config(config: &Value) -> Result<Settings, String> {
    let pick = |k: &str, default: Value| match config.get(k) {
        None | Some(Value::Null) => default,
        Some(v) => v.clone(),
    };
    let params = json!({
        "apply": pick("apply", json!(false)),
        "max_delete": pick("max_delete", json!(DEFAULT_MAX_DELETE)),
        "examples": pick("examples", json!(0)),
    });
    let (apply, request) = entity_cleanup_request(&params)?;
    Ok(Settings {
        apply,
        max_delete: request["max_delete"].as_i64().unwrap_or(DEFAULT_MAX_DELETE),
        examples: request["examples"].as_i64().unwrap_or(0),
    })
}

/// What a person's approval is bound to. A run applies only while the live config still
/// normalises to this.
pub fn fingerprint(s: &Settings) -> String {
    format!("apply={};max_delete={};examples={}", s.apply, s.max_delete, s.examples)
}

/// What a person's decision is bound to for an `entity_cleanup` apply task, `None` for any other
/// action or for a preview. Stored in `authorised_config` and compared at run time.
pub fn fingerprint_of(action: &str, config: &Value) -> Option<String> {
    if action != ACTION {
        return None;
    }
    parse_config(config).ok().filter(|s| s.apply).map(|s| fingerprint(&s))
}

/// The columns a run reads.
#[derive(Debug, Clone, Default)]
pub struct ApprovalRow {
    pub authorised_by: Option<String>,
    pub authorised_at: Option<chrono::DateTime<chrono::Utc>>,
    pub approved_config: Option<String>,
}

/// Does this stored decision cover these settings right now?
pub fn approval_covers(row: &ApprovalRow, s: &Settings) -> bool {
    s.apply && row.authorised_by.is_some() && row.approved_config.as_deref() == Some(fingerprint(s).as_str())
}

async fn read_row(db: &sqlx::PgPool, task_id: &str) -> Result<Option<ApprovalRow>, sqlx::Error> {
    let r: Option<(Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<String>)> = sqlx::query_as(
        "SELECT authorised_by, authorised_at, authorised_config FROM noo_heartbeat_tasks WHERE id = $1",
    )
    .bind(task_id)
    .fetch_optional(db)
    .await?;
    Ok(r.map(|(by, at, cfg)| ApprovalRow { authorised_by: by, authorised_at: at, approved_config: cfg }))
}

/// Reject a config the scheduled action could not run, at write time, with the parser's message.
pub fn validate_write(action: &str, config: &Value) -> Result<(), String> {
    if action == ACTION {
        parse_config(config).map(|_| ()).map_err(|e| format!("entity_cleanup config: {e}"))
    } else {
        Ok(())
    }
}

// ───────────────────────────── running it ─────────────────────────────

/// What one run will do, decided from the live config and the stored approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub settings: Settings,
    /// Whether this run applies. False unless configured, approved for exactly these settings, and
    /// not forced to a preview.
    pub apply: bool,
    pub authorised_by: Option<String>,
    pub authorised_at: Option<String>,
    /// Why a configured `apply: true` is running as a preview, for the result text.
    pub preview_note: Option<&'static str>,
}

/// The decision, pure.
pub fn decide(settings: Settings, row: &ApprovalRow) -> Resolved {
    let apply = settings.apply && approval_covers(row, &settings);
    let preview_note = if settings.apply && !apply {
        Some("no person has authorised these settings; a person edits the task, or approves its proposal (noo heartbeat proposals)")
    } else {
        None
    };
    Resolved {
        settings,
        apply,
        authorised_by: if apply { row.authorised_by.clone() } else { None },
        authorised_at: if apply { row.authorised_at.map(|t| t.to_rfc3339()) } else { None },
        preview_note,
    }
}

/// Keep ids to a plain shape before they go into an audit row (a task id is whatever its creator
/// typed).
fn audit_id(id: &str) -> String {
    id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(64).collect()
}

/// The heartbeat action.
pub async fn run(
    state: &Arc<crate::state::AppState>,
    task_id: &str,
    config: &Value,
) -> Result<NativeOutcome, String> {
    let resolved = resolve(&state.db, task_id, config).await?;
    run_with(&state.db, task_id, &resolved, |body| {
        let state = state.clone();
        async move { state.memory().junk_entity_cleanup(&body).await }
    })
    .await
}

/// Resolve the run from the live task row. The approval is read from the table, never from the
/// config the caller passed (config is what an agent writes).
pub async fn resolve(db: &sqlx::PgPool, task_id: &str, config: &Value) -> Result<Resolved, String> {
    let settings = parse_config(config).map_err(|e| format!("entity_cleanup: bad config: {e}"))?;
    let row = read_row(db, task_id)
        .await
        .map_err(|e| format!("entity_cleanup: could not read the task's approval: {e}"))?
        .unwrap_or_default();
    Ok(decide(settings, &row))
}

/// [`run`] with the worker call as a parameter, so a test stands a worker in without a bus.
/// Everything else is what runs in production.
pub async fn run_with<F, Fut>(
    db: &sqlx::PgPool,
    task_id: &str,
    r: &Resolved,
    ask_worker: F,
) -> Result<NativeOutcome, String>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Value>>,
{
    let (apply, request) = entity_cleanup_request(&json!({
        "apply": r.apply, "max_delete": r.settings.max_delete, "examples": r.settings.examples,
    }))
    .map_err(|e| format!("entity_cleanup: {e}"))?;
    let id = audit_id(task_id);
    let identity = format!("heartbeat:{id}");
    // The task's own identity. It names the harness so no downstream check can read it as a person.
    let requester = RequesterCtx {
        sub: identity.clone(),
        scopes: vec!["read".into(), "write".into(), "admin".into()],
        role: Role::Admin,
        harness: Some(identity.clone()),
        act: None,
    };
    let caller = CleanupCaller {
        actor: identity,
        requester: Some(axum::Extension(requester)),
        extra: json!({
            "via": "heartbeat",
            "task_id": id,
            "authorised_by": r.authorised_by,
            "authorised_at": r.authorised_at,
        }),
    };
    let outcome = entity_cleanup_run(db, &caller, apply, request.clone(), ask_worker).await;
    if let Some(why) = &outcome.failure {
        // RAISE: a returned failure string records status=success (the database_backup defect).
        return Err(format!("entity_cleanup: {why}"));
    }
    let payload = &outcome.body;
    // A 2xx is not yet "it did what was asked": the run says it deleted N only when the worker's own
    // answer says it applied N. An answer that does not confirm what was requested is a FAILED run.
    let status = payload.get("status").and_then(Value::as_str);
    if apply && (status != Some("applied") || !payload.get("staged").is_some_and(Value::is_number)) {
        return Err("entity_cleanup: the worker did not confirm the apply (no `applied` status and staged count); \
                    nothing is recorded as deleted: check the gateway log and `noo graph prune restore`"
            .into());
    }
    if !apply && status == Some("applied") {
        return Err("entity_cleanup: the worker applied a run that was asked to preview; see the audit log".into());
    }
    // The same allow-list the audit row uses: numbers, a validated run id, and report keys that
    // look like identifiers. Nothing the worker echoed can arrive as text here.
    let d = entity_cleanup_audit_details(&request, Some(payload), if apply { "apply" } else { "preview" });
    let n = |k: &str| d.get(k).and_then(Value::as_i64).unwrap_or(0);
    let (scanned, junk, staged, over_cap) = (n("scanned"), n("junk"), n("staged"), n("skipped_over_cap"));
    let run_id = d.get("run_id").and_then(Value::as_str);

    if r.settings.examples > 0 {
        // Names are in the LOG only: never in the run record, the audit row or a channel.
        for ex in payload.get("examples").and_then(Value::as_array).into_iter().flatten() {
            tracing::info!(task_id = %id, example = %ex, "entity_cleanup_example");
        }
    }
    tracing::info!(task_id = %id, apply, scanned, junk, staged, over_cap, run_id = ?run_id, "entity_cleanup_done");

    let mut lines = Vec::new();
    if apply {
        lines.push(format!(
            "Entity cleanup: {staged} junk entities staged and removed (restorable for 30 days) from {scanned} scanned{}.",
            run_id.map(|id| format!(", run {id}")).unwrap_or_default()
        ));
        if over_cap > 0 {
            lines.push(format!(
                "{over_cap} more are over this run's cap of {} and wait for the next run.",
                r.settings.max_delete
            ));
        }
    } else {
        lines.push(format!(
            "Entity cleanup (preview): {junk} junk entities found among {scanned} scanned; nothing was removed."
        ));
        if let Some(note) = r.preview_note {
            lines.push(format!("Apply is configured but this run only previewed: {note}."));
        }
    }
    let mut detail = Vec::new();
    for (label, key) in [("by reason", "by_reason"), ("by type", "by_type")] {
        if let Some(m) = d.get(key).and_then(Value::as_object) {
            let mut pairs: Vec<(&String, i64)> = m.iter().filter_map(|(k, v)| v.as_i64().map(|n| (k, n))).collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            if !pairs.is_empty() {
                detail.push(format!(
                    "{label}: {}",
                    pairs.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
    if let (true, Some(by)) = (apply, r.authorised_by.as_deref()) {
        detail.push(format!("apply authorised by {by}"));
    }
    Ok(SystemReport { lines, detail }.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::tests::{account, scratch, DB_LOCK};
    use crate::task_guard::{apply_approved, write_task, Origin, TaskSpec, Written};
    use std::sync::{Arc as StdArc, Mutex};

    #[test]
    fn config_defaults_and_caps_are_the_routes() {
        assert_eq!(parse_config(&json!({})).unwrap(), Settings { apply: false, max_delete: 1000, examples: 0 });
        assert_eq!(parse_config(&json!({"apply": true, "max_delete": 5000, "examples": 3})).unwrap().max_delete, 5000);
        for bad in [json!({"max_delete": 5001}), json!({"max_delete": 0}), json!({"apply": "true"}), json!({"examples": 201}), json!({"max_delete": "9"})] {
            assert!(parse_config(&bad).is_err(), "{bad}");
            assert!(validate_write(ACTION, &bad).is_err(), "a write of {bad} is refused up front");
        }
        assert!(validate_write("graph_prune", &json!({"max_delete": 99999})).is_ok(), "other actions are not this parser's");
    }

    #[test]
    fn a_run_applies_only_while_the_decision_covers_the_live_settings() {
        let s = Settings { apply: true, max_delete: 100, examples: 0 };
        let approved = ApprovalRow { authorised_by: Some("root".into()), authorised_at: None, approved_config: Some(fingerprint(&s)) };
        assert!(decide(s.clone(), &approved).apply);
        let widened = Settings { max_delete: 5000, ..s.clone() };
        assert!(!decide(widened, &approved).apply, "a widened cap is not what was approved");
        assert!(!decide(s.clone(), &ApprovalRow::default()).apply, "nobody authorised it");
        let off = Settings { apply: false, ..s };
        assert!(!decide(off, &approved).apply, "not configured to apply");
        assert_eq!(fingerprint_of("graph_prune", &json!({"apply": true})), None);
        assert_eq!(fingerprint_of(ACTION, &json!({"apply": false})), None);
        assert!(fingerprint_of(ACTION, &json!({"apply": true})).is_some());
    }

    // ───────────── against a real migrated schema (skips without NOO_BROKER_TEST_DSN) ─────────────

    fn spec(id: &str, config: Value) -> TaskSpec {
        TaskSpec {
            id: id.into(),
            name: id.into(),
            schedule: "30 7 * * 0".into(),
            action: ACTION.into(),
            config,
            channels: json!([]),
            recipients: json!([]),
            enabled: true,
            created_by: "test".into(),
        }
    }
    fn admin() -> Origin {
        Origin::Person { account: "root".into(), role: Role::Admin }
    }
    fn door() -> Origin {
        Origin::Agent { account: "root".into(), via: "harness operator:x".into() }
    }

    /// What the worker answers: names in `examples` that must stay out of everything but the log.
    fn dry_report() -> Value {
        json!({"data": {
            "status": "dry-run", "dry_run": true, "scanned": 1200, "junk": 3, "staged": 0, "skipped_over_cap": 0,
            "run_id": null, "by_reason": {"math_symbol": 2, "bare_number": 1}, "by_type": {"parameter": 3},
            "examples": [{"name": "patient zero", "type": "parameter", "edges": 7}],
        }})
    }
    fn applied_report() -> Value {
        json!({"data": {
            "status": "applied", "dry_run": false, "scanned": 1200, "junk": 3, "staged": 3, "skipped_over_cap": 0,
            "run_id": "entq-1a2b3c4d", "by_reason": {"math_symbol": 2, "bare_number": 1}, "by_type": {"parameter": 3},
            "examples": [{"name": "patient zero", "type": "parameter", "edges": 7}],
        }})
    }

    /// Run the task as the scheduler does, with a worker that records what it was asked.
    async fn run_task(db: &sqlx::PgPool, id: &str, answer: Value) -> (Result<NativeOutcome, String>, Option<Value>) {
        let config: Value = sqlx::query_scalar("SELECT config FROM noo_heartbeat_tasks WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("task row");
        let resolved = resolve(db, id, &config).await.expect("resolve");
        let asked = StdArc::new(Mutex::new(None));
        let a2 = asked.clone();
        let out = run_with(db, id, &resolved, move |body| async move {
            *a2.lock().unwrap() = Some(body);
            Ok(answer)
        })
        .await;
        let body = asked.lock().unwrap().clone();
        (out, body)
    }

    async fn audit(db: &sqlx::PgPool) -> Vec<(String, String, Value)> {
        sqlx::query_as(
            "SELECT actor, outcome, details FROM noo_security_audit WHERE event_type = 'graph_entity_cleanup' ORDER BY \"timestamp\", id",
        )
        .fetch_all(db)
        .await
        .expect("audit rows")
    }

    fn everything(o: &NativeOutcome) -> String {
        format!("{} || {}", o.text, o.channel.clone().unwrap_or_default())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dry_run_task_deletes_nothing_and_reports_counts_without_a_name() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_dry").await else { return };
        // no apply key at all: a preview
        assert!(matches!(write_task(&db, &admin(), &spec("t_dry", json!({"examples": 5})), "create").await.unwrap(), Written::Direct { authorised_by: None }));
        let (out, body) = run_task(&db, "t_dry", dry_report()).await;
        let out = out.expect("a dry run succeeds");
        let body = body.expect("the worker was asked for the preview");
        assert_eq!(body["apply"], false, "no apply request");
        assert_eq!(body["max_delete"], 1000, "the scheduled default cap");
        assert_eq!(body["examples"], 5);
        assert_eq!(body["_requester"]["role"], "admin", "the worker's own admin re-check passes");
        let text = everything(&out);
        assert!(text.contains("preview") && text.contains("3 junk") && text.contains("1200"), "{text}");
        assert!(text.contains("math_symbol 2") && text.contains("parameter 3"), "counts by reason and type: {text}");
        assert!(!text.contains("patient zero"), "no entity name in the run text or the channel: {text}");
        assert!(out.channel.as_deref().is_some_and(|c| !c.contains("math_symbol")), "the channel gets the general lines only");
        assert!(audit(&db).await.is_empty(), "a preview is a read: no audit row");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_a_person_set_to_apply_applies_and_is_audited_with_the_task_and_the_authoriser() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_apply").await else { return };
        let w = write_task(&db, &admin(), &spec("t_apply", json!({"apply": true, "max_delete": 50})), "create").await.unwrap();
        assert_eq!(w, Written::Direct { authorised_by: Some("root".into()) });
        let (by, at): (Option<String>, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT authorised_by, authorised_at FROM noo_heartbeat_tasks WHERE id = 't_apply'").fetch_one(&db).await.unwrap();
        assert_eq!((by.as_deref(), at.is_some()), (Some("root"), true), "who and when are recorded");

        let (out, body) = run_task(&db, "t_apply", applied_report()).await;
        let out = out.expect("an applied run succeeds");
        let body = body.expect("asked");
        assert_eq!(body["apply"], true);
        assert_eq!(body["max_delete"], 50, "the task's cap crosses, nothing else");
        let text = everything(&out);
        assert!(text.contains("3 junk entities staged") && text.contains("restorable for 30 days") && text.contains("entq-1a2b3c4d"), "{text}");
        assert!(text.contains("authorised by root"), "{text}");
        assert!(!text.contains("patient zero"), "{text}");

        let rows = audit(&db).await;
        assert_eq!(rows.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(), ["started", "ok"], "intent row first, result row after");
        for (actor, _, details) in &rows {
            assert_eq!(actor, "heartbeat:t_apply", "the actor is the task");
            assert_eq!(details["authorised_by"], "root", "and the person who authorised it");
            assert_eq!(details["task_id"], "t_apply");
            assert_eq!(details["max_delete"], 50);
        }
        assert_eq!(rows[1].2["run_id"], "entq-1a2b3c4d", "the run id is on the result row (restore by it)");
        assert!(!rows[1].2.to_string().contains("patient zero"), "no entity name in the audit row");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_asked_apply_task_does_not_exist_until_a_person_approves_and_then_applies() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_agent").await else { return };
        let _ = account(&db, "root", Role::Admin).await;
        let w = write_task(&db, &door(), &spec("t_ai", json!({"apply": true, "max_delete": 100})), "create").await.unwrap();
        assert!(matches!(w, Written::Proposed { .. }), "{w:?}");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_heartbeat_tasks WHERE id = 't_ai'").fetch_one(&db).await.unwrap();
        assert_eq!(n, 0, "no task row, so nothing can run");
        // the person approves; the task exists, authorised by them, and applies
        let payload: Value = sqlx::query_scalar("SELECT payload FROM noo_user_proposals WHERE action = 'heartbeat_task'").fetch_one(&db).await.unwrap();
        let mut tx = db.begin().await.unwrap();
        apply_approved(&mut tx, &payload, &admin()).await.unwrap();
        tx.commit().await.unwrap();
        let (out, body) = run_task(&db, "t_ai", applied_report()).await;
        out.expect("ok");
        assert_eq!(body.unwrap()["apply"], true);
        assert_eq!(audit(&db).await[0].2["authorised_by"], "root", "the approver, not the proposer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_that_went_around_the_guard_only_previews() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_bypass").await else { return };
        write_task(&db, &admin(), &spec("t_b", json!({"apply": true, "max_delete": 100})), "create").await.unwrap();
        // the config is changed without the guard (a direct SQL write)
        sqlx::query("UPDATE noo_heartbeat_tasks SET config = jsonb_set(config, '{max_delete}', '4000') WHERE id = 't_b'").execute(&db).await.unwrap();
        let (out, body) = run_task(&db, "t_b", dry_report()).await;
        assert_eq!(body.unwrap()["apply"], false, "the decision is for the settings the person saw");
        assert!(everything(&out.unwrap()).contains("only previewed"));
        assert!(audit(&db).await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cap_is_enforced_and_a_busy_lock_fails_the_run_loudly() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_caps").await else { return };
        let _ = account(&db, "root", Role::Admin).await;
        // over the route's ceiling: refused at write time
        for bad in [json!({"apply": true, "max_delete": 5001}), json!({"max_delete": 0})] {
            assert!(validate_write(ACTION, &bad).is_err(), "{bad}");
        }
        // the ceiling itself is accepted and sent as is
        write_task(&db, &admin(), &spec("t_cap", json!({"apply": true, "max_delete": 5000})), "create").await.unwrap();
        let (out, body) = run_task(&db, "t_cap", json!({"data": {
            "status": "applied", "dry_run": false, "scanned": 9000, "junk": 7000, "staged": 5000, "skipped_over_cap": 2000,
            "run_id": "entq-feed", "by_reason": {}, "by_type": {},
        }})).await;
        assert_eq!(body.unwrap()["max_delete"], 5000);
        let text = everything(&out.unwrap());
        assert!(text.contains("2000 more are over this run's cap of 5000"), "{text}");
        // busy: the worker's lock is held. A failed run, never a quiet success, and the audit says busy
        let (out, _) = run_task(&db, "t_cap", json!({"data": {"status": "busy", "error": "busy: graph prune holds the lock right now; nothing was changed"}})).await;
        assert!(out.unwrap_err().contains("busy"), "busy raises");
        assert!(audit(&db).await.iter().any(|r| r.1 == "busy"), "a busy refusal is recorded");
        // a live recluster: refused before the worker is asked
        sqlx::query(
            "INSERT INTO noo_ops (op_id, op_type, status, owner_uuid, runner_instance, started_at, expires_at) \
             VALUES (gen_random_uuid(), 'graph.recluster', 'running', (SELECT user_uuid FROM noo_users WHERE username = 'root'), \
                     'gw-x', now(), now() + interval '1 day')",
        )
        .execute(&db)
        .await
        .expect("a live recluster op");
        let (out, body) = run_task(&db, "t_cap", applied_report()).await;
        assert!(out.unwrap_err().contains("recluster"), "refused as busy");
        assert!(body.is_none(), "the worker is not asked under a recluster");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_seeded_default_is_a_disabled_weekly_dry_run() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_seed").await else { return };
        let (action, schedule, config, enabled, by): (String, String, Value, bool, Option<String>) = sqlx::query_as(
            "SELECT action, schedule, config, enabled, authorised_by FROM noo_heartbeat_tasks WHERE id = 'entity_cleanup'",
        )
        .fetch_one(&db)
        .await
        .expect("the default task is seeded by the migration");
        assert_eq!(action, ACTION);
        assert_eq!(schedule, "30 7 * * 0", "Sundays, after graph prune's 06:00");
        assert!(!enabled, "seeded disabled: it needs the trellion worker");
        assert_eq!(by, None);
        assert!(!parse_config(&config).unwrap().apply, "never seeded with apply");
        assert!(!crate::task_guard::classify(&action, &config).destructive);
        let (out, body) = run_task(&db, "entity_cleanup", dry_report()).await;
        out.expect("runs");
        assert_eq!(body.unwrap()["apply"], false, "the seeded default is a dry run");
        assert!(audit(&db).await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_worker_error_is_a_failed_run_never_a_recorded_deletion() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("ec_task_fail").await else { return };
        let _ = account(&db, "root", Role::Admin).await;
        write_task(&db, &admin(), &spec("t_f", json!({"apply": true, "max_delete": 100})), "create").await.unwrap();
        // the worker's staging write fails (an undefined relation, 42P01): a 400 from the core
        let (out, body) = run_task(&db, "t_f", json!({"data": {
            "error": "entity cleanup failed (ProgrammingError); batches already committed are staged and restorable, and a re-run continues; see the worker log"
        }})).await;
        assert!(body.is_some(), "the worker was asked");
        let err = out.expect_err("a worker error fails the run");
        assert!(err.contains("entity cleanup failed"), "{err}");
        assert!(!err.contains("staged and removed"), "no deletion is claimed: {err}");
        let rows = audit(&db).await;
        assert_eq!(rows.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(), ["started", "failed"], "the failure is audited, with no counts");
        assert!(rows[1].2["staged"].is_null(), "{}", rows[1].2);
        // a worker that cannot be reached at all
        let resolved = resolve(&db, "t_f", &json!({"apply": true, "max_delete": 100})).await.unwrap();
        let out = run_with(&db, "t_f", &resolved, |_| async move { Err(anyhow::anyhow!("nats: no responders")) }).await;
        assert!(out.is_err(), "an unreachable worker fails the run");
        // a 200 that does not confirm the apply is not recorded as one
        for answer in [
            json!({"data": {"status": "dry-run", "dry_run": true, "scanned": 10, "junk": 3}}),
            json!({"data": {"scanned": 10, "junk": 3}}),
            json!({"data": {"status": "applied", "run_id": "entq-1"}}),
        ] {
            let (out, _) = run_task(&db, "t_f", answer.clone()).await;
            assert!(out.is_err(), "{answer} must not read as a deletion");
        }
        // and a preview that comes back applied is a fault too
        write_task(&db, &admin(), &spec("t_p", json!({})), "create").await.unwrap();
        let (out, _) = run_task(&db, "t_p", applied_report()).await;
        assert!(out.is_err());
    }

    #[test]
    fn no_migration_seeds_an_apply_task() {
        let mig = include_str!("mesh_migrate.rs");
        let from = mig.find("revision: \"085_heartbeat_task_authorisation\"").expect("085");
        let seed = &mig[from..];
        assert!(seed.contains("\"apply\": false"), "the seeded task previews");
        assert!(!seed.contains("\"apply\": true"), "no migration seeds an apply task");
    }
}
